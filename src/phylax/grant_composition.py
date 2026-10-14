"""Composition for the adjustment-grant authority: where keys and state come from.

Task 6 shipped the issuer, the durable store and the verifier adapter, but no
way to provision a signing seed or to open all of them from configuration, so a
deployment could not turn the feature on. This module is that step and nothing
more: it reads secrets from private files, opens durable stores in a private
directory, and returns a ready ``PhylaxGrantAuthority``.

Secrets are never read from environment variables or logged. Every path is
checked for ownership and mode before use, and a missing or loose file refuses
to start rather than falling back.
"""

from __future__ import annotations

import os
import errno
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Final, Iterator

from nacl.bindings import crypto_sign_SEEDBYTES

from .adjustment_grant import (
    PhylaxAdjustmentGrantVerifier,
    PhylaxGrantAuthority,
    PhylaxGrantVerifier,
    RotatingIssuerKeyring,
)
from .grant_store import SqliteGrantAuthorityStore, SqliteGrantVerificationStore
from .p5_approval import P5ApprovalAuthority, SqliteP5ApprovalStore

_REF_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PRIVATE_DIR_MODE: Final = 0o700
_MAX_SEED_FILE_BYTES: Final = 128
_SEED_HEX_RE: Final = re.compile(rb"[0-9A-Fa-f]{%d}" % (crypto_sign_SEEDBYTES * 2))


class CompositionError(ValueError):
    """Raised when configuration, a secret file or a state directory is unsafe."""


@dataclass(frozen=True, slots=True)
class GrantVerifierConfig:
    """Minimal serving configuration; it intentionally has no secret references."""

    state_dir: Path
    verifier_id: str = "phylax-primary"

    def __post_init__(self) -> None:
        """Reject an empty verifier identity before opening durable state."""
        if not isinstance(self.verifier_id, str) or not self.verifier_id.strip():
            raise CompositionError("verifier_id is required")


def _require_private(
    path: Path, *, directory: bool, descriptor: int | None = None
) -> os.stat_result:
    """Return ``path``'s status after checking type, ownership and mode.

    Symlinks, files owned by another user and any group or world access are
    refused: a signing seed that others can read is not a secret.
    """
    try:
        status = os.lstat(path) if descriptor is None else os.fstat(descriptor)
    except FileNotFoundError as exc:
        raise CompositionError(f"{path.name} does not exist") from exc
    if stat.S_ISLNK(status.st_mode):
        raise CompositionError(f"{path.name} must not be a symlink")
    wanted = stat.S_ISDIR if directory else stat.S_ISREG
    if not wanted(status.st_mode):
        raise CompositionError(f"{path.name} must be a {'directory' if directory else 'regular file'}")
    if status.st_uid != os.geteuid():
        raise CompositionError(f"{path.name} must be owned by the current user")
    if stat.S_IMODE(status.st_mode) & 0o077:
        raise CompositionError(f"{path.name} must not be accessible to group or others")
    return status


def _open_creating(name: str, flags: int, dir_fd: int) -> int:
    """Open or create ``name`` under ``dir_fd``, tolerating a rival creating it first.

    Darwin fails the loser of two concurrent ``openat(O_CREAT)`` calls on the same
    new name with a spurious ``ENOENT`` although the directory exists (reproduced
    with bare ``O_RDWR|O_CREAT``; absolute paths and Linux are unaffected). The
    only live-directory cause is a rival's in-flight create, so retry exactly once
    without ``O_CREAT`` to open what it made. The caller's ownership and mode
    checks still run on the returned descriptor, and a directory that really is
    gone fails the retry too and is refused as missing.
    """
    try:
        return os.open(name, flags, 0o600, dir_fd=dir_fd)
    except FileNotFoundError:
        return os.open(name, flags & ~os.O_CREAT, 0o600, dir_fd=dir_fd)


@contextmanager
def _open_private(
    path: Path, *, directory: bool = False, dir_fd: int | None = None,
    create: bool = False,
) -> Iterator[int]:
    """Validate and use one descriptor, refusing final-component symlinks.

    Relative opens are anchored to the validated parent descriptor. Nonblocking
    opens allow a substituted FIFO to be refused by the regular-file check.
    """
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= os.O_DIRECTORY if directory else (os.O_RDWR if create else os.O_RDONLY)
    if create:
        flags |= os.O_CREAT
    try:
        if create and dir_fd is not None:
            descriptor = _open_creating(path.name, flags, dir_fd)
        else:
            descriptor = os.open(path.name if dir_fd is not None else path, flags, 0o600, dir_fd=dir_fd)
    except FileNotFoundError as exc:
        raise CompositionError(f"{path.name} does not exist") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CompositionError(f"{path.name} must not be a symlink") from exc
        raise CompositionError(f"{path.name} cannot be opened as a private {'directory' if directory else 'file'}") from exc
    try:
        _require_private(path, directory=directory, descriptor=descriptor)
        yield descriptor
    finally:
        os.close(descriptor)


class FileSeedProvider:
    """``IssuerSeedProvider`` reading hex seeds from private files in one directory.

    A seed reference is a short file name inside ``root``, never a path, so a
    reference stored in the durable registry cannot point outside it.
    """

    def __init__(self, root: str | Path) -> None:
        """Bind the provider to a private directory of seed files."""
        self._root = Path(root)
        with _open_private(self._root, directory=True):
            pass

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the 32-byte seed named by ``seed_ref`` from its private file."""
        if not isinstance(seed_ref, str) or _REF_RE.fullmatch(seed_ref) is None:
            raise CompositionError("seed reference must be a short file name")
        path = self._root / seed_ref
        with _open_private(self._root, directory=True) as root_fd:
            with _open_private(path, dir_fd=root_fd) as descriptor:
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    raw = stream.read(_MAX_SEED_FILE_BYTES + 1)
        if len(raw) > _MAX_SEED_FILE_BYTES:
            raise CompositionError(f"{seed_ref} exceeds the seed file size limit")
        text = raw.strip()
        if _SEED_HEX_RE.fullmatch(text) is None:
            # Strict: no inner whitespace, prefixes or odd lengths are tolerated.
            if re.fullmatch(rb"[0-9A-Fa-f]*", text) is None:
                raise CompositionError(f"{seed_ref} must contain hex")
            raise CompositionError(f"{seed_ref} must hold exactly {crypto_sign_SEEDBYTES} bytes")
        return bytes.fromhex(text.decode("ascii"))


@dataclass(frozen=True, slots=True)
class GrantAuthorityConfig:
    """Everything a deployment must say to run the adjustment-grant authority."""

    state_dir: Path
    seed_root: Path
    key_id: str
    seed_ref: str
    p5_secret_ref: str
    verifier_id: str = "phylax-primary"

    def __post_init__(self) -> None:
        """Reject unsafe references and identifiers before anything is opened."""
        for name in ("seed_ref", "p5_secret_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
                raise CompositionError(f"{name} must be a short file name")
        if self.seed_ref == self.p5_secret_ref:
            raise CompositionError("the issuer seed and the P5 secret must be different files")
        for name in ("key_id", "verifier_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CompositionError(f"{name} is required")


def _ensure_state_dir(path: Path) -> None:
    """Create the state directory as 0700, or verify an existing one is private."""
    try:
        path.mkdir(mode=_PRIVATE_DIR_MODE, parents=True)
    except FileExistsError:
        pass
    _require_private(path, directory=True)


def _prepare_state_files(path: Path) -> None:
    """Precreate private databases and refuse unsafe existing SQLite sidecars.

    SQLite subsequently opens paths inside this owner-only directory. Its
    contents must remain under that trusted owner's control during operation.
    """
    with _open_private(path, directory=True) as root_fd:
        for name in ("grants.sqlite3", "p5-approvals.sqlite3"):
            with _open_private(path / name, dir_fd=root_fd, create=True):
                pass
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = path / (name + suffix)
                try:
                    os.stat(sidecar.name, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                with _open_private(sidecar, dir_fd=root_fd):
                    pass


def open_grant_authority(
    config: GrantAuthorityConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> PhylaxGrantAuthority:
    """Open a durable, P5-backed grant authority from private configuration.

    Reopening with the same configuration yields the same registry, revocations
    and issued grants. A provisioned seed that does not match the durable
    active key refuses to start (the keyring enforces it).
    """
    _ensure_state_dir(config.state_dir)
    seeds = FileSeedProvider(config.seed_root)
    p5_secret = seeds.load_seed(config.p5_secret_ref)
    _prepare_state_files(config.state_dir)
    keyring = RotatingIssuerKeyring(
        key_id=config.key_id,
        seed_ref=config.seed_ref,
        seed_provider=seeds,
        store=SqliteGrantAuthorityStore(config.state_dir / "grants.sqlite3"),
    )
    p5 = P5ApprovalAuthority(
        signing_key=p5_secret,
        store=SqliteP5ApprovalStore(str(config.state_dir / "p5-approvals.sqlite3")),
        clock=clock,
    )
    return PhylaxGrantAuthority(
        keyring=keyring,
        p5_approval=p5,
        verifier_id=config.verifier_id,
        clock=clock,
    )


def open_grant_verifier(
    config: GrantVerifierConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> PhylaxAdjustmentGrantVerifier:
    """Open a verifier from existing state without reading or creating secrets/state.

    The database is opened with SQLite ``mode=ro`` and query-only enforcement.
    WAL may still require its shared-memory sidecar for coordination, so the
    private state directory must permit that SQLite bookkeeping. Immutable mode
    is avoided so fresh revocations are not hidden behind a stale main-database
    snapshot. No signing seed or P5 secret is loaded by this path.

    Residual limit (not a full guarantee): every check here is made on the path, and SQLite
    then opens that path as a separate step, so a process that can write to the state
    directory could swap the file between the check and the open. The store re-checks the
    file's identity before and after connecting, which narrows that window but does not
    close it. The safety of this path therefore depends on the state directory being
    private to one user, which ``_require_private`` enforces. Closing the gap would mean
    keeping the validated connection instead of reopening by path.
    """
    state_dir = Path(config.state_dir)
    _require_private(state_dir, directory=True)
    database = state_dir / "grants.sqlite3"
    _require_private(database, directory=False)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = state_dir / (database.name + suffix)
        try:
            os.lstat(sidecar)
        except FileNotFoundError:
            continue
        _require_private(sidecar, directory=False)
    try:
        store = SqliteGrantVerificationStore(database)
    except FileNotFoundError as exc:
        raise CompositionError("grants.sqlite3 does not exist") from exc
    verifier = PhylaxGrantVerifier(
        store=store, verifier_id=config.verifier_id, clock=clock
    )
    return PhylaxAdjustmentGrantVerifier(verifier)
