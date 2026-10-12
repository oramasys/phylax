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
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Final

from nacl.bindings import crypto_sign_SEEDBYTES

from .adjustment_grant import PhylaxGrantAuthority, RotatingIssuerKeyring
from .grant_store import SqliteGrantAuthorityStore
from .p5_approval import P5ApprovalAuthority, SqliteP5ApprovalStore

_REF_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PRIVATE_DIR_MODE: Final = 0o700


class CompositionError(ValueError):
    """Raised when configuration, a secret file or a state directory is unsafe."""


def _require_private(path: Path, *, directory: bool) -> os.stat_result:
    """Return ``path``'s status after checking type, ownership and mode.

    Symlinks, files owned by another user and any group or world access are
    refused: a signing seed that others can read is not a secret.
    """
    try:
        status = os.lstat(path)
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


class FileSeedProvider:
    """``IssuerSeedProvider`` reading hex seeds from private files in one directory.

    A seed reference is a short file name inside ``root``, never a path, so a
    reference stored in the durable registry cannot point outside it.
    """

    def __init__(self, root: str | Path) -> None:
        """Bind the provider to a private directory of seed files."""
        self._root = Path(root)
        _require_private(self._root, directory=True)

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the 32-byte seed named by ``seed_ref`` from its private file."""
        if not isinstance(seed_ref, str) or _REF_RE.fullmatch(seed_ref) is None:
            raise CompositionError("seed reference must be a short file name")
        path = self._root / seed_ref
        _require_private(path, directory=False)
        text = path.read_text(encoding="ascii").strip()
        try:
            seed = bytes.fromhex(text)
        except ValueError as exc:
            raise CompositionError(f"{seed_ref} must contain hex") from exc
        if len(seed) != crypto_sign_SEEDBYTES:
            raise CompositionError(f"{seed_ref} must hold exactly {crypto_sign_SEEDBYTES} bytes")
        return seed


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
            if _REF_RE.fullmatch(getattr(self, name)) is None:
                raise CompositionError(f"{name} must be a short file name")
        if self.seed_ref == self.p5_secret_ref:
            raise CompositionError("the issuer seed and the P5 secret must be different files")
        for name in ("key_id", "verifier_id"):
            if not getattr(self, name).strip():
                raise CompositionError(f"{name} is required")


def _ensure_state_dir(path: Path) -> None:
    """Create the state directory as 0700, or verify an existing one is private."""
    if not path.exists():
        path.mkdir(mode=_PRIVATE_DIR_MODE, parents=True)
    _require_private(path, directory=True)


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
