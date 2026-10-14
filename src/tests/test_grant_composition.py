"""Composition: a deployment can provision keys and open the authority safely."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import os
import sqlite3
import stat
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phylax import grant_composition
from phylax.adjustment_grant import AdjustmentGrantRequest, GrantRefusal
from phylax.grant_composition import (
    CompositionError,
    FileSeedProvider,
    GrantAuthorityConfig,
    GrantVerifierConfig,
    open_grant_authority,
    open_grant_verifier,
)
from phylax.grant_store import SqliteGrantAuthorityStore, SqliteGrantVerificationStore
from phylax.p5_approval import SqliteP5ApprovalStore

SEED_HEX = "11" * 32
P5_HEX = "22" * 32


def seed_file(root: Path, name: str, content: str = SEED_HEX, mode: int = 0o600) -> Path:
    """Write one private seed file."""
    path = root / name
    path.write_text(content + "\n", encoding="ascii")
    path.chmod(mode)
    return path


@pytest.fixture
def seeds(tmp_path: Path) -> Path:
    """Return a private seed directory holding an issuer seed and a P5 secret."""
    root = tmp_path / "seeds"
    root.mkdir(mode=0o700)
    seed_file(root, "issuer-1", SEED_HEX)
    seed_file(root, "p5-secret", P5_HEX)
    return root


def config(tmp_path: Path, seeds: Path, **overrides: object) -> GrantAuthorityConfig:
    """Return a complete configuration for the test deployment."""
    values: dict[str, object] = {
        "state_dir": tmp_path / "state",
        "seed_root": seeds,
        "key_id": "issuer-1",
        "seed_ref": "issuer-1",
        "p5_secret_ref": "p5-secret",
    }
    values.update(overrides)
    return GrantAuthorityConfig(**values)  # type: ignore[arg-type]


def grant_request() -> AdjustmentGrantRequest:
    """Return a complete target tuple for one adjustment."""
    return AdjustmentGrantRequest(
        principal="local-operator", run_id="run-1", hold_id="hold:abc", kind="release", units=2,
        units_basis="steps", ledger_cost_basis="legacy_step_only", evidence_digest="a" * 64,
        hold_fence_epoch=1, consumer_lease_epoch=1, ledger_store_id="store:one",
        issuer_ref="phylax-primary", revocation_ref="phylax://revocations/v1",
    )


# --- seed provider ---------------------------------------------------------


def test_a_private_hex_seed_is_loaded(seeds: Path) -> None:
    """A 0600 file of 32 bytes in hex is accepted."""
    assert FileSeedProvider(seeds).load_seed("issuer-1") == bytes.fromhex(SEED_HEX)


@pytest.mark.parametrize(
    ("name", "content", "mode", "match"),
    [
        ("loose", SEED_HEX, 0o644, "group or others"),
        ("short", "11" * 16, 0o600, "exactly 32"),
        ("notahex", "zz" * 32, 0o600, "hex"),
        ("spaced", " ".join(["11"] * 32), 0o600, "hex"),
        ("prefixed", "0x" + "11" * 31, 0o600, "hex"),
        ("oddlength", "1" * 63, 0o600, "exactly 32"),
    ],
)
def test_unsafe_seed_files_are_refused(seeds: Path, name: str, content: str, mode: int, match: str) -> None:
    """Loose permissions, wrong length and non-hex content all refuse."""
    seed_file(seeds, name, content, mode)
    with pytest.raises(CompositionError, match=match):
        FileSeedProvider(seeds).load_seed(name)


@pytest.mark.parametrize("ref", ["../secret", "a/b", "", ".hidden", "x" * 65, "with space"])
def test_seed_references_are_file_names_not_paths(seeds: Path, ref: str) -> None:
    """A stored reference can never point outside the seed directory."""
    with pytest.raises(CompositionError, match="file name"):
        FileSeedProvider(seeds).load_seed(ref)


def test_symlinked_and_missing_seeds_are_refused(seeds: Path, tmp_path: Path) -> None:
    """A symlink, even to a good file, and a missing file refuse."""
    target = seed_file(tmp_path, "outside", SEED_HEX)
    os.symlink(target, seeds / "linked")
    provider = FileSeedProvider(seeds)
    with pytest.raises(CompositionError, match="symlink"):
        provider.load_seed("linked")
    with pytest.raises(CompositionError, match="does not exist"):
        provider.load_seed("absent")


def test_a_group_readable_seed_directory_is_refused(tmp_path: Path) -> None:
    """The directory is part of the secret's protection."""
    loose = tmp_path / "loose-seeds"
    loose.mkdir(mode=0o755)
    loose.chmod(0o755)
    with pytest.raises(CompositionError, match="group or others"):
        FileSeedProvider(loose)


# --- configuration -----------------------------------------------------------


def test_the_issuer_seed_and_p5_secret_must_differ(tmp_path: Path, seeds: Path) -> None:
    """One file cannot serve both roles."""
    with pytest.raises(CompositionError, match="different"):
        config(tmp_path, seeds, p5_secret_ref="issuer-1")


# --- the authority -------------------------------------------------------------


def test_the_opened_authority_issues_and_its_verifier_accepts(tmp_path: Path, seeds: Path) -> None:
    """Provisioning is enough to issue and verify a grant end to end."""
    authority = open_grant_authority(config(tmp_path, seeds))
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    verified = authority.verifier_adapter().verify(grant.to_wire())
    assert verified.grant_id == grant.grant_id and verified.verifier_id == "phylax-primary"
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700


def test_state_survives_reopening_including_revocation(tmp_path: Path, seeds: Path) -> None:
    """A restart keeps the registry, the issued grant and its revocation."""
    first = open_grant_authority(config(tmp_path, seeds))
    grant = first.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    first.revoke(grant.grant_id)

    second = open_grant_authority(config(tmp_path, seeds))
    with pytest.raises(GrantRefusal) as refused:
        second.verifier_adapter().verify(grant.to_wire())
    assert refused.value.reason.value == "grant.revoked"
    assert second.verifier_adapter().revocation(grant.grant_id).revoked is True


def test_verify_only_opens_existing_state_without_secret_configuration(
    tmp_path: Path, seeds: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The serving verifier reads durable authority state without issuer secrets."""
    authority = open_grant_authority(config(tmp_path, seeds))
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )

    def reject_seed_load(self: FileSeedProvider, seed_ref: str) -> bytes:
        raise AssertionError("verify-only mode attempted to load a signing seed")

    monkeypatch.setattr(FileSeedProvider, "load_seed", reject_seed_load)
    verifier = open_grant_verifier(
        GrantVerifierConfig(state_dir=tmp_path / "state", verifier_id="consumer-1")
    )

    assert verifier.verify(grant.to_wire()).grant_id == grant.grant_id
    assert verifier.revocation(grant.grant_id).revoked is False


def test_verify_only_fails_closed_without_creating_state(tmp_path: Path) -> None:
    """A serving process never bootstraps issuer state as a side effect."""
    state = tmp_path / "missing-state"

    with pytest.raises(CompositionError, match="does not exist"):
        open_grant_verifier(GrantVerifierConfig(state_dir=state))

    assert not state.exists()


def test_verify_only_uses_read_only_database_and_observes_revocation(
    tmp_path: Path, seeds: Path
) -> None:
    """The verifier reads WAL-backed revocations without modifying the database."""
    authority = open_grant_authority(config(tmp_path, seeds))
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    authority.revoke(grant.grant_id)
    state = tmp_path / "state"
    database = state / "grants.sqlite3"
    before = database.read_bytes()
    database.chmod(0o400)
    try:
        store = SqliteGrantVerificationStore(database)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            with store._connection() as connection:
                connection.execute(
                    "INSERT INTO grant_revocations(grant_id, revoked_at) VALUES(?, ?)",
                    ("unauthorized-write", "2026-10-14T00:00:00.000000Z"),
                )
        verifier = open_grant_verifier(GrantVerifierConfig(state_dir=state))
        with pytest.raises(GrantRefusal) as refused:
            verifier.verify(grant.to_wire())
        assert refused.value.reason.value == "grant.revoked"
        assert verifier.revocation(grant.grant_id).revoked is True
        assert database.read_bytes() == before
    finally:
        database.chmod(0o600)


def test_verify_only_refuses_database_replaced_after_validation(
    tmp_path: Path, seeds: Path
) -> None:
    """A fresh connection cannot silently follow the verified DB path to another inode."""
    open_grant_authority(config(tmp_path, seeds))
    database = tmp_path / "state" / "grants.sqlite3"
    database.chmod(0o600)
    store = SqliteGrantVerificationStore(database)

    replacement = database.with_name("replacement.sqlite3")
    replacement.write_bytes(database.read_bytes())
    replacement.chmod(0o600)
    database.unlink()
    replacement.replace(database)

    with pytest.raises(PermissionError, match="replaced after validation"):
        store.is_revoked("grant-1")


def test_verifier_reports_a_symlinked_database_as_unavailable(
    tmp_path: Path, seeds: Path
) -> None:
    """A database path turned into a symlink is a verifier fault, not a malformed grant."""
    authority = open_grant_authority(config(tmp_path, seeds))
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    database = tmp_path / "state" / "grants.sqlite3"
    verifier = open_grant_verifier(GrantVerifierConfig(state_dir=database.parent))
    store = SqliteGrantVerificationStore(database)
    real = database.with_name("real.sqlite3")
    database.replace(real)
    database.symlink_to(real)
    with pytest.raises(GrantRefusal) as refused:
        verifier.verify(grant.to_wire())
    assert refused.value.reason.value == "verifier.unavailable"
    with pytest.raises(OSError, match="regular file"):
        store.is_revoked(grant.grant_id)


def test_open_verifier_observes_revoke_while_wal_reader_is_active(
    tmp_path: Path, seeds: Path
) -> None:
    """A verifier opened before a revoke reads the newly committed WAL state."""
    authority = open_grant_authority(config(tmp_path, seeds))
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    database = tmp_path / "state" / "grants.sqlite3"
    verifier = open_grant_verifier(
        GrantVerifierConfig(state_dir=database.parent, verifier_id="consumer-1")
    )
    blocker = sqlite3.connect(database, isolation_level=None)
    try:
        blocker.execute("BEGIN")
        blocker.execute("SELECT COUNT(*) FROM grant_revocations").fetchone()
        authority.revoke(grant.grant_id)
        assert Path(f"{database}-wal").exists()
        with pytest.raises(GrantRefusal) as refused:
            verifier.verify(grant.to_wire())
        assert refused.value.reason.value == "grant.revoked"
        assert verifier.revocation(grant.grant_id).revoked is True
    finally:
        blocker.rollback()
        blocker.close()


def test_a_seed_that_does_not_match_the_durable_key_refuses_to_start(tmp_path: Path, seeds: Path) -> None:
    """Swapping the seed file under an existing registry is caught at open."""
    open_grant_authority(config(tmp_path, seeds))
    seed_file(seeds, "issuer-1", "33" * 32)
    with pytest.raises(ValueError, match="does not match"):
        open_grant_authority(config(tmp_path, seeds))


def test_a_state_directory_created_by_a_concurrent_worker_is_accepted(
    tmp_path: Path, seeds: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing the creation race to another worker is not a startup failure."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    real_exists = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda self: False if self == state else real_exists(self)
    )
    authority = open_grant_authority(config(tmp_path, seeds))
    assert authority.verifier_adapter() is not None


def test_an_existing_state_file_is_refused_as_a_composition_error(
    tmp_path: Path, seeds: Path
) -> None:
    """A non-directory state path retains the closed configuration error contract."""
    (tmp_path / "state").write_text("not a directory", encoding="ascii")
    with pytest.raises(CompositionError, match="must be a directory"):
        open_grant_authority(config(tmp_path, seeds))


def test_two_workers_can_bootstrap_the_same_authority_concurrently(
    tmp_path: Path, seeds: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identical first-time workers may both adopt the one durable initial key."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    grants = state / "grants.sqlite3"
    approvals = state / "p5-approvals.sqlite3"
    grants.touch(mode=0o600)
    approvals.touch(mode=0o600)
    SqliteGrantAuthorityStore(grants)
    SqliteP5ApprovalStore(str(approvals))

    entry_barrier = threading.Barrier(2, timeout=5)
    real_ensure = SqliteGrantAuthorityStore.ensure_active_key

    def synchronized_ensure(store: SqliteGrantAuthorityStore, record):
        """Hold both workers at the registry decision so neither has committed yet."""
        entry_barrier.wait()
        return real_ensure(store, record)

    monkeypatch.setattr(SqliteGrantAuthorityStore, "ensure_active_key", synchronized_ensure)
    deployment = config(tmp_path, seeds)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(open_grant_authority, deployment) for _ in range(2)]
        authorities = [future.result(timeout=10) for future in futures]

    assert all(authority.verifier_adapter() is not None for authority in authorities)


def test_two_workers_can_bootstrap_from_an_empty_state_directory(
    tmp_path: Path, seeds: Path
) -> None:
    """Two workers starting with no state directory or databases both succeed."""
    assert not (tmp_path / "state").exists()
    start = threading.Barrier(2, timeout=5)
    deployment = config(tmp_path, seeds)

    def worker():
        """Open the authority once both workers are released together."""
        start.wait()
        return open_grant_authority(deployment)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(worker) for _ in range(2)]
        authorities = [future.result(timeout=10) for future in futures]

    assert all(authority.verifier_adapter() is not None for authority in authorities)


def test_a_different_key_cannot_adopt_an_initialized_registry(
    tmp_path: Path, seeds: Path
) -> None:
    """Idempotent bootstrap never replaces the durable initial key."""
    open_grant_authority(config(tmp_path, seeds))
    seed_file(seeds, "issuer-2", "33" * 32)

    with pytest.raises(ValueError, match="does not match"):
        open_grant_authority(
            config(tmp_path, seeds, key_id="issuer-2", seed_ref="issuer-2")
        )

    assert open_grant_authority(config(tmp_path, seeds)).verifier_adapter() is not None


def test_a_loose_state_directory_is_refused(tmp_path: Path, seeds: Path) -> None:
    """Durable state in a shared directory is not accepted."""
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o755)
    with pytest.raises(CompositionError, match="group or others"):
        open_grant_authority(config(tmp_path, seeds))


def test_clock_is_injectable(tmp_path: Path, seeds: Path) -> None:
    """Tests and operators can supply the clock the authority uses."""
    fixed = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
    authority = open_grant_authority(config(tmp_path, seeds), clock=lambda: fixed)
    grant = authority.issue(
        grant_request(), authenticated_principal="local-operator",
        operator_evidence_ref="trusted-ui://approval/1",
    )
    assert grant.issued_at == fixed


def test_seed_read_uses_the_file_that_was_validated(
    seeds: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replacing the path after validation must not replace the bytes read."""
    from phylax import grant_composition

    outside = seed_file(tmp_path, "replacement", "33" * 32)
    original = grant_composition._require_private
    swapped = False

    def replace_after_check(path: Path, **kwargs: object) -> os.stat_result:
        """Run the real check, then swap the seed for a symlink, once, as an attacker would."""
        nonlocal swapped
        result = original(path, **kwargs)
        if path.name == "issuer-1" and not swapped:
            swapped = True
            path.unlink()
            path.symlink_to(outside)
        return result

    monkeypatch.setattr(grant_composition, "_require_private", replace_after_check)
    assert FileSeedProvider(seeds).load_seed("issuer-1") == bytes.fromhex(SEED_HEX)


def test_replacing_the_seed_directory_with_a_symlink_is_refused(
    seeds: Path, tmp_path: Path
) -> None:
    """Every load reopens and validates the root without following a symlink."""
    provider = FileSeedProvider(seeds)
    replacement = tmp_path / "replacement-directory"
    replacement.mkdir(mode=0o700)
    seed_file(replacement, "issuer-1", "33" * 32)
    seeds.rename(tmp_path / "original-directory")
    seeds.symlink_to(replacement, target_is_directory=True)
    with pytest.raises(CompositionError):
        provider.load_seed("issuer-1")


@pytest.mark.parametrize("content", ["11" * 100_000, "\xff" * 64])
def test_seed_input_is_bounded_and_decoding_errors_are_normalized(
    seeds: Path, content: str
) -> None:
    """Invalid secret files refuse with the configuration error contract."""
    (seeds / "issuer-1").write_bytes(content.encode("latin-1"))
    with pytest.raises(CompositionError):
        FileSeedProvider(seeds).load_seed("issuer-1")


@pytest.mark.parametrize("name", ["grants.sqlite3", "p5-approvals.sqlite3"])
def test_authority_refuses_symlinked_databases(
    tmp_path: Path, seeds: Path, name: str
) -> None:
    """A private parent must not authorize following a database symlink."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = seed_file(tmp_path, "outside-database", "sentinel")
    (state / name).symlink_to(target)
    with pytest.raises(CompositionError):
        open_grant_authority(config(tmp_path, seeds))
    assert target.read_text(encoding="ascii") == "sentinel\n"


def test_databases_are_private_from_creation(tmp_path: Path, seeds: Path) -> None:
    """A permissive process umask must not make authority state readable."""
    previous = os.umask(0)
    try:
        open_grant_authority(config(tmp_path, seeds))
    finally:
        os.umask(previous)
    for name in ("grants.sqlite3", "p5-approvals.sqlite3"):
        assert (tmp_path / "state" / name).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("name", ["grants.sqlite3", "p5-approvals.sqlite3"])
@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sqlite_sidecar_symlinks_are_refused(
    tmp_path: Path, seeds: Path, name: str, suffix: str
) -> None:
    """Sidecar files have the same trust boundary as the database itself."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    outside = seed_file(tmp_path, "outside-sidecar", "sentinel")
    (state / (name + suffix)).symlink_to(outside)
    with pytest.raises(CompositionError):
        open_grant_authority(config(tmp_path, seeds))
    assert outside.read_text(encoding="ascii") == "sentinel\n"


def test_existing_loose_database_is_refused(tmp_path: Path, seeds: Path) -> None:
    """Startup reports unsafe permissions without silently changing them."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    database = state / "grants.sqlite3"
    database.touch(mode=0o644)
    database.chmod(0o644)
    with pytest.raises(CompositionError, match="group or others"):
        open_grant_authority(config(tmp_path, seeds))


@pytest.mark.parametrize("name", ["seed_ref", "p5_secret_ref", "key_id", "verifier_id"])
def test_non_text_configuration_is_refused(tmp_path: Path, seeds: Path, name: str) -> None:
    """Runtime configuration mistakes retain the closed configuration error type."""
    with pytest.raises(CompositionError):
        config(tmp_path, seeds, **{name: None})


class _RivalCreatesFirst:
    """``os.open`` stand-in reproducing Darwin's spurious ENOENT for a create loser.

    The first O_CREAT open of the target creates the file as a rival would, then
    fails the way the kernel does for the loser of a concurrent same-name create.
    """

    def __init__(self, real_open, target: str, mode: int) -> None:
        """Remember the real ``os.open``, the contested name and the rival's file mode."""
        self.real_open = real_open
        self.target = target
        self.mode = mode
        self.calls: list[int] = []

    def __call__(self, path, flags, mode=0o777, *, dir_fd=None):
        """Create the rival's file once, fail the first create, then pass through."""
        if path != self.target or dir_fd is None:
            return self.real_open(path, flags, mode, dir_fd=dir_fd)
        self.calls.append(flags)
        if len(self.calls) == 1:
            descriptor = self.real_open(path, flags, 0o600, dir_fd=dir_fd)
            os.fchmod(descriptor, self.mode)
            os.close(descriptor)
            raise FileNotFoundError(errno.ENOENT, "spurious ENOENT for a create loser")
        return self.real_open(path, flags, mode, dir_fd=dir_fd)


def test_a_create_loser_opens_the_rivals_file_instead_of_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spurious ENOENT on a contested create is retried once, without creating."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    rival = _RivalCreatesFirst(os.open, "grants.sqlite3", 0o600)
    monkeypatch.setattr(grant_composition.os, "open", rival)

    grant_composition._prepare_state_files(state)

    assert len(rival.calls) == 2
    assert rival.calls[0] & os.O_CREAT
    assert not rival.calls[1] & os.O_CREAT
    assert stat.S_IMODE((state / "grants.sqlite3").stat().st_mode) == 0o600


def test_a_create_loser_still_refuses_an_unsafe_file_the_rival_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry path keeps the ownership and mode checks of the normal path."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(
        grant_composition.os, "open", _RivalCreatesFirst(os.open, "grants.sqlite3", 0o644)
    )

    with pytest.raises(CompositionError, match="group or others"):
        grant_composition._prepare_state_files(state)


def test_a_vanished_directory_is_refused_after_one_retry_not_looped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A persistent ENOENT is a missing directory, so the retry is bounded at one."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    attempts: list[int] = []
    real_open = os.open

    def always_missing(path, flags, mode=0o777, *, dir_fd=None):
        """Fail every file open under the directory descriptor."""
        if dir_fd is None:
            return real_open(path, flags, mode, dir_fd=dir_fd)
        attempts.append(flags)
        raise FileNotFoundError(errno.ENOENT, "gone")

    monkeypatch.setattr(grant_composition.os, "open", always_missing)

    with pytest.raises(CompositionError, match="does not exist"):
        grant_composition._prepare_state_files(state)
    assert len(attempts) == 2
