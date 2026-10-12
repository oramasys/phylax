"""Composition: a deployment can provision keys and open the authority safely."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phylax.adjustment_grant import AdjustmentGrantRequest, GrantRefusal
from phylax.grant_composition import (
    CompositionError,
    FileSeedProvider,
    GrantAuthorityConfig,
    open_grant_authority,
)

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


def test_a_seed_that_does_not_match_the_durable_key_refuses_to_start(tmp_path: Path, seeds: Path) -> None:
    """Swapping the seed file under an existing registry is caught at open."""
    open_grant_authority(config(tmp_path, seeds))
    seed_file(seeds, "issuer-1", "33" * 32)
    with pytest.raises(ValueError, match="does not match"):
        open_grant_authority(config(tmp_path, seeds))


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
