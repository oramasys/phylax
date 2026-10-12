"""Issuer-side adjustment grant tests for P5 binding and Ed25519ph attestations."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib

import pytest

from phylax.adjustment_grant import (
    AdjustmentGrant,
    AdjustmentGrantRequest,
    PhylaxGrantAuthority,
    RotatingIssuerKeyring,
    _grant_body,
    _sign_message,
    _verify_message,
)
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority


class Clock:
    """Mutable shared UTC clock for P5 and grant authority tests."""

    def __init__(self) -> None:
        """Start at a fixed, microsecond-stable UTC instant."""
        self.now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        """Return the current deterministic time."""
        return self.now


def request(**overrides: object) -> AdjustmentGrantRequest:
    """Return a complete immutable target tuple for a human-approved adjustment."""
    values: dict[str, object] = {
        "principal": "operator-1",
        "run_id": "run-1",
        "hold_id": "hold-1",
        "kind": "settle",
        "units": 3,
        "units_basis": "steps",
        "ledger_cost_basis": "legacy-step-only-v1",
        "evidence_digest": "a" * 64,
        "hold_fence_epoch": 4,
        "consumer_lease_epoch": 7,
        "ledger_store_id": "ledger-primary",
        "issuer_ref": "phylax-primary",
        "revocation_ref": "phylax://revocations/v1",
    }
    values.update(overrides)
    return AdjustmentGrantRequest(**values)  # type: ignore[arg-type]


def authority(clock: Clock) -> tuple[PhylaxGrantAuthority, InMemoryP5ApprovalStore]:
    """Return a P5-backed issuer and the test store used to inspect bound intent."""
    p5_store = InMemoryP5ApprovalStore()
    p5 = P5ApprovalAuthority(
        signing_key=b"p5-test-secret",
        store=p5_store,
        clock=clock,
    )
    return (
        PhylaxGrantAuthority(
            keyring=RotatingIssuerKeyring(key_id="issuer-1", seed=b"a" * 32),
            p5_approval=p5,
            clock=clock,
        ),
        p5_store,
    )


def issue(policy: PhylaxGrantAuthority) -> AdjustmentGrant:
    """Issue one grant through the trusted-evidence P5 path."""
    return policy.issue(
        request(),
        authenticated_principal="operator-1",
        operator_evidence_ref="trusted-ui://approval/1",
    )


def test_issue_binds_the_complete_target_to_p5_and_ed25519ph() -> None:
    """Human issuance derives its duration from P5 and signs the exact target body."""
    clock = Clock()
    policy, p5_store = authority(clock)

    grant = issue(policy)

    policy.verify(grant)
    assert grant.expires_at - grant.issued_at == timedelta(seconds=5_400)
    audit = policy.issuance_audit(grant.grant_id)
    assert audit is not None
    assert "trusted-ui" not in audit.approval_token_digest
    stored = p5_store.get(audit.approval_id)
    assert stored is not None
    assignment = stored.preview.intent.preview_payload()["assignments"][0]
    assert assignment["grant_id"] == grant.grant_id
    assert assignment["consumer_lease_epoch"] == 7
    assert assignment["ledger_store_id"] == "ledger-primary"


def test_issue_requires_authenticated_principal_match() -> None:
    """Transport authentication cannot mint a grant for another principal."""
    policy, _store = authority(Clock())

    with pytest.raises(ValueError, match="authenticated principal"):
        policy.issue(
            request(),
            authenticated_principal="different-principal",
            operator_evidence_ref="trusted-ui://approval/1",
        )


def test_mutated_signed_fields_and_signature_are_rejected() -> None:
    """Digest validation and Ed25519ph verification reject independent tampering."""
    policy, _store = authority(Clock())
    grant = issue(policy)

    with pytest.raises(ValueError, match="payload_digest"):
        replace(grant, units=grant.units + 1)
    replacement = "A" if grant.issuer_signature[0] != "A" else "B"
    tampered = replace(grant, issuer_signature=replacement + grant.issuer_signature[1:])
    with pytest.raises(ValueError, match="issuer signature"):
        policy.verify(tampered)


def test_verify_refuses_future_expired_and_revoked_grants() -> None:
    """Issuer verification enforces the ratified 60-second skew and revocation rules."""
    clock = Clock()
    policy, _store = authority(clock)
    grant = issue(policy)

    clock.now += timedelta(seconds=5_401)
    with pytest.raises(ValueError, match="expired"):
        policy.verify(grant)

    clock = Clock()
    policy, _store = authority(clock)
    grant = issue(policy)
    policy.revoke(grant.grant_id)
    with pytest.raises(ValueError, match="revoked"):
        policy.verify(grant)

    future_issued_at = clock.now + timedelta(seconds=61)
    future_expires_at = future_issued_at + timedelta(seconds=5_400)
    future_request = AdjustmentGrantRequest(
        principal=grant.principal,
        run_id=grant.run_id,
        hold_id=grant.hold_id,
        kind=grant.kind,
        units=grant.units,
        units_basis=grant.units_basis,
        ledger_cost_basis=grant.ledger_cost_basis,
        evidence_digest=grant.evidence_digest,
        hold_fence_epoch=grant.hold_fence_epoch,
        consumer_lease_epoch=grant.consumer_lease_epoch,
        ledger_store_id=grant.ledger_store_id,
        issuer_ref=grant.issuer_ref,
        revocation_ref=grant.revocation_ref,
    )
    body = _grant_body(
        future_request,
        grant_id=grant.grant_id,
        issued_at=future_issued_at,
        expires_at=future_expires_at,
        issuer_key_id=grant.issuer_key_id,
    )
    _key_id, signature = policy._keyring.sign(body)
    future = AdjustmentGrant.from_request(
        future_request,
        grant_id=grant.grant_id,
        issued_at=future_issued_at,
        expires_at=future_expires_at,
        issuer_key_id=grant.issuer_key_id,
        payload_digest=hashlib.sha256(body).hexdigest(),
        issuer_signature=signature,
    )
    with pytest.raises(ValueError, match="future skew"):
        policy.verify(future)


def test_retired_key_retains_old_grants_until_floor_then_prunes() -> None:
    """Rotation preserves verification through the monotonic retired-key window."""
    clock = Clock()
    policy, _store = authority(clock)
    grant = issue(policy)
    keyring = policy._keyring
    keyring.rotate(key_id="issuer-2", seed=b"b" * 32, now=clock.now)

    policy.verify(grant)
    assert keyring.retention_for("issuer-1") == clock.now + timedelta(hours=24)
    assert keyring.prune(now=clock.now + timedelta(hours=24)) == ()
    assert keyring.prune(now=clock.now + timedelta(hours=24, microseconds=1)) == ("issuer-1",)
    with pytest.raises(ValueError, match="issuer signature"):
        policy.verify(grant)


def test_request_rejects_ambiguous_units_and_digest() -> None:
    """A grant target has no implicit unit dimension or malformed evidence digest."""
    with pytest.raises(ValueError, match="units must"):
        request(units=True)
    with pytest.raises(ValueError, match="evidence_digest"):
        request(evidence_digest="ABC")


def test_ed25519ph_matches_rfc8032_vector_and_chunk_boundaries() -> None:
    """The signing primitive matches RFC 8032 Ed25519ph rather than plain Ed25519."""
    seed = bytes.fromhex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
    expected_public_key = bytes.fromhex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
    expected_signature = bytes.fromhex(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
        "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
    )

    public_key, signature = _sign_message(seed, b"abc")

    assert public_key == expected_public_key
    assert signature == expected_signature
    assert _verify_message(public_key, signature, b"a", b"b", b"c")
