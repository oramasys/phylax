"""Effect-grant v2 issuance and verification contract."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def test_effect_grant_is_domain_separated_bound_and_revocable(tmp_path: Path) -> None:
    """Only the verified v2 effect projection crosses into a consumer."""
    from phylax.adjustment_grant import RotatingIssuerKeyring
    from phylax.effect_grant import (
        EffectGrantAuthority,
        EffectGrantRefusal,
        EffectGrantRefusalReason,
        EffectGrantRequest,
    )
    from phylax.grant_store import SqliteGrantAuthorityStore
    from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

    class Seeds:
        def load_seed(self, seed_ref: str) -> bytes:
            assert seed_ref == "seed-1"
            return b"e" * 32

    now = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    keyring = RotatingIssuerKeyring(
        key_id="issuer-1", seed_ref="seed-1", seed_provider=Seeds(), store=store
    )
    authority = EffectGrantAuthority(
        keyring=keyring,
        p5_approval=P5ApprovalAuthority(
            signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=lambda: now
        ),
        clock=lambda: now,
    )
    request = EffectGrantRequest(
        principal="principal-1", run_id="run-1", operation_id="operation-1",
        request_digest="a" * 64, effect_class="inert.simulation", ledger_store_id="ledger-1",
        consumer_lease_epoch=3, second_approval_ref="approval-1", issuer_ref="phylax-1",
        revocation_ref="phylax://revocations/v1",
    )

    grant = authority.issue(
        request, authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1"
    )
    verified = authority.verify(grant.to_wire())
    assert (verified.grant_id, verified.second_approval_ref, verified.use_limit) == (
        grant.grant_id, "approval-1", 1
    )
    assert verified.expires_at - verified.issued_at == timedelta(seconds=5_400)

    authority.revoke(grant.grant_id)
    with pytest.raises(EffectGrantRefusal) as refusal:
        authority.verify(grant.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.GRANT_REVOKED


NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


class _Seeds:
    """Serve one deterministic seed per reference for in-process issuers."""

    def __init__(self, seeds: dict[str, bytes] | None = None) -> None:
        """Remember the seeds and every reference that was loaded."""
        self.seeds = seeds or {"seed-1": b"e" * 32}
        self.loaded: list[str] = []

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the seed for one reference and record the access."""
        self.loaded.append(seed_ref)
        return self.seeds[seed_ref]


def _request(**overrides: object):  # type: ignore[no-untyped-def]
    """Build a complete effect-grant request, overriding selected fields."""
    from phylax.effect_grant import EffectGrantRequest

    values: dict[str, object] = {
        "principal": "principal-1", "run_id": "run-1", "operation_id": "operation-1",
        "request_digest": "a" * 64, "effect_class": "inert.simulation", "ledger_store_id": "ledger-1",
        "consumer_lease_epoch": 3, "second_approval_ref": "approval-1", "issuer_ref": "phylax-1",
        "revocation_ref": "phylax://revocations/v1",
    }
    values.update(overrides)
    return EffectGrantRequest(**values)  # type: ignore[arg-type]


def _build(tmp_path: Path, *, seeds: _Seeds | None = None):  # type: ignore[no-untyped-def]
    """Compose a keyring, a P5 authority and an effect authority over a temp store."""
    from phylax.adjustment_grant import RotatingIssuerKeyring
    from phylax.effect_grant import EffectGrantAuthority
    from phylax.grant_store import SqliteGrantAuthorityStore
    from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority

    provider = seeds or _Seeds()
    store = SqliteGrantAuthorityStore(tmp_path / "grants.sqlite3")
    keyring = RotatingIssuerKeyring(key_id="issuer-1", seed_ref="seed-1", seed_provider=provider, store=store)
    p5 = P5ApprovalAuthority(signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=lambda: NOW)
    authority = EffectGrantAuthority(keyring=keyring, p5_approval=p5, clock=lambda: NOW)
    return authority, keyring, store, p5


class _FailingStore:
    """Delegate to a real store but fail selected reads with a chosen exception."""

    def __init__(self, inner: object, failing: set[str], error: Exception) -> None:
        """Wrap ``inner``; the named read operations raise ``error``."""
        self._inner, self._failing, self._error = inner, failing, error

    def _guard(self, name: str) -> None:
        """Raise the configured failure for a guarded operation."""
        if name in self._failing:
            raise self._error

    def key(self, key_id: str):  # type: ignore[no-untyped-def]
        """Read a key record unless configured to fail."""
        self._guard("key")
        return self._inner.key(key_id)  # type: ignore[attr-defined]

    def is_issued(self, grant_id: str, payload_digest: str, wire: bytes) -> bool:
        """Read issuance unless configured to fail."""
        self._guard("is_issued")
        return self._inner.is_issued(grant_id, payload_digest, wire)  # type: ignore[attr-defined]

    def is_revoked(self, grant_id: str) -> bool:
        """Read revocation unless configured to fail."""
        self._guard("is_revoked")
        return self._inner.is_revoked(grant_id)  # type: ignore[attr-defined]


@pytest.mark.parametrize("operation", ["key", "is_issued", "is_revoked"])
@pytest.mark.parametrize("error", [OSError("disk gone"), sqlite3.OperationalError("unable to open")])
def test_store_failures_are_verifier_unavailable_not_malformed(tmp_path: Path, operation: str, error: Exception) -> None:
    """A broken store must not be reported as a bad grant."""
    from phylax.effect_grant import EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier

    authority, _keyring, store, _p5 = _build(tmp_path)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    verifier = EffectGrantVerifier(store=_FailingStore(store, {operation}, error), clock=lambda: NOW)
    with pytest.raises(EffectGrantRefusal) as refusal:
        verifier.verify(grant.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.VERIFIER_UNAVAILABLE


@pytest.mark.parametrize(
    "clock",
    [lambda: datetime(2026, 10, 25, 12, 0), lambda: "2026-10-25", lambda: (_ for _ in ()).throw(TypeError("bad clock"))],
    ids=["naive", "not-a-datetime", "clock-raises-typeerror"],
)
def test_invalid_clock_is_verifier_unavailable(tmp_path: Path, clock) -> None:  # type: ignore[no-untyped-def]
    """An unusable clock is a verifier fault, not a malformed grant."""
    from phylax.effect_grant import EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier

    authority, _keyring, store, _p5 = _build(tmp_path)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    with pytest.raises(EffectGrantRefusal) as refusal:
        EffectGrantVerifier(store=store, clock=clock).verify(grant.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.VERIFIER_UNAVAILABLE


@pytest.mark.parametrize("wire", [b"not json", b"[]", b'{"a": 1}', b"\xff\xfe", b""], ids=["text", "array", "non-canonical", "bad-utf8", "empty"])
def test_malformed_wire_stays_grant_malformed(tmp_path: Path, wire: bytes) -> None:
    """Parser and validation failures keep the malformed reason, even with a failing clock and store."""
    from phylax.effect_grant import EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier

    _authority, _keyring, store, _p5 = _build(tmp_path)
    verifier = EffectGrantVerifier(store=_FailingStore(store, {"key"}, OSError("down")), clock=lambda: "bad")  # type: ignore[arg-type,return-value]
    with pytest.raises(EffectGrantRefusal) as refusal:
        verifier.verify(wire)
    assert refusal.value.reason is EffectGrantRefusalReason.GRANT_MALFORMED
