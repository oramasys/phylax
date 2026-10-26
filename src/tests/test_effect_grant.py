"""Effect-grant v2 issuance and verification contract."""
from __future__ import annotations

import os
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


def test_ledger_store_id_is_bound_into_the_p5_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Requests differing only in ledger target must not share approval claims."""
    from phylax import effect_grant

    monkeypatch.setattr(effect_grant, "token_urlsafe", lambda _n: "fixed-grant-id")
    seen: list[object] = []
    for index, ledger in enumerate(("ledger-1", "ledger-2")):
        authority, _keyring, _store, p5 = _build(tmp_path / f"s{index}")
        original = p5.issue_preview

        def spy(intent, _original=original):  # type: ignore[no-untyped-def]
            """Capture the frozen intent, then delegate."""
            seen.append(intent)
            return _original(intent)

        monkeypatch.setattr(p5, "issue_preview", spy)
        authority.issue(_request(ledger_store_id=ledger), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    first, second = seen
    assert first.preview_payload()["assignments"][0]["ledger_store_id"] == "ledger-1"  # type: ignore[attr-defined]
    assert first.preview_digest() != second.preview_digest()  # type: ignore[attr-defined]
    assert first.claims() != second.claims()  # type: ignore[attr-defined]


def test_rotation_between_approval_and_signing_does_not_strand_the_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A key rotated by another authority after consume still yields a valid grant."""
    from phylax.adjustment_grant import RotatingIssuerKeyring
    from phylax.effect_grant import EffectGrantVerifier

    seeds = _Seeds({"seed-1": b"e" * 32, "seed-2": b"f" * 32})
    authority, _keyring, store, p5 = _build(tmp_path, seeds=seeds)
    other = RotatingIssuerKeyring(key_id="issuer-1", seed_ref="seed-1", seed_provider=seeds, store=store)
    original_consume = p5.consume
    consumed: list[object] = []

    def consume_then_rotate(receipt, intent):  # type: ignore[no-untyped-def]
        """Spend the approval, then let another authority rotate the shared key."""
        decision = original_consume(receipt, intent)
        consumed.append(receipt)
        other.rotate(key_id="issuer-2", seed_ref="seed-2", now=NOW)
        return decision

    monkeypatch.setattr(p5, "consume", consume_then_rotate)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    assert len(consumed) == 1
    assert grant.issuer_key_id == "issuer-2"
    assert EffectGrantVerifier(store=store, clock=lambda: NOW).verify(grant.to_wire()).grant_id == grant.grant_id


def test_snapshot_signing_pairs_one_key_id_with_its_own_seed(tmp_path: Path) -> None:
    """The body builder sees the same key id that the returned signature belongs to."""
    from phylax.adjustment_grant import RotatingIssuerKeyring

    seeds = _Seeds({"seed-1": b"e" * 32, "seed-2": b"f" * 32})
    _authority, keyring, store, _p5 = _build(tmp_path, seeds=seeds)
    RotatingIssuerKeyring(key_id="issuer-1", seed_ref="seed-1", seed_provider=seeds, store=store).rotate(
        key_id="issuer-2", seed_ref="seed-2", now=NOW
    )
    seen: list[str] = []
    body, key_id, _signature = keyring.sign_effect_grant_snapshot(lambda kid: seen.append(kid) or b"body")
    assert (body, key_id, seen) == (b"body", "issuer-2", ["issuer-2"])


@pytest.mark.parametrize(
    ("field", "original", "variant"),
    [
        ("use_limit", b'"use_limit":1', b'"use_limit":true'),
        ("use_limit", b'"use_limit":1', b'"use_limit":1.0'),
        ("consumer_lease_epoch", b'"consumer_lease_epoch":3', b'"consumer_lease_epoch":3.0'),
        ("consumer_lease_epoch", b'"consumer_lease_epoch":3', b'"consumer_lease_epoch":true'),
    ],
    ids=["use_limit-true", "use_limit-float", "epoch-float", "epoch-true"],
)
def test_from_wire_rejects_non_integer_numeric_spellings(tmp_path: Path, field: str, original: bytes, variant: bytes) -> None:
    """Values that merely compare equal to an integer must not be silently rewritten."""
    from phylax.effect_grant import EffectGrant

    authority, _keyring, _store, _p5 = _build(tmp_path)
    wire = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1").to_wire()
    assert EffectGrant.from_wire(wire).to_wire() == wire
    assert original in wire
    with pytest.raises(ValueError, match="malformed"):
        EffectGrant.from_wire(wire.replace(original, variant))


def test_a_body_signed_under_the_recovery_domain_is_rejected(tmp_path: Path) -> None:
    """The verifier must require the v2 effect domain, not merely any shared domain."""
    from phylax.adjustment_grant import _b64decode
    from phylax.effect_grant import (
        EffectGrant,
        EffectGrantRefusal,
        EffectGrantRefusalReason,
        EffectGrantVerifier,
    )

    authority, keyring, store, _p5 = _build(tmp_path)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    verifier = EffectGrantVerifier(store=store, clock=lambda: NOW)
    assert verifier.verify(grant.to_wire()).grant_id == grant.grant_id

    key_id, recovery_signature = keyring.sign(grant.canonical_body())
    assert key_id == grant.issuer_key_id
    assert recovery_signature != grant.issuer_signature
    forged = EffectGrant(
        grant.request, grant.grant_id, grant.issued_at, grant.expires_at, grant.issuer_key_id,
        grant.payload_digest, recovery_signature,
    )
    assert len(_b64decode(forged.issuer_signature)) == len(_b64decode(grant.issuer_signature))
    with pytest.raises(EffectGrantRefusal) as refusal:
        verifier.verify(forged.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.GRANT_SIGNATURE_INVALID


class _ReadOnlyStore:
    """Stand-in for the POSIX-only verification store: reads only, no mutators."""

    def __init__(self, path: Path) -> None:
        """Open the persisted authority database and expose only read operations."""
        from phylax.grant_store import SqliteGrantAuthorityStore

        inner = SqliteGrantAuthorityStore(path)
        self.key, self.is_issued, self.is_revoked = inner.key, inner.is_issued, inner.is_revoked

    def close(self) -> None:
        """Mirror the verification store's lifecycle method."""


def _verify_persisted_issuance(tmp_path: Path, state: Path, seeds: _Seeds) -> None:
    """Issue durably, then verify and revoke through open_effect_grant_verifier only."""
    from phylax.effect_grant import EffectGrantRefusal, EffectGrantRefusalReason, PhylaxEffectGrantVerifier
    from phylax.grant_composition import GrantVerifierConfig, open_effect_grant_verifier

    authority, _keyring, _store, _p5 = _build(state, seeds=seeds)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    loads_after_issue = list(seeds.loaded)

    verifier = open_effect_grant_verifier(GrantVerifierConfig(state_dir=state), clock=lambda: NOW)
    try:
        assert isinstance(verifier, PhylaxEffectGrantVerifier)
        assert verifier.verify(grant.to_wire()).grant_id == grant.grant_id
        assert not hasattr(verifier, "issue") and not hasattr(verifier, "revoke")
        authority.revoke(grant.grant_id)
        with pytest.raises(EffectGrantRefusal) as refusal:
            verifier.verify(grant.to_wire())
        assert refusal.value.reason is EffectGrantRefusalReason.GRANT_REVOKED
    finally:
        verifier.close()
    assert seeds.loaded == loads_after_issue  # the verifier never touched seed material
    assert not (tmp_path / "seeds").exists()


def test_open_effect_grant_verifier_reads_persisted_issuance_without_seed_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Composition wiring with the POSIX-only store and path checks replaced by stand-ins."""
    from phylax import grant_composition

    monkeypatch.setattr(grant_composition, "_require_private", lambda path, **_kw: None)
    monkeypatch.setattr(grant_composition, "SqliteGrantVerificationStore", _ReadOnlyStore)
    state = tmp_path / "state"
    state.mkdir()
    _verify_persisted_issuance(tmp_path, state, _Seeds())


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid"),
    reason="the real verification store needs POSIX private-file semantics (Linux CI)",
)
def test_open_effect_grant_verifier_real_store_without_seed_access(tmp_path: Path) -> None:
    """End to end on the real read-only SQLite verification store, with no seed available."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    database = state / "grants.sqlite3"
    database.touch(mode=0o600)
    database.chmod(0o600)
    _verify_persisted_issuance(tmp_path, state, _Seeds())
