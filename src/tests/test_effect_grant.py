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
        """Supply a deterministic signing seed for this issuance scenario."""
        def load_seed(self, seed_ref: str) -> bytes:
            """Return the fixture seed only for its expected reference."""
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
        consumer_lease_epoch=3, second_approval_ref="", issuer_ref="phylax-1",
        revocation_ref="phylax://revocations/v1",
    )

    grant = authority.issue(
        request, authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1"
    )
    verified = authority.verify(grant.to_wire())
    assert (verified.grant_id, verified.second_approval_ref, verified.use_limit) == (
        grant.grant_id, "", 1
    )
    assert verified.expires_at - verified.issued_at == timedelta(seconds=5_400)

    authority.revoke(grant.grant_id)
    with pytest.raises(EffectGrantRefusal) as refusal:
        authority.verify(grant.to_wire())
    assert refusal.value.reason is EffectGrantRefusalReason.GRANT_REVOKED


NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("reference", ["approval-does-not-exist", "contains spaces", "é", "a" * 1025])
def test_unverified_second_approval_never_creates_issuance(tmp_path: Path, reference: str) -> None:
    """Unsupported or malformed approval claims refuse before signing or persistence."""
    authority, _keyring, store, _p5 = _build(tmp_path)
    with pytest.raises(ValueError):
        authority.issue(_request(second_approval_ref=reference), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    with store._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM issued_grants").fetchone()[0] == 0


def test_unqualified_effect_class_refuses_before_approval(tmp_path: Path) -> None:
    """A single approval cannot enable arbitrary real-effect classes."""
    authority, _keyring, _store, _p5 = _build(tmp_path)
    with pytest.raises(ValueError, match="not qualified"):
        authority.issue(_request(effect_class="shell.execute"), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")


def test_issuer_lookup_uses_verified_durable_facts(tmp_path: Path) -> None:
    """Admission facts come from the real signed issuance and expose durable revocation."""
    from phylax.effect_grant import EffectGrantLookup, EffectGrantVerifier
    authority, _keyring, store, _p5 = _build(tmp_path)
    lookup = EffectGrantLookup(store, EffectGrantVerifier(store=store, clock=lambda: NOW))
    assert lookup.get("missing") is None
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    assert lookup.get(grant.grant_id).payload_digest == grant.payload_digest
    assert lookup.get(grant.grant_id).revoked is False
    authority.revoke(grant.grant_id)
    assert lookup.get(grant.grant_id).revoked is True


def test_expired_lookup_preserves_permit_refusal_and_authentication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Expiry belongs to permit admission; signature and issuance remain mandatory."""
    from phylax.effect_grant import EffectGrantLookup, EffectGrantVerifier, EffectGrantRefusal, EffectGrantRefusalReason
    from phylax.dispatch_permit_store import SqliteDispatchPermitStore, PermitRefused
    from phylax.dispatch_composition import DispatchIssuerSigner
    from phylax import dispatch_wire
    authority, keyring, store, _p5 = _build(tmp_path)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    expired_at = grant.expires_at + timedelta(seconds=1)
    verifier = EffectGrantVerifier(store=store, clock=lambda: expired_at)
    lookup = EffectGrantLookup(store, verifier)
    with pytest.raises(EffectGrantRefusal) as strict:
        verifier.verify(grant.to_wire())
    assert strict.value.reason is EffectGrantRefusalReason.GRANT_EXPIRED
    assert lookup.get(grant.grant_id).expires_at == grant.expires_at
    request = dict(grant_id=grant.grant_id, grant_payload_digest=grant.payload_digest, operation_id="operation-1", request_digest="a" * 64, artifact_digest="b" * 64, reservation_id="res-1", ledger_store_id="ledger-1", configuration_policy_epoch=1, authority_epoch=1, consumer_acked_through=0, attempt_id="attempt-1", requested_at=dispatch_wire.timestamp(expired_at))
    permits = SqliteDispatchPermitStore(tmp_path / "permits.sqlite")
    with pytest.raises(PermitRefused) as refused:
        permits.admit(request, grants=lookup, signer=DispatchIssuerSigner(keyring), now=expired_at)
    assert refused.value.code == "permit.grant_expired"
    monkeypatch.setattr(store, "is_issued", lambda *_args: False)
    with pytest.raises(EffectGrantRefusal) as unissued:
        lookup.get(grant.grant_id)
    assert unissued.value.reason is EffectGrantRefusalReason.GRANT_MALFORMED


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
        "consumer_lease_epoch": 3, "second_approval_ref": "", "issuer_ref": "phylax-1",
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

    def issued_wire(self, grant_id: str) -> bytes | None:
        """Read issued wire data unless configured to fail."""
        self._guard("issued_wire")
        return self._inner.issued_wire(grant_id)  # type: ignore[attr-defined]


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


@pytest.mark.parametrize("error", [OSError("disk gone"), sqlite3.OperationalError("unable to open")])
def test_lookup_issued_wire_failures_are_verifier_unavailable(tmp_path: Path, error: Exception) -> None:
    """A durable-wire lookup failure must retain the verifier's closed refusal."""
    from phylax.effect_grant import EffectGrantLookup, EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier

    authority, _keyring, store, _p5 = _build(tmp_path)
    grant = authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    failing_store = _FailingStore(store, {"issued_wire"}, error)
    lookup = EffectGrantLookup(failing_store, EffectGrantVerifier(store=store, clock=lambda: NOW))  # type: ignore[arg-type]
    with pytest.raises(EffectGrantRefusal) as refusal:
        lookup.get(grant.grant_id)
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


def _issue(authority) -> object:  # type: ignore[no-untyped-def]
    """Issue one standard grant from the fixture authority."""
    return authority.issue(_request(), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")


def _reason(verifier, wire: bytes):  # type: ignore[no-untyped-def]
    """Return the refusal reason ``verifier.verify`` raises for ``wire``."""
    from phylax.effect_grant import EffectGrantRefusal

    with pytest.raises(EffectGrantRefusal) as refusal:
        verifier.verify(wire)
    return refusal.value.reason


def _row_counts(store) -> dict[str, int]:  # type: ignore[no-untyped-def]
    """Count rows in every authority table, so a refusal can prove it wrote nothing."""
    with store._connection() as connection:
        return {
            name: connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
            for name in ("issuer_keys", "issued_grants", "grant_revocations", "issuance_audit")
        }


def test_open_effect_verification_store_is_public_and_the_private_name_still_works() -> None:
    """The opener is a documented, exported public name; the old private alias is kept."""
    import phylax
    from phylax import grant_composition

    assert "open_effect_verification_store" in phylax.__all__
    assert phylax.open_effect_verification_store is grant_composition.open_effect_verification_store
    assert grant_composition._open_grant_verification_store is grant_composition.open_effect_verification_store
    assert grant_composition.open_effect_verification_store.__doc__


def test_public_opener_is_the_one_both_verifiers_open_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """open_grant_verifier and open_effect_grant_verifier route via the public opener."""
    from phylax import grant_composition

    calls: list[object] = []

    def _stop(config: object):  # type: ignore[no-untyped-def]
        """Record the call and stop before touching any state."""
        calls.append(config)
        raise grant_composition.CompositionError("stop")

    monkeypatch.setattr(grant_composition, "open_effect_verification_store", _stop)
    config = grant_composition.GrantVerifierConfig(state_dir=tmp_path)
    for opener in (grant_composition.open_grant_verifier, grant_composition.open_effect_grant_verifier):
        with pytest.raises(grant_composition.CompositionError, match="stop"):
            opener(config)
    assert len(calls) == 2


def test_admission_verification_is_private_to_the_lookup(tmp_path: Path) -> None:
    """No public verifier exposes expired-tolerant verification; only the lookup uses it."""
    from phylax.effect_grant import EffectGrantAuthority, EffectGrantLookup, EffectGrantVerifier, PhylaxEffectGrantVerifier

    for cls in (EffectGrantVerifier, PhylaxEffectGrantVerifier, EffectGrantAuthority):
        assert not hasattr(cls, "verify_for_admission")
    assert hasattr(EffectGrantVerifier, "_verify_for_admission")
    authority, _keyring, store, _p5 = _build(tmp_path)
    grant = _issue(authority)
    lookup = EffectGrantLookup(store, EffectGrantVerifier(store=store, clock=lambda: NOW))
    assert lookup.get(grant.grant_id).payload_digest == grant.payload_digest


def _issue_legacy_with_second_approval(keyring, store, reference: str = "approval-legacy-1"):  # type: ignore[no-untyped-def]
    """Persist a validly signed grant carrying a second approval, as pre-e3e954a issuers could."""
    import hashlib

    from phylax.adjustment_grant import P5IssuanceAudit
    from phylax.effect_grant import EffectGrant, _body

    keyring.ensure_current()
    request, grant_id = _request(second_approval_ref=reference), "legacy-grant-1"
    issued_at, expires_at = NOW, NOW + timedelta(seconds=300)
    body, key_id, signature = keyring.sign_effect_grant_snapshot(
        lambda issuer_key_id: _body(request, grant_id=grant_id, issued_at=issued_at, expires_at=expires_at, issuer_key_id=issuer_key_id)
    )
    grant = EffectGrant(request, grant_id, issued_at, expires_at, key_id, hashlib.sha256(body).hexdigest(), signature)
    store.record_issued(grant, P5IssuanceAudit(grant_id, "preview-1", "0" * 64, "1" * 64, 300, NOW))
    return grant


def test_legacy_second_approval_grants_never_verify(tmp_path: Path) -> None:
    """A signed, issued, unrevoked grant with a second approval reference is GRANT_MALFORMED."""
    from phylax.effect_grant import EffectGrantLookup, EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier

    authority, keyring, store, _p5 = _build(tmp_path)
    legacy = _issue_legacy_with_second_approval(keyring, store)
    assert store.is_issued(legacy.grant_id, legacy.payload_digest, legacy.to_wire())
    verifier = EffectGrantVerifier(store=store, clock=lambda: NOW)
    assert _reason(verifier, legacy.to_wire()) is EffectGrantRefusalReason.GRANT_MALFORMED
    assert _reason(authority._verifier, legacy.to_wire()) is EffectGrantRefusalReason.GRANT_MALFORMED
    with pytest.raises(EffectGrantRefusal) as lookup_refusal:
        EffectGrantLookup(store, verifier).get(legacy.grant_id)
    assert lookup_refusal.value.reason is EffectGrantRefusalReason.GRANT_MALFORMED
    assert verifier.verify(_issue(authority).to_wire()).second_approval_ref == ""


def _persist_signed(keyring, store, request, *, issued_at, grant_id, wrong_domain=False):  # type: ignore[no-untyped-def]
    """Persist an issued grant for ``request``, signed correctly or under the wrong domain."""
    import hashlib

    from phylax.adjustment_grant import P5IssuanceAudit
    from phylax.effect_grant import EffectGrant, _body

    keyring.ensure_current()
    expires_at = issued_at + timedelta(seconds=300)
    if wrong_domain:
        key_id = keyring.sign_effect_grant_snapshot(lambda k: _body(request, grant_id=grant_id, issued_at=issued_at, expires_at=expires_at, issuer_key_id=k))[1]
        body = _body(request, grant_id=grant_id, issued_at=issued_at, expires_at=expires_at, issuer_key_id=key_id)
        _key_id, signature = keyring.sign(body)
    else:
        body, key_id, signature = keyring.sign_effect_grant_snapshot(
            lambda k: _body(request, grant_id=grant_id, issued_at=issued_at, expires_at=expires_at, issuer_key_id=k)
        )
    grant = EffectGrant(request, grant_id, issued_at, expires_at, key_id, hashlib.sha256(body).hexdigest(), signature)
    store.record_issued(grant, P5IssuanceAudit(grant_id, "preview-1", "0" * 64, "1" * 64, 300, NOW))
    return grant


def test_signature_check_precedes_second_approval_refusal(tmp_path: Path) -> None:
    """A badly signed grant carrying a second approval reports GRANT_SIGNATURE_INVALID."""
    from phylax.effect_grant import EffectGrantRefusalReason, EffectGrantVerifier

    _authority, keyring, store, _p5 = _build(tmp_path)
    forged = _persist_signed(keyring, store, _request(second_approval_ref="approval-1"), issued_at=NOW, grant_id="order-a", wrong_domain=True)
    verifier = EffectGrantVerifier(store=store, clock=lambda: NOW)
    assert _reason(verifier, forged.to_wire()) is EffectGrantRefusalReason.GRANT_SIGNATURE_INVALID


def test_second_approval_refusal_precedes_future_dated_check(tmp_path: Path) -> None:
    """A validly signed future-dated grant with a second approval reports GRANT_MALFORMED."""
    from phylax.effect_grant import EffectGrantRefusalReason, EffectGrantVerifier

    _authority, keyring, store, _p5 = _build(tmp_path)
    future = NOW + timedelta(hours=1)
    grant = _persist_signed(keyring, store, _request(second_approval_ref="approval-1"), issued_at=future, grant_id="order-b")
    verifier = EffectGrantVerifier(store=store, clock=lambda: NOW)
    assert _reason(verifier, grant.to_wire()) is EffectGrantRefusalReason.GRANT_MALFORMED
    # Control: without the second approval the same grant is future-dated.
    plain = _persist_signed(keyring, store, _request(), issued_at=future, grant_id="order-c")
    assert _reason(verifier, plain.to_wire()) is EffectGrantRefusalReason.GRANT_FUTURE_DATED


def test_revocation_never_masks_key_or_signature_failures(tmp_path: Path) -> None:
    """A revoked grant under an unusable key or bad signature raises that failure, not revoked facts."""
    import hashlib

    from phylax.adjustment_grant import P5IssuanceAudit
    from phylax.effect_grant import EffectGrant, EffectGrantLookup, EffectGrantRefusal, EffectGrantRefusalReason, EffectGrantVerifier, _body

    seeds = _Seeds({"seed-1": b"e" * 32, "seed-2": b"f" * 32})
    authority, keyring, store, _p5 = _build(tmp_path, seeds=seeds)
    verifier = EffectGrantVerifier(store=store, clock=lambda: NOW)
    lookup = EffectGrantLookup(store, verifier)

    # Bad signature: issued and revoked, but signed under the wrong domain.
    good = _issue(authority)
    body = _body(good.request, grant_id="forged-1", issued_at=good.issued_at, expires_at=good.expires_at, issuer_key_id=good.issuer_key_id)
    _key_id, wrong = keyring.sign(body)
    forged = EffectGrant(good.request, "forged-1", good.issued_at, good.expires_at, good.issuer_key_id, hashlib.sha256(body).hexdigest(), wrong)
    store.record_issued(forged, P5IssuanceAudit("forged-1", "preview-x", "0" * 64, "1" * 64, 300, NOW))
    store.revoke("forged-1", revoked_at=NOW)
    assert store.is_revoked("forged-1")
    assert _reason(verifier, forged.to_wire()) is EffectGrantRefusalReason.GRANT_SIGNATURE_INVALID
    with pytest.raises(EffectGrantRefusal) as bad_sig:
        lookup.get("forged-1")
    assert bad_sig.value.reason is EffectGrantRefusalReason.GRANT_SIGNATURE_INVALID

    # Revoked key: the grant is validly signed and revoked, yet its key is no longer trusted.
    authority.revoke(good.grant_id)
    assert _reason(verifier, good.to_wire()) is EffectGrantRefusalReason.GRANT_REVOKED
    keyring.rotate(key_id="issuer-2", seed_ref="seed-2", now=NOW)
    store.revoke_key("issuer-1")
    assert _reason(verifier, good.to_wire()) is EffectGrantRefusalReason.GRANT_KEY_UNKNOWN
    with pytest.raises(EffectGrantRefusal) as dead_key:
        lookup.get(good.grant_id)
    assert dead_key.value.reason is EffectGrantRefusalReason.GRANT_KEY_UNKNOWN

    # Unknown key: the key record is gone entirely.
    with store._connection() as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DELETE FROM issuer_keys WHERE key_id = 'issuer-1'")
    assert _reason(verifier, good.to_wire()) is EffectGrantRefusalReason.GRANT_KEY_UNKNOWN


def test_revoked_and_expired_grant_is_revoked_for_lookup_and_expired_for_verify(tmp_path: Path) -> None:
    """Strict verify refuses expiry first; the lookup still reports revocation and the expiry."""
    from phylax.effect_grant import EffectGrantLookup, EffectGrantRefusalReason, EffectGrantVerifier

    authority, _keyring, store, _p5 = _build(tmp_path)
    grant = _issue(authority)
    authority.revoke(grant.grant_id)
    later = grant.expires_at + timedelta(seconds=1)
    verifier = EffectGrantVerifier(store=store, clock=lambda: later)
    assert _reason(verifier, grant.to_wire()) is EffectGrantRefusalReason.GRANT_EXPIRED
    facts = EffectGrantLookup(store, verifier).get(grant.grant_id)
    assert (facts.revoked, facts.expires_at) == (True, grant.expires_at)


@pytest.mark.parametrize(
    "overrides",
    [{"second_approval_ref": "approval-1"}, {"effect_class": "shell.execute"}],
    ids=["second-approval", "unqualified-class"],
)
def test_issue_refusals_leave_nothing_consumed_or_written(tmp_path: Path, overrides: dict[str, object]) -> None:
    """Refusals precede approval, key creation, signing and persistence."""
    authority, _keyring, store, p5 = _build(tmp_path)
    before = _row_counts(store)
    with pytest.raises(ValueError):
        authority.issue(_request(**overrides), authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://1")
    with pytest.raises(ValueError):
        authority.issue(_request(**overrides), authenticated_principal="someone-else", operator_evidence_ref="trusted-ui://1")
    assert _row_counts(store) == before
    assert [before[name] for name in ("issued_grants", "grant_revocations", "issuance_audit")] == [0, 0, 0]
    assert p5._store._records == {}


def _admit_at(tmp_path: Path, grant, keyring, when):  # type: ignore[no-untyped-def]
    """Build the permit store, request and signer for admitting ``grant`` at ``when``."""
    from phylax import dispatch_wire
    from phylax.dispatch_composition import DispatchIssuerSigner
    from phylax.dispatch_permit_store import SqliteDispatchPermitStore

    request = dict(grant_id=grant.grant_id, grant_payload_digest=grant.payload_digest, operation_id="operation-1", request_digest="a" * 64, artifact_digest="b" * 64, reservation_id="res-1", ledger_store_id="ledger-1", configuration_policy_epoch=1, authority_epoch=1, consumer_acked_through=0, attempt_id="attempt-1", requested_at=dispatch_wire.timestamp(when))
    permits = SqliteDispatchPermitStore(tmp_path / "permits.sqlite")
    return permits, request, DispatchIssuerSigner(keyring)


def _permit_rows(permits) -> list[str]:  # type: ignore[no-untyped-def]
    """Return the stored expiry stamps of every permit row."""
    connection = sqlite3.connect(permits.path)
    try:
        return [row[0] for row in connection.execute("SELECT expires_at FROM dispatch_permits")]
    finally:
        connection.close()


def test_permit_admitted_just_before_grant_expiry_is_capped_at_grant_expiry(tmp_path: Path) -> None:
    """A permit never outlives its grant, even when admitted one second before expiry."""
    from phylax import dispatch_wire
    from phylax.effect_grant import EffectGrantLookup, EffectGrantVerifier

    authority, keyring, store, _p5 = _build(tmp_path)
    grant = _issue(authority)
    when = grant.expires_at - timedelta(seconds=1)
    lookup = EffectGrantLookup(store, EffectGrantVerifier(store=store, clock=lambda: when))
    permits, request, signer = _admit_at(tmp_path, grant, keyring, when)
    permits.admit(request, grants=lookup, signer=signer, now=when)
    assert _permit_rows(permits) == [dispatch_wire.timestamp(grant.expires_at)]


def test_expired_lookup_leaves_the_permit_store_empty(tmp_path: Path) -> None:
    """An expired grant is refused by admission and nothing is persisted."""
    from phylax.dispatch_permit_store import PermitRefused
    from phylax.effect_grant import EffectGrantLookup, EffectGrantVerifier

    authority, keyring, store, _p5 = _build(tmp_path)
    grant = _issue(authority)
    when = grant.expires_at + timedelta(seconds=1)
    lookup = EffectGrantLookup(store, EffectGrantVerifier(store=store, clock=lambda: when))
    permits, request, signer = _admit_at(tmp_path, grant, keyring, when)
    with pytest.raises(PermitRefused) as refused:
        permits.admit(request, grants=lookup, signer=signer, now=when)
    assert refused.value.code == "permit.grant_expired"
    assert _permit_rows(permits) == []
