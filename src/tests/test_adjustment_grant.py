"""Issuer-side adjustment grant tests for P5 binding and Ed25519ph attestations."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import unicodedata

from nacl.bindings import crypto_sign_seed_keypair
import pytest

from phylax.adjustment_grant import (
    AdjustmentGrant,
    AdjustmentGrantRequest,
    GrantRefusal,
    GrantRefusalReason,
    PhylaxGrantAuthority,
    RotatingIssuerKeyring,
    SqliteGrantAuthorityStore,
    _canonical_bytes,
    _b64decode,
    _b64encode,
    _grant_body,
    _sign,
    _sign_message,
    _verify,
    _verify_message,
)
from phylax.grant_store import IssuerKeyRecord
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority


class Clock:
    """Mutable shared UTC clock for P5 and grant authority tests."""

    def __init__(self) -> None:
        """Start at a fixed, microsecond-stable UTC instant."""
        self.now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        """Return the current deterministic time."""
        return self.now


class SeedMap:
    """Test-only protected-source stand-in keyed by opaque references."""

    def load_seed(self, seed_ref: str) -> bytes:
        """Return the fixed test seed for a known reference."""
        return {"secret-ref:issuer-1": b"a" * 32, "secret-ref:issuer-2": b"b" * 32}[seed_ref]


def request(**overrides: object) -> AdjustmentGrantRequest:
    """Return a complete immutable target tuple for a human-approved adjustment."""
    values: dict[str, object] = {
        "principal": "operator-1",
        "run_id": "run-1",
        "hold_id": "hold-1",
        "kind": "settle",
        "units": 3,
        "units_basis": "steps",
        "ledger_cost_basis": "legacy_step_only",
        "evidence_digest": "a" * 64,
        "hold_fence_epoch": 4,
        "consumer_lease_epoch": 7,
        "ledger_store_id": "ledger-primary",
        "issuer_ref": "phylax-primary",
        "revocation_ref": "phylax://revocations/v1",
    }
    values.update(overrides)
    return AdjustmentGrantRequest(**values)  # type: ignore[arg-type]


def authority(
    clock: Clock, path: str | Path
) -> tuple[PhylaxGrantAuthority, InMemoryP5ApprovalStore, SqliteGrantAuthorityStore]:
    """Return a P5-backed issuer and the test store used to inspect bound intent."""
    grant_store = SqliteGrantAuthorityStore(path)
    p5_store = InMemoryP5ApprovalStore()
    p5 = P5ApprovalAuthority(
        signing_key=b"p5-test-secret",
        store=p5_store,
        clock=clock,
    )
    seed_provider = SeedMap()
    return (
        PhylaxGrantAuthority(
            keyring=RotatingIssuerKeyring(
                key_id="issuer-1",
                seed_ref="secret-ref:issuer-1",
                seed_provider=seed_provider,
                store=grant_store,
            ),
            p5_approval=p5,
            clock=clock,
        ),
        p5_store,
        grant_store,
    )


def issue(policy: PhylaxGrantAuthority, *, duration: int | None = None) -> AdjustmentGrant:
    """Issue one grant through the trusted-evidence P5 path."""
    return policy.issue(
        request(),
        authenticated_principal="operator-1",
        operator_evidence_ref="trusted-ui://approval/1",
        approved_duration_seconds=duration,
    )


def test_issue_binds_the_complete_target_to_p5_and_ed25519ph(tmp_path: Path) -> None:
    """Human issuance derives its duration from P5 and signs the exact target body."""
    clock = Clock()
    policy, p5_store, _grant_store = authority(clock, tmp_path / "grants.db")

    grant = issue(policy)

    policy.verify(grant.to_wire())
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


def test_issue_requires_authenticated_principal_match(tmp_path: Path) -> None:
    """Transport authentication cannot mint a grant for another principal."""
    policy, _p5_store, _grant_store = authority(Clock(), tmp_path / "grants.db")

    with pytest.raises(ValueError, match="authenticated principal"):
        policy.issue(
            request(),
            authenticated_principal="different-principal",
            operator_evidence_ref="trusted-ui://approval/1",
        )


def test_mutated_signed_fields_and_signature_are_rejected(tmp_path: Path) -> None:
    """Digest validation and Ed25519ph verification reject independent tampering."""
    policy, _p5_store, _grant_store = authority(Clock(), tmp_path / "grants.db")
    grant = issue(policy)

    with pytest.raises(ValueError, match="payload_digest"):
        replace(grant, units=grant.units + 1)
    replacement = "A" if grant.issuer_signature[0] != "A" else "B"
    tampered = replace(grant, issuer_signature=replacement + grant.issuer_signature[1:])
    with pytest.raises(GrantRefusal) as refusal:
        policy.verify(tampered.to_wire())
    assert refusal.value.reason is GrantRefusalReason.GRANT_SIGNATURE_INVALID


def test_verify_refuses_future_expired_and_revoked_grants(tmp_path: Path) -> None:
    """Issuer verification enforces the ratified 60-second skew and revocation rules."""
    clock = Clock()
    policy, _p5_store, _grant_store = authority(clock, tmp_path / "first.db")
    grant = issue(policy)

    clock.now += timedelta(seconds=5_401)
    with pytest.raises(GrantRefusal) as expired:
        policy.verify(grant.to_wire())
    assert expired.value.reason is GrantRefusalReason.GRANT_EXPIRED

    clock = Clock()
    policy, _p5_store, _grant_store = authority(clock, tmp_path / "second.db")
    grant = issue(policy)
    policy.revoke(grant.grant_id)
    with pytest.raises(GrantRefusal) as revoked:
        policy.verify(grant.to_wire())
    assert revoked.value.reason is GrantRefusalReason.GRANT_REVOKED

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
    with pytest.raises(GrantRefusal) as future_refusal:
        policy.verify(future.to_wire())
    assert future_refusal.value.reason is GrantRefusalReason.GRANT_FUTURE_DATED


def test_retired_key_retains_old_grants_until_floor_then_prunes(tmp_path: Path) -> None:
    """Rotation preserves verification through the monotonic retired-key window."""
    clock = Clock()
    policy, _p5_store, _grant_store = authority(clock, tmp_path / "grants.db")
    grant = issue(policy)
    keyring = policy._keyring
    keyring.rotate(
        key_id="issuer-2", seed_ref="secret-ref:issuer-2", now=clock.now
    )

    policy.verify(grant.to_wire())
    assert keyring.retention_for("issuer-1") == clock.now + timedelta(hours=24)
    assert keyring.prune(now=clock.now + timedelta(hours=24)) == ()
    assert keyring.prune(now=clock.now + timedelta(hours=24, microseconds=1)) == ("issuer-1",)
    with pytest.raises(GrantRefusal) as refusal:
        policy.verify(grant.to_wire())
    assert refusal.value.reason is GrantRefusalReason.GRANT_KEY_UNKNOWN


def test_request_rejects_ambiguous_units_and_digest() -> None:
    """A grant target has no implicit unit dimension or malformed evidence digest."""
    with pytest.raises(ValueError, match="units must"):
        request(units=True)
    with pytest.raises(ValueError, match="evidence_digest"):
        request(evidence_digest="ABC")
    with pytest.raises(ValueError, match="interoperable integer"):
        request(units=2**53)


def test_p5_action_is_bound_and_grant_duration_is_selected_at_approval(tmp_path: Path) -> None:
    """P5 approval binds the action and fixes the grant duration at approval time."""
    clock = Clock()
    policy, p5_store, _grant_store = authority(clock, tmp_path / "grants.db")

    grant = issue(policy, duration=900)
    audit = policy.issuance_audit(grant.grant_id)

    assert grant.expires_at - grant.issued_at == timedelta(seconds=900)
    assert audit is not None and audit.approved_duration_seconds == 900
    stored = p5_store.get(audit.approval_id)
    assert stored is not None
    assert stored.preview.intent.action == "phylax.adjustment_grant.issue"
    assert stored.preview.intent.claims()["action"] == "phylax.adjustment_grant.issue"


def test_durable_grant_state_survives_authority_restart(tmp_path: Path) -> None:
    """Durable grant state survives restarting the authority."""
    clock = Clock()
    database = tmp_path / "grants.db"
    policy, _p5_store, store = authority(clock, database)
    grant = issue(policy)
    grant_wire = grant.to_wire()
    policy.revoke(grant.grant_id)
    audit = policy.issuance_audit(grant.grant_id)
    assert audit is not None
    assert not hasattr(audit, "operator_evidence_ref")

    restarted_store = SqliteGrantAuthorityStore(database)
    restarted = PhylaxGrantAuthority(
        keyring=RotatingIssuerKeyring(
            key_id="issuer-1",
            seed_ref="secret-ref:issuer-1",
            seed_provider=SeedMap(),
            store=restarted_store,
        ),
        p5_approval=policy._p5_approval,
        clock=clock,
    )

    with pytest.raises(GrantRefusal) as refusal:
        restarted.verify(grant_wire)
    assert refusal.value.reason is GrantRefusalReason.GRANT_REVOKED
    assert restarted.issuance_audit(grant.grant_id) == audit
    assert restarted.revocation(grant.grant_id).revoked is True
    assert restarted_store.issued_wire(grant.grant_id) == grant_wire


def test_verifier_returns_only_consumer_facts_and_closed_refusal(tmp_path: Path) -> None:
    """The verifier exposes only consumer facts and a closed refusal vocabulary."""
    clock = Clock()
    policy, _p5_store, _grant_store = authority(clock, tmp_path / "grants.db")
    grant = issue(policy)

    verifier = policy.verifier_adapter()
    verified = verifier.verify(grant.to_wire())

    assert verified.grant_id == grant.grant_id
    assert verified.payload_digest == grant.payload_digest
    assert verified.verifier_id == "phylax-primary"
    assert not hasattr(verified, "issuer_key_id")
    assert not hasattr(verifier, "issue")
    assert verifier.revocation(grant.grant_id).revoked is False
    with pytest.raises(GrantRefusal) as refusal:
        policy.verify(b"not-json")
    assert refusal.value.reason is GrantRefusalReason.GRANT_MALFORMED


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("grant_id", "altered-grant"),
        ("principal", "altered-principal"),
        ("run_id", "altered-run"),
        ("hold_id", "altered-hold"),
        ("kind", "release"),
        ("units", 4),
        ("units_basis", "elapsed_ms"),
        ("ledger_cost_basis", "altered-basis"),
        ("evidence_digest", "b" * 64),
        ("hold_fence_epoch", 5),
        ("consumer_lease_epoch", 8),
        ("ledger_store_id", "altered-store"),
        ("issued_at", "2026-10-12T12:00:01.000000Z"),
        ("expires_at", "2026-10-12T13:30:01.000000Z"),
        ("issuer_key_id", "unknown-key"),
        ("issuer_ref", "altered-issuer"),
        ("revocation_ref", "altered-revocation-ref"),
        ("payload_digest", "b" * 64),
    ],
)
def test_independent_wire_field_mutation_is_refused(
    tmp_path: Path, field: str, value: object
) -> None:
    """Every grant envelope field is covered by strict parsing or signature validation."""
    policy, _p5_store, _grant_store = authority(Clock(), tmp_path / "grants.db")
    grant = issue(policy)
    payload = json.loads(grant.to_wire())
    payload[field] = value

    with pytest.raises(GrantRefusal):
        policy.verify(_canonical_bytes(payload))


def test_durable_rotation_keeps_previous_public_key_and_live_grant(tmp_path: Path) -> None:
    """A restarted keyring verifies old grants through the persisted retention window."""
    clock = Clock()
    database = tmp_path / "grants.db"
    policy, _p5_store, _store = authority(clock, database)
    grant = issue(policy)
    policy._keyring.rotate(
        key_id="issuer-2", seed_ref="secret-ref:issuer-2", now=clock.now
    )
    reopened = SqliteGrantAuthorityStore(database)
    restarted = PhylaxGrantAuthority(
        keyring=RotatingIssuerKeyring(
            key_id="issuer-2",
            seed_ref="secret-ref:issuer-2",
            seed_provider=SeedMap(),
            store=reopened,
        ),
        p5_approval=policy._p5_approval,
        clock=clock,
    )

    assert restarted.verify(grant.to_wire()).grant_id == grant.grant_id
    assert restarted._keyring.retention_for("issuer-1") == clock.now + timedelta(hours=24)


def test_verifier_fails_closed_when_durable_state_is_unavailable(tmp_path: Path) -> None:
    """Storage failure maps to the sole closed verifier-unavailable refusal."""
    database = tmp_path / "grants.db"
    policy, _p5_store, _store = authority(Clock(), database)
    grant = issue(policy)
    database.unlink()
    database.mkdir()

    with pytest.raises(GrantRefusal) as refusal:
        policy.verify(grant.to_wire())
    assert refusal.value.reason is GrantRefusalReason.VERIFIER_UNAVAILABLE


def test_sqlite_grant_store_rejects_ephemeral_database() -> None:
    """An in-memory database is rejected because grant state must be durable."""
    with pytest.raises(ValueError, match="durable file path"):
        SqliteGrantAuthorityStore(":memory:")


def test_sqlite_grant_store_rejects_incompatible_existing_schema(tmp_path: Path) -> None:
    """An existing database with an incompatible schema is rejected."""
    database = tmp_path / "incompatible.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE issuer_keys (key_id TEXT PRIMARY KEY)")
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="schema is incompatible"):
        SqliteGrantAuthorityStore(database)


def test_shared_grant_vector_is_stable_and_verifies() -> None:
    """The checked-in cross-repository vector fixes bytes, digest and Ed25519ph output."""
    vector_path = Path(__file__).parents[2] / "docs" / "vectors" / "adjustment-grant-v1.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    body = vector["canonical_bytes"].encode("utf-8")
    wire = vector["wire"].encode("utf-8")
    seed = bytes(range(32))
    public_key, signature = _sign(seed, body)

    parsed = AdjustmentGrant.from_wire(wire)
    assert parsed.canonical_body() == body
    assert parsed.to_wire() == wire
    assert hashlib.sha256(body).hexdigest() == vector["payload_digest"]
    assert public_key.hex() == vector["public_key"]
    assert _b64encode(signature) == vector["signature"]
    assert _verify(public_key, body, _b64decode(vector["signature"]))


def test_wire_parser_rejects_duplicate_keys_and_preserves_unicode(tmp_path: Path) -> None:
    """Parsing rejects duplicate names and canonical bytes do not normalize text."""
    policy, _p5_store, _grant_store = authority(Clock(), tmp_path / "grants.db")
    grant = issue(policy)
    wire = grant.to_wire()
    duplicate = wire.replace(b'"grant_id":', b'"grant_id":"shadow","grant_id":', 1)
    with pytest.raises(GrantRefusal) as refusal:
        policy.verify(duplicate)
    assert refusal.value.reason is GrantRefusalReason.GRANT_MALFORMED

    composed = request(principal=unicodedata.normalize("NFC", "e\u0301"))
    decomposed = request(principal=unicodedata.normalize("NFD", "e\u0301"))
    common = {
        "grant_id": "unicode-vector",
        "issued_at": Clock().now,
        "expires_at": Clock().now + timedelta(minutes=1),
        "issuer_key_id": "issuer-1",
    }
    assert _grant_body(composed, **common) != _grant_body(decomposed, **common)


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


@pytest.mark.parametrize("field_name", ["hold_fence_epoch", "consumer_lease_epoch"])
def test_zero_epoch_is_refused_because_no_lease_can_consume_it(field_name: str) -> None:
    """Ledger leases start at epoch 1; a grant naming epoch 0 is unspendable."""
    with pytest.raises(ValueError, match="interoperable integer"):
        request(**{field_name: 0})


def test_issuance_follows_a_rotation_made_by_another_authority(tmp_path: Path) -> None:
    """A worker that missed a rotation adopts the durable active key before issuing."""
    clock = Clock()
    first, _, _ = authority(clock, tmp_path / "shared.db")
    second, _, _ = authority(clock, tmp_path / "shared.db")
    first._keyring.rotate(key_id="issuer-2", seed_ref="secret-ref:issuer-2", now=clock.now)

    grant = issue(second)  # second still cached issuer-1 at construction

    assert grant.issuer_key_id == "issuer-2"
    second.verify(grant.to_wire())
    first.verify(grant.to_wire())


def test_initial_key_registration_is_idempotent_only_for_a_pristine_registry(
    tmp_path: Path,
) -> None:
    """Only the exact lone initial record may be registered more than once."""
    store = SqliteGrantAuthorityStore(tmp_path / "keys.db")
    initial = IssuerKeyRecord(
        "issuer-1", b"1" * 32, "secret-ref:issuer-1", "active", None, None, None
    )
    replacement = IssuerKeyRecord(
        "issuer-2", b"2" * 32, "secret-ref:issuer-2", "active", None, None, None
    )
    store.register_initial_key(initial)
    store.register_initial_key(initial)

    with pytest.raises(ValueError, match="already initialized"):
        store.register_initial_key(replacement)

    store.rotate_key(replacement, now=Clock().now)
    with pytest.raises(ValueError, match="already initialized"):
        store.register_initial_key(replacement)

    now = Clock().now
    revoked_store = SqliteGrantAuthorityStore(tmp_path / "revoked.db")
    revoked = IssuerKeyRecord(
        "issuer-1", b"1" * 32, "secret-ref:issuer-1", "revoked",
        now, now + timedelta(minutes=1), None,
    )
    revoked_store.register_initial_key(revoked)
    with pytest.raises(ValueError, match="already initialized"):
        revoked_store.register_initial_key(revoked)

    historical_store = SqliteGrantAuthorityStore(tmp_path / "historical.db")
    historical = replace(initial, latest_live_expiry=now + timedelta(minutes=1))
    historical_store.register_initial_key(historical)
    with pytest.raises(ValueError, match="already initialized"):
        historical_store.register_initial_key(historical)


class _StaleRegistryReads(SqliteGrantAuthorityStore):
    """Store whose outside-transaction reads observe a registry another worker then fills."""

    def __init__(self, path: Path, rival: SqliteGrantAuthorityStore, record: IssuerKeyRecord) -> None:
        """Remember the rival worker and the key it will commit between read and write."""
        super().__init__(path)
        self._rival = rival
        self._record = record

    def active_key(self) -> IssuerKeyRecord | None:
        """Report the empty registry, then let the rival worker commit the same key."""
        self._rival.register_initial_key(self._record)
        return None


def test_concurrent_first_key_startup_adopts_the_rival_commit(tmp_path: Path) -> None:
    """Worker B sees an empty registry, worker A commits, and B must adopt A's key."""
    database = tmp_path / "keys.db"
    seed_provider = SeedMap()
    public_key, _ = crypto_sign_seed_keypair(seed_provider.load_seed("secret-ref:issuer-1"))
    record = IssuerKeyRecord(
        "issuer-1", public_key, "secret-ref:issuer-1", "active", None, None, None
    )
    rival = SqliteGrantAuthorityStore(database)
    racing = _StaleRegistryReads(database, rival, record)

    keyring = RotatingIssuerKeyring(
        key_id="issuer-1",
        seed_ref="secret-ref:issuer-1",
        seed_provider=seed_provider,
        store=racing,
    )

    assert keyring.active_key_id == "issuer-1"
    assert len(rival.keys()) == 1


def test_first_key_startup_still_rejects_a_registry_without_an_active_key(tmp_path: Path) -> None:
    """Adoption never papers over a revoked-only or conflicting registry."""
    store = SqliteGrantAuthorityStore(tmp_path / "keys.db")
    now = Clock().now
    store.register_initial_key(
        IssuerKeyRecord(
            "issuer-1", b"1" * 32, "secret-ref:issuer-1", "revoked",
            now, now + timedelta(minutes=1), None,
        )
    )
    with pytest.raises(ValueError, match="no active key"):
        RotatingIssuerKeyring(
            key_id="issuer-1", seed_ref="secret-ref:issuer-1",
            seed_provider=SeedMap(), store=store,
        )


def test_rotation_between_signing_and_recording_does_not_strand_the_approval(tmp_path: Path) -> None:
    """A key retired after signing still records the grant and extends its retention."""
    clock = Clock()
    policy, _, store = authority(clock, tmp_path / "shared.db")
    original = store.record_issued

    def rotate_then_record(grant, audit):
        """Rotate the key between signing and recording, then record the grant."""
        policy._keyring.rotate(key_id="issuer-2", seed_ref="secret-ref:issuer-2", now=clock.now)
        return original(grant, audit)

    store.record_issued = rotate_then_record  # type: ignore[method-assign]
    grant = issue(policy)

    assert grant.issuer_key_id == "issuer-1"
    policy.verify(grant.to_wire())
    retired = store.key("issuer-1")
    assert retired is not None and retired.status == "retired"
    assert retired.retain_until >= grant.expires_at + timedelta(seconds=60)


def test_request_text_is_capped_so_an_issued_grant_always_parses() -> None:
    """The cap is shared by issuance and parsing: no grant is signed then refused."""
    request(run_id="r" * 1_024)
    with pytest.raises(ValueError, match="exceeds"):
        request(run_id="r" * 1_025)


def test_worst_case_escaped_request_still_fits_the_wire_limit(tmp_path: Path) -> None:
    """Control characters expand six-fold in JSON; the cap still leaves headroom."""
    clock = Clock()
    policy, _, _ = authority(clock, tmp_path / "p.db")
    heavy = "\x01" * 1_024
    grant = policy.issue(
        request(principal=heavy, run_id=heavy, hold_id=heavy, ledger_cost_basis=heavy,
                ledger_store_id=heavy, issuer_ref=heavy, revocation_ref=heavy),
        authenticated_principal=heavy,
        operator_evidence_ref="trusted-ui://approval/1",
    )
    assert len(grant.to_wire()) < 65_536
    policy.verify(grant.to_wire())


def test_deeply_nested_wire_is_a_malformed_refusal_not_a_recursion_error(tmp_path: Path) -> None:
    """Nested JSON below the size limit still maps into the closed vocabulary."""
    policy, _, _ = authority(Clock(), tmp_path / "p.db")
    nested = b"[" * 20_000 + b"]" * 20_000
    with pytest.raises(GrantRefusal) as refused:
        policy.verify(nested)
    assert refused.value.reason is GrantRefusalReason.GRANT_MALFORMED


@pytest.mark.parametrize("bad_clock", [lambda: datetime(2026, 1, 1), lambda: "not-a-time"])
def test_revocation_reports_clock_faults_as_verifier_unavailable(tmp_path: Path, bad_clock) -> None:
    """Both adapter methods share one refusal contract for a faulty clock."""
    policy, _, _ = authority(Clock(), tmp_path / "p.db")
    policy._clock = bad_clock
    with pytest.raises(GrantRefusal) as refused:
        policy.revocation("grant-1")
    assert refused.value.reason is GrantRefusalReason.VERIFIER_UNAVAILABLE
