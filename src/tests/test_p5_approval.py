"""Strict P5 approval tests: no boolean bypass, drift rejection, and one-time use."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from phylax.p5_approval import (
    InMemoryP5ApprovalStore,
    P5ApprovalAuthority,
    P5ApprovalIntent,
    P5ApprovalReceipt,
    SqliteP5ApprovalStore,
)


class Clock:
    """Mutable UTC clock used for deterministic expiry tests."""

    def __init__(self) -> None:
        """Start at a fixed instant."""
        self.now = datetime(2026, 10, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        """Return the current fixed instant."""
        return self.now


def intent() -> P5ApprovalIntent:
    """Return one immutable swarm-launch approval intent."""
    return P5ApprovalIntent.from_preview(
        "control-plane",
        {
            "objective": "verify a change",
            "task_type": "code-review",
            "optimize_for": "safety",
            "preferred_device": "shared",
            "assignments": [{"role": "reviewer"}, {"role": "verifier"}],
        },
    )


def authority(clock: Clock | None = None) -> P5ApprovalAuthority:
    """Return a strict authority with injected in-memory state."""
    return P5ApprovalAuthority(signing_key=b"test-p5-secret", store=InMemoryP5ApprovalStore(), clock=clock)


def approved(policy: P5ApprovalAuthority) -> P5ApprovalReceipt:
    """Issue then bind trusted operator evidence to one preview."""
    preview = policy.issue_preview(intent())
    return policy.approve(preview.preview_id, operator_evidence_ref="audit://operator/decision-1")


def test_p5_binds_immutable_intent_and_consumes_a_receipt_once() -> None:
    """A verified receipt returns its exact intent once and cannot replay."""
    policy = authority()
    receipt = approved(policy)

    decision = policy.consume(receipt, intent())

    assert decision.intent == intent()
    assert decision.operator_evidence_ref == "audit://operator/decision-1"
    assert decision.approved_duration_seconds == 5_400
    with pytest.raises(ValueError, match="already consumed"):
        policy.consume(receipt, intent())


def test_p5_rejects_payload_drift_even_with_a_valid_token() -> None:
    """A receipt for one preview cannot authorize changed swarm assignments."""
    policy = authority()
    receipt = approved(policy)

    with pytest.raises(ValueError, match="intent mismatch"):
        policy.consume(
            receipt,
            P5ApprovalIntent.from_preview(
                "control-plane",
                {**intent().preview_payload(), "assignments": [{"role": "different-reviewer"}]},
            ),
        )


def test_p5_binds_protected_action_separately_from_the_preview() -> None:
    """The default swarm action remains stable and grant actions cannot cross-use receipts."""
    policy = authority()
    grant_action = P5ApprovalIntent.from_preview(
        "control-plane",
        intent().preview_payload(),
        action="phylax.adjustment_grant.issue",
    )
    assert intent().claims()["action"] == "swarm.launch"
    assert grant_action.claims()["action"] == "phylax.adjustment_grant.issue"
    receipt = policy.approve(
        policy.issue_preview(intent()).preview_id,
        operator_evidence_ref="audit://operator/decision-1",
    )

    with pytest.raises(ValueError, match="intent mismatch"):
        policy.consume(receipt, grant_action)


def test_p5_rejects_tampered_token_without_consuming_the_valid_receipt() -> None:
    """Bad MAC text fails closed and leaves the valid receipt usable."""
    policy = authority()
    receipt = approved(policy)
    encoded_body, encoded_mac = receipt.approval_token.split(".", 1)
    replacement = "A" if encoded_mac[0] != "A" else "B"
    tampered = replace(receipt, approval_token=f"{encoded_body}.{replacement}{encoded_mac[1:]}")

    with pytest.raises(ValueError, match="invalid P5 approval token"):
        policy.consume(tampered, intent())
    assert policy.consume(receipt, intent()).intent == intent()


def test_p5_token_binds_preview_by_digest_without_exposing_raw_preview_or_evidence() -> None:
    """The signed receipt carries a digest, not assignments or evidence text."""
    import base64
    import json

    policy = authority()
    receipt = approved(policy)
    encoded_payload = receipt.approval_token.split(".", 1)[0]
    payload = json.loads(base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4)))

    assert payload["preview_digest"] == intent().preview_digest()
    assert "assignments" not in payload
    assert "operator_evidence_ref" not in payload


def test_p5_requires_operator_evidence_and_has_no_boolean_approval_path() -> None:
    """Approval requires opaque trusted evidence rather than a client approved flag."""
    policy = authority()
    preview = policy.issue_preview(intent())

    with pytest.raises(ValueError, match="operator_evidence_ref is required"):
        policy.approve(preview.preview_id, operator_evidence_ref="")


def test_p5_expiry_applies_before_approval_and_before_consumption() -> None:
    """Expired previews cannot be approved or consumed."""
    clock = Clock()
    policy = authority(clock)
    preview = policy.issue_preview(intent())
    clock.now += timedelta(minutes=5)

    with pytest.raises(ValueError, match="expired"):
        policy.approve(preview.preview_id, operator_evidence_ref="audit://operator/decision-1")

    clock = Clock()
    policy = authority(clock)
    receipt = approved(policy)
    clock.now += timedelta(minutes=5)
    with pytest.raises(ValueError, match="expired"):
        policy.consume(receipt, intent())
    # A retry on an expired receipt still consistently raises expired, not 'already consumed'
    with pytest.raises(ValueError, match="expired"):
        policy.consume(receipt, intent())


def test_p5_duration_is_p5_output_with_ratified_bounds() -> None:
    """The authority defaults the human duration and rejects values over its ceiling."""
    policy = authority()
    preview = policy.issue_preview(intent())
    receipt = policy.approve(
        preview.preview_id,
        operator_evidence_ref="audit://operator/decision-1",
        approved_duration_seconds=9_900,
    )
    assert receipt.approved_duration_seconds == 9_900

    preview = policy.issue_preview(
        P5ApprovalIntent.from_preview(
            "control-plane",
            {**intent().preview_payload(), "assignments": [{"role": "reviewer-2"}]},
        )
    )
    with pytest.raises(ValueError, match="issuance ceiling"):
        policy.approve(
            preview.preview_id,
            operator_evidence_ref="audit://operator/decision-2",
            approved_duration_seconds=9_901,
        )


def test_p5_requires_a_secret_and_rejects_invalid_intent_fields() -> None:
    """Missing cryptographic material and incomplete swarm scope are fail-closed."""
    with pytest.raises(ValueError, match="signing_key is required"):
        P5ApprovalAuthority(signing_key=b"", store=InMemoryP5ApprovalStore())
    with pytest.raises(ValueError, match="fields are incomplete"):
        P5ApprovalIntent.from_preview("control-plane", {**intent().preview_payload(), "objective": ""})


def test_sqlite_store_survives_reopen_and_rejects_replay(tmp_path: Path) -> None:
    """Durable storage preserves a consumed receipt across a new authority instance."""
    database = tmp_path / "p5.db"
    first = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    receipt = approved(first)

    reloaded = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    assert reloaded.consume(receipt, intent()).intent == intent()

    after_consume = P5ApprovalAuthority(
        signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database))
    )
    with pytest.raises(ValueError, match="already consumed"):
        after_consume.consume(receipt, intent())


def test_sqlite_store_preserves_non_default_action_across_reopen(tmp_path: Path) -> None:
    """A persisted grant-specific P5 action survives reload and receipt consumption."""
    database = tmp_path / "p5-action.db"
    grant_intent = P5ApprovalIntent.from_preview(
        "control-plane",
        intent().preview_payload(),
        action="phylax.adjustment_grant.issue",
    )
    first = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    preview = first.issue_preview(grant_intent)
    receipt = first.approve(preview.preview_id, operator_evidence_ref="audit://operator/decision-1")
    reloaded = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))

    assert reloaded.consume(receipt, grant_intent).intent.action == "phylax.adjustment_grant.issue"


def test_sqlite_store_allows_exactly_one_concurrent_consumer(tmp_path: Path) -> None:
    """Independent authorities cannot both consume one durable approval."""
    database = tmp_path / "p5-race.db"
    issuer = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database)))
    receipt = approved(issuer)

    def consume_once() -> bool:
        policy = P5ApprovalAuthority(
            signing_key=b"test-p5-secret", store=SqliteP5ApprovalStore(str(database))
        )
        try:
            policy.consume(receipt, intent())
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: consume_once(), range(2)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1


def test_sqlite_store_busy_timeout_wraps_as_value_error(tmp_path: Path) -> None:
    """A locked SQLite database fails closed with a consistent ValueError message."""
    database = tmp_path / "p5-locked.db"
    store = SqliteP5ApprovalStore(str(database), timeout=0.05)
    policy = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=store)
    preview = policy.issue_preview(intent())
    receipt = policy.approve(preview.preview_id, operator_evidence_ref="audit://op/1")

    # Acquire an exclusive lock on the database from a separate connection
    import sqlite3
    con = sqlite3.connect(str(database))
    con.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ValueError, match="P5 store busy or locked"):
            policy.consume(receipt, intent())
    finally:
        con.rollback()
        con.close()


def test_sqlite_expired_receipt_is_not_consumed(tmp_path: Path) -> None:
    """The SQLite CAS leaves an expired approval available for consistent diagnosis."""
    database = tmp_path / "p5-expired.db"
    clock = Clock()
    store = SqliteP5ApprovalStore(str(database))
    policy = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=store, clock=clock)
    receipt = approved(policy)
    clock.now += timedelta(minutes=5)

    with pytest.raises(ValueError, match="P5 approval expired"):
        policy.consume(receipt, intent())

    stored = store.get(receipt.preview_id)
    assert stored is not None
    assert not stored.consumed


class SequenceClock:
    """Return scripted instants, then repeat the last one, to model time passing under a lock."""

    def __init__(self, *instants: datetime) -> None:
        """Store the scripted instants."""
        self._instants = list(instants)

    def __call__(self) -> datetime:
        """Return the next scripted instant."""
        return self._instants.pop(0) if len(self._instants) > 1 else self._instants[0]


@pytest.fixture(params=["memory", "sqlite"])
def store_factory(request, tmp_path: Path):
    """Build either P5 store flavour so lock-time behaviour is proven on both."""
    if request.param == "memory":
        return lambda: InMemoryP5ApprovalStore()
    return lambda: SqliteP5ApprovalStore(str(tmp_path / "p5-param.db"))


def test_p5_ceiling_cannot_be_raised_above_the_hard_limit() -> None:
    """Callers may lower the issuance ceiling but never raise it past 9,900 seconds."""
    with pytest.raises(ValueError, match="must not exceed 9900"):
        P5ApprovalAuthority(
            signing_key=b"test-p5-secret",
            store=InMemoryP5ApprovalStore(),
            max_issuance_duration_seconds=20_000,
        )
    lowered = P5ApprovalAuthority(
        signing_key=b"test-p5-secret",
        store=InMemoryP5ApprovalStore(),
        default_human_duration_seconds=600,
        max_issuance_duration_seconds=900,
    )
    preview = lowered.issue_preview(intent())
    with pytest.raises(ValueError, match="fresh P5 HITL approval"):
        lowered.approve(preview.preview_id, operator_evidence_ref="audit://op/1", approved_duration_seconds=901)


@pytest.mark.parametrize("bad", [5.5, True, 0, -1])
def test_p5_durations_must_be_positive_integers(bad: object) -> None:
    """Fractional, boolean, and non-positive durations never reach a signed token."""
    policy = authority()
    preview = policy.issue_preview(intent())
    with pytest.raises(ValueError, match="positive integer"):
        policy.approve(preview.preview_id, operator_evidence_ref="audit://op/1", approved_duration_seconds=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive integer"):
        P5ApprovalAuthority(
            signing_key=b"test-p5-secret", store=InMemoryP5ApprovalStore(), default_human_duration_seconds=bad  # type: ignore[arg-type]
        )


def test_p5_approve_rechecks_expiry_after_the_store_lock(store_factory) -> None:
    """A preview that expires while waiting for the store lock cannot yield a receipt."""
    start = datetime(2026, 10, 12, tzinfo=UTC)
    clock = SequenceClock(start, start, start, start + timedelta(minutes=10))
    policy = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=store_factory(), clock=clock)
    preview = policy.issue_preview(intent())

    with pytest.raises(ValueError, match="P5 preview expired"):
        policy.approve(preview.preview_id, operator_evidence_ref="audit://op/1")


def test_p5_consume_reads_the_clock_after_the_store_lock(store_factory) -> None:
    """Expiry that lands while consume waits for the lock is enforced, not skipped."""
    start = datetime(2026, 10, 12, tzinfo=UTC)
    clock = Clock()
    policy = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=store_factory(), clock=clock)
    receipt = approved(policy)
    clock.now = start + timedelta(minutes=5)

    with pytest.raises(ValueError, match="P5 approval expired"):
        policy.consume(receipt, intent())


def test_sqlite_store_rejects_in_memory_database() -> None:
    """:memory: would silently lose the table between connections, so it is refused."""
    with pytest.raises(ValueError, match="durable file path"):
        SqliteP5ApprovalStore(":memory:")


def test_p5_purge_removes_only_records_expired_beyond_retention(store_factory) -> None:
    """Thirty-day retention drops stale previews and keeps recent ones intact."""
    clock = Clock()
    policy = P5ApprovalAuthority(signing_key=b"test-p5-secret", store=store_factory(), clock=clock)
    old = approved(policy)
    clock.now += timedelta(days=29)
    recent = policy.issue_preview(
        P5ApprovalIntent.from_preview("control-plane", {**intent().preview_payload(), "objective": "later"})
    )
    assert policy.purge_expired() == 0

    clock.now += timedelta(days=2)
    assert policy.purge_expired() == 1
    with pytest.raises(ValueError, match="unknown, invalid, or already consumed"):
        policy.consume(old, intent())
    assert policy.purge_expired() == 0
    assert recent.preview_id


def test_p5_purge_rejects_negative_retention() -> None:
    """A negative retention would delete live previews and is refused."""
    with pytest.raises(ValueError, match="must not be negative"):
        authority().purge_expired(retention=timedelta(seconds=-1))
