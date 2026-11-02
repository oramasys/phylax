"""Retained signed checkpoints and retention/pruning on real SQLite files (Part 3 3.1-3.2)."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import (
    GrantFacts,
    OperatorRefused,
    SqliteDispatchPermitStore,
)
from phylax.dispatch_retention import (
    Checkpoint,
    RetainedEventFeed,
    RetentionLedger,
    RetentionRefused,
    append_revocation_once,
    checkpoint_from_event,
    prune,
    prune_ceiling,
    verify_chain,
    verify_checkpoint,
    verify_checkpoint_against_event,
)

NOW = datetime(2026, 11, 2, 4, 0, 0, tzinfo=UTC)
SEEDS = {"key-1": b"1" * 32}


class Signer:
    """Event signer over a fixed test seed."""

    def active_key_id(self) -> str:
        """Return the only key id."""
        return "key-1"

    def sign_permit(self, key_id: str, body: dict) -> str:
        """Sign a permit body."""
        return wire.sign_permit(SEEDS[key_id], body)

    def sign_finalization(self, key_id: str, body: dict) -> str:
        """Sign a finalization body."""
        return wire.sign_finalization(SEEDS[key_id], body)

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest."""
        return wire.sign_event(SEEDS[key_id], digest)


class Resolver:
    """Issuer key resolver for the fixed test seed."""

    def public_key(self, key_id: str) -> bytes | None:
        """Return the public key or None for an unknown id."""
        return crypto_sign_seed_keypair(SEEDS[key_id])[0] if key_id in SEEDS else None


class Operator:
    """Operator port returning a fixed reference or denying."""

    def __init__(self, reference: str | None = "op-1") -> None:
        """Choose the reference (None denies)."""
        self.reference = reference
        self.operations: list[str] = []

    def authorize(self, operation: str, *, attempt_id: str, grant_id: str | None) -> str | None:
        """Record the operation and return the reference."""
        self.operations.append(operation)
        return self.reference


class Grants:
    """Grant lookup giving each grant its own ledger store id."""

    def __init__(self) -> None:
        """Start empty."""
        self.facts: dict[str, GrantFacts] = {}

    def add(self, grant_id: str, ledger: str) -> None:
        """Register a live grant bound to a ledger store id."""
        self.facts[grant_id] = GrantFacts(
            payload_digest="a" * 64, operation_id="op-1", request_digest="b" * 64,
            ledger_store_id=ledger, expires_at=NOW + timedelta(hours=1),
            revoked=False, cascade_pending=False,
        )

    def get(self, grant_id: str) -> GrantFacts | None:
        """Return the facts for a grant."""
        return self.facts.get(grant_id)


def admit_ack(store, grants: Grants, signer: Signer, grant: str, ledger: str, attempt: str, acked: int) -> None:
    """Admit a permit so the issuer observes ``acked`` for ``ledger``."""
    grants.add(grant, ledger)
    store.admit({
        "grant_id": grant, "grant_payload_digest": "a" * 64, "operation_id": "op-1",
        "request_digest": "b" * 64, "artifact_digest": "c" * 64, "reservation_id": "res-" + attempt,
        "ledger_store_id": ledger, "configuration_policy_epoch": 3, "authority_epoch": 5,
        "consumer_acked_through": acked, "attempt_id": attempt, "requested_at": wire.timestamp(NOW),
    }, grants=grants, signer=signer, now=NOW)


@pytest.fixture
def signer() -> Signer:
    """Return a signer."""
    return Signer()


@pytest.fixture
def store(tmp_path: Path) -> SqliteDispatchPermitStore:
    """Return a store."""
    return SqliteDispatchPermitStore(tmp_path / "permits.db")


@pytest.fixture
def ledger(tmp_path: Path) -> RetentionLedger:
    """Return a retention ledger."""
    return RetentionLedger(tmp_path / "retention.db")


def fill(store, signer: Signer, count: int) -> list[dict]:
    """Append ``count`` revocation events and return them."""
    return [store.append_revocation("grant", f"g-{i}", signer=signer) for i in range(count)]


def hot_versions(store) -> list[int]:
    """Return the hot event versions in ascending order."""
    with closing(sqlite3.connect(store.path)) as db:
        return [r[0] for r in db.execute("SELECT version FROM issuer_events ORDER BY version")]


def setup_two_consumers(store, ledger, signer, acks: tuple[int, int]) -> list[dict]:
    """Register two consumers, record their observed acks and return the 10 events."""
    events = fill(store, signer, 10)
    grants = Grants()
    for name in ("ledger-a", "ledger-b"):
        ledger.register_consumer(name, operator=Operator(), now=NOW)
    admit_ack(store, grants, signer, "ga", "ledger-a", "att-a", acks[0])
    admit_ack(store, grants, signer, "gb", "ledger-b", "att-b", acks[1])
    return events


def test_event_row_is_the_signed_checkpoint(store, signer) -> None:
    """3.1: a checkpoint is the event row's (version, digest) and verifies with no extra domain."""
    event = fill(store, signer, 3)[1]
    checkpoint = checkpoint_from_event(event)
    assert checkpoint == Checkpoint(2, event["event_digest"], "key-1", event["signature"])
    verify_checkpoint(checkpoint, Resolver())
    assert set(checkpoint.to_wire()) == {"version", "event_digest", "issuer_key_id", "signature"}


def test_checkpoint_refuses_forged_signature_and_unknown_key(store, signer) -> None:
    """A wrong signature or an unknown issuer key never verifies."""
    event = fill(store, signer, 1)[0]
    other = wire.sign_event(b"9" * 32, event["event_digest"])
    with pytest.raises(RetentionRefused) as forged:
        verify_checkpoint(replace(checkpoint_from_event(event), signature=other), Resolver())
    assert forged.value.code == "retention.signature_invalid"
    with pytest.raises(RetentionRefused) as unknown:
        verify_checkpoint(replace(checkpoint_from_event(event), issuer_key_id="key-x"), Resolver())
    assert unknown.value.code == "retention.unknown_key"
    with pytest.raises(RetentionRefused) as garbage:
        verify_checkpoint(replace(checkpoint_from_event(event), signature="!!"), Resolver())
    assert garbage.value.code == "retention.signature_invalid"


def test_unknown_refusal_code_is_rejected() -> None:
    """The refusal vocabulary is closed."""
    with pytest.raises(ValueError):
        RetentionRefused("retention.made_up")


def test_verify_chain_recomputes_digests_and_links(store, signer) -> None:
    """Chain verification rejects a swapped body, a broken link and a gap."""
    events = fill(store, signer, 4)
    assert verify_chain(events, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=Resolver()) == events[-1]["event_digest"]
    tampered = [dict(e) for e in events]
    tampered[2]["body"] = {"subject_kind": "grant", "subject_id": "evil"}
    for bad, code in (
        (tampered, "retention.chain_broken"),
        ([events[0], events[2]], "retention.chain_broken"),
        ([{**events[0], "extra": 1}], "retention.malformed_event"),
        ([{**events[0], "version": True}], "retention.malformed_event"),
    ):
        with pytest.raises(RetentionRefused) as caught:
            verify_chain(bad, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=Resolver())
        assert caught.value.code == code


def test_prune_without_registered_consumers_is_refused(store, ledger, signer) -> None:
    """No registered consumer means no safe ceiling and nothing moves."""
    fill(store, signer, 5)
    with pytest.raises(RetentionRefused) as caught:
        prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert caught.value.code == "retention.no_consumers"
    assert hot_versions(store) == [1, 2, 3, 4, 5] and ledger.archived_range() is None


def test_prune_uses_lowest_ack_and_keeps_one_anchor(store, ledger, signer) -> None:
    """3.2: rows below the lowest ack move to the archive; the boundary row stays hot."""
    events = setup_two_consumers(store, ledger, signer, acks=(7, 4))
    result = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert (result.ceiling, result.archived_from, result.archived_through) == (4, 1, 3)
    assert result.anchor == checkpoint_from_event(events[3])
    assert hot_versions(store)[0] == 4
    assert ledger.archived_events(1, 3) == events[:3]
    assert [e["ceiling"] for e in ledger.prune_log()] == [4]
    RetainedEventFeed(store, ledger).verify_continuity(Resolver())


def test_unobserved_consumer_holds_the_ceiling_at_zero(store, ledger, signer) -> None:
    """A registered consumer the issuer has never heard from blocks every prune."""
    fill(store, signer, 6)
    ledger.register_consumer("ledger-a", operator=Operator(), now=NOW)
    ledger.register_consumer("ledger-silent", operator=Operator(), now=NOW)
    admit_ack(store, Grants(), signer, "ga", "ledger-a", "att-a", 5)
    result = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert result.ceiling == 0 and result.archived_from is None
    assert hot_versions(store)[0] == 1 and ledger.archived_range() is None


def test_advancing_boundary_archives_the_former_anchor(store, ledger, signer) -> None:
    """A later prune moves the old anchor into the archive; exactly one anchor stays hot."""
    events = setup_two_consumers(store, ledger, signer, acks=(4, 4))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    grants = Grants()
    admit_ack(store, grants, signer, "ga2", "ledger-a", "att-a2", 8)
    admit_ack(store, grants, signer, "gb2", "ledger-b", "att-b2", 8)
    result = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert (result.ceiling, result.archived_from, result.archived_through) == (8, 4, 7)
    assert hot_versions(store)[0] == 8
    assert ledger.archived_events(1, 7) == events[:7]
    feed = RetainedEventFeed(store, ledger)
    assert feed.current_anchor() == checkpoint_from_event(events[7])
    feed.verify_continuity(Resolver())


def test_feed_stitches_both_tiers_and_never_returns_short(store, ledger, signer) -> None:
    """A range served from archive plus hot is whole; an unservable range is refused."""
    events = setup_two_consumers(store, ledger, signer, acks=(6, 6))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    feed = RetainedEventFeed(store, ledger)
    assert feed.events(2, 9) == events[1:9]
    assert feed.checkpoint(3) == checkpoint_from_event(events[2])
    assert feed.current_anchor() == checkpoint_from_event(events[5])
    # The frozen store alone would answer a pruned range with a silent short list.
    assert store.events(2, 9)[0]["version"] == 6
    for low, high in ((0, 3), (5, 4), (8, 30)):
        with pytest.raises(RetentionRefused) as caught:
            feed.events(low, high)
        assert caught.value.code == "retention.range_unavailable"


def test_store_chain_continues_after_prune(store, ledger, signer) -> None:
    """New events link to the retained tip and the whole chain still verifies."""
    setup_two_consumers(store, ledger, signer, acks=(5, 5))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    store.append_revocation("grant", "after-prune", signer=signer)
    feed = RetainedEventFeed(store, ledger)
    full = feed.events(1, 11)
    assert verify_chain(full, previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=Resolver())


def test_archive_is_append_only_and_conflicts_are_refused(store, ledger, signer) -> None:
    """The archive rejects UPDATE and DELETE and refuses a different row at an archived version."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    with closing(sqlite3.connect(ledger.path)) as db:
        for sql in ("UPDATE archived_events SET kind='x'", "DELETE FROM archived_events",
                    "UPDATE prune_log SET ceiling=1", "DELETE FROM prune_log",
                    "DELETE FROM retention_consumers", "UPDATE retention_consumers SET operator_ref='x'"):
            with pytest.raises(sqlite3.DatabaseError):
                db.execute(sql)
    ledger.append_archive(events[:2], now=NOW)  # identical rows are confirmed idempotently
    with pytest.raises(RetentionRefused) as conflict:
        ledger.append_archive([{**events[0], "signature": events[1]["signature"]}], now=NOW)
    assert conflict.value.code == "retention.archive_conflict"
    with pytest.raises(RetentionRefused) as gap:
        ledger.append_archive([events[8]], now=NOW)
    assert gap.value.code == "retention.archive_gap"


def test_prune_is_atomic_when_the_hot_chain_is_tampered(store, ledger, signer) -> None:
    """A corrupted hot row aborts the prune: nothing is archived and nothing is deleted."""
    setup_two_consumers(store, ledger, signer, acks=(6, 6))
    with closing(sqlite3.connect(store.path)) as db:
        db.execute("UPDATE issuer_events SET body = ? WHERE version = 2",
                   ('{"subject_id":"evil","subject_kind":"grant"}',))
        db.commit()
    with pytest.raises(RetentionRefused) as caught:
        prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert caught.value.code == "retention.chain_broken"
    assert hot_versions(store)[0] == 1 and ledger.archived_range() is None


def test_rerun_after_crash_between_archive_and_delete_is_idempotent(store, ledger, signer) -> None:
    """Rows already archived but still hot are confirmed, then removed, with no duplication."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    ledger.append_archive(events[:2], now=NOW)  # simulate the crash window
    assert hot_versions(store)[0] == 1
    result = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert (result.archived_from, result.archived_through) == (1, 4)
    assert ledger.archived_events(1, 4) == events[:4] and hot_versions(store)[0] == 5


def test_prune_is_a_noop_when_nothing_is_below_the_ceiling(store, ledger, signer) -> None:
    """A repeat prune at the same ceiling changes nothing and still reports the anchor."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    again = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert again.archived_from is None and again.anchor == checkpoint_from_event(events[4])
    assert len(ledger.prune_log()) == 1


def test_prune_on_an_empty_chain_is_a_noop(store, ledger) -> None:
    """With no events there is nothing to move and no anchor."""
    ledger.register_consumer("ledger-a", operator=Operator(), now=NOW)
    result = prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    assert result.archived_from is None and result.anchor is None


def test_operator_denial_changes_nothing(store, ledger, signer) -> None:
    """An unauthenticated prune or registration is refused before any read or write."""
    setup_two_consumers(store, ledger, signer, acks=(5, 5))
    with pytest.raises(OperatorRefused):
        prune(store, ledger, Resolver(), operator=Operator(None), now=NOW)
    with pytest.raises(OperatorRefused):
        ledger.register_consumer("ledger-c", operator=Operator("  "), now=NOW)
    assert hot_versions(store)[0] == 1 and ledger.consumers() == ("ledger-a", "ledger-b")


def test_consumer_registration_is_idempotent_and_validated(ledger) -> None:
    """Registering twice keeps one row; an invalid id is refused."""
    for _ in range(2):
        ledger.register_consumer("ledger-a", operator=Operator(), now=NOW)
    assert ledger.consumers() == ("ledger-a",)
    with pytest.raises(RetentionRefused) as caught:
        ledger.register_consumer("bad id", operator=Operator(), now=NOW)
    assert caught.value.code == "retention.consumer_invalid"


def test_revocation_idempotence_survives_pruning(store, ledger, signer) -> None:
    """A revocation already moved to the archive is returned, not duplicated."""
    events = setup_two_consumers(store, ledger, signer, acks=(6, 6))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    again = append_revocation_once(store, ledger, "grant", "g-0", signer=signer)
    assert again == events[0] and store.current_counter() == 10
    fresh = append_revocation_once(store, ledger, "grant", "g-new", signer=signer)
    assert fresh["version"] == 11


def test_prune_ceiling_pure_function() -> None:
    """The ceiling is the minimum over registered consumers; unseen counts as zero."""
    assert prune_ceiling(["a", "b"], {"a": 9, "b": 3, "c": 1}) == 3
    assert prune_ceiling(["a", "b"], {"a": 9}) == 0
    with pytest.raises(RetentionRefused):
        prune_ceiling([], {"a": 9})


def test_ledger_rejects_non_durable_paths() -> None:
    """The ledger needs a real file."""
    with pytest.raises(ValueError):
        RetentionLedger(":memory:")


def test_archive_verification_from_genesis_detects_gap(ledger, store, signer) -> None:
    """An archive that does not start at version 1 cannot be verified and is refused."""
    events = fill(store, signer, 3)
    with closing(sqlite3.connect(ledger.path)) as db:
        db.execute(
            "INSERT INTO archived_events VALUES(2,'revocation','{}','x','y','key-1','s','t')"
        )
        db.commit()
    with pytest.raises(RetentionRefused) as caught:
        ledger.verify_archive(Resolver())
    assert caught.value.code == "retention.archive_gap"
    assert events


def test_bare_checkpoint_does_not_bind_version_but_event_check_does(store, signer) -> None:
    """A changed version passes the digest-only check yet is refused against the event."""
    event = fill(store, signer, 2)[1]
    real = checkpoint_from_event(event)
    forged = replace(real, version=200)
    verify_checkpoint(forged, Resolver())  # digest-only: documented as insufficient for the version
    verify_checkpoint_against_event(real, event, Resolver())
    for bad in (forged, replace(real, event_digest="0" * 64)):
        with pytest.raises(RetentionRefused) as caught:
            verify_checkpoint_against_event(bad, event, Resolver())
        assert caught.value.code in {"retention.chain_broken", "retention.signature_invalid"}


def test_events_retries_when_pruning_moves_the_boundary_mid_read(store, ledger, signer) -> None:
    """A prune landing between the boundary read and the hot read must not yield a false refusal."""
    events = setup_two_consumers(store, ledger, signer, acks=(6, 6))
    feed = RetainedEventFeed(store, ledger)
    real_low, calls = feed._hot_low, {"n": 0}

    def racing_hot_low():
        value = real_low()
        calls["n"] += 1
        if calls["n"] == 1:  # stale boundary: the prune happens right after it was read
            prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
        return value

    feed._hot_low = racing_hot_low  # type: ignore[method-assign]
    assert feed.events(2, 9) == events[1:9]


def test_events_still_refuses_a_range_that_is_really_unavailable(store, ledger, signer) -> None:
    """The retry does not mask a genuinely missing range."""
    setup_two_consumers(store, ledger, signer, acks=(6, 6))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    with pytest.raises(RetentionRefused) as caught:
        RetainedEventFeed(store, ledger).events(8, 30)
    assert caught.value.code == "retention.range_unavailable"


def test_revocation_retry_after_prune_returns_the_original(store, ledger, signer) -> None:
    """A retry that arrives after the original moved to the archive returns it, not a second event."""
    events = setup_two_consumers(store, ledger, signer, acks=(6, 6))
    prune(store, ledger, Resolver(), operator=Operator(), now=NOW)
    again = append_revocation_once(store, ledger, "grant", "g-0", signer=signer)
    assert again == events[0] and hot_versions(store)[0] == 6


def test_prune_and_revocation_append_serialise_on_one_lock(store, ledger, signer) -> None:
    """While a prune holds the retention lock a concurrent append waits rather than interleaving."""
    import threading

    from phylax import dispatch_retention as dr

    order: list[str] = []
    events = setup_two_consumers(store, ledger, signer, acks=(6, 6))
    started, release = threading.Event(), threading.Event()

    def holder() -> None:
        with dr._retention_lock(ledger):
            started.set()
            release.wait(5)
            order.append("holder-done")

    thread = threading.Thread(target=holder)
    thread.start()
    started.wait(5)
    appender = threading.Thread(
        target=lambda: (append_revocation_once(store, ledger, "grant", "g-0", signer=signer), order.append("append-done"))
    )
    appender.start()
    appender.join(0.3)
    assert appender.is_alive() and order == []  # blocked on the lock
    release.set()
    thread.join(5)
    appender.join(5)
    assert order == ["holder-done", "append-done"]
    assert events[0]["version"] == 1


def test_continuity_accepts_the_crash_state_with_overlapping_tiers(store, ledger, signer) -> None:
    """Rows archived but still hot are an intact state, not an archive gap."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    ledger.append_archive(events[:2], now=NOW)
    RetainedEventFeed(store, ledger).verify_continuity(Resolver())


def test_continuity_refuses_an_overlap_that_differs_from_the_archive(store, ledger, signer) -> None:
    """Hot rows that disagree with their archived copy are refused, not waved through."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    ledger.append_archive(events[:2], now=NOW)
    with closing(sqlite3.connect(store.path)) as db:
        db.execute("DROP TRIGGER IF EXISTS issuer_events_no_update")
        db.execute("UPDATE issuer_events SET body = '{\"x\":1}' WHERE version = 2")
        db.commit()
    with pytest.raises(RetentionRefused):
        RetainedEventFeed(store, ledger).verify_continuity(Resolver())


def test_archive_verification_runs_before_the_hot_write_lock(store, ledger, signer) -> None:
    """Hot writers are not blocked while the O(archive) signature walk runs."""
    setup_two_consumers(store, ledger, signer, acks=(5, 5))
    seen: dict[str, bool] = {}

    class Probe(RetentionLedger):
        def verify_archive(self, resolver):
            try:  # a hot writer must be able to take the write lock during the walk
                with closing(sqlite3.connect(store.path, timeout=0.2, isolation_level=None)) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("ROLLBACK")
                seen["free"] = True
            except sqlite3.OperationalError:
                seen["free"] = False
            return super().verify_archive(resolver)

    probe = Probe(ledger.path)
    prune(store, probe, Resolver(), operator=Operator(), now=NOW)
    assert seen == {"free": True}


def test_rows_appended_to_the_archive_after_the_check_are_refused_not_trusted(store, ledger, signer) -> None:
    """A row that lands between the signature walk and the lock changes the tail and is refused."""
    events = setup_two_consumers(store, ledger, signer, acks=(5, 5))
    ledger.append_archive(events[:2], now=NOW)

    class Racing(RetentionLedger):
        raced = False

        def verify_archive(self, resolver):
            tail = super().verify_archive(resolver)
            if not Racing.raced:
                Racing.raced = True
                self.append_archive(events[2:3], now=NOW)  # unchecked row after the walk
            return tail

    racing = Racing(ledger.path)
    with pytest.raises(RetentionRefused) as caught:
        prune(store, racing, Resolver(), operator=Operator(), now=NOW)
    assert caught.value.code == "retention.archive_changed" and hot_versions(store)[0] == 1
    result = prune(store, racing, Resolver(), operator=Operator(), now=NOW)  # a rerun re-verifies
    assert (result.archived_from, result.archived_through) == (1, 4)
