"""Issuer-side dispatch permit store tests on real SQLite files (E1 C2 slice 1)."""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_permit_store as store_module
from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import (
    GrantFacts,
    PermitRefused,
    SqliteDispatchPermitStore,
)

NOW = datetime(2026, 10, 19, 4, 0, 0, tzinfo=UTC)
SEEDS = {"key-1": b"1" * 32, "key-2": b"2" * 32}
GRANT_ID = "grant-1"
PAYLOAD = "a" * 64


@contextmanager
def open_db(path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection, commit on success and always close it."""
    connection = sqlite3.connect(path)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


class FakeGrants:
    """Per-test grant lookup backed by a private dict."""

    def __init__(self) -> None:
        """Start with one live grant matching ``permit_request``."""
        self.facts: dict[str, GrantFacts] = {GRANT_ID: self.live()}

    @staticmethod
    def live(**overrides: object) -> GrantFacts:
        """Return live grant facts matching the default request."""
        base = GrantFacts(
            payload_digest=PAYLOAD, operation_id="op-1", request_digest="b" * 64,
            ledger_store_id="ledger-1", expires_at=NOW + timedelta(hours=1),
            revoked=False, cascade_pending=False,
        )
        return replace(base, **overrides)

    def get(self, grant_id: str) -> GrantFacts | None:
        """Return the facts for a grant id or None."""
        return self.facts.get(grant_id)

    def set(self, grant_id: str = GRANT_ID, **overrides: object) -> None:
        """Replace one grant's facts with a modified copy."""
        self.facts[grant_id] = replace(self.facts[grant_id], **overrides)


class FakeSigner:
    """Signer built on the wire module with fixed test seeds."""

    def __init__(self, active: str = "key-1") -> None:
        """Select the active key id."""
        self.active = active

    def active_key_id(self) -> str:
        """Return the active key id."""
        return self.active

    def sign_permit(self, key_id: str, body: dict) -> str:
        """Sign a permit body."""
        return wire.sign_permit(SEEDS[key_id], body)

    def sign_finalization(self, key_id: str, body: dict) -> str:
        """Sign a finalization body."""
        return wire.sign_finalization(SEEDS[key_id], body)

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest."""
        return wire.sign_event(SEEDS[key_id], digest)


class FakeOperator:
    """Operator authority port: authorizes every operation with a fixed reference, or none."""

    def __init__(self, reference: str | None = "op-1") -> None:
        """Choose the disposition reference returned (None denies every call)."""
        self.reference = reference
        self.calls: list[tuple[str, str, str | None]] = []

    def authorize(self, operation: str, *, attempt_id: str, grant_id: str | None) -> str | None:
        """Record the call and return the configured reference."""
        self.calls.append((operation, attempt_id, grant_id))
        return self.reference


OPERATOR = FakeOperator()


def public_key(key_id: str = "key-1") -> bytes:
    """Return the public key for a fixed test seed."""
    return crypto_sign_seed_keypair(SEEDS[key_id])[0]


def permit_request(**overrides: object) -> dict:
    """Return a valid 12-field permit request."""
    base = {
        "grant_id": GRANT_ID, "grant_payload_digest": PAYLOAD, "operation_id": "op-1",
        "request_digest": "b" * 64, "artifact_digest": "c" * 64, "reservation_id": "res-1",
        "ledger_store_id": "ledger-1", "configuration_policy_epoch": 3, "authority_epoch": 5,
        "consumer_acked_through": 0, "attempt_id": "attempt-1",
        "requested_at": wire.timestamp(NOW),
    }
    return {**base, **overrides}


def final_request(permit_bytes: bytes, **overrides: object) -> dict:
    """Return a valid 8-field finalization request for a permit."""
    permit = json.loads(permit_bytes)
    base = {
        "permit_id": permit["permit_id"], "permit_digest": permit["payload_digest"],
        "attempt_id": permit["attempt_id"], "reservation_id": permit["reservation_id"],
        "ledger_store_id": permit["ledger_store_id"], "consumer_acked_through": 0,
        "authority_epoch": permit["authority_epoch"], "requested_at": wire.timestamp(NOW),
    }
    return {**base, **overrides}


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Return a fresh database path."""
    return tmp_path / "permits.db"


@pytest.fixture
def store(db: Path):
    """Return an open store, closed after the test."""
    opened = SqliteDispatchPermitStore(db)
    yield opened
    opened.close()


@pytest.fixture
def grants() -> FakeGrants:
    """Return a fresh grant lookup."""
    return FakeGrants()


@pytest.fixture
def signer() -> FakeSigner:
    """Return a fresh signer."""
    return FakeSigner()


def admit(store, grants, signer, request=None, now=NOW) -> bytes:
    """Admit a request with the shared fakes."""
    return store.admit(request or permit_request(), grants=grants, signer=signer, now=now)


def finalize(store, grants, signer, request, now=NOW, **kwargs):
    """Finalize a request with the shared fakes."""
    return store.finalize(request, grants=grants, signer=signer, now=now, **kwargs)


def refusal(callable_, *args, **kwargs) -> str:
    """Run a callable that must refuse and return the code."""
    with pytest.raises(PermitRefused) as info:
        callable_(*args, **kwargs)
    return info.value.code


def row_count(db: Path, table: str = "dispatch_permits") -> int:
    """Count rows with a raw connection."""
    with open_db(db) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def raw_exec(db: Path, sql: str, params: tuple = ()) -> None:
    """Execute raw SQL against the file with foreign keys on."""
    conn = sqlite3.connect(db, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(sql, params)
    finally:
        conn.close()


# ---------------------------------------------------------------- admission

def test_admit_returns_a_valid_signed_permit(store, grants, signer) -> None:
    """A first admission yields a 21-field permit whose signature verifies."""
    data = admit(store, grants, signer)
    permit = json.loads(data)
    assert len(permit) == 21 and permit["permit_id"].startswith("permit-")
    body = {k: v for k, v in permit.items() if k not in ("payload_digest", "issuer_signature")}
    assert wire.verify_permit(public_key(), body, permit["issuer_signature"])
    assert permit["revocation_version"] == 0 and permit["issuer_key_id"] == "key-1"
    assert permit["expires_at"] == wire.timestamp(NOW + timedelta(seconds=90))


def test_permit_expiry_is_capped_by_grant_expiry(store, grants, signer) -> None:
    """A permit never outlives its grant."""
    grants.set(expires_at=NOW + timedelta(seconds=10))
    permit = json.loads(admit(store, grants, signer))
    assert permit["expires_at"] == wire.timestamp(NOW + timedelta(seconds=10))


def test_identical_retry_is_byte_identical_and_inserts_nothing(store, db, grants, signer) -> None:
    """A retry with equal binding returns the stored bytes, even with a new requested_at."""
    first = admit(store, grants, signer)
    later = permit_request(requested_at=wire.timestamp(NOW + timedelta(seconds=5)))
    again = admit(store, grants, signer, later, now=NOW + timedelta(seconds=5))
    assert again == first and row_count(db) == 1


def test_same_attempt_changed_binding_conflicts(store, grants, signer) -> None:
    """The same attempt id with a changed binding value is permit.conflict."""
    admit(store, grants, signer)
    assert refusal(admit, store, grants, signer, permit_request(reservation_id="res-2")) == "permit.conflict"


def test_new_attempt_on_grant_with_live_permit_conflicts(store, db, grants, signer) -> None:
    """A different attempt id on a grant holding a live permit conflicts."""
    admit(store, grants, signer)
    code = refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-2"))
    assert code == "permit.conflict" and row_count(db) == 1


def test_new_attempt_on_grant_with_expired_permit_conflicts(store, db, grants, signer) -> None:
    """An expired permit still blocks a new attempt: exactly one row remains."""
    admit(store, grants, signer)
    later = NOW + timedelta(seconds=500)
    code = refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-2"), now=later)
    assert code == "permit.conflict" and row_count(db) == 1


def test_new_attempt_after_finalized_permit_conflicts(store, db, grants, signer) -> None:
    """A terminal-or-finalized permit also blocks a new attempt."""
    permit = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(permit))
    code = refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-2"))
    assert code == "permit.conflict" and row_count(db) == 1


def test_aborted_then_admission_is_refused(store, db, grants, signer) -> None:
    """An aborted attempt id can never be admitted."""
    assert store.abort("attempt-1", GRANT_ID, operator=OPERATOR, now=NOW) == ("abort.recorded", None)
    assert refusal(admit, store, grants, signer) == "permit.attempt_aborted"
    assert row_count(db) == 1


def test_admission_then_abort_admission_won_no_tombstone(store, db, grants, signer) -> None:
    """Abort after admission returns the permit and writes no tombstone."""
    permit = admit(store, grants, signer)
    outcome = store.abort("attempt-1", GRANT_ID, operator=OPERATOR, now=NOW)
    assert outcome == ("abort.admission_won", permit) and row_count(db) == 1
    assert store.lookup_attempt("attempt-1", operator=OPERATOR)["state"] == "issued"


def test_abort_twice_is_idempotent(store, grants, signer) -> None:
    """A second abort reports already_aborted."""
    store.abort("attempt-1", GRANT_ID, operator=OPERATOR, now=NOW)
    assert (
        store.abort("attempt-1", GRANT_ID, operator=FakeOperator("op-2"), now=NOW)
        == ("abort.already_aborted", None)
    )


@pytest.mark.parametrize("admitted", [False, True], ids=["aborted", "admitted"])
@pytest.mark.parametrize("reopen", [False, True], ids=["same-store", "reopened"])
def test_abort_with_other_grant_conflicts_without_mutation(store, db, grants, signer, admitted, reopen) -> None:
    """Wrong-grant aborts cannot return success or change a durable attempt's binding or evidence."""
    if admitted:
        admit(store, grants, signer)
    else:
        store.abort("attempt-1", GRANT_ID, operator=FakeOperator("op-original"), now=NOW)
    with open_db(db) as connection:
        before = list(connection.iterdump())
    if reopen:
        store.close()
        store = SqliteDispatchPermitStore(db)
    try:
        assert refusal(
            store.abort, "attempt-1", "grant-9", operator=FakeOperator("op-retry"),
            now=NOW + timedelta(seconds=5),
        ) == "permit.conflict"
        with open_db(db) as connection:
            assert list(connection.iterdump()) == before
    finally:
        if reopen:
            store.close()


@pytest.mark.parametrize("admitted", [False, True], ids=["aborted", "admitted"])
def test_same_grant_abort_retry_preserves_original_evidence(store, db, grants, signer, admitted) -> None:
    """Authorized same-grant retries return the original outcome without replacing any evidence."""
    if admitted:
        permit = admit(store, grants, signer)
        expected = ("abort.admission_won", permit)
    else:
        store.abort("attempt-1", GRANT_ID, operator=FakeOperator("op-original"), now=NOW)
        expected = ("abort.already_aborted", None)
    with open_db(db) as connection:
        before = list(connection.iterdump())
    assert store.abort(
        "attempt-1", GRANT_ID, operator=FakeOperator("op-retry"), now=NOW + timedelta(seconds=5),
    ) == expected
    with open_db(db) as connection:
        assert list(connection.iterdump()) == before


def test_abort_first_then_new_attempt_for_same_grant_is_admitted(store, db, grants, signer) -> None:
    """An aborted row does not hold the grant: a new attempt id is admitted."""
    store.abort("attempt-1", GRANT_ID, operator=OPERATOR, now=NOW)
    data = admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    assert json.loads(data)["attempt_id"] == "attempt-2" and row_count(db) == 2


@pytest.mark.parametrize("field", ["payload_digest", "operation_id", "request_digest", "ledger_store_id"])
def test_grant_mismatch_for_every_field(store, grants, signer, field) -> None:
    """Each compared grant field mismatches independently."""
    value = "d" * 64 if field.endswith("digest") else "other"
    grants.set(**{field: value})
    assert refusal(admit, store, grants, signer) == "permit.grant_mismatch"


def test_unknown_grant_is_a_mismatch(store, grants, signer) -> None:
    """A grant the lookup does not know is a mismatch."""
    request = permit_request(grant_id="grant-unknown")
    assert refusal(admit, store, grants, signer, request) == "permit.grant_mismatch"


def test_grant_revoked_cascade_and_expired(store, grants, signer) -> None:
    """Revoked, cascade-pending and expired grants are refused with their codes."""
    grants.set(revoked=True)
    assert refusal(admit, store, grants, signer) == "permit.grant_revoked"
    grants.set(revoked=False, cascade_pending=True)
    assert refusal(admit, store, grants, signer) == "permit.grant_revoked"
    grants.set(cascade_pending=False, expires_at=NOW)
    assert refusal(admit, store, grants, signer) == "permit.grant_expired"


def test_invalid_request_is_refused(store, grants, signer) -> None:
    """A malformed request is permit.invalid_request."""
    request = permit_request()
    del request["attempt_id"]
    assert refusal(admit, store, grants, signer, request) == "permit.invalid_request"
    assert refusal(admit, store, grants, signer, permit_request(extra="x")) == "permit.invalid_request"


def test_rollback_floor_at_admission_and_identical_retry(store, grants, signer) -> None:
    """The floor refuses a fresh admission and an identical retry."""
    assert refusal(
        admit, store, grants, signer, permit_request(consumer_acked_through=1)
    ) == "permit.issuer_rolled_back"
    admit(store, grants, signer)
    retry = permit_request(consumer_acked_through=5)
    assert refusal(admit, store, grants, signer, retry) == "permit.issuer_rolled_back"


# ------------------------------------------------------------- finalization

def test_finalization_happy_path(store, db, grants, signer) -> None:
    """One event is appended at R_f = counter + 1 and everything verifies."""
    permit = admit(store, grants, signer)
    data, envelope = finalize(store, grants, signer, final_request(permit))
    fin = json.loads(data)
    assert len(fin) == 15 and fin["revocation_version"] == 1
    body = {k: v for k, v in fin.items() if k != "issuer_signature"}
    assert wire.verify_finalization(public_key(), body, fin["issuer_signature"])
    (event,) = store.events(1, 1)
    assert event["event_digest"] == fin["revocation_event_digest"]
    assert wire.verify_event(public_key(), event["event_digest"], event["signature"])
    assert event["previous_event_digest"] == wire.GENESIS_EVENT_DIGEST
    assert event["body"] == {"finalization_id": fin["finalization_id"]}
    assert envelope == {"events": [event], "from_version": 1, "through_version": 1}
    assert store.lookup_attempt("attempt-1", operator=OPERATOR)["state"] == "finalized"
    assert row_count(db, "issuer_events") == 1 and store.current_counter() == 1


def test_event_chain_digests_verify(store, grants, signer) -> None:
    """Chained events recompute through dispatch_wire.event_digest."""
    for n in range(3):
        grant = f"grant-{n}"
        grants.facts[grant] = grants.live()
        request = permit_request(grant_id=grant, attempt_id=f"attempt-{n}")
        permit = admit(store, grants, signer, request)
        finalize(store, grants, signer, final_request(permit, consumer_acked_through=n))
    events = store.events(1, 3)
    previous = wire.GENESIS_EVENT_DIGEST
    for index, event in enumerate(events, start=1):
        assert event["version"] == index and event["previous_event_digest"] == previous
        expected = wire.event_digest(index, event["kind"], event["body"], previous)
        assert event["event_digest"] == expected
        previous = expected


def test_finalization_retry_is_identical_and_appends_nothing(store, db, grants, signer) -> None:
    """A retry with higher acknowledgement and later requested_at returns the same bytes."""
    permit = admit(store, grants, signer)
    first, _ = finalize(store, grants, signer, final_request(permit))
    later = NOW + timedelta(seconds=10)
    retry = final_request(permit, consumer_acked_through=1, requested_at=wire.timestamp(later))
    again, envelope = finalize(store, grants, signer, retry, now=later)
    assert again == first and row_count(db, "issuer_events") == 1
    assert envelope["from_version"] == 2 and envelope["events"] == []


def test_finalization_retry_never_signs(store, grants) -> None:
    """A retry must not call the signer at all."""
    signer = FakeSigner()
    permit = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(permit))

    class Forbidden(FakeSigner):
        """Signer that fails the test if used."""

        def sign_finalization(self, key_id, body):
            """Fail: retries must not sign."""
            raise AssertionError("signed on retry")

        def sign_event(self, key_id, digest):
            """Fail: retries must not sign."""
            raise AssertionError("signed on retry")

    finalize(store, grants, Forbidden(), final_request(permit))


@pytest.mark.parametrize("field,value", [
    ("attempt_id", "attempt-9"), ("reservation_id", "res-9"), ("ledger_store_id", "ledger-9"),
    ("authority_epoch", 6), ("permit_digest", "e" * 64),
])
def test_finalization_changed_binding_conflicts(store, grants, signer, field, value) -> None:
    """Each compared binding value yields finalization.conflict, before and after finalization."""
    permit = admit(store, grants, signer)
    assert refusal(
        finalize, store, grants, signer, final_request(permit, **{field: value})
    ) == "finalization.conflict"
    finalize(store, grants, signer, final_request(permit))
    assert refusal(
        finalize, store, grants, signer, final_request(permit, **{field: value})
    ) == "finalization.conflict"


def test_finalized_retry_past_expiry_is_unusable(store, grants, signer) -> None:
    """A stored finalization is not returned once expired."""
    permit = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(permit))
    late = NOW + timedelta(seconds=90)
    assert refusal(
        finalize, store, grants, signer, final_request(permit), now=late
    ) == "finalization.permit_unusable"


def test_finalized_retry_applies_floor(store, grants, signer) -> None:
    """An acknowledgement above the counter refuses even a stored finalization."""
    permit = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(permit))
    request = final_request(permit, consumer_acked_through=9)
    assert refusal(finalize, store, grants, signer, request) == "finalization.issuer_rolled_back"


def test_finalization_unknown_expired_and_aborted_permits_unusable(store, grants, signer) -> None:
    """Unknown, expired and non-usable permits are refused as unusable."""
    permit = admit(store, grants, signer)
    request = final_request(permit)
    assert refusal(
        finalize, store, grants, signer, {**request, "permit_id": "permit-none"}
    ) == "finalization.permit_unusable"
    late = NOW + timedelta(seconds=90)
    assert refusal(finalize, store, grants, signer, request, now=late) == "finalization.permit_unusable"
    raw_exec(store.path, "UPDATE dispatch_permits SET state='abandoned'")
    assert refusal(finalize, store, grants, signer, request) == "finalization.permit_unusable"


def test_finalization_invalid_request(store, grants, signer) -> None:
    """A malformed finalization request is finalization.invalid_request."""
    permit = admit(store, grants, signer)
    request = final_request(permit)
    del request["requested_at"]
    assert refusal(finalize, store, grants, signer, request) == "finalization.invalid_request"


def test_catchup_bound_exceeded_changes_nothing(store, db, grants, signer) -> None:
    """Too large a gap refuses before any append or update."""
    permit = admit(store, grants, signer)
    for n in range(3):
        grant = f"other-{n}"
        grants.facts[grant] = grants.live()
        other = admit(store, grants, signer, permit_request(grant_id=grant, attempt_id=f"o-{n}"))
        finalize(store, grants, signer, final_request(other, consumer_acked_through=n))
    assert store.current_counter() == 3
    code = refusal(finalize, store, grants, signer, final_request(permit), catchup_max=3)
    assert code == "finalization.catchup_required"
    assert row_count(db, "issuer_events") == 3
    assert store.lookup_attempt("attempt-1", operator=OPERATOR)["state"] == "issued"
    request = final_request(permit, consumer_acked_through=1)
    data, envelope = finalize(store, grants, signer, request, catchup_max=3)
    assert envelope["from_version"] == 2 and envelope["through_version"] == 4
    assert [e["version"] for e in envelope["events"]] == [2, 3, 4]


def test_catchup_refusal_signs_nothing(store, grants) -> None:
    """A catch-up refusal happens before any event or finalization signature is minted."""
    calls: list[str] = []

    class Counting(FakeSigner):
        """Signer recording every event or finalization signature request."""

        def sign_event(self, key_id, digest):
            """Record and sign an event."""
            calls.append("event")
            return super().sign_event(key_id, digest)

        def sign_finalization(self, key_id, body):
            """Record and sign a finalization."""
            calls.append("finalization")
            return super().sign_finalization(key_id, body)

    signer = Counting()
    permit = admit(store, grants, signer)
    assert refusal(finalize, store, grants, signer, final_request(permit), catchup_max=0) == (
        "finalization.catchup_required"
    )
    assert calls == []


def test_key_rotated_refuses_finalization(store, db, grants, signer) -> None:
    """A permit signed under a no-longer-active key cannot finalize."""
    permit = admit(store, grants, signer)
    code = refusal(finalize, store, grants, FakeSigner("key-2"), final_request(permit))
    assert code == "finalization.key_rotated" and row_count(db, "issuer_events") == 0


def test_finalization_grant_revoked(store, grants, signer) -> None:
    """Revocation or pending cascade at finalization refuses."""
    permit = admit(store, grants, signer)
    grants.set(revoked=True)
    assert refusal(finalize, store, grants, signer, final_request(permit)) == "finalization.grant_revoked"
    grants.set(revoked=False, cascade_pending=True)
    assert refusal(finalize, store, grants, signer, final_request(permit)) == "finalization.grant_revoked"


def test_finalization_floors(store, grants, signer) -> None:
    """The counter must be at least the acknowledgement and at least R_p."""
    permit = admit(store, grants, signer)
    request = final_request(permit, consumer_acked_through=4)
    assert refusal(finalize, store, grants, signer, request) == "finalization.issuer_rolled_back"
    raw_exec(store.path, "UPDATE dispatch_permits SET r_p = 7")
    assert refusal(
        finalize, store, grants, signer, final_request(permit)
    ) == "finalization.issuer_rolled_back"


# ------------------------------------------------------------- constraints

def insert_row(db: Path, attempt: str, grant: str = GRANT_ID, state: str = "issued", **extra: object) -> None:
    """Insert one raw row with permit bytes, for constraint tests."""
    cols = {"permit_id": f"p-{attempt}", "grant_id": grant, "attempt_id": attempt, "state": state,
            "permit_bytes": b"x"}
    cols.update(extra)
    names = ",".join(cols)
    marks = ",".join("?" for _ in cols)
    raw_exec(db, f"INSERT INTO dispatch_permits({names}) VALUES({marks})", tuple(cols.values()))


def test_attempt_id_is_unique(store, db) -> None:
    """A duplicate attempt id is rejected by SQL."""
    insert_row(db, "a1", grant="g1")
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a1", grant="g2", permit_id="p-other")


def test_one_original_permit_per_grant(store, db) -> None:
    """Two original permits for a grant are rejected even when terminal."""
    insert_row(db, "a1", state="abandoned")
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a2", state="abandoned")


def test_one_nonterminal_permit_per_grant(store, db) -> None:
    """A replacement cannot be nonterminal while another permit is nonterminal."""
    insert_row(db, "a1")
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a2", replaces_permit_id="p-a1")


def test_replaces_permit_id_is_unique_and_references(store, db) -> None:
    """Two successors of one permit, and a dangling reference, are rejected."""
    insert_row(db, "a1", state="abandoned")
    insert_row(db, "a2", state="abandoned", replaces_permit_id="p-a1")
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a3", state="abandoned", replaces_permit_id="p-a1")
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a4", state="abandoned", replaces_permit_id="p-missing")


def test_aborted_row_check_constraints(store, db) -> None:
    """An aborted row has no permit bytes; every other row must have them."""
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a1", state="aborted", permit_id=None)
    with pytest.raises(sqlite3.IntegrityError):
        raw_exec(db, "INSERT INTO dispatch_permits(permit_id,grant_id,attempt_id,state) VALUES('p',?,?,?)",
                 ("g", "a2", "issued"))
    with pytest.raises(sqlite3.IntegrityError):
        insert_row(db, "a3", state="bogus")


def test_aborted_rows_do_not_hold_the_grant(store, db) -> None:
    """Several aborted rows for one grant coexist with one live permit."""
    raw_exec(db, "INSERT INTO dispatch_permits(grant_id,attempt_id,state) VALUES('g','x1','aborted')")
    raw_exec(db, "INSERT INTO dispatch_permits(grant_id,attempt_id,state) VALUES('g','x2','aborted')")
    insert_row(db, "a1", grant="g")
    assert row_count(db) == 3


def test_event_table_constraints(store, db) -> None:
    """Event versions start at one and digests are unique."""
    sql = "INSERT INTO issuer_events VALUES(?,?,?,?,?,?,?)"
    with pytest.raises(sqlite3.IntegrityError):
        raw_exec(db, sql, (0, "finalization", "{}", "0" * 64, "d1", "k", "s"))
    raw_exec(db, sql, (1, "finalization", "{}", "0" * 64, "d1", "k", "s"))
    with pytest.raises(sqlite3.IntegrityError):
        raw_exec(db, sql, (2, "finalization", "{}", "d1", "d1", "k", "s"))


# ----------------------------------------------------- persistence and misc

def test_crash_and_reopen_continues(db, grants, signer) -> None:
    """After close and reopen, retries and finalization behave identically."""
    first = SqliteDispatchPermitStore(db)
    permit = admit(first, grants, signer)
    first.close()
    second = SqliteDispatchPermitStore(db)
    assert admit(second, grants, signer) == permit
    data, _ = finalize(second, grants, signer, final_request(permit))
    second.close()
    third = SqliteDispatchPermitStore(db)
    assert finalize(third, grants, signer, final_request(permit))[0] == data
    assert third.current_counter() == 1
    third.close()


def test_two_stores_on_one_file_share_state(db, grants, signer) -> None:
    """A second store object on the same file sees the first one's writes."""
    one, two = SqliteDispatchPermitStore(db), SqliteDispatchPermitStore(db)
    permit = admit(one, grants, signer)
    assert refusal(admit, two, grants, signer, permit_request(attempt_id="attempt-2")) == "permit.conflict"
    finalize(two, grants, signer, final_request(permit))
    assert one.current_counter() == 1
    one.close()
    two.close()


def test_refused_codes_are_in_the_frozen_vocabulary() -> None:
    """PermitRefused only accepts frozen codes."""
    for code in wire.REFUSAL_CODES:
        assert PermitRefused(code).code == code
    with pytest.raises(ValueError):
        PermitRefused("permit.made_up")


def test_every_observed_refusal_is_frozen(store, grants, signer) -> None:
    """Refusals raised by the store carry codes from dispatch_wire only."""
    seen = set()
    for call in (
        lambda: admit(store, grants, signer, permit_request(grant_id="nope")),
        lambda: admit(store, grants, signer, permit_request(consumer_acked_through=3)),
        lambda: finalize(store, grants, signer, {"permit_id": "x"}),
    ):
        seen.add(refusal(call))
    assert seen and seen <= wire.REFUSAL_CODES


def test_schema_guards(tmp_path: Path) -> None:
    """Memory paths, bad timeouts, newer schemas and foreign tables are refused."""
    with pytest.raises(ValueError):
        SqliteDispatchPermitStore(":memory:")
    with pytest.raises(ValueError):
        SqliteDispatchPermitStore(tmp_path / "t.db", timeout=0)
    newer = tmp_path / "newer.db"
    with open_db(newer) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(RuntimeError):
        SqliteDispatchPermitStore(newer)
    foreign = tmp_path / "foreign.db"
    with open_db(foreign) as conn:
        conn.execute("CREATE TABLE dispatch_permits(x INTEGER)")
    with pytest.raises(RuntimeError):
        SqliteDispatchPermitStore(foreign)


def test_read_only_helpers(store, grants, signer) -> None:
    """lookup_attempt and events return plain data without writes."""
    assert store.lookup_attempt("missing", operator=OPERATOR) is None and store.events(1, 5) == []
    admit(store, grants, signer)
    assert store.lookup_attempt("attempt-1", operator=OPERATOR)["grant_id"] == GRANT_ID


@pytest.mark.parametrize("iteration", range(30))
def test_threaded_admission_abort_race_has_one_winner(db, iteration) -> None:
    """Admission and abort race on one attempt id: exactly one wins, never both rows."""
    grants, signer = FakeGrants(), FakeSigner()
    first, second = SqliteDispatchPermitStore(db), SqliteDispatchPermitStore(db)
    attempt = f"race-{iteration}"
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def do_admit() -> None:
        """Admit after the barrier."""
        barrier.wait()
        try:
            results["admit"] = first.admit(
                permit_request(attempt_id=attempt, grant_id=f"g-{iteration}"),
                grants=grants, signer=signer, now=NOW,
            )
        except PermitRefused as error:
            results["admit"] = error.code

    def do_abort() -> None:
        """Abort after the barrier."""
        barrier.wait()
        results["abort"] = second.abort(attempt, f"g-{iteration}", operator=OPERATOR, now=NOW)

    grants.facts[f"g-{iteration}"] = grants.live()
    threads = [threading.Thread(target=do_admit), threading.Thread(target=do_abort)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    row = first.lookup_attempt(attempt, operator=OPERATOR)
    admitted = isinstance(results["admit"], bytes)
    if admitted:
        assert results["abort"] == ("abort.admission_won", results["admit"])
        assert row["state"] == "issued" and row["permit_bytes"] is not None
    else:
        assert results["admit"] == "permit.attempt_aborted"
        assert results["abort"] == ("abort.recorded", None)
        assert row["state"] == "aborted" and row["permit_bytes"] is None
    assert row_count(db) == 1
    first.close()
    second.close()


def test_finalized_retry_applies_the_permits_r_p_floor(store, db, grants, signer) -> None:
    """A stored finalization is refused when the counter has fallen below the permit's R_p."""
    first = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(first))
    grants.facts["grant-2"] = FakeGrants.live()
    second = admit(
        store, grants, signer,
        permit_request(grant_id="grant-2", attempt_id="attempt-2", reservation_id="res-2",
                       consumer_acked_through=1),
    )
    final_request_two = final_request(second, consumer_acked_through=1)
    finalize(store, grants, signer, final_request_two)
    assert json.loads(second)["revocation_version"] == 1
    with open_db(db) as connection:
        connection.execute("DELETE FROM issuer_events")  # simulate a lost chain: counter 0 < R_p 1
    request = final_request(second, consumer_acked_through=0)
    assert refusal(finalize, store, grants, signer, request) == "finalization.issuer_rolled_back"


def test_finalized_retry_after_key_rotation_returns_the_stored_bytes(store, db, grants) -> None:
    """A lost-response retry is not stranded by rotation: stored bytes stay verifiable."""
    old = FakeSigner("key-1")
    permit = admit(store, grants, old)
    first, _ = finalize(store, grants, old, final_request(permit))
    again, _ = finalize(store, grants, FakeSigner("key-2"), final_request(permit))
    assert again == first and row_count(db, "issuer_events") == 1
    body = {k: v for k, v in json.loads(first).items() if k != "issuer_signature"}
    assert wire.verify_finalization(public_key("key-1"), body, json.loads(first)["issuer_signature"])


def _weakened_database(path: Path, old: str, new: str) -> None:
    """Create a database whose DDL has the right column names but one weakened clause."""
    assert old in store_module._SCHEMA
    with open_db(path) as connection:
        connection.executescript(store_module._SCHEMA.replace(old, new, 1))


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("attempt_id TEXT NOT NULL UNIQUE", "attempt_id TEXT NOT NULL"),
        ("replaces_permit_id TEXT UNIQUE REFERENCES", "replaces_permit_id TEXT REFERENCES"),
        ("WHERE replaces_permit_id IS NULL AND state != 'aborted'", "WHERE replaces_permit_id IS NULL"),
        ("WHERE state IN ('issued', 'finalized')", "WHERE state IN ('issued')"),
        ("CHECK(state != 'aborted' OR (permit_bytes IS NULL AND permit_id IS NULL))", "CHECK(1)"),
    ],
)
def test_store_refuses_a_file_with_weaker_constraints_than_the_frozen_schema(tmp_path, old, new) -> None:
    """The right column names are not enough: every constraint and index predicate must match."""
    path = tmp_path / "weak.db"
    _weakened_database(path, old, new)
    with pytest.raises(RuntimeError, match="incompatible"):
        SqliteDispatchPermitStore(path)


def test_a_frozen_schema_file_reopens_cleanly(tmp_path) -> None:
    """The exact frozen DDL created by another connection is accepted."""
    path = tmp_path / "ok.db"
    with open_db(path) as connection:
        connection.executescript(store_module._SCHEMA)
    SqliteDispatchPermitStore(path).close()
