"""E1 C2 slice 2 (issuer): attested abandon, successor issuance and operator authentication."""
# ruff: noqa: F811  (pytest fixtures are imported from the slice-1 test module)
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from test_dispatch_permit_store import (  # noqa: F401  (the fixtures db/store/grants/signer)
    db,
    grants,
    signer,
    store,
    GRANT_ID,
    NOW,
    OPERATOR,
    FakeGrants,
    FakeOperator,
    FakeSigner,
    admit,
    final_request,
    finalize,
    permit_request,
    raw_exec,
    refusal,
    row_count,
)

from phylax import dispatch_wire as wire
from phylax.dispatch_permit_store import (
    AbandonRefused,
    OperatorRefused,
    PermitRefused,
    SqliteDispatchPermitStore,
)


def attestation(permit_bytes: bytes, **overrides: object) -> dict:
    """Return a valid abandon attestation for an issued permit."""
    permit = json.loads(permit_bytes)
    base = {
        "attempt_id": permit["attempt_id"], "permit_id": permit["permit_id"], "cause": "loss",
        "consumer_fencing_epoch": 1, "fence_evidence": "fence-record-1",
        "non_commit_evidence": "no-4.3-commit-1", "release_pending_record": "release-pending-1",
        "no_intent_exists": True,
    }
    return {**base, **overrides}


def abandon_code(store, attest, operator=OPERATOR) -> str:
    """Run an abandon that must refuse and return its code."""
    with pytest.raises(AbandonRefused) as info:
        store.abandon(attest, operator=operator, now=NOW)
    return info.value.code


def state_of(store, attempt: str = "attempt-1") -> str:
    return store.lookup_attempt(attempt, operator=OPERATOR)["state"]


def dump(db: Path) -> dict[str, list]:
    conn = sqlite3.connect(db)
    try:
        return {
            t: conn.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()
            for t in ("dispatch_permits", "abandon_attestations", "issuer_events")
        }
    finally:
        conn.close()


# ---------------------------------------------------------- operator authentication


@pytest.mark.parametrize("reference", [None, "", "   "])
def test_every_operator_call_is_refused_without_a_reference(store, db, grants, signer, reference) -> None:
    permit = admit(store, grants, signer)
    denied = FakeOperator(reference)
    before = dump(db)
    with pytest.raises(OperatorRefused):
        store.lookup_attempt("attempt-1", operator=denied)
    with pytest.raises(OperatorRefused):
        store.abort("attempt-1", GRANT_ID, operator=denied, now=NOW)
    with pytest.raises(OperatorRefused):
        store.abandon(attestation(permit), operator=denied, now=NOW)
    assert dump(db) == before
    assert [c[0] for c in denied.calls] == ["lookup", "abort", "abandon"]


def test_the_operator_port_receives_the_operation_attempt_and_grant(store, grants, signer) -> None:
    admit(store, grants, signer)
    spy = FakeOperator("op-spy")
    store.lookup_attempt("attempt-1", operator=spy)
    store.abort("attempt-1", GRANT_ID, operator=spy, now=NOW)
    assert spy.calls == [("lookup", "attempt-1", None), ("abort", "attempt-1", GRANT_ID)]


def test_the_operator_reference_is_recorded_as_the_abort_disposition(store, db) -> None:
    store.abort("attempt-x", GRANT_ID, operator=FakeOperator("op-77"), now=NOW)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT abort_disposition FROM dispatch_permits").fetchone() == ("op-77",)
    finally:
        conn.close()


def test_a_lookup_never_changes_state(store, db, grants, signer) -> None:
    admit(store, grants, signer)
    before = dump(db)
    assert state_of(store) == "issued"
    assert dump(db) == before


# ------------------------------------------------------------------- attestation shape


@pytest.mark.parametrize(
    "overrides",
    [
        {"cause": "other"}, {"cause": 7}, {"consumer_fencing_epoch": 0},
        {"consumer_fencing_epoch": True}, {"consumer_fencing_epoch": "1"},
        {"no_intent_exists": False}, {"no_intent_exists": "yes"},
        {"fence_evidence": " "}, {"non_commit_evidence": ""}, {"release_pending_record": None},
        {"attempt_id": ""}, {"permit_id": 5},
    ],
)
def test_a_malformed_attestation_is_refused_and_writes_nothing(store, db, grants, signer, overrides) -> None:
    permit = admit(store, grants, signer)
    before = dump(db)
    assert abandon_code(store, attestation(permit, **overrides)) == "abandon.invalid_attestation"
    assert dump(db) == before


def test_an_attestation_with_missing_or_extra_fields_is_refused(store, grants, signer) -> None:
    permit = admit(store, grants, signer)
    good = attestation(permit)
    missing = {k: v for k, v in good.items() if k != "cause"}
    assert abandon_code(store, missing) == "abandon.invalid_attestation"
    assert abandon_code(store, {**good, "verified": True}) == "abandon.invalid_attestation"


def test_a_malformed_attestation_is_refused_before_the_operator_is_consulted(store, grants, signer) -> None:
    permit = admit(store, grants, signer)
    spy = FakeOperator("op-spy")
    assert abandon_code(store, attestation(permit, cause="x"), spy) == "abandon.invalid_attestation"
    assert spy.calls == []


# ------------------------------------------------------------------------ abandon


def test_abandon_marks_the_permit_and_records_the_attestation_as_audit_evidence(store, db, grants, signer) -> None:
    permit = admit(store, grants, signer)
    attest = attestation(permit)
    outcome, record = store.abandon(attest, operator=FakeOperator("op-9"), now=NOW)
    assert outcome == "abandon.recorded" and outcome in wire.ABANDON_OUTCOMES
    assert state_of(store) == "abandoned"
    assert record["permit_id"] == attest["permit_id"] and record["disposition_ref"] == "op-9"
    assert record["attestation_digest"] == wire.attestation_digest(attest)
    conn = sqlite3.connect(db)
    try:
        stored = conn.execute("SELECT attestation FROM abandon_attestations").fetchone()[0]
    finally:
        conn.close()
    assert json.loads(stored) == attest


def test_an_identical_abandon_retry_returns_the_recorded_outcome(store, db, grants, signer) -> None:
    permit = admit(store, grants, signer)
    attest = attestation(permit)
    first = store.abandon(attest, operator=OPERATOR, now=NOW)[1]
    again = store.abandon(attest, operator=FakeOperator("op-other"), now=NOW + timedelta(seconds=5))
    assert again == ("abandon.already_abandoned", first)
    assert row_count(db, "abandon_attestations") == 1


def test_a_different_attestation_for_an_abandoned_permit_conflicts(store, db, grants, signer) -> None:
    permit = admit(store, grants, signer)
    store.abandon(attestation(permit), operator=OPERATOR, now=NOW)
    before = dump(db)
    assert abandon_code(store, attestation(permit, cause="cancellation")) == "abandon.conflict"
    assert dump(db) == before


def test_abandon_of_an_unknown_permit_or_the_wrong_attempt_is_refused(store, grants, signer) -> None:
    permit = admit(store, grants, signer)
    assert abandon_code(store, attestation(permit, permit_id="permit-nope")) == "abandon.permit_unknown"
    assert abandon_code(store, attestation(permit, attempt_id="attempt-9")) == "abandon.attempt_mismatch"
    assert state_of(store) == "issued"


def test_abandon_never_proves_anything_a_finalized_permit_is_abandoned_too(store, grants, signer) -> None:
    permit = admit(store, grants, signer)
    finalize(store, grants, signer, final_request(permit))
    assert state_of(store) == "finalized"
    store.abandon(attestation(permit), operator=OPERATOR, now=NOW)
    assert state_of(store) == "abandoned"


def test_an_abandoned_permit_can_never_be_finalized(store, db, grants, signer) -> None:
    permit = admit(store, grants, signer)
    store.abandon(attestation(permit), operator=OPERATOR, now=NOW)
    before = dump(db)
    assert refusal(finalize, store, grants, signer, final_request(permit)) == "finalization.permit_unusable"
    assert dump(db) == before


def test_abandoning_a_finalized_permit_blocks_a_finalization_retry(store, grants, signer) -> None:
    permit = admit(store, grants, signer)
    request = final_request(permit)
    finalize(store, grants, signer, request)
    store.abandon(attestation(permit), operator=OPERATOR, now=NOW)
    assert refusal(finalize, store, grants, signer, request) == "finalization.permit_unusable"


def test_abandon_refuses_a_nonterminal_permit_that_already_has_a_successor(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    second = admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    store.abandon(attestation(second), operator=OPERATOR, now=NOW)
    raw_exec(db, "UPDATE dispatch_permits SET state = 'issued' WHERE attempt_id = 'attempt-1'")
    assert abandon_code(store, attestation(first)) == "abandon.permit_terminal"


# ----------------------------------------------------------------------- successor


def test_a_new_attempt_after_an_abandon_is_a_successor_and_records_its_predecessor(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    second = admit(store, grants, signer, permit_request(attempt_id="attempt-2"), now=NOW + timedelta(seconds=1))
    assert json.loads(second)["permit_id"] != json.loads(first)["permit_id"]
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT attempt_id, state, replaces_permit_id FROM dispatch_permits ORDER BY row_id"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [
        ("attempt-1", "abandoned", None),
        ("attempt-2", "issued", json.loads(first)["permit_id"]),
    ]


def test_an_unabandoned_permit_never_yields_a_successor_even_when_expired(store, grants, signer) -> None:
    admit(store, grants, signer)
    later = NOW + timedelta(hours=1)
    request = permit_request(attempt_id="attempt-2", requested_at=wire.timestamp(later))
    assert refusal(admit, store, grants, signer, request, later) == "permit.conflict"


def test_a_second_successor_while_the_first_is_live_conflicts(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    assert refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-3")) == "permit.conflict"
    assert row_count(db) == 2


def test_an_identical_successor_retry_returns_the_stored_permit(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    request = permit_request(attempt_id="attempt-2")
    assert admit(store, grants, signer, request) == admit(store, grants, signer, request)
    assert row_count(db) == 2


def test_a_successor_passes_every_issuance_check(store, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    grants.set(revoked=True)
    assert refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-2")) == "permit.grant_revoked"
    grants.set(revoked=False)
    assert refusal(
        admit, store, grants, signer, permit_request(attempt_id="attempt-2", consumer_acked_through=99)
    ) == "permit.issuer_rolled_back"
    grants.set(payload_digest="f" * 64)
    assert refusal(admit, store, grants, signer, permit_request(attempt_id="attempt-2")) == "permit.grant_mismatch"


def test_a_successor_may_itself_be_abandoned_and_replaced(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    second = admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    store.abandon(attestation(second), operator=OPERATOR, now=NOW)
    third = admit(store, grants, signer, permit_request(attempt_id="attempt-3"))
    assert json.loads(third)["attempt_id"] == "attempt-3" and row_count(db) == 3


def test_the_database_itself_refuses_two_successors_of_one_permit(store, db, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    predecessor = json.loads(first)["permit_id"]
    with pytest.raises(sqlite3.IntegrityError):
        raw_exec(
            db,
            "INSERT INTO dispatch_permits(permit_id, grant_id, attempt_id, state, permit_bytes,"
            " replaces_permit_id) VALUES('permit-x', ?, 'attempt-9', 'abandoned', x'00', ?)",
            (GRANT_ID, predecessor),
        )


def test_a_finalized_successor_works_end_to_end(store, grants, signer) -> None:
    first = admit(store, grants, signer)
    store.abandon(attestation(first), operator=OPERATOR, now=NOW)
    second = admit(store, grants, signer, permit_request(attempt_id="attempt-2"))
    data, envelope = finalize(store, grants, signer, final_request(second))
    assert json.loads(data)["attempt_id"] == "attempt-2" and envelope["through_version"] == 1


# ------------------------------------------------------------------------ races


@pytest.mark.parametrize("iteration", range(5))
def test_two_racing_successor_requests_have_exactly_one_winner(db, iteration) -> None:
    grants, signer = FakeGrants(), FakeSigner()
    first, second = SqliteDispatchPermitStore(db), SqliteDispatchPermitStore(db)
    permit = admit(first, grants, signer)
    first.abandon(attestation(permit), operator=OPERATOR, now=NOW)
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def run(name: str, store, attempt: str) -> None:
        barrier.wait()
        try:
            results[name] = admit(store, grants, signer, permit_request(attempt_id=attempt))
        except PermitRefused as error:
            results[name] = error.code

    threads = [
        threading.Thread(target=run, args=("a", first, "attempt-a")),
        threading.Thread(target=run, args=("b", second, "attempt-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    outcomes = sorted(r if isinstance(r, str) else "won" for r in results.values())
    assert outcomes == ["permit.conflict", "won"]
    assert row_count(db) == 2
    first.close()
    second.close()


@pytest.mark.parametrize("iteration", range(5))
def test_abandon_and_finalization_race_leaves_a_consistent_state(db, iteration) -> None:
    grants, signer = FakeGrants(), FakeSigner()
    first, second = SqliteDispatchPermitStore(db), SqliteDispatchPermitStore(db)
    permit = admit(first, grants, signer)
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def do_abandon() -> None:
        barrier.wait()
        results["abandon"] = first.abandon(attestation(permit), operator=OPERATOR, now=NOW)[0]

    def do_finalize() -> None:
        barrier.wait()
        try:
            results["finalize"] = finalize(second, grants, signer, final_request(permit))[0]
        except PermitRefused as error:
            results["finalize"] = error.code

    threads = [threading.Thread(target=do_abandon), threading.Thread(target=do_finalize)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results["abandon"] == "abandon.recorded"
    assert second.lookup_attempt("attempt-1", operator=OPERATOR)["state"] == "abandoned"
    assert isinstance(results["finalize"], (bytes, str))
    assert refusal(finalize, second, grants, signer, final_request(permit)) == "finalization.permit_unusable"
    first.close()
    second.close()


# --------------------------------------------------------------- schema compatibility


def test_a_slice_one_database_gains_the_attestation_table_on_open(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    SqliteDispatchPermitStore(path).close()
    raw_exec(path, "DROP TABLE abandon_attestations")
    SqliteDispatchPermitStore(path).close()
    conn = sqlite3.connect(path)
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert "abandon_attestations" in names


def test_the_abandon_vocabulary_is_closed_and_separate_from_permit_refusals() -> None:
    assert wire.ABANDON_REFUSAL_CODES.isdisjoint(wire.REFUSAL_CODES)
    with pytest.raises(ValueError):
        AbandonRefused("abandon.made_up")
