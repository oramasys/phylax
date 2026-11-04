"""Operator-signed assertions: expiry, single-use nonces, revocation, rollback (real SQLite)."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.bindings import crypto_sign_seed_keypair

from phylax import dispatch_wire as wire
from phylax.operator_assertion import (
    OperatorAssertionRefused,
    OperatorAssertionVerifier,
    parse_assertion,
    parse_registry,
    sign_assertion,
    sign_registry,
)

NOW = datetime(2026, 11, 2, 4, 0, 0, tzinfo=UTC)
TRUST_SEED, ALICE_SEED, BOB_SEED = b"T" * 32, b"A" * 32, b"B" * 32
AUDIENCE = "phylax:issuer-1"


def pub(seed: bytes) -> str:
    """Return the base64url public key for a seed."""
    return wire.b64url_encode(crypto_sign_seed_keypair(seed)[0])


def entry(operator: str, seed: bytes, **overrides: object) -> dict:
    """Return a registry entry for an operator."""
    base = {
        "operator_id": operator, "key_id": f"{operator}-k1", "public_key": pub(seed),
        "not_before": wire.timestamp(NOW - timedelta(days=1)),
        "not_after": wire.timestamp(NOW + timedelta(days=30)),
        "operations": ["abandon", "abort", "retention.prune"], "revoked_at": None,
    }
    return {**base, **overrides}


def registry_bytes(version: int = 1, entries: list | None = None, issued: datetime = NOW) -> bytes:
    """Return a signed registry envelope."""
    body = {
        "schema_version": 1, "registry_version": version, "issued_at": wire.timestamp(issued),
        "entries": entries if entries is not None else [entry("alice", ALICE_SEED), entry("bob", BOB_SEED)],
    }
    return sign_registry(TRUST_SEED, body)


def assertion(seed: bytes = ALICE_SEED, operator: str = "alice", **overrides: object) -> bytes:
    """Return a signed assertion for abandon on attempt-1."""
    body = {
        "schema_version": 1, "operator_id": operator, "key_id": f"{operator}-k1",
        "operation": "abandon", "attempt_id": "attempt-1", "grant_id": "grant-1",
        "audience": AUDIENCE, "nonce": "n" * 22 + "0",
        "issued_at": wire.timestamp(NOW), "expires_at": wire.timestamp(NOW + timedelta(seconds=120)),
    }
    return sign_assertion(seed, {**body, **overrides})


class Env:
    """Mutable clock and registry source for one test."""

    def __init__(self, tmp_path: Path) -> None:
        """Start at NOW with a version-1 registry."""
        self.now = NOW
        self.registry = registry_bytes()
        self.verifier = OperatorAssertionVerifier(
            state_path=tmp_path / "operator.db",
            trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0], audience=AUDIENCE,
            registry_source=lambda: self.registry, clock=lambda: self.now,
        )

    def call(self, raw: bytes, **overrides: object) -> str:
        """Verify and consume an assertion for the default binding."""
        args = {"operation": "abandon", "attempt_id": "attempt-1", "grant_id": "grant-1", **overrides}
        return self.verifier.verify_and_consume(raw, **args)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    """Return a fresh environment."""
    return Env(tmp_path)


def refused(code: str, fn, *args, **kwargs) -> None:
    """Assert a call raises the given operator refusal code."""
    with pytest.raises(OperatorAssertionRefused) as caught:
        fn(*args, **kwargs)
    assert caught.value.code == code


def test_valid_assertion_authorizes_once_and_names_the_person(env) -> None:
    """A good assertion yields a per-person reference; the same nonce is then refused."""
    reference = env.call(assertion())
    assert reference == "operator:alice:" + "n" * 22 + "0"
    refused("operator.replayed", env.call, assertion())


def test_each_person_has_their_own_key(env) -> None:
    """Bob cannot sign as Alice, and Alice's key does not authorize as Bob."""
    refused("operator.signature", env.call, assertion(seed=BOB_SEED))
    refused("operator.signature", env.call, assertion(seed=ALICE_SEED, operator="bob"))
    assert env.call(assertion(seed=BOB_SEED, operator="bob")).startswith("operator:bob:")


def test_same_nonce_for_different_operators_is_independent(env) -> None:
    """Nonces are scoped per operator."""
    env.call(assertion())
    assert env.call(assertion(seed=BOB_SEED, operator="bob"))


@pytest.mark.parametrize(("overrides", "call", "code"), [
    ({"audience": "phylax:other"}, {}, "operator.audience_mismatch"),
    ({}, {"attempt_id": "attempt-2"}, "operator.binding_mismatch"),
    ({}, {"grant_id": "grant-2"}, "operator.binding_mismatch"),
    ({}, {"grant_id": None}, "operator.binding_mismatch"),
    ({}, {"operation": "abort"}, "operator.binding_mismatch"),
    ({"operation": "release"}, {"operation": "release"}, "operator.operation_not_permitted"),
])
def test_binding_and_audience_are_exact(env, overrides, call, code) -> None:
    """An assertion authorizes exactly one operation, attempt, grant and audience."""
    refused(code, env.call, assertion(**overrides), **call)


def test_expiry_future_issue_and_lifetime(env) -> None:
    """Expired, future-dated and over-long assertions are refused."""
    raw = assertion()
    env.now = NOW + timedelta(seconds=121)
    refused("operator.expired", env.call, raw)
    env.now = NOW
    future = assertion(issued_at=wire.timestamp(NOW + timedelta(seconds=60)),
                       expires_at=wire.timestamp(NOW + timedelta(seconds=120)), nonce="f" * 23)
    refused("operator.not_yet_valid", env.call, future)
    long = assertion(expires_at=wire.timestamp(NOW + timedelta(seconds=301)), nonce="l" * 23)
    refused("operator.lifetime_too_long", env.call, long)
    inverted = assertion(expires_at=wire.timestamp(NOW), nonce="i" * 23)
    refused("operator.lifetime_too_long", env.call, inverted)


def test_failed_checks_do_not_burn_the_nonce(env) -> None:
    """A refused attempt consumes nothing; the same assertion works once the cause is fixed."""
    raw = assertion()
    refused("operator.binding_mismatch", env.call, raw, attempt_id="attempt-9")
    assert env.call(raw)


def test_revocation_is_immediate_and_rollback_cannot_undo_it(env) -> None:
    """A newer registry revoking a key stops it at once; replaying the older registry is refused."""
    old = env.registry
    assert env.call(assertion(nonce="a" * 23))
    revoked = entry("alice", ALICE_SEED, revoked_at=wire.timestamp(NOW))
    env.registry = registry_bytes(2, [revoked, entry("bob", BOB_SEED)])
    refused("operator.key_revoked", env.call, assertion(nonce="b" * 23))
    env.registry = old
    refused("operator.registry_rollback", env.call, assertion(nonce="c" * 23))


def test_floor_rises_on_sight_even_when_the_call_is_refused(env) -> None:
    """Seeing a newer authority-signed registry raises the floor, so an older one is rolled back."""
    env.registry = registry_bytes(5)
    refused("operator.binding_mismatch", env.call, assertion(), attempt_id="x")
    env.registry = registry_bytes(1)
    refused("operator.registry_rollback", env.call, assertion(nonce="d" * 23))


def test_key_window_and_removal(env) -> None:
    """A key outside its validity window, or absent from the registry, is refused."""
    env.registry = registry_bytes(1, [entry("alice", ALICE_SEED, not_after=wire.timestamp(NOW - timedelta(seconds=1)))])
    refused("operator.key_inactive", env.call, assertion())
    env.registry = registry_bytes(2, [entry("bob", BOB_SEED)])
    refused("operator.unknown_key", env.call, assertion(nonce="e" * 23))


def test_registry_must_be_signed_by_the_pinned_authority_and_fresh(env) -> None:
    """A registry signed by another key, or older than the freshness bound, is refused."""
    env.registry = sign_registry(b"X" * 32, json.loads(registry_bytes())["body"])
    refused("operator.registry_signature", env.call, assertion())
    env.registry = registry_bytes(1, issued=NOW - timedelta(days=2))
    refused("operator.registry_stale", env.call, assertion())
    env.registry = registry_bytes(1, issued=NOW + timedelta(minutes=5))
    refused("operator.registry_stale", env.call, assertion())


@pytest.mark.parametrize("mutate", [
    lambda b: b + b" ", lambda b: b"not json", lambda b: b'{"body":{},"signature":"x","extra":1}',
    lambda b: b"x" * 70_000, lambda b: b.replace(b'"schema_version":1', b'"schema_version":2'),
])
def test_malformed_assertions_are_refused(env, mutate) -> None:
    """Non-canonical, oversized, extra-field or wrong-version assertions never parse."""
    refused("operator.malformed", env.call, mutate(assertion()))


def test_registry_shape_is_strict() -> None:
    """Unsorted, duplicate, empty-operation or short-key entries are malformed."""
    trust = crypto_sign_seed_keypair(TRUST_SEED)[0]
    a, b = entry("alice", ALICE_SEED), entry("bob", BOB_SEED)
    for entries in ([b, a], [a, a], [{**a, "operations": []}], [{**a, "operations": ["b", "a"]}],
                    [{**a, "public_key": wire.b64url_encode(b"short")}],
                    [{**a, "not_after": a["not_before"]}], [{**a, "extra": 1}]):
        refused("operator.malformed", parse_registry, registry_bytes(1, entries), trust_public_key=trust)
    refused("operator.malformed", parse_registry, registry_bytes(0), trust_public_key=trust)


def test_one_shot_authority_implements_the_port(env) -> None:
    """The authority returns a reference once, then None with a recorded reason."""
    authority = env.verifier.authority_for(assertion())
    assert authority.authorize("abandon", attempt_id="attempt-1", grant_id="grant-1").startswith("operator:alice:")
    assert authority.authorize("abandon", attempt_id="attempt-1", grant_id="grant-1") is None
    assert authority.refusal == "operator.already_used"
    bad = env.verifier.authority_for(assertion(nonce="z" * 23))
    assert bad.authorize("abort", attempt_id="attempt-1", grant_id="grant-1") is None
    assert bad.refusal == "operator.binding_mismatch"


def test_a_refused_first_call_still_ends_the_authority(env) -> None:
    """A mismatched first call is the only call: a matching retry on the same object is refused."""
    raw = assertion()
    authority = env.verifier.authority_for(raw)
    assert authority.authorize("abort", attempt_id="attempt-1", grant_id="grant-1") is None
    assert authority.refusal == "operator.binding_mismatch"
    assert authority.authorize("abandon", attempt_id="attempt-1", grant_id="grant-1") is None
    assert authority.refusal == "operator.already_used"
    # The nonce was not consumed by the refusal, so a fresh authority can still use it.
    assert env.verifier.authority_for(raw).authorize(
        "abandon", attempt_id="attempt-1", grant_id="grant-1").startswith("operator:alice:")


def test_concurrent_replays_consume_exactly_once(env) -> None:
    """Racing threads presenting one assertion: exactly one succeeds."""
    raw = assertion()
    results: list[str] = []

    def attempt() -> None:
        """Authorize one abandon attempt and record its outcome."""
        authority = env.verifier.authority_for(raw)
        results.append(authority.authorize("abandon", attempt_id="attempt-1", grant_id="grant-1") or "none")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r != "none" for r in results) == 1


def test_expired_nonces_are_cleaned_but_live_ones_kept(env) -> None:
    """Cleanup never removes a nonce whose assertion could still verify."""
    env.call(assertion())
    env.now = NOW + timedelta(seconds=60)
    refused("operator.replayed", env.call, assertion())
    env.now = NOW + timedelta(seconds=500)
    env.registry = registry_bytes(1, issued=env.now)
    env.call(assertion(nonce="g" * 23, issued_at=wire.timestamp(env.now),
                       expires_at=wire.timestamp(env.now + timedelta(seconds=60))))
    import sqlite3
    with sqlite3.connect(env.verifier.path) as db:
        assert db.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0] == 1


def test_refusal_vocabulary_is_closed_and_state_must_be_durable(tmp_path) -> None:
    """Unknown codes and in-memory state are rejected at construction."""
    with pytest.raises(ValueError):
        OperatorAssertionRefused("operator.invented")
    with pytest.raises(ValueError):
        OperatorAssertionVerifier(
            state_path=":memory:", trust_public_key=b"1" * 32, audience=AUDIENCE,
            registry_source=lambda: b"", clock=lambda: NOW,
        )
    with pytest.raises(ValueError):
        OperatorAssertionVerifier(
            state_path=tmp_path / "s.db", trust_public_key=b"short", audience=AUDIENCE,
            registry_source=lambda: b"", clock=lambda: NOW,
        )


def test_parse_assertion_rejects_bad_fields() -> None:
    """Bad nonce, operation and grant identifiers are malformed."""
    for overrides in ({"nonce": "short"}, {"operation": "Bad Op"}, {"grant_id": "bad id"},
                      {"issued_at": "yesterday"}):
        refused("operator.malformed", parse_assertion, assertion(**overrides))


def test_new_registry_observed_before_nonce_commit_refuses_old_call(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second verifier's committed revocation fences an already-verified old call."""
    other = OperatorAssertionVerifier(
        state_path=env.verifier.path,
        trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0], audience=AUDIENCE,
        registry_source=lambda: registry_bytes(2, [
            entry("alice", ALICE_SEED, revoked_at=wire.timestamp(NOW)),
            entry("bob", BOB_SEED),
        ]), clock=lambda: NOW,
    )
    commit = env.verifier._commit

    def interleave(
        operator_id: str, nonce: str, expires_at: str, now: datetime, **facts: object
    ) -> None:
        """Observe a revoking registry just before the old call consumes its nonce."""
        refused("operator.key_revoked", other.verify_and_consume, assertion(),
                operation="abandon", attempt_id="attempt-1", grant_id="grant-1")
        return commit(operator_id, nonce, expires_at, now, **facts)

    monkeypatch.setattr(env.verifier, "_commit", interleave)
    refused("operator.registry_rollback", env.call, assertion())


def test_clock_rollback_after_cleanup_and_restart_cannot_replay(env: Env) -> None:
    """A previously consumed assertion cannot become live again after nonce cleanup."""
    raw = assertion()
    env.call(raw)
    env.now = NOW + timedelta(seconds=500)
    env.call(assertion(nonce="q" * 23, issued_at=wire.timestamp(env.now),
                       expires_at=wire.timestamp(env.now + timedelta(seconds=60))))
    env.now = NOW
    restarted = OperatorAssertionVerifier(
        state_path=env.verifier.path,
        trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0], audience=AUDIENCE,
        registry_source=lambda: env.registry, clock=lambda: env.now,
    )
    refused("operator.clock_rollback", restarted.verify_and_consume, raw,
            operation="abandon", attempt_id="attempt-1", grant_id="grant-1")


def test_consumption_clock_migrates_existing_nonce_history(env: Env) -> None:
    """Legacy consumed timestamps seed the durable floor without resetting replay state."""
    env.now = NOW + timedelta(seconds=60)
    env.call(assertion())
    with sqlite3.connect(env.verifier.path) as db:
        db.execute("DROP TABLE consumption_clock")
    env.now = NOW
    restarted = OperatorAssertionVerifier(
        state_path=env.verifier.path,
        trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0], audience=AUDIENCE,
        registry_source=lambda: env.registry, clock=lambda: env.now,
    )
    refused("operator.clock_rollback", restarted.verify_and_consume, assertion(nonce="m" * 23),
            operation="abandon", attempt_id="attempt-1", grant_id="grant-1")


def test_consumption_clock_schema_uses_old_sqlite_compatible_seed_query() -> None:
    """The durable clock migration avoids HAVING without GROUP BY for older SQLite hosts."""
    from phylax.operator_assertion import _STATE_SCHEMA

    assert "HAVING" not in _STATE_SCHEMA
    assert "ORDER BY consumed_at DESC LIMIT 1" in _STATE_SCHEMA


def test_overlapping_valid_calls_sample_clock_under_the_write_lock(tmp_path: Path) -> None:
    """A later writer cannot make an earlier valid request look like clock rollback."""
    registry = registry_bytes()
    trust = crypto_sign_seed_keypair(TRUST_SEED)[0]
    first_ticks = iter((NOW, NOW + timedelta(seconds=2)))
    second_ticks = iter((NOW + timedelta(seconds=1), NOW + timedelta(seconds=1)))
    first = OperatorAssertionVerifier(
        state_path=tmp_path / "operator.db", trust_public_key=trust, audience=AUDIENCE,
        registry_source=lambda: registry, clock=lambda: next(first_ticks),
    )
    second = OperatorAssertionVerifier(
        state_path=tmp_path / "operator.db", trust_public_key=trust, audience=AUDIENCE,
        registry_source=lambda: registry, clock=lambda: next(second_ticks),
    )
    commit = first._commit

    def commit_after_second(
        operator_id: str, nonce: str, expires_at: str, now: datetime, **facts: object,
    ) -> None:
        """Commit another valid assertion between first-call validation and its write lock."""
        second.verify_and_consume(
            assertion(nonce="s" * 23), operation="abandon", attempt_id="attempt-1", grant_id="grant-1",
        )
        commit(operator_id, nonce, expires_at, now, **facts)

    first._commit = commit_after_second  # type: ignore[method-assign]
    assert first.verify_and_consume(
        assertion(nonce="f" * 23), operation="abandon", attempt_id="attempt-1", grant_id="grant-1",
    ).endswith("f" * 23)


def test_clock_step_back_between_validation_and_commit_is_refused(tmp_path: Path) -> None:
    """A backward step during one call cannot clean up or consume a nonce."""
    ticks = iter((NOW, NOW - timedelta(seconds=1)))
    verifier = OperatorAssertionVerifier(
        state_path=tmp_path / "operator.db",
        trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0], audience=AUDIENCE,
        registry_source=registry_bytes, clock=lambda: next(ticks),
    )

    refused(
        "operator.clock_rollback", verifier.verify_and_consume, assertion(),
        operation="abandon", attempt_id="attempt-1", grant_id="grant-1",
    )
    with sqlite3.connect(verifier.path) as database:
        assert database.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("case", "expected"),
    [("expiry", "operator.expired"), ("key", "operator.key_inactive"),
     ("revocation", "operator.key_revoked"), ("registry", "operator.registry_stale")],
)
def test_authority_windows_are_rechecked_under_write_lock(tmp_path: Path, case: str, expected: str) -> None:
    """A slow verification cannot consume an assertion after its authority window closes."""
    later = NOW + timedelta(seconds=121)
    overrides = {}
    if case == "key":
        overrides["not_after"] = wire.timestamp(NOW + timedelta(seconds=1))
    if case == "revocation":
        overrides["revoked_at"] = wire.timestamp(NOW + timedelta(seconds=1))
    registry = registry_bytes(entries=[entry("alice", ALICE_SEED, **overrides)])
    ticks = iter((NOW, later if case == "expiry" else NOW + timedelta(seconds=2)))
    verifier = OperatorAssertionVerifier(
        state_path=tmp_path / "operator.db", trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0],
        audience=AUDIENCE, registry_source=lambda: registry, clock=lambda: next(ticks),
        registry_max_age_seconds=1 if case == "registry" else 3600,
    )
    refused(expected, verifier.verify_and_consume, assertion(), operation="abandon",
            attempt_id="attempt-1", grant_id="grant-1")
    with sqlite3.connect(verifier.path) as database:
        assert database.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0] == 0


def test_commit_samples_the_clock_after_acquiring_the_write_lock(tmp_path: Path) -> None:
    """Time that passes while _commit waits for the write lock still closes the authority window."""
    current = [NOW]
    begins: list[str] = []

    class LockWaitConnection:
        """Delegate to a real connection, advancing the clock as the commit lock is granted."""

        def __init__(self, real: sqlite3.Connection) -> None:
            """Wrap the real connection that the verifier opened."""
            self._real = real

        def __getattr__(self, name: str) -> object:
            """Forward every other attribute to the real connection."""
            return getattr(self._real, name)

        def execute(self, statement: str, *args: object) -> sqlite3.Cursor:
            """Advance the clock on the commit's BEGIN IMMEDIATE (the second), then forward it."""
            if statement == "BEGIN IMMEDIATE":
                begins.append(statement)
                if len(begins) == 2:
                    current[0] = NOW + timedelta(seconds=121)
            return self._real.execute(statement, *args)

    class SlowLockVerifier(OperatorAssertionVerifier):
        """Verifier whose connections simulate a slow write-lock acquisition."""

        def _connect(self) -> sqlite3.Connection:
            """Return the configured connection behind the lock-wait proxy."""
            return LockWaitConnection(super()._connect())  # type: ignore[return-value]

    registry = registry_bytes(entries=[entry("alice", ALICE_SEED)])
    verifier = SlowLockVerifier(
        state_path=tmp_path / "operator.db", trust_public_key=crypto_sign_seed_keypair(TRUST_SEED)[0],
        audience=AUDIENCE, registry_source=lambda: registry, clock=lambda: current[0],
    )
    refused("operator.expired", verifier.verify_and_consume, assertion(), operation="abandon",
            attempt_id="attempt-1", grant_id="grant-1")
    assert len(begins) == 2  # _observe_registry, then _commit
    with sqlite3.connect(verifier.path) as database:
        assert database.execute("SELECT COUNT(*) FROM consumed_nonces").fetchone()[0] == 0


def test_process_exit_during_cleanup_rolls_back_clock_and_nonce_deletion(env: Env) -> None:
    """A process dying before nonce insert cannot commit cleanup or advance its clock."""
    env.call(assertion())
    later = NOW + timedelta(seconds=500)
    raw = assertion(nonce="p" * 23, issued_at=wire.timestamp(later),
                    expires_at=wire.timestamp(later + timedelta(seconds=60)))
    script = '''
import os, sqlite3, sys
from datetime import datetime
from phylax.operator_assertion import OperatorAssertionVerifier

class CrashVerifier(OperatorAssertionVerifier):
    """Exit during nonce insertion with the consuming transaction still open."""

    def _connect(self) -> sqlite3.Connection:
        """Install the crash boundary on every configured database connection."""
        connection = super()._connect()

        def crash(statement: str) -> None:
            """Terminate before inserting a nonce, leaving cleanup uncommitted."""
            if statement.startswith('INSERT INTO consumed_nonces('):
                os._exit(73)
        connection.set_trace_callback(crash)
        return connection

verifier = CrashVerifier(state_path=sys.argv[1], trust_public_key=bytes.fromhex(sys.argv[2]),
    audience=sys.argv[3], registry_source=lambda: bytes.fromhex(sys.argv[4]),
    clock=lambda: datetime.fromisoformat(sys.argv[5]))
verifier.verify_and_consume(bytes.fromhex(sys.argv[6]), operation='abandon',
    attempt_id='attempt-1', grant_id='grant-1')
'''
    child = subprocess.run(
        [sys.executable, "-c", script, str(env.verifier.path),
         crypto_sign_seed_keypair(TRUST_SEED)[0].hex(), AUDIENCE,
         env.registry.hex(), later.isoformat(), raw.hex()],
        capture_output=True, text=True, timeout=20,
    )
    assert child.returncode == 73, child.stderr
    # Recovery sees the original consumption, not the uncommitted cleanup/clock.
    refused("operator.replayed", env.call, assertion())
    env.now = later
    assert env.call(raw)
