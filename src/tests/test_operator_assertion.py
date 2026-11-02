"""Operator-signed assertions: expiry, single-use nonces, revocation, rollback (real SQLite)."""
from __future__ import annotations

import json
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


def test_concurrent_replays_consume_exactly_once(env) -> None:
    """Racing threads presenting one assertion: exactly one succeeds."""
    raw = assertion()
    results: list[str] = []

    def attempt() -> None:
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
