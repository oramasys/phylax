"""D1 verifier-only surface: freshness, denial vocabulary, capability gate, evidence."""

from __future__ import annotations

import ast
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import phylax
from phylax import grant_composition, grant_store
from phylax.adjustment_grant import (
    GrantRefusalReason,
    PhylaxGrantAuthority,
    RevocationObservation,
    RotatingIssuerKeyring,
)
from phylax.capability_record import (
    CAPABILITY_BITS,
    CAPABILITY_RECORD_SCHEMA,
    parse_capability_record,
)
from phylax.effect_grant import (
    EffectGrantAuthority,
    EffectGrantRefusalReason,
    EffectGrantRequest,
)
from phylax.grant_composition import CompositionError, GrantVerifierConfig
from phylax.grant_store import SqliteGrantAuthorityStore
from phylax.p5_approval import InMemoryP5ApprovalStore, P5ApprovalAuthority
from phylax.verifier_surface import (
    REVOCATION_MAX_AGE_SECONDS,
    PublicDenial,
    VerifierDenied,
    VerifierSurface,
    check_revocation_fresh,
    open_verifier_surface,
    public_denial_for,
)
from test_adjustment_grant import request as v1_request

posix_only = pytest.mark.skipif(
    not (hasattr(os, "geteuid") and hasattr(os, "O_DIRECTORY") and Path("/dev/fd").is_dir()),
    reason="SQLite verification store needs POSIX (geteuid, O_DIRECTORY, /dev/fd)",
)

T0 = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


class Clock:
    """Mutable UTC clock."""

    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


class Seeds:
    def load_seed(self, seed_ref: str) -> bytes:
        return b"e" * 32


def record(**caps: bool) -> dict:
    """Return a schema-valid capability record with the given bit overrides."""
    bits = {name: False for name in CAPABILITY_BITS}
    bits.update(caps)
    return {
        "schema": CAPABILITY_RECORD_SCHEMA, "record_id": "r-1", "issued_at": "2026-10-25T12:00:00Z",
        "issuer": "control-plane", "capabilities": bits,
        "binds": {"binary_digest": DIGEST, "config_digest": DIGEST}, "signature": None,
    }


class Env:
    """One authority store with a v1 and a v2 grant, and a verifier surface over it."""

    def __init__(self, directory: Path) -> None:
        self.clock = Clock()
        self.store = SqliteGrantAuthorityStore(directory / "grants.sqlite3")
        keyring = RotatingIssuerKeyring(
            key_id="issuer-1", seed_ref="seed-1", seed_provider=Seeds(), store=self.store
        )
        p5 = P5ApprovalAuthority(
            signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=self.clock
        )
        self.v1_authority = PhylaxGrantAuthority(keyring=keyring, p5_approval=p5, clock=self.clock)
        p5b = P5ApprovalAuthority(
            signing_key=b"p5-test-secret", store=InMemoryP5ApprovalStore(), clock=self.clock
        )
        self.v2_authority = EffectGrantAuthority(keyring=keyring, p5_approval=p5b, clock=self.clock)
        self.v1 = self.v1_authority.issue(
            v1_request(), authenticated_principal="operator-1", operator_evidence_ref="trusted-ui://1"
        )
        self.v2 = self.v2_authority.issue(
            EffectGrantRequest(
                principal="principal-1", run_id="run-1", operation_id="operation-1",
                request_digest="a" * 64, effect_class="inert.simulation",
                ledger_store_id="ledger-1", consumer_lease_epoch=3,
                second_approval_ref="approval-1", issuer_ref="phylax-1",
                revocation_ref="phylax://revocations/v1",
            ),
            authenticated_principal="principal-1", operator_evidence_ref="trusted-ui://2",
        )

    def surface(self, **kw: object) -> VerifierSurface:
        kw.setdefault("caller_check", lambda caller: caller == "consumer")
        return VerifierSurface(store=self.store, clock=self.clock, **kw)  # type: ignore[arg-type]


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def effects_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-only: pretend a verified record enabled effects (no signing path exists)."""
    from phylax import capability_record as cr

    monkeypatch.setattr(
        VerifierSurface, "capabilities",
        lambda self, rec: cr.EffectiveCapabilities(effects=True, valid=True, reason=cr.REASON_OK),
    )


def denial(call) -> PublicDenial:  # type: ignore[no-untyped-def]
    with pytest.raises(VerifierDenied) as info:
        call()
    return info.value.code


# --- capability record reader ---------------------------------------------------------


def test_valid_all_false_record_is_valid_and_denies_everything() -> None:
    caps = parse_capability_record(json.dumps(record()))
    assert caps.valid and caps.reason == "capability.ok"
    assert caps.as_dict() == {name: False for name in CAPABILITY_BITS}


@pytest.mark.parametrize("bit", CAPABILITY_BITS)
def test_any_true_bit_is_refused_unsigned_and_nothing_is_inferred(bit: str) -> None:
    caps = parse_capability_record(record(**{bit: True}))
    assert not caps.valid and caps.reason == "capability.unsigned_enablement"
    assert not any(caps.as_dict().values())
    signed = record(**{bit: True}) | {"signature": "sig"}
    assert parse_capability_record(signed).reason == "capability.unsigned_enablement"


def test_serving_true_never_implies_effects() -> None:
    caps = parse_capability_record(record(serving=True))
    assert caps.serving is False and caps.effects is False


def _without(bit: str) -> dict:
    data = record()
    data["capabilities"].pop(bit)
    return data


def _with_caps(**changes: object) -> dict:
    data = record()
    data["capabilities"].update(changes)
    return data


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (None, "capability.record_missing"),
        (b"\xff\xfe", "capability.record_unreadable"),
        ("{not json", "capability.record_unreadable"),
        ("[]", "capability.record_unreadable"),
        (42, "capability.record_unreadable"),
        (b"{" + b" " * 9000 + b"}", "capability.record_unreadable"),
        ('{"schema": "x", "schema": "x"}', "capability.record_unreadable"),
        (record() | {"schema": "orama-capability-record/v2"}, "capability.schema_unsupported"),
        (record() | {"extra": 1}, "capability.record_invalid"),
        (record() | {"record_id": ""}, "capability.record_invalid"),
        (record() | {"issued_at": "2026-10-25T12:00:00+01:00"}, "capability.record_invalid"),
        (record() | {"issued_at": "not-a-timeZ"}, "capability.record_invalid"),
        (record() | {"signature": 7}, "capability.record_invalid"),
        (record() | {"binds": {"binary_digest": DIGEST}}, "capability.record_invalid"),
        (record() | {"binds": {"binary_digest": "sha256:zz", "config_digest": DIGEST}},
         "capability.record_invalid"),
        (_without("effects"), "capability.bit_invalid"),
        (record() | {"capabilities": "no"}, "capability.bit_invalid"),
        (_with_caps(bonus=False), "capability.bit_invalid"),
        (_with_caps(effects=0), "capability.bit_invalid"),
        (_with_caps(effects="false"), "capability.bit_invalid"),
    ],
)
def test_invalid_records_deny_every_bit_with_a_reason(raw: object, reason: str) -> None:
    caps = parse_capability_record(raw)  # type: ignore[arg-type]
    assert caps.reason == reason and not caps.valid
    assert not any(caps.as_dict().values())


def test_digest_mismatch_denies() -> None:
    other = "sha256:" + "b" * 64
    assert parse_capability_record(record(), expected_binary_digest=DIGEST).valid
    assert parse_capability_record(record(), expected_binary_digest=other).reason == (
        "capability.digest_mismatch"
    )
    assert parse_capability_record(record(), expected_config_digest=other).reason == (
        "capability.digest_mismatch"
    )


def test_a_hostile_mapping_never_raises() -> None:
    from collections.abc import Mapping

    class Boom(Mapping):
        def __getitem__(self, key: object) -> object:
            raise RuntimeError("boom")

        def __iter__(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

        def __len__(self) -> int:
            return 1

    assert parse_capability_record(Boom()).reason == "capability.record_unreadable"


# --- public vocabulary -----------------------------------------------------------------


def test_the_public_vocabulary_is_exactly_the_seven_contract_codes() -> None:
    assert {c.value for c in PublicDenial} == {
        "deny.revocation_stale", "deny.unknown_key", "deny.malformed_grant",
        "deny.revoked_grant", "deny.missing_capability_record",
        "deny.unauthorized_caller", "deny.verifier_unavailable",
    }


def test_every_internal_reason_of_both_enums_maps_to_a_public_code() -> None:
    expected = {
        "revocation.stale": "deny.revocation_stale", "grant.key_unknown": "deny.unknown_key",
        "grant.malformed": "deny.malformed_grant", "grant.schema_unsupported": "deny.malformed_grant",
        "grant.signature_invalid": "deny.malformed_grant", "grant.expired": "deny.malformed_grant",
        "grant.future_dated": "deny.malformed_grant", "grant.revoked": "deny.revoked_grant",
        "verifier.unavailable": "deny.verifier_unavailable",
    }
    for reason in (*GrantRefusalReason, *EffectGrantRefusalReason):
        assert public_denial_for(reason).value == expected[reason.value]
    assert public_denial_for("something.new") is PublicDenial.VERIFIER_UNAVAILABLE


def test_denial_body_is_code_and_correlation_id_only() -> None:
    denied = VerifierDenied(PublicDenial.REVOKED_GRANT)
    assert set(denied.body()) == {"error"}
    assert set(denied.body()["error"]) == {"code", "correlation_id"}
    with pytest.raises(ValueError):
        VerifierDenied("deny.anything")  # type: ignore[arg-type]


# --- revocation freshness ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "fresh"),
    [(0, True), (60, True), (61, False), (3600, False), (-5, True), (-6, False)],
)
def test_freshness_boundaries(age: int, fresh: bool) -> None:
    obs = RevocationObservation("g", False, T0 - timedelta(seconds=age))
    if fresh:
        check_revocation_fresh(obs, T0)
    else:
        with pytest.raises(Exception) as info:
            check_revocation_fresh(obs, T0)
        assert info.value.reason is GrantRefusalReason.REVOCATION_STALE  # type: ignore[attr-defined]
    assert REVOCATION_MAX_AGE_SECONDS == 60


def test_naive_observation_time_is_stale() -> None:
    with pytest.raises(Exception):
        check_revocation_fresh(RevocationObservation("g", False, datetime(2026, 10, 25, 12)), T0)


def test_stale_observation_denies_on_the_v1_path(env: Env) -> None:
    surface = env.surface()
    stale = RevocationObservation(env.v1.grant_id, False, T0 - timedelta(seconds=61))
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="consumer", observation=stale)) is PublicDenial.REVOCATION_STALE
    fresh = RevocationObservation(env.v1.grant_id, False, T0)
    assert surface.verify_adjustment(env.v1.to_wire(), caller="consumer", observation=fresh)


def test_stale_and_future_observation_deny_on_the_v2_path(env: Env, monkeypatch) -> None:
    effects_enabled(monkeypatch)
    surface = env.surface()
    for delta in (-61, 10):
        obs = RevocationObservation(env.v2.grant_id, False, T0 + timedelta(seconds=delta))
        assert denial(lambda: surface.verify_effect(
            env.v2.to_wire(), caller="consumer", capability_record=None, observation=obs)
        ) is PublicDenial.REVOCATION_STALE
    ok = RevocationObservation(env.v2.grant_id, False, T0)
    assert surface.verify_effect(
        env.v2.to_wire(), caller="consumer", capability_record=None, observation=ok)


def test_observation_for_another_grant_is_stale_and_revoked_observation_denies(env: Env) -> None:
    surface = env.surface()
    other = RevocationObservation("someone-else", False, T0)
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="consumer", observation=other)) is PublicDenial.REVOCATION_STALE
    revoked = RevocationObservation(env.v1.grant_id, True, T0)
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="consumer", observation=revoked)) is PublicDenial.REVOKED_GRANT


def test_revocation_freshness_reads_now_and_reports_revocation(env: Env) -> None:
    surface = env.surface()
    seen = surface.revocation_freshness(env.v2.grant_id, caller="consumer")
    assert seen.revoked is False and seen.observed_at == T0
    env.v2_authority.revoke(env.v2.grant_id)
    assert surface.revocation_freshness(env.v2.grant_id, caller="consumer").revoked is True
    stale = RevocationObservation(env.v2.grant_id, False, T0 - timedelta(seconds=90))
    assert denial(lambda: surface.revocation_freshness(
        env.v2.grant_id, caller="consumer", observation=stale)) is PublicDenial.REVOCATION_STALE
    assert denial(lambda: surface.revocation_freshness(
        "  ", caller="consumer")) is PublicDenial.MALFORMED_GRANT


def test_a_read_that_stalls_past_the_max_age_is_stale(env: Env) -> None:
    class Slow:
        def is_revoked(self, grant_id: str) -> bool:
            env.clock.now += timedelta(seconds=61)
            return False

    surface = VerifierSurface(store=Slow(), clock=env.clock, caller_check=lambda c: True)  # type: ignore[arg-type]
    assert denial(lambda: surface.revocation_freshness("g", caller="x")) is (
        PublicDenial.REVOCATION_STALE
    )


def test_unavailable_store_or_clock_is_unavailable(env: Env) -> None:
    class Broken:
        def is_revoked(self, grant_id: str) -> bool:
            raise OSError("path /secret/state")

    surface = VerifierSurface(store=Broken(), clock=env.clock, caller_check=lambda c: True)  # type: ignore[arg-type]
    with pytest.raises(VerifierDenied) as info:
        surface.revocation_freshness("g", caller="x")
    assert info.value.code is PublicDenial.VERIFIER_UNAVAILABLE
    assert "secret" not in repr(info.value.body()) and info.value.__cause__ is None
    naive = VerifierSurface(store=env.store, clock=lambda: datetime(2026, 1, 1),  # type: ignore[arg-type]
                            caller_check=lambda c: True)
    assert denial(lambda: naive.revocation_freshness("g", caller="x")) is (
        PublicDenial.VERIFIER_UNAVAILABLE
    )


# --- verification parity (v1 and v2 share behaviour) --------------------------------------


def test_both_versions_verify_then_deny_revoked(env: Env, monkeypatch) -> None:
    effects_enabled(monkeypatch)
    surface = env.surface()
    assert surface.verify_adjustment(env.v1.to_wire(), caller="consumer").grant_id == env.v1.grant_id
    assert surface.verify_effect(
        env.v2.to_wire(), caller="consumer", capability_record=None).grant_id == env.v2.grant_id
    env.v1_authority.revoke(env.v1.grant_id)
    env.v2_authority.revoke(env.v2.grant_id)
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="consumer")) is PublicDenial.REVOKED_GRANT
    assert denial(lambda: surface.verify_effect(
        env.v2.to_wire(), caller="consumer", capability_record=None)) is PublicDenial.REVOKED_GRANT


def test_expired_garbage_and_cross_version_wire_are_malformed(env: Env, monkeypatch) -> None:
    effects_enabled(monkeypatch)
    surface = env.surface()
    assert denial(lambda: surface.verify_adjustment(
        b"garbage", caller="consumer")) is PublicDenial.MALFORMED_GRANT
    assert denial(lambda: surface.verify_effect(
        env.v1.to_wire(), caller="consumer", capability_record=None)) is PublicDenial.MALFORMED_GRANT
    assert denial(lambda: surface.verify_adjustment(
        env.v2.to_wire(), caller="consumer")) is PublicDenial.MALFORMED_GRANT
    env.clock.now = T0 + timedelta(days=2)
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="consumer")) is PublicDenial.MALFORMED_GRANT


def test_unknown_issuer_key_is_unknown_key(env: Env, monkeypatch) -> None:
    effects_enabled(monkeypatch)

    class NoKeys:
        def key(self, key_id: str) -> None:
            return None

        def is_issued(self, *a: object) -> bool:
            return True

        def is_revoked(self, *a: object) -> bool:
            return False

    surface = VerifierSurface(store=NoKeys(), clock=env.clock, caller_check=lambda c: True)  # type: ignore[arg-type]
    assert denial(lambda: surface.verify_adjustment(
        env.v1.to_wire(), caller="c")) is PublicDenial.UNKNOWN_KEY
    assert denial(lambda: surface.verify_effect(
        env.v2.to_wire(), caller="c", capability_record=None)) is PublicDenial.UNKNOWN_KEY


def test_store_failure_is_unavailable_and_redacted(env: Env) -> None:
    class Failing:
        def key(self, key_id: str):  # type: ignore[no-untyped-def]
            raise OSError("/home/operator/state/grants.sqlite3")

    surface = VerifierSurface(store=Failing(), clock=env.clock, caller_check=lambda c: True)  # type: ignore[arg-type]
    with pytest.raises(VerifierDenied) as info:
        surface.verify_adjustment(env.v1.to_wire(), caller="c")
    assert info.value.code is PublicDenial.VERIFIER_UNAVAILABLE
    assert "operator" not in str(info.value) and "operator" not in repr(info.value.body())
    assert info.value.__cause__ is None


# --- caller and capability gates (red team) -----------------------------------------------


class Spy:
    """A store wrapper that counts every attribute access."""

    def __init__(self, inner: object) -> None:
        self.inner, self.accessed = inner, 0

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        self.accessed += 1
        return getattr(self.inner, name)


def _raises(_: object) -> bool:
    raise RuntimeError("boom")


@pytest.mark.parametrize("checker", [
    lambda c: False, lambda c: "yes", lambda c: 1, lambda c: None, _raises,
])
def test_unauthorized_or_broken_caller_check_denies_before_any_store_access(
    env: Env, checker, monkeypatch
) -> None:
    effects_enabled(monkeypatch)
    spy = Spy(env.store)
    surface = VerifierSurface(store=spy, clock=env.clock, caller_check=checker)  # type: ignore[arg-type]
    wire = env.v1.to_wire()
    assert denial(lambda: surface.verify_adjustment(wire, caller="x")) is PublicDenial.UNAUTHORIZED_CALLER
    assert denial(lambda: surface.verify_effect(
        env.v2.to_wire(), caller="x", capability_record=None)) is PublicDenial.UNAUTHORIZED_CALLER
    assert denial(lambda: surface.revocation_freshness("g", caller="x")) is (
        PublicDenial.UNAUTHORIZED_CALLER)
    assert spy.accessed == 0


def test_a_caller_check_is_mandatory(env: Env) -> None:
    with pytest.raises(ValueError):
        VerifierSurface(store=env.store, caller_check=None)  # type: ignore[arg-type]


@pytest.mark.parametrize("supplied", [
    None, "", "{", record(), record(effects=True), record(serving=True),
    record() | {"schema": "other"}, b"\x00",
])
def test_effects_scope_without_a_valid_enabling_record_is_denied_before_parse(
    env: Env, supplied: object
) -> None:
    spy = Spy(env.store)
    surface = VerifierSurface(store=spy, clock=env.clock, caller_check=lambda c: True)  # type: ignore[arg-type]
    assert denial(lambda: surface.verify_effect(
        env.v2.to_wire(), caller="c", capability_record=supplied)
    ) is PublicDenial.MISSING_CAPABILITY_RECORD
    assert spy.accessed == 0


def test_digest_bound_surface_rejects_a_mismatching_record(env: Env) -> None:
    surface = env.surface(expected_binary_digest="sha256:" + "c" * 64)
    assert surface.capabilities(record()).reason == "capability.digest_mismatch"


def test_adjustment_verification_does_not_need_a_capability_record(env: Env) -> None:
    assert env.surface().verify_adjustment(env.v1.to_wire(), caller="consumer")


# --- evidence ---------------------------------------------------------------------------


def test_evidence_counts_codes_over_a_window_with_no_identifiers(env: Env) -> None:
    got: list[dict] = []
    surface = env.surface(evidence_sink=got.append)
    surface.verify_adjustment(env.v1.to_wire(), caller="consumer")
    denial(lambda: surface.verify_adjustment(b"junk", caller="consumer"))
    denial(lambda: surface.verify_adjustment(env.v1.to_wire(), caller="nobody"))
    now = datetime.now(UTC)
    outcome = surface.export_evidence(now - timedelta(minutes=1), now + timedelta(minutes=1))
    assert outcome.ok and len(got) == 1
    summary = got[0]
    assert summary["counts"] == {
        "adjustment:deny.malformed_grant": 1,
        "adjustment:deny.unauthorized_caller": 1,
        "adjustment:ok": 1,
    }
    assert summary["total"] == 3
    text = json.dumps(summary)
    assert env.v1.grant_id not in text and "issuer-1" not in text and "grants.sqlite3" not in text
    empty = surface.export_evidence(now + timedelta(days=1), now + timedelta(days=2))
    assert empty.ok and got[1]["total"] == 0


def test_evidence_ignores_unknown_scopes() -> None:
    from phylax.verifier_evidence import EvidenceLog

    log = EvidenceLog()
    log.record(T0, "grant-123", "x")
    assert log.summary(T0 - timedelta(1), T0 + timedelta(1))["total"] == 0


@pytest.mark.parametrize("exc", [RuntimeError("boom with /secret/path"), OSError("disk"), KeyError("k")])
def test_a_failing_exporter_is_reported_and_changes_nothing(env: Env, monkeypatch, exc) -> None:
    effects_enabled(monkeypatch)

    def bad_sink(summary: object) -> None:
        raise exc

    good, bad = env.surface(), env.surface(evidence_sink=bad_sink)
    caps_before = bad.capabilities(record())

    def snapshot() -> tuple:
        return (
            bad.verify_adjustment(env.v1.to_wire(), caller="consumer"),
            bad.verify_effect(env.v2.to_wire(), caller="consumer", capability_record=None),
            bad.revocation_freshness(env.v1.grant_id, caller="consumer"),
            denial(lambda: bad.verify_adjustment(b"junk", caller="consumer")),
        )

    before = snapshot()
    now = datetime.now(UTC)
    outcome = bad.export_evidence(now - timedelta(1), now + timedelta(1))
    assert outcome.ok is False and outcome.error == type(exc).__name__
    assert "secret" not in repr(outcome) and bad.export_failures == 1
    assert snapshot() == before
    assert bad.capabilities(record()) == caps_before
    assert not any(parse_capability_record(record(effects=True)).as_dict().values())
    assert good.verify_adjustment(env.v1.to_wire(), caller="consumer") == before[0]


def test_a_sink_mutating_its_summary_cannot_reach_the_log(env: Env) -> None:
    def vandal(summary: dict) -> None:
        summary["counts"].clear()
        summary["total"] = 99

    surface = env.surface(evidence_sink=vandal)
    surface.verify_adjustment(env.v1.to_wire(), caller="consumer")
    now = datetime.now(UTC)
    window = (now - timedelta(1), now + timedelta(1))
    assert surface.export_evidence(*window).ok
    assert surface._evidence.summary(*window)["total"] == 1


def test_recording_failure_never_changes_a_result(env: Env, monkeypatch) -> None:
    surface = env.surface()

    def boom(*a: object) -> None:
        raise RuntimeError

    monkeypatch.setattr(surface._evidence, "record", boom)
    assert surface.verify_adjustment(env.v1.to_wire(), caller="consumer").grant_id == env.v1.grant_id
    assert denial(lambda: surface.verify_adjustment(b"x", caller="consumer")) is (
        PublicDenial.MALFORMED_GRANT)


def test_no_sink_is_a_successful_export(env: Env) -> None:
    now = datetime.now(UTC)
    assert env.surface().export_evidence(now, now).ok


# --- the surface is verifier-only ---------------------------------------------------------


FORBIDDEN = {
    "SqliteGrantAuthorityStore", "FileSeedProvider", "open_grant_authority", "RotatingIssuerKeyring",
    "PhylaxGrantAuthority", "EffectGrantAuthority", "P5ApprovalAuthority", "SqliteP5ApprovalStore",
    "GrantAuthorityConfig", "load_seed",
}


@pytest.mark.parametrize("module", ["verifier_surface", "capability_record", "verifier_evidence"])
def test_new_modules_never_name_the_authority_store_seed_provider_or_issuers(module: str) -> None:
    source = (Path(phylax.__file__).parent / f"{module}.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert not (names & FORBIDDEN)


def test_the_public_surface_exposes_only_verify_freshness_close_and_evidence(env: Env) -> None:
    public = {n for n in dir(env.surface()) if not n.startswith("_")}
    assert public == {
        "verify_adjustment", "verify_effect", "revocation_freshness", "close",
        "capabilities", "export_evidence", "export_failures",
    }


def _forbid_authority(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    hits: list[str] = []

    def trap(name: str):  # type: ignore[no-untyped-def]
        def inner(*a: object, **k: object) -> None:
            hits.append(name)
            raise AssertionError(name)
        return inner

    monkeypatch.setattr(grant_store.SqliteGrantAuthorityStore, "__init__", trap("authority_store"))
    monkeypatch.setattr(grant_composition.FileSeedProvider, "__init__", trap("seed_provider"))
    monkeypatch.setattr(grant_composition.FileSeedProvider, "load_seed", trap("load_seed"))
    monkeypatch.setattr(grant_composition, "open_grant_authority", trap("open_authority"))
    return hits


def test_using_the_surface_never_constructs_the_authority_store_or_reads_seeds(
    env: Env, monkeypatch
) -> None:
    effects_enabled(monkeypatch)
    wire1, wire2 = env.v1.to_wire(), env.v2.to_wire()
    hits = _forbid_authority(monkeypatch)
    surface = env.surface()
    surface.verify_adjustment(wire1, caller="consumer")
    surface.verify_effect(wire2, caller="consumer", capability_record=None)
    surface.revocation_freshness(env.v1.grant_id, caller="consumer")
    surface.export_evidence(T0, T0)
    surface.close()
    assert hits == []


def test_opening_a_missing_state_dir_creates_nothing_and_touches_no_authority(
    tmp_path: Path, monkeypatch
) -> None:
    hits = _forbid_authority(monkeypatch)
    state = tmp_path / "state"
    with pytest.raises(CompositionError):
        open_verifier_surface(GrantVerifierConfig(state), caller_check=lambda c: True)
    assert not state.exists() and list(tmp_path.iterdir()) == [] and hits == []


@posix_only
def test_real_read_only_open_serves_both_versions_and_mutates_nothing(
    tmp_path: Path, monkeypatch
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    env = Env(state)
    effects_enabled(monkeypatch)
    wire1, wire2 = env.v1.to_wire(), env.v2.to_wire()
    for path in state.iterdir():
        path.chmod(0o600)
    database = state / "grants.sqlite3"
    before = database.read_bytes()
    names = sorted(p.name for p in state.iterdir() if not p.name.endswith(("-wal", "-shm")))
    hits = _forbid_authority(monkeypatch)
    surface = open_verifier_surface(
        GrantVerifierConfig(state), caller_check=lambda c: c == "consumer", clock=env.clock
    )
    try:
        assert surface.verify_adjustment(wire1, caller="consumer")
        assert surface.verify_effect(wire2, caller="consumer", capability_record=None)
        assert surface.revocation_freshness(env.v1.grant_id, caller="consumer").revoked is False
    finally:
        surface.close()
    assert hits == []
    assert database.read_bytes() == before
    assert sorted(p.name for p in state.iterdir() if not p.name.endswith(("-wal", "-shm"))) == names
