"""R4 T1: admission decisions carry identity, expiry and authority epoch;
derived evidence cannot satisfy an Observed requirement."""

from datetime import UTC, datetime, timedelta

import pytest

from phylax import ArtifactRef, CompileRequest, PhylaxAuthorizer, RuntimeAdmissionRequest


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 10, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def setup(**kwargs):
    clock = Clock()
    principal_verifier = kwargs.pop("principal_verifier", lambda actor: actor == "oramasys")
    policy = PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
        principal_verifier=principal_verifier,
        clock=clock,
        **kwargs,
    )
    compiled = policy.compile(
        CompileRequest(ArtifactRef("graph", "a" * 64, "slsa://build/graph"), frozenset({"graph.execute"}))
    )
    return policy, compiled, clock


def request(compiled, *, evidence_class="observed"):
    return RuntimeAdmissionRequest(
        compile_ref=compiled.compile_ref,
        artifact_id="graph",
        digest_sha256="a" * 64,
        capability="graph.execute",
        run_id="run-1",
        evidence_class=evidence_class,
    )


def test_decision_carries_id_expiry_and_epoch():
    policy, compiled, clock = setup(decision_ttl=timedelta(seconds=30))
    decision = policy.admit(request(compiled))
    assert decision.allowed
    assert decision.decision_id
    assert decision.decided_at == clock.now
    assert decision.expires_at == clock.now + timedelta(seconds=30)
    assert decision.authority_epoch == policy.authority_epoch == 1


def test_decision_is_current_until_expiry():
    policy, compiled, clock = setup(decision_ttl=timedelta(seconds=30))
    decision = policy.admit(request(compiled))
    assert policy.is_current(decision)
    clock.now += timedelta(seconds=29)
    assert policy.is_current(decision)
    clock.now += timedelta(seconds=1)
    assert not policy.is_current(decision)


def test_revocation_bumps_the_epoch_and_stales_old_decisions():
    policy, compiled, _ = setup()
    decision = policy.admit(request(compiled))
    assert policy.revoke() == 2
    assert not policy.is_current(decision)
    assert policy.is_current(policy.admit(request(compiled)))


def test_refused_decisions_are_never_current():
    policy, compiled, _ = setup()
    refused = policy.admit(
        RuntimeAdmissionRequest(compiled.compile_ref, "graph", "b" * 64, "graph.execute", "run-1")
    )
    assert not refused.allowed
    assert not policy.is_current(refused)


def test_nonobserved_source_cannot_admit():
    # Derived/reconstructed evidence must never satisfy an Observed requirement.
    policy, compiled, _ = setup(observed_required={"graph.execute"})
    for evidence in ("derived", "reconstructed"):
        decision = policy.admit(request(compiled, evidence_class=evidence))
        assert not decision.allowed
        assert decision.reason_code == "evidence_not_observed"
    assert policy.admit(request(compiled, evidence_class="observed")).allowed


def test_missing_hardware_or_principal_refused():
    # No principal-verification evidence available (unverified actor_id,
    # or no verifier configured at all) -> refuse, never default-allow.
    clock = Clock()
    # 1. No verifier configured at all -> fail closed
    no_verifier_policy = PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
        clock=clock,
    )
    compile_req = CompileRequest(
        ArtifactRef("graph", "a" * 64, "slsa://build/graph"),
        frozenset({"graph.execute"}),
        actor_id="actor-1",
    )
    decision = no_verifier_policy.compile(compile_req)
    assert not decision.allowed
    assert decision.reason_code == "unverified_principal"

    # 2. Verifier configured, but actor_id is unverified / unknown
    trusted = {"actor-1"}
    policy = PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
        principal_verifier=lambda actor_id: actor_id in trusted,
        clock=clock,
    )
    # Compile with unknown actor
    unknown_compile = policy.compile(
        CompileRequest(
            ArtifactRef("graph", "a" * 64, "slsa://build/graph"),
            frozenset({"graph.execute"}),
            actor_id="actor-unknown",
        )
    )
    assert not unknown_compile.allowed
    assert unknown_compile.reason_code == "unverified_principal"

    # Compile with trusted actor succeeds
    trusted_compile = policy.compile(compile_req)
    assert trusted_compile.allowed

    # Admit with unknown actor
    runtime_req_unknown = RuntimeAdmissionRequest(
        compile_ref=trusted_compile.compile_ref,
        artifact_id="graph",
        digest_sha256="a" * 64,
        capability="graph.execute",
        run_id="run-1",
        actor_id="actor-unknown",
        evidence_class="observed",
    )
    admit_decision = policy.admit(runtime_req_unknown)
    assert not admit_decision.allowed
    assert admit_decision.reason_code == "unverified_principal"

    # 3. Verifier throwing an exception also fails closed
    failing_verifier_policy = PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
        principal_verifier=lambda actor_id: (_ for _ in ()).throw(RuntimeError("verifier error")),
        clock=clock,
    )
    fail_compile = failing_verifier_policy.compile(compile_req)
    assert not fail_compile.allowed
    assert fail_compile.reason_code == "unverified_principal"
    fail_admit = failing_verifier_policy.admit(runtime_req_unknown)
    assert not fail_admit.allowed
    assert fail_admit.reason_code == "unverified_principal"


def test_duplicate_request_id_cannot_hide_violation():
    # Construct two admission requests with the same unique identifier (compile_ref, capability, run_id)
    # but different other fields, and confirm the second one is rejected or doesn't silently overwrite
    policy, compiled, _ = setup(principal_verifier=lambda actor_id: actor_id in {"oramasys", "actor-1"})
    req1 = RuntimeAdmissionRequest(
        compile_ref=compiled.compile_ref,
        artifact_id="graph",
        digest_sha256="a" * 64,
        capability="graph.execute",
        run_id="run-1",
        actor_id="actor-1",
        evidence_class="observed",
    )
    dec1 = policy.admit(req1)
    assert dec1.allowed

    # Second request with same identity but invalid/violating field or duplicate run
    # Duplicate run_id cannot overwrite or mask
    req2_tampered = RuntimeAdmissionRequest(
        compile_ref=compiled.compile_ref,
        artifact_id="graph",
        digest_sha256="b" * 64,  # bad digest
        capability="graph.execute",
        run_id="run-1",
        actor_id="actor-1",
        evidence_class="observed",
    )
    dec2 = policy.admit(req2_tampered)
    assert not dec2.allowed
    assert dec2.reason_code == "digest_mismatch"
    # Ensure the original allowed decision is still current and intact, not masked/corrupted
    assert policy.is_current(dec1)


def test_unknown_evidence_class_is_rejected():
    _, compiled, _ = setup()
    with pytest.raises(ValueError):
        request(compiled, evidence_class="vibes")


def test_ttl_and_clock_must_be_sane():
    with pytest.raises(ValueError):
        PhylaxAuthorizer(trusted_provenance=set(), allowed_capabilities=set(), decision_ttl=timedelta(0))
    naive = PhylaxAuthorizer(trusted_provenance=set(), allowed_capabilities=set(),
                             clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        naive.compile(CompileRequest(ArtifactRef("graph", "a" * 64, "x"), frozenset()))


# --- review fixes -------------------------------------------------------------


def test_omitted_evidence_class_never_counts_as_observed():
    policy, compiled, _ = setup(observed_required={"graph.execute"})
    unspecified = RuntimeAdmissionRequest(compiled.compile_ref, "graph", "a" * 64, "graph.execute", "run-1")
    assert unspecified.evidence_class is None
    decision = policy.admit(unspecified)
    assert not decision.allowed
    assert decision.reason_code == "evidence_not_observed"


def test_omitted_evidence_class_is_fine_when_observed_is_not_required():
    policy, compiled, _ = setup()
    assert policy.admit(
        RuntimeAdmissionRequest(compiled.compile_ref, "graph", "a" * 64, "graph.execute", "run-1")
    ).allowed


def test_decision_from_another_authorizer_is_not_current():
    first, compiled_a, _ = setup()
    second, _, _ = setup()
    decision = first.admit(request(compiled_a))
    assert first.is_current(decision)
    assert second.authority_epoch == decision.authority_epoch == 1
    assert not second.is_current(decision)


def test_tampered_decision_is_not_current():
    from dataclasses import replace

    policy, compiled, _ = setup()
    decision = policy.admit(request(compiled))
    assert not policy.is_current(replace(decision, capability="graph.admin"))
    assert not policy.is_current(replace(decision, decision_id="forged"))
