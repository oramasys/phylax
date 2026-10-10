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
    policy = PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
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


@pytest.mark.parametrize("evidence", ["derived", "reconstructed"])
def test_non_observed_evidence_cannot_satisfy_an_observed_requirement(evidence):
    policy, compiled, _ = setup(observed_required={"graph.execute"})
    decision = policy.admit(request(compiled, evidence_class=evidence))
    assert not decision.allowed
    assert decision.reason_code == "evidence_not_observed"
    assert policy.admit(request(compiled)).allowed


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
