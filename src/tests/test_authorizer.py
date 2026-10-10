from phylax import ArtifactRef, CompileRequest, PhylaxAuthorizer, RuntimeAdmissionRequest


def artifact() -> ArtifactRef:
    """Test helper: artifact."""
    return ArtifactRef("graph", "a" * 64, "slsa://build/graph")


def authorizer(principal_verifier=None) -> PhylaxAuthorizer:
    """Test helper: authorizer."""
    return PhylaxAuthorizer(
        trusted_provenance={"slsa://build/graph"},
        allowed_capabilities={"graph.execute"},
        principal_verifier=principal_verifier or (lambda actor: actor == "oramasys"),
    )


def test_compile_allows_trusted_artifact_and_capabilities() -> None:
    """Compile allows trusted artifact and capabilities."""
    decision = authorizer().compile(CompileRequest(artifact(), frozenset({"graph.execute"})))

    assert decision.allowed
    assert decision.reason_code == "allowed"
    assert decision.approved_capabilities == frozenset({"graph.execute"})


def test_compile_denies_untrusted_provenance() -> None:
    """Compile denies untrusted provenance."""
    untrusted = ArtifactRef("graph", "a" * 64, "unknown://build/graph")

    decision = authorizer().compile(CompileRequest(untrusted, frozenset({"graph.execute"})))

    assert not decision.allowed
    assert decision.reason_code == "untrusted_provenance"


def test_runtime_admission_requires_matching_digest_and_compile_ref() -> None:
    """Runtime admission requires matching digest and compile ref."""
    policy = authorizer()
    compiled = policy.compile(CompileRequest(artifact(), frozenset({"graph.execute"})))

    decision = policy.admit(
        RuntimeAdmissionRequest(
            compile_ref=compiled.compile_ref,
            artifact_id="graph",
            digest_sha256="b" * 64,
            capability="graph.execute",
            run_id="run-1",
        )
    )

    assert not decision.allowed
    assert decision.reason_code == "digest_mismatch"


def test_runtime_admission_allows_only_compiled_capability() -> None:
    """Runtime admission allows only compiled capability."""
    policy = authorizer()
    compiled = policy.compile(CompileRequest(artifact(), frozenset({"graph.execute"})))

    decision = policy.admit(
        RuntimeAdmissionRequest(
            compile_ref=compiled.compile_ref,
            artifact_id="graph",
            digest_sha256="a" * 64,
            capability="graph.execute",
            run_id="run-1",
        )
    )

    assert decision.allowed
    assert decision.reason_code == "allowed"

