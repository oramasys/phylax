# Phylax

Phylax is the compile-time and runtime security admission authority for
Oramasys. It decides whether an artifact is eligible to enter a runnable
graph and whether a specific capability may be admitted for a run.

Phylax does not own endpoint authorization, provider selection, hardware
placement, orchestration state, or network transport. Telos handles semantic
endpoint-use authorization; the endpoint and SSRF layers still enforce
transport safety; Agate supplies capability and placement evidence; Oramasys
coordinates lifecycle and routing.

## Initial vertical slice

The reference implementation provides:

- immutable artifact, compile-request, and runtime-admission contracts;
- fail-closed digest and provenance checks;
- explicit capability allowlists;
- a compile decision that yields a scoped admission reference;
- runtime admission that requires the matching compile decision and digest;
- a small in-memory decision store suitable for tests and local composition.

The digest and provenance inputs are evidence supplied by an integration. This
package does not pretend to verify signatures or build provenance by itself.
Production integrations must inject a verifier backed by the chosen artifact
and supply-chain system before treating a decision as release-grade.

## Example

```python
from phylax import ArtifactRef, CompileRequest, PhylaxAuthorizer

artifact = ArtifactRef(
    artifact_id="graph-bundle",
    digest_sha256="a" * 64,
    provenance_ref="slsa://build/graph-bundle",
)
authorizer = PhylaxAuthorizer(
    trusted_provenance={artifact.provenance_ref},
    allowed_capabilities={"graph.execute"},
)
decision = authorizer.compile(CompileRequest(artifact, frozenset({"graph.execute"})))
assert decision.allowed
```

## Boundary status

This repository is an early v2 successor scaffold. Perpetua-Tools and
orama-system remain the dual authorities during migration. No legacy policy or
security implementation is silently considered migrated by the presence of
this package.

