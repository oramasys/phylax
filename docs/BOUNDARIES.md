# Phylax Boundaries

Phylax is the compile-time and runtime security admission authority during
the v2 migration.

| Concern | Owner |
| --- | --- |
| Artifact digest/provenance evidence and admission decision | Phylax |
| Endpoint-use authorization | Telos |
| Arbitrary URL safety, DNS resolution, pinning, redirects | SSRF/transport layer |
| Provider selection and readiness | provider adapter / Oramasys |
| Hardware capability and placement | Agate |
| Workflow state, idempotency, and progress | Oramasys |
| Paid-call reservation and settlement | durable accounting authority |

Phylax must fail closed when provenance, digest, compile authorization, or
capability evidence is missing or mismatched. The scaffold validates evidence
shape and policy membership; it does not claim to verify signatures, SLSA
attestations, or build systems without an injected production verifier.

## Migration posture

Perpetua-Tools and orama-system remain the dual v1 authorities. This package
is a reference boundary and admission contract, not proof that the legacy
security implementation has been migrated. Every new consumer needs a tested
compatibility path and an explicit owner decision.

