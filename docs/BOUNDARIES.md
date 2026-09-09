# Phylax Boundaries

Phylax is the generic compile-time/runtime security, safety, admission, redaction, and monitorability authority for Oramasys.

| Concern | Canonical owner |
| --- | --- |
| Artifact digest/provenance evidence and admission | Phylax |
| Generic runtime security/safety policy and monitorability enforcement | Phylax |
| URL parse/canonicalization and endpoint identity | Telos |
| IP/CIDR/metadata classification and SSRF | Telos |
| DNS resolution/rebinding and connection-time pinning | Telos |
| Redirect/proxy/TLS destination safety | Telos |
| Purpose-scoped endpoint-use authorization | Telos |
| Provider protocol/readiness/lifecycle | provider owner / Oramasys composition |
| Hardware capability and placement | Agate |
| Workflow state, idempotency, routing and progress | Oramasys |

Endpoint-specific runtime checks remain Telos policy/enforcement; Phylax must not become a second endpoint-security authority. Conversely, Telos must not absorb generic artifact/runtime admission or monitorability concerns merely because an endpoint participates in a workflow.

Phylax fails closed when provenance, digest, compile authorization, capability evidence, or required generic runtime security evidence is missing or mismatched.
