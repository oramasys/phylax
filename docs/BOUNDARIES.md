# Phylax Boundaries

Phylax is the compile-time and runtime **generic security/safety admission** authority during the v2 migration.

| Concern | Canonical owner |
| --- | --- |
| Artifact digest/provenance evidence and admission | Phylax |
| Generic runtime security/safety admission and policy packs | Phylax |
| Generic monitorability/runtime-check substrate | Phylax |
| Strict P5 approval evidence for security-sensitive actions | Phylax |
| Generic execution primitives and event contracts | Core (`oramasys/perpetua-core`) |
| Endpoint identity and canonicalization | Telos |
| SSRF, DNS resolution/rebinding defense, address classification | Telos |
| Connection-time IP/socket pinning | Telos |
| Redirect/proxy/TLS destination safety | Telos |
| Purpose-scoped endpoint-use authorization | Telos |
| Provider protocol/readiness/lifecycle | provider owner / Oramasys composition |
| Hardware capability and placement | Agate |
| Workflow state, routing, idempotency and progress | Oramasys |

Phylax must fail closed when provenance, digest, compile authorization, or capability evidence is missing or mismatched. Its generic runtime-check mechanism must not absorb domain semantics merely because those checks are security-relevant.

P5 binds a trusted interaction boundary's operator evidence to an immutable
swarm-launch preview and consumes that evidence once. It does not create
adjustment grants, decide ledger admission, or replace an adjustment grant's
independent Ed25519ph signature. A future consumer must provide durable P5
storage and may not add a legacy boolean-approval bypass.

## Explicit endpoint exclusion

The following are **not Phylax responsibilities** and must not be reimplemented here:

- URL parsing or endpoint canonicalization;
- IP/CIDR/special-use or cloud-metadata classification;
- SSRF egress policy;
- DNS resolution or DNS-rebinding/TOCTOU defense;
- connection-time pinning or dedicated dialer/socket behavior;
- redirect revalidation;
- proxy isolation;
- TLS destination identity, Host, or SNI policy;
- endpoint-purpose authorization.

Those concerns belong exclusively to `oramasys/telos`, the restored Tripwire successor.

## Coverage and migration posture

Maintain at least **80% project test coverage**; any stricter component threshold takes precedence and must never be lowered. v1 repositories remain independent legacy authorities. Phylax is a clean-room v2 surface and may use v1 evidence for parity, never as a runtime dependency.
