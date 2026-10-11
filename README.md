# Phylax

**License:** Apache-2.0.

Phylax is the compile-time and runtime **generic security/safety admission** authority for Oramasys. It decides whether an artifact may enter a runnable graph and whether a capability may be admitted for a run.

## Canonical boundary

Phylax owns generic security/safety concerns such as:

- artifact digest and provenance admission;
- compile-time capability admission;
- runtime capability admission;
- generic integrity, provenance, redaction, and safety policy packs;
- reusable runtime-check and monitorability mechanisms that are not owned by a more specific domain authority.
- strict, one-time P5 approval evidence for security-sensitive actions when a
  trusted interaction boundary supplies operator-decision evidence.

Phylax **does not** own endpoint-specific security. `oramasys/telos` is the sole v2 authority for endpoint identity, URL canonicalization, destination/IP classification, SSRF policy, DNS/rebinding defense, connection-time pinning, redirect/proxy/TLS destination safety, and purpose-scoped endpoint-use authorization.

Provider selection/readiness remains with provider owners and Oramasys composition; hardware capability/placement remains Agate; workflow/routing/idempotency/progress remains Oramasys.

## Initial vertical slice

The reference implementation provides immutable artifact/admission contracts, fail-closed digest/provenance checks, explicit capability allowlists, compile decisions with scoped admission references, runtime admission bound to compile evidence, and a `PhylaxPort` protocol for dependency-injected composition.

The digest and provenance inputs are evidence supplied by an integration. This package does not pretend to verify signatures or build provenance by itself; production integrations must inject the selected verifier before treating a decision as release-grade.

## Coverage contract

The project maintains at least **80% test coverage**. If a component defines a stricter threshold, the stricter threshold is binding and must never be lowered. The current scaffold test suite exceeds that floor.

## Migration posture

The v1 repositories remain independent legacy authorities. Phylax is a v2 clean-room successor surface and must not gain runtime dependencies on PT or other v1 implementations. Historical v1 material may be used as evidence and parity input only.

## P5 approval satellite

`P5ApprovalAuthority` is a v2-native, strict approval primitive. It mints a
server-side preview, binds a separately obtained `operator_evidence_ref` and a
P5-decided duration to one immutable swarm preview, then verifies and consumes
the receipt once. The preview includes the operator principal and every
dispatch-relevant swarm field, so a receipt cannot authorize another launch.

This is integrity and replay protection, not a claim that a client-side boolean
proves a human acted. Production composition must provide a trusted interaction
boundary and use the standard-library `SqliteP5ApprovalStore` or a compatible
durable `P5ApprovalStore`; the in-memory store is a test reference only. P5
does not issue or verify adjustment grants, and it has no legacy approval bypass.
