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

Phylax **does not** own endpoint-specific security. `oramasys/telos` is the sole v2 authority for endpoint identity, URL canonicalization, destination/IP classification, SSRF policy, DNS/rebinding defense, connection-time pinning, redirect/proxy/TLS destination safety, and purpose-scoped endpoint-use authorization.

Provider selection/readiness remains with provider owners and Oramasys composition; hardware capability/placement remains Agate; workflow/routing/idempotency/progress remains Oramasys.

## Initial vertical slice

The reference implementation provides immutable artifact/admission contracts, fail-closed digest/provenance checks, explicit capability allowlists, compile decisions with scoped admission references, runtime admission bound to compile evidence, and a `PhylaxPort` protocol for dependency-injected composition.

The digest and provenance inputs are evidence supplied by an integration. This package does not pretend to verify signatures or build provenance by itself; production integrations must inject the selected verifier before treating a decision as release-grade.

## Coverage contract

The project maintains at least **80% test coverage**. If a component defines a stricter threshold, the stricter threshold is binding and must never be lowered. The current scaffold test suite exceeds that floor.

## Migration posture

The v1 repositories remain independent legacy authorities. Phylax is a v2 clean-room successor surface and must not gain runtime dependencies on PT or other v1 implementations. Historical v1 material may be used as evidence and parity input only.
