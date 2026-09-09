# Phylax

Phylax is the compile-time and runtime **generic security/safety admission and monitorability authority** for Oramasys. It decides whether an artifact is eligible to enter a runnable graph and whether a capability may be admitted for a run.

Phylax does **not** own endpoint-specific security. URL parsing/canonicalization, IP/CIDR and metadata classification, SSRF, DNS resolution/rebinding defense, connection-time pinning, redirect/proxy/TLS destination safety, and endpoint-use authorization belong exclusively to **Telos**, the restored Tripwire successor.

Phylax owns generic concerns such as artifact provenance/integrity, runtime admission, redaction/security policy packs, and monitorability enforcement that are not endpoint-specific. Agate supplies hardware capability/placement evidence; provider owners handle provider protocol/lifecycle; Oramasys coordinates lifecycle/routing.

## Initial vertical slice

The reference implementation provides:

- immutable artifact, compile-request, and runtime-admission contracts;
- fail-closed digest and provenance checks;
- explicit capability allowlists;
- a compile decision that yields a scoped admission reference;
- runtime admission that requires the matching compile decision and digest;
- a small in-memory decision store suitable for tests and local composition;
- a `PhylaxPort` protocol for dependency-injected Oramasys lifecycle adapters.

The digest and provenance inputs are evidence supplied by an integration. Production integrations must inject appropriate verification before treating a decision as release-grade.

Phylax uses the Apache License 2.0. The original MIT scaffold was an implementation error and does not define the intended project license.
