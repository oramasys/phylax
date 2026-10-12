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

Policy bounds and retention:

- The issuance ceiling is a hard 9,900 seconds. Callers may configure a lower
  ceiling, never a higher one. A longer-lived decision is only possible through
  a fresh P5 HITL approval; the authority never extends or re-signs in place.
- Expiry is evaluated under the store lock (`approve` and `consume`), so a
  request that waited on the lock past expiry is refused.
- Previews are retained after expiry only as a diagnostic window. Callers
  schedule `P5ApprovalAuthority.purge_expired()`, which drops records that
  expired more than 30 days ago by default; an expired record can never
  authorize, so purging does not weaken replay protection.

## Adjustment-grant issuer

`PhylaxGrantAuthority` owns the issuer side of a one-time adjustment grant:
it authenticates the requesting principal, binds a grant-specific P5 action to
the exact target tuple, accepts only the duration P5 approves, and signs the
canonical wire body with RFC 8032 Ed25519ph. Its `verifier_adapter()` exposes
only `verify(wire)` and `revocation(grant_id)` for dependency-injected
composition; the result omits issuer key IDs, public keys, P5 receipts, and
operator-evidence references.

The issuer has no budget, ledger, or consumption authority. Oramasys must
verify the attestation and atomically consume it against its own ledger. The
P5 receipt remains local issuance evidence; its raw HMAC token never becomes
the Ed25519ph grant signature or crosses that boundary. `SqliteGrantAuthorityStore`
durably records the public key registry, exact issued wire forms, revocations,
key-retention references, and digest-only P5 audit facts. Retired keys remain
available for at least 24 hours and through every live grant they signed, plus
the 60-second skew window. `RotatingIssuerKeyring` requires an injected
`IssuerSeedProvider`; deployments resolve the opaque `seed_ref` through their
protected secret manager. SQLite stores only that reference and public
metadata. Startup fails if the supplied seed does not match the active durable
key record. The shared signature fixture is
[`docs/vectors/adjustment-grant-v1.json`](docs/vectors/adjustment-grant-v1.json).

The human issuance default is 5,400 seconds; a P5-authorized extension may be
up to 9,900 seconds and requires fresh P5 approval. The 900-second autonomous
default belongs to a separate P5 autonomous policy path. That path is not
implemented here, and autonomous grant issuance remains unavailable until P5
defines and authenticates it. The grant issuer does not infer a supervision
tier from a caller-provided duration.

## Enabling adjustment grants

Merging the issuer does not turn the feature on. A grant is spent only when a
deployment (1) provisions an issuer seed and a P5 secret, (2) opens the authority,
and (3) injects its `verifier_adapter()` into the Oramasys consumer. This module
covers (1) and (2); step (3) belongs to the deployment's composition root.

```python
from pathlib import Path
from phylax import GrantAuthorityConfig, open_grant_authority

authority = open_grant_authority(GrantAuthorityConfig(
    state_dir=Path("/var/lib/oramasys/phylax"),   # created 0700, durable stores
    seed_root=Path("/etc/oramasys/phylax-seeds"),  # 0700 directory of 0600 hex files
    key_id="issuer-1", seed_ref="issuer-1", p5_secret_ref="p5-secret",
))
verifier = authority.verifier_adapter()  # hand this to the Oramasys composition root
```

Seeds are 32 bytes in hex, one per file, referenced by file name only; symlinks,
loose modes, and a seed that does not match the durable active key all refuse to
start. Not provided: the 900-second autonomous tier, which stays deferred until a
separately authenticated P5 policy exists, so only the human-approved path issues.
