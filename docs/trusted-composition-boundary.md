# Trusted Dispatch Composition Boundary

## Purpose

This document records the smallest implemented trusted-composition slice for
E1/C2 dispatch permits. It is deliberately an issuer-side key-custody adapter,
not a serving entry point or a new grant protocol.

`PhylaxGrantAuthority.dispatch_signer_adapter()` returns
`DispatchIssuerSigner`, which implements the existing `IssuerSigner` port used
by `SqliteDispatchPermitStore`. The adapter:

- reads the active key only through `RotatingIssuerKeyring`;
- refreshes durable active-key state before every signing operation;
- refuses a caller-supplied key identifier unless it equals the active durable
  key after that refresh;
- signs only the frozen permit, finalization, and issuer-event domains; and
- never exposes a seed, generic signing operation, P5 receipt, grant issuance,
  or revocation-management surface.

The frozen dispatch wire functions own canonical encoding and Ed25519ph domain
separation. The adapter therefore does not define new bytes, fields, key
identifiers, or a network protocol.

## Deliberately Separate Boundaries

`SignedGrantLookup` remains an injected issuer-admission port. It cannot be
derived from `PhylaxAdjustmentGrantVerifier`: `VerifiedGrant` carries the
adjustment-grant tuple, while `GrantFacts` requires dispatch-specific
`operation_id`, `request_digest`, and `cascade_pending` facts. Treating either
missing value as a default would create a new unaudited grant protocol and
weaken the permit binding check.

The following remain outside this slice:

- authenticated construction of dispatch `GrantFacts` from a signed v2
  dispatch-grant format;
- consumer-side `TrustedIssuerKeys` and signature-verifier composition, which
  are owned by Oramasys;
- the issuer outcome authenticator and operator-authority adapters;
- P5 model-launch receipts and GitHub CLI ceremony; and
- provider transport, serving activation, production pins, or deployment
  configuration.

## Evidence and Next Contract Gate

`src/tests/test_dispatch_composition.py` proves that the adapter produces
verifiable permit, finalization, and event signatures under their three
distinct frozen domains, and refuses a substituted key identifier. It does not
claim end-to-end dispatch admission: that requires a separately specified
signed dispatch-grant parser and a trusted producer of every `GrantFacts`
field.

Before wiring `SignedGrantLookup`, the next contract must specify all of the
following together:

1. canonical signed dispatch-grant bytes and issuer/key identity;
2. authenticated binding for `payload_digest`, `operation_id`,
   `request_digest`, `ledger_store_id`, expiry, revocation, and cascade state;
3. failure semantics for unavailable or stale issuer/revocation evidence; and
4. reciprocal, pinned issuer/consumer negative tests for wrong issuer, wrong
   key, changed body, expiry, revocation, and no-write refusal.

Until that contract exists, deployments keep the injected lookup and the
serving switch off.
