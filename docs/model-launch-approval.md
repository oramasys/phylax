# Native P5 Model-Launch Approval

This adapter extends the existing Phylax P5 authority for model-launch intents.
It creates no approval until a trusted human-evidence verifier returns a fresh,
exact-use decision. An absent verifier refuses issuance. The adapter is not a
GitHub authenticator and is not wired to a provider dispatcher.

## Ownership and creation

`ModelLaunchIntent` binds principal, request/task/run/operation IDs, harness path,
model, effort, fast flag, budget-cap reference, scope, orchestration mode,
policy revision and the original request deadline. Its canonical payload uses
the existing native P5 compact sorted JSON encoding. This is distinct from
the RFC 8785 adjustment-grant wire format.

`ModelApprovalEvidenceVerifier` belongs to the trusted interaction composition.
It must authenticate the operator, establish fresh human confirmation, enforce
the original request decision state, and return the server-owned approval ID
bound to that exact intent. An access token or arbitrary evidence-reference
string alone does not establish those facts.

`phylax.github_device_approval.GitHubCliModelApprovalVerifier` is the first
concrete composition adapter. It reuses the established GitHub CLI ceremony:
an operator starts `gh auth login
--web` in a new isolated `GH_CONFIG_DIR`, enters GitHub's short-lived browser
user code, then posts an exact confirmation comment for the immutable launch
intent. The verifier rejects ambient token and host overrides, pins GitHub
public-host calls, checks the active numeric GitHub account ID and local
five-minute marker, spends that marker before API readback, and accepts only
an allowlisted, unedited GitHub comment with the exact canonical body. It
stores neither the browser code nor an access token. This implemented path is
procedural evidence: a fresh isolated CLI login plus an exact operator comment.
It is not an independently verifiable fresh factor or OTP attestation. That
stronger evidence capability remains an open planned extension, not a banned
or impossible design; the read-back comment is the durable audit reference.

`approve_model_launch` checks those facts before writing. It inserts an
`approved` row directly under `BEGIN IMMEDIATE` in the native P5 table. The
model path has no persisted pending queue. Existing swarm pending previews
retain their original behavior. A repeated approval ID cannot create a second
record, even after consumption.

## Receipt and execution clocks

The receipt expiry is the earliest of the original request deadline, evidence
expiry and current time plus the configured receipt TTL. The TTL can be reduced
but cannot exceed 300 seconds. Verified human duration defaults to 5,400 seconds;
the native 9,900-second ceiling applies. Duration is part of the signed receipt,
not an execution clock started by this adapter.

The internal HMAC domain is exactly
`b"phylax-p5-model-launch-approval-v1\x00"` followed by canonical receipt bytes.
Swarm and adjustment-grant approval domains retain their prior bytes. No new
Ed25519 signature format or second replay ledger is introduced.

`consume` verifies domain, MAC and immutable intent, then spends the receipt
once in the native durable store. Oramasys still owns the separate execution
use, budget reservation, dispatch transaction and execution deadline. The P5
commit and Oramasys dispatch commit are not one atomic transaction. A crash
between them must fail closed or recover through an authority-owned, tested
handoff; it must not automatically recreate approval or resend paid work.

## Qualification remaining

- Bind the concrete GitHub CLI verifier through a protected operator-facing
  composition root and an approved allowlist source. The adapter exists but is
  not yet connected to a service endpoint or provider dispatcher.
- Wire the verified decision into the Oramasys dispatch ledger and execution
  lease, without exposing issuer secrets to the serving consumer.
- Bind request/decision audit projections and timeout races at that composition.
- Design and validate an independently verifiable fresh-factor adapter before
  claiming MFA-grade proof from the GitHub CLI procedure.
- Verify the complete producer-to-consumer path before enabling gated execution.

Local tests cover direct approved insertion, exact intent drift, original
deadline, single-use and concurrent consume, domain separation, invalid fields,
missing verifier, GitHub CLI marker freshness, exact-comment readback, token
environment refusal, and compatibility with existing P5 behavior. They do not
prove live GitHub identity, human MFA, or production dispatch wiring.
