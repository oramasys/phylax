# Signed public revocation state, durable feed and combined lookup (decision D3)

**Status:** implementation contract for review; stacked on the retention PR. Dark by default: not
wired into any serving path; it ratifies nothing and enables no effect. Code:
`src/phylax/revocation_publication.py`; tests: `src/tests/test_revocation_publication.py`; shared
truth table: `docs/vectors/revocation-lookup-v1.json`.

## Artifacts

| Artifact | Content | Mutability |
| -------- | ------- | ---------- |
| `events-<low>-<high>.json` | canonical `{events, from_version, through_version}`, at most 64 signed events | immutable |
| `state.json` | issuer-signed summary: head version and digest, issuer-revoked flag, revoked grants and approvals, cascades | replaced |

The state is a *summary*, never the authority: it names the chain head, and a verifier cross-checks
it with `verify_state_against_chain` against the signed, hash-linked feed. Segments are published
before the state that names their head.

## Rules

* **Signature and shape.** Ed25519ph under `phylax-revocation-state-v1`; canonical bytes only; closed
  fields; sorted, duplicate-free subject lists; cascades validated by the existing wire rule.
* **Freshness.** A state older than 60 seconds (ADR 71 revocation freshness) or dated more than 5
  seconds ahead is `publication.stale`. A consumer treats every `publication.*` refusal as
  *revoked/unavailable*, never as "nothing revoked".
* **Read-back.** `FeedPublisher` reads every artifact back from the medium and compares bytes. A
  medium that drops, corrupts or fails is `publication.unavailable` / `publication.readback_mismatch`.
* **Immutability.** `DirectoryMedium` refuses to rewrite a segment name with different bytes. Writers are
  serialized across processes by an advisory lock, each write uses its own temporary file, and the
  directory is synced after the rename before success is reported (POSIX).
* **Exact segments.** `read_feed` requires every segment to carry exactly the requested event
  versions, in order; an empty or shortened segment under a correct range label is
  `publication.malformed`, never an empty feed.
* **Size limit.** A state past `MAX_STATE_BYTES` (1 MiB) is `publication.state_too_large`.
  `FeedPublisher.publish` verifies the state before writing it, so an unverifiable state never replaces
  the last good `state.json`.
* **Combined lookup.** `CombinedRevocationLookup(state, clock=...)` re-checks the state's age on every
  call and raises `publication.stale` once it has expired (treat as revoked).
  `reason(grant_id, approval_ref)` checks, in order,
  issuer, grant, approval chain, cascade, and undeclared-approval, and returns the same reason strings
  as the consumer's `dispatch_revocations.refusal_reason`. The shared vector pins every row; the
  oramasys PR for this decision runs the same file against the consumer function.
* **Pruning-safe.** The state replays through the stitched retained feed, so archived history counts.

## Known limit: cumulative growth

The state is a full summary of every revoked identifier and cascade, and pruning cannot shrink it, so
it grows without bound while the verifier caps it at 1 MiB. The publisher now fails closed (the last
good state stays) instead of replacing it, but a long-lived issuer will eventually hit the cap. The
fix is a paged or segmented state format, which is a schema change and an operator decision; it is
deliberately not made here.

## Not in this PR

Which public medium hosts the artifacts, who owns the seven-year retention of the cold archive, and
the consumer's polling cadence remain operator decisions. A directory medium is provided so the
contract is testable without choosing one.
