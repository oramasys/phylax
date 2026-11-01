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
* **Immutability.** `DirectoryMedium` refuses to rewrite a segment name with different bytes.
* **Combined lookup.** `CombinedRevocationLookup.reason(grant_id, approval_ref)` checks, in order,
  issuer, grant, approval chain, cascade, and undeclared-approval, and returns the same reason strings
  as the consumer's `dispatch_revocations.refusal_reason`. The shared vector pins every row; the
  oramasys PR for this decision runs the same file against the consumer function.
* **Pruning-safe.** The state replays through the stitched retained feed, so archived history counts.

## Not in this PR

Which public medium hosts the artifacts, who owns the seven-year retention of the cold archive, and
the consumer's polling cadence remain operator decisions. A directory medium is provided so the
contract is testable without choosing one.
