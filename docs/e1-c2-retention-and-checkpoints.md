# E1 C2 retention and signed checkpoints (Part 3 amendment sections 3.1 and 3.2)

**Status:** implementation contract for review. Dark by default: nothing here is wired into a
serving path, and no part of it ratifies the Part 3 amendment (that needs the operator decision the
amendment names). `ORAMA_GRANT_SERVING` stays unset. Additive only: the frozen
`dispatch_permits` and `issuer_events` schemas, every wire encoding and every existing store method
are unchanged. Code: `src/phylax/dispatch_retention.py`; tests: `src/tests/test_dispatch_retention.py`.

## 1. Checkpoints (3.1)

An `issuer_events` row is already an issuer-signed `(version, digest)` checkpoint. `Checkpoint` is a
four-field view of that row (`version`, `event_digest`, `issuer_key_id`, `signature`); there is no
second signing domain. `verify_checkpoint` checks the event-domain Ed25519ph signature over the
digest text through an injected `IssuerKeyResolver`. `verify_chain` recomputes every digest from the
body, never from the row, and checks contiguity, `previous_event_digest` links and signatures.

## 2. Retention and pruning (3.2)

| Rule | Behaviour |
| ---- | --------- |
| Ceiling | the lowest acknowledged version across every **registered** consumer; a registered consumer with no observed ack counts as 0; no registered consumer refuses (`retention.no_consumers`) |
| Observed ack | the highest `consumer_acked_through` the issuer has seen per `ledger_store_id` in `dispatch_permits` |
| Move, never discard | rows below the ceiling are appended to the append-only archive, read back and compared before the hot rows are deleted |
| One anchor | the row at the ceiling stays hot; advancing the boundary archives the former anchor |
| Atomicity | the whole operation runs under the hot store's write lock; any failure rolls the hot store back |
| Crash window | rows archived but not yet deleted are confirmed idempotently on rerun |
| Authority | `register_consumer` and `prune` require the injected operator port (`retention.register`, `retention.prune`); registration is permanent (no deregistration, so the ceiling cannot be raised by editing the registry) |
| Archive | `archived_events`, the consumer registry and the prune log reject UPDATE and DELETE by trigger; the archive must stay contiguous from version 1 |

`RetainedEventFeed` stitches archive and hot rows. A range that neither tier can serve in full is
refused (`retention.range_unavailable`); it is never returned short. `verify_continuity` verifies
the archive from genesis and its link to the hot anchor.

## 3. Known residuals (stated, not hidden)

* The frozen store's `events()` and catch-up envelope read only the hot table. A consumer whose ack
  is below the anchor receives a range that starts above `ack + 1`; the consumer's own
  `validate_catchup` refuses it (`catchup_range`), so the failure is closed, but the store itself
  does not name it. Registering every consumer before its first permit keeps this from arising.
* The frozen store's duplicate-revocation lookup reads only the hot table. Use
  `append_revocation_once` (archive first, then store) wherever pruning is enabled.
* Observed acks are consumer-asserted inside authenticated permit requests. An overstated ack can
  only cause an earlier move to the archive, never a discard.
* Moving the archive to a separate durable medium and the seven-year retention owner remain
  operator decisions; this module provides the append-only interface and the continuity proof.

## Review-driven clarifications (2026-11-02)

- **A bare checkpoint authenticates the digest only.** The issuer signature covers the event digest, not the `version` field, so `verify_checkpoint(Checkpoint)` cannot prove a version. `verify_checkpoint_against_event` recomputes the digest from the full event and is the check to use whenever the version matters; `verify_chain` already does this for every event.
- **Reads are consistent across a concurrent prune.** `RetainedEventFeed.events` re-reads the hot boundary and retries (three attempts) when it moved during the read; it still refuses a range that is genuinely unavailable.
- **Prune and retained revocation append share one advisory lock** (`<ledger>.lock`, POSIX `flock`), taken before any hot lock, so a prune cannot move a revocation between the archive check and the append. Code that calls the frozen store's `append_revocation` directly is outside this guarantee.
- **Overlapping tiers are an intact crash state.** `verify_continuity` accepts hot rows that are still present after being archived when they match the archive byte for byte, and refuses them otherwise.
- **The archive signature walk runs before the hot write lock.** `prune` snapshots the archive tail, verifies the whole archive, and re-checks the tail under the hot lock; if a row was appended in between it refuses with `retention.archive_changed` (archived rows are immutable, so an unchanged tail proves nothing unchecked was appended). Hot writers are no longer starved by an O(archive) walk, and the in-lock link, chain and read-back checks are unchanged.
