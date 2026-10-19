# E1 C2 permit contract freeze (slice 1)

**Next actions (read first; the same list closes the document).**

1. Independent reviewers read this freeze, `src/phylax/dispatch_wire.py` and
   `docs/vectors/dispatch-permit-v1.json`, and report every `FREEZE-CHOICE` they disagree with.
2. Implementers build only against this contract. A change to a frozen item needs a new review.
3. Nothing here enables grant serving, issuance or a pin change. `ORAMA_GRANT_SERVING` stays unset.

## 1. Authority and scope

This freezes the items the ratified specification left open before implementation. The
specification is orama-system `E1-C2-PERMIT-WIRE-AND-ROLE-RECONCILIATION-2026-10-18.md`, ratified at
head `1481bc58` (merged as `fe9003a1`), specification only. Where this document and the
specification differ, the specification wins and this document is wrong.

Each decision below is tagged. **SPEC** means the ratified text says it. **FREEZE-CHOICE n** means
the text left it open and this document proposes a value; reviewers must confirm or change it.

Slice 1 covers the permit request and permit, retry and conflict, the single-row `aborted` state,
the finalization with its chain event, and the catch-up envelope. The effect grant v2 parser and
`effect_class` registry, replacement and reconciliation transitions, and retention are later slices.
Slice 1 reaches the signed grant through an injected lookup port, not through the v2 parser.

## 2. Objects (SPEC field sets; types are FREEZE-CHOICE 1)

Every object is a JSON object with exactly the listed keys. No extra keys, no `null`.

| Type | Fields | Wire form |
| --- | --- | --- |
| Text | ids, `issuer_key_id` | non-blank UTF-8, at most 1,024 bytes |
| Digest | `grant_payload_digest`, `request_digest`, `artifact_digest`, `permit_digest`, `revocation_event_digest`, `payload_digest` | 64 lowercase hexadecimal characters |
| Integer | `configuration_policy_epoch`, `authority_epoch`, `issuer_authority_version` | safe integer from 1 to 2^53 - 1 (positive, as the merged consumer helper requires) |
| Integer | `consumer_acked_through`, `revocation_version` | safe integer from 0 to 2^53 - 1 |
| Integer | `schema_version` | exactly 1 |
| Timestamp | `requested_at`, `issued_at`, `expires_at` | `YYYY-MM-DDTHH:MM:SS.ffffffZ`, six digits, UTC |
| Signature | `issuer_signature`, event `signature` | unpadded base64url of 64 bytes, canonical |

* **Permit request, 12 fields:** `grant_id`, `grant_payload_digest`, `operation_id`, `request_digest`,
  `artifact_digest`, `reservation_id`, `ledger_store_id`, `configuration_policy_epoch`,
  `authority_epoch`, `consumer_acked_through`, `attempt_id`, `requested_at`.
* **Permit, 21 fields:** `schema_version`, the 12 request fields, `permit_id`, `revocation_version`
  (written `R_p`), `issuer_authority_version`, `issued_at`, `expires_at`, `issuer_key_id`,
  `payload_digest`, `issuer_signature`.
* **Finalization request, 8 fields:** `permit_id`, `permit_digest`, `attempt_id`, `reservation_id`,
  `ledger_store_id`, `consumer_acked_through`, `authority_epoch`, `requested_at`.
* **Finalization, 15 fields:** `schema_version`, the 8 request fields, `finalization_id`,
  `revocation_version` (written `R_f`), `revocation_event_digest`, `issued_at`, `expires_at`,
  `issuer_signature`.
* **Event wire, 7 fields:** `version`, `kind`, `body`, `previous_event_digest`, `event_digest`,
  `issuer_key_id`, `signature`. `kind` is one of `revocation`, `cascade`, `finalization`.

## 3. Canonical bytes, digests and signatures

* **Canonical bytes (SPEC, finalization event encoding):** `json.dumps` with `sort_keys=True`,
  `separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, encoded as UTF-8. Nothing else is
  valid. This is the same function Phylax already uses for the v1 grant.
* **Permit digest (FREEZE-CHOICE 2):** the body is the canonical bytes of the permit without
  `payload_digest` and `issuer_signature`. `payload_digest` is the SHA-256 of the body. The wire
  adds `payload_digest` and `issuer_signature`. `permit_digest` (a finalization request field) and
  `payload_digest` (a permit wire field) are the SAME value under two names; `permit_digest` is not a
  separate permit field.
* **Finalization digest (FREEZE-CHOICE 3):** the body is the canonical bytes of the finalization
  without `issuer_signature`. The finalization digest recorded in the outbox is the SHA-256 of that
  body. It is computed, never a wire field.
* **Signatures (SPEC domains, FREEZE-CHOICE 4 framing):** Ed25519ph (RFC 8032) over the domain bytes
  followed by the body. Permit domain `phylax-dispatch-permit-v1\x00`, finalization domain
  `phylax-dispatch-finalization-v1\x00`. This matches the v1 grant framing exactly.
* **Binding digest (SPEC):** SHA-256 hex of the canonical object of exactly nine fields: `grant_id`,
  `grant_payload_digest`, `operation_id`, `request_digest`, `artifact_digest`, `reservation_id`,
  `ledger_store_id`, `configuration_policy_epoch`, `authority_epoch`. `requested_at`,
  `consumer_acked_through` and `attempt_id` are excluded. It is byte-identical to the consumer
  repository's merged `compute_binding_digest`, and the vector file carries one example.
* **Event digest (SPEC):** SHA-256 hex of the canonical wrapper
  `{"body", "kind", "previous_event_digest", "version"}`. A finalization body is exactly
  `{"finalization_id": ...}`. The first event's previous digest is 64 `0` characters.
* **Event signature (FREEZE-CHOICE 5):** Ed25519ph over the domain `phylax-issuer-event-v1\x00`
  followed by the 64 ASCII hexadecimal characters of the event digest.
* **Catch-up envelope (SPEC shape, FREEZE-CHOICE 6 names):** `{"events": [event wire, ...],
  "from_version": n, "through_version": m}`. It is not signed as a whole, may differ per retry, and
  its events are each signed. `events` is contiguous and ordered, and ends at `R_f`.

## 4. Key selection (FREEZE-CHOICE 7)

* A permit is signed with the keyring's active key and names it in `issuer_key_id`.
* A finalization carries no key id. It is signed with the key named by its bound permit, and the
  consumer verifies it under that key. If that key is no longer the active key, the issuer refuses
  with `finalization.key_rotated` and the attempt ends through the attested abandon. This applies to a
  FIRST finalization only. A retry of an already stored finalization returns the stored bytes unchanged
  even after a rotation: a lost-response retry must not be stranded, and the stored bytes stay
  verifiable for as long as the retired public key stays published in the registry.
* Every event names its own `issuer_key_id`. Public keys come from the existing key registry.
* The vector key is a fixed test seed and is never a production key.

## 5. Refusal vocabulary (SPEC names where marked, otherwise FREEZE-CHOICE 8)

The set is closed. A collaborator or storage fault is never one of these; it raises an error.

| Code | When |
| --- | --- |
| `permit.conflict` (SPEC) | different binding with the same `attempt_id`, or a new `attempt_id` on a grant whose latest permit is nonterminal |
| `permit.attempt_aborted` | the `attempt_id` has an `aborted` row |
| `permit.grant_mismatch` | digest, operation, request or ledger differs from the signed grant |
| `permit.grant_revoked` | grant, approval chain or issuer revoked, or a cascade pending |
| `permit.grant_expired` | the signed grant has expired, so no permit can outlive it |
| `permit.issuer_rolled_back` | the issuer counter is below `consumer_acked_through` |
| `permit.invalid_request` | malformed request wire |
| `finalization.conflict` (SPEC) | a changed binding value for the same permit and attempt |
| `finalization.catchup_required` (SPEC) | the gap exceeds the bound; no event and no finalization created |
| `finalization.permit_unusable` | permit unknown, expired, abandoned, aborted or terminal |
| `finalization.grant_revoked` | revocation or pending cascade at finalization |
| `finalization.issuer_rolled_back` | counter below the request's acknowledgement or below `R_p` |
| `finalization.key_rotated` | the permit's key is not the active key |
| `finalization.invalid_request` | malformed request wire |

Abort outcomes (not refusals): `abort.recorded`, `abort.already_aborted` (idempotent), and
`abort.admission_won`, which returns the existing record and does not authorize release.
`dispatch.issuer_unavailable` is a consumer-side status, never an issuer refusal.

## 6. Resource bounds (FREEZE-CHOICE 9)

* Wire objects: at most 65,536 bytes (SPEC). Text fields: at most 1,024 bytes. Integers: at most
  2^53 - 1. Lifetime: 90 seconds for permit and finalization (SPEC), never past the grant's expiry
  or the permit's expiry. Expiry is strict: refused when `now >= expires_at`.
* Constants in the wire module: lifetime 90 seconds, `ISSUER_AUTHORITY_VERSION` 1 for slice 1,
  catch-up bound 64 events.
* Catch-up bound: 64 events per envelope, a starting value to be replaced by a measured signed-policy
  value before enablement. Recovery-call timeouts: signed policy, not fixed here.

## 7. Issuer persistence contract (SQLite, FREEZE-CHOICE 10)

Phylax's store uses SQLite in WAL mode with `BEGIN IMMEDIATE` for every write, so all issuer writes
share one serialization domain; there is no lock-order problem to solve in slice 1.

* `dispatch_permits`: surrogate `row_id` primary key; `permit_id` unique and nullable; `grant_id`;
  `attempt_id` **unique**; `state` in `issued`, `finalized`, `abandoned`, `aborted`; the permit
  columns (`payload_digest`, `permit_bytes`, `r_p`, `issued_at`, `expires_at`, binding columns, and
  `finalization_id`, `finalization_bytes`, `finalization_digest` when present);
  `replaces_permit_id`; `abort_disposition`. An `aborted` row has no permit bytes.
* Three database constraints that count only rows holding a permit (each a partial unique index on
  `grant_id`, which is NOT NULL, so SQLite's rule that NULLs are distinct in a unique index does not
  apply; the predicate `replaces_permit_id IS NULL` only selects which rows are counted): at most one original permit
  (`replaces_permit_id IS NULL`) per `grant_id`; at most one `issued` or `finalized` permit per
  grant; `replaces_permit_id` unique where present.
* `issuer_events`: `version` primary key, `kind`, `body`, `previous_event_digest`, `event_digest`
  unique, `issuer_key_id`, `signature`. An append requires `version` equal to the current maximum
  plus one, inside the same `BEGIN IMMEDIATE` transaction.
* The counter `R_p` is the current maximum event version. Finalization appends one event and `R_f`
  is that version.

## 8. Ownership matrix

| Concern | Owner | Notes |
| --- | --- | --- |
| Signing, keys, issuer persistence and transactions | Phylax | this repository |
| Permit and finalization verification | consumer via a verifier port | no cryptography in the consumer |
| Attempts, fence, grant-use consumption, intent, outbox | Oramasys | one transaction at step 4.3 |
| Vectors | Phylax produces; Oramasys vendors a byte-identical copy with a hash test | |

## 8a. Slice 1 implementation notes (for reviewers; each is a choice to confirm)

* **FREEZE-CHOICE 11, finalization retry and the bound.** A finalization retry applies the same
  catch-up bound as a first finalization. If the gap from the request's acknowledgement to the stored
  `R_f` exceeds the bound it is refused as `finalization.catchup_required` and nothing changes. The
  retry envelope runs from `consumer_acked_through + 1` through the stored `R_f`; it is empty when the
  acknowledgement is already at or past `R_f`.
* **FREEZE-CHOICE 12, unknown grant at finalization.** A grant the lookup no longer knows is refused
  as `finalization.grant_revoked` (fail closed). The vocabulary has no separate code for it.
* **FREEZE-CHOICE 13, retry expiry.** A finalization retry reads the finalization's expiry from its
  stored bytes; no expiry column is added.
* **FREEZE-CHOICE 14, schema and files.** The permit store uses its own database file (separate from
  the grant store), `user_version` 1, a connection per operation, and validates the schema by comparing
  the stored DDL text of every table and index with the frozen DDL (column names alone would bless a
  file with weaker constraints). It adds no private-file-mode handling, as the existing writer store
  has none.

## 9. What is not in slice 1

Deliberately deferred, so slice 1 is not mistaken for the whole ratified specification:

* **Issuer:** the attested abandon and the successor request (an `abandoned` permit with no successor),
  the operator lookup and operator authentication of abort and abandon (the store's abort method
  trusts its caller), reconciliation, retention and checkpoints, and wiring the signer port to the
  existing key registry.
* **Consumer client:** request-side validators (12 and 8 fields), catch-up envelope validation
  (contiguity, `from_version`, `through_version`, the 64-event bound; slice 1 ingests a bare event
  list), wiring the sender precondition at the effect boundary, a durable UTC high-water mark, the
  15-second minimum finalization window, deadline accounting and bounded
  retries, the circuit breaker and alert, the recovery calls after the authority deadline, and the
  `dispatch.issuer_unavailable` status path.
* **Both:** the body shapes of `revocation` and `cascade` events (not frozen; slice 1 treats them as
  opaque and its revocation port is the consumer's abstraction of them), the effect grant v2 parser and `effect_class` registry (slice 1 reaches the signed grant
  through an injected lookup), and any pin change. None is enabled by this freeze.

**Next actions (repeated).** Reviewers confirm or change each `FREEZE-CHOICE`; implementers build
only against this contract; nothing enables serving, issuance or a pin change.
