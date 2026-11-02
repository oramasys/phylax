# Operator-signed assertions (production operator authentication)

**Status:** implementation contract for review. Dark by default: this module implements the existing
`OperatorAuthority` port and is wired into nothing. It enables no serving and ratifies nothing.
Code: `src/phylax/operator_assertion.py`; tests: `src/tests/test_operator_assertion.py`.

## Model

* **Registry.** One canonical-JSON document of per-person Ed25519 keys, signed (domain
  `phylax-operator-registry-v1`) by a registry authority key pinned in the verifier. Each entry has
  `operator_id`, `key_id`, `public_key`, a validity window, the `operations` the key may assert, and
  `revoked_at`. Entries are sorted, unique and bounded (64 entries, 16 operations each).
* **Assertion.** One signed statement (domain `phylax-operator-assertion-v1`) binding an operator
  key to exactly one `(operation, attempt_id, grant_id)` for the verifier's `audience`, with a nonce,
  `issued_at` and `expires_at` at most 300 seconds apart (5 s clock-skew allowance).
* **Verifier.** Holds public keys only; operator seeds never exist on the verifier host.
  `authority_for(assertion)` returns a one-shot `OperatorAuthority` whose first matching call
  consumes the nonce and returns `operator:<operator_id>:<nonce>` as the disposition reference, so
  each recorded decision names a person. Any failure returns `None` and records a closed code.

## Guarantees and the checks that enforce them

| Property | Enforcement |
| -------- | ----------- |
| Per-person identity | key lookup by `(operator_id, key_id)`; one person's key never authorizes another |
| Expiry | `now < expires_at`, lifetime <= 300 s, not issued in the future beyond skew |
| Single use | `(operator_id, nonce)` primary key inside a `BEGIN IMMEDIATE`; concurrent presentations consume once |
| No burn on failure | the nonce is consumed only after every other check passes |
| Revocation | `revoked_at` refuses immediately, including already-issued assertions |
| Anti-rollback | the registry-version floor rises on sight of any authority-signed registry (even when the call is refused) and a trigger forbids lowering it |
| Freshness | a registry older than 24 h (or from the future beyond skew) is refused |
| Exact binding | operation, attempt, grant and audience must equal the call; the operation must be in the key's list |
| Strictness | canonical bytes only, no duplicate keys, closed fields, 64 KiB bound |

Refusal codes are a closed vocabulary (`operator.*`). Operator key custody, the registry authority
key ceremony and the registry distribution medium remain operator decisions.
