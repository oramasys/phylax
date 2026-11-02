# GitHub device-ceremony approval for effect issuance (decisions D1=A and D2)

**Status:** implementation contract for review. Dark by default: it adds a verifier in front of the
existing `EffectGrantAuthority.issue`, changes no grant wire or schema, enables no effect and
ratifies nothing. Code: `src/phylax/github_effect_approval.py`; tests:
`src/tests/test_github_effect_approval.py`.

## Decisions recorded

* **D1 = A (this release).** A signed approval chain proves a human approved the operation *at
  issuance*; the concrete dispatch attempt is bound later by the permit and finalization. **D1 = B**
  (a new signed human receipt for every dispatch attempt) is required before any real effect class
  is qualified or if strict per-attempt confirmation is demanded. This module does not provide B.
* **D2.** The existing fresh-login GitHub device ceremony is extended to effect issuance by reusing
  its verifier core (`verify_comment_ceremony`, extracted from the model-launch adapter with its 37
  existing tests unchanged).

## What the human posts

One exact, unedited comment binding the whole request: principal, effect class, operation id, ledger
store id, a SHA-256 over **every** `EffectGrantRequest` field, the review deadline and the approved
duration, plus the line `assurance: procedural-github-device-ceremony; not an independently
attested MFA claim`. A comment approving one request never authorizes a request that differs in any
field or in the deadline.

## Assurance, stated plainly

The evidence is **procedural**: a specific GitHub account (mapped to the principal by numeric id)
completed a fresh isolated login and posted the exact text. It is not an independently attested MFA
claim; `VerifiedEffectApproval.assurance` and `mfa_attested=False` say so, and the comment itself
says so to the person signing it.

## Order and failure behaviour

`issue_with_github_approval` checks the authenticated principal, then spends the fresh login and
verifies the comment, and only then calls `authority.issue`. Unverifiable evidence therefore creates
no P5 preview and no grant. The login is single-use even when the comment readback fails. An
unqualified effect class still refuses inside `issue`.
