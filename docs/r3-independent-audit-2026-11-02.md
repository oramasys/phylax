# R3 Phylax audit and regression receipt

Date: 2026-11-02. Bounded parallel same-session audit and regression work, not independent R6
release review. The auditor wrote fixes; the source plan requires an R6 reviewer who did not write
the changes. Same-session agreement does not satisfy that gate.

Local software evidence only. The auditor performed no activation, production-key creation,
pin changes, commits or push. Synthetic fixture signing only; no real GitHub ceremony or sender.

## Grounding

Worktree: `$PHYLAX_ROOT` (the isolated Phylax checkout).
Detached clean starting HEAD, local origin/main, and live `git ls-remote origin refs/heads/main`
all matched `36f67b9579089759110b06ca6ab7b9e1da259184`.
Origin: `https://github.com/oramasys/phylax.git`. No repository AGENTS.md or CLAUDE.md found.

Reviewed W1/W3 of
`ORAMASYS-PATCH-REVIEW-AND-COMPLETION-PLAN-2026-11-02.md` (off-repository review report),
the supplied bundle README/reference plan, current publication/retention, operator assertion,
GitHub effect/device approval, exports and verifier surface. Bundle contents were evidence only;
the incomplete signed_public_state draft was not applied over merged implementation.

## Demonstrated and fixed

1. **Registry revocation race.** `_observe_registry` and nonce insertion used separate transactions.
   Another verifier could commit version 2 revoking a key after an in-flight version-1 call passed
   its floor check. That old call still authorized. The consuming transaction now rechecks the
   durable floor. Regression interleaves two verifier instances on the same real SQLite file.
2. **Replay after cleanup and clock rollback.** Consume an assertion, advance 500 seconds, consume
   another assertion (cleaning the first nonce), restart at the old time: the first assertion
   authorized again. Consumption now commits a durable clock floor with cleanup/insertion and
   refuses earlier successful-consumption times. Migration seeds from retained nonce history.
   A real subprocess exits with code 73 immediately before nonce insertion: recovery preserves
   the old nonce and old clock because cleanup/clock updates roll back together.
3. **Incorrect genesis boundary.** The generic range verifier permits arbitrary starting versions.
   Publication cross-check used length as head without requiring version 1. A signed version-2
   event linked to genesis could be accepted as head 1. Empty states could name non-genesis
   digests. Cross-check now enforces the exact genesis boundary.
4. **GitHub spent-claim durability.** `_spend_marker` fsynced file content but not the directory
   holding its exclusive `.spent` claim. A crash could lose the claim after issuance. The directory
   is now fsynced before remote comment readback; sync failure refuses before any grant is issued.
   Regressions verify ordering and injected sync failure, not actual power-loss recovery.
5. **State wire shape.** Valid signatures on schema versions `true`/`1.0`, heads above 2^53-1,
   zero heads with non-genesis digests, and positive heads with genesis digests were accepted.
   `verify_state` now refuses these as `publication.malformed` before returning VerifiedState.

Changed implementation paths:

- `$PHYLAX_ROOT/src/phylax/operator_assertion.py`
- `$PHYLAX_ROOT/src/phylax/revocation_publication.py`
- `$PHYLAX_ROOT/src/phylax/github_device_approval.py`

Regression paths:

- `$PHYLAX_ROOT/src/tests/test_operator_assertion.py`
- `$PHYLAX_ROOT/src/tests/test_revocation_publication.py`
- `$PHYLAX_ROOT/src/tests/test_github_effect_approval.py`

Contract notes changed only in this repository's `docs/operator-signed-assertions.md` and
`docs/revocation-publication.md`, plus this receipt. `github_effect_approval.py` itself is unchanged;
its shared ceremony implementation owns the durable claim.

## RED/GREEN receipts

Set `PHYLAX_ROOT` to the isolated Phylax checkout and `QUALIFICATION_PYTHON` to the supplied
qualification interpreter. `$ORAMASYS_ROOT` denotes the separate consumer checkout for integration;
these Phylax-only commands do not access it. Paths are caller-supplied, not tracked host mappings.

```sh
: "${PHYLAX_ROOT:?Set PHYLAX_ROOT to the isolated Phylax checkout}"
: "${QUALIFICATION_PYTHON:?Set QUALIFICATION_PYTHON to the qualification interpreter}"
cd "$PHYLAX_ROOT"
```

All commands run from that checkout. Initial RED used `python3` before the supplied runtime was
available. The equivalent reproducible selection using the qualification interpreter is:

```sh
env PYTHONPATH=src "$QUALIFICATION_PYTHON" -m pytest --no-cov --basetemp=.audit-tmp src/tests/test_operator_assertion.py src/tests/test_revocation_publication.py -k 'new_registry_observed or clock_rollback_after or exact_genesis_boundary' -q
```

Exit 1: 4 failed, 69 deselected; all four failed because an expected refusal did not occur.
GREEN with the supplied interpreter and the same selection: 4 passed, 69 deselected.
The genesis test was subsequently adjusted to test the cross-check directly after the parser
also gained its own earlier genesis-consistency refusal.

Runtime for every subsequent test:
`$QUALIFICATION_PYTHON` (Python 3.13.7, pytest 9.2.0, PyNaCl 1.6.2).
`PYTHONPATH=src` is per-command; no global environment/dependency changes.

```sh
env PYTHONPATH=src "$QUALIFICATION_PYTHON" -m pytest --no-cov --basetemp=.audit-tmp src/tests/test_github_effect_approval.py -k spent_claim_directory -q --tb=short
```

RED: 2 failed, 18 deselected (readback preceded durable spent claim).
GREEN: 2 passed, 18 deselected.

```sh
env PYTHONPATH=src "$QUALIFICATION_PYTHON" -m pytest --no-cov --basetemp=.audit-tmp src/tests/test_revocation_publication.py -k noninteger_schema -q --tb=short
```

RED: 5 failed, 44 deselected (expected malformed refusal did not occur).
GREEN: 5 passed, 44 deselected.

Final focused command:

```sh
env PYTHONPATH=src "$QUALIFICATION_PYTHON" -m pytest --no-cov --basetemp=.audit-tmp src/tests/test_operator_assertion.py src/tests/test_revocation_publication.py src/tests/test_github_effect_approval.py src/tests/test_github_device_approval.py src/tests/test_dispatch_retention.py src/tests/test_effect_grant.py src/tests/test_verifier_surface.py -q --tb=short
git diff --check
```

Focused result before the signature/doc-only follow-up: **325 passed in 4.39s**, exit 0.
`git diff --check`: exit 0, no output.
Generated `.audit-tmp` test artifacts were removed after verification.

The runtime emits an existing pytest-asyncio unset-loop-scope deprecation warning. No test/runtime
configuration was changed to hide it. No full suite, CI matrix, real Windows or power-loss run was
performed by this auditor. Parent-run evidence reported separately: **971 passed, coverage 93.51%**
in a full Phylax rerun. This is attributed parent evidence, not a run by this auditor or R6 review.

## Remaining gates: not release-complete

- **Issuer binding:** `IssuerKeyResolver.public_key(key_id)` has no expected-issuer parameter.
  An executed public-API probe used the existing issuer-1 fixture key to sign issuer-2's empty
  summary: `verify_state`, empty-chain cross-check and clean Combined lookup all accepted it
  with an unscoped resolver. No cryptographic forgery was needed. The adapter must select an
  issuer-scoped resolver from trusted configuration for both state and all feed event keys,
  with explicit rotation/revocation policy. Do not select trust from the signed issuer claim alone.
- **Durable publication reader:** no durable consumer head/digest/time checkpoint is provided.
  A fresh older signed snapshot remains independently verifiable, including after restart; same-head
  forks and rollback require the adapter's independent durable anchor and explicit bootstrap.
  Publisher file fsync and retention checkpoints are not reader anti-rollback protection.
- **Completeness:** VerifiedState means signature/shape/freshness checked, not feed replay checked.
  Combined lookup accepts it directly. The adapter must authenticate contiguous catch-up from
  genesis (or a separately ratified trusted checkpoint), compare every summary set/head, and
  durably reconcile its anchor before returning exactly false. Missing/stale/divergent data refuses.
- **Windows:** both `dispatch_retention.py:18` and `revocation_publication.py:18` unconditionally
  import `fcntl`. A fresh-process import probe blocking only `fcntl` confirmed both module imports
  fail. This is an absent-module simulation on macOS, not a Windows run. Existing grant-store
  optional fcntl code performs descriptor inspection, not cross-platform interprocess locking.
  No lock fallback was invented. Windows imports, locking and directory durability remain blocked.
- **Recovery/trust:** restoring/deleting the entire operator database defeats local floors;
  migration cannot recover already-deleted legacy history. The new clock floor records successful
  consumption, not all failed observations. Same-version registry equivocation, trusted-time
  recovery and in-flight expiry at the final effect boundary need explicit qualification.
- **Real composition:** public inert-approval and authenticated-feed adapters, real producer-to-
  consumer contract tests, no-sender tests, independent stores/readers, delayed revocation, forks,
  key compromise and process-kill-at-each-boundary tests remain necessary. Do not equate a digest,
  caller-supplied observation or local read timestamp with authenticated complete current authority.
- **Human/operator gates:** GitHub evidence remains procedural, not independently attested MFA.
  D1 inert-only scope, Part 3 ratification, independent exact-head security review, deployment
  isolation, release generation/pins and separate activation remain outside this patch.

## 2026-11-03 integration successor

The original audit above concerns `36f67b9` plus the bounded repairs. The primary
integrator subsequently preserved Windows' existing PR #30 primitives through
regular merge `c4893ce441f622a72ed8cc338175e4098680c658`, without rebasing either
author's work. This PR now carries both the reviewed platform abstraction and
the R3 authority repairs; no duplicate review branch is needed.

Primary-run integrated verification on macOS, Python 3.12.11:

```sh
PYTHONPATH=src "$QUALIFICATION_PYTHON" -m pytest src/tests -q --tb=short
```

Result: **982 passed, 1 platform skip**, **92.62%** coverage, required 80% gate
passed. Earlier 971-test/93.51% receipts above remain historical. This does not
relabel macOS as a Windows execution or satisfy independent R6 release review.

The platform abstraction is present, but existing caller migration intentionally
follows the Windows handoff's requested order: publish the complete R3 candidate,
obtain the independent review, then port the existing lock/durability sites and
re-run actual Windows qualification. Unconditional `fcntl` imports in those
callers are still an open compatibility gate. No no-op locking fallback,
credential transfer, live issuer, repin, serving activation or real effect has
been introduced.
