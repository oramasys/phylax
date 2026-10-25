"""The direct-xAI fast-mode exception is spendable once, only for the exact launch."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from phylax.fast_launch_gate import FastLaunchRefused, authorize_direct_xai_fast
from phylax.model_launch_approval import (
    ModelLaunchApprovalAuthority,
    ModelLaunchIntent,
    VerifiedModelApproval,
)
from phylax.p5_approval import SqliteP5ApprovalStore

NOW = datetime(2026, 10, 25, tzinfo=UTC)
OPERATOR = "synthetic-operator"


def _launch(**overrides: object) -> dict[str, object]:
    """Build the dispatcher's own canonical launch fields (synthetic identifiers only)."""
    base: dict[str, object] = {
        "request_id": "request-a", "task_id": "task-a", "run_id": "run-a",
        "operation_id": "operation-a", "harness_path": "direct_xai",
        "model_id": "grok-4.7", "effort": "medium", "fast": True,
        "budget_cap": "cap-reference-a", "scope": "task-a",
        "mode": "standard", "policy_revision": "policy-a",
        "review_expires_at": int(NOW.timestamp()) + 300,
    }
    base.update(overrides)
    return base


class _Verifier:
    """Test-only stand-in for the trusted human-evidence port."""

    def verify(self, requested: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
        """Attest exactly the requested intent."""
        return VerifiedModelApproval(
            approval_id=f"approval-{requested.preview_digest()[:8]}",
            operator_principal=OPERATOR, task_id="task-a",
            request_digest=requested.preview_digest(), approved_at=NOW,
            expires_at=NOW + timedelta(minutes=5), evidence_ref=evidence_ref,
        )


class _Clock:
    """Mutable test clock."""

    def __init__(self) -> None:
        """Start at the fixed instant."""
        self.now = NOW

    def __call__(self) -> datetime:
        """Return the current test instant."""
        return self.now


def _setup(tmp_path: Path) -> tuple[ModelLaunchApprovalAuthority, _Clock]:
    """Create a durable authority with an explicit verifier and controllable clock."""
    clock = _Clock()
    authority = ModelLaunchApprovalAuthority(
        signing_key=b"synthetic-signing-key", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db")),
        evidence_verifier=_Verifier(), clock=clock,
    )
    return authority, clock


def _approve(authority: ModelLaunchApprovalAuthority, **overrides: object):
    """Obtain a receipt through the verified-evidence path only."""
    intent = ModelLaunchIntent.from_fast_launch(OPERATOR, _launch(**overrides))
    return authority.approve_model_launch(intent, evidence_ref="opaque-human-evidence")


def _spend(authority, receipt, *, caller: str = OPERATOR, **overrides: object):
    """Present the dispatcher's actual launch to the gate."""
    return authorize_direct_xai_fast(
        authority, receipt, launch=_launch(**overrides),
        operator_principal=OPERATOR, caller_principal=caller,
    )


def test_exact_fast_launch_is_accepted_once_with_a_verified_receipt(tmp_path: Path) -> None:
    """A verified receipt authorizes the exact launch one time, then is spent."""
    authority, _ = _setup(tmp_path)
    receipt = _approve(authority)
    decision = _spend(authority, receipt)
    assert decision.intent.preview_payload()["fast"] is True
    with pytest.raises(FastLaunchRefused, match="already consumed"):
        _spend(authority, receipt)


def test_concurrent_double_spend_of_one_fast_receipt_is_single_use(tmp_path: Path) -> None:
    """Racing threads, each with its own authority and store on one file, spend one receipt once."""
    workers = 8
    db_path = tmp_path / "p5.db"
    issuer, _ = _setup(tmp_path)
    receipt = _approve(issuer)
    barrier = threading.Barrier(workers)
    outcomes: list[str] = [""] * workers

    def race(index: int) -> None:
        """Wait for every peer, then spend the receipt through a private authority and store."""
        authority = ModelLaunchApprovalAuthority(
            signing_key=b"synthetic-signing-key", store=SqliteP5ApprovalStore(str(db_path)),
            evidence_verifier=_Verifier(), clock=_Clock(),
        )
        barrier.wait(timeout=30)
        try:
            _spend(authority, receipt)
            outcomes[index] = "ok"
        except FastLaunchRefused:
            outcomes[index] = "refused"

    threads = [threading.Thread(target=race, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    assert outcomes.count("ok") == 1
    assert outcomes.count("refused") == workers - 1
    with sqlite3.connect(db_path) as connection:
        states = [row[0] for row in connection.execute("SELECT state FROM p5_approvals")]
    connection.close()
    assert states == ["consumed"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("model_id", "grok-4.8"), ("effort", "high"), ("scope", "task-b"),
        ("request_id", "request-b"), ("run_id", "run-b"), ("policy_revision", "policy-b"),
    ],
)
def test_mismatched_launch_is_refused_without_spending_the_receipt(
    tmp_path: Path, field: str, value: str
) -> None:
    """Any bound field that differs refuses, and the genuine launch still works afterwards."""
    authority, _ = _setup(tmp_path)
    receipt = _approve(authority)
    with pytest.raises(FastLaunchRefused):
        _spend(authority, receipt, **{field: value})
    assert _spend(authority, receipt).operator_evidence_ref == "opaque-human-evidence"


def test_fast_off_launch_cannot_use_the_fast_exception(tmp_path: Path) -> None:
    """The gate only ever builds a fast-on intent, so fast=False cannot be presented to it."""
    authority, _ = _setup(tmp_path)
    receipt = _approve(authority)
    with pytest.raises(FastLaunchRefused, match="fast"):
        _spend(authority, receipt, fast=False)


def test_expired_receipt_is_refused(tmp_path: Path) -> None:
    """A receipt past its deadline cannot be spent."""
    authority, clock = _setup(tmp_path)
    receipt = _approve(authority)
    clock.now = NOW + timedelta(minutes=6)
    with pytest.raises(FastLaunchRefused, match="expired"):
        _spend(authority, receipt)


def test_automated_caller_cannot_spend_the_operators_receipt(tmp_path: Path) -> None:
    """Only the approving operator principal may spend; another principal is refused unspent."""
    authority, _ = _setup(tmp_path)
    receipt = _approve(authority)
    with pytest.raises(FastLaunchRefused, match="operator principal"):
        _spend(authority, receipt, caller="synthetic-automation")
    assert _spend(authority, receipt)


def test_ordinary_launch_receipt_cannot_authorize_fast_mode(tmp_path: Path) -> None:
    """A fast-off model.launch receipt is in a different domain and never validates as fast."""
    authority, _ = _setup(tmp_path)
    plain = ModelLaunchIntent.from_launch(OPERATOR, _launch(fast=False))
    receipt = authority.approve_model_launch(plain, evidence_ref="opaque-human-evidence")
    with pytest.raises(FastLaunchRefused):
        _spend(authority, receipt)


def test_forged_or_altered_token_is_refused(tmp_path: Path) -> None:
    """A tampered approval token never reaches the one-use ledger."""
    authority, _ = _setup(tmp_path)
    receipt = _approve(authority)
    forged = replace(receipt, approval_token=receipt.approval_token[:-2] + "AA")
    with pytest.raises(FastLaunchRefused, match="invalid"):
        _spend(authority, forged)


def test_fast_intent_is_limited_to_direct_xai_medium() -> None:
    """The exception cannot be minted for another harness path or a non-default effort."""
    with pytest.raises(ValueError, match="direct_xai"):
        ModelLaunchIntent.from_fast_launch(OPERATOR, _launch(harness_path="cursor_grok_bot"))
    with pytest.raises(ValueError, match="direct_xai"):
        ModelLaunchIntent.from_fast_launch(OPERATOR, _launch(effort="high"))


def test_fast_intent_has_no_pending_preview_path(tmp_path: Path) -> None:
    """Fast approval cannot be created through the legacy preview issuer."""
    authority, _ = _setup(tmp_path)
    with pytest.raises(ValueError, match="verified human evidence"):
        authority.issue_preview(ModelLaunchIntent.from_fast_launch(OPERATOR, _launch()))
