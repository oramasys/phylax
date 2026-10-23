"""Model approvals bind verified human evidence before durable authority exists."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
import base64
import hashlib
import hmac

import pytest

from phylax.model_launch_approval import (
    ModelLaunchApprovalAuthority,
    ModelLaunchIntent,
    VerifiedModelApproval,
)
from phylax.p5_approval import P5ApprovalAuthority, SqliteP5ApprovalStore


NOW = datetime(2026, 10, 23, tzinfo=UTC)


def intent(*, expires_in: int = 300, model_id: str = "model-a") -> ModelLaunchIntent:
    """Create one fully bound launch independent of a vendor's model catalog."""
    return ModelLaunchIntent.from_launch("control-plane", {
        "request_id": "request-a", "task_id": "task-a", "run_id": "run-a",
        "operation_id": "operation-a", "harness_path": "provider-a",
        "model_id": model_id, "effort": "medium", "fast": False,
        "budget_cap": "cap-reference-a", "scope": "task-a",
        "mode": "standard", "policy_revision": "policy-a",
        "review_expires_at": int(NOW.timestamp()) + expires_in,
    })


class EvidenceVerifier:
    """Test-only trusted-port stand-in; it does not model GitHub authentication."""

    def verify(self, requested: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
        """Attest the exact test request after an independent human interaction."""
        return VerifiedModelApproval(
            approval_id="approval-a", operator_principal="control-plane",
            task_id="task-a", request_digest=requested.preview_digest(),
            approved_at=NOW, expires_at=NOW + timedelta(minutes=5),
            approved_duration_seconds=5400, evidence_ref=evidence_ref,
        )


def authority(path: Path, verifier: EvidenceVerifier | None = None) -> ModelLaunchApprovalAuthority:
    """Construct a durable authority with an explicit evidence-verification port."""
    return ModelLaunchApprovalAuthority(
        signing_key=b"test-only-secret", store=SqliteP5ApprovalStore(str(path)),
        evidence_verifier=verifier, clock=lambda: NOW,
    )


def states(path: Path) -> list[str]:
    """Inspect actual persisted state rather than a mocked write call."""
    with closing(sqlite3.connect(path)) as db:
        return [row[0] for row in db.execute("SELECT state FROM p5_approvals")]


def test_missing_verifier_cannot_create_an_approval(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"
    policy = authority(path)
    with pytest.raises(ValueError, match="verifier"):
        policy.approve_model_launch(intent(), evidence_ref="opaque-human-evidence")
    assert states(path) == []


def test_model_approval_is_created_approved_and_consumed_once(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"
    policy = authority(path, EvidenceVerifier())
    receipt = policy.approve_model_launch(intent(), evidence_ref="opaque-human-evidence")
    assert states(path) == ["approved"]
    assert receipt.preview_id == "approval-a"
    assert receipt.approved_duration_seconds == 5400
    decision = policy.consume(receipt, intent())
    assert decision.intent == intent()
    assert states(path) == ["consumed"]
    with pytest.raises(ValueError, match="already consumed"):
        authority(path, EvidenceVerifier()).consume(receipt, intent())


def test_model_cannot_create_a_pending_preview(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"
    policy = authority(path, EvidenceVerifier())
    with pytest.raises(ValueError, match="human"):
        policy.issue_preview(intent())
    assert states(path) == []


def test_human_decision_does_not_restart_request_deadline(tmp_path: Path) -> None:
    policy = authority(tmp_path / "p5.db", EvidenceVerifier())
    requested = intent(expires_in=20)
    receipt = policy.approve_model_launch(requested, evidence_ref="opaque-human-evidence")
    assert receipt.expires_at == NOW + timedelta(seconds=20)


def test_verified_evidence_must_match_exact_intent(tmp_path: Path) -> None:
    class WrongDigest(EvidenceVerifier):
        def verify(self, requested: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
            return replace(super().verify(requested, evidence_ref), request_digest="0" * 64)

    path = tmp_path / "p5.db"
    with pytest.raises(ValueError, match="evidence"):
        authority(path, WrongDigest()).approve_model_launch(intent(), evidence_ref="opaque")
    assert states(path) == []


def test_payload_drift_does_not_spend_valid_model_receipt(tmp_path: Path) -> None:
    policy = authority(tmp_path / "p5.db", EvidenceVerifier())
    receipt = policy.approve_model_launch(intent(), evidence_ref="opaque")
    with pytest.raises(ValueError, match="intent mismatch"):
        policy.consume(receipt, intent(model_id="model-b"))
    assert policy.consume(receipt, intent()).intent == intent()


def test_concurrent_consumers_admit_one_model_launch(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"
    policy = authority(path, EvidenceVerifier())
    receipt = policy.approve_model_launch(intent(), evidence_ref="opaque")

    def consume() -> bool:
        try:
            authority(path).consume(receipt, intent())
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: consume(), range(2))) == [False, True]


def test_base_authority_also_rejects_pending_model_intents(tmp_path: Path) -> None:
    policy = P5ApprovalAuthority(
        signing_key=b"test-only-secret", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db"))
    )
    with pytest.raises(ValueError, match="human"):
        policy.issue_preview(intent())


def test_human_verification_happens_before_first_authority_write(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"

    class InspectBeforeVerify(EvidenceVerifier):
        def verify(self, requested: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
            assert states(path) == []
            return super().verify(requested, evidence_ref)

    authority(path, InspectBeforeVerify()).approve_model_launch(intent(), evidence_ref="opaque")
    assert states(path) == ["approved"]


def test_model_receipt_uses_its_own_exact_hmac_domain(tmp_path: Path) -> None:
    policy = authority(tmp_path / "p5.db", EvidenceVerifier())
    receipt = policy.approve_model_launch(intent(), evidence_ref="opaque")
    encoded_body, encoded_mac = receipt.approval_token.split(".")
    body = base64.urlsafe_b64decode(encoded_body + "=" * (-len(encoded_body) % 4))
    mac = base64.urlsafe_b64decode(encoded_mac + "=" * (-len(encoded_mac) % 4))
    assert hmac.compare_digest(
        mac, hmac.digest(b"test-only-secret", b"phylax-p5-model-launch-approval-v1\x00" + body, hashlib.sha256)
    )
    wrong_mac = hmac.digest(b"test-only-secret", b"phylax-p5-swarm-approval-v1\x00" + body, hashlib.sha256)
    encoded_wrong_mac = base64.urlsafe_b64encode(wrong_mac).decode().rstrip("=")
    with pytest.raises(ValueError, match="invalid P5 approval token"):
        policy.consume(replace(receipt, approval_token=encoded_body + "." + encoded_wrong_mac), intent())
    assert policy.consume(receipt, intent()).intent == intent()


def test_expired_model_request_cannot_be_issued_or_consumed(tmp_path: Path) -> None:
    path = tmp_path / "p5.db"
    policy = authority(path, EvidenceVerifier())
    with pytest.raises(ValueError, match="expired"):
        policy.approve_model_launch(intent(expires_in=0), evidence_ref="opaque")
    assert states(path) == []
    receipt = policy.approve_model_launch(intent(expires_in=1), evidence_ref="opaque")
    later = ModelLaunchApprovalAuthority(
        signing_key=b"test-only-secret", store=SqliteP5ApprovalStore(str(path)),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="expired"):
        later.consume(receipt, intent(expires_in=1))


def test_repeated_evidence_cannot_create_two_approvals(tmp_path: Path) -> None:
    policy = authority(tmp_path / "p5.db", EvidenceVerifier())
    policy.approve_model_launch(intent(), evidence_ref="opaque")
    with pytest.raises(ValueError, match="already exists"):
        policy.approve_model_launch(intent(), evidence_ref="opaque")


@pytest.mark.parametrize("field,value", [("fast", True), ("effort", "xhigh"), ("review_expires_at", True)])
def test_model_intent_rejects_unsafe_or_ambiguous_types(field: str, value: object) -> None:
    payload = intent().preview_payload()
    payload[field] = value
    with pytest.raises(ValueError):
        ModelLaunchIntent.from_launch("control-plane", payload)


@pytest.mark.parametrize("field,value", [
    ("operator_principal", "another-principal"),
    ("task_id", "another-task"),
    ("approved_at", NOW + timedelta(seconds=1)),
    ("approved_at", NOW - timedelta(minutes=5)),
    ("expires_at", NOW),
    ("approved_duration_seconds", True),
    ("approved_duration_seconds", 9901),
])
def test_invalid_human_evidence_never_creates_authority(
    tmp_path: Path, field: str, value: object,
) -> None:
    class InvalidEvidence(EvidenceVerifier):
        def verify(self, requested: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
            return replace(super().verify(requested, evidence_ref), **{field: value})

    path = tmp_path / "p5.db"
    with pytest.raises(ValueError):
        authority(path, InvalidEvidence()).approve_model_launch(intent(), evidence_ref="opaque")
    assert states(path) == []


def test_receipt_ttl_cannot_be_raised_above_policy_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="300 seconds"):
        ModelLaunchApprovalAuthority(
            signing_key=b"test-only-secret", store=SqliteP5ApprovalStore(str(tmp_path / "p5.db")),
            evidence_verifier=EvidenceVerifier(), preview_ttl=timedelta(seconds=301),
        )
