"""Exact model-launch intents and approved-only native P5 authority.

The verifier port must be implemented by a trusted human-interaction boundary.
This module does not authenticate GitHub, infer human presence from a bearer,
or authorize provider dispatch. Its receipts are consumed by the native P5 store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Protocol

from .p5_approval import (
    P5ApprovalAuthority,
    P5ApprovalIntent,
    P5ApprovalPreview,
    P5ApprovalReceipt,
    P5ApprovalStore,
    _canonical_bytes,
    _require_positive_int,
    _utc_timestamp,
)

_MODEL_DOMAIN = b"phylax-p5-model-launch-approval-v1\x00"
_TEXT_FIELDS = frozenset({
    "request_id", "task_id", "run_id", "operation_id", "harness_path",
    "model_id", "effort", "scope", "mode", "policy_revision",
})
_FIELDS = _TEXT_FIELDS | {"fast", "budget_cap", "review_expires_at"}


@dataclass(frozen=True, slots=True)
class ModelLaunchIntent(P5ApprovalIntent):
    """Version-one immutable model intent, independent of the swarm preview shape."""

    action: str = "model.launch"

    def __post_init__(self) -> None:
        """Validate exact keys, types and policy-independent intent invariants."""
        if not isinstance(self.operator_principal, str) or not self.operator_principal.strip():
            raise ValueError("operator_principal is required")
        if self.action != "model.launch":
            raise ValueError("model launch action is required")
        try:
            payload = json.loads(self.canonical_preview_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("canonical model launch JSON is required") from exc
        if not isinstance(payload, dict) or set(payload) != _FIELDS:
            raise ValueError("model launch fields are incomplete")
        if _canonical_bytes(payload).decode("utf-8") != self.canonical_preview_json:
            raise ValueError("model launch must use canonical JSON")
        if any(not isinstance(payload[key], str) or not payload[key].strip() for key in _TEXT_FIELDS):
            raise ValueError("model launch text fields must be nonempty strings")
        if payload["effort"] not in ("medium", "high") or payload["mode"] not in ("standard", "ultracode"):
            raise ValueError("model launch effort or mode is unsupported")
        if payload["fast"] is not False:
            raise ValueError("model launch requires explicit fast off")
        if payload["budget_cap"] is not None and (
            not isinstance(payload["budget_cap"], str) or not payload["budget_cap"].strip()
        ):
            raise ValueError("budget_cap must be an opaque nonempty reference or null")
        _require_positive_int(payload["review_expires_at"], "review_expires_at")

    @classmethod
    def from_launch(cls, operator_principal: str, payload: dict[str, object]) -> ModelLaunchIntent:
        """Freeze named fields with the existing native P5 canonical JSON encoder."""
        return cls(operator_principal, _canonical_bytes(payload).decode("utf-8"))

    def signature_domain(self) -> bytes:
        """Separate model receipts from all existing swarm and grant receipts."""
        return _MODEL_DOMAIN


@dataclass(frozen=True, slots=True)
class VerifiedModelApproval:
    """Facts returned only by the configured trusted verifier, never a client body."""

    approval_id: str
    operator_principal: str
    task_id: str
    request_digest: str
    approved_at: datetime
    expires_at: datetime
    evidence_ref: str
    approved_duration_seconds: int = 5_400


class ModelApprovalEvidenceVerifier(Protocol):
    """Authenticate an operator and bind explicit human confirmation to this intent."""

    def verify(self, intent: ModelLaunchIntent, evidence_ref: str) -> VerifiedModelApproval:
        """Return fresh, single-use challenge facts or raise on unverifiable evidence."""


class ModelLaunchApprovalAuthority(P5ApprovalAuthority):
    """Use the native P5 ledger, creating authority only after human verification."""

    def __init__(
        self, *, signing_key: bytes, store: P5ApprovalStore,
        evidence_verifier: ModelApprovalEvidenceVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        preview_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        """Leave issuance unavailable until the composition root supplies a verifier."""
        if preview_ttl > timedelta(minutes=5):
            raise ValueError("model approval receipt must not exceed 300 seconds")
        super().__init__(signing_key=signing_key, store=store, clock=clock, preview_ttl=preview_ttl)
        self._evidence_verifier = evidence_verifier

    def approve_model_launch(self, intent: ModelLaunchIntent, *, evidence_ref: str) -> P5ApprovalReceipt:
        """Verify an exact human decision, then atomically insert approved authority."""
        if self._evidence_verifier is None:
            raise ValueError("model human-evidence verifier is unavailable")
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            raise ValueError("model human evidence is required")
        evidence = self._evidence_verifier.verify(intent, evidence_ref)
        if not isinstance(evidence, VerifiedModelApproval):
            raise ValueError("invalid model human evidence")
        payload = intent.preview_payload()
        now = self._now()
        if (
            evidence.operator_principal != intent.operator_principal
            or evidence.task_id != payload["task_id"]
            or evidence.request_digest != intent.preview_digest()
            or not isinstance(evidence.approval_id, str) or not evidence.approval_id.strip()
            or not isinstance(evidence.evidence_ref, str) or not evidence.evidence_ref.strip()
        ):
            raise ValueError("model human evidence does not match intent")
        _utc_timestamp(evidence.approved_at)
        _utc_timestamp(evidence.expires_at)
        if evidence.approved_at > now or now - evidence.approved_at >= self._preview_ttl:
            raise ValueError("model human evidence is not fresh")
        deadline = min(
            now + self._preview_ttl, evidence.expires_at,
            datetime.fromtimestamp(int(payload["review_expires_at"]), tz=now.tzinfo),
        )
        if deadline <= now:
            raise ValueError("model approval request expired")
        preview = P5ApprovalPreview(evidence.approval_id, intent, deadline)
        receipt = self._make_receipt(
            preview, evidence.evidence_ref, evidence.approved_duration_seconds, evidence.approved_at
        )
        self._store.put_approved(
            preview, receipt, evidence.evidence_ref, evidence.approved_at, clock=self._now
        )
        return receipt
