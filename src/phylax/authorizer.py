"""Reference compile and runtime admission authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from .contracts import (
    ArtifactRef,
    CompileDecision,
    CompileRequest,
    RuntimeAdmissionDecision,
    RuntimeAdmissionRequest,
)


class PhylaxAuthorizer:
    def __init__(
        self,
        *,
        trusted_provenance: set[str] | frozenset[str],
        allowed_capabilities: set[str] | frozenset[str],
        policy_version: str = "phylax-policy-v1",
        decision_ttl: timedelta = timedelta(minutes=5),
        observed_required: set[str] | frozenset[str] = frozenset(),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not policy_version.strip():
            raise ValueError("policy version is required")
        if decision_ttl <= timedelta(0):
            raise ValueError("decision_ttl must be positive")
        self._trusted_provenance = frozenset(trusted_provenance)
        self._allowed_capabilities = frozenset(allowed_capabilities)
        self._policy_version = policy_version
        self._decisions: dict[str, CompileDecision] = {}
        self._ttl = decision_ttl
        self._observed_required = frozenset(observed_required)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._epoch = 1

    @property
    def authority_epoch(self) -> int:
        return self._epoch

    def revoke(self) -> int:
        """Invalidate every outstanding runtime decision; returns the new epoch."""
        self._epoch += 1
        return self._epoch

    def is_current(self, decision: RuntimeAdmissionDecision) -> bool:
        return (
            decision.allowed
            and decision.authority_epoch == self._epoch
            and decision.expires_at is not None
            and self._now() < decision.expires_at
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Phylax clock must return an aware UTC datetime")
        return now.astimezone(UTC)

    def compile(self, request: CompileRequest) -> CompileDecision:
        missing = request.requested_capabilities - self._allowed_capabilities
        if request.artifact.provenance_ref not in self._trusted_provenance:
            reason_code = "untrusted_provenance"
            allowed = False
        elif missing:
            reason_code = "capability_not_permitted"
            allowed = False
        else:
            reason_code = "allowed"
            allowed = True

        decision = CompileDecision(
            allowed=allowed,
            reason_code=reason_code,
            policy_version=self._policy_version,
            compile_ref=token_urlsafe(18),
            artifact=request.artifact,
            approved_capabilities=request.requested_capabilities if allowed else frozenset(),
            decided_at=self._now(),
        )
        if allowed:
            self._decisions[decision.compile_ref] = decision
        return decision

    def admit(self, request: RuntimeAdmissionRequest) -> RuntimeAdmissionDecision:
        compile_decision = self._decisions.get(request.compile_ref)
        if compile_decision is None:
            reason_code = "compile_decision_not_found"
        elif compile_decision.artifact.artifact_id != request.artifact_id:
            reason_code = "artifact_mismatch"
        elif compile_decision.artifact.digest_sha256.lower() != request.digest_sha256.lower():
            reason_code = "digest_mismatch"
        elif request.capability not in compile_decision.approved_capabilities:
            reason_code = "capability_not_permitted"
        elif request.capability in self._observed_required and request.evidence_class != "observed":
            reason_code = "evidence_not_observed"
        else:
            reason_code = "allowed"

        now = self._now()
        return RuntimeAdmissionDecision(
            allowed=reason_code == "allowed",
            reason_code=reason_code,
            policy_version=self._policy_version,
            compile_ref=request.compile_ref,
            artifact_id=request.artifact_id,
            capability=request.capability,
            decided_at=now,
            decision_id=token_urlsafe(18),
            expires_at=now + self._ttl,
            authority_epoch=self._epoch,
        )

