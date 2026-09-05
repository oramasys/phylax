"""Reference compile and runtime admission authority."""

from __future__ import annotations

from datetime import UTC, datetime
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
    ) -> None:
        if not policy_version.strip():
            raise ValueError("policy version is required")
        self._trusted_provenance = frozenset(trusted_provenance)
        self._allowed_capabilities = frozenset(allowed_capabilities)
        self._policy_version = policy_version
        self._decisions: dict[str, CompileDecision] = {}

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
            decided_at=datetime.now(UTC),
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
        else:
            reason_code = "allowed"

        return RuntimeAdmissionDecision(
            allowed=reason_code == "allowed",
            reason_code=reason_code,
            policy_version=self._policy_version,
            compile_ref=request.compile_ref,
            artifact_id=request.artifact_id,
            capability=request.capability,
            decided_at=datetime.now(UTC),
        )

