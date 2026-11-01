"""GitHub device-ceremony approval for effect-grant issuance (decisions D1=A and D2).

The existing fresh-login ceremony is reused unchanged through
:func:`phylax.github_device_approval.verify_comment_ceremony`. A human performs a fresh isolated
``gh`` login and posts one exact, unedited comment that binds the *whole* effect request; Phylax
verifies that comment and only then calls :meth:`EffectGrantAuthority.issue`.

Assurance, stated plainly: this is **procedural evidence** that a specific GitHub account (mapped to
an operator principal by numeric id) made the decision. It is not an independently attested MFA
claim, and the evidence says so. Per D1=A the approval is proven once, at issuance; the concrete
dispatch attempt is bound later by the permit and finalization. Per-attempt human receipts (D1=B) are
required before any real effect class is qualified. Contract: ``docs/github-effect-approval.md``.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .effect_grant import EffectGrant, EffectGrantAuthority, EffectGrantRequest
from .github_device_approval import _resolve_gh, _run, verify_comment_ceremony

SCHEMA: Final = "oramasys-effect-issuance-approval: v1"
ASSURANCE: Final = "procedural-github-device-ceremony"
ASSURANCE_LINE: Final = f"assurance: {ASSURANCE}; not an independently attested MFA claim"
APPROVED_DURATION_SECONDS: Final = 5_400


def effect_request_digest(request: EffectGrantRequest) -> str:
    """Return the SHA-256 of the canonical form of every effect-request field."""
    fields = {
        "principal": request.principal, "run_id": request.run_id,
        "operation_id": request.operation_id, "request_digest": request.request_digest,
        "effect_class": request.effect_class, "ledger_store_id": request.ledger_store_id,
        "consumer_lease_epoch": request.consumer_lease_epoch,
        "second_approval_ref": request.second_approval_ref, "issuer_ref": request.issuer_ref,
        "revocation_ref": request.revocation_ref,
    }
    canonical = json.dumps(fields, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def effect_approval_body(request: EffectGrantRequest, *, review_expires_at: int) -> str:
    """Render the exact comment a human must post for this request and review deadline."""
    if isinstance(review_expires_at, bool) or not isinstance(review_expires_at, int) or review_expires_at < 1:
        raise ValueError("review_expires_at must be a positive epoch second")
    return "\n".join((
        SCHEMA,
        ASSURANCE_LINE,
        f"operator_principal: {request.principal}",
        f"effect_class: {request.effect_class}",
        f"operation_id: {request.operation_id}",
        f"ledger_store_id: {request.ledger_store_id}",
        f"request_digest: {effect_request_digest(request)}",
        f"review_expires_at: {review_expires_at}",
        f"approved_duration_seconds: {APPROVED_DURATION_SECONDS}",
    )) + "\n"


@dataclass(frozen=True, slots=True)
class VerifiedEffectApproval:
    """Facts returned only by the configured verifier, never from a client body."""

    evidence_ref: str
    operator_principal: str
    request_digest: str
    approved_at: datetime
    expires_at: datetime
    assurance: str = ASSURANCE
    mfa_attested: bool = False


@dataclass(frozen=True, slots=True)
class GitHubCliEffectApprovalVerifier:
    """Verify fresh isolated-gh login plus the exact unedited effect-issuance comment."""

    config_dir: Path
    repository: str
    approvers: Mapping[int, str]
    runner: Callable[..., str] = _run
    gh_executable: Path | None = None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self) -> None:
        """Resolve the CLI once so later PATH changes cannot redirect calls."""
        object.__setattr__(self, "gh_executable", _resolve_gh(self.gh_executable))

    def verify(
        self, request: EffectGrantRequest, evidence_ref: str, *, review_expires_at: int
    ) -> VerifiedEffectApproval:
        """Spend the fresh login and prove the comment binds exactly this request."""
        proof = verify_comment_ceremony(
            self,
            evidence_ref=evidence_ref,
            operator_principal=request.principal,
            expected_body=effect_approval_body(request, review_expires_at=review_expires_at),
            review_expires_at=review_expires_at,
        )
        return VerifiedEffectApproval(
            evidence_ref=evidence_ref, operator_principal=proof.principal,
            request_digest=effect_request_digest(request), approved_at=proof.approved_at,
            expires_at=proof.expires_at,
        )


def issue_with_github_approval(
    authority: EffectGrantAuthority,
    verifier: GitHubCliEffectApprovalVerifier,
    request: EffectGrantRequest,
    *,
    authenticated_principal: str,
    evidence_ref: str,
    review_expires_at: int,
) -> EffectGrant:
    """Verify the ceremony evidence for this exact request, then issue one effect grant.

    Verification runs before the P5 preview exists, so unverifiable evidence creates no approval
    and no grant. The verified comment URL becomes the P5 operator evidence reference, which the
    issuer already records (hashed) in its issuance audit.
    """
    if not isinstance(evidence_ref, str) or not evidence_ref.strip():
        raise ValueError("effect issuance requires human evidence")
    if authenticated_principal != request.principal:
        raise ValueError("authenticated principal does not match effect grant principal")
    evidence = verifier.verify(request, evidence_ref, review_expires_at=review_expires_at)
    if (
        evidence.mfa_attested
        or evidence.operator_principal != request.principal
        or evidence.request_digest != effect_request_digest(request)
    ):
        raise ValueError("effect approval evidence does not match the request")
    return authority.issue(
        request, authenticated_principal=authenticated_principal,
        operator_evidence_ref=evidence.evidence_ref,
    )
