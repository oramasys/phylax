"""Stable Phylax compile and runtime admission contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, TypeAlias

# Source class of the evidence behind a runtime request. Only "observed" evidence can
# satisfy an Observed requirement; derived or reconstructed evidence never can.
EvidenceClass: TypeAlias = Literal["observed", "derived", "reconstructed"]
EVIDENCE_CLASSES: tuple[str, ...] = ("observed", "derived", "reconstructed")


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Reference to an artifact by id, digest and provenance."""
    artifact_id: str
    digest_sha256: str
    provenance_ref: str

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        if not self.artifact_id.strip():
            raise ValueError("artifact_id is required")
        if len(self.digest_sha256) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in self.digest_sha256
        ):
            raise ValueError("digest_sha256 must be a 64-character hexadecimal digest")
        if not self.provenance_ref.strip():
            raise ValueError("provenance_ref is required")


@dataclass(frozen=True, slots=True)
class CompileRequest:
    """Request to compile an artifact with requested capabilities."""
    artifact: ArtifactRef
    requested_capabilities: frozenset[str]
    actor_id: str = "oramasys"

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        if any(not capability.strip() for capability in self.requested_capabilities):
            raise ValueError("capability names must not be empty")


@dataclass(frozen=True, slots=True)
class CompileDecision:
    """Result of a compile-time authority check."""
    allowed: bool
    reason_code: str
    policy_version: str
    compile_ref: str
    artifact: ArtifactRef
    approved_capabilities: frozenset[str]
    decided_at: datetime


@dataclass(frozen=True, slots=True)
class RuntimeAdmissionRequest:
    """Request to admit a compiled artifact for a run."""
    compile_ref: str
    artifact_id: str
    digest_sha256: str
    capability: str
    run_id: str
    actor_id: str = "oramasys"
    # None means the caller did not classify its evidence. That is never treated as
    # observed: capabilities that require Observed evidence refuse it.
    evidence_class: EvidenceClass | None = None

    def __post_init__(self) -> None:
        """Validate the fields at construction and fail closed on bad input."""
        for field_name in ("compile_ref", "artifact_id", "digest_sha256", "capability", "run_id", "actor_id"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")
        if self.evidence_class is not None and self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"unknown evidence_class: {self.evidence_class!r}")


@dataclass(frozen=True, slots=True)
class RuntimeAdmissionDecision:
    """Result of runtime admission with id, expiry and authority epoch."""
    allowed: bool
    reason_code: str
    policy_version: str
    compile_ref: str
    artifact_id: str
    capability: str
    decided_at: datetime
    # R4 T1 lifecycle. A decision authorizes nothing once expired or once the
    # authority epoch has moved on (revocation); callers re-check before every
    # execution boundary instead of copying policy.
    decision_id: str = ""
    expires_at: datetime | None = None
    authority_epoch: int = 0


class PrincipalVerifier(Protocol):
    """Checks whether a principal/actor identity is currently trusted."""

    def __call__(self, actor_id: str) -> bool:
        """Return True if actor_id is currently trusted/verified, False otherwise."""
        ...


class PhylaxPort(Protocol):
    """Composition boundary for compile and runtime admission."""

    def compile(self, request: CompileRequest) -> CompileDecision:
        """Evaluate whether an artifact may enter a runnable graph."""

    def admit(self, request: RuntimeAdmissionRequest) -> RuntimeAdmissionDecision:
        """Evaluate whether a capability may run for a compiled artifact."""

    def is_current(self, decision: RuntimeAdmissionDecision) -> bool:
        """True only for an allowed, unexpired decision at the current authority epoch."""

