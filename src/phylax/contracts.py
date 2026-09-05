"""Stable Phylax compile and runtime admission contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    artifact_id: str
    digest_sha256: str
    provenance_ref: str

    def __post_init__(self) -> None:
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
    artifact: ArtifactRef
    requested_capabilities: frozenset[str]
    actor_id: str = "oramasys"

    def __post_init__(self) -> None:
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        if any(not capability.strip() for capability in self.requested_capabilities):
            raise ValueError("capability names must not be empty")


@dataclass(frozen=True, slots=True)
class CompileDecision:
    allowed: bool
    reason_code: str
    policy_version: str
    compile_ref: str
    artifact: ArtifactRef
    approved_capabilities: frozenset[str]
    decided_at: datetime


@dataclass(frozen=True, slots=True)
class RuntimeAdmissionRequest:
    compile_ref: str
    artifact_id: str
    digest_sha256: str
    capability: str
    run_id: str
    actor_id: str = "oramasys"

    def __post_init__(self) -> None:
        for field_name in ("compile_ref", "artifact_id", "digest_sha256", "capability", "run_id", "actor_id"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")


@dataclass(frozen=True, slots=True)
class RuntimeAdmissionDecision:
    allowed: bool
    reason_code: str
    policy_version: str
    compile_ref: str
    artifact_id: str
    capability: str
    decided_at: datetime

