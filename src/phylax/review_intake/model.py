"""Immutable records for review intake: findings, verdicts and ledger entries.

A review comment is untrusted *data*. Nothing in these types can carry an
instruction to an agent: suggested edits and embedded instructions are held as
inert strings that no API in this package executes or applies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal

Severity = Literal["critical", "high", "medium", "low", "info", "unspecified"]
VerdictKind = Literal["valid", "invalid", "already_fixed", "needs_decision"]

SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info", "unspecified"})
VERDICT_KINDS: Final = frozenset({"valid", "invalid", "already_fixed", "needs_decision"})

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_FINDING_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")

MAX_CLAIM_CHARS: Final = 2_000
MAX_SUGGESTION_CHARS: Final = 4_000
MAX_INSTRUCTION_CHARS: Final = 500
MAX_INSTRUCTIONS: Final = 20


def claim_key(claim: str) -> str:
    """Return the canonical comparison form of a claim: lower-case, single-spaced.

    The finding id and the ledger's collision check both use this one function,
    so two claims that share an id are, by construction, the same claim.
    """
    return " ".join(claim.lower().split())


class ReviewIntakeError(ValueError):
    """Raised when review text or a ledger operation is refused (fail closed)."""


_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def validate_source(value: object) -> str:
    """Require a short safe label (for example ``coderabbit``) and return it.

    The source is persisted and shown to later readers, so free text, control
    characters and markup are refused rather than normalized.
    """
    if not isinstance(value, str) or _SOURCE_RE.fullmatch(value) is None:
        raise ReviewIntakeError("source must be a short label of letters, digits and _.:-")
    return value


def is_commit_sha(value: object) -> bool:
    """Report whether ``value`` is a lower-case abbreviated or full commit SHA."""
    return isinstance(value, str) and _COMMIT_RE.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class FindingLocation:
    """Where a finding points; both parts are optional metadata, never trusted."""

    path: str | None = None
    line: int | None = None

    def __post_init__(self) -> None:
        """Reject absolute, drive-qualified, control-character or traversing paths and bad lines."""
        if self.path is not None:
            if not self.path or len(self.path) > 512 or self.path.startswith(("/", "~")):
                raise ReviewIntakeError("location path must be a short repository-relative path")
            if _DRIVE_RE.match(self.path):
                raise ReviewIntakeError("location path must not be drive-qualified")
            if any(ord(char) < 32 or ord(char) == 127 for char in self.path):
                raise ReviewIntakeError("location path must not contain control characters")
            if ".." in self.path.split("/") or "\\" in self.path:
                raise ReviewIntakeError("location path must not traverse directories")
        if self.line is not None and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1):
            raise ReviewIntakeError("location line must be a positive integer")


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    """One sanitized claim extracted from review text."""

    finding_id: str
    source: str
    location: FindingLocation
    claim: str
    severity: Severity = "unspecified"
    suggested_change: str = ""
    embedded_instructions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate shape and bounds; the claim must say something."""
        if not _FINDING_ID_RE.fullmatch(self.finding_id):
            raise ReviewIntakeError("finding_id must be a 32-character hex digest")
        validate_source(self.source)
        if not self.claim.strip():
            raise ReviewIntakeError("finding has no claim")
        if len(self.claim) > MAX_CLAIM_CHARS or len(self.suggested_change) > MAX_SUGGESTION_CHARS:
            raise ReviewIntakeError("finding text exceeds its bound")
        if self.severity not in SEVERITIES:
            raise ReviewIntakeError("severity is not recognised")
        if len(self.embedded_instructions) > MAX_INSTRUCTIONS or any(
            len(text) > MAX_INSTRUCTION_CHARS for text in self.embedded_instructions
        ):
            raise ReviewIntakeError("quarantined instructions exceed their bound")

    @property
    def quarantined(self) -> int:
        """Return how many embedded instructions were set aside, unexecuted."""
        return len(self.embedded_instructions)


@dataclass(frozen=True, slots=True)
class Verdict:
    """A verifier's judgement of a finding against the *current* code."""

    kind: VerdictKind
    evidence: str
    verified_by: str
    verified_at: datetime

    def __post_init__(self) -> None:
        """Require evidence for every verdict: a bare 'valid' is a rubber stamp."""
        if self.kind not in VERDICT_KINDS:
            raise ReviewIntakeError("verdict kind is not recognised")
        if not self.evidence.strip():
            raise ReviewIntakeError("a verdict requires evidence from the current code")
        if not self.verified_by.strip():
            raise ReviewIntakeError("a verdict requires its verifier")
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() is None:
            raise ReviewIntakeError("verified_at must be timezone-aware")

    @classmethod
    def now(cls, kind: VerdictKind, evidence: str, verified_by: str) -> Verdict:
        """Build a verdict stamped with the current UTC time."""
        return cls(kind, evidence, verified_by, datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """The full trace for one finding: verdict, fixing commit and reply."""

    finding: ReviewFinding
    verdict: Verdict | None
    applied_in: str | None
    replied_with: str | None
    reply_commit: str | None
