"""Review intake: untrusted review text in, inert verified findings out.

Public surface for harnesses. This package never fetches, executes, applies or
pushes anything; it parses, scrubs and keeps the finding-to-commit trace.
"""

from .ledger import LedgerRefusal, SqliteReviewLedger
from .model import (
    FindingLocation,
    LedgerEntry,
    ReviewFinding,
    ReviewIntakeError,
    Verdict,
)
from .parse import normalize_text, parse_comment, parse_many, scrub

__all__ = [
    "FindingLocation",
    "LedgerEntry",
    "LedgerRefusal",
    "ReviewFinding",
    "ReviewIntakeError",
    "SqliteReviewLedger",
    "Verdict",
    "normalize_text",
    "parse_comment",
    "parse_many",
    "scrub",
]
