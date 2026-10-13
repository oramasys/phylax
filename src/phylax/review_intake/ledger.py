"""Durable finding -> verdict -> commit -> reply trace for review remediation.

The ledger is append-only in spirit: verdicts are never rewritten, a newer one
supersedes and the history stays queryable. It refuses the two moves the
doctrine forbids: applying a finding nobody verified, and answering one without
saying where it was resolved.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .model import (
    LedgerEntry,
    ReviewFinding,
    ReviewIntakeError,
    Verdict,
    FindingLocation,
    claim_key,
    is_commit_sha,
)


class LedgerRefusal(ReviewIntakeError):
    """Raised when a ledger operation would break a remediation invariant."""


class SqliteReviewLedger:
    """SQLite ledger with the same durability conventions as the P5 store."""

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        """Open or create the ledger file; WAL is set once at initialisation."""
        if not str(path).strip() or str(path).strip() == ":memory:":
            raise LedgerRefusal("ledger requires a durable file path")
        if timeout <= 0:
            raise LedgerRefusal("ledger timeout must be positive")
        self._path = str(path)
        self._timeout = timeout
        try:
            with self._connect() as db:
                db.execute("PRAGMA journal_mode = WAL")
                db.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS findings(
                        finding_id TEXT PRIMARY KEY, source TEXT NOT NULL, path TEXT, line INTEGER,
                        claim TEXT NOT NULL, severity TEXT NOT NULL, suggested_change TEXT NOT NULL,
                        instructions_json TEXT NOT NULL, ingested_at TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS verdicts(
                        seq INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL,
                        kind TEXT NOT NULL, evidence TEXT NOT NULL, verified_by TEXT NOT NULL,
                        verified_at TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS applications(
                        finding_id TEXT NOT NULL, verdict_seq INTEGER NOT NULL,
                        commit_sha TEXT NOT NULL, applied_at TEXT NOT NULL,
                        PRIMARY KEY(finding_id, verdict_seq));
                    CREATE TABLE IF NOT EXISTS replies(
                        finding_id TEXT NOT NULL, verdict_seq INTEGER NOT NULL,
                        reference TEXT NOT NULL, commit_sha TEXT, replied_at TEXT NOT NULL,
                        PRIMARY KEY(finding_id, verdict_seq));
                    """
                )
        except sqlite3.OperationalError as exc:
            raise LedgerRefusal("review ledger is busy or unavailable") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a short-lived autocommit connection and always close it."""
        db = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _snapshot(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection holding one read transaction, so reads agree."""
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                try:
                    yield db
                finally:
                    db.execute("ROLLBACK")
        except sqlite3.OperationalError as exc:
            raise LedgerRefusal("review ledger is busy or unavailable") from exc

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """Open an immediate transaction, translating lock failures to refusals."""
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
                db.execute("COMMIT")
        except sqlite3.OperationalError as exc:
            raise LedgerRefusal("review ledger is busy or unavailable") from exc

    # -- ingest ------------------------------------------------------------

    def ingest(self, finding: ReviewFinding) -> bool:
        """Record a finding once; an identical re-ingest is a no-op returning False."""
        with self._write() as db:
            existing = db.execute(
                "SELECT claim FROM findings WHERE finding_id = ?", (finding.finding_id,)
            ).fetchone()
            if existing is not None:
                if claim_key(existing["claim"]) != claim_key(finding.claim):
                    raise LedgerRefusal("finding id collides with a different claim")
                return False
            db.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    finding.finding_id, finding.source, finding.location.path, finding.location.line,
                    finding.claim, finding.severity, finding.suggested_change,
                    json.dumps(list(finding.embedded_instructions)), datetime.now(UTC).isoformat(),
                ),
            )
            return True

    # -- verdicts ----------------------------------------------------------

    def record_verdict(self, finding_id: str, verdict: Verdict) -> int:
        """Append a verdict; a later one supersedes it without erasing history.

        Re-recording the verdict that already governs is a no-op returning its
        sequence number, so a repeat cannot reopen an answered finding. A
        different verdict opens a new resolution: its application and reply are
        recorded against it, never inherited from the one it supersedes.
        """
        with self._write() as db:
            self._require_finding(db, finding_id)
            latest = self._latest(db, finding_id)
            if latest is not None and (latest[1].kind, latest[1].evidence, latest[1].verified_by) == (
                verdict.kind, verdict.evidence, verdict.verified_by
            ):
                return latest[0]
            cursor = db.execute(
                "INSERT INTO verdicts(finding_id, kind, evidence, verified_by, verified_at) VALUES (?,?,?,?,?)",
                (finding_id, verdict.kind, verdict.evidence, verdict.verified_by, verdict.verified_at.isoformat()),
            )
            return int(cursor.lastrowid)

    def verdict_history(self, finding_id: str) -> tuple[Verdict, ...]:
        """Return every verdict for a finding, oldest first."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT kind, evidence, verified_by, verified_at FROM verdicts WHERE finding_id = ? ORDER BY seq",
                (finding_id,),
            ).fetchall()
        return tuple(self._verdict(row) for row in rows)

    # -- application and reply --------------------------------------------

    def mark_applied(self, finding_id: str, commit_sha: str) -> None:
        """Record the commit that fixed a finding; requires a current 'valid' verdict."""
        if not is_commit_sha(commit_sha):
            raise LedgerRefusal("commit_sha must be a lower-case abbreviated or full SHA")
        with self._write() as db:
            self._require_finding(db, finding_id)
            latest = self._latest(db, finding_id)
            if latest is None or latest[1].kind != "valid":
                raise LedgerRefusal("a finding is applied only after a 'valid' verdict from the current code")
            seq = latest[0]
            row = db.execute(
                "SELECT commit_sha FROM applications WHERE finding_id = ? AND verdict_seq = ?",
                (finding_id, seq),
            ).fetchone()
            if row is not None:
                if row["commit_sha"] != commit_sha:
                    raise LedgerRefusal("finding is already applied in a different commit")
                return
            db.execute(
                "INSERT INTO applications VALUES (?,?,?,?)",
                (finding_id, seq, commit_sha, datetime.now(UTC).isoformat()),
            )

    def record_reply(self, finding_id: str, reference: str, commit_sha: str | None = None) -> None:
        """Record the reply posted for a finding, tied to where it was resolved."""
        if not reference.strip() or len(reference) > 300:
            raise LedgerRefusal("reply reference is required and must be short")
        if commit_sha is not None and not is_commit_sha(commit_sha):
            raise LedgerRefusal("commit_sha must be a lower-case abbreviated or full SHA")
        with self._write() as db:
            self._require_finding(db, finding_id)
            latest = self._latest(db, finding_id)
            if latest is None:
                raise LedgerRefusal("a reply needs a verdict first")
            seq, verdict = latest
            applied = db.execute(
                "SELECT commit_sha FROM applications WHERE finding_id = ? AND verdict_seq = ?",
                (finding_id, seq),
            ).fetchone()
            if verdict.kind == "valid":
                if applied is None:
                    raise LedgerRefusal("a 'valid' finding must be applied before it is answered")
                if commit_sha is not None and commit_sha != applied["commit_sha"]:
                    raise LedgerRefusal("reply commit must be the commit that applied the finding")
                commit_sha = applied["commit_sha"]
            elif verdict.kind == "already_fixed" and commit_sha is None:
                raise LedgerRefusal("an 'already_fixed' reply must name the commit that fixed it")
            elif verdict.kind == "needs_decision":
                raise LedgerRefusal("a finding that needs a decision cannot be answered yet")
            existing = db.execute(
                "SELECT reference FROM replies WHERE finding_id = ? AND verdict_seq = ?",
                (finding_id, seq),
            ).fetchone()
            if existing is not None:
                if existing["reference"] != reference:
                    raise LedgerRefusal("finding already has a different reply")
                return
            db.execute(
                "INSERT INTO replies VALUES (?,?,?,?,?)",
                (finding_id, seq, reference, commit_sha, datetime.now(UTC).isoformat()),
            )

    # -- reads -------------------------------------------------------------

    def trace(self, finding_id: str) -> LedgerEntry:
        """Return the finding -> verdict -> commit -> reply trace for the current verdict.

        All reads share one transaction, so the records describe a single moment.
        Applications and replies belong to the verdict they resolved: after a
        verdict is superseded they read as absent until the new one is resolved.
        """
        with self._snapshot() as db:
            row = db.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
            if row is None:
                raise LedgerRefusal("unknown finding")
            latest = self._latest(db, finding_id)
            seq = None if latest is None else latest[0]
            applied = db.execute(
                "SELECT commit_sha FROM applications WHERE finding_id = ? AND verdict_seq IS ?",
                (finding_id, seq),
            ).fetchone()
            reply = db.execute(
                "SELECT reference, commit_sha FROM replies WHERE finding_id = ? AND verdict_seq IS ?",
                (finding_id, seq),
            ).fetchone()
        return LedgerEntry(
            finding=self._finding(row),
            verdict=None if latest is None else latest[1],
            applied_in=None if applied is None else applied["commit_sha"],
            replied_with=None if reply is None else reply["reference"],
            reply_commit=None if reply is None else reply["commit_sha"],
        )

    def pending(self) -> tuple[str, ...]:
        """Return finding ids whose current verdict lacks a reply, oldest first.

        A finding with no verdict, or whose latest verdict has not been answered
        (including one that superseded an answered verdict), is pending.
        """
        with self._snapshot() as db:
            rows = db.execute(
                "SELECT f.finding_id FROM findings f WHERE NOT EXISTS ("
                "SELECT 1 FROM replies r WHERE r.finding_id = f.finding_id AND r.verdict_seq = "
                "(SELECT MAX(seq) FROM verdicts v WHERE v.finding_id = f.finding_id)) "
                "ORDER BY f.ingested_at, f.finding_id"
            ).fetchall()
        return tuple(row["finding_id"] for row in rows)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _require_finding(db: sqlite3.Connection, finding_id: str) -> None:
        """Refuse an operation on a finding that was never ingested."""
        if db.execute("SELECT 1 FROM findings WHERE finding_id = ?", (finding_id,)).fetchone() is None:
            raise LedgerRefusal("unknown finding")

    @staticmethod
    def _verdict(row: sqlite3.Row) -> Verdict:
        """Rebuild a verdict from a stored row."""
        return Verdict(
            kind=row["kind"],
            evidence=row["evidence"],
            verified_by=row["verified_by"],
            verified_at=datetime.fromisoformat(row["verified_at"]),
        )

    def _latest(self, db: sqlite3.Connection, finding_id: str) -> tuple[int, Verdict] | None:
        """Return the governing verdict with its sequence number, or None."""
        row = db.execute(
            "SELECT seq, kind, evidence, verified_by, verified_at FROM verdicts "
            "WHERE finding_id = ? ORDER BY seq DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        return None if row is None else (int(row["seq"]), self._verdict(row))

    @staticmethod
    def _finding(row: sqlite3.Row) -> ReviewFinding:
        """Rebuild a finding from a stored row."""
        return ReviewFinding(
            finding_id=row["finding_id"],
            source=row["source"],
            location=FindingLocation(path=row["path"], line=row["line"]),
            claim=row["claim"],
            severity=row["severity"],
            suggested_change=row["suggested_change"],
            embedded_instructions=tuple(json.loads(row["instructions_json"])),
        )
