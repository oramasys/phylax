"""Durable issuer registry, grant index, revocations, and P5 audit records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import math
import sqlite3
from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from .adjustment_grant import AdjustmentGrant, P5IssuanceAudit


def _stamp(value: datetime) -> str:
    """Encode UTC timestamps in the grant store's lexically sortable form."""
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC-aware")
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond:06d}Z"


def _parse_stamp(value: str | None) -> datetime | None:
    """Decode the store's fixed-width UTC timestamp representation."""
    if value is None:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class IssuerKeyRecord:
    """Public registry metadata; private seed material remains externally held."""

    key_id: str
    public_key: bytes
    seed_ref: str
    status: str
    retired_at: datetime | None
    retain_until: datetime | None
    latest_live_expiry: datetime | None

    def __post_init__(self) -> None:
        """Reject malformed public key metadata before it reaches SQLite."""
        if (
            not isinstance(self.key_id, str)
            or not self.key_id.strip()
            or not isinstance(self.seed_ref, str)
            or not self.seed_ref.strip()
        ):
            raise ValueError("issuer key id and seed reference are required")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("issuer public key must be 32 bytes")
        if self.status not in {"active", "retired", "revoked"}:
            raise ValueError("issuer key status is invalid")
        if self.status == "active" and (self.retired_at is not None or self.retain_until is not None):
            raise ValueError("active issuer key cannot have retirement metadata")
        if self.status != "active" and (self.retired_at is None or self.retain_until is None):
            raise ValueError("retired issuer key requires retention metadata")


class SqliteGrantAuthorityStore:
    """File-backed durable state for the Phylax grant authority."""

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        """Open a durable database and create the idempotent schema."""
        raw_path = str(path)
        if raw_path == ":memory:" or "mode=memory" in raw_path:
            raise ValueError("grant authority store requires a durable file path")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Close each short-lived SQLite connection after its operation."""
        connection = self._connect()
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        """Create durable tables once; repeated construction is safe."""
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise RuntimeError("grant authority store schema is newer than this Phylax build")
            self._validate_schema(connection, require_all=False)
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS issuer_keys (
                    key_id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    seed_ref TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'retired', 'revoked')),
                    retired_at TEXT,
                    retain_until TEXT,
                    latest_live_expiry TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_issuer_key
                    ON issuer_keys(status) WHERE status = 'active';
                CREATE TABLE IF NOT EXISTS issued_grants (
                    grant_id TEXT PRIMARY KEY,
                    key_id TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    grant_wire BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS issued_grants_by_key
                    ON issued_grants(key_id, expires_at);
                CREATE TABLE IF NOT EXISTS grant_revocations (
                    grant_id TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS issuance_audit (
                    grant_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    approval_token_digest TEXT NOT NULL,
                    operator_evidence_digest TEXT NOT NULL,
                    approved_duration_seconds INTEGER NOT NULL,
                    approved_at TEXT NOT NULL
                );
                """
            )
            self._validate_schema(connection, require_all=True)
            connection.execute("PRAGMA user_version = 1")

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection, *, require_all: bool) -> None:
        """Reject incompatible pre-existing tables instead of blessing them."""
        expected = {
            "issuer_keys": (
                "key_id", "public_key", "seed_ref", "status", "retired_at", "retain_until",
                "latest_live_expiry",
            ),
            "issued_grants": ("grant_id", "key_id", "payload_digest", "expires_at", "grant_wire"),
            "grant_revocations": ("grant_id", "revoked_at"),
            "issuance_audit": (
                "grant_id", "approval_id", "approval_token_digest", "operator_evidence_digest",
                "approved_duration_seconds", "approved_at",
            ),
        }
        existing = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table, expected_columns in expected.items():
            if table not in existing and not require_all:
                continue
            actual_columns = tuple(
                row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            if actual_columns != expected_columns:
                raise RuntimeError("grant authority store schema is incompatible")

    def keys(self) -> tuple[IssuerKeyRecord, ...]:
        """Return all durable key metadata without private key material."""
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM issuer_keys ORDER BY key_id").fetchall()
        return tuple(self._key_record(row) for row in rows)

    def key(self, key_id: str) -> IssuerKeyRecord | None:
        """Look up one key by its exact signed identifier."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM issuer_keys WHERE key_id = ?", (key_id,)).fetchone()
        return None if row is None else self._key_record(row)

    def active_key(self) -> IssuerKeyRecord | None:
        """Return the unique active key, if the authority has been provisioned."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM issuer_keys WHERE status = 'active'").fetchone()
        return None if row is None else self._key_record(row)

    def register_initial_key(self, record: IssuerKeyRecord) -> None:
        """Persist the first public key and its external seed reference."""
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM issuer_keys LIMIT 1").fetchone() is not None:
                connection.rollback()
                raise ValueError("issuer key registry is already initialized")
            self._insert_key(connection, record)
            connection.commit()

    def rotate_key(self, record: IssuerKeyRecord, *, now: datetime) -> IssuerKeyRecord:
        """Retire the active key and install a new one in a single transaction."""
        now_text = _stamp(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute("SELECT * FROM issuer_keys WHERE status = 'active'").fetchone()
            if prior is None:
                connection.rollback()
                raise ValueError("issuer key registry has no active key")
            if record.key_id == prior["key_id"] or connection.execute(
                "SELECT 1 FROM issuer_keys WHERE key_id = ?", (record.key_id,)
            ).fetchone() is not None:
                connection.rollback()
                raise ValueError("issuer_key_id already exists")
            live = connection.execute(
                "SELECT MAX(expires_at) FROM issued_grants WHERE key_id = ? AND expires_at >= ?",
                (prior["key_id"], now_text),
            ).fetchone()[0]
            required = now + timedelta(hours=24)
            latest = _parse_stamp(live)
            if latest is not None:
                required = max(required, latest + timedelta(seconds=60))
            prior_retention = _parse_stamp(prior["retain_until"])
            retain_until = max(required, prior_retention or required)
            connection.execute(
                "UPDATE issuer_keys SET status='retired', retired_at=?, retain_until=?, latest_live_expiry=? WHERE key_id=?",
                (now_text, _stamp(retain_until), live, prior["key_id"]),
            )
            self._insert_key(connection, record)
            connection.commit()
        return self.key(prior["key_id"])  # type: ignore[return-value]

    def record_issued(self, grant: AdjustmentGrant, audit: P5IssuanceAudit) -> None:
        """Atomically persist the signed grant, key-retention reference, and digests."""
        key_id = grant.issuer_key_id
        grant_id = grant.grant_id
        expires_at = grant.expires_at
        payload_digest = grant.payload_digest
        wire = grant.to_wire()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            key = connection.execute(
                "SELECT status FROM issuer_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
            # A key retired by a concurrent rotation is still retained, so a grant
            # it signed moments ago remains verifiable; only a revoked or unknown
            # key refuses the record.
            if key is None or key["status"] not in {"active", "retired"}:
                connection.rollback()
                raise ValueError("issuer key is not available")
            connection.execute(
                "INSERT INTO issued_grants(grant_id,key_id,payload_digest,expires_at,grant_wire) VALUES(?,?,?,?,?)",
                (grant_id, key_id, payload_digest, _stamp(expires_at), wire),
            )
            connection.execute(
                "UPDATE issuer_keys SET latest_live_expiry = CASE WHEN latest_live_expiry IS NULL OR latest_live_expiry < ? THEN ? ELSE latest_live_expiry END WHERE key_id = ?",
                (_stamp(expires_at), _stamp(expires_at), key_id),
            )
            if key["status"] == "retired":
                # Retention only ever grows: the live grant must stay verifiable.
                needed = _stamp(expires_at + timedelta(seconds=60))
                connection.execute(
                    "UPDATE issuer_keys SET retain_until = CASE WHEN retain_until IS NULL OR retain_until < ? THEN ? ELSE retain_until END WHERE key_id = ?",
                    (needed, needed, key_id),
                )
            connection.execute(
                "INSERT INTO issuance_audit(grant_id,approval_id,approval_token_digest,operator_evidence_digest,approved_duration_seconds,approved_at) VALUES(?,?,?,?,?,?)",
                (
                    grant_id,
                    audit.approval_id,
                    audit.approval_token_digest,
                    audit.operator_evidence_digest,
                    audit.approved_duration_seconds,
                    _stamp(audit.approved_at),
                ),
            )
            connection.commit()

    def issued_wire(self, grant_id: str) -> bytes | None:
        """Return the exact durably issued wire form for an idempotent lookup."""
        with self._connection() as connection:
            row = connection.execute("SELECT grant_wire FROM issued_grants WHERE grant_id = ?", (grant_id,)).fetchone()
        return None if row is None else bytes(row["grant_wire"])

    def is_issued(self, grant_id: str, payload_digest: str, wire: bytes) -> bool:
        """Require an exact match with the durable issuance record."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload_digest,grant_wire FROM issued_grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        return row is not None and row["payload_digest"] == payload_digest and bytes(row["grant_wire"]) == wire

    def revoke(self, grant_id: str, *, revoked_at: datetime) -> None:
        """Durably revoke an issued grant; repeated revocation is idempotent."""
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM issued_grants WHERE grant_id = ?", (grant_id,)).fetchone() is None:
                connection.rollback()
                raise ValueError("grant_id is not issued by this authority")
            connection.execute(
                "INSERT OR IGNORE INTO grant_revocations(grant_id,revoked_at) VALUES(?,?)",
                (grant_id, _stamp(revoked_at)),
            )
            connection.commit()

    def is_revoked(self, grant_id: str) -> bool:
        """Read durable revocation state; SQLite errors propagate to fail-closed callers."""
        with self._connection() as connection:
            return connection.execute(
                "SELECT 1 FROM grant_revocations WHERE grant_id = ?", (grant_id,)
            ).fetchone() is not None

    def revoke_key(self, key_id: str) -> None:
        """Mark a compromised retired key unusable for verification."""
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT status FROM issuer_keys WHERE key_id = ?", (key_id,)).fetchone()
            if row is None:
                connection.rollback()
                raise ValueError("issuer_key_id is unknown")
            if row["status"] == "active":
                connection.rollback()
                raise ValueError("active issuer key must be rotated before revocation")
            connection.execute("UPDATE issuer_keys SET status='revoked' WHERE key_id = ?", (key_id,))
            connection.commit()

    def issuance_audit(self, grant_id: str) -> dict[str, object] | None:
        """Read the durable digest-only approval audit for one issued grant."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM issuance_audit WHERE grant_id = ?", (grant_id,)).fetchone()
        if row is None:
            return None
        return {
            "grant_id": row["grant_id"],
            "approval_id": row["approval_id"],
            "approval_token_digest": row["approval_token_digest"],
            "operator_evidence_digest": row["operator_evidence_digest"],
            "approved_duration_seconds": row["approved_duration_seconds"],
            "approved_at": _parse_stamp(row["approved_at"]),
        }

    def prune(self, *, now: datetime) -> tuple[str, ...]:
        """Drop expired index references and only then prune safely-retired keys."""
        now_text = _stamp(now)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM issued_grants WHERE expires_at < ?",
                (_stamp(now - timedelta(seconds=60)),),
            )
            rows = connection.execute(
                "SELECT key_id FROM issuer_keys WHERE status='retired' AND retain_until < ?",
                (now_text,),
            ).fetchall()
            removed: list[str] = []
            for row in rows:
                key_id = row["key_id"]
                live = connection.execute(
                    "SELECT 1 FROM issued_grants WHERE key_id = ? LIMIT 1", (key_id,)
                ).fetchone()
                if live is None:
                    connection.execute("DELETE FROM issuer_keys WHERE key_id = ?", (key_id,))
                    removed.append(key_id)
            connection.commit()
        return tuple(removed)

    @staticmethod
    def _insert_key(connection: sqlite3.Connection, record: IssuerKeyRecord) -> None:
        connection.execute(
            "INSERT INTO issuer_keys(key_id,public_key,seed_ref,status,retired_at,retain_until,latest_live_expiry) VALUES(?,?,?,?,?,?,?)",
            (
                record.key_id,
                record.public_key,
                record.seed_ref,
                record.status,
                _stamp(record.retired_at) if record.retired_at else None,
                _stamp(record.retain_until) if record.retain_until else None,
                _stamp(record.latest_live_expiry) if record.latest_live_expiry else None,
            ),
        )

    @staticmethod
    def _key_record(row: sqlite3.Row) -> IssuerKeyRecord:
        """Convert a SQLite row to immutable public registry metadata."""
        return IssuerKeyRecord(
            key_id=row["key_id"],
            public_key=bytes(row["public_key"]),
            seed_ref=row["seed_ref"],
            status=row["status"],
            retired_at=_parse_stamp(row["retired_at"]),
            retain_until=_parse_stamp(row["retain_until"]),
            latest_live_expiry=_parse_stamp(row["latest_live_expiry"]),
        )
