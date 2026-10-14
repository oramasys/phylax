"""Durable issuer registry, grant index, revocations, and P5 audit records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import math
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

from .sqlite_wal import enable_wal

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
        """Open one configured connection with row access and enforced foreign keys."""
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
            enable_wal(connection, timeout=self._timeout)
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
        """Insert the first key into an empty registry, or refuse.

        Strictly insert-only: it never adopts an existing row, even an identical
        one. Reconciling a provisioned key with durable state, including a rival
        worker's concurrent first commit, is ``ensure_active_key``'s single policy.
        """
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM issuer_keys LIMIT 1").fetchone() is not None:
                connection.rollback()
                raise ValueError("issuer key registry is already initialized")
            self._insert_key(connection, record)
            connection.commit()

    def ensure_active_key(self, record: IssuerKeyRecord) -> None:
        """Atomically initialize the registry or confirm the durable active key matches.

        The empty-registry decision and the insert share one write transaction, so a
        worker that raced another worker to first-key initialization adopts the
        committed key instead of refusing it. A registry that is nonempty but has no
        active key, or whose active key differs, is still rejected.

        This runs on every start, not only the first. Identity (key id, public key,
        seed reference) is therefore the whole gate: recording a grant legitimately
        sets ``latest_live_expiry`` on the active key, so demanding a pristine row
        would refuse to restart a service that has issued anything. ``one_active_
        issuer_key`` guarantees a single active row, and only retired keys carry
        ``retired_at`` or ``retain_until``.
        """
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT * FROM issuer_keys WHERE status = 'active'"
            ).fetchone()
            if active is not None:
                existing = self._key_record(active)
                connection.rollback()
                if (
                    existing.key_id != record.key_id
                    or existing.public_key != record.public_key
                    or existing.seed_ref != record.seed_ref
                ):
                    raise ValueError("provisioned issuer key does not match the durable active key")
                return
            if connection.execute("SELECT 1 FROM issuer_keys LIMIT 1").fetchone() is not None:
                connection.rollback()
                raise ValueError("issuer key registry has no active key")
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
        """Insert one issuer key record on an already-open write transaction."""
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


def _open_regular_files() -> dict[int, os.stat_result] | None:
    """Return fd -> status for every regular file this process holds, or None if unlistable.

    ``/dev/fd`` exists on Linux and macOS; where it does not, the caller keeps its
    path-based checks and states that the descriptor proof was unavailable.
    """
    try:
        names = os.listdir("/dev/fd")
    except OSError:
        return None
    held: dict[int, os.stat_result] = {}
    for name in names:
        if not name.isdigit():
            continue
        try:
            status = os.fstat(int(name))
        except OSError:
            continue
        if stat.S_ISREG(status.st_mode):
            held[int(name)] = status
    return held


class SqliteGrantVerificationStore:
    """Read grant verification facts from an existing SQLite database only.

    The database is validated and opened once. The validated file is the one the retained
    read-only connection holds: after the single open, the descriptors SQLite acquired are
    compared with the file that was checked (device and inode, owner, private mode), so a
    swap between the check and the open is refused, including a swap that is put back
    before a second path check. No operation reopens the path.

    A path that later stops naming the held file (replaced, linked, loosened) makes every
    read fail closed as unavailable until :meth:`reopen` repeats the full validation. The
    held file is never read through a different path.

    Limits, stated honestly: the descriptor proof needs ``/dev/fd`` (Linux, macOS); where it
    is absent only the path checks apply. If SQLite reuses a descriptor it already held for
    this inode, no new descriptor appears and the open is refused rather than assumed safe;
    :meth:`reopen` retries. Sidecars are proven only to be private regular files owned by
    this user, not tied to a path. The checks remain sound only for a state directory that
    is private to one user.
    """

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        """Validate the database, open it once read-only, and retain the connection."""
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout
        self._lock = threading.RLock()
        self._connection_handle: sqlite3.Connection | None = None
        self.path = Path(path)
        self._open_validated(Path(path))

    @staticmethod
    def _check_private_regular(status: os.stat_result, *, what: str) -> None:
        """Refuse anything but a private regular file owned by the effective user."""
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise ValueError(f"{what} must be a regular file")
        if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o077:
            raise PermissionError(f"{what} is not private to the current user")

    def _open_validated(self, raw_path: Path) -> None:
        """Validate on the held object, open once, prove the open took the validated file."""
        try:
            status = raw_path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError("grant authority database does not exist") from None
        self._check_private_regular(status, what="grant authority database")
        resolved = raw_path.resolve(strict=True)
        # Validate the object itself: the descriptor, not the path, is what is inspected.
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            held = os.fstat(descriptor)
            self._check_private_regular(held, what="grant authority database")
            if (held.st_dev, held.st_ino) != (status.st_dev, status.st_ino):
                raise PermissionError("grant authority database changed during validation")
            identity = (held.st_dev, held.st_ino)
            before = _open_regular_files()
            connection = sqlite3.connect(
                resolved.as_uri() + "?mode=ro",
                uri=True,
                timeout=self._timeout,
                isolation_level=None,
                check_same_thread=False,
            )
            try:
                self._prove_open(connection, identity, before)
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                connection.execute("PRAGMA foreign_keys = ON")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version > 1:
                    raise RuntimeError(
                        "grant authority store schema is newer than this Phylax build"
                    )
                SqliteGrantAuthorityStore._validate_schema(connection, require_all=True)
            except BaseException:
                connection.close()
                raise
        finally:
            os.close(descriptor)
        self.path = resolved
        self._identity = identity
        self._connection_handle = connection

    @staticmethod
    def _prove_open(
        connection: sqlite3.Connection,
        identity: tuple[int, int],
        before: dict[int, os.stat_result] | None,
    ) -> None:
        """Refuse unless the descriptors SQLite just opened include the validated file."""
        connection.execute("PRAGMA user_version").fetchone()  # force the file to open
        after = _open_regular_files()
        if before is None or after is None:
            return
        opened = [status for fd, status in after.items() if fd not in before]
        if not any((s.st_dev, s.st_ino) == identity for s in opened):
            raise PermissionError(
                "grant authority database opened by SQLite is not the file that was validated"
            )
        for status in opened:
            if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o077:
                raise PermissionError("a file opened by SQLite is not private to the current user")

    def _assert_database_identity(self) -> None:
        """Fail closed when the path no longer names the file this store holds."""
        try:
            status = self.path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError("grant authority database does not exist") from None
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            # An OSError subtype: a path that changed after open is a verifier fault
            # (verifier.unavailable), not evidence that the presented grant is malformed.
            raise PermissionError("grant authority database must be a regular file")
        if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) & 0o077:
            raise PermissionError("grant authority database is not private to the current user")
        if (status.st_dev, status.st_ino) != self._identity:
            raise PermissionError("grant authority database was replaced after validation")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Yield the retained read-only connection after confirming the path still matches."""
        with self._lock:
            connection = self._connection_handle
            if connection is None:
                raise sqlite3.ProgrammingError("grant verification store is closed")
            self._assert_database_identity()
            yield connection

    def close(self) -> None:
        """Release the retained connection; every later read fails closed."""
        with self._lock:
            connection, self._connection_handle = self._connection_handle, None
        if connection is not None:
            connection.close()

    def reopen(self) -> None:
        """Repeat the full validation and open; on failure the store stays closed."""
        with self._lock:
            path = self.path
            self.close()
            self._open_validated(path)

    def key(self, key_id: str) -> IssuerKeyRecord | None:
        """Read public key metadata for the exact issuer key identifier."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM issuer_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        return None if row is None else SqliteGrantAuthorityStore._key_record(row)

    def is_issued(self, grant_id: str, payload_digest: str, wire: bytes) -> bool:
        """Require an exact durable issuance record without mutating the database."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload_digest,grant_wire FROM issued_grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
        return row is not None and row["payload_digest"] == payload_digest and bytes(row["grant_wire"]) == wire

    def is_revoked(self, grant_id: str) -> bool:
        """Read current durable revocation state; SQLite errors fail closed upstream."""
        with self._connection() as connection:
            return connection.execute(
                "SELECT 1 FROM grant_revocations WHERE grant_id = ?", (grant_id,)
            ).fetchone() is not None
