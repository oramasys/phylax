"""Strict, one-time P5 approval evidence for security-sensitive actions.

This module binds an independently attested operator decision to an immutable
intent. It is deliberately not a grant issuer and it does not infer that an
operator is human: callers must obtain ``operator_evidence_ref`` through their
own trusted interaction boundary before they call :meth:`approve`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from threading import Lock
from typing import Callable, Iterator, Protocol

from .sqlite_wal import enable_wal

_DOMAIN = b"phylax-p5-swarm-approval-v1\x00"
_DEFAULT_PREVIEW_TTL = timedelta(minutes=5)
_DEFAULT_HUMAN_DURATION_SECONDS = 5_400
_MAX_ISSUANCE_DURATION_SECONDS = 9_900
_DEFAULT_PREVIEW_RETENTION = timedelta(days=30)


def _utc_timestamp(value: datetime) -> int:
    """Return an integral UTC timestamp, rejecting naive datetimes."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("P5 clock must return an aware UTC datetime")
    return int(value.astimezone(UTC).timestamp())


def _require_positive_int(value: object, name: str) -> int:
    """Return value when it is a positive integer; booleans and floats are rejected."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _canonical_bytes(payload: dict[str, object]) -> bytes:
    """Encode a stable compact JSON representation for token signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64encode(value: bytes) -> str:
    """Encode unpadded base64url text."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    """Decode unpadded base64url text and reject malformed input."""
    try:
        return base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("invalid P5 approval token") from exc


@dataclass(frozen=True, slots=True)
class P5ApprovalIntent:
    """Immutable protected-action preview that needs a fresh operator decision."""

    operator_principal: str
    canonical_preview_json: str
    action: str = "swarm.launch"

    def __post_init__(self) -> None:
        """Reject empty or malformed intent fields before approval is possible."""
        if not self.operator_principal.strip():
            raise ValueError("operator_principal is required")
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("action is required")
        try:
            preview = json.loads(self.canonical_preview_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("canonical swarm preview JSON is required") from exc
        if not isinstance(preview, dict) or _canonical_bytes(preview).decode("utf-8") != self.canonical_preview_json:
            raise ValueError("swarm preview must use canonical JSON")
        required = {"objective", "task_type", "optimize_for", "preferred_device", "assignments"}
        if set(preview) != required or not all(isinstance(preview[key], str) and preview[key].strip() for key in required - {"assignments"}):
            raise ValueError("swarm preview fields are incomplete")
        if not isinstance(preview["assignments"], list):
            raise ValueError("swarm preview assignments must be a list")

    @classmethod
    def from_preview(
        cls,
        operator_principal: str,
        preview: dict[str, object],
        *,
        action: str = "swarm.launch",
    ) -> P5ApprovalIntent:
        """Freeze a caller preview and protected action into canonical intent."""
        return cls(operator_principal, _canonical_bytes(preview).decode("utf-8"), action)

    def preview_digest(self) -> str:
        """Return the digest of every dispatch-relevant swarm preview field."""
        return hashlib.sha256(_canonical_bytes(self.preview_payload())).hexdigest()

    def preview_payload(self) -> dict[str, object]:
        """Return the complete canonical swarm preview retained only in the store."""
        return json.loads(self.canonical_preview_json)

    def claims(self) -> dict[str, str | int]:
        """Return signed envelope claims without exposing the stored preview."""
        return {
            "action": self.action,
            "operator_principal": self.operator_principal,
            "preview_digest": self.preview_digest(),
            "version": 1,
        }


@dataclass(frozen=True, slots=True)
class P5ApprovalPreview:
    """Server-minted preview awaiting a separately attested operator decision."""

    preview_id: str
    intent: P5ApprovalIntent
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class P5ApprovalReceipt:
    """Signed P5 decision evidence consumed exactly once by the local authority."""

    approval_token: str
    preview_id: str
    expires_at: datetime
    approved_duration_seconds: int


@dataclass(frozen=True, slots=True)
class P5ApprovalDecision:
    """Verified operator-decision evidence released after one successful consume."""

    intent: P5ApprovalIntent
    operator_evidence_ref: str
    approved_duration_seconds: int
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class _StoredPreview:
    """Persisted preview plus its approval-token digest and approved duration."""

    preview: P5ApprovalPreview
    approval_token_digest: str | None = None
    approved_duration_seconds: int | None = None
    operator_evidence_ref: str | None = None
    approved_at: datetime | None = None
    consumed: bool = False


class P5ApprovalStore(Protocol):
    """Durable-state boundary for one-time preview approval and consumption."""

    def put(self, preview: P5ApprovalPreview) -> None:
        """Persist a newly issued preview."""

    def get(self, preview_id: str) -> _StoredPreview | None:
        """Return current state for a preview without mutating it."""

    def approve(
        self,
        preview_id: str,
        receipt: P5ApprovalReceipt,
        operator_evidence_ref: str,
        approved_at: datetime,
        *,
        clock: Callable[[], datetime],
    ) -> bool:
        """Persist the first approval for an unexpired preview; clock is read under the store lock."""

    def consume(
        self, preview_id: str, approval_token: str, *, clock: Callable[[], datetime]
    ) -> _StoredPreview | None:
        """Atomically consume an unexpired approved preview; clock is read under the store lock."""

    def purge_expired(self, *, expired_before: datetime) -> int:
        """Delete records whose preview expired before the cutoff and return the count."""


class InMemoryP5ApprovalStore:
    """Thread-safe reference store; production composition must inject durability."""

    def __init__(self) -> None:
        """Initialise an empty approval store."""
        self._records: dict[str, _StoredPreview] = {}
        self._lock = Lock()

    def put(self, preview: P5ApprovalPreview) -> None:
        """Persist a unique preview id."""
        with self._lock:
            if preview.preview_id in self._records:
                raise ValueError("P5 preview_id already exists")
            self._records[preview.preview_id] = _StoredPreview(preview=preview)

    def get(self, preview_id: str) -> _StoredPreview | None:
        """Read preview state under the store lock."""
        with self._lock:
            return self._records.get(preview_id)

    def approve(
        self,
        preview_id: str,
        receipt: P5ApprovalReceipt,
        operator_evidence_ref: str,
        approved_at: datetime,
        *,
        clock: Callable[[], datetime],
    ) -> bool:
        """Persist an approval exactly once unless it was already consumed."""
        with self._lock:
            current = self._records.get(preview_id)
            if current is None or current.approval_token_digest is not None or current.consumed:
                return False
            if _utc_timestamp(clock()) >= _utc_timestamp(current.preview.expires_at):
                raise ValueError("P5 preview expired")
            self._records[preview_id] = _StoredPreview(
                preview=current.preview,
                approval_token_digest=_token_digest(receipt.approval_token),
                approved_duration_seconds=receipt.approved_duration_seconds,
                operator_evidence_ref=operator_evidence_ref,
                approved_at=approved_at,
            )
            return True

    def consume(
        self, preview_id: str, approval_token: str, *, clock: Callable[[], datetime]
    ) -> _StoredPreview | None:
        """Atomically consume a matching approved preview and return its old state."""
        with self._lock:
            current = self._records.get(preview_id)
            if current is None or current.approval_token_digest is None or current.consumed:
                return None
            if _utc_timestamp(clock()) >= _utc_timestamp(current.preview.expires_at):
                raise ValueError("P5 approval expired")
            if not hmac.compare_digest(current.approval_token_digest, _token_digest(approval_token)):
                return None
            self._records[preview_id] = _StoredPreview(
                preview=current.preview,
                approval_token_digest=current.approval_token_digest,
                approved_duration_seconds=current.approved_duration_seconds,
                operator_evidence_ref=current.operator_evidence_ref,
                approved_at=current.approved_at,
                consumed=True,
            )
            return current


    def purge_expired(self, *, expired_before: datetime) -> int:
        """Delete records whose preview expired before the cutoff."""
        cutoff = _utc_timestamp(expired_before)
        with self._lock:
            stale = [
                preview_id
                for preview_id, record in self._records.items()
                if _utc_timestamp(record.preview.expires_at) < cutoff
            ]
            for preview_id in stale:
                del self._records[preview_id]
            return len(stale)


def _token_digest(approval_token: str) -> str:
    """Return a non-reversible lookup value for persisted receipt tokens."""
    return hashlib.sha256(approval_token.encode("utf-8")).hexdigest()


class SqliteP5ApprovalStore:
    """Durable SQLite P5 store with transactional, one-time receipt consumption."""

    def __init__(self, path: str, *, timeout: float = 5.0) -> None:
        """Open or initialise a local SQLite store at the supplied path."""
        if not path.strip():
            raise ValueError("P5 SQLite path is required")
        if path.strip() == ":memory:":
            raise ValueError("P5 SQLite store requires a durable file path; use InMemoryP5ApprovalStore")
        if timeout <= 0:
            raise ValueError("P5 SQLite timeout must be positive")
        self._path = path
        self._connection_timeout = timeout
        try:
            with self._connection() as connection:
                enable_wal(connection, timeout=self._connection_timeout)
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS p5_approvals (
                        preview_id TEXT PRIMARY KEY,
                        intent_json TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        approval_token_digest TEXT,
                        approved_duration_seconds INTEGER,
                        operator_evidence_ref TEXT,
                        approved_at INTEGER
                    )
                    """
                )
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc

    def put(self, preview: P5ApprovalPreview) -> None:
        """Persist a pending preview and reject a colliding server-generated id."""
        intent_json = _canonical_bytes(
            {
                "operator_principal": preview.intent.operator_principal,
                "canonical_preview_json": preview.intent.canonical_preview_json,
                "action": preview.intent.action,
            }
        ).decode("utf-8")
        try:
            with self._connection() as connection:
                connection.execute(
                    "INSERT INTO p5_approvals (preview_id, intent_json, expires_at, state) VALUES (?, ?, ?, 'pending')",
                    (preview.preview_id, intent_json, _utc_timestamp(preview.expires_at)),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("P5 preview_id already exists") from exc
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc

    def get(self, preview_id: str) -> _StoredPreview | None:
        """Load current approval state without changing it."""
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT * FROM p5_approvals WHERE preview_id = ?", (preview_id,)
                ).fetchone()
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc
        return self._from_row(row) if row is not None else None

    def approve(
        self,
        preview_id: str,
        receipt: P5ApprovalReceipt,
        operator_evidence_ref: str,
        approved_at: datetime,
        *,
        clock: Callable[[], datetime],
    ) -> bool:
        """Compare-and-swap pending state into approved state exactly once, unexpired."""
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT expires_at FROM p5_approvals WHERE preview_id = ? AND state = 'pending'",
                    (preview_id,),
                ).fetchone()
                if row is None:
                    connection.rollback()
                    return False
                if _utc_timestamp(clock()) >= int(row[0]):
                    connection.rollback()
                    raise ValueError("P5 preview expired")
                cursor = connection.execute(
                    """
                    UPDATE p5_approvals
                    SET state = 'approved', approval_token_digest = ?, approved_duration_seconds = ?,
                        operator_evidence_ref = ?, approved_at = ?
                    WHERE preview_id = ? AND state = 'pending'
                    """,
                    (
                        _token_digest(receipt.approval_token),
                        receipt.approved_duration_seconds,
                        operator_evidence_ref,
                        _utc_timestamp(approved_at),
                        preview_id,
                    ),
                )
                connection.commit()
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc
        return cursor.rowcount == 1

    def consume(
        self, preview_id: str, approval_token: str, *, clock: Callable[[], datetime]
    ) -> _StoredPreview | None:
        """Atomically consume a matching approved record and return its old state."""
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM p5_approvals WHERE preview_id = ?", (preview_id,)
                ).fetchone()
                if row is None or row[3] != "approved" or not isinstance(row[4], str):
                    connection.rollback()
                    return None
                if _utc_timestamp(clock()) >= int(row[2]):
                    connection.rollback()
                    raise ValueError("P5 approval expired")
                if not hmac.compare_digest(row[4], _token_digest(approval_token)):
                    connection.rollback()
                    return None
                stored = self._from_row(row)
                cursor = connection.execute(
                    "UPDATE p5_approvals SET state = 'consumed' WHERE preview_id = ? AND state = 'approved'",
                    (preview_id,),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc
        return stored

    def purge_expired(self, *, expired_before: datetime) -> int:
        """Delete records whose preview expired before the cutoff and return the count."""
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    "DELETE FROM p5_approvals WHERE expires_at < ?",
                    (_utc_timestamp(expired_before),),
                )
        except sqlite3.OperationalError as exc:
            raise ValueError("P5 store busy or locked") from exc
        return cursor.rowcount

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Yield and always close a connection configured for local writers."""
        connection = sqlite3.connect(self._path, timeout=self._connection_timeout, isolation_level=None)
        try:
            enable_wal(connection, timeout=self._connection_timeout)
            yield connection
        finally:
            connection.close()

    def _from_row(self, row: tuple[object, ...]) -> _StoredPreview:
        """Reconstruct immutable approval state from one validated SQLite row."""
        try:
            intent_data = json.loads(row[1])
            intent = P5ApprovalIntent(
                operator_principal=intent_data["operator_principal"],
                canonical_preview_json=intent_data["canonical_preview_json"],
                action=intent_data.get("action", "swarm.launch"),
            )
            preview = P5ApprovalPreview(
                preview_id=str(row[0]),
                intent=intent,
                expires_at=datetime.fromtimestamp(int(row[2]), UTC),
            )
            return _StoredPreview(
                preview=preview,
                approval_token_digest=str(row[4]) if row[4] is not None else None,
                approved_duration_seconds=int(row[5]) if row[5] is not None else None,
                operator_evidence_ref=str(row[6]) if row[6] is not None else None,
                approved_at=datetime.fromtimestamp(int(row[7]), UTC) if row[7] is not None else None,
                consumed=row[3] == "consumed",
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("stored P5 approval is invalid") from exc


class P5ApprovalAuthority:
    """Strict P5 approval authority with no legacy boolean approval path."""

    def __init__(self, *, signing_key: bytes, store: P5ApprovalStore, clock: Callable[[], datetime] | None = None, preview_ttl: timedelta = _DEFAULT_PREVIEW_TTL, default_human_duration_seconds: int = _DEFAULT_HUMAN_DURATION_SECONDS, max_issuance_duration_seconds: int = _MAX_ISSUANCE_DURATION_SECONDS) -> None:
        """Initialise strict approval policy and validate fixed safety bounds."""
        if not signing_key:
            raise ValueError("P5 signing_key is required")
        if preview_ttl <= timedelta(0):
            raise ValueError("P5 preview_ttl must be positive")
        _require_positive_int(max_issuance_duration_seconds, "P5 issuance ceiling")
        _require_positive_int(default_human_duration_seconds, "P5 default duration")
        if max_issuance_duration_seconds > _MAX_ISSUANCE_DURATION_SECONDS:
            raise ValueError("P5 issuance ceiling must not exceed 9900 seconds; callers may lower it, never raise it")
        if default_human_duration_seconds > max_issuance_duration_seconds:
            raise ValueError("P5 default duration must be within the issuance ceiling")
        self._signing_key = signing_key
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._preview_ttl = preview_ttl
        self._default_duration = default_human_duration_seconds
        self._max_duration = max_issuance_duration_seconds

    def issue_preview(self, intent: P5ApprovalIntent) -> P5ApprovalPreview:
        """Mint and persist a preview; no caller boolean can bypass this step."""
        now = self._now()
        preview = P5ApprovalPreview(token_urlsafe(24), intent, now + self._preview_ttl)
        self._store.put(preview)
        return preview

    def approve(self, preview_id: str, *, operator_evidence_ref: str, approved_duration_seconds: int | None = None) -> P5ApprovalReceipt:
        """Bind trusted operator evidence and P5-selected duration to a preview."""
        if not operator_evidence_ref.strip():
            raise ValueError("operator_evidence_ref is required")
        duration = self._default_duration if approved_duration_seconds is None else approved_duration_seconds
        _require_positive_int(duration, "approved_duration_seconds")
        if duration > self._max_duration:
            raise ValueError(
                "approved_duration_seconds exceeds the P5 issuance ceiling; "
                "a longer-lived decision requires a fresh P5 HITL approval"
            )
        stored = self._require_live_preview(preview_id)
        now = self._now()
        payload = {
            "approved_at": _utc_timestamp(now),
            "approved_duration_seconds": duration,
            "expires_at": _utc_timestamp(stored.preview.expires_at),
            "operator_evidence_digest": hashlib.sha256(operator_evidence_ref.encode("utf-8")).hexdigest(),
            "approval_id": stored.preview.preview_id,
            **stored.preview.intent.claims(),
        }
        body = _canonical_bytes(payload)
        token = f"{_b64encode(body)}.{_b64encode(hmac.new(self._signing_key, _DOMAIN + body, hashlib.sha256).digest())}"
        receipt = P5ApprovalReceipt(token, stored.preview.preview_id, stored.preview.expires_at, duration)
        if not self._store.approve(
            stored.preview.preview_id, receipt, operator_evidence_ref, now, clock=self._now
        ):
            raise ValueError("P5 preview is already approved or consumed")
        return receipt

    def consume(self, receipt: P5ApprovalReceipt, intent: P5ApprovalIntent) -> P5ApprovalDecision:
        """Verify exact canonical claims and consume a receipt once, fail-closed."""
        payload = self._verified_payload(receipt)
        self._validate_claims(payload, receipt, intent)
        stored = self._store.consume(
            receipt.preview_id, receipt.approval_token, clock=self._now
        )
        if stored is None or stored.operator_evidence_ref is None or stored.approved_at is None:
            raise ValueError("P5 approval is unknown, invalid, or already consumed")
        return P5ApprovalDecision(intent, stored.operator_evidence_ref, receipt.approved_duration_seconds, stored.approved_at)

    def purge_expired(self, *, retention: timedelta = _DEFAULT_PREVIEW_RETENTION) -> int:
        """Delete previews that expired more than retention ago; callers schedule this.

        An expired preview can never authorize anything, so dropping it cannot
        weaken replay protection; retention only preserves a diagnostic window.
        """
        if retention < timedelta(0):
            raise ValueError("P5 retention must not be negative")
        return self._store.purge_expired(expired_before=self._now() - retention)

    def _now(self) -> datetime:
        """Return injected time normalized to UTC."""
        now = self._clock()
        _utc_timestamp(now)
        return now.astimezone(UTC)

    def _require_live_preview(self, preview_id: str) -> _StoredPreview:
        """Load an unexpired preview or fail without offering a legacy bypass."""
        stored = self._store.get(preview_id)
        if stored is None:
            raise ValueError("P5 preview is unknown")
        if self._now() >= stored.preview.expires_at:
            raise ValueError("P5 preview expired")
        return stored

    def _verified_payload(self, receipt: P5ApprovalReceipt) -> dict[str, object]:
        """Verify token framing, HMAC, and canonical JSON before parsing claims."""
        try:
            encoded_body, encoded_mac = receipt.approval_token.split(".", 1)
            body = _b64decode(encoded_body)
            supplied_mac = _b64decode(encoded_mac)
        except (AttributeError, ValueError) as exc:
            raise ValueError("invalid P5 approval token") from exc
        expected_mac = hmac.new(self._signing_key, _DOMAIN + body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, supplied_mac):
            raise ValueError("invalid P5 approval token")
        try:
            payload = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid P5 approval token") from exc
        if not isinstance(payload, dict) or _canonical_bytes(payload) != body:
            raise ValueError("invalid P5 approval token")
        return payload

    def _validate_claims(self, payload: dict[str, object], receipt: P5ApprovalReceipt, intent: P5ApprovalIntent) -> None:
        """Ensure a valid token is bound to this receipt, intent, and live expiry."""
        expected = {
            "approved_duration_seconds": receipt.approved_duration_seconds,
            "expires_at": _utc_timestamp(receipt.expires_at),
            "approval_id": receipt.preview_id,
            **intent.claims(),
        }
        for field_name, value in expected.items():
            if payload.get(field_name) != value:
                raise ValueError("P5 approval intent mismatch")
        if not isinstance(payload.get("approved_at"), int) or not isinstance(payload.get("operator_evidence_digest"), str):
            raise ValueError("invalid P5 approval token")
