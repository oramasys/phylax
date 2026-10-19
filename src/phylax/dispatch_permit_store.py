"""Durable issuer-side store for E1 C2 dispatch permits, finalizations and the event chain.

Behaviour is fixed by ``docs/e1-c2-permit-contract-freeze.md``; every encoding, digest and
signature comes from :mod:`phylax.dispatch_wire`. Every write runs inside ``BEGIN IMMEDIATE``.
"""

from __future__ import annotations

import json
import math
import secrets
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol

from . import dispatch_wire as wire
from .sqlite_wal import enable_wal

_SCHEMA_VERSION = 1
_COLUMNS = (
    "row_id", "permit_id", "grant_id", "attempt_id", "state", "binding_digest", "ledger_store_id",
    "reservation_id", "request_digest", "r_p", "consumer_acked_through", "requested_at", "issued_at",
    "expires_at", "permit_bytes", "payload_digest", "issuer_key_id", "finalization_id",
    "finalization_bytes", "finalization_digest", "replaces_permit_id", "abort_disposition",
)
_EVENT_COLUMNS = (
    "version", "kind", "body", "previous_event_digest", "event_digest", "issuer_key_id", "signature",
)
_ATTESTATION_COLUMNS = (
    "permit_id", "attempt_id", "attestation_digest", "attestation", "disposition_ref", "recorded_at",
)
_INDEXES = ("one_original_permit_per_grant", "one_nonterminal_permit_per_grant")
_LIFETIME = timedelta(seconds=wire.PERMIT_LIFETIME_SECONDS)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dispatch_permits (
    row_id INTEGER PRIMARY KEY,
    permit_id TEXT UNIQUE,
    grant_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('issued', 'finalized', 'abandoned', 'aborted')),
    binding_digest TEXT,
    ledger_store_id TEXT,
    reservation_id TEXT,
    request_digest TEXT,
    r_p INTEGER,
    consumer_acked_through INTEGER,
    requested_at TEXT,
    issued_at TEXT,
    expires_at TEXT,
    permit_bytes BLOB,
    payload_digest TEXT,
    issuer_key_id TEXT,
    finalization_id TEXT,
    finalization_bytes BLOB,
    finalization_digest TEXT,
    replaces_permit_id TEXT UNIQUE REFERENCES dispatch_permits(permit_id),
    abort_disposition TEXT,
    CHECK(state != 'aborted' OR (permit_bytes IS NULL AND permit_id IS NULL)),
    CHECK(state = 'aborted' OR (permit_bytes IS NOT NULL AND permit_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS one_original_permit_per_grant
    ON dispatch_permits(grant_id) WHERE replaces_permit_id IS NULL AND state != 'aborted';
CREATE UNIQUE INDEX IF NOT EXISTS one_nonterminal_permit_per_grant
    ON dispatch_permits(grant_id) WHERE state IN ('issued', 'finalized');
CREATE TABLE IF NOT EXISTS abandon_attestations (
    permit_id TEXT PRIMARY KEY REFERENCES dispatch_permits(permit_id),
    attempt_id TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    attestation TEXT NOT NULL,
    disposition_ref TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issuer_events (
    version INTEGER PRIMARY KEY CHECK(version >= 1),
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    previous_event_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    issuer_key_id TEXT NOT NULL,
    signature TEXT NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class GrantFacts:
    """Signed-grant facts the issuer checks a permit request against."""

    payload_digest: str
    operation_id: str
    request_digest: str
    ledger_store_id: str
    expires_at: datetime
    revoked: bool
    cascade_pending: bool


class SignedGrantLookup(Protocol):
    """Injected port that resolves a grant id to its current signed facts."""

    def get(self, grant_id: str) -> GrantFacts | None:
        """Return the facts for ``grant_id`` or None when it is unknown."""


class IssuerSigner(Protocol):
    """Injected port holding the signing material; the store never sees a seed."""

    def active_key_id(self) -> str:
        """Return the identifier of the active signing key."""

    def sign_permit(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign a permit body under ``key_id``."""

    def sign_finalization(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign a finalization body under ``key_id``."""

    def sign_event(self, key_id: str, digest: str) -> str:
        """Sign an event digest under ``key_id``."""


class PermitRefused(Exception):
    """A closed-vocabulary issuer refusal carrying its frozen ``code``."""

    def __init__(self, code: str) -> None:
        """Record the refusal code, which must belong to the frozen vocabulary."""
        if code not in wire.REFUSAL_CODES:
            raise ValueError(f"unknown refusal code: {code}")
        super().__init__(code)
        self.code = code


class OperatorAuthority(Protocol):
    """Injected port that authenticates the operator acting for the authorized consumer scope."""

    def authorize(self, operation: str, *, attempt_id: str, grant_id: str | None) -> str | None:
        """Return a non-blank operator disposition reference, or None when not authorized.

        ``operation`` is ``lookup``, ``abort`` or ``abandon``. A lookup only inspects and can
        never authorize a release; an abort or abandon is a recorded, operator-owned decision.
        """


class OperatorRefused(Exception):
    """The operator port did not authorize the call; nothing was read or written."""


class AbandonRefused(Exception):
    """A closed-vocabulary abandon refusal carrying its frozen ``code``."""

    def __init__(self, code: str) -> None:
        """Record the refusal code, which must belong to the abandon vocabulary."""
        if code not in wire.ABANDON_REFUSAL_CODES:
            raise ValueError(f"unknown abandon refusal code: {code}")
        super().__init__(code)
        self.code = code


def _operator_ref(
    operator: OperatorAuthority, operation: str, *, attempt_id: str, grant_id: str | None
) -> str:
    """Return the operator disposition reference or refuse before touching the database."""
    reference = operator.authorize(operation, attempt_id=attempt_id, grant_id=grant_id)
    if not isinstance(reference, str) or not reference.strip():
        raise OperatorRefused(f"operator is not authorized to {operation}")
    return reference


def _normalize_sql(sql: str) -> str:
    """Collapse whitespace so equivalent DDL text compares equal."""
    return " ".join(sql.split())


_EXPECTED_SQL: dict[str, str] = {}


def _expected_sql() -> dict[str, str]:
    """Return the DDL SQLite stores for the frozen schema, by object name (built once)."""
    if not _EXPECTED_SQL:
        memory = sqlite3.connect(":memory:")
        try:
            memory.executescript(_SCHEMA)
            for name, sql in memory.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL"):
                _EXPECTED_SQL[name] = _normalize_sql(sql)
        finally:
            memory.close()
    return _EXPECTED_SQL


class SqliteDispatchPermitStore:
    """File-backed issuer state for dispatch permits, finalizations and the event chain."""

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        """Open a durable database and create or validate the schema."""
        raw_path = str(path)
        if raw_path == ":memory:" or "mode=memory" in raw_path:
            raise ValueError("dispatch permit store requires a durable file path")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._initialize()

    def close(self) -> None:
        """Release the store; connections are per operation, so nothing is held open."""

    def _connect(self) -> sqlite3.Connection:
        """Open one configured connection with row access and enforced foreign keys."""
        connection = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Close each short-lived connection after its operation, rolling back on error."""
        connection = self._connect()
        try:
            yield connection
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """Run one write transaction under BEGIN IMMEDIATE and commit on success."""
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()

    def _initialize(self) -> None:
        """Create the schema once; repeated construction is safe, incompatible files refused."""
        with self._connection() as connection:
            enable_wal(connection, timeout=self._timeout)
            if connection.execute("PRAGMA user_version").fetchone()[0] > _SCHEMA_VERSION:
                raise RuntimeError("dispatch permit store schema is newer than this Phylax build")
            self._validate_schema(connection, require_all=False)
            connection.executescript(_SCHEMA)
            self._validate_schema(connection, require_all=True)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection, *, require_all: bool) -> None:
        """Reject incompatible pre-existing tables or indexes instead of blessing them."""
        stored = {
            row["name"]: _normalize_sql(row["sql"]) for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
        }
        for name, sql in _expected_sql().items():
            if name in stored and stored[name] != sql:
                raise RuntimeError("dispatch permit store schema is incompatible")
            if name not in stored and require_all:
                raise RuntimeError("dispatch permit store schema is incompatible")
        expected = {
            "dispatch_permits": _COLUMNS, "issuer_events": _EVENT_COLUMNS,
            "abandon_attestations": _ATTESTATION_COLUMNS,
        }
        existing = {
            row["name"] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','index')"
            ).fetchall()
        }
        for table, columns in expected.items():
            if table not in existing and not require_all:
                continue
            actual = tuple(r["name"] for r in connection.execute(f"PRAGMA table_info({table})"))
            if actual != columns:
                raise RuntimeError("dispatch permit store schema is incompatible")
        if require_all and not set(_INDEXES) <= existing:
            raise RuntimeError("dispatch permit store schema is incompatible")

    @staticmethod
    def _counter(connection: sqlite3.Connection) -> int:
        """Return the current maximum event version, the issuer counter."""
        return int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM issuer_events").fetchone()[0])

    def current_counter(self) -> int:
        """Return the issuer's revocation counter (read-only)."""
        with self._connection() as connection:
            return self._counter(connection)

    def lookup_attempt(
        self, attempt_id: str, *, operator: OperatorAuthority
    ) -> dict[str, object] | None:
        """Return the stored row for an attempt id, or None (read-only, operator-authenticated).

        Inspection only: nothing returned here ever authorizes a release or an abandon.
        """
        _operator_ref(operator, "lookup", attempt_id=attempt_id, grant_id=None)
        with self._connection() as connection:
            row = self._row_by_attempt(connection, attempt_id)
        return None if row is None else dict(row)

    def events(self, from_version: int, through_version: int) -> list[dict[str, object]]:
        """Return event wire dicts for the inclusive version range (read-only)."""
        with self._connection() as connection:
            return self._events(connection, from_version, through_version)

    @staticmethod
    def _events(connection: sqlite3.Connection, low: int, high: int) -> list[dict[str, object]]:
        """Read event wire dicts for the inclusive range on an open connection."""
        rows = connection.execute(
            "SELECT * FROM issuer_events WHERE version BETWEEN ? AND ? ORDER BY version", (low, high)
        ).fetchall()
        return [
            {
                "version": r["version"], "kind": r["kind"], "body": json.loads(r["body"]),
                "previous_event_digest": r["previous_event_digest"],
                "event_digest": r["event_digest"], "issuer_key_id": r["issuer_key_id"],
                "signature": r["signature"],
            }
            for r in rows
        ]

    @staticmethod
    def _row_by_attempt(connection: sqlite3.Connection, attempt_id: object) -> sqlite3.Row | None:
        """Fetch the row holding an attempt id."""
        return connection.execute(
            "SELECT * FROM dispatch_permits WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()

    def admit(
        self,
        request: Mapping[str, object],
        *,
        grants: SignedGrantLookup,
        signer: IssuerSigner,
        now: datetime,
    ) -> bytes:
        """Admit a permit request once, returning the permit wire bytes or refusing."""
        try:
            wire.validate_fields(request, wire.PERMIT_REQUEST_FIELDS)
        except wire.WireError:
            raise PermitRefused("permit.invalid_request") from None
        with self._write() as connection:
            stored, replaces = self._admit_existing(connection, request)
            if stored is not None:
                return stored
            facts = self._check_grant(request, grants, now)
            counter = self._counter(connection)
            if counter < request["consumer_acked_through"]:
                raise PermitRefused("permit.issuer_rolled_back")
            return self._issue(connection, request, facts, signer, now, counter, replaces)

    def _admit_existing(
        self, connection: sqlite3.Connection, request: Mapping[str, object]
    ) -> tuple[bytes | None, str | None]:
        """Resolve an attempt row or grant state: (stored bytes, None), or (None, predecessor).

        The predecessor is the grant's ``abandoned`` permit with no successor, which makes the
        request a successor request; it is None for a first issuance.
        """
        row = self._row_by_attempt(connection, request["attempt_id"])
        if row is not None:
            if row["state"] == "aborted":
                raise PermitRefused("permit.attempt_aborted")
            if wire.binding_digest(request) != row["binding_digest"]:
                raise PermitRefused("permit.conflict")
            if self._counter(connection) < request["consumer_acked_through"]:
                raise PermitRefused("permit.issuer_rolled_back")
            return bytes(row["permit_bytes"]), None
        latest = connection.execute(
            "SELECT permit_id, state FROM dispatch_permits WHERE grant_id = ? AND state != 'aborted'"
            " ORDER BY row_id DESC LIMIT 1",
            (request["grant_id"],),
        ).fetchone()
        if latest is None:
            return None, None
        if latest["state"] != "abandoned":
            raise PermitRefused("permit.conflict")
        return None, str(latest["permit_id"])

    @staticmethod
    def _check_grant(
        request: Mapping[str, object], grants: SignedGrantLookup, now: datetime,
    ) -> GrantFacts:
        """Refuse unless the signed grant matches the request and is live; return its facts."""
        facts = grants.get(request["grant_id"])
        if (
            facts is None
            or facts.payload_digest != request["grant_payload_digest"]
            or facts.operation_id != request["operation_id"]
            or facts.request_digest != request["request_digest"]
            or facts.ledger_store_id != request["ledger_store_id"]
        ):
            raise PermitRefused("permit.grant_mismatch")
        if facts.revoked or facts.cascade_pending:
            raise PermitRefused("permit.grant_revoked")
        if facts.expires_at <= now:
            raise PermitRefused("permit.grant_expired")
        return facts

    def _issue(
        self, connection: sqlite3.Connection, request: Mapping[str, object],
        facts: GrantFacts, signer: IssuerSigner, now: datetime, counter: int,
        replaces: str | None = None,
    ) -> bytes:
        """Build, sign and persist a new permit; return its wire bytes."""
        key_id = signer.active_key_id()
        expires = min(now + _LIFETIME, facts.expires_at)
        body = {
            "schema_version": wire.SCHEMA_VERSION,
            **{name: request[name] for name in wire.PERMIT_REQUEST_FIELDS},
            "permit_id": "permit-" + secrets.token_hex(16),
            "revocation_version": counter,
            "issuer_authority_version": wire.ISSUER_AUTHORITY_VERSION,
            "issued_at": wire.timestamp(now),
            "expires_at": wire.timestamp(expires),
            "issuer_key_id": key_id,
        }
        signature = signer.sign_permit(key_id, body)
        permit_bytes = wire.permit_wire_bytes(body, signature)
        connection.execute(
            "INSERT INTO dispatch_permits(permit_id, grant_id, attempt_id, state, binding_digest,"
            " ledger_store_id, reservation_id, request_digest, r_p, consumer_acked_through,"
            " requested_at, issued_at, expires_at, permit_bytes, payload_digest, issuer_key_id,"
            " replaces_permit_id) VALUES(?,?,?,'issued',?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                body["permit_id"], request["grant_id"], request["attempt_id"],
                wire.binding_digest(request), request["ledger_store_id"], request["reservation_id"],
                request["request_digest"], counter, request["consumer_acked_through"],
                request["requested_at"], body["issued_at"], body["expires_at"], permit_bytes,
                wire.permit_payload_digest(body), key_id, replaces,
            ),
        )
        return permit_bytes

    def finalize(
        self,
        request: Mapping[str, object],
        *,
        grants: SignedGrantLookup,
        signer: IssuerSigner,
        now: datetime,
        catchup_max: int = wire.CATCHUP_MAX_EVENTS,
    ) -> tuple[bytes, dict[str, object]]:
        """Finalize a permit once, returning the finalization bytes and a catch-up envelope."""
        try:
            wire.validate_fields(request, wire.FINALIZATION_REQUEST_FIELDS)
        except wire.WireError:
            raise PermitRefused("finalization.invalid_request") from None
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM dispatch_permits WHERE permit_id = ?", (request["permit_id"],)
            ).fetchone()
            if row is None or row["state"] not in ("issued", "finalized"):
                raise PermitRefused("finalization.permit_unusable")
            permit = json.loads(bytes(row["permit_bytes"]))
            self._check_finalization_binding(request, row, permit)
            acked = request["consumer_acked_through"]
            counter = self._counter(connection)
            if row["state"] == "finalized":
                return self._finalize_retry(connection, request, row, now, counter, catchup_max)
            if now >= wire.parse_timestamp(row["expires_at"]):
                raise PermitRefused("finalization.permit_unusable")
            if row["issuer_key_id"] != signer.active_key_id():
                raise PermitRefused("finalization.key_rotated")
            facts = grants.get(row["grant_id"])
            if facts is None or facts.revoked or facts.cascade_pending:
                raise PermitRefused("finalization.grant_revoked")
            if counter < acked or counter < row["r_p"]:
                raise PermitRefused("finalization.issuer_rolled_back")
            if counter + 1 - acked > catchup_max:
                raise PermitRefused("finalization.catchup_required")
            return self._append_finalization(connection, request, row, permit, signer, now, counter)

    @staticmethod
    def _check_finalization_binding(
        request: Mapping[str, object], row: sqlite3.Row, permit: Mapping[str, object]
    ) -> None:
        """Refuse a request whose binding values differ from the stored permit."""
        if (
            request["attempt_id"] != row["attempt_id"]
            or request["reservation_id"] != row["reservation_id"]
            or request["ledger_store_id"] != row["ledger_store_id"]
            or request["authority_epoch"] != permit["authority_epoch"]
            or request["permit_digest"] != row["payload_digest"]
        ):
            raise PermitRefused("finalization.conflict")

    def _finalize_retry(
        self, connection: sqlite3.Connection, request: Mapping[str, object], row: sqlite3.Row,
        now: datetime, counter: int, catchup_max: int,
    ) -> tuple[bytes, dict[str, object]]:
        """Return the stored finalization unchanged with a fresh envelope; sign and append nothing."""
        stored = bytes(row["finalization_bytes"])
        body = json.loads(stored)
        if now >= wire.parse_timestamp(body["expires_at"]):
            raise PermitRefused("finalization.permit_unusable")
        acked = request["consumer_acked_through"]
        if counter < acked or counter < row["r_p"]:
            raise PermitRefused("finalization.issuer_rolled_back")
        r_f = body["revocation_version"]
        if r_f - acked > catchup_max:
            raise PermitRefused("finalization.catchup_required")
        return stored, self._envelope(connection, acked, r_f)

    def _envelope(self, connection: sqlite3.Connection, acked: int, through: int) -> dict[str, object]:
        """Build the unsigned catch-up envelope for versions acked+1 through ``through``."""
        return {
            "events": self._events(connection, acked + 1, through),
            "from_version": acked + 1,
            "through_version": through,
        }

    def _append_finalization(
        self, connection: sqlite3.Connection, request: Mapping[str, object], row: sqlite3.Row,
        permit: Mapping[str, object], signer: IssuerSigner, now: datetime, counter: int,
    ) -> tuple[bytes, dict[str, object]]:
        """Append the finalization event, sign and store the finalization, and build the envelope."""
        key_id = row["issuer_key_id"]
        r_f = counter + 1
        previous = connection.execute(
            "SELECT event_digest FROM issuer_events WHERE version = ?", (counter,)
        ).fetchone()
        previous_digest = wire.GENESIS_EVENT_DIGEST if previous is None else previous["event_digest"]
        finalization_id = "fin-" + secrets.token_hex(16)
        digest = wire.finalization_event_digest(r_f, finalization_id, previous_digest)
        event_body = {"finalization_id": finalization_id}
        connection.execute(
            "INSERT INTO issuer_events(version, kind, body, previous_event_digest, event_digest,"
            " issuer_key_id, signature) VALUES(?,?,?,?,?,?,?)",
            (
                r_f, "finalization", wire.canonical_bytes(event_body).decode("utf-8"),
                previous_digest, digest, key_id, signer.sign_event(key_id, digest),
            ),
        )
        permit_expiry = wire.parse_timestamp(row["expires_at"])
        body = {
            "schema_version": wire.SCHEMA_VERSION,
            **{name: request[name] for name in wire.FINALIZATION_REQUEST_FIELDS},
            "finalization_id": finalization_id,
            "revocation_version": r_f,
            "revocation_event_digest": digest,
            "issued_at": wire.timestamp(now),
            "expires_at": wire.timestamp(min(permit_expiry, now + _LIFETIME)),
        }
        final_bytes = wire.finalization_wire_bytes(body, signer.sign_finalization(key_id, body))
        connection.execute(
            "UPDATE dispatch_permits SET state='finalized', finalization_id=?, finalization_bytes=?,"
            " finalization_digest=? WHERE row_id=?",
            (finalization_id, final_bytes, wire.finalization_digest(body), row["row_id"]),
        )
        return final_bytes, self._envelope(connection, request["consumer_acked_through"], r_f)

    def abort(
        self, attempt_id: str, grant_id: str, *, operator: OperatorAuthority, now: datetime
    ) -> tuple[str, bytes | None]:
        """Serialize an operator-authenticated abort against admission: exactly one wins."""
        disposition_ref = _operator_ref(operator, "abort", attempt_id=attempt_id, grant_id=grant_id)
        with self._write() as connection:
            row = self._row_by_attempt(connection, attempt_id)
            if row is None:
                connection.execute(
                    "INSERT INTO dispatch_permits(permit_id, grant_id, attempt_id, state,"
                    " requested_at, abort_disposition) VALUES(NULL,?,?,'aborted',?,?)",
                    (grant_id, attempt_id, wire.timestamp(now), disposition_ref),
                )
                return "abort.recorded", None
            if row["state"] == "aborted":
                return "abort.already_aborted", None
            if row["grant_id"] != grant_id:
                raise PermitRefused("permit.conflict")
            return "abort.admission_won", bytes(row["permit_bytes"])

    def abandon(
        self, attestation: Mapping[str, object], *, operator: OperatorAuthority, now: datetime
    ) -> tuple[str, dict[str, object]]:
        """Record an operator-authenticated, attested abandon; an identical retry is idempotent.

        The attestation is stored as audit evidence and is NOT verified: the issuer cannot see
        the consumer's store, and safety does not rest on it (the consumer fences first and
        consumes the grant's single use at step 4.3). The abandon applies only while the permit
        is nonterminal and has no successor; later finalization of it is refused.
        """
        try:
            wire.validate_abandon_attestation(attestation)
        except wire.WireError:
            raise AbandonRefused("abandon.invalid_attestation") from None
        attempt_id = str(attestation["attempt_id"])
        disposition_ref = _operator_ref(operator, "abandon", attempt_id=attempt_id, grant_id=None)
        digest = wire.attestation_digest(attestation)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM dispatch_permits WHERE permit_id = ?", (attestation["permit_id"],)
            ).fetchone()
            if row is None:
                raise AbandonRefused("abandon.permit_unknown")
            if row["attempt_id"] != attempt_id:
                raise AbandonRefused("abandon.attempt_mismatch")
            stored = connection.execute(
                "SELECT * FROM abandon_attestations WHERE permit_id = ?", (row["permit_id"],)
            ).fetchone()
            if row["state"] == "abandoned":
                if stored is not None and stored["attestation_digest"] == digest:
                    return "abandon.already_abandoned", self._abandon_record(stored)
                raise AbandonRefused("abandon.conflict")
            if connection.execute(
                "SELECT 1 FROM dispatch_permits WHERE replaces_permit_id = ?", (row["permit_id"],)
            ).fetchone() is not None:
                raise AbandonRefused("abandon.permit_terminal")
            connection.execute(
                "UPDATE dispatch_permits SET state = 'abandoned' WHERE row_id = ?", (row["row_id"],)
            )
            connection.execute(
                "INSERT INTO abandon_attestations(permit_id, attempt_id, attestation_digest,"
                " attestation, disposition_ref, recorded_at) VALUES(?,?,?,?,?,?)",
                (
                    row["permit_id"], attempt_id, digest,
                    wire.canonical_bytes(dict(attestation)).decode("utf-8"), disposition_ref,
                    wire.timestamp(now),
                ),
            )
            recorded = connection.execute(
                "SELECT * FROM abandon_attestations WHERE permit_id = ?", (row["permit_id"],)
            ).fetchone()
            return "abandon.recorded", self._abandon_record(recorded)

    @staticmethod
    def _abandon_record(row: sqlite3.Row) -> dict[str, object]:
        """Return the recorded abandon outcome as a plain dict."""
        return {
            "permit_id": row["permit_id"], "attempt_id": row["attempt_id"],
            "attestation_digest": row["attestation_digest"],
            "disposition_ref": row["disposition_ref"], "recorded_at": row["recorded_at"],
        }
