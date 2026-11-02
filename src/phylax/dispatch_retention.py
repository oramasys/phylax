"""Retained signed checkpoints and bounded hot-store retention for the issuer event chain.

Implements Part 3 amendment sections 3.1 and 3.2 additively: nothing here changes the frozen
``issuer_events`` or ``dispatch_permits`` schema, any wire encoding, or any existing store method.
The contract is ``docs/e1-c2-retention-and-checkpoints.md``.

* An ``issuer_events`` row already is an issuer-signed ``(version, digest)`` checkpoint, so a
  :class:`Checkpoint` is a view over that row and no second signing domain exists.
* :func:`prune` moves rows strictly below the lowest acknowledged version of every registered
  consumer into an append-only :class:`RetentionLedger` archive. It never discards: the archive is
  written and read back before the hot rows are removed, and the boundary row stays hot as the one
  retained anchor.
* A range that neither tier can serve in full is refused, never returned short.
"""

from __future__ import annotations

import fcntl
import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from . import dispatch_wire as wire
from .dispatch_permit_store import (
    OperatorAuthority,
    OperatorRefused,
    SqliteDispatchPermitStore,
)
from .sqlite_wal import enable_wal

_EVENTS_ATTEMPTS = 3
_EVENT_FIELDS = (
    "version", "kind", "body", "previous_event_digest", "event_digest", "issuer_key_id",
    "signature",
)
RETENTION_REFUSAL_CODES = frozenset({
    "retention.malformed_event", "retention.chain_broken", "retention.signature_invalid",
    "retention.unknown_key", "retention.archive_conflict", "retention.archive_gap",
    "retention.no_consumers", "retention.readback_mismatch", "retention.anchor_missing",
    "retention.range_unavailable", "retention.consumer_invalid",
})

_ARCHIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS archived_events (
    version INTEGER PRIMARY KEY CHECK(version >= 1),
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    previous_event_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    issuer_key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    archived_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS archived_revocations_by_body
    ON archived_events(body) WHERE kind = 'revocation';
CREATE TABLE IF NOT EXISTS retention_consumers (
    consumer_id TEXT PRIMARY KEY,
    registered_at TEXT NOT NULL,
    operator_ref TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS prune_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ceiling INTEGER NOT NULL,
    pruned_from INTEGER NOT NULL,
    pruned_through INTEGER NOT NULL,
    operator_ref TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS archived_events_no_update BEFORE UPDATE ON archived_events
BEGIN SELECT RAISE(ABORT, 'archive is append-only'); END;
CREATE TRIGGER IF NOT EXISTS archived_events_no_delete BEFORE DELETE ON archived_events
BEGIN SELECT RAISE(ABORT, 'archive is append-only'); END;
CREATE TRIGGER IF NOT EXISTS retention_consumers_no_update BEFORE UPDATE ON retention_consumers
BEGIN SELECT RAISE(ABORT, 'consumer registry is append-only'); END;
CREATE TRIGGER IF NOT EXISTS retention_consumers_no_delete BEFORE DELETE ON retention_consumers
BEGIN SELECT RAISE(ABORT, 'consumer registry is append-only'); END;
CREATE TRIGGER IF NOT EXISTS prune_log_no_update BEFORE UPDATE ON prune_log
BEGIN SELECT RAISE(ABORT, 'prune log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS prune_log_no_delete BEFORE DELETE ON prune_log
BEGIN SELECT RAISE(ABORT, 'prune log is append-only'); END;
"""


class RetentionRefused(Exception):
    """A closed-vocabulary retention refusal carrying its stable ``code``."""

    def __init__(self, code: str) -> None:
        """Record the refusal code, which must belong to the retention vocabulary."""
        if code not in RETENTION_REFUSAL_CODES:
            raise ValueError(f"unknown retention refusal code: {code}")
        super().__init__(code)
        self.code = code


class IssuerKeyResolver(Protocol):
    """Injected port mapping an issuer key id to its 32-byte public key, or None if unknown."""

    def public_key(self, key_id: str) -> bytes | None:
        """Return the public key for ``key_id`` or None when the key is not a known issuer key."""


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """An issuer-signed ``(version, digest)`` pair taken from an event row (section 3.1)."""

    version: int
    event_digest: str
    issuer_key_id: str
    signature: str

    def to_wire(self) -> dict[str, object]:
        """Return the four-field wire dict of this checkpoint."""
        return {
            "version": self.version, "event_digest": self.event_digest,
            "issuer_key_id": self.issuer_key_id, "signature": self.signature,
        }


def checkpoint_from_event(event: Mapping[str, object]) -> Checkpoint:
    """Return the checkpoint an event row literally is; refuse a malformed row."""
    _require_event_shape(event)
    return Checkpoint(
        int(event["version"]), str(event["event_digest"]), str(event["issuer_key_id"]),
        str(event["signature"]),
    )


def verify_checkpoint(checkpoint: Checkpoint, resolver: IssuerKeyResolver) -> None:
    """Verify the issuer signature over the checkpoint digest or raise :class:`RetentionRefused`.

    This authenticates the *digest only*. The signature does not cover ``version``, so a bare
    checkpoint can never prove which version it belongs to; use
    :func:`verify_checkpoint_against_event` (or :func:`verify_chain`, which recomputes every digest
    from the body) whenever the version matters.
    """
    key = resolver.public_key(checkpoint.issuer_key_id)
    if key is None:
        raise RetentionRefused("retention.unknown_key")
    try:
        valid = wire.verify_event(key, checkpoint.event_digest, checkpoint.signature)
    except wire.WireError as error:
        raise RetentionRefused("retention.signature_invalid") from error
    if not valid:
        raise RetentionRefused("retention.signature_invalid")


def verify_checkpoint_against_event(
    checkpoint: Checkpoint, event: Mapping[str, object], resolver: IssuerKeyResolver
) -> None:
    """Bind ``checkpoint.version`` to the issuer signature by recomputing the digest from ``event``.

    The event digest commits to version, kind, body and the previous digest, so a checkpoint whose
    version, digest or signature differs from the event it claims to summarise is refused.
    """
    _require_event_shape(event)
    version = int(event["version"])  # type: ignore[call-overload]
    try:
        digest = wire.event_digest(
            version, str(event["kind"]), event["body"], str(event["previous_event_digest"])  # type: ignore[arg-type]
        )
    except wire.WireError as error:
        raise RetentionRefused("retention.malformed_event") from error
    if checkpoint.version != version or checkpoint.event_digest != digest or digest != event["event_digest"]:
        raise RetentionRefused("retention.chain_broken")
    verify_checkpoint(checkpoint, resolver)


def _require_event_shape(event: Mapping[str, object]) -> None:
    """Require the exact seven-field event wire shape with a real integer version."""
    if not isinstance(event, Mapping) or set(event) != set(_EVENT_FIELDS):
        raise RetentionRefused("retention.malformed_event")
    version = event["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RetentionRefused("retention.malformed_event")
    if not isinstance(event["body"], Mapping):
        raise RetentionRefused("retention.malformed_event")


def verify_chain(
    events: Sequence[Mapping[str, object]], *, previous_digest: str, resolver: IssuerKeyResolver
) -> str:
    """Verify contiguity, digest links and signatures; return the last event digest.

    ``previous_digest`` is the digest the first event must link to (the genesis digest for
    version 1, or the digest of the event just below the range). Every digest is recomputed from
    the body, never trusted from the row.
    """
    link = previous_digest
    first: int | None = None
    for index, event in enumerate(events):
        _require_event_shape(event)
        version = int(event["version"])  # type: ignore[call-overload]
        first = version if first is None else first
        if version != first + index or event["previous_event_digest"] != link:
            raise RetentionRefused("retention.chain_broken")
        try:
            digest = wire.event_digest(version, str(event["kind"]), event["body"], link)  # type: ignore[arg-type]
        except wire.WireError as error:
            raise RetentionRefused("retention.malformed_event") from error
        if digest != event["event_digest"]:
            raise RetentionRefused("retention.chain_broken")
        verify_checkpoint(checkpoint_from_event(event), resolver)
        link = digest
    return link


def _row_to_event(row: sqlite3.Row) -> dict[str, object]:
    """Return the issuer event wire dict for a stored row."""
    return {
        "version": row["version"], "kind": row["kind"], "body": json.loads(row["body"]),
        "previous_event_digest": row["previous_event_digest"],
        "event_digest": row["event_digest"], "issuer_key_id": row["issuer_key_id"],
        "signature": row["signature"],
    }


def _valid_consumer_id(consumer_id: object) -> str:
    """Return a canonical consumer id (a ledger store id) or refuse it."""
    try:
        wire.validate_identifier("consumer_id", consumer_id)
    except wire.WireError as error:
        raise RetentionRefused("retention.consumer_invalid") from error
    return str(consumer_id)


@contextmanager
def _retention_lock(ledger: RetentionLedger) -> Iterator[None]:
    """Hold an exclusive advisory lock shared by pruning and retained revocation appends.

    The frozen store takes its own hot write lock inside ``append_revocation``, so a lock cannot be
    held across the archive lookup and that append from outside it. Serialising on a sibling lock
    file (taken before any hot lock by both parties, so no lock-order cycle) closes the window in
    which a prune moves a revocation out of the hot table between the two duplicate checks.
    """
    lock_path = ledger.path.with_name(ledger.path.name + ".lock")
    with open(lock_path, "a+b") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class RetentionLedger:
    """Append-only cold archive, consumer registry and prune log in one durable file."""

    def __init__(self, path: str | Path, *, timeout: float = 5.0) -> None:
        """Open or create the ledger; a non-durable path is refused."""
        raw = str(path)
        if raw == ":memory:" or "mode=memory" in raw:
            raise ValueError("retention ledger requires a durable file path")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        with closing(self._connect()) as connection:
            enable_wal(connection, timeout=timeout)
            connection.executescript(_ARCHIVE_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Open one configured connection."""
        connection = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def register_consumer(
        self, consumer_id: str, *, operator: OperatorAuthority, now: datetime
    ) -> None:
        """Register a consumer whose acknowledgement bounds pruning; idempotent and permanent."""
        consumer = _valid_consumer_id(consumer_id)
        reference = operator.authorize("retention.register", attempt_id=consumer, grant_id=None)
        if not isinstance(reference, str) or not reference.strip():
            raise OperatorRefused("operator is not authorized to register a retention consumer")
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR IGNORE INTO retention_consumers(consumer_id, registered_at, operator_ref)"
                " VALUES(?,?,?)", (consumer, wire.timestamp(now), reference),
            )

    def consumers(self) -> tuple[str, ...]:
        """Return the registered consumer ids in ascending order."""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT consumer_id FROM retention_consumers ORDER BY consumer_id"
            ).fetchall()
        return tuple(row["consumer_id"] for row in rows)

    def archived_range(self) -> tuple[int, int] | None:
        """Return the inclusive archived version range, or None while nothing is archived."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT MIN(version) AS low, MAX(version) AS high FROM archived_events"
            ).fetchone()
        return None if row["low"] is None else (int(row["low"]), int(row["high"]))

    def archived_events(self, low: int, high: int) -> list[dict[str, object]]:
        """Return archived event wire dicts for the inclusive range, in version order."""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM archived_events WHERE version BETWEEN ? AND ? ORDER BY version",
                (low, high),
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def find_revocation(self, subject_kind: str, subject_id: str) -> dict[str, object] | None:
        """Return the archived revocation event for a subject, or None."""
        body = {"subject_kind": subject_kind, "subject_id": subject_id}
        wire.validate_event_body("revocation", body)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM archived_events WHERE kind = 'revocation' AND body = ?",
                (wire.canonical_bytes(body).decode("utf-8"),),
            ).fetchone()
        return None if row is None else _row_to_event(row)

    def prune_log(self) -> list[dict[str, object]]:
        """Return the append-only prune log, oldest first."""
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT * FROM prune_log ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def append_archive(self, events: Sequence[Mapping[str, object]], *, now: datetime) -> None:
        """Append events idempotently; an identical row is kept, a different one is a conflict.

        The archive must stay contiguous from version 1: a first row other than 1, or a row that
        skips a version, is refused so that the archive can always be verified from genesis.
        """
        if not events:
            return
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for event in events:
                    self._append_one(connection, event, now)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _append_one(connection: sqlite3.Connection, event: Mapping[str, object], now: datetime) -> None:
        """Append or confirm one archived event inside an open write transaction."""
        _require_event_shape(event)
        version = int(event["version"])  # type: ignore[call-overload]
        existing = connection.execute(
            "SELECT * FROM archived_events WHERE version = ?", (version,)
        ).fetchone()
        if existing is not None:
            if _row_to_event(existing) != dict(event):
                raise RetentionRefused("retention.archive_conflict")
            return
        top = connection.execute("SELECT COALESCE(MAX(version), 0) AS top FROM archived_events").fetchone()
        if version != int(top["top"]) + 1:
            raise RetentionRefused("retention.archive_gap")
        connection.execute(
            "INSERT INTO archived_events(version, kind, body, previous_event_digest, event_digest,"
            " issuer_key_id, signature, archived_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                version, event["kind"], wire.canonical_bytes(event["body"]).decode("utf-8"),  # type: ignore[arg-type]
                event["previous_event_digest"], event["event_digest"], event["issuer_key_id"],
                event["signature"], wire.timestamp(now),
            ),
        )

    def verify_archive(self, resolver: IssuerKeyResolver) -> str:
        """Verify the whole archive from genesis; return its tail digest (genesis if empty)."""
        span = self.archived_range()
        if span is None:
            return wire.GENESIS_EVENT_DIGEST
        if span[0] != 1:
            raise RetentionRefused("retention.archive_gap")
        return verify_chain(
            self.archived_events(*span), previous_digest=wire.GENESIS_EVENT_DIGEST, resolver=resolver
        )

    def _record_prune(
        self, ceiling: int, low: int, high: int, reference: str, now: datetime
    ) -> None:
        """Append one prune-log row."""
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT INTO prune_log(ceiling, pruned_from, pruned_through, operator_ref,"
                " recorded_at) VALUES(?,?,?,?,?)", (ceiling, low, high, reference, wire.timestamp(now)),
            )


@dataclass(frozen=True, slots=True)
class PruneResult:
    """Outcome of one prune: the ceiling used, the moved range (if any) and the retained anchor."""

    ceiling: int
    archived_from: int | None
    archived_through: int | None
    anchor: Checkpoint | None


def _observed_acks(connection: sqlite3.Connection) -> dict[str, int]:
    """Return the highest acknowledged version the issuer has seen for each ledger store id."""
    rows = connection.execute(
        "SELECT ledger_store_id, MAX(consumer_acked_through) AS acked FROM dispatch_permits"
        " GROUP BY ledger_store_id"
    ).fetchall()
    return {row["ledger_store_id"]: int(row["acked"]) for row in rows}


def prune_ceiling(registered: Sequence[str], observed: Mapping[str, int]) -> int:
    """Return the lowest acknowledged version across every registered consumer.

    A registered consumer with no observed acknowledgement counts as 0, so it holds the ceiling
    at the floor. No registered consumer means no safe ceiling: the call is refused.
    """
    if not registered:
        raise RetentionRefused("retention.no_consumers")
    return min(observed.get(consumer, 0) for consumer in registered)


def prune(
    store: SqliteDispatchPermitStore,
    ledger: RetentionLedger,
    resolver: IssuerKeyResolver,
    *,
    operator: OperatorAuthority,
    now: datetime,
) -> PruneResult:
    """Move rows below the pruning ceiling to the archive, keeping one hot anchor (section 3.2).

    Under one hot write transaction: compute the ceiling, verify the rows being moved, append them
    to the archive, read them back and require byte equality, and only then delete the hot rows.
    Any failure rolls the hot store back untouched; a crash after the archive write leaves rows in
    both tiers, and a rerun confirms them idempotently. Nothing is ever deleted without a verified
    archived copy.
    """
    reference = operator.authorize("retention.prune", attempt_id="retention-prune", grant_id=None)
    if not isinstance(reference, str) or not reference.strip():
        raise OperatorRefused("operator is not authorized to prune")
    with _retention_lock(ledger), closing(sqlite3.connect(store.path, timeout=5.0, isolation_level=None)) as hot:
        hot.row_factory = sqlite3.Row
        hot.execute("PRAGMA synchronous = FULL")
        hot.execute("BEGIN IMMEDIATE")
        try:
            result = _prune_locked(hot, ledger, resolver, reference, now)
            hot.execute("COMMIT")
        except BaseException:
            if hot.in_transaction:
                hot.execute("ROLLBACK")
            raise
    return result


def _prune_locked(
    hot: sqlite3.Connection, ledger: RetentionLedger, resolver: IssuerKeyResolver,
    reference: str, now: datetime,
) -> PruneResult:
    """Run the prune steps while the hot write lock is held."""
    ceiling = prune_ceiling(ledger.consumers(), _observed_acks(hot))
    bounds = hot.execute(
        "SELECT MIN(version) AS low, MAX(version) AS high FROM issuer_events"
    ).fetchone()
    if bounds["low"] is None:
        return PruneResult(ceiling, None, None, None)
    low, top = int(bounds["low"]), int(bounds["high"])
    ceiling = min(ceiling, top)
    archived = ledger.archived_range()
    anchor_row = hot.execute("SELECT * FROM issuer_events WHERE version = ?", (max(ceiling, low),)).fetchone()
    if ceiling <= low:
        anchor = checkpoint_from_event(_row_to_event(anchor_row)) if archived else None
        return PruneResult(ceiling, None, None, anchor)
    if anchor_row is None:
        raise RetentionRefused("retention.anchor_missing")
    rows = [
        _row_to_event(row) for row in hot.execute(
            "SELECT * FROM issuer_events WHERE version >= ? AND version < ? ORDER BY version",
            (low, ceiling),
        )
    ]
    ledger.verify_archive(resolver)
    # A crash after the archive write leaves rows in both tiers; the archive may already hold
    # versions at or above ``low``, which the idempotent append below confirms byte for byte.
    if (archived[1] if archived else 0) < low - 1:
        raise RetentionRefused("retention.archive_gap")
    if low == 1:
        link = wire.GENESIS_EVENT_DIGEST
    else:
        below = ledger.archived_events(low - 1, low - 1)
        if not below:
            raise RetentionRefused("retention.archive_gap")
        link = str(below[0]["event_digest"])
    verify_chain(rows, previous_digest=link, resolver=resolver)
    ledger.append_archive(rows, now=now)
    if ledger.archived_events(low, ceiling - 1) != rows:
        raise RetentionRefused("retention.readback_mismatch")
    hot.execute("DELETE FROM issuer_events WHERE version < ?", (ceiling,))
    ledger._record_prune(ceiling, low, ceiling - 1, reference, now)
    return PruneResult(ceiling, low, ceiling - 1, checkpoint_from_event(_row_to_event(anchor_row)))


class RetainedEventFeed:
    """Read-only view stitching the archive and the hot store into one contiguous event range."""

    def __init__(self, store: SqliteDispatchPermitStore, ledger: RetentionLedger) -> None:
        """Bind the issuer store and its retention ledger."""
        self._store = store
        self._ledger = ledger

    def _hot_low(self) -> int | None:
        """Return the lowest hot event version, or None for an empty chain."""
        uri = self._store.path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            value = connection.execute("SELECT MIN(version) FROM issuer_events").fetchone()[0]
        return None if value is None else int(value)

    def events(self, low: int, high: int) -> list[dict[str, object]]:
        """Return events low..high inclusive from both tiers, or refuse if any is unavailable."""
        if low < 1 or high < low:
            raise RetentionRefused("retention.range_unavailable")
        for _ in range(_EVENTS_ATTEMPTS):
            hot_low = self._hot_low()
            boundary = (hot_low if hot_low is not None else high + 1)
            out: list[dict[str, object]] = []
            if low < boundary:
                out.extend(self._ledger.archived_events(low, min(high, boundary - 1)))
            if high >= boundary:
                out.extend(self._store.events(max(low, boundary), high))
            if [int(e["version"]) for e in out] == list(range(low, high + 1)):  # type: ignore[call-overload]
                return out
            if self._hot_low() == hot_low:
                break  # the boundary did not move, so the range really is unavailable
        raise RetentionRefused("retention.range_unavailable")

    def checkpoint(self, version: int) -> Checkpoint:
        """Return the issuer-signed checkpoint at ``version`` from whichever tier holds it."""
        return checkpoint_from_event(self.events(version, version)[0])

    def current_anchor(self) -> Checkpoint | None:
        """Return the retained boundary checkpoint, or None before the first prune."""
        if self._ledger.archived_range() is None:
            return None
        hot_low = self._hot_low()
        return None if hot_low is None else self.checkpoint(hot_low)

    def verify_continuity(self, resolver: IssuerKeyResolver) -> None:
        """Verify the archive from genesis and its link to the hot anchor; refuse any break."""
        tail = self._ledger.verify_archive(resolver)
        span = self._ledger.archived_range()
        hot_low = self._hot_low()
        if span is None or hot_low is None:
            return
        if hot_low > span[1] + 1:
            raise RetentionRefused("retention.archive_gap")
        if hot_low <= span[1]:
            # Supported crash state: rows archived but not yet deleted from the hot store. The
            # archive is already verified from genesis, so the overlap must match it byte for byte.
            if self._store.events(hot_low, span[1]) != self._ledger.archived_events(hot_low, span[1]):
                raise RetentionRefused("retention.archive_conflict")
            return
        anchor = self._store.events(hot_low, hot_low)
        verify_chain(anchor, previous_digest=tail, resolver=resolver)


def append_revocation_once(
    store: SqliteDispatchPermitStore, ledger: RetentionLedger, subject_kind: str, subject_id: str,
    *, signer: object,
) -> dict[str, object]:
    """Append a revocation, or return the identical one already recorded in either tier.

    The frozen store looks for a duplicate only in the hot table; after a prune the original may
    live in the archive, so this wrapper consults the archive first and keeps idempotence intact.
    It shares one advisory lock with :func:`prune`, so a prune cannot move the original between the
    archive check and the append. Callers that bypass this wrapper and call the store directly are
    outside that guarantee (the store is frozen and cannot take the lock itself).
    """
    with _retention_lock(ledger):
        archived = ledger.find_revocation(subject_kind, subject_id)
        if archived is not None:
            return archived
        return store.append_revocation(subject_kind, subject_id, signer=signer)  # type: ignore[arg-type]
