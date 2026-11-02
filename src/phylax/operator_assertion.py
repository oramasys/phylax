"""Production operator authentication by per-person signed assertions.

Implements the ``OperatorAuthority`` port of :mod:`phylax.dispatch_permit_store` (and the
retention operations of :mod:`phylax.dispatch_retention`) without any shared secret. Contract:
``docs/operator-signed-assertions.md``.

* A registry of per-person Ed25519 operator keys is itself signed by a pinned registry authority
  key. Entries carry a validity window, the operations the key may assert, and an optional
  ``revoked_at``. The registry version only moves forward (anti-rollback floor).
* An assertion binds one operator key to one ``(operation, attempt_id, grant_id)`` for at most 300
  seconds, names its audience, and carries a nonce that is consumed exactly once.
* Verification holds public keys only. Operator signing seeds never exist on the verifier host.
* Every failure is a closed-vocabulary code; the port returns ``None`` (not authorized) and keeps the
  code on the one-shot authority for the audit record.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from nacl import exceptions as nacl_exceptions
from nacl.bindings import (
    crypto_sign_ed25519ph_final_create,
    crypto_sign_ed25519ph_final_verify,
    crypto_sign_ed25519ph_state,
    crypto_sign_ed25519ph_update,
    crypto_sign_seed_keypair,
)

from . import dispatch_wire as wire
from .sqlite_wal import enable_wal

REGISTRY_DOMAIN: Final = b"phylax-operator-registry-v1\x00"
ASSERTION_DOMAIN: Final = b"phylax-operator-assertion-v1\x00"
SCHEMA_VERSION: Final = 1
MAX_ASSERTION_SECONDS: Final = 300
CLOCK_SKEW_SECONDS: Final = 5
DEFAULT_REGISTRY_MAX_AGE_SECONDS: Final = 86_400
MAX_ENTRIES: Final = 64
MAX_OPERATIONS: Final = 16
MAX_WIRE_BYTES: Final = 65_536

ASSERTION_REFUSAL_CODES: Final = frozenset({
    "operator.malformed", "operator.registry_signature", "operator.registry_rollback",
    "operator.registry_stale", "operator.unknown_key", "operator.key_inactive",
    "operator.key_revoked", "operator.operation_not_permitted", "operator.binding_mismatch",
    "operator.audience_mismatch", "operator.expired", "operator.not_yet_valid",
    "operator.lifetime_too_long", "operator.signature", "operator.replayed",
    "operator.already_used",
    "operator.clock_rollback",
})

_OPERATION = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{22,64}")
_REGISTRY_ENTRY_FIELDS = (
    "operator_id", "key_id", "public_key", "not_before", "not_after", "operations", "revoked_at",
)
_REGISTRY_BODY_FIELDS = ("schema_version", "registry_version", "issued_at", "entries")
_ENVELOPE_FIELDS = ("body", "signature")
_ASSERTION_FIELDS = (
    "schema_version", "operator_id", "key_id", "operation", "attempt_id", "grant_id", "audience",
    "nonce", "issued_at", "expires_at",
)

_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS registry_floor (
    slot INTEGER PRIMARY KEY CHECK(slot = 1),
    registry_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS consumed_nonces (
    operator_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (operator_id, nonce)
);
CREATE TABLE IF NOT EXISTS consumption_clock (
    slot INTEGER PRIMARY KEY CHECK(slot = 1),
    observed_at TEXT NOT NULL
);
INSERT OR IGNORE INTO consumption_clock(slot, observed_at)
    SELECT 1, MAX(consumed_at) FROM consumed_nonces HAVING MAX(consumed_at) IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS registry_floor_forward_only BEFORE UPDATE ON registry_floor
WHEN NEW.registry_version < OLD.registry_version
BEGIN SELECT RAISE(ABORT, 'registry floor only moves forward'); END;
"""


class OperatorAssertionRefused(Exception):
    """A closed-vocabulary refusal of an operator assertion or registry."""

    def __init__(self, code: str) -> None:
        """Record the code, which must belong to the assertion vocabulary."""
        if code not in ASSERTION_REFUSAL_CODES:
            raise ValueError(f"unknown operator refusal code: {code}")
        super().__init__(code)
        self.code = code


def _domain_sign(seed: bytes, domain: bytes, payload: bytes) -> str:
    """Return an unpadded base64url Ed25519ph signature over domain plus payload."""
    _public, secret = crypto_sign_seed_keypair(seed)
    state = crypto_sign_ed25519ph_state()
    crypto_sign_ed25519ph_update(state, domain)
    crypto_sign_ed25519ph_update(state, payload)
    return wire.b64url_encode(crypto_sign_ed25519ph_final_create(state, secret))


def _domain_verify(public_key: bytes, signature: str, domain: bytes, payload: bytes) -> bool:
    """Return True only when the signature verifies over domain plus payload."""
    try:
        raw = wire.b64url_decode(signature)
        state = crypto_sign_ed25519ph_state()
        crypto_sign_ed25519ph_update(state, domain)
        crypto_sign_ed25519ph_update(state, payload)
        return bool(crypto_sign_ed25519ph_final_verify(state, raw, public_key))
    except (wire.WireError, nacl_exceptions.BadSignatureError, nacl_exceptions.ValueError):
        return False


def sign_registry(seed: bytes, body: Mapping[str, object]) -> bytes:
    """Return the signed registry envelope bytes (operator-side tool; never on the verifier)."""
    envelope = {"body": dict(body), "signature": _domain_sign(seed, REGISTRY_DOMAIN, wire.canonical_bytes(body))}
    return wire.canonical_bytes(envelope)


def sign_assertion(seed: bytes, body: Mapping[str, object]) -> bytes:
    """Return the signed assertion envelope bytes (operator-side tool)."""
    envelope = {"body": dict(body), "signature": _domain_sign(seed, ASSERTION_DOMAIN, wire.canonical_bytes(body))}
    return wire.canonical_bytes(envelope)


def _load_envelope(raw: object) -> tuple[dict[str, object], str]:
    """Parse strict canonical JSON into ``(body, signature)`` or refuse as malformed."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_WIRE_BYTES:
        raise OperatorAssertionRefused("operator.malformed")
    try:
        document = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as error:
        raise OperatorAssertionRefused("operator.malformed") from error
    if not isinstance(document, dict) or set(document) != set(_ENVELOPE_FIELDS):
        raise OperatorAssertionRefused("operator.malformed")
    body, signature = document["body"], document["signature"]
    if not isinstance(body, dict) or not isinstance(signature, str):
        raise OperatorAssertionRefused("operator.malformed")
    if wire.canonical_bytes(document) != bytes(raw):
        raise OperatorAssertionRefused("operator.malformed")
    return body, signature


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object keys."""
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _stamp(value: object) -> datetime:
    """Parse a fixed-format wire timestamp or refuse as malformed."""
    try:
        return wire.parse_timestamp(value)
    except wire.WireError as error:
        raise OperatorAssertionRefused("operator.malformed") from error


def _identifier(value: object) -> str:
    """Return a canonical identifier or refuse as malformed."""
    try:
        wire.validate_identifier("identifier", value)
    except wire.WireError as error:
        raise OperatorAssertionRefused("operator.malformed") from error
    return str(value)


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """One operator key with its validity window, permitted operations and revocation time."""

    operator_id: str
    key_id: str
    public_key: bytes
    not_before: datetime
    not_after: datetime
    operations: frozenset[str]
    revoked_at: datetime | None


@dataclass(frozen=True, slots=True)
class Registry:
    """A verified operator registry."""

    version: int
    issued_at: datetime
    entries: Mapping[tuple[str, str], RegistryEntry]


def parse_registry(raw: bytes, *, trust_public_key: bytes) -> Registry:
    """Verify the registry signature, then parse the closed body; refuse anything malformed."""
    body, signature = _load_envelope(raw)
    if not _domain_verify(trust_public_key, signature, REGISTRY_DOMAIN, wire.canonical_bytes(body)):
        raise OperatorAssertionRefused("operator.registry_signature")
    if set(body) != set(_REGISTRY_BODY_FIELDS) or body["schema_version"] != SCHEMA_VERSION:
        raise OperatorAssertionRefused("operator.malformed")
    version = body["registry_version"]
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= wire.MAX_SAFE_INTEGER:
        raise OperatorAssertionRefused("operator.malformed")
    entries_raw = body["entries"]
    if not isinstance(entries_raw, list) or len(entries_raw) > MAX_ENTRIES:
        raise OperatorAssertionRefused("operator.malformed")
    entries: dict[tuple[str, str], RegistryEntry] = {}
    order: list[tuple[str, str]] = []
    for item in entries_raw:
        entry = _parse_entry(item)
        pair = (entry.operator_id, entry.key_id)
        if pair in entries:
            raise OperatorAssertionRefused("operator.malformed")
        entries[pair] = entry
        order.append(pair)
    if order != sorted(order):
        raise OperatorAssertionRefused("operator.malformed")
    return Registry(version, _stamp(body["issued_at"]), entries)


def _parse_entry(item: object) -> RegistryEntry:
    """Parse one closed registry entry."""
    if not isinstance(item, dict) or set(item) != set(_REGISTRY_ENTRY_FIELDS):
        raise OperatorAssertionRefused("operator.malformed")
    try:
        public_key = wire.b64url_decode(item["public_key"])
    except wire.WireError as error:
        raise OperatorAssertionRefused("operator.malformed") from error
    operations = item["operations"]
    if (
        len(public_key) != 32 or not isinstance(operations, list)
        or not 1 <= len(operations) <= MAX_OPERATIONS
        or any(not isinstance(op, str) or not _OPERATION.fullmatch(op) for op in operations)
        or operations != sorted(set(operations))
    ):
        raise OperatorAssertionRefused("operator.malformed")
    not_before, not_after = _stamp(item["not_before"]), _stamp(item["not_after"])
    if not_after <= not_before:
        raise OperatorAssertionRefused("operator.malformed")
    revoked = item["revoked_at"]
    return RegistryEntry(
        _identifier(item["operator_id"]), _identifier(item["key_id"]), public_key, not_before,
        not_after, frozenset(operations), None if revoked is None else _stamp(revoked),
    )


@dataclass(frozen=True, slots=True)
class OperatorAssertion:
    """A parsed, not yet verified, operator assertion."""

    body: Mapping[str, object]
    signature: str


def parse_assertion(raw: bytes) -> OperatorAssertion:
    """Parse the closed assertion body; the signature is checked later against the registry."""
    body, signature = _load_envelope(raw)
    if set(body) != set(_ASSERTION_FIELDS) or body["schema_version"] != SCHEMA_VERSION:
        raise OperatorAssertionRefused("operator.malformed")
    for name in ("operator_id", "key_id", "attempt_id", "audience"):
        _identifier(body[name])
    if body["grant_id"] is not None:
        _identifier(body["grant_id"])
    operation, nonce = body["operation"], body["nonce"]
    if not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
        raise OperatorAssertionRefused("operator.malformed")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise OperatorAssertionRefused("operator.malformed")
    _stamp(body["issued_at"])
    _stamp(body["expires_at"])
    return OperatorAssertion(body, signature)


class OperatorAssertionVerifier:
    """Verifies assertions against a pinned registry authority and consumes their nonces."""

    def __init__(
        self,
        *,
        state_path: str | Path,
        trust_public_key: bytes,
        audience: str,
        registry_source: Callable[[], bytes],
        clock: Callable[[], datetime],
        registry_max_age_seconds: int = DEFAULT_REGISTRY_MAX_AGE_SECONDS,
        timeout: float = 5.0,
    ) -> None:
        """Bind trust, audience, the registry source and the durable replay/rollback state."""
        if len(trust_public_key) != 32:
            raise ValueError("registry trust key must be 32 bytes")
        _identifier(audience)
        raw = str(state_path)
        if raw == ":memory:" or "mode=memory" in raw:
            raise ValueError("operator state requires a durable file path")
        self._trust = trust_public_key
        self._audience = audience
        self._registry_source = registry_source
        self._clock = clock
        self._max_age = timedelta(seconds=registry_max_age_seconds)
        self._timeout = timeout
        self.path = Path(state_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            enable_wal(connection, timeout=timeout)
            connection.executescript(_STATE_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Open one configured connection."""
        connection = sqlite3.connect(self.path, timeout=self._timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def verify_and_consume(
        self, raw: bytes, *, operation: str, attempt_id: str, grant_id: str | None
    ) -> str:
        """Verify an assertion for exactly this call and consume its nonce; return the reference.

        The registry floor rises on sight of a verified registry. No nonce is consumed unless every
        check passes, and the nonce and the expired-nonce cleanup commit in one transaction.
        """
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock must return an aware datetime")
        registry = parse_registry(self._registry_source(), trust_public_key=self._trust)
        self._observe_registry(registry.version)
        if now - registry.issued_at > self._max_age or registry.issued_at - now > timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise OperatorAssertionRefused("operator.registry_stale")
        assertion = parse_assertion(raw)
        entry = self._authorize_entry(registry, assertion.body, now)
        self._check_binding(assertion.body, entry, operation, attempt_id, grant_id, now)
        payload = wire.canonical_bytes(assertion.body)
        if not _domain_verify(entry.public_key, assertion.signature, ASSERTION_DOMAIN, payload):
            raise OperatorAssertionRefused("operator.signature")
        nonce = str(assertion.body["nonce"])
        self._commit(entry.operator_id, nonce, str(assertion.body["expires_at"]), now,
                     registry_version=registry.version)
        return f"operator:{entry.operator_id}:{nonce}"

    @staticmethod
    def _authorize_entry(registry: Registry, body: Mapping[str, object], now: datetime) -> RegistryEntry:
        """Find the operator key and require it be active, unrevoked and in its window."""
        entry = registry.entries.get((str(body["operator_id"]), str(body["key_id"])))
        if entry is None:
            raise OperatorAssertionRefused("operator.unknown_key")
        if entry.revoked_at is not None and now >= entry.revoked_at:
            raise OperatorAssertionRefused("operator.key_revoked")
        issued = wire.parse_timestamp(body["issued_at"])
        if not (entry.not_before <= issued <= entry.not_after and entry.not_before <= now <= entry.not_after):
            raise OperatorAssertionRefused("operator.key_inactive")
        return entry

    def _check_binding(
        self, body: Mapping[str, object], entry: RegistryEntry, operation: str, attempt_id: str,
        grant_id: str | None, now: datetime,
    ) -> None:
        """Require audience, exact call binding, permitted operation and a short live window."""
        if body["audience"] != self._audience:
            raise OperatorAssertionRefused("operator.audience_mismatch")
        if body["operation"] not in entry.operations:
            raise OperatorAssertionRefused("operator.operation_not_permitted")
        if (body["operation"], body["attempt_id"], body["grant_id"]) != (operation, attempt_id, grant_id):
            raise OperatorAssertionRefused("operator.binding_mismatch")
        issued, expires = wire.parse_timestamp(body["issued_at"]), wire.parse_timestamp(body["expires_at"])
        if expires <= issued or expires - issued > timedelta(seconds=MAX_ASSERTION_SECONDS):
            raise OperatorAssertionRefused("operator.lifetime_too_long")
        if issued - now > timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise OperatorAssertionRefused("operator.not_yet_valid")
        if now >= expires:
            raise OperatorAssertionRefused("operator.expired")

    def _observe_registry(self, version: int) -> None:
        """Refuse a registry older than any already seen; otherwise raise the floor to it.

        The floor moves on sight of any authority-signed registry, not only after a success: a
        registry that revokes a key must not be undone by replaying an older one, even when the
        call that revealed the newer registry was itself refused.
        """
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                floor = connection.execute("SELECT registry_version FROM registry_floor").fetchone()
                if floor is not None and version < floor["registry_version"]:
                    raise OperatorAssertionRefused("operator.registry_rollback")
                connection.execute(
                    "INSERT INTO registry_floor(slot, registry_version) VALUES(1, ?)"
                    " ON CONFLICT(slot) DO UPDATE SET registry_version = excluded.registry_version",
                    (version,),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _commit(
        self, operator_id: str, nonce: str, expires_at: str, now: datetime, *, registry_version: int
    ) -> None:
        """Fence registry/clock rollback and consume atomically with expired-nonce cleanup."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                floor = connection.execute("SELECT registry_version FROM registry_floor").fetchone()
                if floor is None or registry_version < floor["registry_version"]:
                    raise OperatorAssertionRefused("operator.registry_rollback")
                observed = connection.execute("SELECT observed_at FROM consumption_clock").fetchone()
                if observed is not None and now < wire.parse_timestamp(observed["observed_at"]):
                    raise OperatorAssertionRefused("operator.clock_rollback")
                # Retain the cleanup clock even after every older nonce has been deleted.
                connection.execute(
                    "INSERT INTO consumption_clock(slot, observed_at) VALUES(1, ?)"
                    " ON CONFLICT(slot) DO UPDATE SET observed_at = excluded.observed_at",
                    (wire.timestamp(now),),
                )
                cutoff = wire.timestamp(
                    now - timedelta(seconds=MAX_ASSERTION_SECONDS + 2 * CLOCK_SKEW_SECONDS)
                )
                connection.execute("DELETE FROM consumed_nonces WHERE expires_at < ?", (cutoff,))
                try:
                    connection.execute(
                        "INSERT INTO consumed_nonces(operator_id, nonce, expires_at, consumed_at)"
                        " VALUES(?,?,?,?)", (operator_id, nonce, expires_at, wire.timestamp(now)),
                    )
                except sqlite3.IntegrityError as error:
                    raise OperatorAssertionRefused("operator.replayed") from error
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def authority_for(self, raw_assertion: bytes) -> AssertionAuthority:
        """Return a one-shot ``OperatorAuthority`` that honours exactly this assertion once."""
        return AssertionAuthority(self, raw_assertion)


class AssertionAuthority:
    """One-shot ``OperatorAuthority``: the first ``authorize`` call is its only call.

    Any later call returns None with ``operator.already_used``, even when the first call was refused
    (for example ``operator.binding_mismatch``); build a new authority to retry. The nonce itself is
    consumed only when that first call passes every check.
    """

    def __init__(self, verifier: OperatorAssertionVerifier, raw_assertion: bytes) -> None:
        """Hold the assertion bytes; nothing is verified until ``authorize`` is called."""
        self._verifier = verifier
        self._raw = raw_assertion
        self._used = False
        self.refusal: str | None = None

    def authorize(self, operation: str, *, attempt_id: str, grant_id: str | None) -> str | None:
        """Return the operator disposition reference, or None with ``refusal`` set."""
        if self._used:
            self.refusal = "operator.already_used"
            return None
        self._used = True
        try:
            reference = self._verifier.verify_and_consume(
                self._raw, operation=operation, attempt_id=attempt_id, grant_id=grant_id
            )
        except OperatorAssertionRefused as refusal:
            self.refusal = refusal.code
            return None
        self.refusal = None
        return reference

