"""Strict Phylax-issued adjustment grants with Ed25519ph attestations.

This module owns issuance, verification, revocation, and issuer-key lifecycle.
It deliberately does not consume a grant against a budget or decide whether a
ledger has remaining balance; that is an Oramasys-owned transaction.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Callable, Final, Literal, Protocol

from nacl import exceptions as nacl_exceptions
from nacl.bindings import (
    crypto_sign_BYTES,
    crypto_sign_SEEDBYTES,
    crypto_sign_ed25519ph_final_create,
    crypto_sign_ed25519ph_final_verify,
    crypto_sign_ed25519ph_state,
    crypto_sign_ed25519ph_update,
    crypto_sign_seed_keypair,
)

from .p5_approval import (
    P5ApprovalAuthority,
    P5ApprovalDecision,
    P5ApprovalIntent,
    P5ApprovalReceipt,
)
from . import dispatch_wire
from .grant_store import IssuerKeyRecord, SqliteGrantAuthorityStore

if TYPE_CHECKING:
    from .dispatch_composition import DispatchIssuerSigner

_DOMAIN: Final = b"phylax-adjustment-grant-v1\x00"
_EFFECT_GRANT_DOMAIN: Final = b"phylax-effect-grant-v2\x00"
_SCHEMA_VERSION: Final = 1
_FUTURE_ISSUANCE_SKEW: Final = timedelta(seconds=60)
_UNIT_BASES: Final = frozenset({"steps", "elapsed_ms", "cost_microunits", "effect_attempts"})
_KINDS: Final = frozenset({"settle", "release"})
_MAX_SAFE_INTEGER: Final = (2**53) - 1
# Seven request strings at this cap, even fully JSON-escaped, stay far below the
# 65,536-byte wire limit, so a grant that can be issued can always be parsed.
_MAX_TEXT_BYTES: Final = 1_024
_GRANT_ACTION: Final = "phylax.adjustment_grant.issue"


class GrantRefusalReason(StrEnum):
    """Closed issuer-verification refusal vocabulary shared with Oramasys."""

    GRANT_MALFORMED = "grant.malformed"
    GRANT_SCHEMA_UNSUPPORTED = "grant.schema_unsupported"
    GRANT_KEY_UNKNOWN = "grant.key_unknown"
    GRANT_SIGNATURE_INVALID = "grant.signature_invalid"
    GRANT_EXPIRED = "grant.expired"
    GRANT_FUTURE_DATED = "grant.future_dated"
    GRANT_REVOKED = "grant.revoked"
    REVOCATION_STALE = "revocation.stale"
    VERIFIER_UNAVAILABLE = "verifier.unavailable"


class GrantRefusal(Exception):
    """A verifier refusal with no unstructured or caller-controlled detail."""

    def __init__(self, reason: GrantRefusalReason) -> None:
        """Store the closed-set refusal reason, rejecting anything outside it."""
        if not isinstance(reason, GrantRefusalReason):
            raise ValueError("grant refusal reason is not in the closed set")
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class VerifiedGrant:
    """Only the grant facts the Oramasys ledger needs to validate and spend."""

    grant_id: str
    principal: str
    run_id: str
    hold_id: str
    kind: Literal["settle", "release"]
    units: int
    units_basis: str
    ledger_cost_basis: str
    hold_fence_epoch: int
    consumer_lease_epoch: int
    ledger_store_id: str
    issued_at: datetime
    expires_at: datetime
    payload_digest: str
    verifier_id: str


class GrantVerificationStore(Protocol):
    """Read-only facts required to validate an issued grant."""

    def key(self, key_id: str) -> IssuerKeyRecord | None: ...

    def is_issued(self, grant_id: str, payload_digest: str, wire: bytes) -> bool: ...

    def is_revoked(self, grant_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class RevocationObservation:
    """Durable revocation state with an observation timestamp."""

    grant_id: str
    revoked: bool
    observed_at: datetime


class IssuerSeedProvider(Protocol):
    """Composition-owned source for private signing seeds."""

    def load_seed(self, seed_ref: str) -> bytes:
        """Return secret seed material for one opaque registry reference."""


def _require_text(value: str, field_name: str) -> None:
    """Reject empty strings before they can enter a signed grant."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")


def _require_digest(value: str, field_name: str) -> None:
    """Require a lower-case SHA-256 hexadecimal digest."""
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{field_name} must be a lower-case SHA-256 digest")


def _require_safe_integer(value: object, field_name: str, *, minimum: int = 0) -> None:
    """Enforce I-JSON's interoperable integer range without accepting bools."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= _MAX_SAFE_INTEGER:
        raise ValueError(f"{field_name} must be an interoperable integer")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys before a signed payload is interpreted."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _utc_datetime(value: datetime, field_name: str) -> datetime:
    """Require a timezone-aware UTC datetime and normalize its representation."""
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a UTC-aware datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime, field_name: str) -> str:
    """Encode an instant in the fixed six-digit UTC wire representation."""
    normalized = _utc_datetime(value, field_name)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.") + f"{normalized.microsecond:06d}Z"


def _b64encode(value: bytes) -> str:
    """Encode unpadded base64url text for the signature wire field."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    """Decode strict unpadded base64url text."""
    if not isinstance(value, str):
        raise ValueError("issuer_signature is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("issuer_signature is invalid") from exc
    if _b64encode(decoded) != value:
        raise ValueError("issuer_signature is invalid")
    return decoded


def _canonical_bytes(body: dict[str, object]) -> bytes:
    """Serialize the fixed ASCII-keyed v1 body in its JCS-compatible subset.

    This fixed schema contains only ASCII property names, strings, and safe
    integers. Callers reject values outside that interoperable JCS subset.
    """
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _grant_body(
    request: AdjustmentGrantRequest,
    *,
    grant_id: str,
    issued_at: datetime,
    expires_at: datetime,
    issuer_key_id: str,
) -> bytes:
    """Build the complete digest and signature preimage from validated grant fields."""
    return _canonical_bytes(
        {
            "consumer_lease_epoch": request.consumer_lease_epoch,
            "evidence_digest": request.evidence_digest,
            "expires_at": _timestamp(expires_at, "expires_at"),
            "grant_id": grant_id,
            "hold_fence_epoch": request.hold_fence_epoch,
            "hold_id": request.hold_id,
            "issued_at": _timestamp(issued_at, "issued_at"),
            "issuer_key_id": issuer_key_id,
            "issuer_ref": request.issuer_ref,
            "kind": request.kind,
            "ledger_cost_basis": request.ledger_cost_basis,
            "ledger_store_id": request.ledger_store_id,
            "principal": request.principal,
            "revocation_ref": request.revocation_ref,
            "run_id": request.run_id,
            "schema_version": _SCHEMA_VERSION,
            "units": request.units,
            "units_basis": request.units_basis,
        }
    )


def _sign_message(seed: bytes, *chunks: bytes) -> tuple[bytes, bytes]:
    """Create an RFC 8032 Ed25519ph signature over arbitrary message chunks."""
    public_key, secret_key = crypto_sign_seed_keypair(seed)
    state = crypto_sign_ed25519ph_state()
    for chunk in chunks:
        crypto_sign_ed25519ph_update(state, chunk)
    return public_key, crypto_sign_ed25519ph_final_create(state, secret_key)


def _verify_message(public_key: bytes, signature: bytes, *chunks: bytes) -> bool:
    """Verify an RFC 8032 Ed25519ph signature over arbitrary message chunks."""
    state = crypto_sign_ed25519ph_state()
    for chunk in chunks:
        crypto_sign_ed25519ph_update(state, chunk)
    try:
        return crypto_sign_ed25519ph_final_verify(state, signature, public_key)
    except nacl_exceptions.BadSignatureError:
        return False


def _sign(seed: bytes, body: bytes) -> tuple[bytes, bytes]:
    """Create an RFC 8032 Ed25519ph signature over the domain-prefixed body."""
    return _sign_message(seed, _DOMAIN, body)


def _verify(public_key: bytes, body: bytes, signature: bytes) -> bool:
    """Verify the exact domain-separated RFC 8032 Ed25519ph message framing."""
    return _verify_message(public_key, signature, _DOMAIN, body)


@dataclass(frozen=True, slots=True)
class AdjustmentGrantRequest:
    """Immutable target tuple submitted by an authenticated issuance caller."""

    principal: str
    run_id: str
    hold_id: str
    kind: Literal["settle", "release"]
    units: int
    units_basis: Literal["steps", "elapsed_ms", "cost_microunits", "effect_attempts"]
    ledger_cost_basis: str
    evidence_digest: str
    hold_fence_epoch: int
    consumer_lease_epoch: int
    ledger_store_id: str
    issuer_ref: str
    revocation_ref: str

    def __post_init__(self) -> None:
        """Reject an incomplete or ambiguous adjustment target."""
        for field_name in (
            "principal",
            "run_id",
            "hold_id",
            "ledger_cost_basis",
            "ledger_store_id",
            "issuer_ref",
            "revocation_ref",
        ):
            _require_text(getattr(self, field_name), field_name)
            if len(getattr(self, field_name).encode("utf-8")) > _MAX_TEXT_BYTES:
                raise ValueError(f"{field_name} exceeds {_MAX_TEXT_BYTES} bytes")
        if not isinstance(self.kind, str) or self.kind not in _KINDS:
            raise ValueError("kind must be settle or release")
        if isinstance(self.units, bool) or not isinstance(self.units, int) or self.units <= 0:
            raise ValueError("units must be a positive integer")
        _require_safe_integer(self.units, "units", minimum=1)
        if not isinstance(self.units_basis, str) or self.units_basis not in _UNIT_BASES:
            raise ValueError("units_basis is invalid")
        _require_digest(self.evidence_digest, "evidence_digest")
        for field_name in ("hold_fence_epoch", "consumer_lease_epoch"):
            value = getattr(self, field_name)
            # Ledger leases start at epoch 1, so a zero epoch can never be consumed.
            _require_safe_integer(value, field_name, minimum=1)


@dataclass(frozen=True, slots=True)
class AdjustmentGrant:
    """A single-use, Phylax-attested authority token for one ledger adjustment."""

    schema_version: Literal[1]
    grant_id: str
    principal: str
    run_id: str
    hold_id: str
    kind: Literal["settle", "release"]
    units: int
    units_basis: Literal["steps", "elapsed_ms", "cost_microunits", "effect_attempts"]
    ledger_cost_basis: str
    evidence_digest: str
    hold_fence_epoch: int
    consumer_lease_epoch: int
    ledger_store_id: str
    issued_at: datetime
    expires_at: datetime
    issuer_key_id: str
    issuer_ref: str
    revocation_ref: str
    payload_digest: str
    issuer_signature: str

    def __post_init__(self) -> None:
        """Verify every structural invariant and the deterministic payload digest."""
        if type(self.schema_version) is not int or self.schema_version != _SCHEMA_VERSION:
            raise ValueError("schema_version is unsupported")
        AdjustmentGrantRequest(
            principal=self.principal,
            run_id=self.run_id,
            hold_id=self.hold_id,
            kind=self.kind,
            units=self.units,
            units_basis=self.units_basis,
            ledger_cost_basis=self.ledger_cost_basis,
            evidence_digest=self.evidence_digest,
            hold_fence_epoch=self.hold_fence_epoch,
            consumer_lease_epoch=self.consumer_lease_epoch,
            ledger_store_id=self.ledger_store_id,
            issuer_ref=self.issuer_ref,
            revocation_ref=self.revocation_ref,
        )
        _require_text(self.grant_id, "grant_id")
        _require_text(self.issuer_key_id, "issuer_key_id")
        issued_at = _utc_datetime(self.issued_at, "issued_at")
        expires_at = _utc_datetime(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise ValueError("expires_at must be after issued_at")
        _require_digest(self.payload_digest, "payload_digest")
        signature = _b64decode(self.issuer_signature)
        if len(signature) != crypto_sign_BYTES:
            raise ValueError("issuer_signature is invalid")
        expected_digest = hashlib.sha256(self.canonical_body()).hexdigest()
        if self.payload_digest != expected_digest:
            raise ValueError("payload_digest does not match the canonical grant body")

    @classmethod
    def from_request(
        cls,
        request: AdjustmentGrantRequest,
        *,
        grant_id: str,
        issued_at: datetime,
        expires_at: datetime,
        issuer_key_id: str,
        payload_digest: str,
        issuer_signature: str,
    ) -> AdjustmentGrant:
        """Build a grant from its immutable request and attestation fields."""
        return cls(
            schema_version=_SCHEMA_VERSION,
            grant_id=grant_id,
            principal=request.principal,
            run_id=request.run_id,
            hold_id=request.hold_id,
            kind=request.kind,
            units=request.units,
            units_basis=request.units_basis,
            ledger_cost_basis=request.ledger_cost_basis,
            evidence_digest=request.evidence_digest,
            hold_fence_epoch=request.hold_fence_epoch,
            consumer_lease_epoch=request.consumer_lease_epoch,
            ledger_store_id=request.ledger_store_id,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_key_id=issuer_key_id,
            issuer_ref=request.issuer_ref,
            revocation_ref=request.revocation_ref,
            payload_digest=payload_digest,
            issuer_signature=issuer_signature,
        )

    def canonical_body(self) -> bytes:
        """Return the exact UTF-8 canonical body covered by digest and signature."""
        return _grant_body(
            AdjustmentGrantRequest(
                principal=self.principal,
                run_id=self.run_id,
                hold_id=self.hold_id,
                kind=self.kind,
                units=self.units,
                units_basis=self.units_basis,
                ledger_cost_basis=self.ledger_cost_basis,
                evidence_digest=self.evidence_digest,
                hold_fence_epoch=self.hold_fence_epoch,
                consumer_lease_epoch=self.consumer_lease_epoch,
                ledger_store_id=self.ledger_store_id,
                issuer_ref=self.issuer_ref,
                revocation_ref=self.revocation_ref,
            ),
            grant_id=self.grant_id,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            issuer_key_id=self.issuer_key_id,
        )

    def to_wire(self) -> bytes:
        """Serialize the complete signed grant as canonical UTF-8 JSON."""
        body = json.loads(self.canonical_body())
        body["payload_digest"] = self.payload_digest
        body["issuer_signature"] = self.issuer_signature
        return _canonical_bytes(body)

    @classmethod
    def from_wire(cls, wire: bytes) -> AdjustmentGrant:
        """Parse a canonical wire record, rejecting duplicates and extensions."""
        if not isinstance(wire, bytes) or not wire or len(wire) > 65_536:
            raise ValueError("grant wire is malformed")
        try:
            payload = json.loads(wire.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise ValueError("grant wire is malformed") from exc
        if not isinstance(payload, dict):
            raise ValueError("grant wire is malformed")
        expected_fields = {
            "schema_version", "grant_id", "principal", "run_id", "hold_id", "kind", "units",
            "units_basis", "ledger_cost_basis", "evidence_digest", "hold_fence_epoch",
            "consumer_lease_epoch", "ledger_store_id", "issued_at", "expires_at", "issuer_key_id",
            "issuer_ref", "revocation_ref", "payload_digest", "issuer_signature",
        }
        if set(payload) != expected_fields:
            raise ValueError("grant wire is malformed")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != _SCHEMA_VERSION:
            raise NotImplementedError("grant schema is unsupported")
        try:
            canonical = _canonical_bytes(payload)
        except RecursionError as exc:
            raise ValueError("grant wire is malformed") from exc
        if canonical != wire:
            raise ValueError("grant wire is not canonical")
        try:
            request = AdjustmentGrantRequest(
                principal=payload["principal"],
                run_id=payload["run_id"],
                hold_id=payload["hold_id"],
                kind=payload["kind"],
                units=payload["units"],
                units_basis=payload["units_basis"],
                ledger_cost_basis=payload["ledger_cost_basis"],
                evidence_digest=payload["evidence_digest"],
                hold_fence_epoch=payload["hold_fence_epoch"],
                consumer_lease_epoch=payload["consumer_lease_epoch"],
                ledger_store_id=payload["ledger_store_id"],
                issuer_ref=payload["issuer_ref"],
                revocation_ref=payload["revocation_ref"],
            )
            return cls.from_request(
                request,
                grant_id=payload["grant_id"],
                issued_at=_parse_timestamp(payload["issued_at"], "issued_at"),
                expires_at=_parse_timestamp(payload["expires_at"], "expires_at"),
                issuer_key_id=payload["issuer_key_id"],
                payload_digest=payload["payload_digest"],
                issuer_signature=payload["issuer_signature"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("grant wire is malformed") from exc


def _parse_timestamp(value: object, field_name: str) -> datetime:
    """Parse only the ratified six-digit UTC timestamp spelling."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} is malformed")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError(f"{field_name} is malformed") from exc
    if _timestamp(parsed, field_name) != value:
        raise ValueError(f"{field_name} is malformed")
    return parsed


@dataclass(frozen=True, slots=True)
class P5IssuanceAudit:
    """Opaque P5 proof retained at issuance without retaining the raw token."""

    grant_id: str
    approval_id: str
    approval_token_digest: str
    operator_evidence_digest: str
    approved_duration_seconds: int
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class _IssuerKey:
    """Active signing seed held only for the current process."""

    key_id: str
    seed: bytes
    seed_ref: str


class RotatingIssuerKeyring:
    """SQLite-backed public key registry with externally provisioned signing seeds."""

    def __init__(
        self,
        *,
        key_id: str,
        seed_ref: str,
        seed_provider: IssuerSeedProvider,
        store: SqliteGrantAuthorityStore,
    ) -> None:
        """Load a secret through the injected provider and initialize durable metadata."""
        _require_text(key_id, "issuer_key_id")
        _require_text(seed_ref, "seed_ref")
        seed = seed_provider.load_seed(seed_ref)
        if not isinstance(seed, bytes) or len(seed) != crypto_sign_SEEDBYTES:
            raise ValueError("issuer signing seed has an invalid length")
        self._store = store
        self._seed_provider = seed_provider
        public_key, _secret_key = crypto_sign_seed_keypair(seed)
        store.ensure_active_key(
            IssuerKeyRecord(key_id, public_key, seed_ref, "active", None, None, None)
        )
        self._active = _IssuerKey(key_id, seed, seed_ref)

    @property
    def store(self) -> SqliteGrantAuthorityStore:
        """Expose the durable registry shared by issuance and verification."""
        return self._store

    @property
    def active_key_id(self) -> str:
        """Return the only key eligible to issue new grants."""
        return self._active.key_id

    def active_public_key(self) -> bytes:
        """Return the public key corresponding to the active signing generation."""
        record = self._store.key(self._active.key_id)
        if record is None or record.status != "active":
            raise ValueError("active issuer key is unavailable")
        return record.public_key

    def rotate(self, *, key_id: str, seed_ref: str, now: datetime) -> None:
        """Retire the former generation and activate a new unique signing key."""
        _require_text(key_id, "issuer_key_id")
        _require_text(seed_ref, "seed_ref")
        now = _utc_datetime(now, "rotation time")
        seed = self._seed_provider.load_seed(seed_ref)
        if not isinstance(seed, bytes) or len(seed) != crypto_sign_SEEDBYTES:
            raise ValueError("issuer signing seed has an invalid length")
        public_key, _ = crypto_sign_seed_keypair(seed)
        self._store.rotate_key(
            IssuerKeyRecord(key_id, public_key, seed_ref, "active", None, None, None),
            now=now,
        )
        self._active = _IssuerKey(key_id, seed, seed_ref)

    def ensure_current(self) -> None:
        """Adopt the durable active key when another authority rotated it.

        Several authorities may share one registry. Each reads the registry's
        active key before spending an approval, so a worker never signs with a
        generation another worker has already retired.
        """
        record = self._store.active_key()
        if record is None:
            raise ValueError("issuer key registry has no active key")
        if record.key_id == self._active.key_id:
            return
        seed = self._seed_provider.load_seed(record.seed_ref)
        if not isinstance(seed, bytes) or len(seed) != crypto_sign_SEEDBYTES:
            raise ValueError("issuer signing seed has an invalid length")
        public_key, _ = crypto_sign_seed_keypair(seed)
        if public_key != record.public_key:
            raise ValueError("provisioned issuer key does not match the durable active key")
        self._active = _IssuerKey(record.key_id, seed, record.seed_ref)

    def sign(self, body: bytes) -> tuple[str, str]:
        """Sign one canonical body with the current active Ed25519ph key."""
        key = self._active
        _public_key, signature = _sign(key.seed, body)
        return key.key_id, _b64encode(signature)

    def sign_effect_grant(self, body: bytes) -> tuple[str, str]:
        """Sign one v2 effect-grant body under its dedicated protocol domain."""
        self.ensure_current()
        key = self._active
        _public_key, signature = _sign_message(key.seed, _EFFECT_GRANT_DOMAIN, body)
        return key.key_id, _b64encode(signature)

    def sign_effect_grant_snapshot(self, build_body: Callable[[str], bytes]) -> tuple[bytes, str, str]:
        """Build and sign one v2 effect-grant body from a single key snapshot.

        The durable active key is refreshed once; its identifier is handed to
        ``build_body`` and the very same generation's seed signs the result, so a
        concurrent rotation can never pair one generation's identifier with
        another generation's signature. Returns ``(body, key_id, signature)``.
        """
        self.ensure_current()
        key = self._active
        body = build_body(key.key_id)
        _public_key, signature = _sign_message(key.seed, _EFFECT_GRANT_DOMAIN, body)
        return body, key.key_id, _b64encode(signature)

    def dispatch_active_key_id(self) -> str:
        """Return the current dispatch-signing key after validating its frozen wire grammar.

        Dispatch permits, finalizations, and issuer events use their own
        domain-separated signatures.  They may reuse the durable issuer-key
        registry, but never the adjustment-grant signature framing.
        """
        return self._current_dispatch_key().key_id

    def _current_dispatch_key(self) -> _IssuerKey:
        """Refresh durable state and return one immutable snapshot of the active key.

        Callers read the identifier and seed from this single object, so a
        concurrent ``rotate`` can never pair one generation's identifier with
        another generation's seed.
        """
        self.ensure_current()
        key = self._active
        dispatch_wire.validate_key_id(key.key_id)
        return key

    def sign_dispatch_permit(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign one validated dispatch-permit body with the active durable key only."""
        return dispatch_wire.sign_permit(self._dispatch_seed(key_id), body)

    def sign_dispatch_finalization(self, key_id: str, body: Mapping[str, object]) -> str:
        """Sign one validated dispatch-finalization body with the active durable key only."""
        return dispatch_wire.sign_finalization(self._dispatch_seed(key_id), body)

    def sign_dispatch_event(self, key_id: str, digest: str) -> str:
        """Sign one validated issuer-event digest with the active durable key only."""
        return dispatch_wire.sign_event(self._dispatch_seed(key_id), digest)

    def _dispatch_seed(self, key_id: str) -> bytes:
        """Return the active seed only for one exact dispatch signer operation.

        Refreshing before the comparison makes a rotation between a caller's
        key lookup and its signature request fail closed rather than minting a
        permit under a retired generation.
        """
        key = self._current_dispatch_key()
        if key_id != key.key_id:
            raise ValueError("dispatch signing key is not the active issuer key")
        return key.seed

    def verify(self, grant: AdjustmentGrant, *, now: datetime) -> bool:
        """Verify a signed grant against its exact key id without trial verification."""
        key = self._store.key(grant.issuer_key_id)
        if key is None or key.status == "revoked":
            return False
        if key.status == "retired" and key.retain_until is not None and now > key.retain_until:
            return False
        return _verify(key.public_key, grant.canonical_body(), _b64decode(grant.issuer_signature))

    def prune(self, *, now: datetime) -> tuple[str, ...]:
        """Prune expired durable grant references before eligible retired keys."""
        return self._store.prune(now=_utc_datetime(now, "prune time"))

    def retention_for(self, key_id: str) -> datetime | None:
        """Expose retention metadata for operational qualification and tests."""
        key = self._store.key(key_id)
        return None if key is None else key.retain_until

    def revoke_key(self, key_id: str) -> None:
        """Fail closed on a compromised retired key identifier."""
        self._store.revoke_key(key_id)


class PhylaxGrantAuthority:
    """Durable P5-backed issuer and verifier for immutable adjustment grants."""

    def __init__(
        self,
        *,
        keyring: RotatingIssuerKeyring,
        p5_approval: P5ApprovalAuthority,
        verifier_id: str = "phylax-primary",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Compose only the trusted P5 authority and active issuer-key lifecycle."""
        self._keyring = keyring
        self._p5_approval = p5_approval
        self._store = keyring.store
        _require_text(verifier_id, "verifier_id")
        self._verifier_id = verifier_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self._verifier = PhylaxGrantVerifier(
            store=self._store, verifier_id=verifier_id, clock=lambda: self._clock()
        )

    def issue(
        self,
        request: AdjustmentGrantRequest,
        *,
        authenticated_principal: str,
        operator_evidence_ref: str,
        approved_duration_seconds: int | None = None,
    ) -> AdjustmentGrant:
        """Mint one human-approved grant; duration is P5 output, never caller input."""
        _require_text(authenticated_principal, "authenticated_principal")
        if authenticated_principal != request.principal:
            raise ValueError("authenticated principal does not match grant principal")
        # Refresh the signing key from durable state BEFORE the single-use
        # approval is spent, so a concurrent rotation cannot strand it.
        self._keyring.ensure_current()
        grant_id = token_urlsafe(24)
        approval_intent = self._approval_intent(request, grant_id)
        preview = self._p5_approval.issue_preview(approval_intent)
        receipt = self._p5_approval.approve(
            preview.preview_id,
            operator_evidence_ref=operator_evidence_ref,
            approved_duration_seconds=approved_duration_seconds,
        )
        approval = self._p5_approval.consume(receipt, approval_intent)
        issued_at = self._now()
        expires_at = issued_at + timedelta(seconds=approval.approved_duration_seconds)
        issuer_key_id = self._keyring.active_key_id
        body = _grant_body(
            request,
            grant_id=grant_id,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_key_id=issuer_key_id,
        )
        payload_digest = hashlib.sha256(body).hexdigest()
        signed_key_id, issuer_signature = self._keyring.sign(body)
        if signed_key_id != issuer_key_id:
            raise ValueError("active issuer key changed during grant construction")
        grant = AdjustmentGrant.from_request(
            request,
            grant_id=grant_id,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_key_id=issuer_key_id,
            payload_digest=payload_digest,
            issuer_signature=issuer_signature,
        )
        self._store.record_issued(grant, self._audit(grant_id, receipt, approval))
        return grant

    def verify(self, wire: bytes) -> VerifiedGrant:
        """Verify durable issuance, signature, time and revocation before projection."""
        return self._verifier.verify(wire)

    def revoke(self, grant_id: str) -> None:
        """Durably revoke a grant; a restart cannot make it valid again."""
        _require_text(grant_id, "grant_id")
        self._store.revoke(grant_id, revoked_at=self._now())

    def revoke_key(self, key_id: str) -> None:
        """Disable a retired key; rotate the active key before revoking it."""
        _require_text(key_id, "issuer_key_id")
        self._store.revoke_key(key_id)

    def revocation(self, grant_id: str) -> RevocationObservation:
        """Return a durable, timestamped revocation observation for transport."""
        return self._verifier.revocation(grant_id)

    def revocation_status(self, grant_id: str) -> RevocationObservation:
        """Compatibility spelling for the issuer-side transport operation."""
        return self.revocation(grant_id)

    def verifier_adapter(self) -> PhylaxAdjustmentGrantVerifier:
        """Return the narrow verify/revocation surface for composition wiring."""
        return PhylaxAdjustmentGrantVerifier(self._verifier)

    def dispatch_signer_adapter(self) -> DispatchIssuerSigner:
        """Return the narrow issuer signer for frozen dispatch wire domains.

        This exposes no seed, adjustment-grant issuance, P5 receipt, or
        revocation operation.  Grant admission remains the separately injected
        ``SignedGrantLookup`` port of the dispatch-permit store.
        """
        from .dispatch_composition import DispatchIssuerSigner

        return DispatchIssuerSigner(self._keyring)

    def issuance_audit(self, grant_id: str) -> P5IssuanceAudit | None:
        """Return the opaque P5 issuance evidence without exposing raw receipt tokens."""
        record = self._store.issuance_audit(grant_id)
        return None if record is None else P5IssuanceAudit(**record)

    def _approval_intent(self, request: AdjustmentGrantRequest, grant_id: str) -> P5ApprovalIntent:
        """Bind P5 approval to the exact server-minted grant target tuple."""
        return P5ApprovalIntent.from_preview(
            request.principal,
            {
                "objective": "authorize a phylax adjustment grant",
                "task_type": "adjustment-grant",
                "optimize_for": "safety",
                "preferred_device": "shared",
                "assignments": [
                    {
                        "consumer_lease_epoch": request.consumer_lease_epoch,
                        "evidence_digest": request.evidence_digest,
                        "grant_id": grant_id,
                        "hold_fence_epoch": request.hold_fence_epoch,
                        "hold_id": request.hold_id,
                        "kind": request.kind,
                        "ledger_cost_basis": request.ledger_cost_basis,
                        "ledger_store_id": request.ledger_store_id,
                        "principal": request.principal,
                        "run_id": request.run_id,
                        "units": request.units,
                        "units_basis": request.units_basis,
                    }
                ],
            },
            action=_GRANT_ACTION,
        )

    def _audit(
        self,
        grant_id: str,
        receipt: P5ApprovalReceipt,
        approval: P5ApprovalDecision,
    ) -> P5IssuanceAudit:
        """Record P5 evidence by digest only after its single successful consume."""
        return P5IssuanceAudit(
            grant_id=grant_id,
            approval_id=receipt.preview_id,
            approval_token_digest=hashlib.sha256(receipt.approval_token.encode("utf-8")).hexdigest(),
            operator_evidence_digest=hashlib.sha256(
                approval.operator_evidence_ref.encode("utf-8")
            ).hexdigest(),
            approved_duration_seconds=approval.approved_duration_seconds,
            approved_at=approval.approved_at,
        )

    def _now(self) -> datetime:
        """Return the injected authority clock normalized to UTC."""
        return _utc_datetime(self._clock(), "authority clock")


class PhylaxGrantVerifier:
    """Verify grants using public keys and durable records, with no issuer secrets."""

    def __init__(
        self,
        *,
        store: GrantVerificationStore,
        verifier_id: str = "phylax-primary",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the verifier to a read-only store and a timestamp source."""
        _require_text(verifier_id, "verifier_id")
        self._store = store
        self._verifier_id = verifier_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(self, wire: bytes) -> VerifiedGrant:
        """Verify canonical wire, signature, durable issuance, time and revocation."""
        try:
            grant = AdjustmentGrant.from_wire(wire)
            try:
                now = _utc_datetime(self._clock(), "verifier clock")
            except (TypeError, ValueError) as exc:
                raise GrantRefusal(GrantRefusalReason.VERIFIER_UNAVAILABLE) from exc
            key = self._store.key(grant.issuer_key_id)
            if key is None or key.status == "revoked":
                raise GrantRefusal(GrantRefusalReason.GRANT_KEY_UNKNOWN)
            if key.status == "retired" and key.retain_until is not None and now > key.retain_until:
                raise GrantRefusal(GrantRefusalReason.GRANT_KEY_UNKNOWN)
            if not _verify(key.public_key, grant.canonical_body(), _b64decode(grant.issuer_signature)):
                raise GrantRefusal(GrantRefusalReason.GRANT_SIGNATURE_INVALID)
            if grant.issued_at > now + _FUTURE_ISSUANCE_SKEW:
                raise GrantRefusal(GrantRefusalReason.GRANT_FUTURE_DATED)
            if now >= grant.expires_at:
                raise GrantRefusal(GrantRefusalReason.GRANT_EXPIRED)
            if not self._store.is_issued(grant.grant_id, grant.payload_digest, wire):
                raise GrantRefusal(GrantRefusalReason.GRANT_MALFORMED)
            if self._store.is_revoked(grant.grant_id):
                raise GrantRefusal(GrantRefusalReason.GRANT_REVOKED)
            return VerifiedGrant(
                grant_id=grant.grant_id,
                principal=grant.principal,
                run_id=grant.run_id,
                hold_id=grant.hold_id,
                kind=grant.kind,
                units=grant.units,
                units_basis=grant.units_basis,
                ledger_cost_basis=grant.ledger_cost_basis,
                hold_fence_epoch=grant.hold_fence_epoch,
                consumer_lease_epoch=grant.consumer_lease_epoch,
                ledger_store_id=grant.ledger_store_id,
                issued_at=grant.issued_at,
                expires_at=grant.expires_at,
                payload_digest=grant.payload_digest,
                verifier_id=self._verifier_id,
            )
        except GrantRefusal:
            raise
        except NotImplementedError as exc:
            raise GrantRefusal(GrantRefusalReason.GRANT_SCHEMA_UNSUPPORTED) from exc
        except (sqlite3.Error, OSError) as exc:
            raise GrantRefusal(GrantRefusalReason.VERIFIER_UNAVAILABLE) from exc
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise GrantRefusal(GrantRefusalReason.GRANT_MALFORMED) from exc

    def revocation(self, grant_id: str) -> RevocationObservation:
        """Return a timestamped observation from the durable revocation index."""
        _require_text(grant_id, "grant_id")
        try:
            revoked = self._store.is_revoked(grant_id)
            observed_at = _utc_datetime(self._clock(), "verifier clock")
            return RevocationObservation(grant_id, revoked, observed_at)
        except (sqlite3.Error, OSError, TypeError, ValueError, AttributeError) as exc:
            raise GrantRefusal(GrantRefusalReason.VERIFIER_UNAVAILABLE) from exc

    def close(self) -> None:
        """Release a retained read-only store connection; never exposes issuer operations.

        A store that holds no connection (the issuer-side store, an injected test store)
        has nothing to release, so it is a no-op there. Safe to call more than once.
        """
        close = getattr(self._store, "close", None)
        if callable(close):
            close()


class PhylaxAdjustmentGrantVerifier:
    """Structural consumer adapter exposing no signing or grant-management operations."""

    def __init__(self, verifier: PhylaxGrantVerifier) -> None:
        """Bind only the public verification surface, not the issuer authority."""
        self._verifier = verifier

    def verify(self, wire: bytes) -> VerifiedGrant:
        """Return the minimal verified projection for the consumer port."""
        return self._verifier.verify(wire)

    def revocation(self, grant_id: str) -> RevocationObservation:
        """Return durable revocation state with its observation time."""
        return self._verifier.revocation(grant_id)

    def close(self) -> None:
        """Release retained verification resources during the consumer's shutdown."""
        self._verifier.close()
