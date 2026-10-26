"""Strict, P5-backed v2 authority for one durable effect operation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from secrets import token_urlsafe
from typing import Callable, Final, Protocol

from nacl.bindings import crypto_sign_BYTES

from .adjustment_grant import (
    GrantVerificationStore,
    P5IssuanceAudit,
    RotatingIssuerKeyring,
    _EFFECT_GRANT_DOMAIN,
    _FUTURE_ISSUANCE_SKEW,
    _MAX_SAFE_INTEGER,
    _b64decode,
    _canonical_bytes,
    _parse_timestamp,
    _require_digest,
    _require_safe_integer,
    _require_text,
    _utc_datetime,
    _verify_message,
)
from .grant_store import SqliteGrantAuthorityStore
from .p5_approval import P5ApprovalAuthority, P5ApprovalDecision, P5ApprovalIntent, P5ApprovalReceipt

_SCHEMA_VERSION: Final = 2
_PURPOSE: Final = "effect"
_ACTION: Final = "phylax.effect_grant.issue"
_MAX_TEXT_BYTES: Final = 1_024


class EffectGrantRefusalReason(StrEnum):
    """The shared closed verification vocabulary for v2 effect grants."""

    GRANT_MALFORMED = "grant.malformed"
    GRANT_SCHEMA_UNSUPPORTED = "grant.schema_unsupported"
    GRANT_KEY_UNKNOWN = "grant.key_unknown"
    GRANT_SIGNATURE_INVALID = "grant.signature_invalid"
    GRANT_EXPIRED = "grant.expired"
    GRANT_FUTURE_DATED = "grant.future_dated"
    GRANT_REVOKED = "grant.revoked"
    VERIFIER_UNAVAILABLE = "verifier.unavailable"


class EffectGrantRefusal(Exception):
    """A closed reason that is safe to pass across the consumer boundary."""

    def __init__(self, reason: EffectGrantRefusalReason) -> None:
        """Keep refusal construction constrained to the shared vocabulary."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class EffectGrantRequest:
    """Authenticated, immutable target facts for exactly one effect authority."""

    principal: str
    run_id: str
    operation_id: str
    request_digest: str
    effect_class: str
    ledger_store_id: str
    consumer_lease_epoch: int
    second_approval_ref: str
    issuer_ref: str
    revocation_ref: str

    def __post_init__(self) -> None:
        """Reject ambiguous targets before P5 can approve or consume anything."""
        for name in (
            "principal", "run_id", "operation_id", "effect_class", "ledger_store_id",
            "issuer_ref", "revocation_ref",
        ):
            value = getattr(self, name)
            _require_text(value, name)
            if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
                raise ValueError(f"{name} exceeds {_MAX_TEXT_BYTES} bytes")
        _require_digest(self.request_digest, "request_digest")
        _require_safe_integer(self.consumer_lease_epoch, "consumer_lease_epoch", minimum=1)
        if not isinstance(self.second_approval_ref, str) or len(self.second_approval_ref.encode("utf-8")) > _MAX_TEXT_BYTES:
            raise ValueError("second_approval_ref is invalid")
        if self.second_approval_ref and any(not 0x21 <= ord(char) <= 0x7e for char in self.second_approval_ref):
            raise ValueError("second_approval_ref must be a canonical identifier")


def _body(request: EffectGrantRequest, *, grant_id: str, issued_at: datetime, expires_at: datetime, issuer_key_id: str) -> bytes:
    """Encode the exact 17 signed v2 fields; digest and signature remain outer fields."""
    return _canonical_bytes({
        "schema_version": _SCHEMA_VERSION, "purpose": _PURPOSE, "grant_id": grant_id,
        "principal": request.principal, "run_id": request.run_id, "operation_id": request.operation_id,
        "request_digest": request.request_digest, "effect_class": request.effect_class, "use_limit": 1,
        "ledger_store_id": request.ledger_store_id, "consumer_lease_epoch": request.consumer_lease_epoch,
        "second_approval_ref": request.second_approval_ref, "issued_at": _stamp(issued_at),
        "expires_at": _stamp(expires_at), "issuer_key_id": issuer_key_id,
        "issuer_ref": request.issuer_ref, "revocation_ref": request.revocation_ref,
    })


def _stamp(value: datetime) -> str:
    """Use the exact six-digit UTC representation shared by the frozen grant wires."""
    return _utc_datetime(value, "timestamp").strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True, slots=True)
class EffectGrant:
    """One signed, single-use effect grant with the ratified 19-field wire shape."""

    request: EffectGrantRequest
    grant_id: str
    issued_at: datetime
    expires_at: datetime
    issuer_key_id: str
    payload_digest: str
    issuer_signature: str

    def __post_init__(self) -> None:
        """Verify internal structural and digest invariants before serialization."""
        _require_text(self.grant_id, "grant_id")
        _require_text(self.issuer_key_id, "issuer_key_id")
        _utc_datetime(self.issued_at, "issued_at")
        if _utc_datetime(self.expires_at, "expires_at") <= self.issued_at:
            raise ValueError("expires_at must follow issued_at")
        _require_digest(self.payload_digest, "payload_digest")
        if len(_b64decode(self.issuer_signature)) != crypto_sign_BYTES:
            raise ValueError("issuer_signature is invalid")
        if self.payload_digest != hashlib.sha256(self.canonical_body()).hexdigest():
            raise ValueError("payload_digest does not match effect-grant body")

    def canonical_body(self) -> bytes:
        """Return exactly the bytes covered by the v2 digest and signature."""
        return _body(self.request, grant_id=self.grant_id, issued_at=self.issued_at, expires_at=self.expires_at, issuer_key_id=self.issuer_key_id)

    def to_wire(self) -> bytes:
        """Return the canonical exact-field JSON wire record."""
        payload = json.loads(self.canonical_body())
        payload.update(payload_digest=self.payload_digest, issuer_signature=self.issuer_signature)
        return _canonical_bytes(payload)

    @classmethod
    def from_wire(cls, wire: bytes) -> "EffectGrant":
        """Parse only canonical v2 effect records; every other family is refused first."""
        if not isinstance(wire, bytes) or not wire or len(wire) > 65_536:
            raise ValueError("effect grant wire is malformed")
        try:
            payload = json.loads(wire.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
            raise ValueError("effect grant wire is malformed") from error
        if not isinstance(payload, dict) or _canonical_bytes(payload) != wire:
            raise ValueError("effect grant wire is malformed")
        if type(payload.get("schema_version")) is not int or payload["schema_version"] != _SCHEMA_VERSION:
            raise NotImplementedError("effect grant schema is unsupported")
        if payload.get("purpose") != _PURPOSE:
            raise ValueError("effect grant purpose is malformed")
        expected = {
            "schema_version", "purpose", "grant_id", "principal", "run_id", "operation_id",
            "request_digest", "effect_class", "use_limit", "ledger_store_id", "consumer_lease_epoch",
            "second_approval_ref", "issued_at", "expires_at", "issuer_key_id", "issuer_ref",
            "revocation_ref", "payload_digest", "issuer_signature",
        }
        if set(payload) != expected or type(payload["use_limit"]) is not int or payload["use_limit"] != 1:
            raise ValueError("effect grant wire is malformed")
        try:
            request = EffectGrantRequest(
                principal=payload["principal"], run_id=payload["run_id"], operation_id=payload["operation_id"],
                request_digest=payload["request_digest"], effect_class=payload["effect_class"],
                ledger_store_id=payload["ledger_store_id"], consumer_lease_epoch=payload["consumer_lease_epoch"],
                second_approval_ref=payload["second_approval_ref"], issuer_ref=payload["issuer_ref"], revocation_ref=payload["revocation_ref"],
            )
            return cls(request, payload["grant_id"], _parse_timestamp(payload["issued_at"], "issued_at"), _parse_timestamp(payload["expires_at"], "expires_at"), payload["issuer_key_id"], payload["payload_digest"], payload["issuer_signature"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("effect grant wire is malformed") from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys before interpreting signed JSON."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class VerifiedEffectGrant:
    """The public, verified projection consumed by Oramasys and nothing else."""

    grant_id: str
    principal: str
    run_id: str
    operation_id: str
    request_digest: str
    effect_class: str
    use_limit: int
    ledger_store_id: str
    consumer_lease_epoch: int
    second_approval_ref: str
    issued_at: datetime
    expires_at: datetime
    payload_digest: str
    verifier_id: str


class EffectGrantVerifier:
    """Read-only v2 verifier; it exposes no seed, issuance, or generic signing."""

    def __init__(self, *, store: GrantVerificationStore, verifier_id: str = "phylax-primary", clock: Callable[[], datetime] | None = None) -> None:
        """Bind public issuance records and a trusted clock without acquiring signing powers."""
        self._store, self._verifier_id, self._clock = store, verifier_id, clock or (lambda: datetime.now(UTC))

    def verify(self, wire: bytes) -> VerifiedEffectGrant:
        """Verify live consumer authority; expired grants always refuse."""
        return self._verify(wire, allow_expired=False)

    def verify_for_admission(self, wire: bytes) -> VerifiedEffectGrant:
        """Authenticate durable grant facts while leaving expiry disposition to the permit store."""
        return self._verify(wire, allow_expired=True)

    def _verify(self, wire: bytes, *, allow_expired: bool) -> VerifiedEffectGrant:
        """Verify canonical wire, issuer key, signature, issuance, time and revocation.

        Malformed wire and validation errors are ``GRANT_MALFORMED``; store, file and
        invalid-clock failures are ``VERIFIER_UNAVAILABLE`` so a broken verifier is
        distinguishable from a bad grant.
        """
        try:
            grant = EffectGrant.from_wire(wire)
            try:
                now = _utc_datetime(self._clock(), "verifier clock")
            except (TypeError, ValueError) as error:
                raise EffectGrantRefusal(EffectGrantRefusalReason.VERIFIER_UNAVAILABLE) from error
            key = self._store.key(grant.issuer_key_id)
            if key is None or key.status == "revoked":
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_KEY_UNKNOWN)
            if key.status == "retired" and key.retain_until is not None and now > key.retain_until:
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_KEY_UNKNOWN)
            if not _verify_message(key.public_key, _b64decode(grant.issuer_signature), _EFFECT_GRANT_DOMAIN, grant.canonical_body()):
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_SIGNATURE_INVALID)
            if grant.issued_at > now + _FUTURE_ISSUANCE_SKEW:
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_FUTURE_DATED)
            if not allow_expired and now >= grant.expires_at:
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_EXPIRED)
            if not self._store.is_issued(grant.grant_id, grant.payload_digest, wire):
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_MALFORMED)
            if self._store.is_revoked(grant.grant_id):
                raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_REVOKED)
            request = grant.request
            return VerifiedEffectGrant(grant.grant_id, request.principal, request.run_id, request.operation_id, request.request_digest, request.effect_class, 1, request.ledger_store_id, request.consumer_lease_epoch, request.second_approval_ref, grant.issued_at, grant.expires_at, grant.payload_digest, self._verifier_id)
        except EffectGrantRefusal:
            raise
        except NotImplementedError as error:
            raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_SCHEMA_UNSUPPORTED) from error
        except (sqlite3.Error, OSError) as error:
            raise EffectGrantRefusal(EffectGrantRefusalReason.VERIFIER_UNAVAILABLE) from error
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise EffectGrantRefusal(EffectGrantRefusalReason.GRANT_MALFORMED) from error

    def close(self) -> None:
        """Release an owned read-only store without exposing authority operations."""
        close = getattr(self._store, "close", None)
        if callable(close):
            close()


class PhylaxEffectGrantVerifier:
    """Structural public adapter for the consumer-owned effect verifier port."""

    def __init__(self, verifier: EffectGrantVerifier) -> None:
        """Bind only public verification and lifecycle operations."""
        self._verifier = verifier

    def verify(self, wire: bytes) -> VerifiedEffectGrant:
        """Return a verified v2 effect projection or a closed refusal."""
        return self._verifier.verify(wire)

    def close(self) -> None:
        """Release verification resources at serving shutdown."""
        self._verifier.close()


class EffectGrantAuthority:
    """P5-backed issuer for v2 effect grants and its matching public verifier."""

    def __init__(self, *, keyring: RotatingIssuerKeyring, p5_approval: P5ApprovalAuthority, verifier_id: str = "phylax-primary", clock: Callable[[], datetime] | None = None) -> None:
        """Compose durable key custody, P5 decisions and a matching public verifier."""
        self._keyring, self._p5, self._store = keyring, p5_approval, keyring.store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._verifier = EffectGrantVerifier(store=self._store, verifier_id=verifier_id, clock=self._clock)

    def issue(self, request: EffectGrantRequest, *, authenticated_principal: str, operator_evidence_ref: str, approved_duration_seconds: int | None = None) -> EffectGrant:
        """Issue one human-approved, single-use effect grant for its exact operation."""
        if authenticated_principal != request.principal:
            raise ValueError("authenticated principal does not match effect grant principal")
        # This release qualifies only the single-approval inert class. Never
        # attest a second approval without an authority that verifies its record.
        if request.second_approval_ref:
            raise ValueError("second approval verification is unavailable")
        if request.effect_class != "inert.simulation":
            raise ValueError("effect class is not qualified")
        self._keyring.ensure_current()
        grant_id = token_urlsafe(24)
        intent = P5ApprovalIntent.from_preview(request.principal, {"objective": "authorize one phylax effect grant", "task_type": "effect-grant", "optimize_for": "safety", "preferred_device": "shared", "assignments": [{"grant_id": grant_id, "principal": request.principal, "run_id": request.run_id, "operation_id": request.operation_id, "request_digest": request.request_digest, "effect_class": request.effect_class, "consumer_lease_epoch": request.consumer_lease_epoch, "ledger_store_id": request.ledger_store_id}]}, action=_ACTION)
        preview = self._p5.issue_preview(intent)
        receipt = self._p5.approve(preview.preview_id, operator_evidence_ref=operator_evidence_ref, approved_duration_seconds=approved_duration_seconds)
        decision = self._p5.consume(receipt, intent)
        issued_at = _utc_datetime(self._clock(), "authority clock")
        expires_at = issued_at + timedelta(seconds=decision.approved_duration_seconds)
        body, key_id, signature = self._keyring.sign_effect_grant_snapshot(
            lambda issuer_key_id: _body(request, grant_id=grant_id, issued_at=issued_at, expires_at=expires_at, issuer_key_id=issuer_key_id)
        )
        grant = EffectGrant(request, grant_id, issued_at, expires_at, key_id, hashlib.sha256(body).hexdigest(), signature)
        self._store.record_issued(grant, P5IssuanceAudit(grant_id, receipt.preview_id, hashlib.sha256(receipt.approval_token.encode()).hexdigest(), hashlib.sha256(decision.operator_evidence_ref.encode()).hexdigest(), decision.approved_duration_seconds, decision.approved_at))
        return grant

    def verify(self, wire: bytes) -> VerifiedEffectGrant:
        """Verify a v2 effect grant without opening a second authority path."""
        return self._verifier.verify(wire)

    def revoke(self, grant_id: str) -> None:
        """Durably revoke one issued effect grant."""
        self._store.revoke(grant_id, revoked_at=_utc_datetime(self._clock(), "authority clock"))


class EffectGrantLookup:
    """Resolve issuer admission facts exclusively from durably issued, verified v2 grants."""

    def __init__(self, store: SqliteGrantAuthorityStore, verifier: EffectGrantVerifier) -> None:
        """Bind the lookup to the issuer's own durable index and matching verifier."""
        self._store, self._verifier = store, verifier

    def get(self, grant_id: str):
        """Return signed grant facts; unavailable or invalid authority always refuses."""
        from .dispatch_permit_store import GrantFacts
        try:
            wire = self._store.issued_wire(grant_id)
        except (sqlite3.Error, OSError) as error:
            raise EffectGrantRefusal(EffectGrantRefusalReason.VERIFIER_UNAVAILABLE) from error
        if wire is None:
            return None
        try:
            grant = self._verifier.verify_for_admission(wire)
        except EffectGrantRefusal as error:
            if error.reason is not EffectGrantRefusalReason.GRANT_REVOKED:
                raise
            parsed = EffectGrant.from_wire(wire)
            return GrantFacts(parsed.payload_digest, parsed.request.operation_id, parsed.request.request_digest, parsed.request.ledger_store_id, parsed.expires_at, True, False)
        return GrantFacts(grant.payload_digest, grant.operation_id, grant.request_digest, grant.ledger_store_id, grant.expires_at, False, False)
