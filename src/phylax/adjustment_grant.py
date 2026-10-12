"""Strict Phylax-issued adjustment grants with Ed25519ph attestations.

This module owns issuance, verification, revocation, and issuer-key lifecycle.
It deliberately does not consume a grant against a budget or decide whether a
ledger has remaining balance; that is an Oramasys-owned transaction.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from typing import Callable, Final, Literal

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

_DOMAIN: Final = b"phylax-adjustment-grant-v1\x00"
_SCHEMA_VERSION: Final = 1
_FUTURE_ISSUANCE_SKEW: Final = timedelta(seconds=60)
_RETIRED_KEY_FLOOR: Final = timedelta(hours=24)
_RETIRED_KEY_SKEW: Final = timedelta(seconds=60)
_UNIT_BASES: Final = frozenset({"steps", "elapsed_ms", "cost_microunits", "effect_attempts"})
_KINDS: Final = frozenset({"settle", "release"})


def _require_text(value: str, field_name: str) -> None:
    """Reject empty strings before they can enter a signed grant."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")


def _require_digest(value: str, field_name: str) -> None:
    """Require a lower-case SHA-256 hexadecimal digest."""
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{field_name} must be a lower-case SHA-256 digest")


def _utc_datetime(value: datetime, field_name: str) -> datetime:
    """Require a timezone-aware UTC datetime and normalize its representation."""
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
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("issuer_signature is invalid") from exc
    if _b64encode(decoded) != value:
        raise ValueError("issuer_signature is invalid")
    return decoded


def _canonical_bytes(body: dict[str, object]) -> bytes:
    """Serialize the fixed ASCII-keyed v1 body in its JCS-compatible subset.

    The grant schema contains no floats or caller-defined object keys. Python's
    compact UTF-8 JSON with lexicographic ASCII property ordering is therefore
    equivalent to RFC 8785 for this fixed field set; construction rejects every
    value outside that subset before this helper is reached.
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
        if self.kind not in _KINDS:
            raise ValueError("kind must be settle or release")
        if isinstance(self.units, bool) or not isinstance(self.units, int) or self.units <= 0:
            raise ValueError("units must be a positive integer")
        if self.units_basis not in _UNIT_BASES:
            raise ValueError("units_basis is invalid")
        _require_digest(self.evidence_digest, "evidence_digest")
        for field_name in ("hold_fence_epoch", "consumer_lease_epoch"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")


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
        if self.schema_version != _SCHEMA_VERSION:
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


@dataclass(frozen=True, slots=True)
class P5IssuanceAudit:
    """Opaque P5 proof retained at issuance without retaining the raw token."""

    grant_id: str
    approval_id: str
    approval_token_digest: str
    operator_evidence_ref: str
    approved_duration_seconds: int
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class RevocationStatus:
    """Issuer-owned revocation observation for a specific grant."""

    grant_id: str
    revoked: bool
    observed_at: datetime


@dataclass(slots=True)
class _IssuerKey:
    """Private in-memory signing material plus monotonic retirement metadata."""

    key_id: str
    seed: bytes
    public_key: bytes
    retired_at: datetime | None = None
    retain_until: datetime | None = None
    latest_live_expiry: datetime | None = None


class RotatingIssuerKeyring:
    """Minimal key lifecycle that never shortens a retired key's retention floor."""

    def __init__(self, *, key_id: str, seed: bytes) -> None:
        """Create the initial active Ed25519ph signing generation from a seed."""
        self._keys: dict[str, _IssuerKey] = {}
        self._active_key_id = ""
        self.rotate(key_id=key_id, seed=seed, now=datetime.now(UTC), initial=True)

    @property
    def active_key_id(self) -> str:
        """Return the only key eligible to issue new grants."""
        return self._active_key_id

    def active_public_key(self) -> bytes:
        """Return the public key corresponding to the active signing generation."""
        return self._keys[self._active_key_id].public_key

    def rotate(self, *, key_id: str, seed: bytes, now: datetime, initial: bool = False) -> None:
        """Retire the former generation and activate a new unique signing key."""
        _require_text(key_id, "issuer_key_id")
        now = _utc_datetime(now, "rotation time")
        if len(seed) != crypto_sign_SEEDBYTES:
            raise ValueError("issuer signing seed has an invalid length")
        if key_id in self._keys:
            raise ValueError("issuer_key_id already exists")
        if not initial:
            prior = self._keys[self._active_key_id]
            prior.retired_at = now
            required_until = now + _RETIRED_KEY_FLOOR
            if prior.latest_live_expiry is not None:
                required_until = max(required_until, prior.latest_live_expiry + _RETIRED_KEY_SKEW)
            prior.retain_until = max(prior.retain_until or required_until, required_until)
        public_key, _ = crypto_sign_seed_keypair(seed)
        self._keys[key_id] = _IssuerKey(key_id=key_id, seed=seed, public_key=public_key)
        self._active_key_id = key_id

    def sign(self, body: bytes) -> tuple[str, str]:
        """Sign one canonical body with the current active Ed25519ph key."""
        active = self._keys[self._active_key_id]
        _public_key, signature = _sign(active.seed, body)
        return active.key_id, _b64encode(signature)

    def verify(self, grant: AdjustmentGrant) -> bool:
        """Verify a signed grant against its exact key id without trial verification."""
        key = self._keys.get(grant.issuer_key_id)
        if key is None:
            return False
        return _verify(key.public_key, grant.canonical_body(), _b64decode(grant.issuer_signature))

    def record_issued(self, grant: AdjustmentGrant) -> None:
        """Extend the issuing key's live-grant index without ever shortening retention."""
        key = self._keys.get(grant.issuer_key_id)
        if key is None:
            raise ValueError("issuer_key_id is unknown")
        key.latest_live_expiry = max(key.latest_live_expiry or grant.expires_at, grant.expires_at)
        if key.retired_at is not None:
            required_until = max(
                key.retired_at + _RETIRED_KEY_FLOOR,
                key.latest_live_expiry + _RETIRED_KEY_SKEW,
            )
            key.retain_until = max(key.retain_until or required_until, required_until)

    def prune(self, *, now: datetime) -> tuple[str, ...]:
        """Remove only retired generations past their immutable retention and live expiry."""
        now = _utc_datetime(now, "prune time")
        removed: list[str] = []
        for key_id, key in tuple(self._keys.items()):
            if key_id == self._active_key_id or key.retain_until is None:
                continue
            if key.latest_live_expiry is not None and now <= key.latest_live_expiry:
                continue
            if now > key.retain_until:
                del self._keys[key_id]
                removed.append(key_id)
        return tuple(removed)

    def retention_for(self, key_id: str) -> datetime | None:
        """Expose retention metadata for operational qualification and tests."""
        key = self._keys.get(key_id)
        return None if key is None else key.retain_until


class PhylaxGrantAuthority:
    """P5-backed issuer and verifier for immutable adjustment grants."""

    def __init__(
        self,
        *,
        keyring: RotatingIssuerKeyring,
        p5_approval: P5ApprovalAuthority,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Compose only the trusted P5 authority and active issuer-key lifecycle."""
        self._keyring = keyring
        self._p5_approval = p5_approval
        self._clock = clock or (lambda: datetime.now(UTC))
        self._revoked: set[str] = set()
        self._issuance_audit: dict[str, P5IssuanceAudit] = {}

    def issue(
        self,
        request: AdjustmentGrantRequest,
        *,
        authenticated_principal: str,
        operator_evidence_ref: str,
    ) -> AdjustmentGrant:
        """Mint one human-approved grant; duration is P5 output, never caller input."""
        _require_text(authenticated_principal, "authenticated_principal")
        if authenticated_principal != request.principal:
            raise ValueError("authenticated principal does not match grant principal")
        grant_id = token_urlsafe(24)
        approval_intent = self._approval_intent(request, grant_id)
        preview = self._p5_approval.issue_preview(approval_intent)
        receipt = self._p5_approval.approve(
            preview.preview_id,
            operator_evidence_ref=operator_evidence_ref,
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
        self._keyring.record_issued(grant)
        self._issuance_audit[grant_id] = self._audit(grant_id, receipt, approval)
        return grant

    def verify(self, grant: AdjustmentGrant) -> None:
        """Verify signature, revocation, future skew, and live expiry fail-closed."""
        now = self._now()
        if grant.issued_at > now + _FUTURE_ISSUANCE_SKEW:
            raise ValueError("grant issued_at exceeds future skew tolerance")
        if now >= grant.expires_at:
            raise ValueError("grant is expired")
        if grant.grant_id in self._revoked:
            raise ValueError("grant is revoked")
        if not self._keyring.verify(grant):
            raise ValueError("grant issuer signature is invalid")

    def revoke(self, grant_id: str) -> None:
        """Mark a server-issued grant revoked; consumers obtain this through Telos later."""
        _require_text(grant_id, "grant_id")
        self._revoked.add(grant_id)

    def revocation_status(self, grant_id: str) -> RevocationStatus:
        """Return a timestamped local revocation observation for the grant id."""
        _require_text(grant_id, "grant_id")
        return RevocationStatus(grant_id, grant_id in self._revoked, self._now())

    def issuance_audit(self, grant_id: str) -> P5IssuanceAudit | None:
        """Return the opaque P5 issuance evidence without exposing raw receipt tokens."""
        return self._issuance_audit.get(grant_id)

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
            operator_evidence_ref=approval.operator_evidence_ref,
            approved_duration_seconds=approval.approved_duration_seconds,
            approved_at=approval.approved_at,
        )

    def _now(self) -> datetime:
        """Return the injected authority clock normalized to UTC."""
        return _utc_datetime(self._clock(), "authority clock")
