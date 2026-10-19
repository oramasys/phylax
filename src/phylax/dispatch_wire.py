"""Frozen E1 C2 wire encoding for dispatch permits, finalizations and issuer events.

This module is pure: no I/O, no clock, no database. It fixes the exact field sets, types,
canonical bytes, digests and signature framing that the issuer (Phylax) and any consumer
must share. Behaviour and rationale are in ``docs/e1-c2-permit-contract-freeze.md``; the
byte-exact examples are in ``docs/vectors/dispatch-permit-v1.json``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Final, Mapping

from nacl import exceptions as nacl_exceptions
from nacl.bindings import (
    crypto_sign_BYTES,
    crypto_sign_ed25519ph_final_create,
    crypto_sign_ed25519ph_final_verify,
    crypto_sign_ed25519ph_state,
    crypto_sign_ed25519ph_update,
    crypto_sign_seed_keypair,
)

SCHEMA_VERSION: Final = 1
MAX_SAFE_INTEGER: Final = (2**53) - 1
MAX_TEXT_BYTES: Final = 1_024
MAX_WIRE_BYTES: Final = 65_536

PERMIT_DOMAIN: Final = b"phylax-dispatch-permit-v1\x00"
FINALIZATION_DOMAIN: Final = b"phylax-dispatch-finalization-v1\x00"
EVENT_DOMAIN: Final = b"phylax-issuer-event-v1\x00"
GENESIS_EVENT_DIGEST: Final = "0" * 64

EVENT_KINDS: Final = frozenset({"revocation", "cascade", "finalization"})

PERMIT_LIFETIME_SECONDS: Final = 90
ISSUER_AUTHORITY_VERSION: Final = 1
CATCHUP_MAX_EVENTS: Final = 64

BINDING_FIELDS: Final = (
    "grant_id", "grant_payload_digest", "operation_id", "request_digest", "artifact_digest",
    "reservation_id", "ledger_store_id", "configuration_policy_epoch", "authority_epoch",
)

PERMIT_REFUSAL_CODES: Final = frozenset({
    "permit.conflict", "permit.attempt_aborted", "permit.grant_mismatch", "permit.grant_revoked",
    "permit.grant_expired", "permit.issuer_rolled_back", "permit.invalid_request",
})
FINALIZATION_REFUSAL_CODES: Final = frozenset({
    "finalization.conflict", "finalization.catchup_required", "finalization.permit_unusable",
    "finalization.grant_revoked", "finalization.issuer_rolled_back", "finalization.key_rotated",
    "finalization.invalid_request",
})
REFUSAL_CODES: Final = PERMIT_REFUSAL_CODES | FINALIZATION_REFUSAL_CODES
ABORT_OUTCOMES: Final = frozenset({"abort.recorded", "abort.already_aborted", "abort.admission_won"})

PERMIT_REQUEST_FIELDS: Final = (
    "grant_id", "grant_payload_digest", "operation_id", "request_digest", "artifact_digest",
    "reservation_id", "ledger_store_id", "configuration_policy_epoch", "authority_epoch",
    "consumer_acked_through", "attempt_id", "requested_at",
)
PERMIT_BODY_FIELDS: Final = tuple(sorted((
    "schema_version", *PERMIT_REQUEST_FIELDS, "permit_id", "revocation_version",
    "issuer_authority_version", "issued_at", "expires_at", "issuer_key_id",
)))
PERMIT_WIRE_FIELDS: Final = tuple(sorted((*PERMIT_BODY_FIELDS, "payload_digest", "issuer_signature")))

FINALIZATION_REQUEST_FIELDS: Final = (
    "permit_id", "permit_digest", "attempt_id", "reservation_id", "ledger_store_id",
    "consumer_acked_through", "authority_epoch", "requested_at",
)
FINALIZATION_BODY_FIELDS: Final = tuple(sorted((
    "schema_version", *FINALIZATION_REQUEST_FIELDS, "finalization_id", "revocation_version",
    "revocation_event_digest", "issued_at", "expires_at",
)))
FINALIZATION_WIRE_FIELDS: Final = tuple(sorted((*FINALIZATION_BODY_FIELDS, "issuer_signature")))

EVENT_WIRE_FIELDS: Final = (
    "body", "event_digest", "issuer_key_id", "kind", "previous_event_digest", "signature", "version",
)

_DIGEST_FIELDS: Final = frozenset({
    "grant_payload_digest", "request_digest", "artifact_digest", "permit_digest",
    "revocation_event_digest", "payload_digest",
})
_INTEGER_FIELDS: Final = frozenset({
    "configuration_policy_epoch", "authority_epoch", "consumer_acked_through",
    "revocation_version", "issuer_authority_version", "schema_version",
})
_POSITIVE_INTEGER_FIELDS: Final = frozenset({
    "configuration_policy_epoch", "authority_epoch", "issuer_authority_version",
})
_TIMESTAMP_FIELDS: Final = frozenset({"requested_at", "issued_at", "expires_at"})
_DIGEST_RE: Final = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def _is_digest(value: object) -> bool:
    """Return whether ``value`` is exactly 64 lowercase hexadecimal characters of text."""
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


class WireError(ValueError):
    """A wire object is malformed: wrong fields, wrong types or non-canonical bytes."""


def timestamp(value: datetime) -> str:
    """Encode an aware instant as the fixed six-digit UTC wire text."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise WireError("timestamp must be an aware datetime")
    normalized = value.astimezone(UTC)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.") + f"{normalized.microsecond:06d}Z"


def parse_timestamp(value: object) -> datetime:
    """Decode strict six-digit UTC wire text, refusing every other representation."""
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise WireError("timestamp must be six-digit UTC text")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise WireError("timestamp is not a real instant") from exc


def b64url_encode(value: bytes) -> str:
    """Encode unpadded base64url text."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: object) -> bytes:
    """Decode strict unpadded base64url text; padded or non-canonical text is refused."""
    if not isinstance(value, str):
        raise WireError("signature must be base64url text")
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (UnicodeEncodeError, ValueError) as exc:
        raise WireError("signature is not base64url") from exc
    if b64url_encode(decoded) != value:
        raise WireError("signature is not canonical unpadded base64url")
    return decoded


def canonical_bytes(obj: Mapping[str, object]) -> bytes:
    """Serialize ``obj`` as the one valid canonical JSON form (sorted keys, no whitespace)."""
    if not isinstance(obj, Mapping):
        raise WireError("canonical form requires an object")
    try:
        return json.dumps(
            dict(obj), ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WireError("value cannot be canonicalised") from exc


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _require_text(name: str, value: object) -> None:
    """Require non-blank text no longer than the frozen byte limit."""
    if not isinstance(value, str) or not value.strip():
        raise WireError(f"{name} must be non-blank text")
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        raise WireError(f"{name} exceeds {MAX_TEXT_BYTES} bytes")


def validate_fields(obj: Mapping[str, object], expected: tuple[str, ...]) -> None:
    """Require exactly the ``expected`` fields, each of its frozen type; no extras, no nulls."""
    if not isinstance(obj, Mapping):
        raise WireError("wire object must be a mapping")
    keys = set(obj)
    if keys != set(expected):
        missing, extra = sorted(set(expected) - keys), sorted(keys - set(expected))
        raise WireError(f"fields differ: missing={missing} extra={extra}")
    for name, value in obj.items():
        if name in _INTEGER_FIELDS:
            minimum = 1 if name in _POSITIVE_INTEGER_FIELDS else 0
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_SAFE_INTEGER:
                raise WireError(f"{name} must be a safe integer of at least {minimum}")
        elif name in _DIGEST_FIELDS:
            if not _is_digest(value):
                raise WireError(f"{name} must be 64 lowercase hexadecimal characters")
        elif name in _TIMESTAMP_FIELDS:
            parse_timestamp(value)
        elif name == "issuer_signature":
            if len(b64url_decode(value)) != crypto_sign_BYTES:
                raise WireError("issuer_signature has the wrong length")
        else:
            _require_text(name, value)
    if obj.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise WireError("schema_version must be the integer 1")


def binding_digest(request: Mapping[str, object]) -> str:
    """Return the retry-identity digest: SHA-256 of the canonical object of the nine binding fields.

    ``requested_at``, ``consumer_acked_through`` and ``attempt_id`` are excluded. The encoding is
    identical to the consumer repository's merged ``compute_binding_digest``.
    """
    missing = [name for name in BINDING_FIELDS if name not in request]
    if missing:
        raise WireError(f"binding fields missing: {missing}")
    return sha256_hex(canonical_bytes({name: request[name] for name in BINDING_FIELDS}))


def permit_body_bytes(body: Mapping[str, object]) -> bytes:
    """Return the canonical permit body (no digest, no signature): the digest and signature preimage."""
    validate_fields(body, PERMIT_BODY_FIELDS)
    return canonical_bytes(body)


def permit_payload_digest(body: Mapping[str, object]) -> str:
    """Return the permit's ``payload_digest``: SHA-256 of its canonical body bytes."""
    return sha256_hex(permit_body_bytes(body))


def permit_wire_bytes(body: Mapping[str, object], signature: str) -> bytes:
    """Return the canonical signed permit: the body plus ``payload_digest`` and ``issuer_signature``."""
    wire = {**body, "payload_digest": permit_payload_digest(body), "issuer_signature": signature}
    validate_fields(wire, PERMIT_WIRE_FIELDS)
    data = canonical_bytes(wire)
    if len(data) > MAX_WIRE_BYTES:
        raise WireError("permit exceeds the wire size limit")
    return data


def finalization_body_bytes(body: Mapping[str, object]) -> bytes:
    """Return the canonical finalization body (no signature): the signature preimage."""
    validate_fields(body, FINALIZATION_BODY_FIELDS)
    return canonical_bytes(body)


def finalization_digest(body: Mapping[str, object]) -> str:
    """Return the finalization digest recorded in the outbox: SHA-256 of its canonical body bytes."""
    return sha256_hex(finalization_body_bytes(body))


def finalization_wire_bytes(body: Mapping[str, object], signature: str) -> bytes:
    """Return the canonical signed finalization: the body plus ``issuer_signature``."""
    wire = {**body, "issuer_signature": signature}
    validate_fields(wire, FINALIZATION_WIRE_FIELDS)
    data = canonical_bytes(wire)
    if len(data) > MAX_WIRE_BYTES:
        raise WireError("finalization exceeds the wire size limit")
    return data


def event_digest(version: int, kind: str, body: Mapping[str, object], previous_event_digest: str) -> str:
    """Return an issuer event's digest: SHA-256 of the canonical wrapper object.

    The wrapper is ``{"body", "kind", "previous_event_digest", "version"}``. For a finalization
    the body is exactly ``{"finalization_id": ...}``; ``finalization_id`` alone is never the
    preimage. The signature is detached and is not part of the preimage.
    """
    if not isinstance(kind, str) or kind not in EVENT_KINDS:
        raise WireError("unknown event kind")
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= MAX_SAFE_INTEGER:
        raise WireError("event version must be a positive safe integer")
    if not _is_digest(previous_event_digest):
        raise WireError("previous_event_digest must be 64 lowercase hexadecimal characters")
    if not isinstance(body, Mapping):
        raise WireError("event body must be an object")
    if kind == "finalization":
        if set(body) != {"finalization_id"}:
            raise WireError("a finalization event body is exactly {finalization_id}")
        _require_text("finalization_id", body["finalization_id"])
    return sha256_hex(canonical_bytes({
        "body": dict(body), "kind": kind,
        "previous_event_digest": previous_event_digest, "version": version,
    }))


def finalization_event_digest(version: int, finalization_id: str, previous_event_digest: str) -> str:
    """Return the digest of the finalization event for ``finalization_id`` at ``version``."""
    return event_digest(version, "finalization", {"finalization_id": finalization_id}, previous_event_digest)


def _sign(seed: bytes, *chunks: bytes) -> bytes:
    """Return an RFC 8032 Ed25519ph signature over the concatenated message chunks."""
    _public_key, secret_key = crypto_sign_seed_keypair(seed)
    state = crypto_sign_ed25519ph_state()
    for chunk in chunks:
        crypto_sign_ed25519ph_update(state, chunk)
    return crypto_sign_ed25519ph_final_create(state, secret_key)


def _verify(public_key: bytes, signature: bytes, *chunks: bytes) -> bool:
    """Return True only if the Ed25519ph signature verifies over the message chunks."""
    state = crypto_sign_ed25519ph_state()
    for chunk in chunks:
        crypto_sign_ed25519ph_update(state, chunk)
    try:
        return crypto_sign_ed25519ph_final_verify(state, signature, public_key)
    except nacl_exceptions.BadSignatureError:
        return False


def sign_permit(seed: bytes, body: Mapping[str, object]) -> str:
    """Sign a permit body (Ed25519ph over the permit domain and the canonical body)."""
    return b64url_encode(_sign(seed, PERMIT_DOMAIN, permit_body_bytes(body)))


def verify_permit(public_key: bytes, body: Mapping[str, object], signature: str) -> bool:
    """Verify a permit signature over exactly the domain-separated canonical body."""
    return _verify(public_key, b64url_decode(signature), PERMIT_DOMAIN, permit_body_bytes(body))


def sign_finalization(seed: bytes, body: Mapping[str, object]) -> str:
    """Sign a finalization body (Ed25519ph over the finalization domain and the canonical body)."""
    return b64url_encode(_sign(seed, FINALIZATION_DOMAIN, finalization_body_bytes(body)))


def verify_finalization(public_key: bytes, body: Mapping[str, object], signature: str) -> bool:
    """Verify a finalization signature over exactly the domain-separated canonical body."""
    return _verify(public_key, b64url_decode(signature), FINALIZATION_DOMAIN, finalization_body_bytes(body))


def sign_event(seed: bytes, digest: str) -> str:
    """Sign an event digest (Ed25519ph over the event domain and the 64 ASCII hex characters)."""
    if not _is_digest(digest):
        raise WireError("event digest must be 64 lowercase hexadecimal characters")
    return b64url_encode(_sign(seed, EVENT_DOMAIN, digest.encode("ascii")))


def verify_event(public_key: bytes, digest: str, signature: str) -> bool:
    """Verify an event signature over exactly the domain-separated digest text."""
    if not _is_digest(digest):
        return False
    return _verify(public_key, b64url_decode(signature), EVENT_DOMAIN, digest.encode("ascii"))
