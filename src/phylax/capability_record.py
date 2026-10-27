"""Capability-record reader (``orama-capability-record/v1``): a pure, fail-closed parser.

Phylax only consumes the record; it never writes one and has no signing path. Every
failure mode (missing, unreadable, wrong schema, missing or non-boolean bit, unknown
field, digest mismatch, a true bit with an unverifiable digest, a true bit without a
verified signature) yields every bit ``False`` plus a stable reason. Bits are independent: none is inferred from another.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Mapping

CAPABILITY_RECORD_SCHEMA: Final = "orama-capability-record/v1"
CAPABILITY_BITS: Final = (
    "serving", "effects", "transport", "continuation", "autonomous_settlement",
)
_MAX_RECORD_BYTES: Final = 8192
_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOP_KEYS: Final = frozenset(
    {"schema", "record_id", "issued_at", "issuer", "capabilities", "binds", "signature"}
)

REASON_OK: Final = "capability.ok"
REASON_MISSING: Final = "capability.record_missing"
REASON_UNREADABLE: Final = "capability.record_unreadable"
REASON_SCHEMA: Final = "capability.schema_unsupported"
REASON_INVALID: Final = "capability.record_invalid"
REASON_BIT: Final = "capability.bit_invalid"
REASON_DIGEST: Final = "capability.digest_mismatch"
REASON_DIGEST_UNVERIFIED: Final = "capability.digest_unverified"
REASON_UNSIGNED: Final = "capability.unsigned_enablement"


@dataclass(frozen=True, slots=True)
class EffectiveCapabilities:
    """The effective value of each independent bit and why it differs from the record."""

    serving: bool = False
    effects: bool = False
    transport: bool = False
    continuation: bool = False
    autonomous_settlement: bool = False
    valid: bool = False
    reason: str = REASON_MISSING

    def as_dict(self) -> dict[str, bool]:
        """Return the five effective bits by name (readiness output)."""
        return {name: getattr(self, name) for name in CAPABILITY_BITS}


DENY_ALL: Final = EffectiveCapabilities()


def _deny(reason: str) -> EffectiveCapabilities:
    """Return the all-false result carrying ``reason``."""
    return EffectiveCapabilities(reason=reason)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse JSON objects that repeat a key (an ambiguity an attacker could use)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _is_text(value: object) -> bool:
    """Return whether ``value`` is a non-blank string."""
    return isinstance(value, str) and bool(value.strip())


def _is_utc_stamp(value: object) -> bool:
    """Return whether ``value`` is an RFC3339 UTC timestamp ending in ``Z``."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def parse_capability_record(
    raw: bytes | str | Mapping[str, Any] | None,
    *,
    expected_binary_digest: str | None = None,
    expected_config_digest: str | None = None,
) -> EffectiveCapabilities:
    """Parse and validate a capability record into effective bits; never raises.

    ``None`` is a missing record. Digest expectations, when given, must equal the
    record's ``binds``; a mismatch denies every bit. When any bit is ``true`` both
    expected digests must be supplied: a missing one denies with
    ``capability.digest_unverified`` (an enablement is never trusted unbound). A supplied
    digest that differs is reported as a mismatch before any missing one. Because no
    signing path exists in R0-2, a record with any ``true`` bit is refused with ``capability.unsigned_enablement``
    whatever its ``signature`` says.
    """
    try:
        return _parse(raw, expected_binary_digest, expected_config_digest)
    except Exception:  # noqa: BLE001 - a reader must fail closed, never propagate
        return _deny(REASON_UNREADABLE)


def _parse(
    raw: bytes | str | Mapping[str, Any] | None,
    expected_binary_digest: str | None,
    expected_config_digest: str | None,
) -> EffectiveCapabilities:
    """Do the work of ``parse_capability_record``; may raise on hostile input."""
    if raw is None:
        return _deny(REASON_MISSING)
    if isinstance(raw, (bytes, bytearray, str)):
        data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        if len(data) > _MAX_RECORD_BYTES:
            return _deny(REASON_UNREADABLE)
        try:
            record = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
        except (ValueError, UnicodeError, RecursionError):
            return _deny(REASON_UNREADABLE)
    elif isinstance(raw, Mapping):
        record = dict(raw)
    else:
        return _deny(REASON_UNREADABLE)
    if not isinstance(record, dict):
        return _deny(REASON_UNREADABLE)
    if record.get("schema") != CAPABILITY_RECORD_SCHEMA:
        return _deny(REASON_SCHEMA)
    if set(record) != _TOP_KEYS:
        return _deny(REASON_INVALID)
    if not (_is_text(record["record_id"]) and _is_text(record["issuer"])
            and _is_utc_stamp(record["issued_at"])):
        return _deny(REASON_INVALID)
    caps, binds = record["capabilities"], record["binds"]
    if not isinstance(caps, dict) or set(caps) != set(CAPABILITY_BITS):
        return _deny(REASON_BIT)
    if any(type(caps[name]) is not bool for name in CAPABILITY_BITS):
        return _deny(REASON_BIT)
    if not isinstance(binds, dict) or set(binds) != {"binary_digest", "config_digest"}:
        return _deny(REASON_INVALID)
    if not all(isinstance(v, str) and _DIGEST_RE.fullmatch(v) for v in binds.values()):
        return _deny(REASON_INVALID)
    any_true = any(caps[name] for name in CAPABILITY_BITS)
    pairs = (
        (expected_binary_digest, binds["binary_digest"]),
        (expected_config_digest, binds["config_digest"]),
    )
    # Mismatch outranks unverified regardless of which digest is missing.
    if any(expected is not None and expected != actual for expected, actual in pairs):
        return _deny(REASON_DIGEST)
    if any_true and any(expected is None for expected, _ in pairs):
        return _deny(REASON_DIGEST_UNVERIFIED)
    signature = record["signature"]
    if signature is not None and not _is_text(signature):
        return _deny(REASON_INVALID)
    if any_true:
        # No verified operator signature path exists in R0-2: any enablement is refused.
        return _deny(REASON_UNSIGNED)
    return EffectiveCapabilities(valid=True, reason=REASON_OK)
