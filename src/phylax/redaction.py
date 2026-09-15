"""Phylax redaction: policy-owned scrubbing before records leave a boundary.

GatewayLifecycle's ``PhylaxPort`` requires ``redact(details)`` before any
progress event or ledger row escapes the dispatch boundary. Phylax owns the
redaction policy; callers only pass key/value pairs and receive redacted
copies. Original mappings are never mutated.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

# Key fragments whose values are always redacted regardless of format.
_SENSITIVE_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "private_key",
    "credential",
)

# URL query strings commonly carry keys; keep scheme/host/port, drop the rest.
_URL_QUERY_RE = re.compile(r"^(?P<base>[a-z][a-z0-9+.-]*://[^?]*)(\?.*)?$", re.IGNORECASE)

_REDACTED = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    folded = key.casefold()
    return any(fragment in folded for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        match = _URL_QUERY_RE.match(value)
        if match:
            return f"{match.group('base')}?{_REDACTED}"
        return value
    return value


def redact_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Return a redacted copy of *details* (never mutating the input).

    Sensitive keys get ``[REDACTED]`` values; URL-shaped string values keep
    only scheme/host/port. Non-sensitive values pass through unchanged.
    """
    return {
        key: _REDACTED if _is_sensitive_key(key) else _redact_value(value)
        for key, value in details.items()
    }
