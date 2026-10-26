"""Redacted verifier evidence: counts of public reason codes over a window.

Evidence is monitoring only. Recording and export are isolated from verification: a
failure here is caught and counted, and nothing in this module can read or change a
capability bit or a verification result. Events hold a time, a scope label and a public
code; never a grant id, key id, path or payload.
"""

from __future__ import annotations

import threading
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Final, Mapping

EVIDENCE_SCHEMA: Final = "phylax-verifier-evidence/v1"
_MAX_EVENTS: Final = 10_000
_SCOPES: Final = frozenset({"adjustment", "effect", "revocation"})


@dataclass(frozen=True, slots=True)
class ExportOutcome:
    """Result of one export attempt; ``error`` is only an exception class name."""

    ok: bool
    error: str | None = None


class EvidenceLog:
    """Bounded in-memory event log producing redacted window summaries."""

    def __init__(self, max_events: int = _MAX_EVENTS) -> None:
        """Start empty; failures of the sink are counted in ``export_failures``.

        ``max_events`` bounds memory; events evicted past it are counted, and a summary
        whose window may have lost events says so instead of looking complete.
        """
        self._max_events = max_events
        self._events: deque[tuple[datetime, str, str]] = deque()
        self._dropped = 0
        self._last_dropped_at: datetime | None = None
        self._lock = threading.Lock()
        self.export_failures = 0

    def record(self, at: datetime, scope: str, code: str) -> None:
        """Append one event; ``scope`` and ``code`` must come from closed vocabularies."""
        if scope not in _SCOPES:
            return
        with self._lock:
            if len(self._events) >= self._max_events:
                evicted_at = self._events.popleft()[0]
                self._dropped += 1
                if self._last_dropped_at is None or evicted_at > self._last_dropped_at:
                    self._last_dropped_at = evicted_at
            self._events.append((at, scope, str(code)))

    def summary(self, start: datetime, end: datetime) -> dict[str, object]:
        """Return counts by scope and code for events with ``start <= at < end``.

        ``complete`` is false when an event at or after ``start`` has been evicted, so
        ``total`` and ``counts`` are then a lower bound. ``dropped_total`` is the lifetime
        eviction count and ``retained_from`` the oldest retained event time (or None).
        """
        with self._lock:
            events = [e for e in self._events if start <= e[0] < end]
            dropped = self._dropped
            complete = self._last_dropped_at is None or self._last_dropped_at < start
            retained_from = self._events[0][0].isoformat() if self._events else None
        counts: Counter[tuple[str, str]] = Counter((s, c) for _, s, c in events)
        return {
            "schema": EVIDENCE_SCHEMA,
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "total": len(events),
            "complete": complete,
            "dropped_total": dropped,
            "retained_from": retained_from,
            "counts": {f"{s}:{c}": n for (s, c), n in sorted(counts.items())},
        }


def safe_export(
    log: EvidenceLog,
    sink: Callable[[Mapping[str, object]], object] | None,
    start: datetime,
    end: datetime,
) -> ExportOutcome:
    """Hand a window summary to ``sink``; catch and report any failure, never raise.

    The sink receives a fresh dict, so mutating it cannot reach the log. A failing sink
    increments ``log.export_failures`` and is reported as the exception class name only.
    """
    if sink is None:
        return ExportOutcome(True)
    try:
        sink(log.summary(start, end))
    except BaseException as exc:  # noqa: BLE001 - monitoring must never escape
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        log.export_failures += 1
        return ExportOutcome(False, type(exc).__name__)
    return ExportOutcome(True)
