"""Tests for race-tolerant WAL activation."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from phylax.sqlite_wal import enable_wal


class _LockedThenFree:
    """Connection double that reports a lock a fixed number of times, then succeeds."""

    def __init__(self, failures: int, message: str = "database is locked") -> None:
        """Record how many attempts fail and with which SQLite message."""
        self.failures = failures
        self.message = message
        self.calls = 0

    def execute(self, sql: str) -> None:
        """Raise the configured lock error until the failure budget is spent."""
        self.calls += 1
        if self.calls <= self.failures:
            raise sqlite3.OperationalError(self.message)


def test_wal_activation_retries_a_transient_lock() -> None:
    """A lock held by another first-time opener is retried until it clears."""
    connection = _LockedThenFree(failures=3)
    enable_wal(connection, timeout=5.0)  # type: ignore[arg-type]
    assert connection.calls == 4


def test_wal_activation_gives_up_after_the_timeout() -> None:
    """A lock that never clears surfaces the original error once the timeout passes."""
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        enable_wal(_LockedThenFree(failures=10**6), timeout=0.05)  # type: ignore[arg-type]


def test_wal_activation_does_not_swallow_other_errors() -> None:
    """Only lock contention is retried; any other SQLite error is raised immediately."""
    connection = _LockedThenFree(failures=1, message="disk I/O error")
    with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
        enable_wal(connection, timeout=5.0)  # type: ignore[arg-type]
    assert connection.calls == 1


def test_wal_activation_switches_a_real_database(tmp_path: Path) -> None:
    """A fresh database file ends up in WAL mode."""
    connection = sqlite3.connect(tmp_path / "wal.db")
    enable_wal(connection, timeout=1.0)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    connection.close()
