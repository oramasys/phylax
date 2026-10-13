"""Race-tolerant WAL activation shared by Phylax's SQLite stores."""

from __future__ import annotations

import sqlite3
import time


def enable_wal(connection: sqlite3.Connection, *, timeout: float) -> None:
    """Switch a database to WAL, retrying while another first-time opener holds the lock.

    SQLite does not apply the connection busy timeout to the journal-mode switch of a
    brand-new database, so two workers opening it together can see "database is locked"
    even though the switch is idempotent. Retry only that condition, only until the
    configured timeout elapses, and re-raise anything else.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as error:
            if "locked" not in str(error) and "busy" not in str(error):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
