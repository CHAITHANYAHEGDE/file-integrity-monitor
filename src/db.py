"""
db.py — SQLite-backed baseline storage for FIM.

Design decisions:
- SQLite chosen over flat JSON: ACID transactions prevent partial writes
  from corrupting the baseline during an interrupted scan.
- WAL journal mode: improves concurrent read performance.
- Path stored as TEXT PRIMARY KEY: unique constraint prevents duplicate
  entries without an extra lookup.
- All queries use parameterised statements to prevent SQL injection —
  even though the input is internal, it's a security habit.
"""
from __future__ import annotations


import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional


@dataclass
class FileRecord:
    """Represents one file's snapshot in the baseline."""
    path: str
    sha256: str
    size_bytes: int
    mtime: float         # POSIX timestamp (os.stat().st_mtime)
    permissions: str     # Octal string, e.g. "0o644"
    recorded_at: str     # ISO-8601 UTC timestamp


SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    path         TEXT    PRIMARY KEY,
    sha256       TEXT    NOT NULL,
    size_bytes   INTEGER NOT NULL,
    mtime        REAL    NOT NULL,
    permissions  TEXT    NOT NULL,
    recorded_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class BaselineDB:
    """
    Manages the SQLite database storing the file baseline.

    Usage:
        db = BaselineDB("fim_baseline.db")
        db.init()
        db.upsert(record)
        records = db.get_all()
        db.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def init(self) -> None:
        """Create tables if they don't exist and configure the connection."""
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        """Flush and close the connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an atomic transaction."""
        assert self._conn is not None, "Database not initialised. Call init() first."
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def upsert(self, record: FileRecord) -> None:
        """
        Insert or replace a FileRecord in the baseline.
        Uses INSERT OR REPLACE to handle re-baselining an existing path.
        """
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO baseline
                    (path, sha256, size_bytes, mtime, permissions, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.path,
                    record.sha256,
                    record.size_bytes,
                    record.mtime,
                    record.permissions,
                    record.recorded_at,
                ),
            )

    def get(self, path: str) -> Optional[FileRecord]:
        """Retrieve a single FileRecord by path. Returns None if not found."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT * FROM baseline WHERE path = ?", (path,)
        ).fetchone()
        return _row_to_record(row) if row else None

    def get_all(self) -> list[FileRecord]:
        """Return all records in the baseline as a list."""
        assert self._conn is not None
        rows = self._conn.execute("SELECT * FROM baseline ORDER BY path").fetchall()
        return [_row_to_record(r) for r in rows]

    def delete(self, path: str) -> None:
        """Remove a record from the baseline (used when purging a deleted file)."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM baseline WHERE path = ?", (path,))

    def clear(self) -> None:
        """Wipe all records. Used when creating a fresh baseline."""
        with self._transaction() as conn:
            conn.execute("DELETE FROM baseline")

    def count(self) -> int:
        """Return total number of records in the baseline."""
        assert self._conn is not None
        row = self._conn.execute("SELECT COUNT(*) FROM baseline").fetchone()
        return int(row[0])

    def set_metadata(self, key: str, value: str) -> None:
        """Store a key-value pair in the metadata table (e.g., baseline timestamp)."""
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve a metadata value by key."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return str(row[0]) if row else None


def _row_to_record(row: sqlite3.Row) -> FileRecord:
    return FileRecord(
        path=row["path"],
        sha256=row["sha256"],
        size_bytes=row["size_bytes"],
        mtime=row["mtime"],
        permissions=row["permissions"],
        recorded_at=row["recorded_at"],
    )


def now_utc_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
