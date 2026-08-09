"""
baseline.py — Scan a directory and create/update the FIM baseline.

Responsibilities:
- Walk a directory tree, excluding configured patterns
- Hash each file with SHA-256
- Collect metadata: size, mtime, permissions
- Store FileRecord entries into SQLite via BaselineDB

Design note on mtime:
    mtime (modification time) is included as a quick-change indicator,
    but it is NOT treated as authoritative. An attacker with file-system
    access can falsify mtime using `touch -t`. SHA-256 is the authoritative
    change detector; mtime is supplementary metadata only.
"""
from __future__ import annotations


import fnmatch
import os
import stat
from pathlib import Path
from typing import Callable, Optional

from src.db import BaselineDB, FileRecord, now_utc_iso
from src.hasher import hash_file
from src.logger import EventType, Severity, TamperEvidentLogger


class BaselineManager:
    """
    Creates and updates the FIM baseline.

    Args:
        db: Initialised BaselineDB instance.
        logger: TamperEvidentLogger for audit trail.
        exclude_patterns: List of glob patterns to skip (e.g. ["*.pyc", ".git"]).
    """

    def __init__(
        self,
        db: BaselineDB,
        logger: TamperEvidentLogger,
        exclude_patterns: Optional[list[str]] = None,
    ) -> None:
        self.db = db
        self.logger = logger
        self.exclude_patterns: list[str] = exclude_patterns or []

    def create_baseline(
        self,
        watch_paths: list[str | Path],
        clear_existing: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> int:
        """
        Walk all watch_paths, hash each file, and store in the baseline.

        Args:
            watch_paths: Directories or files to include.
            clear_existing: Wipe previous baseline before scanning.
            progress_callback: Optional function called with each file path.

        Returns:
            Number of files recorded in the baseline.
        """
        if clear_existing:
            self.db.clear()

        count = 0
        for root_path in watch_paths:
            root = Path(root_path).resolve()
            if not root.exists():
                self.logger.log(
                    Severity.HIGH,
                    EventType.BASELINE_CREATED,
                    f"Watch path does not exist: {root}",
                )
                continue

            for file_path in self._walk(root):
                record = self._make_record(file_path)
                if record is None:
                    continue
                self.db.upsert(record)
                count += 1
                if progress_callback:
                    progress_callback(str(file_path))

        self.db.set_metadata("baseline_created_at", now_utc_iso())
        self.db.set_metadata("baseline_file_count", str(count))

        self.logger.log(
            Severity.LOW,
            EventType.BASELINE_CREATED,
            f"Baseline created: {count} files recorded across {len(watch_paths)} path(s)",
        )
        return count

    def _walk(self, root: Path):
        """
        Yield all non-excluded regular files under root.
        Follows symlinks=False to avoid loops.
        """
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Filter excluded directories in-place (modifies os.walk traversal)
            dirnames[:] = [
                d for d in dirnames
                if not self._is_excluded(d)
            ]
            for fname in filenames:
                if not self._is_excluded(fname):
                    yield Path(dirpath) / fname

    def _is_excluded(self, name: str) -> bool:
        """Return True if name matches any exclusion glob pattern."""
        return any(fnmatch.fnmatch(name, pat) for pat in self.exclude_patterns)

    def _make_record(self, path: Path) -> Optional[FileRecord]:
        """
        Build a FileRecord for a single file.
        Returns None if the file is unreadable or has disappeared.
        """
        try:
            file_stat = path.stat()
            sha256 = hash_file(path)
            return FileRecord(
                path=str(path),
                sha256=sha256,
                size_bytes=file_stat.st_size,
                mtime=file_stat.st_mtime,
                permissions=oct(stat.S_IMODE(file_stat.st_mode)),
                recorded_at=now_utc_iso(),
            )
        except (FileNotFoundError, PermissionError, OSError):
            # File may have disappeared between walk and hash — not an error
            return None
