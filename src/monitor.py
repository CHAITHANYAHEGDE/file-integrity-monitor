"""
monitor.py — Compare the current filesystem state against the FIM baseline.

Detection logic:
    1. MODIFIED: path exists in baseline AND on disk, but SHA-256 differs.
    2. DELETED:  path exists in baseline but NOT on disk.
    3. CREATED:  path exists on disk but NOT in baseline.
    4. UNCHANGED: path in baseline, SHA-256 matches — no alert generated.

Why SHA-256 and not just mtime?
    mtime can be set arbitrarily with `touch -t`. An attacker replacing a
    binary could preserve the original mtime. SHA-256 of content is the
    authoritative change detector.

Optional real-time mode uses the `watchdog` library (inotify/FSEvents/kqueue).
The polling fallback re-runs a full comparison on a configurable interval.
"""
from __future__ import annotations


import fnmatch
import os
import stat
from pathlib import Path
from typing import Optional

from src.alerts import Alert
from src.db import BaselineDB, FileRecord
from src.hasher import hash_file
from src.logger import EventType, Severity, TamperEvidentLogger


# Map event types to severities — mirrors fim_config.yaml for consistency
_SEVERITY_MAP = {
    EventType.FILE_CREATED: Severity.MEDIUM,
    EventType.FILE_MODIFIED: Severity.HIGH,
    EventType.FILE_DELETED: Severity.CRITICAL,
}


class Monitor:
    """
    Compares the live filesystem against the stored baseline and emits Alerts.

    Args:
        db: Initialised BaselineDB containing the baseline.
        logger: TamperEvidentLogger for audit trail.
        exclude_patterns: Glob patterns to ignore.
        severity_overrides: Optional dict to override default severities.
    """

    def __init__(
        self,
        db: BaselineDB,
        logger: TamperEvidentLogger,
        exclude_patterns: Optional[list[str]] = None,
        severity_overrides: Optional[dict[EventType, Severity]] = None,
    ) -> None:
        self.db = db
        self.logger = logger
        self.exclude_patterns: list[str] = exclude_patterns or []
        self._severity_map = {**_SEVERITY_MAP, **(severity_overrides or {})}

    def run_comparison(
        self,
        watch_paths: list[str | Path],
    ) -> list[Alert]:
        """
        Perform a one-shot comparison of watch_paths against the baseline.

        Returns:
            Sorted list of Alert objects (CRITICAL first).
        """
        alerts: list[Alert] = []

        # Collect current state of all monitored paths
        current_files: dict[str, FileRecord] = {}
        for root_path in watch_paths:
            root = Path(root_path).resolve()
            if not root.exists():
                continue
            for file_path in self._walk(root):
                record = self._snapshot(file_path)
                if record:
                    current_files[record.path] = record

        # Retrieve baseline
        baseline_records: dict[str, FileRecord] = {
            r.path: r for r in self.db.get_all()
        }

        # --- Detect MODIFIED and UNCHANGED ---
        for path, baseline_rec in baseline_records.items():
            current_rec = current_files.get(path)
            if current_rec is None:
                # DELETED
                alert = self._make_alert(
                    EventType.FILE_DELETED,
                    path,
                    f"File deleted. Last known SHA-256: {baseline_rec.sha256[:16]}...",
                    expected=baseline_rec.sha256,
                    actual=None,
                )
                alerts.append(alert)
                self._log_alert(alert)
            elif current_rec.sha256 != baseline_rec.sha256:
                # MODIFIED
                alert = self._make_alert(
                    EventType.FILE_MODIFIED,
                    path,
                    (
                        f"SHA-256 mismatch. "
                        f"Expected: {baseline_rec.sha256[:16]}... "
                        f"Got: {current_rec.sha256[:16]}..."
                    ),
                    expected=baseline_rec.sha256,
                    actual=current_rec.sha256,
                )
                alerts.append(alert)
                self._log_alert(alert)
            else:
                # UNCHANGED — log at DEBUG level, no Alert object
                self.logger.log(
                    Severity.LOW,
                    EventType.FILE_UNCHANGED,
                    f"Verified: {path}",
                )

        # --- Detect CREATED (in current but not in baseline) ---
        for path, current_rec in current_files.items():
            if path not in baseline_records:
                alert = self._make_alert(
                    EventType.FILE_CREATED,
                    path,
                    f"New file detected. SHA-256: {current_rec.sha256[:16]}...",
                    expected=None,
                    actual=current_rec.sha256,
                )
                alerts.append(alert)
                self._log_alert(alert)

        # Sort: CRITICAL → HIGH → MEDIUM → LOW
        _order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        alerts.sort(key=lambda a: _order.get(a.severity, 9))

        self.logger.log(
            Severity.LOW,
            EventType.SCAN_COMPLETED,
            f"Scan complete. {len(alerts)} alert(s) generated.",
        )
        return alerts

    def _make_alert(
        self,
        event_type: EventType,
        path: str,
        details: str,
        expected: Optional[str],
        actual: Optional[str],
    ) -> Alert:
        return Alert(
            event_type=event_type,
            severity=self._severity_map[event_type],
            path=path,
            details=details,
            expected_hash=expected,
            actual_hash=actual,
        )

    def _log_alert(self, alert: Alert) -> None:
        self.logger.log(alert.severity, alert.event_type, f"{alert.path} | {alert.details}")

    def _walk(self, root: Path):
        """Yield non-excluded regular files under root."""
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not self._is_excluded(d)]
            for fname in filenames:
                if not self._is_excluded(fname):
                    yield Path(dirpath) / fname

    def _is_excluded(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, pat) for pat in self.exclude_patterns)

    def _snapshot(self, path: Path) -> Optional[FileRecord]:
        """Take a lightweight snapshot of a file for comparison."""
        from src.db import now_utc_iso
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
            return None
