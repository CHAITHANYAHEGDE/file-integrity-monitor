"""
test_monitor.py — Tests for file change detection logic.

Covers the four detection cases:
  - MODIFIED  (SHA-256 differs)
  - DELETED   (file no longer on disk)
  - CREATED   (file not in baseline)
  - UNCHANGED (no changes)

Each case is tested with the 6-type protocol.
"""

import tempfile
from pathlib import Path

import pytest

from src.alerts import Alert
from src.db import BaselineDB, FileRecord, now_utc_iso
from src.hasher import generate_hmac_key, hash_file
from src.logger import EventType, Severity, TamperEvidentLogger
from src.monitor import Monitor


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def fim_env(tmp_path):
    """
    Creates a complete FIM environment:
    - A watch directory with test files
    - An initialised SQLite database
    - A TamperEvidentLogger
    - A Monitor instance
    """
    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()

    db_path = tmp_path / "test_baseline.db"
    log_path = tmp_path / "test.log"
    key = generate_hmac_key()

    db = BaselineDB(db_path)
    db.init()
    logger = TamperEvidentLogger(log_path, key)
    monitor = Monitor(db=db, logger=logger)

    return {
        "watch_dir": watch_dir,
        "db": db,
        "logger": logger,
        "monitor": monitor,
    }


def _seed_baseline(db: BaselineDB, file_path: Path) -> FileRecord:
    """Helper: hash a file and insert it into the baseline."""
    import stat, os
    s = file_path.stat()
    record = FileRecord(
        path=str(file_path),
        sha256=hash_file(file_path),
        size_bytes=s.st_size,
        mtime=s.st_mtime,
        permissions=oct(stat.S_IMODE(s.st_mode)),
        recorded_at=now_utc_iso(),
    )
    db.upsert(record)
    return record


# ─── MODIFIED detection ───────────────────────────────────────────────────────

class TestModifiedDetection:
    def test_true_positive_modified_file_detected(self, fim_env):
        """A file whose content changes after baselining must be flagged MODIFIED."""
        f = fim_env["watch_dir"] / "config.py"
        f.write_text("original content")
        _seed_baseline(fim_env["db"], f)

        # Simulate modification
        f.write_text("maliciously changed content")

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        modified = [a for a in alerts if a.event_type == EventType.FILE_MODIFIED]
        assert len(modified) == 1
        assert modified[0].path == str(f)
        assert modified[0].severity == Severity.HIGH

    def test_true_negative_unchanged_file_no_alert(self, fim_env):
        """A file that has not changed must NOT generate a MODIFIED alert."""
        f = fim_env["watch_dir"] / "readme.txt"
        f.write_text("untouched")
        _seed_baseline(fim_env["db"], f)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        modified = [a for a in alerts if a.event_type == EventType.FILE_MODIFIED]
        assert len(modified) == 0

    def test_edge_case_single_byte_change(self, fim_env):
        """Changing a single byte must trigger MODIFIED detection."""
        f = fim_env["watch_dir"] / "binary.bin"
        f.write_bytes(b"\x00" * 1024)
        _seed_baseline(fim_env["db"], f)

        # Flip one byte
        f.write_bytes(b"\x01" + b"\x00" * 1023)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        modified = [a for a in alerts if a.event_type == EventType.FILE_MODIFIED]
        assert len(modified) == 1

    def test_false_positive_mtime_change_no_content_change(self, fim_env):
        """Updating mtime without changing content must NOT trigger MODIFIED."""
        import os, time
        f = fim_env["watch_dir"] / "timestamps.txt"
        f.write_text("content stays the same")
        _seed_baseline(fim_env["db"], f)

        # Touch file to update mtime without changing content
        time.sleep(0.01)
        os.utime(str(f), None)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        modified = [a for a in alerts if a.event_type == EventType.FILE_MODIFIED]
        # SHA-256 is authoritative — mtime change alone must not trigger alert
        assert len(modified) == 0

    def test_malformed_baseline_record_with_wrong_hash(self, fim_env):
        """
        A baseline record with a corrupt stored hash must trigger MODIFIED
        when the actual file hash differs — not crash.
        """
        f = fim_env["watch_dir"] / "corrupt_baseline.txt"
        f.write_text("real content")
        # Manually insert a wrong hash into baseline
        import stat as st
        s = f.stat()
        record = FileRecord(
            path=str(f),
            sha256="a" * 64,  # Deliberately wrong hash
            size_bytes=s.st_size,
            mtime=s.st_mtime,
            permissions=oct(st.S_IMODE(s.st_mode)),
            recorded_at=now_utc_iso(),
        )
        fim_env["db"].upsert(record)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        modified = [a for a in alerts if a.event_type == EventType.FILE_MODIFIED]
        assert len(modified) == 1

    def test_failure_handling_unreadable_file(self, fim_env):
        """If a file becomes unreadable during scan, monitor must not crash."""
        f = fim_env["watch_dir"] / "locked.txt"
        f.write_text("original")
        _seed_baseline(fim_env["db"], f)

        # Remove read permission
        f.chmod(0o000)
        try:
            # Should not raise — unreadable files are skipped
            alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
            # File disappears from current scan → detected as DELETED (acceptable)
            # What matters is: no exception raised
        finally:
            f.chmod(0o644)  # Restore for cleanup


# ─── DELETED detection ────────────────────────────────────────────────────────

class TestDeletedDetection:
    def test_true_positive_deleted_file_detected(self, fim_env):
        """Deleting a baselined file must generate a DELETED CRITICAL alert."""
        f = fim_env["watch_dir"] / "important.conf"
        f.write_text("critical configuration")
        _seed_baseline(fim_env["db"], f)

        f.unlink()  # Delete the file

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        deleted = [a for a in alerts if a.event_type == EventType.FILE_DELETED]
        assert len(deleted) == 1
        assert deleted[0].severity == Severity.CRITICAL

    def test_true_negative_present_file_no_deleted_alert(self, fim_env):
        """A file still present must not generate a DELETED alert."""
        f = fim_env["watch_dir"] / "present.txt"
        f.write_text("still here")
        _seed_baseline(fim_env["db"], f)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        deleted = [a for a in alerts if a.event_type == EventType.FILE_DELETED]
        assert len(deleted) == 0

    def test_edge_case_multiple_deletions(self, fim_env):
        """Multiple deleted files must each generate their own alert."""
        files = [fim_env["watch_dir"] / f"file{i}.txt" for i in range(5)]
        for f in files:
            f.write_text("content")
            _seed_baseline(fim_env["db"], f)

        for f in files:
            f.unlink()

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        deleted = [a for a in alerts if a.event_type == EventType.FILE_DELETED]
        assert len(deleted) == 5


# ─── CREATED detection ───────────────────────────────────────────────────────

class TestCreatedDetection:
    def test_true_positive_new_file_detected(self, fim_env):
        """A file that appears after baselining must be flagged as CREATED."""
        # Baseline is empty — no files seeded
        new_file = fim_env["watch_dir"] / "unexpected.sh"
        new_file.write_text("#!/bin/bash\nrm -rf /")

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        created = [a for a in alerts if a.event_type == EventType.FILE_CREATED]
        assert len(created) == 1
        assert created[0].severity == Severity.MEDIUM

    def test_true_negative_baselined_file_not_flagged_as_new(self, fim_env):
        """A file already in the baseline must not be flagged as CREATED."""
        f = fim_env["watch_dir"] / "expected.txt"
        f.write_text("this was in the baseline")
        _seed_baseline(fim_env["db"], f)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        created = [a for a in alerts if a.event_type == EventType.FILE_CREATED]
        assert len(created) == 0

    def test_edge_case_empty_file_created(self, fim_env):
        """Even an empty file appearing after baselining must be detected."""
        empty = fim_env["watch_dir"] / "empty_new.txt"
        empty.write_bytes(b"")

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        created = [a for a in alerts if a.event_type == EventType.FILE_CREATED]
        assert len(created) == 1


# ─── UNCHANGED detection ─────────────────────────────────────────────────────

class TestUnchangedDetection:
    def test_no_alerts_for_unmodified_baseline(self, fim_env):
        """A clean filesystem with no changes must produce zero alerts."""
        for i in range(3):
            f = fim_env["watch_dir"] / f"stable{i}.txt"
            f.write_text(f"stable content {i}")
            _seed_baseline(fim_env["db"], f)

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        assert alerts == []

    def test_mixed_scenario_only_changed_files_alerted(self, fim_env):
        """With 3 unchanged and 1 modified file, only 1 alert expected."""
        stable = [fim_env["watch_dir"] / f"stable{i}.txt" for i in range(3)]
        for f in stable:
            f.write_text("stable")
            _seed_baseline(fim_env["db"], f)

        changed = fim_env["watch_dir"] / "changed.txt"
        changed.write_text("original")
        _seed_baseline(fim_env["db"], changed)
        changed.write_text("modified")

        alerts = fim_env["monitor"].run_comparison([fim_env["watch_dir"]])
        assert len(alerts) == 1
        assert alerts[0].event_type == EventType.FILE_MODIFIED
