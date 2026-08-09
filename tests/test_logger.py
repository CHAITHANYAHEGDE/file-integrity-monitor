"""
test_logger.py — Tests for the tamper-evident log chain.

Key tests:
  - Valid chain passes verification
  - Deleting a log entry breaks the chain
  - Modifying a log entry breaks the chain
  - Appending to the chain resumes correctly
"""

import tempfile
from pathlib import Path

import pytest

from src.hasher import generate_hmac_key
from src.logger import EventType, Severity, TamperEvidentLogger


@pytest.fixture
def log_env(tmp_path):
    key = generate_hmac_key()
    log_path = tmp_path / "test.log"
    logger = TamperEvidentLogger(log_path, key)
    return {"logger": logger, "log_path": log_path, "key": key}


class TestLoggerChain:
    def test_true_positive_fresh_log_verifies(self, log_env):
        """A fresh log with a few entries should verify cleanly."""
        lg = log_env["logger"]
        lg.log(Severity.LOW, EventType.SCAN_STARTED, "test start")
        lg.log(Severity.HIGH, EventType.FILE_MODIFIED, "/etc/passwd | changed")
        lg.log(Severity.CRITICAL, EventType.FILE_DELETED, "/bin/bash | deleted")

        ok, bad = lg.verify_integrity()
        assert ok is True
        assert bad == []

    def test_true_negative_deleted_entry_breaks_chain(self, log_env):
        """Removing a line from the log must break HMAC chain verification."""
        lg = log_env["logger"]
        for i in range(5):
            lg.log(Severity.LOW, EventType.FILE_UNCHANGED, f"file{i}.txt")

        # Tamper: remove line 2
        lines = log_env["log_path"].read_text().splitlines()
        lines.pop(2)  # Remove middle entry
        log_env["log_path"].write_text("\n".join(lines) + "\n")

        # Reload logger with same key to re-read file
        tampered_logger = TamperEvidentLogger(log_env["log_path"], log_env["key"])
        ok, bad = tampered_logger.verify_integrity()
        assert ok is False
        assert len(bad) > 0

    def test_true_negative_modified_entry_breaks_chain(self, log_env):
        """Altering a single character in a log entry must break verification."""
        lg = log_env["logger"]
        lg.log(Severity.HIGH, EventType.FILE_MODIFIED, "critical_file_changed")
        lg.log(Severity.LOW, EventType.SCAN_COMPLETED, "done")

        # Tamper: change one character in the first line's details field
        content = log_env["log_path"].read_text()
        tampered = content.replace("critical_file_changed", "critical_file_changeX")
        log_env["log_path"].write_text(tampered)

        tampered_logger = TamperEvidentLogger(log_env["log_path"], log_env["key"])
        ok, bad = tampered_logger.verify_integrity()
        assert ok is False

    def test_edge_case_empty_log_verifies(self, log_env):
        """An empty log file should verify as clean (nothing to check)."""
        ok, bad = log_env["logger"].verify_integrity()
        assert ok is True
        assert bad == []

    def test_edge_case_single_entry_verifies(self, log_env):
        """A log with a single entry must verify correctly."""
        log_env["logger"].log(Severity.LOW, EventType.BASELINE_CREATED, "one entry")
        ok, bad = log_env["logger"].verify_integrity()
        assert ok is True

    def test_false_positive_different_key_fails_verification(self, log_env, tmp_path):
        """Log written with key A must NOT verify with key B."""
        lg = log_env["logger"]
        lg.log(Severity.MEDIUM, EventType.FILE_CREATED, "new file")

        wrong_key = generate_hmac_key()
        assert wrong_key != log_env["key"]  # Sanity check — must be different

        wrong_key_logger = TamperEvidentLogger(log_env["log_path"], wrong_key)
        ok, bad = wrong_key_logger.verify_integrity()
        assert ok is False

    def test_malformed_input_corrupted_log_line(self, log_env):
        """A log file with a malformed line (missing fields) should not crash."""
        log_env["log_path"].write_text("this is not a valid log entry\n")
        ok, bad = log_env["logger"].verify_integrity()
        # Should return False, not raise an exception
        assert ok is False
        assert 1 in bad

    def test_chain_resumes_across_logger_instances(self, log_env):
        """A new logger instance with the same key should resume the HMAC chain."""
        key = log_env["key"]
        log_path = log_env["log_path"]

        logger1 = TamperEvidentLogger(log_path, key)
        logger1.log(Severity.LOW, EventType.SCAN_STARTED, "run 1")

        # Simulate restart — new logger instance, same key
        logger2 = TamperEvidentLogger(log_path, key)
        logger2.log(Severity.LOW, EventType.SCAN_COMPLETED, "run 2")

        # Verify entire chain with either logger
        ok, bad = logger2.verify_integrity()
        assert ok is True
