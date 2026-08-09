"""
logger.py — Tamper-evident log for FIM using HMAC-SHA256 chaining.

How tamper evidence works:
    Each log entry contains fixed-width fields joined by ASCII Unit Separator (\x1F):
        TIMESTAMP\x1FSEVERITY\x1FEVENT_TYPE\x1FDETAILS\x1FPREV_HMAC\x1FTHIS_HMAC

    THIS_HMAC = HMAC-SHA256(key, TIMESTAMP + SEVERITY + EVENT_TYPE + DETAILS + PREV_HMAC)

    ASCII \x1F (0x1F) is chosen as field separator because it is a non-printable
    control character that cannot appear in file paths or human-readable details,
    preventing the separator-collision bug that would occur with ' | ' in paths.

    This chains entries: modifying or deleting any entry breaks all subsequent
    HMACs. An attacker cannot silently remove a log entry without invalidating
    every entry that follows it.

Honest limitation documented here:
    The HMAC key is stored on the same host. A privileged attacker who has
    already compromised the system can read the key from memory or the process
    environment and forge log entries. This is a recognised limitation of
    host-local FIM — real enterprise systems forward logs to a remote
    SIEM over an encrypted channel with key management (HSM / KMS).
"""
from __future__ import annotations


import logging
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from src.hasher import compute_hmac, verify_hmac


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    BASELINE_CREATED = "BASELINE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    FILE_CREATED = "FILE_CREATED"
    FILE_UNCHANGED = "FILE_UNCHANGED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    LOG_VERIFIED = "LOG_VERIFIED"
    LOG_TAMPERED = "LOG_TAMPERED"


# ASCII Unit Separator (0x1F) as field delimiter.
# Cannot appear in file paths or human-readable text, preventing
# the separator-collision bug that arises from using ' | ' in paths.
_FIELD_SEP = "\x1F"
_GENESIS_HASH = "0" * 64  # Sentinel previous-HMAC for the first entry


class TamperEvidentLogger:
    """
    Writes HMAC-chained log entries to a file.

    Thread safety: NOT thread-safe. Single-threaded FIM runs only.
    For multi-threaded use, wrap writes in a threading.Lock().
    """

    def __init__(self, log_path: str | Path, key: bytes) -> None:
        self.log_path = Path(log_path)
        self._key = key
        self._prev_hmac: str = _GENESIS_HASH
        self._python_logger = logging.getLogger("fim")

        # Initialise Python stdlib logger for console output
        if not self._python_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
            self._python_logger.addHandler(handler)
            self._python_logger.setLevel(logging.DEBUG)

        # Resume chaining from existing log
        if self.log_path.exists():
            self._prev_hmac = self._read_last_hmac()

    def log(
        self,
        severity: Severity,
        event_type: EventType,
        details: str,
    ) -> None:
        """
        Write a single tamper-evident log entry.

        Args:
            severity: Alert severity level.
            event_type: Category of the event.
            details: Human-readable event description.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        # Build the authenticated payload (everything before THIS_HMAC)
        payload = _FIELD_SEP.join(
            [timestamp, severity.value, event_type.value, details, self._prev_hmac]
        )
        this_hmac = compute_hmac(self._key, payload)

        line = f"{payload}{_FIELD_SEP}{this_hmac}\n"

        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

        self._prev_hmac = this_hmac

        # Echo to console via stdlib logger
        log_level = {
            Severity.LOW: logging.INFO,
            Severity.MEDIUM: logging.WARNING,
            Severity.HIGH: logging.WARNING,
            Severity.CRITICAL: logging.CRITICAL,
        }[severity]
        self._python_logger.log(log_level, "[%s] %s: %s", event_type.value, severity.value, details)

    def verify_integrity(self) -> tuple[bool, list[int]]:
        """
        Walk every log entry and verify its HMAC chain.

        Returns:
            (all_valid, list_of_tampered_line_numbers)
            An empty tampered list means the log is intact.

        Complexity: O(n) where n = number of log lines.
        """
        if not self.log_path.exists():
            return True, []

        tampered_lines: list[int] = []
        prev_hmac = _GENESIS_HASH

        with self.log_path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                line = raw_line.rstrip("\n")
                parts = line.split(_FIELD_SEP)
                if len(parts) != 6:
                    tampered_lines.append(line_no)
                    continue

                timestamp, severity, event_type, details, stored_prev, stored_hmac = parts
                # Reconstruct payload and verify
                payload = _FIELD_SEP.join(
                    [timestamp, severity, event_type, details, stored_prev]
                )
                if not verify_hmac(self._key, payload, stored_hmac):
                    tampered_lines.append(line_no)
                    continue
                if stored_prev != prev_hmac:
                    tampered_lines.append(line_no)
                    continue

                prev_hmac = stored_hmac

        return len(tampered_lines) == 0, tampered_lines

    def _read_last_hmac(self) -> str:
        """Extract the HMAC of the last line to continue the chain."""
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                last_line = line.rstrip("\n")
        if not last_line:
            return _GENESIS_HASH
        parts = last_line.split(_FIELD_SEP)
        return parts[-1] if len(parts) == 6 else _GENESIS_HASH
