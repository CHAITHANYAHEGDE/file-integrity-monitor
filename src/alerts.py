"""
alerts.py — Alert dataclass and console display for FIM.
"""
from __future__ import annotations


from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.logger import EventType, Severity


@dataclass
class Alert:
    """
    Represents a single FIM detection event.

    Kept as a pure data container — no business logic here.
    Separation of concerns: Alert stores what happened;
    the caller decides what to do (log, display, send).
    """
    event_type: EventType
    severity: Severity
    path: str
    details: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expected_hash: Optional[str] = None   # Baseline SHA-256
    actual_hash: Optional[str] = None     # Current SHA-256 (for modified files)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "event_type": self.event_type.value,
            "path": self.path,
            "details": self.details,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
        }

    def __str__(self) -> str:
        return (
            f"[{self.timestamp}] {self.severity.value} | "
            f"{self.event_type.value} | {self.path} | {self.details}"
        )
