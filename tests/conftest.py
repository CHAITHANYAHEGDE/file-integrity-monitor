"""
conftest.py — Shared pytest fixtures and sys.path configuration.

Adds the project root to sys.path so `from src.hasher import ...` works
without installing the package.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
