"""
hasher.py — SHA-256 file hashing and HMAC-SHA256 log signing utilities.

Design decisions:
- SHA-256 chosen over MD5/SHA-1: both are broken for collision resistance.
- SHA-256 is not a KDF — appropriate here because we're detecting change,
  not storing a secret. For passwords, use bcrypt/Argon2id.
- HMAC-SHA256 used for log tamper evidence: provides authentication of log
  entries without requiring asymmetric keys.
- Files read in chunks (8KB default) to handle large files without loading
  entire content into memory.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


CHUNK_SIZE: int = 8192  # 8 KB read buffer


def hash_file(path: str | Path) -> str:
    """
    Compute the SHA-256 digest of a file's content.

    Args:
        path: Absolute or relative path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest string (64 characters).

    Raises:
        FileNotFoundError: If the path does not exist.
        PermissionError: If the file is not readable.
        IsADirectoryError: If path points to a directory.
    """
    path = Path(path)
    sha256 = hashlib.sha256()

    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            sha256.update(chunk)

    return sha256.hexdigest()


def compute_hmac(key: bytes, message: str) -> str:
    """
    Compute HMAC-SHA256 of a message string using the given key.

    The HMAC provides message authentication: verifying the log entry was
    produced by someone holding the same key. It does NOT provide encryption.

    Args:
        key: Raw bytes key. Must be kept secret and consistent per FIM run.
        message: The log entry string to authenticate.

    Returns:
        Lowercase hex-encoded HMAC-SHA256 digest (64 characters).
    """
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, message: str, expected_hmac: str) -> bool:
    """
    Constant-time comparison of expected vs computed HMAC.

    Uses hmac.compare_digest() to prevent timing-based side-channel attacks.
    A naive `==` comparison could leak information about how many bytes match.

    Args:
        key: Same key used when computing the HMAC.
        message: The log entry string.
        expected_hmac: The stored HMAC to validate against.

    Returns:
        True if the HMAC matches; False otherwise.
    """
    actual = compute_hmac(key, message)
    return hmac.compare_digest(actual, expected_hmac)


def generate_hmac_key() -> bytes:
    """
    Generate a cryptographically secure 32-byte random key using os.urandom().

    os.urandom() reads from the OS CSPRNG (/dev/urandom on Linux/macOS),
    which is appropriate for key material. Do not use random.randbytes().

    Returns:
        32 bytes of random key material.
    """
    return os.urandom(32)


def hash_string(content: str) -> str:
    """
    Compute SHA-256 of a UTF-8 string. Useful for chaining log entries.

    Args:
        content: String to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
