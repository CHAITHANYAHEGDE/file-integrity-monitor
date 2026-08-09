"""
test_hasher.py — Unit tests for SHA-256 hashing and HMAC utilities.

Test protocol per function:
  1. True positive     — correct computation on known input
  2. True negative     — different inputs produce different output
  3. Edge case         — empty file, empty string
  4. Malformed input   — non-existent path, wrong types
  5. False-positive    — verify no accidental collisions on similar inputs
  6. Failure handling  — permission error, directory instead of file
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.hasher import (
    compute_hmac,
    generate_hmac_key,
    hash_file,
    hash_string,
    verify_hmac,
)

# ─── hash_file ───────────────────────────────────────────────────────────────

class TestHashFile:
    def test_true_positive_known_content(self, tmp_path):
        """SHA-256 of 'hello\n' is a well-known value."""
        f = tmp_path / "hello.txt"
        f.write_bytes(b"hello\n")
        # Known SHA-256 for b"hello\n"
        expected = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        assert hash_file(f) == expected

    def test_true_negative_different_content(self, tmp_path):
        """Two files with different content must have different hashes."""
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("content A")
        f2.write_text("content B")
        assert hash_file(f1) != hash_file(f2)

    def test_edge_case_empty_file(self, tmp_path):
        """SHA-256 of empty file is a fixed known value."""
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        # SHA-256("") = e3b0...
        assert hash_file(f).startswith("e3b0c44298fc1c149afb")

    def test_edge_case_large_file(self, tmp_path):
        """Chunked reading should handle files larger than CHUNK_SIZE."""
        f = tmp_path / "large.bin"
        f.write_bytes(b"x" * (1024 * 1024))  # 1 MB
        digest = hash_file(f)
        assert len(digest) == 64
        assert digest.islower()

    def test_malformed_file_not_found(self, tmp_path):
        """FileNotFoundError raised for missing file."""
        with pytest.raises(FileNotFoundError):
            hash_file(tmp_path / "ghost.txt")

    def test_failure_directory_raises(self, tmp_path):
        """Passing a directory should raise IsADirectoryError."""
        with pytest.raises(IsADirectoryError):
            hash_file(tmp_path)

    def test_false_positive_similar_names_different_content(self, tmp_path):
        """Files with similar names but different content must have different hashes."""
        f1 = tmp_path / "config.yaml"
        f2 = tmp_path / "config.yml"
        f1.write_text("key: value1")
        f2.write_text("key: value2")
        assert hash_file(f1) != hash_file(f2)

    def test_same_content_different_path_same_hash(self, tmp_path):
        """Same content in different files must produce the same hash (content-based)."""
        f1 = tmp_path / "copy1.txt"
        f2 = tmp_path / "copy2.txt"
        f1.write_text("identical")
        f2.write_text("identical")
        assert hash_file(f1) == hash_file(f2)


# ─── compute_hmac / verify_hmac ──────────────────────────────────────────────

class TestHMAC:
    def setup_method(self):
        self.key = b"test_key_32_bytes_exactly_here!!"
        self.message = "2024-01-01T00:00:00 | HIGH | FILE_MODIFIED | /etc/passwd | abc123"

    def test_true_positive_hmac_verifies(self):
        """HMAC computed and then verified with same key/message should pass."""
        h = compute_hmac(self.key, self.message)
        assert verify_hmac(self.key, self.message, h) is True

    def test_true_negative_wrong_key_fails(self):
        """HMAC verified with a different key must return False."""
        h = compute_hmac(self.key, self.message)
        wrong_key = b"wrong_key_32_bytes_exactly_here!"
        assert verify_hmac(wrong_key, self.message, h) is False

    def test_true_negative_tampered_message(self):
        """Changing even one character in the message must invalidate HMAC."""
        h = compute_hmac(self.key, self.message)
        tampered = self.message[:-1] + "X"
        assert verify_hmac(self.key, tampered, h) is False

    def test_edge_case_empty_message(self):
        """Empty string should still produce a valid HMAC."""
        h = compute_hmac(self.key, "")
        assert verify_hmac(self.key, "", h) is True
        assert len(h) == 64

    def test_edge_case_unicode_message(self):
        """Unicode in message should be handled via UTF-8 encoding."""
        msg = "détection | 日本語 | CRITICAL"
        h = compute_hmac(self.key, msg)
        assert verify_hmac(self.key, msg, h) is True

    def test_false_positive_similar_messages_different_hmac(self):
        """Nearly identical messages must produce different HMACs."""
        msg1 = "FILE_MODIFIED | /etc/passwd"
        msg2 = "FILE_MODIFIED | /etc/shadow"
        h1 = compute_hmac(self.key, msg1)
        h2 = compute_hmac(self.key, msg2)
        assert h1 != h2

    def test_malformed_wrong_hmac_type(self):
        """Passing wrong type for expected_hmac should raise TypeError or return False."""
        h = compute_hmac(self.key, self.message)
        # verify_hmac compares strings — passing non-string should error gracefully
        with pytest.raises((TypeError, AttributeError)):
            verify_hmac(self.key, self.message, 12345)  # type: ignore

    def test_hmac_deterministic(self):
        """Same key + message always produces same HMAC (deterministic)."""
        h1 = compute_hmac(self.key, self.message)
        h2 = compute_hmac(self.key, self.message)
        assert h1 == h2


# ─── generate_hmac_key ───────────────────────────────────────────────────────

class TestGenerateKey:
    def test_returns_32_bytes(self):
        key = generate_hmac_key()
        assert len(key) == 32

    def test_different_each_call(self):
        """Keys must be unique across calls (CSPRNG)."""
        keys = {generate_hmac_key() for _ in range(10)}
        assert len(keys) == 10

    def test_key_is_bytes(self):
        assert isinstance(generate_hmac_key(), bytes)


# ─── hash_string ─────────────────────────────────────────────────────────────

class TestHashString:
    def test_known_value(self):
        """SHA-256('abc') is a well-known constant."""
        result = hash_string("abc")
        assert result == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_empty_string(self):
        result = hash_string("")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        assert hash_string("test") == hash_string("test")
