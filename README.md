# File Integrity Monitor (FIM)

A host-based file integrity monitoring system that detects unauthorized file modifications, deletions, and creations using SHA-256 content hashing and an HMAC-SHA256 tamper-evident audit log.

---

## Problem Statement

An attacker who gains access to a system often modifies files — replacing binaries, altering configurations, or installing persistence mechanisms. A File Integrity Monitor answers the question: *"Has anything on this filesystem changed since we last trusted it?"*

SHA-256 hashing of file content provides a cryptographically strong change detector. Unlike filesystem metadata (mtime, size), SHA-256 cannot be silently forged without detection.

---

## Security Objective

Detect post-compromise file modifications on a monitored host by comparing current SHA-256 digests against a trusted baseline, and maintain a tamper-evident audit log of all detected changes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI (fim.py)                          │
│    baseline | scan | verify | watch                      │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
┌────────▼──────┐ ┌──────▼──────┐ ┌─────▼──────────┐
│  BaselineManager│ │   Monitor   │ │ TamperEvident  │
│  (baseline.py)  │ │(monitor.py) │ │ Logger         │
│                 │ │             │ │ (logger.py)    │
│ - Walk dirs     │ │ - MODIFIED  │ │                │
│ - SHA-256 hash  │ │ - DELETED   │ │ HMAC-SHA256    │
│ - Collect meta  │ │ - CREATED   │ │ chain per entry│
│ - Store SQLite  │ │ - UNCHANGED │ │                │
└───────┬─────────┘ └──────┬──────┘ └────────────────┘
        │                  │
┌───────▼──────────────────▼──┐
│        BaselineDB            │
│        (db.py / SQLite)      │
│                              │
│  path | sha256 | size |      │
│  mtime | perms | recorded_at │
└──────────────────────────────┘
```

**Data flow:**
1. `baseline` command → BaselineManager walks directories → hashes each file → stores FileRecord in SQLite
2. `scan` command → Monitor reads baseline from SQLite → hashes current files → compares SHA-256
3. Every event → TamperEvidentLogger writes HMAC-chained entry to audit log
4. `verify` command → Logger re-reads each entry, recomputes HMAC chain, reports any breaks

---

## Features

| Feature | Implementation |
|---|---|
| SHA-256 file hashing | `hashlib.sha256`, chunked 8KB reads |
| Baseline storage | SQLite with ACID transactions, WAL mode |
| Modification detection | SHA-256 content comparison (not mtime) |
| Deletion detection | Baseline path not found on disk |
| Creation detection | Disk path not in baseline |
| HMAC-chained audit log | HMAC-SHA256 over each entry linking to previous |
| Exclusion patterns | Glob matching (`.pyc`, `.DS_Store`, etc.) |
| JSON report output | `--output report.json` |
| Real-time polling | `watch` command with configurable interval |
| CLI | Click-based with config file + flag overrides |

---

## Technologies

- Python 3.9+
- `hashlib` (SHA-256) — stdlib
- `hmac` (HMAC-SHA256) — stdlib
- `sqlite3` (baseline storage) — stdlib
- `click` (CLI framework)
- `watchdog` (real-time filesystem events, optional)
- `pytest` (test suite)

---

## Installation

```bash
git clone https://github.com/yourusername/project3-fim.git
cd project3-fim

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### 1. Create a baseline

```bash
# Export an HMAC key to continue the log chain across runs
export FIM_HMAC_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")

python3 src/fim.py baseline --path ./examples/watch_dir
```

### 2. Scan for changes

```bash
python3 src/fim.py scan
```

### 3. Simulate a change and re-scan

```bash
echo "modified" >> ./examples/watch_dir/sample.txt
python3 src/fim.py scan
```

### 4. Verify log integrity

```bash
python3 src/fim.py verify
```

### 5. Continuous monitoring

```bash
python3 src/fim.py watch --interval 10
```

---

## Example Output

```
[FIM] Creating baseline for: ['./examples/watch_dir']
  Hashing: /path/to/examples/watch_dir/sample.txt
  Hashing: /path/to/examples/watch_dir/config.yaml
✓ Baseline created: 2 file(s) recorded.

# After modifying a file:

============================================================
  1 INTEGRITY ALERT(S) DETECTED
============================================================

[HIGH] FILE_MODIFIED
  Path:    /path/to/examples/watch_dir/sample.txt
  Details: SHA-256 mismatch. Expected: a3f5d2c9b1e7... Got: 9c2b8f14a6d3...
  Expected SHA-256: a3f5d2c9b1e70a2...
  Actual   SHA-256: 9c2b8f14a6d30e1...
```

---

## Detection Methodology

### Why SHA-256 and not mtime?

`mtime` (file modification time) can be set arbitrarily:
```bash
touch -t 202001010000 /etc/passwd  # Restore original mtime
```

SHA-256 is computed from file **content** — it cannot be faked without changing the digest. This is the authoritative change indicator.

### Severity Classification

| Event | Severity | Rationale |
|---|---|---|
| File deleted | CRITICAL | Attacker may have removed a security tool or log |
| File modified | HIGH | Binary or config may be backdoored |
| File created | MEDIUM | Unauthorized file dropped (webshell, persistence) |
| File unchanged | LOW | Informational only |

### HMAC Chain

Each log entry is authenticated with HMAC-SHA256 covering all previous entries:

```
Entry 1: HMAC(key, T1 || SEV1 || EVT1 || DETAIL1 || GENESIS_HASH) = H1
Entry 2: HMAC(key, T2 || SEV2 || EVT2 || DETAIL2 || H1)           = H2
Entry 3: HMAC(key, T3 || SEV3 || EVT3 || DETAIL3 || H2)           = H3
```

Deleting Entry 2 makes H3 unverifiable. This prevents an attacker from silently removing evidence.

Field separator: ASCII `\x1F` (Unit Separator) — a non-printable control character that cannot appear in file paths or human-readable text.

---

## Threat Model

### What this protects against
- An attacker who modifies files **after** baselining and lacks root access to the FIM process
- Accidental file changes (configuration drift)
- Detection of new files dropped by malware

### What this does **not** protect against

> [!WARNING]
> **Key Storage Limitation**: The HMAC key is derived from the host environment. A privileged attacker with root access can read the key from the process environment and forge log entries.

This is an **honest, known limitation** of host-local FIM. Enterprise FIM systems address this through:

```
Local FIM agent
  → TLS-encrypted channel
  → Centralised log collector (Splunk/ELK SIEM)
  → Key management service (HashiCorp Vault / AWS KMS)
  → Immutable log storage (WORM storage)
```

Examples: Tripwire Enterprise, OSSEC/Wazuh, Qualys FIM.

### Attack surface
- The baseline database itself (if writable by attacker)
- The FIM binary (if replaced by attacker)
- The HMAC key in memory/environment
- Race conditions between walk and hash (TOCTOU)

---

## OWASP / MITRE Mapping

| Technique | Reference |
|---|---|
| T1565 — Data Manipulation | MITRE ATT&CK |
| T1070.006 — Timestomp | MITRE ATT&CK (mtime limitation) |
| T1036 — Masquerading | MITRE ATT&CK |
| SI-7 — Software, Firmware, Info Integrity | NIST SP 800-53 |

---

## Testing

```bash
source .venv/bin/activate
pytest tests/ -v
```

**44 tests** covering:
- SHA-256 correctness (known hash values)
- HMAC computation and constant-time verification
- HMAC chain: valid chain passes, deleted/modified entry breaks chain
- Modification, deletion, creation, and unchanged detection
- False-positive: mtime change without content change produces **no** alert
- Edge cases: empty files, binary files, unreadable files, unicode paths

---

## Limitations

1. **Privileged attacker** can bypass everything — HMAC key on same host
2. **TOCTOU race**: a file could be modified between the walk and hash steps
3. **No encryption**: baseline database and logs are readable by any user with access
4. **No network forwarding**: logs stay local; real systems ship to SIEM
5. **No digital signatures**: HMAC requires the same key to verify — not a public verifiable signature
6. **mtime is supplementary** — stored but not used for detection (by design)

---

## Future Improvements

- [ ] Forward logs to a remote collector via TLS
- [ ] Ed25519 signatures for non-repudiable log entries
- [ ] inotify/FSEvents-native real-time mode (not polling)
- [ ] Baseline encryption at rest
- [ ] YARA rule integration for detecting known malware signatures
- [ ] Git-style diff of changed file content (where readable)

---

## Ethical / Legal Disclaimer

This tool monitors only files on systems you own or have explicit written authorisation to monitor. Deploying FIM on systems without authorisation may violate computer fraud laws (CFAA in the US, Computer Misuse Act in the UK). The HMAC key must be stored securely and not shared.

---

## License

MIT License. See `LICENSE` for details.
