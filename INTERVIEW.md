# INTERVIEW.md — File Integrity Monitor

---

## 30-Second Explanation (Recruiter)

> "I built a host-based file integrity monitoring system. It creates a SHA-256 hash baseline of a monitored directory, then detects any modifications, deletions, or new files by comparing current hashes against that baseline. Every event is recorded in a tamper-evident audit log where each entry is HMAC-signed and chained to the previous, so you can't silently delete a log entry. This maps directly to MITRE ATT&CK T1565 — Data Manipulation — and mirrors how tools like Tripwire and OSSEC operate."

---

## 2-Minute Explanation (Technical)

> "The system has four modules: a baseline manager that walks directories and hashes every file with SHA-256 using chunked reads, storing results in SQLite with ACID transactions; a monitor that compares the live filesystem against baseline records, triggering alerts for modified, deleted, or new files; a tamper-evident logger that chains each HMAC-SHA256 entry to the previous, using ASCII 0x1F as field separator to prevent separator-injection attacks; and a Click-based CLI with four subcommands: baseline, scan, verify, and watch. I deliberately use SHA-256 as the authoritative change detector rather than mtime, because mtime is trivially spoofable with `touch -t`. The key design trade-off I'm honest about: the HMAC key is on the same host, so a privileged attacker with root access can forge the log. Real enterprise systems like Tripwire forward logs to an off-host SIEM with key management via HSM or KMS."

---

## Deep Technical Explanation

### 1. Why SHA-256 and not SHA-3?
SHA-256 has no known practical attacks and is widely standardised (FIPS 180-4). SHA-3 (Keccak) is newer and uses a different sponge construction, but SHA-256 is sufficient here. The key property needed is **collision resistance** and **second-preimage resistance** — an attacker shouldn't be able to create a modified file that has the same digest. SHA-256 provides both.

### 2. Why chunked file reads?
Reading 8KB chunks prevents loading multi-GB files into memory. The SHA-256 `update()` method takes partial input — it maintains an internal state, so chunked feeding is equivalent to hashing the full content at once. This is the standard pattern for file hashing.

### 3. Why SQLite and not a flat JSON file?
SQLite provides ACID transactions: if the baseline scan is interrupted mid-way (crash, Ctrl+C), you don't get a partially-written corrupt JSON file. WAL (Write-Ahead Logging) mode additionally improves concurrent read performance. The schema uses `path` as PRIMARY KEY to enforce uniqueness and make lookups O(log n) via the B-tree index.

### 4. How does the HMAC chain work exactly?
Each entry contains: `TIMESTAMP \x1F SEVERITY \x1F EVENT_TYPE \x1F DETAILS \x1F PREV_HMAC \x1F THIS_HMAC`

`THIS_HMAC = HMAC-SHA256(key, TIMESTAMP + SEVERITY + EVENT_TYPE + DETAILS + PREV_HMAC)`

The first entry uses a genesis hash of 64 zeros as `PREV_HMAC`. Every subsequent entry includes the previous entry's HMAC in its computation. Deleting any entry makes the following entry's `PREV_HMAC` field inconsistent — verification catches this.

### 5. Why ASCII 0x1F as field separator?
In the first implementation I used ` | ` as separator. File paths containing ` | ` would cause the parser to split a single entry into more than 6 fields. ASCII 0x1F is the Unit Separator control character — it's non-printable and cannot appear in POSIX file paths or UTF-8 human-readable text. This is a real production consideration.

### 6. Why `hmac.compare_digest()` instead of `==`?
A naive `==` on strings in Python performs an early-exit comparison — it returns False as soon as two characters differ. An attacker measuring response time can leak how many leading bytes match (timing attack). `compare_digest()` always takes O(n) time regardless of where the mismatch occurs.

### 7. Why is mtime stored but not used for detection?
mtime is supplementary metadata. It can be set to any value with `touch -t`. An attacker replacing `/bin/bash` could restore the original mtime and a mtime-based check would give a false negative. SHA-256 must be the authoritative indicator.

### 8. TOCTOU race condition
Between `os.walk()` and `hash_file()`, a file could be modified. The hash would reflect the attacker's version, not the honest version. This is a known limitation of any scan-based FIM. Real-time systems using inotify/FSEvents reduce (but don't eliminate) this window.

---

## Goldman Sachs Interview Questions

### Q1. Why is SHA-256 used here instead of MD5?
**Testing:** Cryptographic knowledge.
**Answer:** MD5 is broken for collision resistance — it's computationally feasible to produce two different files with the same MD5 hash. SHA-1 has also been practically broken (SHAttered attack, 2017). SHA-256 has no known practical attacks. For FIM, we need second-preimage resistance: given a file and its hash, an attacker cannot produce a different file with the same hash. MD5 and SHA-1 don't provide this reliably.
**Follow-up:** "Is SHA-256 a good password hashing algorithm?" — No. SHA-256 is fast by design. Password storage requires slow KDFs (bcrypt, Argon2id) to resist brute force.
**Key concept:** Distinguish hash function properties: collision resistance, second-preimage resistance, preimage resistance.

### Q2. Explain the HMAC chain and what it protects against.
**Testing:** Applied cryptography.
**Answer:** HMAC-SHA256 provides message authentication — proof that a log entry was produced by someone with the secret key. Chaining means each entry's HMAC is computed over all previous entries (via PREV_HMAC). Deleting any entry breaks the chain because subsequent entries reference a HMAC that no longer exists. Modifying any entry breaks its own HMAC and all subsequent ones.
**Follow-up:** "Can the attacker delete the log file entirely?" — Yes. Log file existence is not protected. The HMAC chain only proves entries haven't been silently edited or partially removed.
**Key concept:** HMAC ≠ encryption. HMAC provides authentication (who wrote it) and integrity (unchanged). Not confidentiality.

### Q3. What's the most critical security limitation of this system?
**Testing:** Threat modeling honesty.
**Answer:** The HMAC key is stored in the process environment on the same host being monitored. A privileged attacker (root) can read the key, forge new log entries, and regenerate a valid chain. This completely bypasses the tamper-evidence property. Enterprise systems solve this by forwarding logs to an off-host SIEM over TLS, with key management via HSM or KMS (e.g., HashiCorp Vault). The FIM agent never stores or accesses the signing key directly.
**Follow-up:** "How would you implement the enterprise solution?" — Deploy a Wazuh or Splunk forwarder agent. Log signing key in KMS. Agent authenticates to KMS with short-lived tokens. Logs written to immutable (WORM) storage.
**Key concept:** Security boundaries — on-host controls cannot protect against a compromised host.

### Q4. What is TOCTOU and how does it apply here?
**Testing:** OS security, race conditions.
**Answer:** TOCTOU is Time-Of-Check to Time-Of-Use. Between listing a file (`os.walk`) and computing its hash (`hash_file`), an attacker could replace the file with a different version. The FIM would hash the replacement, not the original. This is a fundamental limitation of any scan-based FIM. Real-time hooks (inotify on Linux, FSEvents on macOS, kernel-level drivers) reduce the window but don't eliminate it — there's always a brief moment between the file write completing and the kernel notifying the FIM.
**Follow-up:** "How do EDR tools address this?" — Kernel-mode drivers intercept file system calls at the I/O manager level before the write completes, eliminating the TOCTOU window.
**Key concept:** Scan-based detection vs. event-based detection.

### Q5. What is the time complexity of verify_integrity()?
**Testing:** Algorithms.
**Answer:** O(n) where n is the number of log entries. We read each line once, perform one HMAC-SHA256 computation per line, and do a constant-time string comparison. No sorting, no nested loops. HMAC-SHA256 itself is O(m) where m is the message length — since log entries are bounded size, this is effectively O(1) per entry. Total: O(n).
**Follow-up:** "Could you make it faster?" — No meaningful way without breaking security. You'd need to read every entry to verify the chain — skipping any entry means an attacker can delete middle entries undetected.
**Key concept:** Security requirements constrain algorithmic optimisation.

### Q6. Why does `os.walk()` use `followlinks=False`?
**Testing:** Filesystem security.
**Answer:** Following symlinks can cause the walker to traverse into directories outside the intended scope, or create infinite loops if a symlink points to a parent directory. `followlinks=False` (the default) prevents this. An attacker could also create a symlink within the monitored directory pointing to `/etc/` to cause the FIM to hash sensitive files or consume excessive resources.
**Follow-up:** "What if a monitored file is itself a symlink?" — `os.stat()` follows symlinks to the target by default. We could use `os.lstat()` if we wanted to hash the symlink itself rather than its target.
**Key concept:** Secure path traversal.

### Q7. How does SQLite's WAL mode improve this application?
**Testing:** Database knowledge.
**Answer:** WAL (Write-Ahead Logging) is a journal mode where writes go to a separate WAL file before being committed to the main database. This allows readers and writers to operate concurrently without blocking each other — readers see the last committed state without waiting for an in-progress write. For FIM, this means the scan command can read the baseline while the watch command is potentially writing new records. In rollback journal mode (default), a writer blocks all readers.
**Follow-up:** "When would you not use WAL mode?" — WAL requires the database and WAL file to be on the same filesystem (no NFS support). For networked filesystems, rollback journal is safer.
**Key concept:** Database concurrency, SQLite journal modes.

### Q8. How does `hmac.new()` differ from `hashlib.sha256()`?
**Testing:** Standard library knowledge.
**Answer:** `hashlib.sha256()` produces a cryptographic hash of a message — anyone can verify or produce it from the same input. `hmac.new()` produces a keyed MAC — only someone with the secret key can produce or verify the tag. HMAC internally does `SHA256(key XOR opad || SHA256(key XOR ipad || message))` — the double-hashing with key material prevents length-extension attacks that would be possible if you just did `SHA256(key || message)`.
**Follow-up:** "What is a length-extension attack?" — For hash functions like SHA-256 in Merkle-Damgård construction, given `H(m)` and `len(m)`, you can compute `H(m || extra)` without knowing `m`. HMAC's nested structure prevents this.
**Key concept:** MAC vs. hash, length extension.

### Q9. What happens if the baseline database is deleted?
**Testing:** Failure modes.
**Answer:** The scan command has no baseline to compare against. Depending on implementation: it could raise an error (current behaviour — `get_all()` returns empty list → all current files appear as CREATED). This is a false-positive flood, not a missed detection. The correct mitigation is to protect the baseline database with strict file permissions (read-only to all except the FIM user, immutable flag `chattr +i` on Linux) and back it up to off-host storage.
**Follow-up:** "What's `chattr +i`?" — The Linux immutable bit. Even root cannot modify or delete an immutable file without first removing the attribute via `chattr -i`. Requires physical/console access or the `CAP_LINUX_IMMUTABLE` capability.
**Key concept:** Defence in depth for the baseline.

### Q10. Explain the difference between FIM and an antivirus.
**Testing:** Security concept clarity.
**Answer:** FIM is **change detection** — it tells you *that* a file changed, not *what* the change is or whether it's malicious. Antivirus uses **signature matching and behavioural analysis** — it tells you *whether* a file is known malware. They're complementary: FIM detects that `/bin/bash` was replaced; AV determines if the replacement is a known rootkit. Enterprise EDR tools combine both: YARA rules for signature matching + hash-based baselining.
**Follow-up:** "Which is better?" — Neither is sufficient alone. FIM has no malware knowledge; AV misses unknown/custom malware. Defence-in-depth uses both.

### Q11. How would you make the baseline tamper-resistant?
**Testing:** Security architecture.
**Answer:** Several layers:
1. **File permissions**: `chmod 440` on the database, owned by the FIM service account
2. **Immutable flag**: `chattr +i fim_baseline.db` (Linux)
3. **Remote storage**: Copy baseline to an off-host location (read-only S3, SFTP server)
4. **Hash the baseline itself**: Store SHA-256 of `fim_baseline.db` in a TPM or remote KMS
5. **Hardware roots of trust**: TPM 2.0 can seal measurements — if the system state changes, the TPM refuses to release the key
**Key concept:** Trusted storage requires a trust anchor outside the compromised system.

### Q12. What is the difference between HMAC and a digital signature?
**Testing:** Applied cryptography depth.
**Answer:** HMAC uses **symmetric** key cryptography — the same secret key is used to produce and verify the tag. Both parties (producer and verifier) must have the key. Digital signatures (ECDSA, Ed25519) use **asymmetric** keys — a private key signs, a public key verifies. Signatures provide **non-repudiation**: anyone with the public key can verify, but only the private key holder can sign. For FIM, HMAC is sufficient if we trust the system running verification. For publicly auditable logs, digital signatures would be more appropriate.
**Key concept:** Symmetric MAC vs. asymmetric signature, non-repudiation.

### Q13. Why is the baseline scan susceptible to being outdated?
**Testing:** Practical security thinking.
**Answer:** The baseline represents a point-in-time trust snapshot. If malware was already present **when the baseline was created**, it will appear "clean" forever — its hash is in the baseline. This is why baselining must happen on a known-good, freshly provisioned system before deployment. Enterprise FIM workflows include: (1) Deploy from a hardened golden image, (2) Create baseline immediately post-deployment, (3) Verify the image against a vendor-provided hash manifest before baselining.
**Key concept:** Garbage-in-garbage-out for trust anchors.

### Q14. How does the exclusion pattern system work and what are its risks?
**Testing:** Attention to security edge cases.
**Answer:** `fnmatch.fnmatch(name, pattern)` — glob matching on file/directory basenames. Risk: over-broad exclusions could hide attacker-placed files. Example: excluding `*.log` might hide a maliciously named `rootkit.log`. Exclusions should be as specific as possible and reviewed regularly. A security audit of the exclusion list is itself a security control.

### Q15. What is the difference between integrity and authenticity?
**Testing:** Security vocabulary precision.
**Answer:** **Integrity**: the data hasn't been altered (SHA-256 hash). **Authenticity**: the data came from who it claims to come from (HMAC, digital signature). SHA-256 alone provides integrity — you can verify a file hasn't changed, but you can't verify who changed it. HMAC provides both integrity AND authenticity (to anyone with the key). This is why HMAC is used for the log (we need to know the log was written by the legitimate FIM process) and SHA-256 for file hashing (we just need to detect change).

### Q16. Why use `os.urandom()` for key generation rather than `random.randbytes()`?
**Testing:** Secure coding practices.
**Answer:** `random` uses a deterministic PRNG seeded from `time.time()` by default — it is **not** cryptographically secure. An attacker knowing the approximate seed time can reconstruct the sequence. `os.urandom()` reads from the OS CSPRNG — `/dev/urandom` on Linux/macOS, `CryptGenRandom` on Windows — which uses hardware entropy sources. Always use `os.urandom()` or `secrets` module for any key/token generation.

### Q17. What is `sqlite3.Row` and why use it?
**Testing:** Practical Python/DB knowledge.
**Answer:** `sqlite3.Row` is a row factory that wraps query results to support both index-based (`row[0]`) and name-based (`row["path"]`) column access. Without it, rows are plain tuples — `row[0]` for `path`, `row[1]` for `sha256`, etc. Name-based access is more robust against column order changes in the schema and much more readable. It's a minor but real code quality choice.

### Q18. How would this system scale to monitor 10,000 files?
**Testing:** Scalability thinking.
**Answer:** The current single-threaded implementation hashes files sequentially. For 10,000 files: (1) SHA-256 is fast — ~500 MB/s on modern hardware, so 10K small files (~10KB average) = ~200MB total = ~0.4 seconds hashing time, (2) SQLite with WAL handles this easily, (3) For large binary files (multi-GB), parallelise with `concurrent.futures.ThreadPoolExecutor` — disk I/O is the bottleneck, not CPU, so threads (not processes) are appropriate. For 100K+ files, consider a producer-consumer pattern with a queue.
**Follow-up:** "Would you use multiprocessing?" — No. Disk I/O is the bottleneck. Threads with GIL released during I/O are sufficient. Multiprocessing adds overhead from process creation and IPC.

### Q19. Explain the `contextmanager` usage in `db.py`.
**Testing:** Python internals.
**Answer:** `@contextmanager` from `contextlib` converts a generator function into a context manager. The code before `yield` runs at `__enter__`, the `yield` value is the context object, and code after `yield` runs at `__exit__`. The try/except/finally pattern inside ensures `rollback()` is always called on exception and `commit()` only on success. This gives us automatic transaction management without subclassing `AbstractContextManager`.

### Q20. What questions should you never bluff on?

**"Explain exactly how HMAC-SHA256 works internally."**
Know the HMAC construction: `HMAC(k, m) = H((k XOR opad) || H((k XOR ipad) || m))`. Know what ipad and opad are (0x36 and 0x5C repeated). Know why the double-hash prevents length extension.

**"What is a collision attack and is SHA-256 vulnerable?"**
Collision: find two different inputs with the same hash. MD5 and SHA-1 are broken. SHA-256: best known attack is O(2^128) — computationally infeasible. SHA-256 is **not** vulnerable.

**"What is a preimage attack?"**
Given hash H, find message m such that hash(m) = H. Distinct from collision attack. SHA-256: O(2^256) — infeasible.

**"Why is your key storage insecure?"**
The key is in the process environment. Environment variables are visible to any process with the same UID via `/proc/PID/environ` on Linux. The correct answer includes this and the enterprise mitigation.

**"How does hmac.compare_digest() prevent timing attacks?"**
It compares all bytes in constant time regardless of where the first mismatch occurs. Never say "it's just a secure comparison function" without explaining why constant-time matters.
