## 30-Second Explanation
"I developed a File Integrity Monitor in Python to detect unauthorized filesystem changes. It uses SHA-256 hashing to build a persistent SQLite baseline of known-good file states. To ensure that an attacker cannot alter the logs to hide their activity, I engineered a tamper-evident audit trail using chained HMAC-SHA256 signatures, mathematically linking each log entry to the previous one."

## 2-Minute Explanation
"This project is a defensive Host Security tool designed to detect malicious persistence or configuration tampering. It operates in two phases: baselining and monitoring. During baselining, it traverses specified directories, calculating SHA-256 cryptographic hashes for all files and storing them in an SQLite database. In the monitoring phase, it recalculates these hashes and compares them to the baseline to detect file creation, modification, or deletion. Importantly, modifications are evaluated solely on SHA-256 mismatch, not mtime changes, to prevent false positives. To secure the system's own logs against tampering, every alert is appended to a chained HMAC audit log. If an attacker deletes or alters a log entry, the cryptographic chain is broken and the tampering is immediately detectable. The system is verified by 44 automated unit tests."

## Architecture Walkthrough
The Filesystem is scanned by the Baseline Manager, applying SHA-256 to create an SQLite Baseline. During polling, the Comparison engine evaluates the current state against the baseline. Anomalies generate Alerts, which are immediately appended to the HMAC Audit Log before final output to the Report.

## Key Design Decisions
- **SHA-256 over mtime**: Relying on mtime (modification time) is vulnerable to timestamp spoofing (timestomping) and benign updates. SHA-256 guarantees actual content verification.
- **HMAC Log Chaining**: Modeled after basic blockchain mechanics, each log entry incorporates the HMAC of the preceding entry, making historical log modification computationally infeasible without the secret key.

## Technical Deep Dive
The HMAC chain is initialized with a genesis hash. For every new log event `E_n`, the system calculates `HMAC(Key, E_n + Hash_{n-1})`. Verification requires re-running this sequence; a deleted or altered line will cause a cascading validation failure for all subsequent logs.

## Security Trade-offs
The current implementation relies on polling rather than kernel-level event hooks (like `inotify` or FSEvents), which introduces a small race condition window between a file change and its detection.

## Limitations
The `FIM_HMAC_KEY` is currently managed via local environment variables. In a scenario where an attacker gains root access, they could theoretically compromise this key. Production implementations require KMS or HSM integration.

## Likely Interview Questions
1. **Why not just check the file's last modified time?** (Answer: Timestamps can be easily spoofed using `touch` or API calls, and benign operations can change timestamps without altering content).
2. **How does the HMAC chain detect log deletion?** (Answer: Deleting line 3 means line 4's expected previous hash won't match line 2's actual hash, breaking the verification chain).

## Questions I Should Never Bluff On
- Kernel-level filesystem filtering (eBPF/inotify).
- Claims that the local `FIM_HMAC_KEY` is completely immune to root-level compromise.
