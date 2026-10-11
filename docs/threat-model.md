# Exposure Triage Workbench (ETW) — Threat Model & Security Architecture

**Document Version:** 1.0  
**Date:** 2026-10-11  
**Status:** Approved Security Baseline  

---

## 1. System Overview & Trust Boundaries

Exposure Triage Workbench (ETW) is a local-first security CLI designed to ingest raw scanner findings, classify candidate exposures, and generate redacted triage reports. Because ETW processes files that potentially contain active production credentials and untrusted input data, strict security boundaries are established.

```
+-----------------------------------------------------------------------------------+
| OPERATOR ENVIRONMENT (Host OS, Terminal, File System)                              |
|                                                                                   |
|  [Operator Input File] (Untrusted / Contains Raw Secrets)                         |
|         |                                                                         |
|         v (Read-only Ingestion)                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | ETW IN-MEMORY PROCESSING BOUNDARY (Ephemeral Python Process)                |  |
|  |                                                                             |  |
|  |  +---------------------+       +-------------------+       +-------------+  |  |
|  |  | Parser & Sanitizer  | ----> | HMAC Fingerprint  | ----> | Rule Engine |  |  |
|  |  | (Size/Depth Bounded)|       | (HMAC-SHA256 Key) |       | (No Exec)   |  |  |
|  |  +---------------------+       +-------------------+       +-------------+  |  |
|  |             |                            |                        |         |  |
|  |             +----------------------------+------------------------+         |  |
|  |                                          |                                  |  |
|  |                         [REDACT RAW SECRETS BEFORE EMISSION]                |  |
|  +------------------------------------------+----------------------------------+  |
|                                             |                                     |
|         +-----------------------------------+----------------------------------+  |
|         |                                   |                                  |  |
|         v                                   v                                  v  |
|  [ETW Database (.etw.db)]          [Redacted Reports]               [JSON Exports] |
|  - WAL / Journal Sanitized         - Escaped Markdown               - Redacted     |
|  - Fingerprints Only               - Fingerprints Only              - Schema-Valid |
|  - No Raw Values                   - Zero Raw Secrets               - Provenance   |
+-----------------------------------------------------------------------------------+
```

### Trust Boundary Definitions:
1. **Untrusted Input Boundary:** Scanner JSON reports, repository metadata, commit logs, and configuration files provided to ETW are untrusted. They may be malformed, hostile, or crafted to trigger memory exhaustion, regex denial of service (ReDoS), or report injection.
2. **Confidentiality Boundary:** Raw secret candidates exist in memory only during normalization and fingerprinting. They must never cross into persistent ETW-controlled artifacts.
3. **Execution Boundary:** Configuration files (e.g. MCP JSON) containing commands, flags, or URLs must be treated strictly as static data. The application runtime must never invoke a subprocess, shell out, or initiate external network connections.

---

## 2. Asset Inventory & Classification

| Asset | Sensitivity | Location | Protection Mechanism |
|---|---|---|---|
| **Raw Candidate Secrets** | Critical | Memory only (ephemeral) | In-memory redaction; regex scrubber on all exception/logging paths; never written to DB or disk. |
| **HMAC Secret Key** | High | `.etw/hmac.key` or `ETW_HMAC_KEY` | File permissions restricted to operator (0600 on POSIX; explicit ACL on Windows); excluded from git. |
| **Candidate Fingerprints** | Medium | SQLite database, reports | Truncated HMAC-SHA256 (32 hex chars); irreversible without the HMAC key. |
| **Case Metadata & Audit Log** | Medium | `.etw/etw.db` | Local SQLite store; ACID transactional integrity with WAL mode. |
| **Generated Reports** | Medium | `reports/*.md`, `reports/*.json` | HTML/Markdown escaped; redacted context snippets; evidence provenance links. |
| **Operator Host System** | Critical | Host environment | Zero remote execution; zero network requests; zero environment variable reading. |

---

## 3. Threat Analysis & Mitigations

### Threat 1: Accidental Raw Secret Persistence
* **Threat:** Raw candidate credentials leaked into SQLite database rows, SQLite Write-Ahead Logs (WAL) or journal files, application logs, debug tracebacks, temporary files, or CLI error outputs.
* **Impact:** Compromise of customer or organization credentials; violation of compliance and safe-handling guarantees.
* **Mitigations:**
  1. **Strict Data Contract:** The `Observation` and `Case` Pydantic models contain `raw_secret` as an ephemeral private field (`_raw_secret` or in-memory argument) that is excluded from serialization (`exclude=True`) and never stored in database columns.
  2. **Scrubbing Interceptor:** All exception formatters and logging handlers pass messages through a redaction filter that replaces potential secret strings with `[REDACTED_SECRET:<fingerprint_prefix>]`.
  3. **Zero Temporary Files:** Ingestion does not write temporary unencrypted staging files to disk.
  4. **Automated Leak Tests:** Regression tests seed known synthetic canary secrets and inspect the entirety of `.etw/etw.db`, WAL files, stdout logs, and report outputs to verify 0 raw occurrences.

### Threat 2: Report Injection & Cross-Site Scripting (XSS)
* **Threat:** Malicious scanner findings containing markdown formatting, raw HTML, Javascript tags, or terminal escape sequences injected into file paths, repository names, or context snippets, leading to report spoofing or script execution when viewed in web/markdown viewers.
* **Impact:** Analyst deception, cross-site scripting in report consumers, or terminal corruption.
* **Mitigations:**
  1. **HTML Entity Escaping:** All user-controlled text strings are passed through HTML entity escaping (`html.escape()`) before being injected into Jinja2 Markdown templates.
  2. **ANSI Control Character Scrubbing:** Terminal output strips ANSI escape sequences from candidate strings.
  3. **Link Defanging:** URLs extracted from snippets are rendered as defanged text or escaped code blocks, never clickable active hyperlinks, preventing drive-by clicks.

### Threat 3: Denial of Service via Malformed Inputs & ReDoS
* **Threat:** Massive multi-gigabyte scanner exports, deeply nested JSON structures, or pathological input strings that trigger catastrophic backtracking in regex matching (ReDoS).
* **Impact:** Process crash, unbounded CPU consumption, or memory exhaustion.
* **Mitigations:**
  1. **Input Size Envelopes:** Enforce maximum file size (50 MB) and maximum finding snippet size (64 KB).
  2. **Stream/Line-by-Line Ingestion:** For JSONL formats, process records line by line to keep working memory bounded ($O(1)$ memory per record).
  3. **Bounded Linear Regexes:** All detection regexes are audited for polynomial/exponential backtracking, pre-compiled, and evaluated against truncated candidate strings.

### Threat 4: Arbitrary Command Execution via Config Ingestion
* **Threat:** Ingesting MCP configuration files containing commands (e.g. `npx`, `python`, `bash`, `curl`) causes ETW to spawn local child processes.
* **Impact:** Remote Code Execution (RCE) on the analyst's workstation.
* **Mitigations:**
  1. **Zero Subprocess Calls:** The ETW codebase prohibits calling `subprocess.Popen`, `os.system`, `eval`, or `exec` on any parsed configuration field.
  2. **Static AST / JSON Parsing Only:** Configuration files are parsed strictly as passive JSON data structures using standard JSON parsers.

### Threat 5: Accidental Live Network Probing & Canary Triggering
* **Threat:** Attempting live verification or sending HTTP requests to candidate URLs triggers canary tokens (e.g. Canarytokens.org, AWS canary keys), alerting attackers or invalidating defense canaries, or causes Server-Side Request Forgery (SSRF).
* **Impact:** Premature incident alerting, active defense failure, unintended third-party disclosure.
* **Mitigations:**
  1. **Network Disablement:** ETW's core pipeline contains zero network request libraries (no outbound `requests`, `urllib.request`, or sockets in the triage engine).
  2. **Canary Pattern Recognition:** Dedicated rules identify documented canary indicators (`likely_canary`) and explicitly flag them with urgent warnings: *"Do not probe or interact; potential active defense canary."*

### Threat 6: Cross-Tenant / Cross-Asset Case Collisions
* **Threat:** Grouping cases purely by secret value merges unrelated assets or client repositories, causing data leakage between customer files or confused analyst attribution.
* **Impact:** Cross-customer finding contamination; loss of provenance.
* **Mitigations:**
  1. **Scoped Grouping Keys:** Case identity is strictly bound to `(candidate_fingerprint, credential_type, asset_scope)`. Findings from different repositories or projects never share a single `Case` object; they are cross-referenced as `RelatedCases` while retaining separate records.

---

## 4. Security Verification Strategy

The following security test suite is mandatory and runs on every build:
1. **`test_zero_secret_leakage.py`:** Runs end-to-end ingestion and reporting on seeded synthetic secrets, reading the raw byte streams of `.etw/etw.db`, `-wal`, `-shm`, generated markdown files, and JSON exports to assert that zero seed secrets are present.
2. **`test_report_injection.py`:** Ingests payloads with HTML (`<script>alert(1)</script>`), Markdown image tags, and terminal control codes to assert full escaping in output.
3. **`test_malformed_input_resilience.py`:** Tests truncated JSON, non-UTF8 bytes, oversized lines, and invalid schema variants to verify graceful, non-crashing quarantine.
4. **`test_network_and_execution_guard.py`:** Unit test auditing that the triage modules import zero networking or process-spawning functions.
