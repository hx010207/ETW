# Exposure Triage Workbench (ETW) — Project Architecture & Technical Overview

> **Notice & Legal Disclaimer:**
> Exposure Triage Workbench (ETW) is an independent cybersecurity research and engineering project. It is **not affiliated with, endorsed by, sponsored by, or supported by CloudSEK**. All concepts and benchmarks use synthetic test fixtures and represent an architectural prototype for secret-safe security triage.

---

## 1. Problem Statement & Motivation

Modern software organizations employ automated secret scanners (such as TruffleHog and Gitleaks) in continuous integration pipelines. While detection tools are effective at identifying candidate high-entropy strings, security engineering teams encounter four major operational bottlenecks post-detection:

1. **The Triage Fatigue Bottleneck:**
   A typical scan run across thousands of repositories produces tens of thousands of raw alerts. A significant proportion consists of benign artifacts: documentation template tokens (`example_api_key`), unit test fixtures (`test_secret_abc123`), mock configs, and low-entropy strings. Manually reviewing each alert overwhelms AppSec teams.

2. **The Secondary Data Breach Hazard:**
   Traditional triage workflows often ingest raw scanner findings directly into centralized SaaS ticketing systems, cloud databases, or web applications. If that central repository is compromised, attackers gain instant access to an index of active credentials across the entire organization.

3. **Blast Radius & Ownership Obfuscation:**
   Naïve deduplication algorithms merge identical secret strings across different repositories or microservices into a single finding. While this artificially lowers ticket counts, it obliterates ownership provenance and remediation blast radius: rotating an AWS key in Repository A does not remediate its unauthorized presence in Repository B.

4. **The Canary Token Trap:**
   Security operations teams increasingly plant active Canarytokens as honeypot tripwires. When automated scanners or overzealous security tools automatically "verify" these credentials by sending live HTTP requests, they unintentionally trigger incident response alerts and disclose the presence of the scanner.

---

## 2. Intended Users & Operating Paradigm

ETW is designed for:
- **Application Security (AppSec) Engineers:** Who require a fast, local-first engine to preprocess raw scanner dumps before tickets are assigned to developers.
- **Security Operations Center (SOC) Triage Analysts:** Who need auditable evidence, transparent priority rationales, and safe validation boundaries.
- **Platform & DevSecOps Teams:** Who require automated ingestion pipelines that respect asset boundaries and leave zero raw credentials on disk.

### Operating Paradigm: Local-First & Defense-in-Depth
ETW operates entirely on the engineer's machine or within isolated CI runners. It makes **zero external network requests**, requires no SaaS subscriptions, and stores all metadata in a local, permission-restricted SQLite database operating in Write-Ahead Logging (WAL) mode.

---

## 3. Core Architectural Decisions (ADRs)

| Architectural Decision | Decision Rationale | Operational Guarantee |
| :--- | :--- | :--- |
| **ADR 0001: Bounded MVP Scope** | Keep implementation minimal, robust, and focused strictly on the post-detection triage layer rather than scanner execution or active remediation. | Smallest complete codebase; zero unnecessary microservices or distributed brokers. |
| **Zero Raw Secret Persistence** | Raw credentials must never be written to SQLite tables, WAL files, log messages, audit events, or exports. | Secrets are processed in-memory only. The database schema contains zero secret columns. Persisted identifiers use keyed **HMAC-SHA256 digests**. |
| **Strict Asset-Scoped Deduplication** | Identical credentials found in distinct asset scopes (e.g. separate repositories or environments) must **never** be merged into one case. | Cases are partitioned strictly by `(fingerprint, asset_scope)`. Cross-scope collisions are linked via `related_cases` pointers without merging. |
| **Explainable Priority Matrix (P1–P4)** | Priority assignments must follow transparent, deterministic logic rather than opaque machine-learning scoring. | Every priority assignment is accompanied by explicit evidence factors (`priority_factors`) and an immutable classification rationale. |
| **Passive Static MCP Analysis** | Model Context Protocol server configs (`claude_desktop_config.json`) must be audited for cleartext HTTP, hardcoded secrets, and root path mounts. | Pure AST/JSON inspection: zero subprocess spawning, zero network requests, zero environment variable expansion. |
| **Exclusion of Live Credential Validation** | Automated tools must never send live requests to third-party APIs using candidate credentials. | Eliminates accidental Canary tripping, credential revocation risks, and unauthorized intrusion hazards. |

---

## 4. System Architecture & Components

```
                        +----------------------------------+
                        | Raw Scanner Findings / Configs   |
                        | (TruffleHog, Gitleaks, MCP JSON) |
                        +-----------------+----------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Ingestion & Quarantine Boundary (src/etw/ingest/)                                 |
| - Streaming JSON / JSONL parsing with strict file size guards (max 50 MB)         |
| - Raw secret extraction into transient in-memory Observation models               |
| - Keyed HMAC-SHA256 digest computation (src/etw/storage/fingerprint.py)          |
| - Defensive quarantine of malformed records (quarantined_records table)           |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Deterministic Classification Engine (src/etw/rules/classifier.py)                 |
| - RULE-PLACEHOLDER-001 (Template tokens, uppercase boilerplate, zeroed hex)      |
| - RULE-TEST-001 (Test paths, mock prefixes, fixture files)                        |
| - RULE-CANARY-001 (Canary tokens, tripwire URLs with non-interaction warnings)    |
| - RULE-AMBIGUOUS-001 (Low-entropy strings, indeterminate context)                 |
| - RULE-CANDIDATE-001 (Operational candidate secrets)                             |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Correlation & Prioritization Engine (src/etw/analysis/)                           |
| - Grouping by (candidate_fingerprint, asset_scope) (case_grouper.py)              |
| - Cross-scope linkage via related_cases pointers                                  |
| - Priority Matrix (prioritize.py):                                                |
|   * P1_urgent: Upstream verified credentials or active Canary tokens              |
|   * P2_high: Candidate secrets in operational asset scopes                        |
|   * P3_normal: Ambiguous findings requiring analyst review                        |
|   * P4_low: Filtered documentation placeholders and test mocks                   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Persistence & Storage Layer (src/etw/storage/database.py)                         |
| - SQLite with Write-Ahead Logging (WAL) and foreign keys enabled                  |
| - Schema migration tracking (schema_migrations table)                             |
| - Zero raw secret columns; restricted file permissions (0600 on POSIX)           |
| - Run retention & cascading purge (etw purge <run_id>)                           |
+--------------------+--------------------+--------------------+--------------------+
                     |                    |                    |
                     v                    v                    v
          +--------------------+ +--------------------+ +--------------------+
          | Markdown Reports   | | JSON Export Bundles| | CLI Interface      |
          | (Sanitized summary | | (Machine-readable  | | (etw ingest, case, |
          | with canary alerts)| | SIEM/SOAR format)  | | triage, purge)     |
          +--------------------+ +--------------------+ +--------------------+
```

---

## 5. Security Boundaries & Threat Model

ETW implements a multi-tier defense-in-depth model across its operational boundaries:

### 1. In-Memory Secret Redaction & Zero Persistence
- Raw secret strings are held strictly in the `Observation.raw_secret` transient field.
- The Pydantic model explicitly marks `raw_secret` with `exclude=True`. Serializing observations via `model_dump()` or `model_dump_json()` automatically drops the secret.
- The SQLite database schema contains no columns for raw secrets. Persisted records only contain the keyed digest `candidate_fingerprint` (`hmac-sha256:[a-f0-9]{32}`) and the masked snippet `redacted_match` (`sk_l...[REDACTED]...CC`).
- Binary byte-level regression tests (`tests/security/test_zero_secret_leakage.py` and `tests/unit/test_database.py`) scan the database file and WAL buffers to confirm zero secret presence.

### 2. HMAC Key Management & Lifecycle
- Digest generation uses a 32-byte cryptographically secure key (`secrets.token_bytes(32)`).
- Precedence: Explicit CLI argument -> `ETW_HMAC_KEY` environment variable -> Local key file (`.etw/hmac.key`).
- Corruption recovery: If `.etw/hmac.key` is empty, truncated (< 16 bytes), or unreadable, ETW automatically regenerates a secure 32-byte key.
- Key rotation: Re-running triage with a new key updates digests without exposing previous secrets.

### 3. Terminal & Output Injection Protection
- Malformed filenames, branch names, and commit metadata extracted from untrusted repositories are sanitized before terminal display via `sanitize_terminal_output()`.
- ANSI escape sequences and non-printable ASCII control characters (`\x00-\x08`, `\x0b-\x1f`, `\x7f`) are stripped to prevent terminal command injection or cursor hijacking.

### 4. Resource Exhaustion & Denial of Service Protection
- Ingestion adapters enforce a strict 50 MB maximum file size limit (`validate_file_size()`) before reading files into memory.
- SQLite connection pooling utilizes connection timeouts (10.0 seconds) and guaranteed `conn.close()` handlers via Python context managers to prevent file lock exhaustion.

---

## 6. Documented Limitations & Scope Boundaries

1. **Benchmark Scope vs. Real-World Enterprise Noise:**
   The Decision Gate 1 metrics (100% precision, 100% recall, 0% false dismissal rate) were measured against the pinned, synthetic 68-finding corpus in `datasets/fixtures-v1/`. While these results prove deterministic contract adherence and rule correctness, **they do not represent production triage accuracy on real-world enterprise codebases**, where custom tokens, obfuscated variables, and messy commits introduce ambiguity.
2. **Absence of Live Credential Validation:**
   ETW intentionally does not probe external APIs to check if credentials are valid. A status of `candidate_secret` indicates structural conformity and context priority, not confirmed live exploitability.
3. **Local-First Single-Node Design:**
   ETW is architected as an engineer-local tool or CI job runner using SQLite WAL. It is not designed as a distributed, multi-tenant cluster service.
4. **Independent Research Status:**
   ETW is an independent software engineering prototype and is not affiliated with or endorsed by CloudSEK.
