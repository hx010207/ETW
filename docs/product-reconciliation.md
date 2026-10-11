# Exposure Triage Workbench (ETW) — Product Specification Reconciliation

**Document Version:** 1.0  
**Date:** 2026-10-11  
**Status:** Approved Engineering Baseline  
**Source Specification:** `PRODUCT.md` (Version 0.1)  
**Critical Due Diligence:** `ETW_Product_Due_Diligence_CloudSEK.md`  

---

## 1. Executive Summary & Reconciliation Objective

This document serves as the authoritative reconciliation between the initial proposal in `PRODUCT.md` (v0.1) and the critical findings established in the independent due-diligence report (`ETW_Product_Due_Diligence_CloudSEK.md`).

The core hypothesis under evaluation is:
> *Can a local-first, post-detection triage workbench measurably improve the consistency, evidence quality, and review speed of security analysts processing raw credential detections, without increasing false dismissals or leaking secrets?*

ETW is **not** a scanner, discovery engine, attack-surface manager, or live verification utility. It operates strictly downstream of authorized detectors. All requirements from `PRODUCT.md` have been audited against the due-diligence findings, and the resulting engineering decisions are codified below.

---

## 2. Resolution of the Ten Critical Architectural Questions

### 2.1 Separation of Observation, Validity, Exposure, Disposition, and Impact
* **Issue:** In `PRODUCT.md`, candidate states mixed detector observations with analyst conclusions (e.g. `confirmed`), creating dangerous confusion with live credential validity.
* **Resolution:** ETW establishes five distinct, non-overlapping data dimensions:
  1. **Source Observation (`Observation`):** The immutable finding as emitted by the external detector (e.g., TruffleHog, Gitleaks).
  2. **Source Validity (`SourceReportedValidity`):** The verification status reported by the source detector (`verified`, `unverified`, `unknown`, `not_checked`), strictly attributed to the external tool. ETW makes zero independent claims of live validity.
  3. **Exposure Context (`ExposureEvidence`):** Provenance of where the candidate was found (repository, branch, file path, line, commit, file type, documentation vs. source).
  4. **Analyst Disposition (`DispositionState`):** The operational workflow state set by the human reviewer (`new`, `needs_review`, `confirmed_issue`, `false_positive`, `accepted_risk`, `remediated`). The ambiguous status `confirmed` is renamed `confirmed_issue` and explicitly documented as "an acknowledged exposure requiring remediation", never "active/live credential".
  5. **Asset Impact (`ImpactCandidate`):** Potential blast radius derived solely from co-located identifiers, explicitly marked as `inferred_candidate` until human confirmation.

### 2.2 Observation vs. Case Deduplication
* **Issue:** Deduplicating purely on secret hash risks merging unrelated assets, owners, or repositories simply because they share a common test token or leaked value. Deduplicating on file path fails to track repeated sightings across commits.
* **Resolution:**
  * **Observation ID:** A unique UUID assigned to each ingested raw detector item.
  * **Candidate Fingerprint:** Keyed HMAC-SHA256 of the normalized raw secret candidate.
  * **Case Grouping Key:** `(candidate_fingerprint, credential_type, asset_scope)` where `asset_scope` defaults to the repository or project identifier.
  * **Linkage:** Multiple observations sharing the same candidate fingerprint across different scopes are linked via `RelatedCases` references, preserving separate ownership and audit trails while surfacing reuse.

### 2.3 Precise Boundary for Raw-Secret Handling
* **Issue:** The promise "zero raw secrets persisted" is unachievable if interpreted as controlling input files or OS swap, and must be strictly protected against leaks in exceptions, logs, and database journals.
* **Resolution:**
  * **ETW-Controlled Boundary:** ETW guarantees that raw candidate secret values are handled in-memory only during ingestion and classification. They are **never** written to ETW-controlled databases, SQLite WAL/journal files, log messages, exception tracebacks, CLI stdout/stderr (unless explicitly masked), debug traces, JSON exports, or Markdown reports.
  * **Sanitization Layer:** All error handlers and loggers intercept input fields and apply regex scrubbing (`REDACTED_SECRET[...hmac_prefix...]`).
  * **Operator Responsibility Boundary:** ETW explicitly documents that it does not delete, wipe, or encrypt the operator's original input scanner files, nor does it control host operating system swap space, crash dumps, or memory paging.

### 2.4 HMAC Fingerprint Lifecycle and Scoping
* **Issue:** Without a defined key lifecycle, fingerprints cannot persist across runs, or conversely, global keys leak cross-tenant correlation.
* **Resolution:**
  * **Key Derivation:** ETW uses HMAC-SHA256. The secret key is loaded from the environment variable `ETW_HMAC_KEY`.
  * **Default Workspace Key:** If `ETW_HMAC_KEY` is unset, ETW checks for a local key file `.etw/hmac.key` (generated on first run with restricted file permissions: 0600 on POSIX, current-user ACL on Windows).
  * **Fingerprint Format:** Lowercase hex-encoded HMAC-SHA256 truncated to 32 characters (`hmac-sha256:[a-f0-9]{32}`).
  * **Rotation Policy:** A key rotation utility (`etw admin rekey`) recomputes fingerprints in the local database while logging an audit event.

### 2.5 Explainable Review Priority vs. Arbitrary Scoring
* **Issue:** The 0–100 score in `PRODUCT.md` §9.2 had arbitrary weights, undefined scales, and a contradictory uncertainty penalty.
* **Resolution:**
  * The synthetic 0–100 score is eliminated.
  * Replaced by an **Explainable Review Priority**:
    * `P1 (Immediate Review)`: High-entropy secret in production config/code with verified source status or critical exposure indicators; canary tokens requiring urgent isolation.
    * `P2 (High Priority)`: Unverified candidate secret in production code or exposed configuration.
    * `P3 (Normal Review)`: Candidate secret in non-production branch, test environment, or missing contextual details (`needs_review`).
    * `P4 (Low / Informational)`: Deterministic placeholder, documentation example, or known test fixture (`likely_placeholder`, `likely_test_value`).
  * Each priority assignment is accompanied by a transparent factor checklist: `[Classification: candidate_secret]`, `[File Context: production_config]`, `[Source Validity: unverified]`.

### 2.6 Asset Correlation Boundaries
* **Issue:** `PRODUCT.md` claimed asset correlation and blast radius estimation, which exceeds the information present in detector JSON.
* **Resolution:**
  * ETW extracts only contextual strings present directly within the ingested record or bounded snippet: file path, repository URL, commit author, hostnames, cloud resource ARNs, and package names.
  * Every association is explicitly tagged with an evidence level:
    * `observed`: Literally present in the detector finding.
    * `derived`: Matched via deterministic pattern in co-located code snippet.
    * `analyst_confirmed`: Verified by human investigator.
  * ETW explicitly disclaims verifying network reachability, credential permissions, or actual system access.

### 2.7 Static MCP Configuration Indicators
* **Issue:** `PRODUCT.md` listed rules that implied server reachability or authentication vulnerabilities from static config files.
* **Resolution:**
  * All MCP findings are designated `ConfigurationIndicator` or `ReviewFinding`, never `Vulnerability`.
  * Severities are lowered: Missing authentication fields are flagged as `MCP-CFG-002: Authentication Posture Not Evidenced in File` (Informational/Low), not "Unauthenticated Server".
  * ETW strictly never executes `command` or `args`, never fetches remote URLs, and never reads host environment variables.

### 2.8 Supported Input Formats and Pinned Versions
* **Issue:** Ambiguity over which scanner formats are mandatory for MVP.
* **Resolution:**
  * **Primary Mandatory Scanner:** **TruffleHog v3 JSON** (JSON array and line-delimited JSON).
  * **Secondary Supported Scanner:** **Gitleaks v8 JSON** (`gitleaks dir` / `gitleaks git` JSON report).
  * **Internal Benchmark Schema:** **ETW Synthetic Fixture v1 JSON**.
  * All parsers use strict Pydantic v2 schemas and fail closed on invalid or malicious inputs.

### 2.9 Untrusted, Malformed, and Conflicting Input Handling
* **Issue:** Input files could be massive, contain malformed JSON, exploit regex ReDoS, or inject Markdown into reports.
* **Resolution:**
  * **Size Bounds:** Max file size 50 MB; max snippet size 64 KB per finding.
  * **Defensive Parsing:** Stream parsing / line-by-line parsing for JSONL; malformed records generate structured parse errors and are quarantined into a run log without crashing the batch.
  * **Report Escaping:** All user-controlled strings (file paths, repo names, snippets) are escaped before rendering in Markdown and HTML.
  * **ReDoS Prevention:** Regexes are bounded and pre-compiled with timeout/length limits.

### 2.10 Storage Lifecycle, Permissions, and Retention
* **Issue:** Unclear database lifecycle, location, permissions, and migration policy.
* **Resolution:**
  * **Database Engine:** SQLite 3 with WAL (Write-Ahead Logging) enabled.
  * **Location:** Default `./.etw/etw.db` within the repository/project root, overrideable via `--db <path>`.
  * **File Permissions:** Restricted file creation masks (0600 on POSIX; ACL inheritance restricted on Windows).
  * **Lifecycle & Immutability:** Observations and run manifests are append-only. Case status updates create versioned audit events. Reports and exports are point-in-time immutable files.
  * **Purge Command:** `etw admin purge --run <run-id>` provides auditable removal of triage records.

---

## 3. Requirement Categorization Matrix

| Requirement | Proposed in `PRODUCT.md` | Reconciliation Decision | Action & Justification |
|---|---|---|---|
| **F-001: Local-first CLI** | Typer CLI | **Retain (Standardized)** | Use standard Python CLI (argparse/typer) with local SQLite and JSON/Markdown outputs. |
| **F-002: Credential Adapter** | TruffleHog and/or Gitleaks | **Retain (Explicitly Pinned)** | Pin TruffleHog v3 JSON & Gitleaks v8 JSON. |
| **F-003: Normalized Case Schema** | Finding/Case models | **Retain (Refined)** | Strict separation of `Observation`, `Case`, `Evidence`, and `Disposition`. |
| **F-004: Deduplication** | Keyed fingerprint | **Retain (Refined)** | Group by `(fingerprint, type, asset_scope)`. Retain all observation links. |
| **F-005: Secret-safe Storage** | No raw secrets persisted | **Retain (Hardened)** | Enforce in-memory only handling, HMAC-SHA256 fingerprints, exception scrubbing, and automated leak tests. |
| **F-006: Deterministic Triage** | Placeholders, test keys, canaries | **Retain** | Deterministic rule engine with positive/negative test suites and clear rationales. |
| **F-007: MCP Config Adapter** | `mcpServers` JSON | **Conditional (Phase 7 Gate)** | Build only after Phase 6 credential benchmark passes and value is demonstrated. |
| **F-008: MCP Static Rules** | 10 static config rules | **Conditional (Phase 7 Gate)** | Recalibrate severities to indicators; exclude runtime exploit assumptions. |
| **F-009: Shared Case Lifecycle** | `new`, `needs_review`, `confirmed`, etc. | **Retain (Refined)** | Rename `confirmed` to `confirmed_issue`; record timestamped audit log for status transitions. |
| **F-010: Asset/Context Extraction** | Hostnames, URLs, packages | **Retain (Bounded)** | Extract only from supplied records; tag as `observed` or `derived` candidates. |
| **F-011: Explainable Priority** | 0–100 score | **Redesign** | Replace with P1–P4 transparent triage priority matrix. |
| **F-012: Report Output** | Markdown and JSON | **Retain** | Escaped Jinja2 Markdown report and schema-validated JSON export. |
| **F-013: Benchmark Harness** | Fixture evaluation | **Retain (Elevated)** | Mandatory core feature: measure baseline vs. ETW, precision, recall, and false dismissals. |
| **F-014: Security & Leak Tests** | Secret leakage assertions | **Retain** | Mandatory automated test asserting 0 raw secrets across all output files. |
| **F-015: Documentation** | Docs, threat model, runbooks | **Retain** | Comprehensive docs under `docs/`. |
| **Live Credential Verification** | Proposed as stretch | **Exclude** | Prohibited in MVP. ETW preserves source verification only. |
| **Dynamic MCP Probing** | Out of scope | **Exclude** | Strictly prohibited. |

---

## 4. Unverified Assumptions & Boundary Declarations

1. **Internal CloudSEK Tooling:** Public job descriptions establish the nature of the triage tasks, but ETW makes no claim regarding internal CloudSEK software architectures.
2. **Economic Value:** No savings or ROI claims are asserted until empirical before-and-after triage timings are measured.
3. **Detection Accuracy:** ETW does not claim improved secret detection over TruffleHog or Gitleaks; its value lies entirely in post-detection noise reduction, evidence organization, and safe triage.
