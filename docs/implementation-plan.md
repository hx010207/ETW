# Exposure Triage Workbench (ETW) — Phase-by-Phase Implementation Plan

**Document Version:** 1.0  
**Date:** 2026-10-11  
**Status:** Approved Implementation Roadmap  

---

## 1. Overview & Phased Roadmap

This plan translates the reconciled product specification into discrete, test-driven engineering milestones. Each phase defines concrete deliverables, test criteria, and exit conditions. In accordance with the project hierarchy, all tasks adhere to Superpowers TDD and Ponytail simplicity.

```
[Phase 1: Recon & Scope]  <-- COMPLETED
         |
         v
[Phase 2: Contracts & Fixtures]  --> [Models + Pinned Test Corpus]
         |
         v
[Phase 3: Ingestion & Normalization]  --> [TruffleHog & Gitleaks Parsers]
         |
         v
[Phase 4: Classification & HMAC Engine]  --> [Rule Engine + Zero-Leak Boundary]
         |
         v
[Phase 5: Cases, Priority & Reports]  --> [Scoped Cases, Reports & CLI]
         |
         v
[Phase 6: Benchmark & CodeRabbit Review]  --> [Gate Evaluation]
         |
         +-------------------------------------+
         | (Gate Passed)                       | (Gate Failed / Deferred)
         v                                     v
[Phase 7: Conditional Static MCP Check]     [Halt / Refine Credential Core]
         |                                     |
         +------------------+------------------+
                            |
                            v
[Phase 8: Final Verification & Release]
```

---

## 2. Detailed Phase Breakdown

### Phase 1 — Reconnaissance and Architectural Reconciliation (Status: COMPLETE)
* **Goal:** Inspect repository, environment, and source documents; resolve specification contradictions; author baseline planning artifacts.
* **Deliverables:**
  - `docs/product-reconciliation.md`
  - `docs/decisions/0001-mvp-scope.md`
  - `docs/threat-model.md`
  - `docs/benchmark-plan.md`
  - `docs/implementation-plan.md`
* **Exit Criteria:** All 10 architectural questions resolved; safety boundaries and evaluation gates accepted.

---

### Phase 2 — Data Contracts & Test Fixtures
* **Goal:** Define strict Pydantic v2 schemas and build the comprehensive, labelled synthetic evaluation dataset.
* **Tasks:**
  1. Define core domain schemas in `src/etw/models/`:
     - `Observation`: Raw external detector sighting (UUID, detector type, source metadata, raw candidate in private memory field).
     - `Evidence`: Context snippet, file path, line numbers, commit, repository, asset scope.
     - `ClassificationState`: Enum (`candidate_secret`, `likely_placeholder`, `likely_test_value`, `likely_canary`, `needs_review`, `excluded_by_policy`).
     - `DispositionState`: Enum (`new`, `needs_review`, `confirmed_issue`, `false_positive`, `accepted_risk`, `remediated`).
     - `Case`: Grouped analyst entity with fingerprint, type, scope, priority, observations, and audit events.
  2. Implement strict serialization controls:
     - `raw_secret` marked `exclude=True` on all models; impossible to emit in `model_dump()` or `model_dump_json()`.
  3. Author the 68-finding labelled test corpus in `datasets/fixtures-v1/`:
     - `fixtures_trufflehog.json`
     - `fixtures_gitleaks.json`
     - `ground_truth_labels.json`
* **Verification & Test Criteria:**
  - Unit tests in `tests/unit/test_models.py` verify validation rules, missing optional fields, and serialization safety.

---

### Phase 3 — Ingestion & Normalization
* **Goal:** Implement secure, streaming input adapters for external scanner JSON formats.
* **Tasks:**
  1. Build `src/etw/ingest/trufflehog.py`:
     - Ingest TruffleHog v3 JSON lines and JSON arrays.
     - Extract detector type, verified status, file path, line number, and raw secret snippet.
  2. Build `src/etw/ingest/gitleaks.py`:
     - Ingest Gitleaks v8 JSON output.
     - Extract rule ID, commit, author, line number, and secret match.
  3. Implement input defensive boundaries:
     - Stream processing with line size limit (max 64 KB per snippet, max 50 MB per file).
     - Non-blocking error quarantine for malformed or truncated records.
* **Verification & Test Criteria:**
  - Unit tests in `tests/unit/test_ingest.py` validating valid, malformed, non-UTF8, and edge-case inputs.

---

### Phase 4 — Deterministic Classification & Keyed HMAC Storage
* **Goal:** Build the secret-safe HMAC fingerprinting service and the deterministic rule classification engine.
* **Tasks:**
  1. Build `src/etw/storage/fingerprint.py`:
     - Keyed HMAC-SHA256 generation using `ETW_HMAC_KEY` or `.etw/hmac.key`.
     - Output truncated hex format: `hmac-sha256:[a-f0-9]{32}`.
  2. Build `src/etw/rules/classifier.py`:
     - Deterministic regex & pattern matchers for documentation examples and placeholders.
     - Known test credentials and unit-test context matchers.
     - Canary token markers (Canarytokens, AWS canary markers).
     - Entropy calculation as a secondary supporting signal.
     - Explanation generator providing rule IDs and explicit evidence rationale for every label.
  3. Build in-memory redaction boundary in `src/etw/storage/redaction.py`:
     - Central scrubber replacing raw secrets with redacted badges.
* **Verification & Test Criteria:**
  - `tests/unit/test_classifier.py`: Positive and negative test for every classification rule.
  - `tests/security/test_zero_secret_leakage.py`: Seeded secret persistence test.

---

### Phase 5 — Cases, Review Priority, Reports & CLI
* **Goal:** Implement case deduplication, explainable P1–P4 review priority, SQLite persistence, report generation, and CLI interface.
* **Tasks:**
  1. Build `src/etw/analysis/case_grouper.py`:
     - Group observations by `(fingerprint, type, asset_scope)`.
     - Link identical fingerprints across different scopes via `RelatedCases`.
  2. Build `src/etw/analysis/prioritize.py`:
     - Calculate explainable P1–P4 review priority based on classification, file context, and source verification.
  3. Build `src/etw/storage/database.py`:
     - SQLite database with WAL mode storing cases, observations, and audit transitions.
  4. Build `src/etw/reports/`:
     - `markdown.py`: Escaped Jinja2 Markdown report generator with provenance links.
     - `json_export.py`: Schema-validated JSON export generator.
  5. Build `src/etw/cli.py`:
     - CLI commands: `ingest`, `cases list`, `cases show`, `cases set-status`, `report`, `benchmark`.
* **Verification & Test Criteria:**
  - `tests/integration/test_pipeline.py`: Full end-to-end run from scanner JSON to Markdown and JSON reports.

---

### Phase 6 — Benchmark Evaluation & Critical Review
* **Goal:** Execute the automated benchmark on the labelled corpus, verify success metrics, and run independent CodeRabbit review.
* **Tasks:**
  1. Implement `src/etw/benchmark/runner.py`:
     - Ingest `datasets/fixtures-v1/`.
     - Run Baseline (raw un-deduplicated findings) vs. ETW.
     - Compute precision, recall, false dismissal count, and duplicate reduction.
  2. Evaluate Phase 6 Gate:
     - 0 raw secret leaks?
     - 0 false dismissals?
     - >70% placeholder noise reduction?
  3. Execute automated test suite and record coverage.
  4. Run CodeRabbit review (`coderabbit review --agent` or user-authenticated CLI) and inspect findings.
* **Exit Criteria:** Phase 6 Gate passed; benchmark results recorded in `benchmark/results/`.

---

### Phase 7 — Conditional Static MCP Configuration Analysis
* **Goal:** (Conditional on Phase 6 pass) Implement bounded, passive MCP configuration analysis.
* **Tasks:**
  1. Build `src/etw/ingest/mcp_config.py`:
     - Parse `mcpServers` JSON structures without executing commands.
  2. Build `src/etw/rules/mcp.py`:
     - High-signal static indicators (`MCP-CFG-001` cleartext remote HTTP, `MCP-CFG-003` literal secret in config string, `MCP-CFG-007` dangerous capability hints).
  3. Integrate MCP findings into the shared `Case` and `Report` pipelines.
* **Verification & Test Criteria:**
  - Tests validating zero subprocess calls, zero network calls, and safe parsing of malformed configs.

---

### Phase 8 — Final Verification & Release Readiness
* **Goal:** Finalize installation reproducibility, runbook documentation, and release integrity.
* **Tasks:**
  1. Verify clean setup and documentation execution.
  2. Generate demonstration walkthrough using synthetic data.
  3. Audit git diff to ensure only intentional, clean changes exist.
  4. Publish final engineering and benchmark summary report.
