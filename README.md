# Exposure Triage Workbench (ETW)

> **Important Legal Disclaimer:**
> Exposure Triage Workbench (ETW) is an independent security research prototype. It is **not affiliated with, endorsed by, sponsored by, or supported by CloudSEK**. All product concepts, names, and references are used solely for research evaluation and architectural triage bench design.

**Exposure Triage Workbench (ETW)** is a local-first, secret-safe post-detection triage engine for cybersecurity findings. It bridges the gap between raw detection scanners (such as TruffleHog and Gitleaks) and actionable security operations by applying deterministic evidence-based rules, keyed HMAC deduplication, transparent review priorities, and immutable audit trails—with **zero raw secret persistence** enforced by structural model serialization boundaries and verified by binary byte-level leak testing.

---

## Key Features

1. **Deterministic Classification Engine:**
   - Filters documentation placeholders and boilerplate (`RULE-PLACEHOLDER-001`).
   - Identifies unit-test fixtures and mock keys (`RULE-TEST-001`).
   - Alerts on active Canary tokens with a **mandatory non-interaction warning** (`RULE-CANARY-001`).
   - Conservatively defers ambiguous, low-entropy findings to human analysts (`RULE-AMBIGUOUS-001`).
   - Classifies high-confidence credentials without making unverified claims of exploitability (`RULE-CANDIDATE-001`).

2. **Zero Raw Secret Persistence:**
   - Secrets are processed in-memory only.
   - Credentials are represented in storage, logs, reports, and exports exclusively by truncated keyed **HMAC-SHA256 digests** (`hmac-sha256:[a-f0-9]{32}`) and redacted snippets.
   - Verified by active binary byte-level leak tests against SQLite database and WAL files.

3. **Strict Asset-Scoped Case Correlation:**
   - Deduplicates repeated sightings of identical credentials within the same asset scope.
   - **Never merges separate repositories or assets** even if secret fingerprints match; instead, links cross-scope collisions via `related_cases`.

4. **Transparent P1–P4 Review Priorities:**
   - **P1 (Urgent):** Upstream scanner-verified credentials or active Canary tokens.
   - **P2 (High):** Well-formed candidate secrets in operational scopes.
   - **P3 (Normal):** Ambiguous findings requiring manual review.
   - **P4 (Low / Noise):** Filtered documentation placeholders and test fixtures.

5. **Static Model Context Protocol (MCP) Config Inspection:**
   - Passively inspects MCP server configurations (`claude_desktop_config.json`, etc.).
   - Pure AST / JSON inspection: **Zero process executions, zero network requests, zero environment variable expansions**.
   - Flags cleartext HTTP transports (`MCP-CFG-001`), hardcoded credentials (`MCP-CFG-003`), and root filesystem access (`MCP-CFG-007`).

---

## Installation

ETW is built with Python (>= 3.10) and standard libraries with minimal external dependencies (`pydantic>=2.0.0`, `jinja2>=3.0.0`).

```bash
# Clone the repository
git clone <repository-url>
cd CloudSEK

# Install in editable mode
pip install -e .
```

---

## Portfolio Guides & Technical Documentation

For interviewers, security leads, and evaluators, detailed technical documentation is available:

- [**docs/PORTFOLIO_DEMO.md**](docs/PORTFOLIO_DEMO.md) — Step-by-step reproducible walkthrough covering ingestion, triage, analyst disposition, report generation, and benchmarking.
- [**docs/PROJECT_OVERVIEW.md**](docs/PROJECT_OVERVIEW.md) — Comprehensive architecture specification, problem statement, threat model, ADRs, and limitations.
- [**docs/INTERVIEW_PREPARATION.md**](docs/INTERVIEW_PREPARATION.md) — Deep-dive interview defense covering HMAC security, SQLite WAL concurrency, case scoping, and design trade-offs.
- **One-Command Automated Verification:** Run `python scripts/verify_demo_cli.py` to execute the complete end-to-end demo and verify zero-leakage assertions in a clean temporary workspace.

---

## CLI Quickstart & Usage

The `etw` command-line interface provides end-to-end finding ingestion, triage review, case management, and export capabilities.

### 1. Ingest Scanner Findings
Ingest TruffleHog v3, Gitleaks v8, or MCP configuration outputs. Formats are auto-detected:

```bash
# Ingest TruffleHog JSONL findings
etw ingest datasets/fixtures-v1/trufflehog_fixtures.jsonl

# Ingest Gitleaks JSON findings
etw ingest datasets/fixtures-v1/gitleaks_fixtures.json

# Ingest Model Context Protocol configuration
etw ingest datasets/fixtures-v1/sample_mcp_config.json
```

### 2. Inspect and Filter Cases
List deduplicated cases stored in the local SQLite database (`./.etw/etw.db`):

```bash
# List all cases
etw case list

# Filter by review priority (P1_urgent, P2_high, P3_normal, P4_low)
etw case list --priority P1_urgent

# Filter by disposition status
etw case list --status new
```

### 3. Review Case Evidence & Provenance
Display detailed observation provenance, classification rationale, priority factors, related cases, and audit history:

```bash
etw case show <CASE_ID>
```

### 4. Record Analyst Disposition
Update the disposition of a case with an immutable, timestamped audit log entry:

```bash
etw case set-status <CASE_ID> --status confirmed_issue --actor "alice_analyst" --note "Verified credential with asset owner; rotation initiated without live secret testing."
```

Valid disposition states: `new`, `needs_review`, `confirmed_issue`, `false_positive`, `accepted_risk`, `remediated`.

> **Safety Notice:** ETW workflows strictly forbid live credential testing or unauthorized network probing. Analyst verification relies exclusively on static context and direct escalation to asset owners for internal validation.

### 5. Generate Sanitized Reports and Exports
Produce human-readable Markdown reports or schema-validated JSON export bundles:

```bash
# Generate Markdown triage report with provenance links and audit log
etw report -o triage_report.md

# Generate structured JSON export
etw export --format json -o triage_export.json
```

### 6. Run Comparative Benchmark Harness
Execute the automated benchmark against the 68 synthetic labelled fixtures:

```bash
etw benchmark run -o benchmark/results/benchmark_report.json
```

### 7. Run Purging & Data Retention
Safely purge an ingested run and its associated records according to local data retention policies, automatically cleaning up orphaned cases:

```bash
etw purge run-20261011-120000
```

---

## Benchmark Results (Decision Gate 1)

Evaluated against the pinned, synthetic test corpus in `datasets/fixtures-v1/`:

| Metric | Target | Evaluated Result | Gate Status |
| :--- | :---: | :---: | :---: |
| **Raw Secret Leakage** | 0 leaks | **0 leaks** | **PASS** |
| **False Dismissal Rate** | 0.0% | **0.0%** (0 / 29) | **PASS** |
| **Noise Reduction (P4)** | >= 70% | **100.0%** (22 / 22 fixtures to P4) | **PASS** |
| **Cross-Repo Separation** | 0 merges | **0 cross-repo merges** | **PASS** |
| **Duplicate Consolidation** | Verified | **8.1% net case reduction** | **PASS** |
| **Macro Precision / Recall** | Ground Truth | **100.0% / 100.0%** | **PASS** |

> **Benchmark Disclaimer:**
> Synthetic fixture results validate contract adherence, rule correctness, and defensive parser boundaries, but do **not** establish real-world accuracy on noisy enterprise codebases.

---

## Running the Automated Test Suite

ETW includes comprehensive unit, integration, and security test suites:

```bash
# Run all ETW domain and security tests (76 tests)
pytest tests/

# Run the agent observability dashboard test suite (20 tests)
pytest tools/agent-observability/tests/

# Run the complete test suite (96 tests total)
pytest tests/ tools/agent-observability/tests/
```

---

## Project Structure

```
├── .etw/                         # Default local SQLite database (etw.db) and HMAC keys
├── datasets/fixtures-v1/         # 68 labelled synthetic test fixtures
├── docs/                         # Reconciled specs, ADRs, threat model, benchmark plan
├── src/etw/
│   ├── analysis/                 # Case correlation, grouping, and prioritization
│   ├── benchmark/                # Comparative benchmark evaluation runner
│   ├── ingest/                   # Streaming TruffleHog, Gitleaks, and MCP adapters
│   ├── models/                   # Strict Pydantic domain models and enums
│   ├── reports/                  # Sanitized Markdown reports and JSON exports
│   ├── rules/                    # Deterministic classification rules & MCP indicators
│   ├── storage/                  # SQLite WAL persistence, HMAC fingerprinting, redaction
│   └── cli.py                    # Unified CLI command interface
├── tests/
│   ├── integration/              # CLI and end-to-end lifecycle integration tests
│   ├── security/                 # Zero secret leakage and byte-level persistence tests
│   └── unit/                     # Classifier, correlation, database, and model tests
└── tools/agent-observability/    # Localhost development toolchain dashboard (port 8765)
```

---

## License

Proprietary — Internal Developer & Security Research Prototype.
