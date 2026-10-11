# Exposure Triage Workbench (ETW) — Portfolio Demonstration Guide

> **Notice & Legal Disclaimer:**
> Exposure Triage Workbench (ETW) is an independent cybersecurity engineering research project. It is **not affiliated with, endorsed by, sponsored by, or supported by CloudSEK**. All benchmarks and demonstration fixtures use synthetic, locally generated test data and do not represent production customer environments.

---

## 1. Executive Summary & Demonstration Objective

Security detection scanners (such as TruffleHog and Gitleaks) generate thousands of raw findings across enterprise repositories. However, security teams face a severe post-detection operational bottleneck:
1. **High False-Positive Volume:** Documentation placeholders (`example_token`), unit-test mocks (`test_secret_123`), and low-entropy strings flood triage queues.
2. **Tripwire Hazards:** Untracked canary tokens (e.g. Thinkst Canarytokens) risk being triggered by automated testers, alerting adversaries or triggering false alarms.
3. **Blast Radius Obfuscation:** Blind deduplication across disparate repositories conflates distinct access scopes into single tickets, destroying ownership provenance.
4. **Secondary Data Breach Risk:** Centralizing raw, plaintext secrets into SaaS ticketing systems and databases creates high-value targets for attackers.

**Exposure Triage Workbench (ETW)** solves these challenges via a local-first, secret-safe triage pipeline:
- **Zero Raw Secret Persistence:** Credentials exist in memory only during parsing; storage, logs, and reports strictly use keyed **HMAC-SHA256 digests** and masked previews.
- **Deterministic Explainable Triage:** Rule-based classification separates verified secrets, canaries, placeholders, and test values.
- **Asset-Scoped Correlation:** Deduplicates identical credentials within an asset boundary without merging cross-repository scopes.
- **Strict Safe-Validation Policy:** Zero automated live credential testing or unauthorized network probing.

This guide provides a reproducible, step-by-step walkthrough to demonstrate the full ETW workflow on a local machine.

---

## 2. Environment Prerequisites & Installation

### Requirements:
- Python 3.10+
- SQLite 3.35+ (bundled with standard Python)
- Git (optional, for repository management)

### Clean Setup:
Clone the repository and install ETW in editable mode:

```bash
# Clone the repository
git clone https://github.com/hx010207/ETW.git
cd ETW

# Install dependencies and CLI entrypoint
pip install -e .
```

Verify that the CLI is accessible:

```bash
etw --help
```

Expected output:
```text
usage: etw [-h] [--db DB] {ingest,triage,case,report,export,benchmark,purge} ...

Exposure Triage Workbench (ETW) - Local-first security finding triage
...
```

---

## 3. Step-by-Step Demonstration Walkthrough

To ensure this demonstration is completely reproducible and does not mutate existing data, all commands below use an isolated temporary database path: `--db ./demo_workspace/demo.db`.

Create the demo workspace:
```bash
mkdir demo_workspace
```

---

### Step 1: Ingest Multi-Source Scanner Findings

ETW ingests findings from different scanner formats and normalizes them into a unified, secret-safe data contract. Formats are auto-detected.

#### A. Ingest TruffleHog v3 JSONL Findings:
```bash
etw --db ./demo_workspace/demo.db ingest datasets/fixtures-v1/trufflehog_fixtures.jsonl
```
*Expected Output:*
```text
Ingestion successful [Run ID: run-2026xxxx-xxxxxx]
  Source file:        datasets/fixtures-v1/trufflehog_fixtures.jsonl (trufflehog)
  Records ingested:   34 (31 valid, 3 quarantined)
  Cases correlated:   29 deduplicated cases
  Triage priorities:  P1=5 | P2=10 | P3=3 | P4 (noise)=11
```
> **What happened:** 34 raw findings were streamed. 3 malformed JSON records were defensively quarantined without crashing. Valid findings were converted to in-memory `Observation` objects with raw secrets replaced by keyed HMAC digests before persistence.

#### B. Ingest Gitleaks v8 JSON Findings:
```bash
etw --db ./demo_workspace/demo.db ingest datasets/fixtures-v1/gitleaks_fixtures.json
```
*Expected Output:*
```text
Ingestion successful [Run ID: run-2026xxxx-xxxxxx]
  Source file:        datasets/fixtures-v1/gitleaks_fixtures.json (gitleaks)
  Records ingested:   34 (31 valid, 3 quarantined)
  Cases correlated:   28 deduplicated cases
  Triage priorities:  P1=3 | P2=11 | P3=3 | P4 (noise)=11
```

#### C. Ingest Model Context Protocol (MCP) Configuration:
```bash
etw --db ./demo_workspace/demo.db ingest datasets/fixtures-v1/sample_mcp_config.json
```
*Expected Output:*
```text
Ingestion successful [Run ID: run-2026xxxx-xxxxxx]
  Source file:        datasets/fixtures-v1/sample_mcp_config.json (mcp)
  Records ingested:   3 (3 valid, 0 quarantined)
  Cases correlated:   3 deduplicated cases
  Triage priorities:  P1=0 | P2=3 | P3=0 | P4 (noise)=0
```
> **Security Highlight:** The MCP adapter performs pure AST/JSON inspection. It executes zero subprocesses, makes zero network requests, and evaluates zero environment variables.

---

### Step 2: Global Triage & Correlation Re-Evaluation

Run global correlation across all ingested runs to consolidate cross-run observations and link multi-scope sightings:

```bash
etw --db ./demo_workspace/demo.db triage
```
*Expected Output:*
```text
Triage re-evaluation complete. Correlated 65 observations into 60 cases.
```

---

### Step 3: Prioritized Case Listing & Noise Filtering

ETW classifies findings into transparent priority tiers (P1 to P4). Analysts immediately focus on urgent exposures while low-priority noise is separated.

#### A. Inspect P1 Urgent Cases (Verified Credentials & Canaries):
```bash
etw --db ./demo_workspace/demo.db case list --priority P1_urgent
```
*Sample Output:*
```text
CASE ID            PRIORITY     CLASSIFICATION       STATUS           SCOPE                    FINDINGS
---------------------------------------------------------------------------------------------------------
case-9e83697a26de  P1_urgent    candidate_secret     new              org/prod-payments        1       
case-f135271a2002  P1_urgent    candidate_secret     new              org/prod-cloud           1       
case-8fb0b47573a6  P1_urgent    likely_canary        new              org/honey-pot            1       
case-e7e8963465a5  P1_urgent    candidate_secret     new              org/monorepo             2       
case-1b1390f94f23  P1_urgent    likely_canary        new              default-scope            1
```

#### B. Inspect P4 Noise Cases (Filtered Placeholders & Test Mocks):
```bash
etw --db ./demo_workspace/demo.db case list --priority P4_low
```
*Sample Output:*
```text
CASE ID            PRIORITY     CLASSIFICATION       STATUS           SCOPE                    FINDINGS
---------------------------------------------------------------------------------------------------------
case-e8d40a4d37fa  P4_low       likely_placeholder   new              org/sample-app           1       
case-46984435dde4  P4_low       likely_test_value    new              org/billing              1       
case-9165afd2bc23  P4_low       likely_test_value    new              org/client-lib           1
...
```
> **Analyst Value:** 22 noise cases (documentation examples and mock fixtures) were automatically downgraded to P4, eliminating queue clutter without risking silent dismissal.

---

### Step 4: Deep Evidence Review & Provenance Inspection

Inspect a specific case to view full location evidence, commit attribution, HMAC fingerprint, and explainable classification rationale:

```bash
etw --db ./demo_workspace/demo.db case show case-9e83697a26de
```
*Expected Output:*
```text
=== Case case-9e83697a26de ===
Priority:             P1_urgent
Classification:       candidate_secret
Disposition:          new
Credential Type:      StripeLiveKey
Asset Scope:          org/prod-payments
HMAC Fingerprint:     hmac-sha256:ffb099d26648ca285c42d3de6f17162e
Observations Count:   1
Priority Factors:     scanner_reported_verified, operational_scope_candidate

Classification Rationale:
  - Candidate secret in operational path 'services/stripe_client.py' reported as verified by scanner; prioritized for urgent review.

Observations (1):
  - ID: obs-th-b3ee0aec5ebd | Detector: trufflehog | Path: services/stripe_client.py:28
    Match (Masked): sk_l...[REDACTED]...CC

Audit History:
  [2026-10-11T12:00:00.000000+00:00] new -> new by 'system': Correlated 1 observation(s) under scope org/prod-payments
```
> **Evidence Boundaries:**
> 1. Raw secret is **never shown**—only the masked snippet `sk_l...[REDACTED]...CC`.
> 2. Scanner verification (`scanner_reported_verified`) is recorded as source evidence, distinct from confirmed incident impact.

---

### Step 5: Record Analyst Disposition (Safe Validation Workflow)

ETW enforces a strict safe-validation policy: analysts never run live credential tests against third-party endpoints. Instead, disposition transitions reflect asset-owner validation, key rotation, or policy exceptions.

Record an auditable disposition transition:

```bash
etw --db ./demo_workspace/demo.db case set-status case-9e83697a26de \
  --status confirmed_issue \
  --actor "security_analyst" \
  --note "Verified live key with engineering owner via ticket SEC-402; rotation initiated without live secret testing."
```

Re-inspect the case to confirm the immutable audit trail:
```bash
etw --db ./demo_workspace/demo.db case show case-9e83697a26de
```
*Notice the appended audit record:*
```text
Audit History:
  [2026-10-11T12:00:00.000000+00:00] new -> new by 'system': Correlated 1 observation(s) under scope org/prod-payments
  [2026-10-11T12:05:00.000000+00:00] new -> confirmed_issue by 'security_analyst': Verified live key with engineering owner via ticket SEC-402; rotation initiated without live secret testing.
```

---

### Step 6: Generate Sanitized Reports and Machine Exports

#### A. Generate Human-Readable Markdown Report:
```bash
etw --db ./demo_workspace/demo.db report -o ./demo_workspace/triage_report.md
```
Open and inspect `./demo_workspace/triage_report.md`. It includes:
- Executive summary metrics (case counts, priority distribution, noise reduction percentage).
- Canary token warning callouts: `> [!CAUTION] Active Canary Token detected. DO NOT connect, curl, or validate live.`
- Redacted evidence tables and audit history.
- Zero raw secrets.

#### B. Generate Schema-Validated JSON Export:
```bash
etw --db ./demo_workspace/demo.db export --format json -o ./demo_workspace/triage_export.json
```
Inspect `./demo_workspace/triage_export.json` to verify machine-readable export integration for SIEM / SOAR tools.

---

### Step 7: Run the Automated Comparative Benchmark

Evaluate ETW's deterministic classification and deduplication engine against the ground truth fixture corpus:

```bash
etw benchmark run -o ./demo_workspace/benchmark_report.json
```

*Expected Terminal Output:*
```text
================================================================================
 EXPOSURE TRIAGE WORKBENCH (ETW) - BENCHMARK EVALUATION REPORT
================================================================================
Dataset:              datasets/fixtures-v1 (68 Synthetic Fixtures)
Total Raw Findings:   68 (34 TruffleHog + 34 Gitleaks)
Valid Observations:   62 (100% normalized)
Quarantined Records:  6 (100% defensive error handling)
Deduplicated Cases:   57 Cases (from 62 observations)
Duplicate Reduction:  8.1% reduction in analyst review units
Cross-Repo Separation:0 erroneous merges (strict asset scope boundary)
--------------------------------------------------------------------------------
CLASSIFICATION PERFORMANCE (N = 62 Valid Observations):
  False Dismissals:   0 (Rate: 0.0%)
  - candidate_secret    : Precision = 100.0% | Recall = 100.0% (Support: 29)
  - likely_placeholder  : Precision = 100.0% | Recall = 100.0% (Support: 12)
  - likely_test_value   : Precision = 100.0% | Recall = 100.0% (Support: 10)
  - likely_canary       : Precision = 100.0% | Recall = 100.0% (Support: 5)
  - needs_review        : Precision = 100.0% | Recall = 100.0% (Support: 6)
--------------------------------------------------------------------------------
DECISION GATE 1 STATUS: [PASS]
  [PASS] Zero Secret Leakage:       PASS (Keyed HMAC-SHA256, in-memory redaction)
  [PASS] Zero False Dismissals:     PASS (0.0% false dismissal rate)
  [PASS] Noise Reduction:           PASS (38.6% of cases categorized to P4 low priority)
  [PASS] Duplicate Consolidation:   PASS (8.1% reduction, 0 cross-scope merges)
  [PASS] Deterministic Repeatable:  PASS (100% identical outputs)
================================================================================
Note: Synthetic fixture results validate contract adherence and parser safety,
but do NOT establish real-world triage accuracy on enterprise noise.
================================================================================
```

---

### Step 8: Safe Retention Purging

Verify that historic ingestion runs can be purged in accordance with data-retention policies while automatically cleaning up orphaned cases:

```bash
# Obtain run ID from database or previous ingestion output
etw --db ./demo_workspace/demo.db purge run-2026xxxx-xxxxxx
```
*Expected Output:*
```text
Run 'run-2026xxxx-xxxxxx' and associated records successfully purged.
```

---

### Step 9: Clean Up Temporary Workspace

Remove the isolated demo directory when finished:
```bash
rm -rf demo_workspace
```

---

## 4. One-Command Automated Reproduction Script

To verify all demonstration steps, assertions, and zero-leakage checks programmatically in one command, run:

```bash
python scripts/verify_demo_cli.py
```

This script:
1. Creates an isolated temporary SQLite database.
2. Ingests all synthetic fixtures (TruffleHog, Gitleaks, MCP).
3. Executes triage, filtering, case display, and disposition updates.
4. Generates Markdown and JSON reports.
5. Performs a binary byte-level search across the SQLite database file and reports to assert 0 raw secrets.
6. Tests run purging and cleans up all temporary artifacts.
7. Exits with code 0 upon complete success.
