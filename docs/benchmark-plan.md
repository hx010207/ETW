# Exposure Triage Workbench (ETW) — Benchmark Methodology & Evaluation Plan

**Document Version:** 1.0  
**Date:** 2026-10-11  
**Status:** Approved Benchmark Specification  

---

## 1. Objective and Core Hypothesis

The goal of this benchmark is to rigorously and reproducibly evaluate whether ETW delivers measurable triage efficiency, noise reduction, and safety improvements over raw secret-scanner output.

### Primary Hypothesis
> *Applying deterministic context classification, keyed deduplication, and evidence-linked reporting to raw detector output substantially reduces analyst review units and eliminates routine placeholder/test noise without causing false dismissals of genuine candidate secrets or persisting sensitive values.*

---

## 2. Experimental Design: Baseline vs. ETW

To eliminate subjective claims, the benchmark conducts a side-by-side comparison between two workflows on the identical, pinned dataset:

```
               [Labelled Synthetic Corpus (datasets/fixtures-v1)]
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
         [BASELINE WORKFLOW]                     [ETW WORKFLOW]
    Raw Scanner JSON Ingestion              ETW Ingest, Classify, Group
                 |                                       |
    - 1 Finding = 1 Review Unit             - Grouped into De-duplicated Cases
    - No Automated Categorization           - Deterministic Placeholders Filtered
    - Manual De-duplication Needed          - Canary Tokens Urgently Flagged
    - Raw Secrets Unredacted in Output      - Provenance & Evidence Linked
                 |                          - Zero Raw Secrets Persisted
                 v                                       v
       [Baseline Metrics]                        [ETW Metrics]
                 \                                       /
                  \                                     /
                   v                                   v
             [COMPARATIVE EVALUATION & CONFUSION MATRIX]
```

### Workflow A: The Baseline (Raw Scanner Output)
* Every raw detection emitted by TruffleHog or Gitleaks is treated as an individual, un-deduplicated review unit.
* An analyst must inspect every finding linearly to determine whether it is an example string, test key, canary, or active candidate.
* Duplicate findings appearing across multiple commits or files must be manually matched.
* Raw secrets remain visible in the raw scanner JSON output.

### Workflow B: The ETW Triage Pipeline
* Ingests the raw detector output.
* Normalizes findings into `Observation` records and groups them into scoped `Case` records using keyed HMAC fingerprints.
* Evaluates deterministic rules for placeholders, test keys, and canaries with explicit evidence rationale.
* Assigns transparent P1–P4 review priority.
* Emits a redacted JSON case bundle and an evidence-backed Markdown triage report.

---

## 3. Labelled Corpus Composition (`datasets/fixtures-v1/`)

The evaluation corpus consists of synthetic, ethically crafted, and strictly non-production test fixtures covering realistic detection scenarios:

| Category | Description | Count | Expected ETW Label |
|---|---|---:|---|
| **True Candidate Secrets** | Realistic API keys, tokens, and database connection strings in production-like configurations and code. | 15 | `candidate_secret` (Priority P1 / P2) |
| **Documentation Placeholders** | Standard documentation strings (`YOUR_API_KEY_HERE`, `<insert-key-here>`, `sk_live_xxx...`, `example_secret`). | 12 | `likely_placeholder` (Priority P4) |
| **Unit Test Fixtures** | Obvious mock strings, unit-test credentials, and fixture files (`test_secret_123`, `mock_token_abc`, in `test_*.py`). | 10 | `likely_test_value` (Priority P4) |
| **Canary Tokens** | Documented canary formats (e.g. Canarytokens markers, AWS canary markers) requiring urgent non-interaction warnings. | 5 | `likely_canary` (Priority P1 Caution) |
| **Repeated Sightings (Duplicates)** | The same candidate credential appearing across multiple files, commits, and lines within the same repository. | 10 | Grouped into existing Cases |
| **Cross-Repository Collisions** | The identical test credential appearing in two separate repository scopes (must NOT be merged into one Case). | 4 | 2 Distinct Cases with `RelatedCases` link |
| **Ambiguous / Incomplete Context** | Low-entropy or truncated strings without definitive keywords requiring human analyst adjudication. | 6 | `needs_review` (Priority P3) |
| **Malformed / Edge-Case Inputs** | Truncated JSON lines, invalid UTF-8 bytes, missing required fields, oversized context windows. | 6 | Quarantine with parse warning |
| **Total Test Corpus** | | **68** | |

---

## 4. Evaluation Metrics & Mathematical Definitions

### 4.1 Classification Accuracy & Confusion Matrix
For each category $c \in \{\text{candidate\_secret}, \text{likely\_placeholder}, \text{likely\_test\_value}, \text{likely\_canary}, \text{needs\_review}\}$:
$$\text{Precision}_c = \frac{\text{True Positives}_c}{\text{True Positives}_c + \text{False Positives}_c}$$
$$\text{Recall}_c = \frac{\text{True Positives}_c}{\text{True Positives}_c + \text{False Negatives}_c}$$

### 4.2 False Dismissal Rate (Critical Safety Metric)
A **False Dismissal** occurs when a genuine candidate secret is erroneously categorized as a placeholder, test value, or excluded:
$$\text{False Dismissal Rate} = \frac{\text{Count}(\text{True Candidate Secret classified as Placeholder/Test/Excluded})}{\text{Total True Candidate Secrets}}$$
* **Target:** **Exactly 0.0%**. Any false dismissal of a real candidate is an unacceptable safety defect.

### 4.3 Duplicate Reduction & Erroneous Merge Rate
* **Duplicate Reduction Ratio:**
$$\text{Duplicate Reduction} = 1 - \frac{\text{Total Generated Cases}}{\text{Total Valid Observations}}$$
* **Erroneous Merge Count:** Instances where observations from different repository scopes or asset owners were incorrectly combined into a single case.
* **Target:** **Zero Erroneous Merges**.

### 4.4 Redaction & Secret-Safe Storage Pass Rate
$$\text{Secret Leakage Count} = \text{Occurrences of raw secret strings in DB, WAL, logs, reports, or JSON exports}$$
* **Target:** **Zero Leaks (100% Pass Rate)**.

### 4.5 Evidence Completeness
$$\text{Evidence Completeness} = \frac{\text{Claims backed by direct evidence or explicit inference labels}}{\text{Total claims in generated report}}$$
* **Target:** **100% Completeness**.

---

## 5. Decision Gates & Acceptance Criteria

### Gate 1: Phase 6 Credential Evaluation Gate (Pre-requisite for Release & Phase 7)
The credential triage pipeline passes if and only if all of the following conditions are met:
1. **Zero Secret Leakage:** Seeded raw secret strings appear 0 times in `.etw/etw.db`, `-wal`, `-shm`, logs, terminal outputs, and reports.
2. **Zero False Dismissals:** 0 genuine candidate secrets are classified as `likely_placeholder` or `likely_test_value`.
3. **High Noise Reduction:** At least 70% of placeholder/test-key fixtures correctly classified to P4 low priority.
4. **Duplicate Consolidation:** Repeated findings in the same scope reduce total review units by at least 25% without cross-repository collisions.
5. **Reproducibility:** Running `etw benchmark run` on the pinned dataset reproduces identical metrics across runs.

### Abort / Failure Protocol:
* If secret leakage occurs: **Immediate halt.** Block release and re-implement memory redaction boundary.
* If false dismissals > 0: **Gate failed.** Tighten classification rules to downgrade uncertain matches to `needs_review` rather than discarding. Do not advance to Phase 7 (MCP).
