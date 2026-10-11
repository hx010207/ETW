# ETW Labelled Synthetic Fixture Dataset (v1)

**Version:** 1.0.0  
**Date:** 2026-10-11  
**Total Records:** 68 labelled scanner findings  
**Formats Supported:** TruffleHog v3 JSONL & Gitleaks v8 JSON Array  
**Ground Truth Document:** `ground_truth.json`  

---

## 1. Ethical & Safety Declaration

> [!IMPORTANT]
> **Zero Real Secrets:** All credentials, tokens, API keys, email addresses, and server hostnames contained in this dataset are **100% synthetic and fictional**.
> - No active third-party credentials or personal data exist in this repository.
> - These fixtures are created strictly for local unit testing, reproducible benchmark evaluation, and safe regression verification.
> - These fixtures do not represent real-world prevalence or production vulnerability rates.

---

## 2. Dataset Partition & Distribution

The 68 findings are partitioned symmetrically between the two supported input scanner formats:
- **34 TruffleHog v3 findings** (`trufflehog_fixtures.jsonl`)
- **34 Gitleaks v8 findings** (`gitleaks_fixtures.json`)

### Distribution across Categories:

| ID Range | Category | TruffleHog | Gitleaks | Total | Expected ETW Label | Expected Priority | Description |
|---|---|---:|---:|---:|---|---|---|
| `FIX-01` – `FIX-15` | **True Candidate Secrets** | 8 | 7 | **15** | `candidate_secret` | P1_urgent / P2_high | High-entropy, production-like API keys, tokens, and database URIs in application code and configuration. |
| `FIX-16` – `FIX-27` | **Documentation Placeholders** | 6 | 6 | **12** | `likely_placeholder` | P4_low | Obvious documentation samples (`YOUR_API_KEY_HERE`, `<insert-token-here>`, `REPLACE_WITH_YOUR_SECRET_KEY`). |
| `FIX-28` – `FIX-37` | **Unit Test Fixtures** | 5 | 5 | **10** | `likely_test_value` | P4_low | Mock test credentials in test files (`tests/test_auth.py`, `conftest.py`, `mock_*.ts`). |
| `FIX-38` – `FIX-42` | **Canary Tokens** | 2 | 3 | **5** | `likely_canary` | P1_urgent (Caution) | Known canary token markers (`canarytokens.com`, `canarytoken-...`, AWS canary access keys) requiring immediate non-interaction alerts. |
| `FIX-43` – `FIX-52` | **Repeated Sightings** | 5 | 5 | **10** | Grouped into Cases | P1_urgent / P2_high | 5 distinct secrets repeated across multiple files/commits within the same repository (`org/monorepo`). Tests deduplication reduction. |
| `FIX-53` – `FIX-56` | **Cross-Repo Collisions** | 2 | 2 | **4** | Separate Cases | P2_high | 2 distinct secrets appearing across different repository scopes (`customer-a` vs `customer-b`, `tenant-x` vs `tenant-y`). Tests cross-tenant scoping preservation. |
| `FIX-57` – `FIX-62` | **Ambiguous Context** | 3 | 3 | **6** | `needs_review` | P3_normal | Truncated hashes, UUIDs, or low-entropy strings lacking decisive context keywords; must remain in `needs_review`. |
| `FIX-63` – `FIX-68` | **Malformed Edge Cases** | 3 | 3 | **6** | `quarantined` | N/A | Truncated JSON lines, missing `Raw`/`Secret` fields, non-string data types. Tests defensive error quarantine. |
| **Total** | | **34** | **34** | **68** | | | |

---

## 3. Ground Truth Assumptions & Benchmark Rules

1. **False Dismissal Definition:** An evaluation error where a record in category `true_candidate_secret` is erroneously classified as `likely_placeholder`, `likely_test_value`, or `quarantined`. Target rate is strictly **0.0%**.
2. **Deduplication Baseline:**
   - In raw scanner output, the 10 repeated sightings (`FIX-43` through `FIX-52`) represent 10 individual review items.
   - Under ETW scoped deduplication, they must collapse into exactly 5 review cases.
3. **Cross-Repository Boundary:**
   - Findings `FIX-53` and `FIX-54` share the same secret string but belong to `customer-a/web-app` and `customer-b/internal-tools`.
   - They must **never** be merged into a single case, but linked as `RelatedCases`.
4. **Reproducibility:**
   - The generator `generate_fixtures.py` is deterministic. Running `python datasets/fixtures-v1/generate_fixtures.py` regenerates the exact identical fixture files.
