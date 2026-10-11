# Exposure Triage Workbench (ETW) — Technical Interview Preparation & Architecture Defense

> **Target Audience:** Technical interviewers, AppSec leads, systems architects, and hiring panels.  
> **Topic:** Design decisions, cryptographic trade-offs, concurrency models, and security boundaries in ETW.

---

## 1. Cryptographic Security & Secret Fingerprinting

### Q1: Why use keyed HMAC-SHA256 for secret fingerprinting instead of standard SHA-256 or MD5?
**Answer:**
A secret scanner finds high-entropy strings, but many secrets (e.g. API keys for specific SaaS providers, GitHub tokens, AWS keys) follow known prefix formats or may be relatively low in entropy. 
If we used an unkeyed hash like SHA-256:
1. **Rainbow Table & Dictionary Attacks:** An attacker with read access to the triage database could precompute SHA-256 hashes for all leaked secrets from public breach databases (e.g., HaveIBeenPwned or public GitHub leaks) and invert the hashes instantly to recover the plaintext secrets.
2. **Keyed HMAC-SHA256 Protection:** By computing `HMAC-SHA256(key, secret)`, the fingerprint is cryptographically tied to a secret key that is stored locally with restricted permissions (`0600`) or provided via the environment (`ETW_HMAC_KEY`). Without the key, an attacker cannot perform offline dictionary attacks against the fingerprints.
3. **Key Rotation & Isolation:** Organizations can rotate the HMAC key per scan cycle or per environment, isolating repositories cryptographically.

### Q2: How does ETW guarantee that raw secrets do not leak into the SQLite database, logs, or reports?
**Answer:**
We implement a multi-layered defense-in-depth model:
1. **Structural Exclusion at the Model Layer:** In `Observation`, the `raw_secret` field is defined in Pydantic with `exclude=True`. When observations are serialized to JSON (`model_dump()`, `model_dump_json()`), the raw secret is automatically dropped.
2. **Schema-Level Exclusion:** The SQLite schema contains zero columns for secret values. Observations are persisted only with `candidate_fingerprint` (`hmac-sha256:...`) and `redacted_match` (`sk_l...[REDACTED]...CC`).
3. **In-Memory Sanitization:** Any diagnostic or error message passes through `sanitize_message()` and `mask_snippet()`, replacing secret characters with masked ellipses.
4. **Binary Byte-Level Verification:** We wrote active security regression tests (`tests/security/test_zero_secret_leakage.py` and `tests/unit/test_database.py`) that ingest seeded secrets and scan the raw bytes of the SQLite database file and WAL buffers to assert that 0 raw secret bytes ever hit disk.

---

## 2. Case Correlation & Asset Scoping

### Q3: Why doesn't ETW deduplicate identical secrets across different repositories into a single case?
**Answer:**
This is one of the most critical architectural decisions in ETW. In naive triage systems, deduplicating strictly by secret value collapses cross-repository sightings into one ticket. While this reduces ticket counts, it creates major security operational failures:
1. **Destruction of Ownership Provenance:** If an AWS access key is found in both `org/payment-service` (managed by the Payments team) and `org/public-docs` (managed by Technical Writing), combining them into one ticket obscures who owns the exposure and who must rotate the credential.
2. **Conflating Incident Blast Radius:** The remediation workflow differs fundamentally: `org/public-docs` requires an immediate emergency key revocation and public incident report, whereas `org/payment-service` may require a scheduled secret rotation in a Kubernetes vault.
3. **ETW's Solution:** ETW partitions cases strictly by the composite key `(candidate_fingerprint, asset_scope)`. Duplicate sightings *within* the same scope are collapsed into one case. If the same secret appears in *different* scopes, ETW creates separate cases for each scope and links them bidirectionally via the `related_cases` list.

---

## 3. Storage Architecture, SQLite WAL & Concurrency

### Q4: Why did you choose SQLite with Write-Ahead Logging (WAL) over a client-server database like PostgreSQL?
**Answer:**
1. **Local-First Threat Boundary:** ETW is designed for local-first triage on an engineer's workstation or inside an ephemeral CI job. Running a PostgreSQL service requires network sockets, connection strings, credentials, and infrastructure maintenance—introducing unnecessary attack surface.
2. **WAL Mode Concurrency:** SQLite in rollback-journal mode locks the entire database during writes. By executing `PRAGMA journal_mode = WAL;`, readers do not block writers, and writers do not block readers. This allows background ingestion streams or parallel CLI queries without contention.
3. **Crash Durability:** In WAL mode, changes are written sequentially to the WAL file before being committed to the main database, providing ACID guarantees and instant recovery upon process restart.
4. **Context Manager Lifecycle:** On Windows, open SQLite handles cause file locking (`WinError 32`). We engineered `Database.get_connection()` as a Python `@contextmanager` that wraps every operation in a transaction and guarantees `conn.close()` in a `finally` block.

---

## 4. Triage, Classification & Canary Tripwires

### Q5: Why use a deterministic rule engine instead of an LLM or ML classifier for Phase 4?
**Answer:**
1. **Explainability & Auditability:** In security operations, an analyst or auditor must know *why* an alert was deprioritized. A deterministic rule produces an explicit reason string (e.g. `RULE-PLACEHOLDER-001: matches known documentation template`) and priority factors. LLMs are non-deterministic and prone to hallucination.
2. **Zero False Dismissals on Ground Truth:** Our deterministic classifier achieved 0 false dismissals across all test fixtures. An LLM classifier can exhibit stochastic drift, occasionally misclassifying an active credential as boilerplate.
3. **Air-Gapped & Zero-Latency Execution:** The rule engine executes in microseconds with zero network calls and zero API cost, allowing it to evaluate 10,000 findings per second locally without third-party data leakage.

### Q6: How does ETW protect against active Canarytokens?
**Answer:**
Canarytokens (such as Thinkst Canary tokens or AWS decoy keys) are deliberate tripwires deployed by blue teams. If a security triage tool automatically curls the URL or validates the key against an AWS endpoint, it trips the wire and alerts the blue team (or burns an active deception campaign).
- ETW implements `RULE-CANARY-001`: It identifies canary URL patterns and detector flags, assigns them to **P1 (Urgent)**, and attaches a mandatory alert:  
  `> [!CAUTION] Active Canary Token detected. DO NOT connect, curl, or validate live.`
- In all reports and CLI views, this warning is prominently displayed, preventing analysts from accidentally setting off alarms.

### Q7: Why does ETW strictly refuse automated live credential testing?
**Answer:**
Live credential testing (sending test requests with the secret to GitHub, AWS, Stripe, etc.) introduces severe risks:
1. **Legal & Policy Violations:** Testing credentials against third-party or customer endpoints without explicit authorization may violate CFAA, terms of service, or bug bounty rules.
2. **Accidental Denial of Service / Side Effects:** Calling an API with an administrative key might trigger state mutations, billing charges, or automated account lockouts.
3. **Tripwire Triggers:** As noted above, live validation sets off Canary alarms.
- In ETW, validation is handled safely: candidate secrets are triaged based on location provenance and scanner-reported validity, and then escalated to the asset owner for internal rotation.

---

## 5. Benchmarking & Measurement

### Q8: The benchmark reports 100% precision and recall on fixtures. How do you defend this claim in an interview?
**Answer:**
We explicitly qualify this metric:
- **It is a synthetic fixture benchmark, not a real-world enterprise claim.** The 100% precision and recall metrics reflect that the rule engine adheres perfectly to the ground-truth contracts specified in our 68 synthetic test fixtures (`datasets/fixtures-v1/`).
- **Real-World Reality:** In a production codebase with legacy repositories, developers write non-standard tokens, obscure variable names, and unusual test mocks. Real-world precision will naturally be lower than 100%. The benchmark's purpose is regression prevention and contract adherence testing (Decision Gate 1), not marketing exaggeration.

---

## 6. Engineering Trade-offs & Philosophy

### Q9: What are the primary trade-offs you made in this architecture?
**Answer:**
1. **Regex & Heuristics vs. Full AST Parsing for Source Code:**
   - *Choice:* We used regex heuristics and path patterns for code findings, while reserving strict AST parsing for MCP JSON configs.
   - *Trade-off:* Extremely fast multi-language support without requiring 15 language parsers (Python, Go, JS, etc.), at the cost of slight vulnerability to edge-case formatting.
2. **SQLite vs. Distributed Message Queues (Kafka / Celery):**
   - *Choice:* Embedded SQLite WAL with direct streaming ingestion.
   - *Trade-off:* Maximum simplicity, zero ops overhead, and instant local execution, but single-node throughput ceiling (sufficient for ~500k findings/day, but not multi-terabyte log streams).
3. **Ponytail Minimalism vs. Feature Bloat:**
   - *Choice:* We built the smallest defensible product that completely solves post-detection triage: ingestion, classification, correlation, persistence, and reporting. We deliberately rejected bloated feature requests like automated ticketing webhooks or live active probing.
