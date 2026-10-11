# 1. Bounded MVP Scope & Module Sequencing

Date: 2026-10-11  
Status: Accepted  
Deciders: Principal Engineer / Implementation Lead  
Consulted: `PRODUCT.md` (v0.1), `ETW_Product_Due_Diligence_CloudSEK.md`  

---

## Context and Problem Statement

`PRODUCT.md` proposed an ambitious eight-week dual-module workbench spanning both secret-finding triage and Model Context Protocol (MCP) configuration security. The independent due-diligence review identified critical risks:
1. Building two unvalidated modules simultaneously risks delivering a bloated prototype where neither module proves measurable value.
2. The credential triage workflow addresses an established industry problem directly reflected in security analyst roles, whereas generic MCP static configuration rules offer low differentiation against existing tools (e.g., Cisco AI Defense MCP Scanner) and risk creating noisy findings.
3. Attempting to build live network verification, remote probing, complex web dashboards, or premature platform integrations would violate safety constraints and dilute the core post-detection hypothesis.

We need a clear, defensible decision on the exact scope, boundaries, and milestone gating for the Exposure Triage Workbench (ETW) MVP.

---

## Decision

We will build the **smallest defensible product** that proves the core hypothesis:
*Post-detection triage adds measurable value over reviewing raw secret-scanner output alone.*

### 1. Mandatory Core: Credential Exposure Triage Module
The initial implementation will focus exclusively on the credential triage pipeline:
- **Input Ingestion:** TruffleHog v3 JSON (JSONL & array) and Gitleaks v8 JSON, plus ETW's synthetic fixture schema.
- **Normalization:** Ingestion into stable `Observation` and `Case` schemas, preserving full provenance.
- **Deduplication:** Grouping by `(candidate_fingerprint, credential_type, asset_scope)` to prevent cross-asset/owner misattribution.
- **Classification Engine:** Deterministic rule engine for documentation examples, placeholders, known test keys, canary indicators, and context keywords.
- **Safe Handling:** In-memory candidate processing, keyed HMAC-SHA256 fingerprinting, zero raw secrets written to persistent storage, logs, reports, or test snapshots.
- **Triage Priority:** Explainable P1–P4 review priority with factor attribution (replacing the uncalibrated 0–100 score).
- **Consultant Reporting:** Redacted, escaped Markdown investigation report and schema-validated JSON export.
- **Reproducible Benchmark:** Labelled synthetic fixture benchmark measuring precision, recall, false-positive reduction, false-dismissal rate, and duplicate handling.

### 2. Strictly Conditional Extension: MCP Configuration Analysis (Phase 7)
The MCP configuration module is **not** part of the mandatory credential MVP.
- Implementation of the MCP static parser is deferred until **Phase 7**.
- Transition to Phase 7 is gated by the success of the Phase 6 credential evaluation:
  - If the credential triage workflow demonstrates measurable value (0 false dismissals on true secrets, valid deduplication, zero secret leaks, and clean test pass), we proceed to implement a minimal, static MCP configuration indicator check.
  - If the credential triage workflow fails or requires fundamental replanning, the MCP module will be deferred or dropped entirely to prevent scope creep.

### 3. Explicit Exclusions
The following capabilities are permanently excluded from the MVP:
- General-purpose secret scanning or crawler discovery.
- Live credential verification via external network or API calls.
- Remote MCP server probing, execution, or dynamic fuzzing.
- Execution of commands or script arguments parsed from MCP configurations.
- Reading environment variables from the host operating system.
- Web UI, multi-tenant database servers, cloud deployment, or vector databases.

---

## Consequences

### Positive
- **High Focus & Quality:** Engineering effort is concentrated on solving the high-value credential triage problem thoroughly and safely.
- **Guaranteed Safety:** Eliminating network probing and command execution avoids accidental token invalidation, third-party disclosure, or remote code execution risks.
- **Measurable Value:** A dedicated benchmark directly evaluates whether ETW reduces analyst burden compared to raw scanner output.
- **Maintainability:** Adheres to Ponytail principles by minimizing dependencies (standard library and battle-tested local libraries) and avoiding speculative abstractions.

### Negative / Trade-offs
- The dual-module promise of `PRODUCT.md` is serialized; MCP capability is not delivered in the first milestone.
- ETW cannot independently verify if a credential is live; it must rely on attributed scanner metadata.

### Risks Mitigated
- **Scope Creep:** Prevents the project from stalling midway through an unmanageable feature list.
- **Security Vulnerabilities:** Prevents credential leakage and command injection by establishing strict in-memory and static-only constraints.
- **Noisy MCP Findings:** Prevents generating low-value "unauthenticated server" alerts based on incomplete static configuration files.
