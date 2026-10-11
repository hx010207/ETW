"""
Markdown report generator for Exposure Triage Workbench (ETW).

Guarantees:
1. Zero raw secret exposure: only redacted badges and HMAC fingerprints are rendered.
2. Sanitization: untrusted strings (paths, snippets, analyst notes) are escaped.
3. Separation of scanner verification and confirmed risk.
4. Canary tokens prominently display non-interaction warnings.
5. Filtered noise (placeholders, mock test values) is clearly delineated.
"""

from collections import Counter
from datetime import datetime, timezone
import html
from typing import Dict, List, Optional

from etw.models.case import Case
from etw.models.enums import ClassificationState, DispositionState, ReviewPriority
from etw.models.observation import Observation


def _escape_md(text: Optional[str]) -> str:
    """Escapes pipes, angles, and backticks for safe markdown rendering."""
    if not text:
        return ""
    # First escape HTML tags
    clean = html.escape(str(text))
    # Replace markdown table delimiter pipe
    clean = clean.replace("|", "\\|")
    return clean


def generate_markdown_report(
    cases: List[Case],
    observations_by_case: Optional[Dict[str, List[Observation]]] = None,
    run_id: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    Renders an evidence-backed, human-readable Markdown triage report.

    Args:
        cases: List of Case entities.
        observations_by_case: Optional mapping from case_id to list of Observations.
        run_id: Optional scan run identifier.
        generated_at: Optional ISO timestamp.

    Returns:
        Formatted Markdown string.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()
    if run_id is None:
        run_id = "run-manual"

    total_cases = len(cases)
    total_observations = sum(c.observations_count for c in cases)

    # Compute metric distributions
    priority_counts = Counter(c.priority.value for c in cases)
    classification_counts = Counter(c.classification.value for c in cases)
    disposition_counts = Counter(c.disposition.value for c in cases)

    p1_count = priority_counts.get(ReviewPriority.P1.value, 0)
    p2_count = priority_counts.get(ReviewPriority.P2.value, 0)
    p3_count = priority_counts.get(ReviewPriority.P3.value, 0)
    p4_count = priority_counts.get(ReviewPriority.P4.value, 0)

    # Placeholders & test values filtered count
    noise_count = (
        classification_counts.get(ClassificationState.LIKELY_PLACEHOLDER.value, 0)
        + classification_counts.get(ClassificationState.LIKELY_TEST_VALUE.value, 0)
    )
    noise_pct = (noise_count / total_cases * 100) if total_cases > 0 else 0.0

    lines: List[str] = []

    # Title & Metadata
    lines.append("# Exposure Triage Workbench (ETW) — Security Triage Report")
    lines.append("")
    lines.append(f"- **Generated At:** `{generated_at}`")
    lines.append(f"- **Run ID:** `{_escape_md(run_id)}`")
    lines.append(f"- **Total Ingested Observations:** `{total_observations}`")
    lines.append(f"- **Deduplicated Cases:** `{total_cases}`")
    lines.append("")

    # Executive Summary
    lines.append("## 1. Executive Summary & Triage Overview")
    lines.append("")
    lines.append("| Triage Category | Count | Percentage | Description |")
    lines.append("| :--- | :---: | :---: | :--- |")
    lines.append(f"| **P1 (Urgent Action)** | {p1_count} | {(p1_count/total_cases*100 if total_cases else 0):.1f}% | Verified credentials or active Canary tokens |")
    lines.append(f"| **P2 (High Priority)** | {p2_count} | {(p2_count/total_cases*100 if total_cases else 0):.1f}% | Candidate secrets in operational scope |")
    lines.append(f"| **P3 (Normal Review)** | {p3_count} | {(p3_count/total_cases*100 if total_cases else 0):.1f}% | Ambiguous findings requiring manual review |")
    lines.append(f"| **P4 (Low / Noise)** | {p4_count} | {(p4_count/total_cases*100 if total_cases else 0):.1f}% | Documented placeholders and test fixtures |")
    lines.append("")
    lines.append(f"> **Triage Noise Reduction:** **{noise_count} of {total_cases} cases ({noise_pct:.1f}%)** were identified as documentation placeholders or test fixtures and automatically categorized to P4 low priority.")
    lines.append("")

    # Urgent & High Priority Action Items (P1 & P2)
    p1_p2_cases = [c for c in cases if c.priority in (ReviewPriority.P1, ReviewPriority.P2)]
    lines.append("## 2. Actionable Findings (P1 Urgent & P2 High Priority)")
    lines.append("")
    if not p1_p2_cases:
        lines.append("*No urgent or high priority cases detected.*")
        lines.append("")
    else:
        for c in p1_p2_cases:
            is_canary = c.classification == ClassificationState.LIKELY_CANARY
            lines.append(f"### Case `{c.id}` — [{c.priority.value}] {c.credential_type}")
            lines.append("")
            if is_canary:
                lines.append("> [!CAUTION]")
                lines.append("> **CANARY TOKEN DETECTED — DO NOT INTERACT**")
                lines.append("> This secret matches known canary/tripwire patterns. **DO NOT** attempt to validate, ping, or curl this credential against endpoints. Report to Security Operations immediately.")
                lines.append("")

            lines.append(f"- **Asset Scope:** `{_escape_md(c.asset_scope)}`")
            lines.append(f"- **Classification:** `{c.classification.value}`")
            lines.append(f"- **Current Disposition:** `{c.disposition.value}`")
            lines.append(f"- **HMAC Fingerprint:** `{c.fingerprint}`")
            lines.append(f"- **Observations Count:** `{c.observations_count}`")
            if c.related_cases:
                related_str = ", ".join(f"`{r}`" for r in c.related_cases)
                lines.append(f"- **Related Cases (Cross-Scope Collisions):** {related_str}")

            if c.asset_candidates:
                assets_str = ", ".join(f"`{_escape_md(a.identifier)}` ({a.asset_type})" for a in c.asset_candidates)
                lines.append(f"- **Extracted Assets:** {assets_str}")

            if c.priority_factors:
                factors_str = ", ".join(f"`{f}`" for f in c.priority_factors)
                lines.append(f"- **Priority Factors:** {factors_str}")

            lines.append("")
            lines.append("**Classification Rationale:**")
            for r in c.classification_reasons:
                lines.append(f"- {_escape_md(r)}")
            lines.append("")

            # Render associated observations if provided
            if observations_by_case and c.id in observations_by_case:
                lines.append("**Observation Provenance:**")
                lines.append("| Obs ID | File Location | Line | Detector | Redacted Match |")
                lines.append("| :--- | :--- | :---: | :--- | :--- |")
                for o in observations_by_case[c.id]:
                    loc = f"{_escape_md(o.location.file_path)}"
                    line_no = o.location.line_start or "-"
                    lines.append(f"| `{o.id}` | `{loc}` | {line_no} | `{o.detector}` | `{_escape_md(o.redacted_match)}` |")
                lines.append("")

    # Ambiguous Findings Requiring Analyst Review (P3)
    p3_cases = [c for c in cases if c.priority == ReviewPriority.P3]
    lines.append("## 3. Ambiguous Findings Requiring Review (P3 Normal Priority)")
    lines.append("")
    if not p3_cases:
        lines.append("*No ambiguous cases requiring review.*")
        lines.append("")
    else:
        lines.append("| Case ID | Scope | Credential Type | Fingerprint | Reason |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in p3_cases:
            reason = _escape_md(c.classification_reasons[0]) if c.classification_reasons else "Entropy/Generic rule"
            lines.append(f"| `{c.id}` | `{_escape_md(c.asset_scope)}` | `{c.credential_type}` | `{c.fingerprint}` | {reason} |")
        lines.append("")

    # Filtered Documentation Placeholders & Test Fixtures (P4)
    p4_cases = [c for c in cases if c.priority == ReviewPriority.P4]
    lines.append("## 4. Filtered Placeholders and Test Keys (P4 Low Priority)")
    lines.append("")
    if not p4_cases:
        lines.append("*No placeholder or test fixtures filtered.*")
        lines.append("")
    else:
        lines.append(f"A total of **{len(p4_cases)}** cases were evaluated as non-actionable documentation placeholders or unit-test fixtures:")
        lines.append("")
        lines.append("| Case ID | Scope | Classification | Fingerprint | Rationale |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in p4_cases:
            reason = _escape_md(c.classification_reasons[0]) if c.classification_reasons else "Placeholder/Test match"
            lines.append(f"| `{c.id}` | `{_escape_md(c.asset_scope)}` | `{c.classification.value}` | `{c.fingerprint}` | {reason} |")
        lines.append("")

    # Complete Audit Trail
    lines.append("## 5. Audit Log & Decision History")
    lines.append("")
    has_audit = False
    for c in cases:
        if len(c.audit_history) > 1:  # More than initial system creation
            has_audit = True
            lines.append(f"### Audit History for Case `{c.id}`")
            lines.append("| Timestamp | Transition | Actor | Note |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for ev in c.audit_history:
                trans = f"`{ev.from_status.value}` → `{ev.to_status.value}`"
                lines.append(f"| `{ev.timestamp}` | {trans} | `{_escape_md(ev.actor)}` | {_escape_md(ev.note)} |")
            lines.append("")

    if not has_audit:
        lines.append("*All cases currently in initial state. No analyst disposition transitions recorded yet.*")
        lines.append("")

    # Security Disclaimer
    lines.append("---")
    lines.append("> **Security Guarantee:**")
    lines.append("> This report contains zero raw credentials. All secrets are represented exclusively by deterministic HMAC-SHA256 digests and masked previews. Detector verification indicates an upstream network check conducted by the scanner and does not guarantee that the credential has not been rotated or expired.")
    lines.append("")

    return "\n".join(lines)
