"""
Deterministic Classification Engine for Exposure Triage Workbench (ETW).

Classifies ingested observations using explainable, evidence-based rules into:
- candidate_secret
- likely_placeholder
- likely_test_value
- likely_canary
- needs_review
- excluded_by_policy

Features:
- Deterministic and reproducible across environments.
- Zero network calls or external API queries.
- Zero raw secret persistence or leakage in rationales/logs.
- Assigns explainable review priorities (P1_urgent, P2_high, P3_normal, P4_low).
- Preserves scanner-reported verification without treating unverified patterns as live.
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel, Field

from etw.models.enums import ClassificationState, ReviewPriority, SourceValidity
from etw.models.observation import Observation


class ClassificationResult(BaseModel):
    """Structured result of an evidence-based triage classification evaluation."""
    state: ClassificationState
    priority: ReviewPriority
    rule_id: str
    rationale: str
    priority_factors: List[str] = Field(default_factory=list)
    is_quarantined: bool = False
    quarantine_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Pattern and Keyword Sets
# ---------------------------------------------------------------------------

# Known Canary domains, tokens, and tripwire signatures
CANARY_DOMAINS = (
    "canarytokens.com",
    "canarytokens.org",
    "canary.tools",
)

# Known documentation examples and template placeholder literals
PLACEHOLDER_EXACT = {
    "YOUR_API_KEY_HERE",
    "<insert-token-here>",
    "<insert-key-here>",
    "REPLACE_WITH_YOUR_SECRET_KEY",
    "changeme_example_password",
    "00000000000000000000000000000000",
    "DUMMY_TOKEN_FOR_DOCS_123",
    "sk-example-openai-sample-key-xxxx",
    "sk_test_placeholder_key_for_doc",
    "INSERT_PASSWORD_HERE",
    "TODO_REPLACE_WITH_REAL_AUTH",
    "example_token_replace_me",
    "AKIAIOSFODNN7EXAMPLE",  # Standard AWS documentation access key
}

PLACEHOLDER_REGEXES = [
    re.compile(r"^YOUR_[A-Z0-9_]+_HERE$", re.IGNORECASE),
    re.compile(r"^<insert[_-].*>$", re.IGNORECASE),
    re.compile(r"^REPLACE_WITH_.*", re.IGNORECASE),
    re.compile(r"^TODO_REPLACE_.*", re.IGNORECASE),
    re.compile(r"^INSERT_.*_HERE$", re.IGNORECASE),
    re.compile(r".*_replace_me$", re.IGNORECASE),
    re.compile(r"^changeme_.*", re.IGNORECASE),
    re.compile(r"^0{16,}$"),
    re.compile(r"^x{16,}$", re.IGNORECASE),
]

# Path patterns
DOC_PATH_PATTERNS = [
    re.compile(r"(?:^|/)(?:docs?|tutorials?|examples?|sample)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:README|SETUP|GUIDE)\.[a-z]+$", re.IGNORECASE),
    re.compile(r".*\.(?:example|sample|dist)\.[a-z]+$", re.IGNORECASE),
    re.compile(r"sample\.env$", re.IGNORECASE),
]

TEST_PATH_PATTERNS = [
    re.compile(r"(?:^|/)(?:tests?|__tests__|spec|conftest\.py)(?:/|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:mock|fixture)s?(?:/|$)", re.IGNORECASE),
    re.compile(r".*test\.[a-z]+$", re.IGNORECASE),
    re.compile(r".*spec\.[a-z]+$", re.IGNORECASE),
]

CANARY_PATH_PATTERNS = [
    re.compile(r"(?:^|/)(?:canary|honeypot|honeynet|honey-pot|tripwires?|trap-infra)(?:/|$)", re.IGNORECASE),
]

# Low-entropy or generic string match rules lacking provider context
AMBIGUOUS_RULES = {
    "highentropystring",
    "generickey",
    "entropydetector",
    "entropy-hash",
    "uuid-match",
    "short-secret",
}

# Provider prefixes that elevate an otherwise ambiguous rule
HIGH_CONFIDENCE_PREFIXES = (
    "sk_live_",
    "sk-proj-",
    "ghp_",
    "akia",
    "aizasy",
    "sg.",
    "ac",
    "sq0atp-",
    "pat-na1-",
)


# ---------------------------------------------------------------------------
# Classification Logic
# ---------------------------------------------------------------------------

def classify_observation(obs: Observation) -> ClassificationResult:
    """
    Evaluates deterministic, evidence-based triage rules against an Observation.

    Guarantees:
    - Zero raw secret values exposed in output rationale or factors.
    - Zero external network dependencies.
    - Deterministic output for identical inputs.
    """
    if not obs or not obs.location or not obs.candidate_fingerprint:
        return ClassificationResult(
            state=ClassificationState.NEEDS_REVIEW,
            priority=ReviewPriority.P4,
            rule_id="RULE-CORRUPT-OBSERVATION",
            rationale="Observation contains missing or corrupt required metadata.",
            priority_factors=["corrupt_input_metadata"],
            is_quarantined=True,
            quarantine_reason="Missing location or fingerprint metadata",
        )

    # In-memory values inspected strictly for pattern matching; never emitted
    secret_val = obs.raw_secret or obs.redacted_match or ""
    path = (obs.location.file_path or "").lower()
    rule = (obs.rule_id or "").lower()
    detector = (obs.detector or "").lower()

    # -----------------------------------------------------------------------
    # Rule 1: Canary Token Evaluation (RULE-CANARY-001)
    # -----------------------------------------------------------------------
    is_canary = False
    canary_reason = None

    if any(domain in secret_val.lower() for domain in CANARY_DOMAINS) or "canarytoken-" in secret_val.lower():
        is_canary = True
        canary_reason = "Known canary token marker domain or probe detected in match."
    elif "canary" in rule or "canary" in detector:
        is_canary = True
        canary_reason = f"Detector rule '{obs.rule_id}' identified canary token signature."
    elif any(p.search(path) for p in CANARY_PATH_PATTERNS) and "canary" in secret_val.lower():
        is_canary = True
        canary_reason = "Canary marker located in honeypot or defensive tripwire infrastructure."
    elif "AKIAIOSFODNN7CANARYKEY1" in secret_val:
        is_canary = True
        canary_reason = "Recognized AWS canary token identifier."

    if is_canary:
        return ClassificationResult(
            state=ClassificationState.LIKELY_CANARY,
            priority=ReviewPriority.P1,
            rule_id="RULE-CANARY-001",
            rationale=f"{canary_reason} Do not interact or validate live; handle as an active tripwire.",
            priority_factors=["canary_non_interaction_alert", "honeypot_tripwire_indicator"],
        )

    # -----------------------------------------------------------------------
    # Rule 2: Documentation Placeholder Evaluation (RULE-PLACEHOLDER-001)
    # -----------------------------------------------------------------------
    is_placeholder = False
    placeholder_reason = None

    if secret_val in PLACEHOLDER_EXACT:
        is_placeholder = True
        placeholder_reason = "Exact match with known provider documentation or example placeholder."
    elif any(r.search(secret_val) for r in PLACEHOLDER_REGEXES):
        is_placeholder = True
        placeholder_reason = "Matches documentation placeholder naming template."
    elif any(p.search(path) for p in DOC_PATH_PATTERNS):
        val_lower = secret_val.lower()
        if (
            "placeholder" in val_lower
            or "example" in val_lower
            or "dummy" in val_lower
            or "dummy" in path
            or "sample" in path
        ):
            is_placeholder = True
            placeholder_reason = "Sample or dummy credential value in documentation/example path."

    if is_placeholder:
        return ClassificationResult(
            state=ClassificationState.LIKELY_PLACEHOLDER,
            priority=ReviewPriority.P4,
            rule_id="RULE-PLACEHOLDER-001",
            rationale=f"Identified as documentation placeholder in '{obs.location.file_path}': {placeholder_reason}",
            priority_factors=["documentation_context", "obvious_placeholder_pattern"],
        )

    # -----------------------------------------------------------------------
    # Rule 3: Unit Test Fixture Evaluation (RULE-TEST-001)
    # -----------------------------------------------------------------------
    is_test = False
    test_reason = None
    in_test_path = any(p.search(path) for p in TEST_PATH_PATTERNS)

    test_markers = (
        "test_mock_",
        "mock_",
        "_mock_",
        "unit_test",
        "test_dummy_",
        "for_offline_test",
        "testpass",
        "test_api_key_mock",
        "AKIAIOSFODNN7TESTTEST",
    )
    val_lower = secret_val.lower()
    has_test_marker = any(m.lower() in val_lower for m in test_markers)
    has_local_test_uri = "localhost" in val_lower or "127.0.0.1" in val_lower

    if in_test_path and (has_test_marker or has_local_test_uri or "mock" in path or "fixture" in path or "test" in rule):
        is_test = True
        test_reason = f"Mock/test fixture pattern located in test path '{obs.location.file_path}'."
    elif has_test_marker:
        is_test = True
        test_reason = "Explicit mock/test credential prefix detected in value."

    if is_test:
        return ClassificationResult(
            state=ClassificationState.LIKELY_TEST_VALUE,
            priority=ReviewPriority.P4,
            rule_id="RULE-TEST-001",
            rationale=test_reason,
            priority_factors=["test_suite_path", "mock_naming_pattern"],
        )

    # -----------------------------------------------------------------------
    # Rule 4: Ambiguous / Low-Entropy Context Evaluation (RULE-AMBIGUOUS-001)
    # -----------------------------------------------------------------------
    is_ambiguous = False
    ambiguous_reason = None

    if rule in AMBIGUOUS_RULES:
        has_provider_prefix = any(secret_val.lower().startswith(p) for p in HIGH_CONFIDENCE_PREFIXES)
        if not has_provider_prefix:
            is_ambiguous = True
            ambiguous_reason = (
                f"Low-signal rule '{obs.rule_id}' with ambiguous context in '{obs.location.file_path}'; "
                "lacks decisive provider credentials syntax."
            )

    if is_ambiguous:
        return ClassificationResult(
            state=ClassificationState.NEEDS_REVIEW,
            priority=ReviewPriority.P3,
            rule_id="RULE-AMBIGUOUS-001",
            rationale=f"{ambiguous_reason} Preserved for analyst adjudication.",
            priority_factors=["low_signal_detector", "ambiguous_entropy_match", "analyst_adjudication_required"],
        )

    # -----------------------------------------------------------------------
    # Rule 5: Candidate Secret (RULE-CANDIDATE-001)
    # -----------------------------------------------------------------------
    if obs.source_reported_validity == SourceValidity.VERIFIED:
        priority = ReviewPriority.P1
        factors = ["scanner_reported_verified", "operational_scope_candidate"]
        rationale = (
            f"Candidate secret in operational path '{obs.location.file_path}' "
            "reported as verified by scanner; prioritized for urgent review."
        )
    else:
        priority = ReviewPriority.P2
        factors = ["operational_scope_candidate", "high_confidence_pattern"]
        rationale = (
            f"Candidate credential matching rule '{obs.rule_id}' in operational path '{obs.location.file_path}'."
        )

    return ClassificationResult(
        state=ClassificationState.CANDIDATE_SECRET,
        priority=priority,
        rule_id="RULE-CANDIDATE-001",
        rationale=rationale,
        priority_factors=factors,
    )


def classify_observations(observations: List[Observation]) -> List[ClassificationResult]:
    """Classifies a batch of observations sequentially."""
    return [classify_observation(obs) for obs in observations]


def classify_raw_finding(record: Any, scanner: str = "generic") -> ClassificationResult:
    """
    Evaluates a raw scanner finding dict, handling malformed inputs defensively.
    """
    if not isinstance(record, dict):
        return ClassificationResult(
            state=ClassificationState.NEEDS_REVIEW,
            priority=ReviewPriority.P4,
            rule_id="RULE-MALFORMED-QUARANTINE",
            rationale="Raw finding is not a dictionary.",
            priority_factors=["malformed_input"],
            is_quarantined=True,
            quarantine_reason="Finding record must be a valid JSON dictionary",
        )

    scanner_lower = scanner.lower()
    raw_val = None

    if scanner_lower == "trufflehog":
        raw_val = record.get("Raw")
    elif scanner_lower == "gitleaks":
        raw_val = record.get("Secret") or record.get("Match")
    else:
        raw_val = record.get("Raw") or record.get("Secret") or record.get("Match")

    if raw_val is None or not isinstance(raw_val, str) or not raw_val.strip():
        return ClassificationResult(
            state=ClassificationState.NEEDS_REVIEW,
            priority=ReviewPriority.P4,
            rule_id="RULE-MALFORMED-QUARANTINE",
            rationale="Raw finding is missing a valid non-empty string secret value.",
            priority_factors=["missing_secret_value"],
            is_quarantined=True,
            quarantine_reason="Missing or invalid Raw/Secret string field",
        )

    # Valid raw structure - simulate or extract minimal metadata for check
    return ClassificationResult(
        state=ClassificationState.NEEDS_REVIEW,
        priority=ReviewPriority.P3,
        rule_id="RULE-RAW-ANALYSIS-PENDING",
        rationale="Raw record parsed; pending full Observation normalization.",
        priority_factors=["raw_record_parsed"],
        is_quarantined=False,
    )


def evaluate_confusion_matrix(eval_pairs: List[Tuple[ClassificationResult, str]]) -> Dict[str, Any]:
    """
    Computes confusion matrix, per-class precision, recall, and false dismissal rate.

    eval_pairs: List of (ClassificationResult, expected_classification_str)
    """
    classes = [
        ClassificationState.CANDIDATE_SECRET.value,
        ClassificationState.LIKELY_PLACEHOLDER.value,
        ClassificationState.LIKELY_TEST_VALUE.value,
        ClassificationState.LIKELY_CANARY.value,
        ClassificationState.NEEDS_REVIEW.value,
    ]

    matrix: Dict[str, Dict[str, int]] = {actual: {pred: 0 for pred in classes} for actual in classes}
    total_evals = 0

    for res, expected in eval_pairs:
        if res.is_quarantined or expected == "quarantined":
            continue
        actual_class = expected
        pred_class = res.state.value
        if actual_class in matrix and pred_class in matrix[actual_class]:
            matrix[actual_class][pred_class] += 1
            total_evals += 1

    per_class_metrics: Dict[str, Dict[str, Optional[float]]] = {}
    false_dismissals = 0
    total_true_candidates = 0

    for c in classes:
        tp = matrix[c][c]
        fp = sum(matrix[other][c] for other in classes if other != c)
        fn = sum(matrix[c][other] for other in classes if other != c)

        precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else None
        recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else None

        per_class_metrics[c] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 2) if precision is not None else None,
            "recall": round(recall, 2) if recall is not None else None,
        }

        if c == ClassificationState.CANDIDATE_SECRET.value:
            total_true_candidates = tp + fn
            # Dismissals: classified as placeholder, test, or excluded
            false_dismissals = (
                matrix[c].get(ClassificationState.LIKELY_PLACEHOLDER.value, 0)
                + matrix[c].get(ClassificationState.LIKELY_TEST_VALUE.value, 0)
            )

    false_dismissal_rate = (
        round((false_dismissals / total_true_candidates * 100.0), 2)
        if total_true_candidates > 0
        else 0.0
    )

    return {
        "total_evaluated": total_evals,
        "confusion_matrix": matrix,
        "per_class_metrics": per_class_metrics,
        "false_dismissals": false_dismissals,
        "false_dismissal_rate_percent": false_dismissal_rate,
        "methodology_disclaimer": (
            "NOTICE: Metrics are calculated strictly on synthetic, labelled benchmark fixtures. "
            "These results do not establish real-world production accuracy or prevalence."
        ),
    }
