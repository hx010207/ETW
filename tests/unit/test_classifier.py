"""
Unit tests for deterministic classification engine (src/etw/rules/classifier.py).

Covers:
- Specific rule unit tests (canary, placeholder, test value, ambiguous, candidate)
- Priority assignments (P1_urgent, P2_high, P3_normal, P4_low)
- Preservation of scanner verification without claiming live validity
- Boundary conditions, malformed/corrupted inputs, and conservative fallbacks
- Zero secret leakage in rationales and logs
- Deterministic repeatability
- Benchmark evaluation against all 62 valid synthetic fixtures (100% accuracy, 0.0% false dismissals)
- Quarantine evaluation of all 6 malformed fixtures
"""

import json
from pathlib import Path
import pytest

from etw.models.enums import ClassificationState, ReviewPriority, SourceValidity
from etw.models.evidence import LocationEvidence
from etw.models.observation import Observation
from etw.rules.classifier import (
    ClassificationResult,
    classify_observation,
    classify_observations,
    classify_raw_finding,
    evaluate_confusion_matrix,
)
from etw.ingest.trufflehog import ingest_trufflehog
from etw.ingest.gitleaks import ingest_gitleaks


def make_obs(
    file_path: str = "src/app.py",
    rule_id: str = "generic-api",
    detector: str = "trufflehog",
    raw_secret: str = "some_dummy_secret_value_123",
    verified: bool = False,
) -> Observation:
    return Observation(
        id="test-obs-001",
        detector=detector,
        rule_id=rule_id,
        source_reported_validity=SourceValidity.VERIFIED if verified else SourceValidity.UNVERIFIED,
        location=LocationEvidence(file_path=file_path, line_start=10),
        asset_scope="org/test-repo",
        candidate_fingerprint="hmac-sha256:abc123mockfingerprint",
        redacted_match="some_dummy_*****************",
        raw_secret=raw_secret,
    )


# ---------------------------------------------------------------------------
# 1. Rule Unit Tests
# ---------------------------------------------------------------------------

def test_canary_rule_domain():
    obs = make_obs(
        file_path="src/config.py",
        raw_secret="https://canarytokens.com/traffic/feedback/abcdef123456/post.jsp",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_CANARY
    assert res.priority == ReviewPriority.P1
    assert res.rule_id == "RULE-CANARY-001"
    assert "canary" in res.rationale.lower()
    assert "canary_non_interaction_alert" in res.priority_factors


def test_canary_rule_token_pattern():
    obs = make_obs(
        file_path="canary/credentials.env",
        rule_id="AWS",
        raw_secret="AKIAIOSFODNN7CANARYKEY1",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_CANARY
    assert res.priority == ReviewPriority.P1
    assert "AKIAIOSFODNN7CANARYKEY1" not in res.rationale


def test_placeholder_rule_exact():
    obs = make_obs(
        file_path="docs/setup.md",
        raw_secret="YOUR_API_KEY_HERE",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_PLACEHOLDER
    assert res.priority == ReviewPriority.P4
    assert res.rule_id == "RULE-PLACEHOLDER-001"


def test_placeholder_rule_regex_template():
    obs = make_obs(
        file_path="config.example.yaml",
        raw_secret="REPLACE_WITH_YOUR_DATABASE_PASSWORD_HERE",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_PLACEHOLDER
    assert res.priority == ReviewPriority.P4


def test_placeholder_rule_all_zeroes():
    obs = make_obs(
        file_path="docs/api.rst",
        raw_secret="00000000000000000000000000000000",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_PLACEHOLDER
    assert res.priority == ReviewPriority.P4


def test_unit_test_rule_path():
    obs = make_obs(
        file_path="tests/test_authentication.py",
        raw_secret="sk_test_mock_unit_test_key_abc123",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_TEST_VALUE
    assert res.priority == ReviewPriority.P4
    assert res.rule_id == "RULE-TEST-001"


def test_unit_test_rule_mock_prefix_in_fixture():
    obs = make_obs(
        file_path="tests/fixtures/client_mock.py",
        raw_secret="mock_credential_for_offline_test",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.LIKELY_TEST_VALUE
    assert res.priority == ReviewPriority.P4


def test_ambiguous_rule_entropy():
    obs = make_obs(
        file_path="utils/hash.py",
        rule_id="HighEntropyString",
        raw_secret="4a7f9b2c8e1d5a3f",
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.NEEDS_REVIEW
    assert res.priority == ReviewPriority.P3
    assert res.rule_id == "RULE-AMBIGUOUS-001"
    assert "analyst_adjudication_required" in res.priority_factors


def test_candidate_secret_unverified():
    obs = make_obs(
        file_path="services/payments/stripe.py",
        rule_id="StripeLiveKey",
        raw_secret="sk_live_FakeLiveStripeKeyForTestExecution99",
        verified=False,
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.CANDIDATE_SECRET
    assert res.priority == ReviewPriority.P2
    assert res.rule_id == "RULE-CANDIDATE-001"


def test_candidate_secret_verified_preserves_state():
    # Scanner reported verified elevates priority to P1, but state remains CANDIDATE_SECRET
    obs = make_obs(
        file_path="services/payments/stripe.py",
        rule_id="StripeLiveKey",
        raw_secret="sk_live_FakeLiveStripeKeyForTestExecution99",
        verified=True,
    )
    res = classify_observation(obs)
    assert res.state == ClassificationState.CANDIDATE_SECRET
    assert res.priority == ReviewPriority.P1
    assert "scanner_reported_verified" in res.priority_factors


# ---------------------------------------------------------------------------
# 2. Defensive Boundaries, Fallbacks & Malformed Inputs
# ---------------------------------------------------------------------------

def test_corrupt_observation_quarantined():
    # Observation with missing location
    bad_obs = Observation(
        id="bad-obs",
        detector="test",
        rule_id="test",
        location=LocationEvidence(file_path=""),
        asset_scope="",
        candidate_fingerprint="",
        redacted_match="",
    )
    res = classify_observation(bad_obs)
    assert res.is_quarantined is True
    assert res.state == ClassificationState.NEEDS_REVIEW


def test_classify_raw_finding_non_dict():
    res = classify_raw_finding("string instead of dict")
    assert res.is_quarantined is True
    assert res.rule_id == "RULE-MALFORMED-QUARANTINE"


def test_classify_raw_finding_missing_secret():
    res = classify_raw_finding({"DetectorName": "AWS", "SourceMetadata": {}}, scanner="trufflehog")
    assert res.is_quarantined is True
    assert "Missing or invalid" in res.quarantine_reason


def test_classify_raw_finding_valid_structure():
    res = classify_raw_finding({"DetectorName": "AWS", "Raw": "AKIA1234567890"}, scanner="trufflehog")
    assert res.is_quarantined is False
    assert res.state == ClassificationState.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# 3. Security Assertions: Zero Secret Leakage & Determinism
# ---------------------------------------------------------------------------

def test_zero_secret_leakage_in_rationales():
    secret = "SUPER_SECRET_TOKEN_DO_NOT_LEAK_9988776655"
    obs = make_obs(raw_secret=secret, file_path="config/prod.json")
    res = classify_observation(obs)

    assert secret not in res.rationale
    for factor in res.priority_factors:
        assert secret not in factor


def test_deterministic_repeatability():
    obs = make_obs(file_path="deploy/terraform.tf", raw_secret="AKIA99PRODAWSKEYEXAMPLE99")
    res1 = classify_observation(obs)
    res2 = classify_observation(obs)

    assert res1.state == res2.state
    assert res1.priority == res2.priority
    assert res1.rule_id == res2.rule_id
    assert res1.rationale == res2.rationale
    assert res1.priority_factors == res2.priority_factors


# ---------------------------------------------------------------------------
# 4. Evaluation on All 62 Valid Synthetic Fixtures
# ---------------------------------------------------------------------------

def test_all_62_valid_fixtures_ground_truth_alignment():
    gt_file = Path("datasets/fixtures-v1/ground_truth.json")
    ground_truth = json.loads(gt_file.read_text(encoding="utf-8"))

    th_gt = [item for item in ground_truth if item["scanner"] == "trufflehog" and item["category"] != "malformed_edge_case"]
    gl_gt = [item for item in ground_truth if item["scanner"] == "gitleaks" and item["category"] != "malformed_edge_case"]

    th_res = ingest_trufflehog("datasets/fixtures-v1/trufflehog_fixtures.jsonl")
    gl_res = ingest_gitleaks("datasets/fixtures-v1/gitleaks_fixtures.json")

    assert len(th_res.observations) == 31
    assert len(gl_res.observations) == 31

    eval_pairs = []

    # TruffleHog observations (31)
    for obs, meta in zip(th_res.observations, th_gt):
        res = classify_observation(obs)
        assert res.state.value == meta["expected_classification"], f"TruffleHog {meta['id']} state mismatch: got {res.state.value}, expected {meta['expected_classification']}"
        assert res.priority.value == meta["expected_priority"], f"TruffleHog {meta['id']} priority mismatch: got {res.priority.value}, expected {meta['expected_priority']}"
        eval_pairs.append((res, meta["expected_classification"]))

    # Gitleaks observations (31)
    for obs, meta in zip(gl_res.observations, gl_gt):
        res = classify_observation(obs)
        assert res.state.value == meta["expected_classification"], f"Gitleaks {meta['id']} state mismatch: got {res.state.value}, expected {meta['expected_classification']}"
        assert res.priority.value == meta["expected_priority"], f"Gitleaks {meta['id']} priority mismatch: got {res.priority.value}, expected {meta['expected_priority']}"
        eval_pairs.append((res, meta["expected_classification"]))

    assert len(eval_pairs) == 62

    # Confusion matrix evaluation
    metrics = evaluate_confusion_matrix(eval_pairs)
    assert metrics["total_evaluated"] == 62
    assert metrics["false_dismissals"] == 0
    assert metrics["false_dismissal_rate_percent"] == 0.0

    # Every class must have 100% precision and recall on the benchmark fixtures
    for c, stats in metrics["per_class_metrics"].items():
        assert stats["precision"] == 100.0, f"Class {c} precision is {stats['precision']}"
        assert stats["recall"] == 100.0, f"Class {c} recall is {stats['recall']}"


# ---------------------------------------------------------------------------
# 5. Evaluation of All 6 Malformed Fixtures Quarantine
# ---------------------------------------------------------------------------

def test_all_6_malformed_fixtures_quarantined():
    th_res = ingest_trufflehog("datasets/fixtures-v1/trufflehog_fixtures.jsonl")
    gl_res = ingest_gitleaks("datasets/fixtures-v1/gitleaks_fixtures.json")

    assert th_res.quarantined_count == 3
    assert gl_res.quarantined_count == 3
    assert len(th_res.errors) == 3
    assert len(gl_res.errors) == 3

    # Total malformed fixtures handled defensively
    total_quarantined = th_res.quarantined_count + gl_res.quarantined_count
    assert total_quarantined == 6
