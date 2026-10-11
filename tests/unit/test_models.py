import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from etw.models.enums import (
    ClassificationState,
    DispositionState,
    ReviewPriority,
    SourceValidity,
    EvidenceLevel,
)
from etw.models.evidence import LocationEvidence, ContextSnippet, AssetCandidate
from etw.models.observation import Observation
from etw.models.case import Case, AuditEvent


def test_enums_values():
    assert ClassificationState.CANDIDATE_SECRET.value == "candidate_secret"
    assert ClassificationState.LIKELY_PLACEHOLDER.value == "likely_placeholder"
    assert ClassificationState.LIKELY_TEST_VALUE.value == "likely_test_value"
    assert ClassificationState.LIKELY_CANARY.value == "likely_canary"
    assert ClassificationState.NEEDS_REVIEW.value == "needs_review"
    assert ClassificationState.EXCLUDED_BY_POLICY.value == "excluded_by_policy"

    assert DispositionState.NEW.value == "new"
    assert DispositionState.CONFIRMED_ISSUE.value == "confirmed_issue"

    assert ReviewPriority.P1.value == "P1_urgent"
    assert ReviewPriority.P4.value == "P4_low"


def test_observation_excludes_raw_secret_on_serialization():
    obs = Observation(
        id="obs-1234",
        detector="trufflehog",
        rule_id="AWS-SECRET-KEY",
        source_reported_validity=SourceValidity.UNVERIFIED,
        location=LocationEvidence(
            file_path="src/config.py",
            line_start=12,
            line_end=12,
            repo_name="org/core-api",
        ),
        asset_scope="org/core-api",
        candidate_fingerprint="hmac-sha256:abcdef1234567890abcdef1234567890",
        redacted_match="AKIA****************",
        raw_secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )

    # In-memory access is permitted
    assert obs.raw_secret == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # Crucial security guarantee: raw_secret must be omitted from dump and json
    dump_dict = obs.model_dump()
    assert "raw_secret" not in dump_dict
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in str(dump_dict)

    dump_json = obs.model_dump_json()
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in dump_json
    assert "raw_secret" not in dump_json


def test_asset_candidate_evidence_levels():
    asset = AssetCandidate(
        identifier="prod-db.internal.net",
        asset_type="hostname",
        evidence_level=EvidenceLevel.DERIVED,
    )
    assert asset.identifier == "prod-db.internal.net"
    assert asset.evidence_level == EvidenceLevel.DERIVED


def test_case_creation_and_audit_history():
    case = Case(
        id="CASE-0001",
        fingerprint="hmac-sha256:11223344556677889900aabbccddeeff",
        credential_type="AWS-KEY",
        asset_scope="org/backend",
        classification=ClassificationState.CANDIDATE_SECRET,
        disposition=DispositionState.NEW,
        priority=ReviewPriority.P2,
        priority_factors=["classification:candidate_secret", "context:production"],
        classification_reasons=["High entropy token found in production config"],
        observation_ids=["obs-1", "obs-2"],
        observations_count=2,
    )

    assert case.id == "CASE-0001"
    assert case.disposition == DispositionState.NEW
    assert case.observations_count == 2

    # Add audit transition
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        from_status=DispositionState.NEW,
        to_status=DispositionState.CONFIRMED_ISSUE,
        actor="analyst@example.com",
        note="Confirmed in staging repo",
    )
    case.audit_history.append(event)
    case.disposition = DispositionState.CONFIRMED_ISSUE

    assert len(case.audit_history) == 1
    assert case.disposition == DispositionState.CONFIRMED_ISSUE


def test_invalid_enum_validation_error():
    with pytest.raises(ValidationError):
        Observation(
            id="obs-invalid",
            detector="trufflehog",
            rule_id="RULE-1",
            source_reported_validity="invalid_validity_string",
            location=LocationEvidence(file_path="test.py"),
            asset_scope="scope",
            candidate_fingerprint="hmac-sha256:abc",
            redacted_match="REDACTED",
        )
