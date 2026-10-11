"""
Unit tests for ETW Markdown report and JSON export generation.
"""

import json
from etw.models.case import AuditEvent, Case
from etw.models.enums import (
    ClassificationState,
    DispositionState,
    ReviewPriority,
    SourceValidity,
)
from etw.models.evidence import LocationEvidence
from etw.models.observation import Observation
from etw.reports.json_export import generate_json_export
from etw.reports.markdown import generate_markdown_report


def _make_test_case_and_obs():
    canary_secret = "SECRET_CANARY_NEVER_LEAK_IN_REPORT_9988"
    obs = Observation(
        id="obs-rep-1",
        detector="trufflehog",
        rule_id="canary-token",
        source_reported_validity=SourceValidity.NOT_CHECKED,
        location=LocationEvidence(
            file_path="src/<script>alert(1)</script>.py",
            line_start=15,
            line_end=15,
            repo_name="org/canary-repo",
        ),
        asset_scope="org/canary-repo",
        candidate_fingerprint="hmac-sha256:cccc1111cccc1111cccc1111cccc1111",
        redacted_match="canary_token_***",
        raw_secret=canary_secret,
    )

    case = Case(
        id="case-canary-1",
        fingerprint=obs.candidate_fingerprint,
        credential_type="canary-token",
        asset_scope="org/canary-repo",
        classification=ClassificationState.LIKELY_CANARY,
        disposition=DispositionState.NEW,
        priority=ReviewPriority.P1,
        priority_factors=["canary_non_interaction_alert"],
        classification_reasons=["Matches canary tripwire domain: canarytokens.com"],
        observation_ids=["obs-rep-1"],
        observations_count=1,
    )

    return case, obs, canary_secret


def test_markdown_report_zero_raw_secret_and_canary_alert():
    """Markdown report contains canary alert and zero raw secrets."""
    case, obs, secret = _make_test_case_and_obs()
    obs_map = {case.id: [obs]}

    report = generate_markdown_report(cases=[case], observations_by_case=obs_map, run_id="run-test")

    # Assert raw secret is NOT leaked
    assert secret not in report

    # Assert canary alert banner exists
    assert "CANARY TOKEN DETECTED — DO NOT INTERACT" in report
    assert "canarytokens.com" in report

    # Assert untrusted inputs are escaped
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report

    # Assert provenance section exists
    assert "`obs-rep-1`" in report
    assert "`canary_token_***`" in report


def test_json_export_structure_and_zero_raw_secret():
    """JSON export contains metadata, summaries, and zero raw secrets."""
    case, obs, secret = _make_test_case_and_obs()
    obs_map = {case.id: [obs]}

    export_dict = generate_json_export(cases=[case], observations_by_case=obs_map, run_id="run-test")

    # Validate JSON serializability
    json_str = json.dumps(export_dict)
    assert secret not in json_str
    assert "raw_secret" not in json_str

    assert export_dict["metadata"]["total_cases"] == 1
    assert export_dict["metadata"]["total_observations"] == 1
    assert export_dict["summary"]["by_priority"]["P1_urgent"] == 1
    assert export_dict["cases"][0]["id"] == "case-canary-1"
    assert len(export_dict["cases"][0]["observations"]) == 1
    assert export_dict["cases"][0]["observations"][0]["id"] == "obs-rep-1"
