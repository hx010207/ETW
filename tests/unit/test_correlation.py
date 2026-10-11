"""
Unit tests for observation-to-case correlation and priority calculation in ETW.
"""

import pytest
from etw.analysis.case_grouper import correlate_observations_into_cases
from etw.analysis.prioritize import calculate_case_priority
from etw.models.enums import (
    ClassificationState,
    DispositionState,
    ReviewPriority,
    SourceValidity,
    EvidenceLevel,
)
from etw.models.evidence import AssetCandidate, LocationEvidence
from etw.models.observation import Observation
from etw.rules.classifier import ClassificationResult


def _make_obs(
    obs_id: str,
    fingerprint: str = "hmac-sha256:11112222333344445555666677778888",
    rule_id: str = "aws-access-key-id",
    asset_scope: str = "github.com/org/repo-a",
    file_path: str = "src/config.py",
    validity: SourceValidity = SourceValidity.NOT_CHECKED,
    assets: list = None,
    raw_secret: str = "AKIA9876543210123456",
) -> Observation:
    return Observation(
        id=obs_id,
        detector="trufflehog",
        rule_id=rule_id,
        source_reported_validity=validity,
        location=LocationEvidence(
            file_path=file_path,
            line_start=10,
            line_end=10,
            repo_name=asset_scope,
        ),
        asset_scope=asset_scope,
        candidate_fingerprint=fingerprint,
        redacted_match="AKIA************",
        raw_secret=raw_secret,
        extracted_assets=assets or [],
    )


def test_deduplication_within_same_scope():
    """Observations sharing fingerprint, rule_id, and asset_scope must merge into one case."""
    obs1 = _make_obs("obs-1", file_path="src/config.py")
    obs2 = _make_obs("obs-2", file_path="src/aws.py")
    obs3 = _make_obs("obs-3", file_path="deploy/run.sh")

    cases = correlate_observations_into_cases([obs1, obs2, obs3])

    assert len(cases) == 1
    case = cases[0]
    assert case.observations_count == 3
    assert set(case.observation_ids) == {"obs-1", "obs-2", "obs-3"}
    assert case.fingerprint == "hmac-sha256:11112222333344445555666677778888"
    assert case.asset_scope == "github.com/org/repo-a"
    assert len(case.related_cases) == 0
    assert len(case.audit_history) == 1
    assert case.audit_history[0].actor == "system"


def test_cross_asset_separation_and_related_cases_link():
    """Observations sharing a fingerprint across DIFFERENT asset_scopes must NOT merge."""
    fp = "hmac-sha256:sharedsecret9999888877776666"
    obs_repo_a = _make_obs("obs-a", fingerprint=fp, asset_scope="github.com/org/repo-a")
    obs_repo_b = _make_obs("obs-b", fingerprint=fp, asset_scope="github.com/org/repo-b")

    cases = correlate_observations_into_cases([obs_repo_a, obs_repo_b])

    # Must produce 2 separate cases, never 1
    assert len(cases) == 2
    case_a = next(c for c in cases if c.asset_scope == "github.com/org/repo-a")
    case_b = next(c for c in cases if c.asset_scope == "github.com/org/repo-b")

    assert case_a.id != case_b.id
    assert case_a.observations_count == 1
    assert case_b.observations_count == 1

    # Cross-repository links must connect them
    assert case_a.related_cases == [case_b.id]
    assert case_b.related_cases == [case_a.id]


def test_case_priority_elevation():
    """If one observation is verified/urgent (P1), the entire case priority elevates to P1."""
    obs_unverified = _make_obs("obs-1", validity=SourceValidity.NOT_CHECKED)
    obs_verified = _make_obs("obs-2", validity=SourceValidity.VERIFIED)

    cases = correlate_observations_into_cases([obs_unverified, obs_verified])

    assert len(cases) == 1
    case = cases[0]
    assert case.priority == ReviewPriority.P1
    assert "scanner_reported_verified" in case.priority_factors


def test_asset_candidates_deduplication():
    """Asset candidates across observations in a case are aggregated and deduplicated."""
    asset1 = AssetCandidate(identifier="api.example.com", asset_type="hostname")
    asset2 = AssetCandidate(identifier="s3://my-bucket", asset_type="cloud_resource")
    asset1_dup = AssetCandidate(identifier="api.example.com", asset_type="hostname")

    obs1 = _make_obs("obs-1", assets=[asset1, asset2])
    obs2 = _make_obs("obs-2", assets=[asset1_dup])

    cases = correlate_observations_into_cases([obs1, obs2])

    assert len(cases) == 1
    assert len(cases[0].asset_candidates) == 2
    identifiers = [a.identifier for a in cases[0].asset_candidates]
    assert set(identifiers) == {"api.example.com", "s3://my-bucket"}


def test_empty_observations():
    """Empty observation list produces empty case list."""
    assert correlate_observations_into_cases([]) == []
