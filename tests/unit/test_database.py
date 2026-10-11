"""
Unit and security tests for ETW SQLite persistence and zero-secret database storage.
"""

import os
from pathlib import Path
import pytest
from etw.models.case import AuditEvent, Case
from etw.models.enums import (
    ClassificationState,
    DispositionState,
    ReviewPriority,
    SourceValidity,
)
from etw.models.evidence import AssetCandidate, LocationEvidence
from etw.models.observation import Observation
from etw.storage.database import Database


@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_etw.db"
    return Database(str(db_file))


def _create_sample_obs(obs_id: str, secret: str = "CANARY_SECRET_NEVER_PERSIST_12345") -> Observation:
    return Observation(
        id=obs_id,
        detector="trufflehog",
        rule_id="slack-webhook",
        source_reported_validity=SourceValidity.VERIFIED,
        location=LocationEvidence(
            file_path="src/notifications.py",
            line_start=42,
            line_end=42,
            repo_name="org/alerts-service",
        ),
        asset_scope="org/alerts-service",
        candidate_fingerprint="hmac-sha256:abcd1234abcd1234abcd1234abcd1234",
        redacted_match="https://hooks.slack.com/services/T00/B00/X***",
        raw_secret=secret,
        extracted_assets=[
            AssetCandidate(identifier="hooks.slack.com", asset_type="hostname")
        ],
    )


def test_schema_initialization(temp_db: Database):
    """Database initializes tables and records schema version 1."""
    with temp_db.get_connection() as conn:
        row = conn.execute("SELECT version FROM schema_migrations").fetchone()
        assert row is not None
        assert row["version"] == 1


def test_save_and_retrieve_observations(temp_db: Database):
    """Observations are saved and retrieved with full metadata but WITHOUT raw secret."""
    canary = "SUPER_SECRET_CANARY_DO_NOT_STORE_9999"
    obs = _create_sample_obs("obs-001", secret=canary)

    temp_db.save_run(
        run_id="run-1",
        source_file="scan.json",
        scanner_type="trufflehog",
        total_records=1,
        valid_records=1,
        quarantined_records=0,
    )
    temp_db.save_observations("run-1", [obs])

    # Check via raw SQL: no raw secret column exists in the schema
    with temp_db.get_connection() as conn:
        row = conn.execute("SELECT * FROM observations WHERE id = 'obs-001'").fetchone()
        assert row is not None
        assert row["candidate_fingerprint"] == "hmac-sha256:abcd1234abcd1234abcd1234abcd1234"
        assert row["redacted_match"] == "https://hooks.slack.com/services/T00/B00/X***"
        assert "raw_secret" not in row.keys()


def test_zero_raw_secret_in_db_file_bytes(temp_db: Database):
    """Assert byte-level inspection of SQLite db and WAL files contains zero raw secret leaks."""
    canary = "UNIQUE_CANARY_TOKEN_BYTES_CHECK_9876543210"
    obs = _create_sample_obs("obs-002", secret=canary)

    temp_db.save_run(
        run_id="run-2",
        source_file="scan.json",
        scanner_type="trufflehog",
        total_records=1,
        valid_records=1,
        quarantined_records=0,
    )
    temp_db.save_observations("run-2", [obs])

    # Read binary contents of database file and any associated WAL / SHM files
    db_bytes = temp_db.db_path.read_bytes()
    assert canary.encode("utf-8") not in db_bytes

    wal_file = Path(f"{temp_db.db_path}-wal")
    if wal_file.exists():
        assert canary.encode("utf-8") not in wal_file.read_bytes()


def test_case_crud_and_audit_history(temp_db: Database):
    """Case persistence, observation linkage, and disposition transition audit events."""
    obs = _create_sample_obs("obs-100")
    temp_db.save_run("run-3", "scan.json", "trufflehog", 1, 1, 0)
    temp_db.save_observations("run-3", [obs])

    case = Case(
        id="case-100",
        fingerprint=obs.candidate_fingerprint,
        credential_type=obs.rule_id,
        asset_scope=obs.asset_scope,
        classification=ClassificationState.CANDIDATE_SECRET,
        disposition=DispositionState.NEW,
        priority=ReviewPriority.P1,
        priority_factors=["scanner_reported_verified"],
        classification_reasons=["High-confidence verified webhook"],
        observation_ids=["obs-100"],
        observations_count=1,
        related_cases=[],
        asset_candidates=obs.extracted_assets,
        audit_history=[
            AuditEvent(
                from_status=DispositionState.NEW,
                to_status=DispositionState.NEW,
                actor="system",
                note="Initial ingestion",
            )
        ],
    )

    temp_db.save_cases([case])

    # Retrieve and verify
    retrieved = temp_db.get_case("case-100")
    assert retrieved is not None
    assert retrieved.id == "case-100"
    assert retrieved.priority == ReviewPriority.P1
    assert retrieved.observation_ids == ["obs-100"]
    assert len(retrieved.audit_history) == 1

    # Update disposition
    updated = temp_db.update_case_disposition(
        case_id="case-100",
        new_status=DispositionState.CONFIRMED_ISSUE,
        actor="alice_analyst",
        note="Verified live alert with SRE team",
    )
    assert updated is not None
    assert updated.disposition == DispositionState.CONFIRMED_ISSUE
    assert len(updated.audit_history) == 2
    assert updated.audit_history[1].actor == "alice_analyst"
    assert updated.audit_history[1].from_status == DispositionState.NEW
    assert updated.audit_history[1].to_status == DispositionState.CONFIRMED_ISSUE
    assert updated.audit_history[1].note == "Verified live alert with SRE team"


def test_list_cases_filtering(temp_db: Database):
    """Filtering cases by priority and disposition."""
    case_p1 = Case(
        id="case-p1",
        fingerprint="fp1",
        credential_type="aws",
        asset_scope="scope1",
        classification=ClassificationState.CANDIDATE_SECRET,
        disposition=DispositionState.NEW,
        priority=ReviewPriority.P1,
    )
    case_p4 = Case(
        id="case-p4",
        fingerprint="fp2",
        credential_type="doc",
        asset_scope="scope2",
        classification=ClassificationState.LIKELY_PLACEHOLDER,
        disposition=DispositionState.FALSE_POSITIVE,
        priority=ReviewPriority.P4,
    )
    temp_db.save_cases([case_p1, case_p4])

    p1_cases = temp_db.list_cases(priority=ReviewPriority.P1)
    assert len(p1_cases) == 1
    assert p1_cases[0].id == "case-p1"

    fp_cases = temp_db.list_cases(disposition=DispositionState.FALSE_POSITIVE)
    assert len(fp_cases) == 1
    assert fp_cases[0].id == "case-p4"


def test_get_observations_for_case(temp_db: Database):
    """Retrieve observations associated with a case."""
    obs1 = _create_sample_obs("obs-c1")
    obs2 = _create_sample_obs("obs-c2")
    temp_db.save_run("run-4", "scan.json", "trufflehog", 2, 2, 0)
    temp_db.save_observations("run-4", [obs1, obs2])

    case = Case(
        id="case-c",
        fingerprint=obs1.candidate_fingerprint,
        credential_type=obs1.rule_id,
        asset_scope=obs1.asset_scope,
        classification=ClassificationState.CANDIDATE_SECRET,
        priority=ReviewPriority.P2,
        observation_ids=["obs-c1", "obs-c2"],
        observations_count=2,
    )
    temp_db.save_cases([case])

    linked_obs = temp_db.get_observations_for_case("case-c")
    assert len(linked_obs) == 2
    assert {o.id for o in linked_obs} == {"obs-c1", "obs-c2"}


def test_purge_run_cascades(temp_db: Database):
    """Purging a run deletes associated observations."""
    obs = _create_sample_obs("obs-purge")
    temp_db.save_run("run-purge", "scan.json", "trufflehog", 1, 1, 0)
    temp_db.save_observations("run-purge", [obs])

    assert temp_db.purge_run("run-purge") is True
    with temp_db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) as c FROM observations WHERE id = 'obs-purge'").fetchone()["c"] == 0
