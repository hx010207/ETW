"""
Regression tests for adversarial security audit and hardening.

Covers:
1. Terminal escape code and control character injection protection.
2. HMAC key lifecycle, corruption recovery, and stability.
3. Database run purging and orphaned case cleanup.
4. MCP parser environment variable non-expansion guarantee.
5. CLI purge command execution and error handling.
"""

import os
from pathlib import Path
from unittest.mock import patch
import pytest

from etw.cli import create_parser, main
from etw.ingest.mcp_config import ingest_mcp_config
from etw.models.enums import (
    ClassificationState,
    DispositionState,
    ReviewPriority,
    SourceValidity,
)
from etw.models.evidence import LocationEvidence
from etw.models.observation import Observation
from etw.storage.database import Database
from etw.storage.fingerprint import get_hmac_key
from etw.storage.redaction import sanitize_terminal_output


def test_sanitize_terminal_output_removes_ansi_and_control_chars():
    # ANSI color and cursor control sequences
    ansi_payload = "\x1b[31;1mCRITICAL_ALERT\x1b[0m\x1b[2J\x1b[H"
    sanitized = sanitize_terminal_output(ansi_payload)
    assert "\x1b" not in sanitized
    assert sanitized == "CRITICAL_ALERT"

    # Terminal title change (OSC sequence)
    osc_payload = "SafePrefix\x1b]0;TitleHijack\x07SafeSuffix"
    sanitized_osc = sanitize_terminal_output(osc_payload)
    assert "\x1b" not in sanitized_osc
    assert "SafePrefix" in sanitized_osc
    assert "SafeSuffix" in sanitized_osc

    # Non-printable ASCII control characters (null byte, bell, backspace)
    ctrl_payload = "File\x00Name\x07With\x08BadChars\x7f"
    sanitized_ctrl = sanitize_terminal_output(ctrl_payload)
    assert sanitized_ctrl == "FileNameWithBadChars"

    # Clean text remains unchanged
    normal_text = "src/main/config.json:42 (P1_urgent)"
    assert sanitize_terminal_output(normal_text) == normal_text


def test_hmac_key_recovers_from_zero_or_corrupted_keyfile(tmp_path: Path):
    key_file = tmp_path / "corrupted.key"

    # Test 1: Empty (0 bytes) file
    key_file.write_bytes(b"")
    key = get_hmac_key(key_path=str(key_file))
    assert len(key) == 32
    assert key_file.stat().st_size == 32

    # Test 2: Stability - reading again returns identical key
    key_again = get_hmac_key(key_path=str(key_file))
    assert key == key_again

    # Test 3: Truncated / insecure key (< 16 bytes)
    key_file.write_bytes(b"short_insecure")
    key_recovered = get_hmac_key(key_path=str(key_file))
    assert len(key_recovered) == 32
    assert key_recovered != b"short_insecure"


def test_purge_run_cleans_up_orphaned_cases(tmp_path: Path):
    db_file = tmp_path / "test_purge.db"
    db = Database(db_file)

    loc = LocationEvidence(
        file_path="app.py",
        line_start=1,
        line_end=1,
        column_start=1,
        column_end=10,
        commit_hash="abc",
        commit_author="dev",
        repo_name="repo",
    )
    obs = Observation(
        id="obs-purge-1",
        detector="test",
        rule_id="RULE-1",
        source_reported_validity=SourceValidity.UNVERIFIED,
        location=loc,
        asset_scope="repo",
        candidate_fingerprint="fp-purge-1",
        redacted_match="REDACTED",
        raw_secret=None,
        extracted_assets=[],
    )

    from etw.analysis.case_grouper import correlate_observations_into_cases

    run_id = "run-test-purge-100"
    db.save_run(
        run_id=run_id,
        source_file="test.json",
        scanner_type="test",
        total_records=1,
        valid_records=1,
        quarantined_records=0,
    )
    db.save_observations(run_id, [obs])

    cases = correlate_observations_into_cases([obs])
    db.save_cases(cases)

    # Verify run and case exist
    initial_cases = db.list_cases()
    assert len(initial_cases) == 1

    # Purge run
    purged = db.purge_run(run_id)
    assert purged is True

    # Case must have been cleaned up because all linked observations are gone
    remaining_cases = db.list_cases()
    assert len(remaining_cases) == 0

    # Purging non-existent run returns False
    assert db.purge_run("run-non-existent") is False


def test_mcp_config_never_expands_environment_variables(tmp_path: Path):
    env_var_name = "ETW_TEST_SECRET_ENV_VAR"
    env_var_val = "SECRET_CANARY_VALUE_XYZ_999"

    # Set real environment variable in process
    os.environ[env_var_name] = env_var_val
    try:
        cfg_content = f"""{{
            "mcpServers": {{
                "test_srv": {{
                    "command": "node",
                    "env": {{
                        "TEST_KEY": "${{{env_var_name}}}",
                        "RAW_REF": "${env_var_name}"
                    }}
                }}
            }}
        }}"""

        cfg_file = tmp_path / "claude_desktop_config.json"
        cfg_file.write_text(cfg_content, encoding="utf-8")

        res = ingest_mcp_config(cfg_file)
        assert res.successful_count == 1

        # Assert no observation or model contains the expanded secret
        for obs in res.observations:
            assert env_var_val not in obs.redacted_match
            assert env_var_val not in str(obs.extracted_assets)
            assert env_var_val not in obs.model_dump_json()

    finally:
        os.environ.pop(env_var_name, None)


def test_cli_purge_command(tmp_path: Path):
    db_file = tmp_path / "cli_purge.db"
    db = Database(db_file)

    run_id = "run-for-cli-purge"
    db.save_run(
        run_id=run_id,
        source_file="test.json",
        scanner_type="test",
        total_records=0,
        valid_records=0,
        quarantined_records=0,
    )

    # Purge via CLI args
    exit_code = main(["--db", str(db_file), "purge", run_id])
    assert exit_code == 0

    # Repeated purge should fail with exit code 1
    exit_code_again = main(["--db", str(db_file), "purge", run_id])
    assert exit_code_again == 1
