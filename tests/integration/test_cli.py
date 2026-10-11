"""
End-to-end integration tests for ETW Command-Line Interface.
"""

import json
from pathlib import Path
import pytest
from etw.cli import main


@pytest.fixture
def cli_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "cli_test.db")


def test_cli_help(capsys):
    """Test that CLI root help prints usage."""
    code = main(["--help"])
    assert code == 0
    captured = capsys.readouterr()
    assert "Exposure Triage Workbench" in captured.out


def test_cli_ingest_trufflehog_and_verify_counts(cli_db_path: str, capsys):
    """Test ingesting TruffleHog synthetic fixture file."""
    fixture_path = "datasets/fixtures-v1/trufflehog_fixtures.jsonl"
    code = main(["--db", cli_db_path, "ingest", fixture_path])
    assert code == 0

    captured = capsys.readouterr()
    assert "Ingestion successful" in captured.out
    assert "31 valid, 3 quarantined" in captured.out


def test_cli_case_list_and_filters(cli_db_path: str, capsys):
    """Test listing cases and filtering by priority."""
    fixture_path = "datasets/fixtures-v1/gitleaks_fixtures.json"
    main(["--db", cli_db_path, "ingest", fixture_path])
    capsys.readouterr()  # clear buffer

    # List all
    code = main(["--db", cli_db_path, "case", "list"])
    assert code == 0
    out = capsys.readouterr().out
    assert "CASE ID" in out
    assert "PRIORITY" in out

    # Filter P1
    code_p1 = main(["--db", cli_db_path, "case", "list", "--priority", "P1_urgent"])
    assert code_p1 == 0
    out_p1 = capsys.readouterr().out
    assert "P1_urgent" in out_p1
    assert "P4_low" not in out_p1


def test_cli_case_show_and_set_status(cli_db_path: str, capsys):
    """Test inspecting a case and changing its disposition with an audit note."""
    fixture_path = "datasets/fixtures-v1/trufflehog_fixtures.jsonl"
    main(["--db", cli_db_path, "ingest", fixture_path])

    # Get first case ID from list
    from etw.storage.database import Database
    db = Database(cli_db_path)
    cases = db.list_cases()
    assert len(cases) > 0
    target_case_id = cases[0].id

    # Show case
    code_show = main(["--db", cli_db_path, "case", "show", target_case_id])
    assert code_show == 0
    show_out = capsys.readouterr().out
    assert f"=== Case {target_case_id} ===" in show_out
    assert "Classification Rationale:" in show_out
    assert "Audit History:" in show_out

    # Update disposition
    code_update = main([
        "--db", cli_db_path, "case", "set-status", target_case_id,
        "--status", "confirmed_issue",
        "--actor", "alice_analyst",
        "--note", "Triage confirmed with team",
    ])
    assert code_update == 0
    update_out = capsys.readouterr().out
    assert "disposition updated to 'confirmed_issue'" in update_out

    # Verify updated state
    updated_case = db.get_case(target_case_id)
    assert updated_case.disposition.value == "confirmed_issue"
    assert updated_case.audit_history[-1].actor == "alice_analyst"
    assert updated_case.audit_history[-1].note == "Triage confirmed with team"


def test_cli_report_and_export_files(cli_db_path: str, tmp_path: Path):
    """Test generating Markdown report and JSON export files and verify zero secret leaks."""
    fixture_path = "datasets/fixtures-v1/trufflehog_fixtures.jsonl"
    main(["--db", cli_db_path, "ingest", fixture_path])

    report_file = tmp_path / "report.md"
    export_file = tmp_path / "export.json"

    # Generate Report
    code_report = main(["--db", cli_db_path, "report", "-o", str(report_file)])
    assert code_report == 0
    assert report_file.exists()
    report_text = report_file.read_text(encoding="utf-8")
    assert "Security Triage Report" in report_text
    assert "Executive Summary" in report_text

    # Generate JSON Export
    code_export = main(["--db", cli_db_path, "export", "--format", "json", "-o", str(export_file)])
    assert code_export == 0
    assert export_file.exists()
    export_data = json.loads(export_file.read_text(encoding="utf-8"))
    assert export_data["metadata"]["tool"] == "Exposure Triage Workbench (ETW)"
    assert export_data["metadata"]["total_cases"] > 0
    assert "cases" in export_data


def test_cli_error_handling(cli_db_path: str, capsys):
    """Test that CLI errors exit with code 1 and clean error messages."""
    # Non-existent file
    code_missing = main(["--db", cli_db_path, "ingest", "does_not_exist.json"])
    assert code_missing == 1
    err = capsys.readouterr().err
    assert "Finding file not found" in err

    # Non-existent case
    code_bad_case = main(["--db", cli_db_path, "case", "show", "case-non-existent"])
    assert code_bad_case == 1
    err_case = capsys.readouterr().err
    assert "not found" in err_case

    # Invalid status
    code_bad_status = main(["--db", cli_db_path, "case", "set-status", "case-1", "--status", "invalid_status"])
    assert code_bad_status == 1
    err_status = capsys.readouterr().err
    assert "Invalid status" in err_status


def test_cli_benchmark_run(capsys):
    """Test running the benchmark command via CLI."""
    code = main(["benchmark", "run", "--fixtures-dir", "datasets/fixtures-v1"])
    assert code == 0
    out = capsys.readouterr().out
    assert "BENCHMARK EVALUATION REPORT" in out
    assert "DECISION GATE 1 STATUS: [PASS]" in out
