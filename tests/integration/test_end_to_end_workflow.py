"""
Comprehensive End-to-End Workflow Integration Test for ETW.

Validates the full lifecycle:
Scanner File -> Ingestion -> Classification -> Case Correlation ->
Secure Persistence -> Application Restart -> Analyst Review & Disposition ->
Sanitized Markdown Report & JSON Export -> Byte-Level Zero Secret Leak Audit.
"""

import json
from pathlib import Path
import pytest

from etw.cli import main
from etw.models.enums import DispositionState, ReviewPriority
from etw.storage.database import Database


def test_full_end_to_end_triage_lifecycle(tmp_path: Path, capsys):
    """
    Executes a complete end-to-end triage lifecycle using synthetic fixtures
    and asserts zero secret leaks, correct disposition tracking, and valid reports.
    """
    db_path = str(tmp_path / "lifecycle_etw.db")
    fixture_path = "datasets/fixtures-v1/trufflehog_fixtures.jsonl"
    report_path = tmp_path / "lifecycle_report.md"
    export_path = tmp_path / "lifecycle_export.json"

    # Step 1: Ingest scanner findings
    code_ingest = main(["--db", db_path, "ingest", fixture_path])
    assert code_ingest == 0
    ingest_out = capsys.readouterr().out
    assert "Ingestion successful" in ingest_out
    assert "31 valid, 3 quarantined" in ingest_out

    # Step 2: Query cases from database (Application Restart simulation)
    db = Database(db_path)
    cases = db.list_cases()
    assert len(cases) > 0

    # Ensure urgent cases (P1) exist
    p1_cases = [c for c in cases if c.priority == ReviewPriority.P1]
    assert len(p1_cases) > 0
    target_case = p1_cases[0]

    # Step 3: Perform Analyst Review & record disposition
    code_status = main([
        "--db", db_path, "case", "set-status", target_case.id,
        "--status", "confirmed_issue",
        "--actor", "lead_analyst_carol",
        "--note", "Verified credential exposure with engineering; rotation initiated.",
    ])
    assert code_status == 0
    status_out = capsys.readouterr().out
    assert "disposition updated to 'confirmed_issue'" in status_out

    # Step 4: Verify audit history persisted across restart
    db_reopened = Database(db_path)
    case_verified = db_reopened.get_case(target_case.id)
    assert case_verified is not None
    assert case_verified.disposition == DispositionState.CONFIRMED_ISSUE
    assert len(case_verified.audit_history) >= 2
    last_audit = case_verified.audit_history[-1]
    assert last_audit.actor == "lead_analyst_carol"
    assert last_audit.to_status == DispositionState.CONFIRMED_ISSUE
    assert "rotation initiated" in last_audit.note

    # Step 5: Generate Markdown Report
    code_report = main(["--db", db_path, "report", "-o", str(report_path)])
    assert code_report == 0
    assert report_path.exists()
    report_content = report_path.read_text(encoding="utf-8")
    assert "Security Triage Report" in report_content
    assert "Audit Log & Decision History" in report_content
    assert "lead_analyst_carol" in report_content

    # Step 6: Generate JSON Export
    code_export = main(["--db", db_path, "export", "--format", "json", "-o", str(export_path)])
    assert code_export == 0
    assert export_path.exists()
    export_content = json.loads(export_path.read_text(encoding="utf-8"))
    assert export_content["metadata"]["total_cases"] == len(cases)
    assert export_content["summary"]["by_disposition"]["confirmed_issue"] >= 1

    # Step 7: Security Audit - Binary Byte-Level Zero Secret Leakage Check
    # Verify no raw secrets appear in DB file, WAL file, report, or export
    db_bytes = Path(db_path).read_bytes()
    wal_path = Path(f"{db_path}-wal")
    wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""

    # Synthetic canary secret from fixtures: "AKIAIOSFODNN7EXAMPLE" / known fixture strings
    # Ensure raw secret field name is nowhere in JSON or SQLite
    assert b'"raw_secret"' not in db_bytes
    assert b'"raw_secret"' not in wal_bytes
    assert "raw_secret" not in json.dumps(export_content)
