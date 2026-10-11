"""
Reproducible CLI verification and portfolio demonstration script.

Executes the complete lifecycle against an isolated temporary database:
1. Ingest TruffleHog fixtures
2. Ingest Gitleaks fixtures
3. Ingest MCP config
4. Re-triage / correlate
5. Case list with priority filtering
6. Case detail inspection
7. Analyst disposition update with audit history
8. Markdown report generation (sanitized)
9. JSON export generation (sanitized)
10. Binary zero-raw-secret verification on SQLite database file
11. Run purging and retention cleanup
"""

import json
import os
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd_list, check=True):
    print(f"\n[EXEC] {' '.join(cmd_list)}")
    res = subprocess.run(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if res.stdout:
        print(f"[STDOUT]\n{res.stdout.strip()}")
    if res.stderr:
        print(f"[STDERR]\n{res.stderr.strip()}", file=sys.stderr)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {res.returncode}")
    return res


def main():
    repo_root = Path(__file__).resolve().parent.parent
    demo_dir = repo_root / ".etw_demo_tmp"
    demo_dir.mkdir(parents=True, exist_ok=True)

    db_path = demo_dir / "demo.db"
    report_path = demo_dir / "demo_report.md"
    export_path = demo_dir / "demo_export.json"

    # Remove previous demo artifacts if present
    for p in [db_path, report_path, export_path]:
        if p.exists():
            p.unlink()

    print("=================================================================")
    print("ETW REPRODUCIBLE CLI DEMONSTRATION & VERIFICATION")
    print(f"Isolated DB Path: {db_path}")
    print("=================================================================")

    # 1. Ingest TruffleHog
    th_file = repo_root / "datasets" / "fixtures-v1" / "trufflehog_fixtures.jsonl"
    run_cmd(["etw", "--db", str(db_path), "ingest", str(th_file)])

    # 2. Ingest Gitleaks
    gl_file = repo_root / "datasets" / "fixtures-v1" / "gitleaks_fixtures.json"
    run_cmd(["etw", "--db", str(db_path), "ingest", str(gl_file)])

    # 3. Ingest MCP Config
    mcp_file = repo_root / "datasets" / "fixtures-v1" / "sample_mcp_config.json"
    run_cmd(["etw", "--db", str(db_path), "ingest", str(mcp_file)])

    # 4. Run Triage Re-evaluation
    run_cmd(["etw", "--db", str(db_path), "triage"])

    # 5. List P1 Urgent Cases
    p1_res = run_cmd(["etw", "--db", str(db_path), "case", "list", "--priority", "P1_urgent"])
    assert "P1_urgent" in p1_res.stdout

    # 6. List P4 Low Cases
    p4_res = run_cmd(["etw", "--db", str(db_path), "case", "list", "--priority", "P4_low"])
    assert "P4_low" in p4_res.stdout

    # 7. Extract first case ID and show details
    first_case_id = None
    for line in p1_res.stdout.splitlines():
        line = line.strip()
        if line.startswith("- case-") or line.startswith("case-") or "[case-" in line:
            parts = line.replace("-", " ").replace("[", " ").replace("]", " ").split()
            for part in parts:
                if part.startswith("case-"):
                    first_case_id = part
                    break
        if first_case_id:
            break

    if not first_case_id:
        # Fallback inspection of cases
        from etw.storage.database import Database
        cases = Database(db_path).list_cases()
        assert len(cases) > 0
        first_case_id = cases[0].id

    print(f"\n[DEMO] Selected Case for Deep Inspection: {first_case_id}")
    show_res = run_cmd(["etw", "--db", str(db_path), "case", "show", first_case_id])
    assert "Fingerprint:" in show_res.stdout
    assert "Audit History:" in show_res.stdout

    # 8. Record Analyst Disposition
    note = "Verified with asset owner via security ticket; rotation scheduled."
    run_cmd([
        "etw", "--db", str(db_path), "case", "set-status", first_case_id,
        "--status", "confirmed_issue",
        "--actor", "lead_auditor",
        "--note", note,
    ])

    # 9. Verify updated status and audit entry
    show_updated = run_cmd(["etw", "--db", str(db_path), "case", "show", first_case_id])
    assert "confirmed_issue" in show_updated.stdout
    assert "lead_auditor" in show_updated.stdout
    assert note in show_updated.stdout

    # 10. Generate Markdown Report
    run_cmd(["etw", "--db", str(db_path), "report", "-o", str(report_path)])
    assert report_path.exists()
    report_content = report_path.read_text(encoding="utf-8")
    assert "Security Triage Report" in report_content
    assert first_case_id in report_content

    # 11. Generate JSON Export
    run_cmd(["etw", "--db", str(db_path), "export", "--format", "json", "-o", str(export_path)])
    assert export_path.exists()
    export_data = json.loads(export_path.read_text(encoding="utf-8"))
    assert "cases" in export_data
    assert len(export_data["cases"]) > 0

    # 12. Security Check: Assert zero raw secrets in SQLite file or exports
    known_test_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_000000000000000000000000000000000000",
        "sqp_0000000000000000000000000000000000000000",
    ]
    db_bytes = db_path.read_bytes()
    for s in known_test_secrets:
        assert s.encode("utf-8") not in db_bytes, f"Raw secret leaked in SQLite DB: {s}"
        assert s not in report_content, f"Raw secret leaked in Markdown report: {s}"
        assert s not in export_path.read_text(encoding="utf-8"), f"Raw secret leaked in JSON export: {s}"

    print("\n[VERIFICATION PASS] Zero raw secrets found in SQLite file, reports, or JSON exports.")

    # 13. Test Run Purging
    from etw.storage.database import Database
    db = Database(db_path)
    with db.get_connection() as conn:
        runs = [r["id"] for r in conn.execute("SELECT id FROM runs").fetchall()]

    assert len(runs) > 0
    run_to_purge = runs[0]
    purge_res = run_cmd(["etw", "--db", str(db_path), "purge", run_to_purge])
    assert f"Run '{run_to_purge}' and associated records successfully purged." in purge_res.stdout

    # Clean up demo files
    for p in [db_path, report_path, export_path]:
        if p.exists():
            p.unlink()
    if demo_dir.exists():
        try:
            demo_dir.rmdir()
        except OSError:
            pass

    print("\n=================================================================")
    print("ALL CLI WORKFLOW DEMONSTRATION STEPS COMPLETED SUCCESSFULLY!")
    print("=================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
