"""
Command-Line Interface for Exposure Triage Workbench (ETW).

Commands:
  etw ingest      Ingest raw scanner JSON/JSONL, classify, correlate into cases, and persist.
  etw triage      Re-evaluate triage classification and case correlation across observations.
  etw case list   List cases with priority and status filters.
  etw case show   Display detailed evidence and audit history for a specific case.
  etw case set-status  Update case disposition with auditable analyst note.
  etw report      Generate human-readable, sanitized Markdown triage report.
  etw export      Export machine-readable JSON or Markdown case bundle.
  etw benchmark   Execute comparative benchmark on fixture corpus.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from etw.analysis.case_grouper import correlate_observations_into_cases
from etw.ingest.gitleaks import ingest_gitleaks
from etw.ingest.mcp_config import ingest_mcp_config
from etw.ingest.trufflehog import ingest_trufflehog
from etw.models.enums import ClassificationState, DispositionState, ReviewPriority
from etw.models.observation import Observation
from etw.reports.json_export import generate_json_export
from etw.reports.markdown import generate_markdown_report
from etw.rules.classifier import classify_observation
from etw.storage.database import Database
from etw.storage.fingerprint import get_hmac_key
from etw.storage.redaction import sanitize_terminal_output


DEFAULT_DB_PATH = "./.etw/etw.db"


def _get_db(args: argparse.Namespace) -> Database:
    """Helper to initialize database from arguments."""
    db_path = getattr(args, "db", None) or DEFAULT_DB_PATH
    return Database(db_path)


# ---------------------------------------------------------------------------
# Command: ingest
# ---------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest scanner finding file, classify, correlate, and store in SQLite."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: Finding file not found: {file_path}", file=sys.stderr)
        return 1

    db = _get_db(args)
    scanner_format = args.format

    # Auto-detect format if not explicitly provided
    if not scanner_format:
        scanner_format = _detect_scanner_format(file_path)

    # Ingest observations
    key = get_hmac_key(explicit_key=args.hmac_key)
    observations: List[Observation] = []
    quarantined: List[dict] = []

    try:
        if scanner_format == "trufflehog":
            res = ingest_trufflehog(file_path, hmac_key=key)
            observations = res.observations
            quarantined = [{"index": e.record_index, "reason": e.message} for e in res.errors]
        elif scanner_format == "gitleaks":
            res = ingest_gitleaks(file_path, hmac_key=key)
            observations = res.observations
            quarantined = [{"index": e.record_index, "reason": e.message} for e in res.errors]
        elif scanner_format == "mcp":
            res = ingest_mcp_config(file_path, hmac_key=key)
            observations = res.observations
            quarantined = [{"index": e.record_index, "reason": e.message} for e in res.errors]
        else:
            print(f"Error: Unsupported scanner format '{scanner_format}'. Use 'trufflehog', 'gitleaks', or 'mcp'.", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"Error during ingestion: {exc}", file=sys.stderr)
        return 1

    total_records = len(observations) + len(quarantined)
    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # Correlate into cases
    cases = correlate_observations_into_cases(observations)

    # Persist in SQLite
    db.save_run(
        run_id=run_id,
        source_file=str(file_path),
        scanner_type=scanner_format,
        total_records=total_records,
        valid_records=len(observations),
        quarantined_records=len(quarantined),
    )
    db.save_observations(run_id, observations)
    db.save_quarantined_records(run_id, quarantined)
    db.save_cases(cases)

    # Print summary
    p1 = sum(1 for c in cases if c.priority == ReviewPriority.P1)
    p2 = sum(1 for c in cases if c.priority == ReviewPriority.P2)
    p3 = sum(1 for c in cases if c.priority == ReviewPriority.P3)
    p4 = sum(1 for c in cases if c.priority == ReviewPriority.P4)

    print(f"Ingestion successful [Run ID: {run_id}]")
    print(f"  Source file:        {file_path} ({scanner_format})")
    print(f"  Records ingested:   {total_records} ({len(observations)} valid, {len(quarantined)} quarantined)")
    print(f"  Cases correlated:   {len(cases)} deduplicated cases")
    print(f"  Triage priorities:  P1={p1} | P2={p2} | P3={p3} | P4 (noise)={p4}")
    return 0


def _detect_scanner_format(file_path: Path) -> str:
    """Heuristic detector for TruffleHog, Gitleaks, and MCP config files."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(2048).strip()
            if '"mcpServers"' in head:
                return "mcp"
            if head.startswith("["):
                # JSON array: check for Gitleaks fields vs TruffleHog fields
                if '"Description"' in head or '"RuleID"' in head or '"Match"' in head:
                    return "gitleaks"
                if '"DetectorName"' in head or '"Raw"' in head:
                    return "trufflehog"
            # JSON lines: TruffleHog standard
            if '"SourceMetadata"' in head or '"DetectorName"' in head or '"DetectorType"' in head:
                return "trufflehog"
    except Exception:
        pass
    return "trufflehog"  # default fallback


# ---------------------------------------------------------------------------
# Command: triage
# ---------------------------------------------------------------------------

def cmd_triage(args: argparse.Namespace) -> int:
    """Re-correlate and classify all stored observations."""
    db = _get_db(args)
    # Collect all observations
    with db.get_connection() as conn:
        obs_rows = conn.execute("SELECT id FROM observations").fetchall()

    if not obs_rows:
        print("No observations stored in database. Run 'etw ingest <file>' first.")
        return 0

    all_obs: List[Observation] = []
    for r in obs_rows:
        with db.get_connection() as conn:
            row = conn.execute("SELECT * FROM observations WHERE id = ?", (r["id"],)).fetchone()
            if row:
                obs = db.get_observations_for_case("dummy")  # helper
    
    # Alternatively query directly
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM observations").fetchall()
    
    for r in rows:
        from etw.models.evidence import LocationEvidence, AssetCandidate
        loc = LocationEvidence(
            file_path=r["file_path"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            column_start=r["column_start"],
            column_end=r["column_end"],
            commit_hash=r["commit_hash"],
            commit_author=r["commit_author"],
            repo_name=r["repo_name"],
        )
        obs = Observation(
            id=r["id"],
            detector=r["detector"],
            rule_id=r["rule_id"],
            source_reported_validity=r["source_reported_validity"],
            location=loc,
            asset_scope=r["asset_scope"],
            candidate_fingerprint=r["candidate_fingerprint"],
            redacted_match=r["redacted_match"],
            timestamp=r["timestamp"],
        )
        all_obs.append(obs)

    cases = correlate_observations_into_cases(all_obs)
    db.save_cases(cases)
    print(f"Triage re-evaluation complete. Correlated {len(all_obs)} observations into {len(cases)} cases.")
    return 0


# ---------------------------------------------------------------------------
# Command: case (list, show, set-status)
# ---------------------------------------------------------------------------

def cmd_case_list(args: argparse.Namespace) -> int:
    """List cases with optional priority and disposition filtering."""
    db = _get_db(args)
    priority = ReviewPriority(args.priority) if args.priority else None
    disposition = DispositionState(args.status) if args.status else None

    cases = db.list_cases(priority=priority, disposition=disposition)
    if not cases:
        print("No cases found matching criteria.")
        return 0

    print(f"{'CASE ID':<18} {'PRIORITY':<12} {'CLASSIFICATION':<20} {'STATUS':<16} {'SCOPE':<24} {'FINDINGS':<8}")
    print("-" * 105)
    for c in cases:
        safe_scope = sanitize_terminal_output(c.asset_scope[:22])
        safe_type = sanitize_terminal_output(c.credential_type)
        print(
            f"{c.id:<18} {c.priority.value:<12} {c.classification.value:<20} "
            f"{c.disposition.value:<16} {safe_scope:<24} {c.observations_count:<8}"
        )
    return 0


def cmd_case_show(args: argparse.Namespace) -> int:
    """Show detailed evidence, provenance, and audit history for a single case."""
    db = _get_db(args)
    case = db.get_case(args.case_id)
    if not case:
        print(f"Error: Case '{args.case_id}' not found.", file=sys.stderr)
        return 1

    observations = db.get_observations_for_case(case.id)

    print(f"=== Case {case.id} ===")
    print(f"Priority:             {case.priority.value}")
    print(f"Classification:       {case.classification.value}")
    print(f"Disposition:          {case.disposition.value}")
    print(f"Credential Type:      {sanitize_terminal_output(case.credential_type)}")
    print(f"Asset Scope:          {sanitize_terminal_output(case.asset_scope)}")
    print(f"HMAC Fingerprint:     {case.fingerprint}")
    print(f"Observations Count:   {case.observations_count}")
    if case.related_cases:
        print(f"Related Cases:        {', '.join(case.related_cases)}")
    if case.asset_candidates:
        assets_str = ", ".join(f"{sanitize_terminal_output(a.identifier)} ({a.asset_type})" for a in case.asset_candidates)
        print(f"Extracted Assets:     {assets_str}")
    if case.priority_factors:
        print(f"Priority Factors:     {', '.join(case.priority_factors)}")

    print("\nClassification Rationale:")
    for r in case.classification_reasons:
        print(f"  - {sanitize_terminal_output(r)}")

    print(f"\nObservations ({len(observations)}):")
    for o in observations:
        loc_str = f"{sanitize_terminal_output(o.location.file_path)}:{o.location.line_start or 1}"
        print(f"  - ID: {o.id} | Detector: {o.detector} | Path: {loc_str}")
        print(f"    Match (Masked): {sanitize_terminal_output(o.redacted_match)}")

    print("\nAudit History:")
    for ev in case.audit_history:
        actor = sanitize_terminal_output(ev.actor)
        note = sanitize_terminal_output(ev.note)
        print(f"  [{ev.timestamp}] {ev.from_status.value} -> {ev.to_status.value} by '{actor}': {note}")

    return 0


def cmd_case_set_status(args: argparse.Namespace) -> int:
    """Update case disposition status with an analyst note."""
    db = _get_db(args)
    try:
        new_status = DispositionState(args.status)
    except ValueError:
        valid_statuses = [s.value for s in DispositionState]
        print(f"Error: Invalid status '{args.status}'. Valid choices: {', '.join(valid_statuses)}", file=sys.stderr)
        return 1

    actor = args.actor or os.environ.get("USER", os.environ.get("USERNAME", "analyst"))
    note = args.note or ""

    updated = db.update_case_disposition(args.case_id, new_status, actor=actor, note=note)
    if not updated:
        print(f"Error: Case '{args.case_id}' not found.", file=sys.stderr)
        return 1

    print(f"Case {updated.id} disposition updated to '{updated.disposition.value}'.")
    return 0


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    """Generate Markdown triage report."""
    db = _get_db(args)
    cases = db.list_cases()
    if not cases:
        print("No cases found in database. Run 'etw ingest <file>' first.")
        return 0

    obs_by_case = {c.id: db.get_observations_for_case(c.id) for c in cases}
    md_content = generate_markdown_report(cases, obs_by_case)

    output_path = args.output
    if output_path and output_path != "-":
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md_content, encoding="utf-8")
        print(f"Markdown report generated: {out.resolve()}")
    else:
        print(md_content)
    return 0


# ---------------------------------------------------------------------------
# Command: export
# ---------------------------------------------------------------------------

def cmd_export(args: argparse.Namespace) -> int:
    """Export machine-readable JSON or Markdown triage bundle."""
    db = _get_db(args)
    cases = db.list_cases()
    if not cases:
        print("No cases found in database. Run 'etw ingest <file>' first.")
        return 0

    obs_by_case = {c.id: db.get_observations_for_case(c.id) for c in cases}
    export_fmt = args.format.lower()

    if export_fmt == "json":
        export_data = generate_json_export(cases, obs_by_case)
        content = json.dumps(export_data, indent=2)
    elif export_fmt in ("markdown", "md"):
        content = generate_markdown_report(cases, obs_by_case)
    else:
        print(f"Error: Unsupported format '{export_fmt}'. Choose 'json' or 'markdown'.", file=sys.stderr)
        return 1

    output_path = args.output
    if output_path and output_path != "-":
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        print(f"Export ({export_fmt}) written to: {out.resolve()}")
    else:
        print(content)
    return 0


# ---------------------------------------------------------------------------
# Command: benchmark (delegated to benchmark runner)
# ---------------------------------------------------------------------------

def cmd_benchmark(args: argparse.Namespace) -> int:
    """Run benchmark against synthetic fixture corpus."""
    from etw.benchmark.runner import run_benchmark
    fixtures_dir = getattr(args, "fixtures_dir", "datasets/fixtures-v1")
    output_path = getattr(args, "output", None)
    return run_benchmark(fixtures_dir=fixtures_dir, output_path=output_path)


# ---------------------------------------------------------------------------
# Command: purge
# ---------------------------------------------------------------------------

def cmd_purge(args: argparse.Namespace) -> int:
    """Purge a specific run and its associated records according to retention rules."""
    db = _get_db(args)
    run_id = args.run_id
    success = db.purge_run(run_id)
    if success:
        print(f"Run '{run_id}' and associated records successfully purged.")
        return 0
    else:
        print(f"Error: Run '{run_id}' not found in database.", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Main CLI Parser Construction
# ---------------------------------------------------------------------------

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etw",
        description="Exposure Triage Workbench (ETW) - Local-first security finding triage",
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest scanner findings file")
    p_ingest.add_argument("file", help="Path to raw scanner findings JSON/JSONL file")
    p_ingest.add_argument("--format", choices=["trufflehog", "gitleaks", "mcp"], help="Scanner format (auto-detected if omitted)")
    p_ingest.add_argument("--hmac-key", help="Explicit HMAC secret key for fingerprinting")
    p_ingest.set_defaults(func=cmd_ingest)

    # triage
    p_triage = subparsers.add_parser("triage", help="Re-evaluate triage classification and case correlation")
    p_triage.set_defaults(func=cmd_triage)

    # case
    p_case = subparsers.add_parser("case", help="Manage and inspect cases")
    case_sub = p_case.add_subparsers(dest="case_command", help="Case actions")

    # case list
    p_case_list = case_sub.add_parser("list", help="List cases")
    p_case_list.add_argument("--priority", choices=["P1_urgent", "P2_high", "P3_normal", "P4_low"], help="Filter by priority")
    p_case_list.add_argument("--status", choices=["new", "needs_review", "confirmed_issue", "false_positive", "accepted_risk", "remediated"], help="Filter by status")
    p_case_list.set_defaults(func=cmd_case_list)

    # case show
    p_case_show = case_sub.add_parser("show", help="Show case details")
    p_case_show.add_argument("case_id", help="Case ID to inspect")
    p_case_show.set_defaults(func=cmd_case_show)

    # case set-status
    p_case_status = case_sub.add_parser("set-status", help="Update case disposition status")
    p_case_status.add_argument("case_id", help="Case ID")
    p_case_status.add_argument("--status", required=True, help="New disposition status")
    p_case_status.add_argument("--actor", help="Analyst identity")
    p_case_status.add_argument("--note", default="", help="Audit rationale note")
    p_case_status.set_defaults(func=cmd_case_set_status)

    # report
    p_report = subparsers.add_parser("report", help="Generate Markdown triage report")
    p_report.add_argument("-o", "--output", default="./.etw/triage_report.md", help="Output file path (use '-' for stdout)")
    p_report.set_defaults(func=cmd_report)

    # export
    p_export = subparsers.add_parser("export", help="Export cases in JSON or Markdown format")
    p_export.add_argument("--format", choices=["json", "markdown"], default="json", help="Export format (default: json)")
    p_export.add_argument("-o", "--output", default="./.etw/triage_export.json", help="Output file path (use '-' for stdout)")
    p_export.set_defaults(func=cmd_export)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Execute comparative benchmark against test fixtures")
    bench_sub = p_bench.add_subparsers(dest="benchmark_command", help="Benchmark actions")
    p_bench_run = bench_sub.add_parser("run", help="Run benchmark evaluation")
    p_bench_run.add_argument("--fixtures-dir", default="datasets/fixtures-v1", help="Path to test fixture directory")
    p_bench_run.add_argument("-o", "--output", help="Optional path to write benchmark results JSON")
    p_bench_run.set_defaults(func=cmd_benchmark)

    # purge
    p_purge = subparsers.add_parser("purge", help="Purge an ingested run and its associated records")
    p_purge.add_argument("run_id", help="ID of the run to purge (e.g. run-20261011-120000)")
    p_purge.set_defaults(func=cmd_purge)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0

    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
