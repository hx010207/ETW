"""
CLI and hook helper to record an event into the SQLite database.
"""
import sys
import argparse
import json
from pathlib import Path

# Add current folder to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import init_db, record_event

def main():
    parser = argparse.ArgumentParser(description="Record toolchain usage event")
    parser.add_argument("--tool-id", required=True, help="Tool identifier")
    parser.add_argument("--event-type", default="manual_usage_record", help="Type of event")
    parser.add_argument("--status", default="success", choices=["success", "failed", "pending"], help="Outcome status")
    parser.add_argument("--duration-ms", type=int, default=None, help="Duration in milliseconds")
    parser.add_argument("--task-id", default=None, help="Task ID")
    parser.add_argument("--phase-id", default=None, help="Phase ID")
    parser.add_argument("--exit-code", type=int, default=0, help="Process exit code")
    parser.add_argument("--evidence-source", default="manual_entry", help="Source of evidence")
    parser.add_argument("--details", default="", help="Sanitized details")
    parser.add_argument("--event-id", default=None, help="Idempotent event ID")
    parser.add_argument("--db", default="tools/agent-observability/data/observability.db", help="Database path")
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    init_db(db_path)

    event = {
        "id": args.event_id,
        "tool_id": args.tool_id,
        "event_type": args.event_type,
        "status": args.status,
        "duration_ms": args.duration_ms,
        "task_id": args.task_id,
        "phase_id": args.phase_id,
        "exit_code": args.exit_code,
        "evidence_source": args.evidence_source,
        "details": args.details
    }

    inserted = record_event(db_path, event)
    if inserted:
        print(f"Recorded event for {args.tool_id} ({args.event_type}): {args.status}")
    else:
        print(f"Event skipped (duplicate ID): {args.event_id}")

if __name__ == "__main__":
    main()
