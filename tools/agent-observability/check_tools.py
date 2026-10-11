"""
CLI entry point for running health checks.
"""
import sys
import argparse
from pathlib import Path

# Add current folder to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import init_db
from health_checker import run_all_health_checks

def main():
    parser = argparse.ArgumentParser(description="Run toolchain health checks")
    parser.add_argument("--db", default="tools/agent-observability/data/observability.db", help="Path to sqlite db")
    parser.add_argument("--workspace", default=".", help="Path to workspace root")
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    ws_path = Path(args.workspace).resolve()

    init_db(db_path)
    checks = run_all_health_checks(db_path, ws_path)

    print("=" * 85)
    print(f"{'TOOL ID':<15} | {'INSTALL STATUS':<32} | {'RUNTIME STATUS':<24} | {'VERSION'}")
    print("=" * 85)
    for c in checks:
        ver = c.get('version') or '-'
        print(f"{c['tool_id']:<15} | {c['result_status']:<32} | {c['runtime_status']:<24} | {ver}")
    print("=" * 85)

if __name__ == "__main__":
    main()
