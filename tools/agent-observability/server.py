"""
Minimal, secure localhost-only HTTP server for Agent Observability.
Binds strictly to 127.0.0.1.
Zero external dependencies (uses standard library http.server).
"""
import sys
import os
import json
import socket
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import (
    init_db, get_latest_health_checks, get_events, record_event,
    get_work_sessions, record_work_session, get_config, set_config,
    clear_database, export_data
)
from health_checker import TOOLS_REGISTRY, run_all_health_checks
from metrics import calculate_tool_usage_summary, calculate_productivity_summary

try:
    import collector
    from collector import BackgroundSyncRunner
except ImportError:
    collector = None
    BackgroundSyncRunner = None

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_REQUEST_BYTES = 1024 * 1024  # 1 MB

class ObservabilityHandler(BaseHTTPRequestHandler):
    db_path: Path = Path("tools/agent-observability/data/observability.db")
    workspace_root: Path = Path(".")

    def server_version_header(self):
        # Override to avoid leaking system details
        return "AgentObservability/1.0"

    def send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status_code: int, message: str):
        self.send_json(status_code, {"error": message, "status": status_code})

    def validate_request(self) -> bool:
        """Validates host header and request headers for localhost security."""
        host = self.headers.get("Host", "")
        # Strictly localhost or 127.0.0.1 with optional port
        if not (host.startswith("localhost") or host.startswith("127.0.0.1")):
            self.send_error_json(400, "Invalid Host header. Localhost binding only.")
            return False
            
        # Origin check if provided
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.hostname not in ("127.0.0.1", "localhost"):
                self.send_error_json(403, "Forbidden cross-origin request.")
                return False
                
        return True

    def read_json_body(self) -> tuple[bool, any]:
        """Reads and validates incoming JSON payload with size limits."""
        content_len = self.headers.get("Content-Length")
        if not content_len:
            return False, "Missing Content-Length"
        try:
            length = int(content_len)
        except ValueError:
            return False, "Invalid Content-Length"
            
        if length > MAX_REQUEST_BYTES:
            return False, "Payload too large (exceeds 1MB limit)"
            
        try:
            body = self.rfile.read(length).decode("utf-8")
            return True, json.loads(body)
        except json.JSONDecodeError:
            return False, "Malformed JSON payload"
        except Exception as e:
            return False, "Failed to read request body"

    def do_GET(self):
        if not self.validate_request():
            return
            
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Serve static assets
        if path in ("/", "/index.html"):
            return self.serve_static_file("index.html", "text/html; charset=utf-8")
        elif path == "/styles.css":
            return self.serve_static_file("styles.css", "text/css; charset=utf-8")
        elif path == "/app.js":
            return self.serve_static_file("app.js", "application/javascript; charset=utf-8")

        # API Routes
        if path == "/api/health":
            health = get_latest_health_checks(self.db_path, TOOLS_REGISTRY)
            # Determine staleness
            timestamps = [h.get("timestamp") for h in health.values() if h.get("timestamp")]
            latest_ts = max(timestamps) if timestamps else None
            is_stale = True
            if latest_ts:
                try:
                    dt = datetime.fromisoformat(latest_ts.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    is_stale = (now - dt) > timedelta(hours=1)
                except Exception:
                    is_stale = True
                    
            return self.send_json(200, {
                "tools": health,
                "latest_timestamp": latest_ts,
                "is_stale": is_stale,
                "registered_tools": TOOLS_REGISTRY
            })

        elif path == "/api/events":
            if collector:
                try:
                    collector.sync_all(self.workspace_root, self.db_path)
                except Exception:
                    pass
            tool_id = query.get("tool_id", [None])[0]
            start_date = query.get("start_date", [None])[0]
            end_date = query.get("end_date", [None])[0]
            events = get_events(self.db_path, tool_id=tool_id, start_date=start_date, end_date=end_date, limit=200)
            all_events = get_events(self.db_path, limit=1000)
            usage_summary = calculate_tool_usage_summary(all_events, TOOLS_REGISTRY)
            return self.send_json(200, {
                "events": events,
                "usage_summary": usage_summary
            })

        elif path == "/api/sessions":
            sessions = get_work_sessions(self.db_path, limit=200)
            return self.send_json(200, {"sessions": sessions})

        elif path == "/api/metrics":
            sessions = get_work_sessions(self.db_path, limit=1000)
            hr_str = get_config(self.db_path, "hourly_rate_inr")
            cost_str = get_config(self.db_path, "attributable_costs_inr")
            
            hourly_rate = float(hr_str) if hr_str is not None else None
            costs = float(cost_str) if cost_str is not None else None
            
            summary = calculate_productivity_summary(
                sessions=sessions,
                hourly_rate_inr=hourly_rate,
                attributable_costs_inr=costs
            )
            return self.send_json(200, summary)

        elif path == "/api/config":
            return self.send_json(200, {
                "hourly_rate_inr": get_config(self.db_path, "hourly_rate_inr"),
                "attributable_costs_inr": get_config(self.db_path, "attributable_costs_inr"),
                "currency": "INR"
            })

        elif path == "/api/export":
            export_payload = export_data(self.db_path, TOOLS_REGISTRY)
            return self.send_json(200, export_payload)

        else:
            self.send_error_json(404, "Endpoint not found.")

    def do_POST(self):
        if not self.validate_request():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health/run":
            # Runs fixed allowlist checks without shell injection
            checks = run_all_health_checks(self.db_path, self.workspace_root)
            return self.send_json(200, {"status": "ok", "checks": checks})

        elif path == "/api/events":
            ok, data = self.read_json_body()
            if not ok:
                return self.send_error_json(400, str(data))
            if not isinstance(data, dict) or "tool_id" not in data:
                return self.send_error_json(400, "Missing required tool_id in payload.")
            if data["tool_id"] not in TOOLS_REGISTRY:
                return self.send_error_json(400, f"tool_id must be one of: {TOOLS_REGISTRY}")

            inserted = record_event(self.db_path, data)
            return self.send_json(201, {"recorded": inserted, "tool_id": data["tool_id"]})

        elif path == "/api/sessions":
            ok, data = self.read_json_body()
            if not ok:
                return self.send_error_json(400, str(data))
            if not isinstance(data, dict) or "task_name" not in data:
                return self.send_error_json(400, "Missing required task_name in payload.")

            session_id = record_work_session(self.db_path, data)
            return self.send_json(201, {"session_id": session_id, "status": "recorded"})

        elif path == "/api/config":
            ok, data = self.read_json_body()
            if not ok:
                return self.send_error_json(400, str(data))
            if not isinstance(data, dict):
                return self.send_error_json(400, "Expected JSON object.")

            if "hourly_rate_inr" in data:
                rate = data["hourly_rate_inr"]
                if rate is None or rate == "":
                    set_config(self.db_path, "hourly_rate_inr", "")
                else:
                    try:
                        val = float(rate)
                        set_config(self.db_path, "hourly_rate_inr", str(val))
                    except ValueError:
                        return self.send_error_json(400, "hourly_rate_inr must be a valid number.")

            if "attributable_costs_inr" in data:
                cost = data["attributable_costs_inr"]
                if cost is None or cost == "":
                    set_config(self.db_path, "attributable_costs_inr", "")
                else:
                    try:
                        val = float(cost)
                        set_config(self.db_path, "attributable_costs_inr", str(val))
                    except ValueError:
                        return self.send_error_json(400, "attributable_costs_inr must be a valid number.")

            return self.send_json(200, {"status": "updated"})

        elif path == "/api/clear":
            ok, data = self.read_json_body()
            if not ok:
                return self.send_error_json(400, str(data))
            if not isinstance(data, dict) or not data.get("confirm"):
                return self.send_error_json(400, "Confirmation required: payload must include {'confirm': true}.")

            clear_database(self.db_path)
            return self.send_json(200, {"status": "cleared", "message": "Database cleared successfully."})

        elif path == "/api/sync":
            if collector:
                res = collector.sync_all(self.workspace_root, self.db_path)
                return self.send_json(200, {"status": "ok", "sync": res})
            return self.send_json(200, {"status": "ok", "message": "Collector unavailable"})

        else:
            self.send_error_json(404, "Endpoint not found.")

    def serve_static_file(self, filename: str, content_type: str):
        """Safely serves approved static files, preventing directory traversal."""
        target = (STATIC_DIR / filename).resolve()
        # Verify path stays within STATIC_DIR
        try:
            target.relative_to(STATIC_DIR)
        except ValueError:
            return self.send_error_json(403, "Access denied.")
            
        if not target.is_file():
            return self.send_error_json(404, "File not found.")
            
        try:
            with open(target, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error_json(500, "Error loading static asset.")

    def log_message(self, format, *args):
        # Override standard log to avoid noisy stderr prints during tests
        pass

def run_server(port: int = 8765, db_path: Optional[Path] = None, workspace_root: Optional[Path] = None):
    host = "127.0.0.1"  # STRICT LOCALHOST BINDING
    db = db_path or (Path(__file__).resolve().parent / "data" / "observability.db")
    ws = workspace_root or Path(".").resolve()
    
    init_db(db)
    ObservabilityHandler.db_path = db
    ObservabilityHandler.workspace_root = ws

    try:
        server = HTTPServer((host, port), ObservabilityHandler)
    except OSError as e:
        print(f"Error: Unable to bind to {host}:{port}. {e}")
        print(f"If port {port} is occupied, specify an alternative port: python server.py --port <port>")
        sys.exit(1)

    print(f"Agent Observability Dashboard running at http://{host}:{port}/")
    print(f"Bound strictly to loopback interface {host}. Press Ctrl+C to terminate.")

    sync_runner = None
    if BackgroundSyncRunner:
        sync_runner = BackgroundSyncRunner(ws, db, interval_seconds=2.0)
        sync_runner.start()
        print("Live agent event collector active (2s background sync).")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        if sync_runner:
            sync_runner.stop()
        server.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run local Agent Observability server")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    parser.add_argument("--db", default=None, help="Path to sqlite database")
    parser.add_argument("--workspace", default=None, help="Path to workspace root")
    args = parser.parse_args()

    db_arg = Path(args.db).resolve() if args.db else None
    ws_arg = Path(args.workspace).resolve() if args.workspace else None
    run_server(port=args.port, db_path=db_arg, workspace_root=ws_arg)
