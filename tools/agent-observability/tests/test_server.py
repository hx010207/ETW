"""
Automated acceptance tests for Agent Observability HTTP server & security.
Uses standard library unittest and urllib.
"""
import unittest
import threading
import time
import json
import urllib.request
import urllib.error
from pathlib import Path
import tempfile
import sys

# Add parent directory to sys.path
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))

from server import HTTPServer, ObservabilityHandler
from database import init_db, record_health_check, record_event, sanitize_text

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_observability.db"
        init_db(cls.db_path)

        cls.port = 8799
        cls.host = "127.0.0.1"

        ObservabilityHandler.db_path = cls.db_path
        ObservabilityHandler.workspace_root = Path(cls.temp_dir.name)

        cls.server = HTTPServer((cls.host, cls.port), ObservabilityHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp_dir.cleanup()

    def request(self, path: str, method: str = "GET", data: dict = None, headers: dict = None):
        url = f"http://{self.host}:{self.port}{path}"
        req_headers = {"Host": f"{self.host}:{self.port}"}
        if headers:
            req_headers.update(headers)
        
        body = json.dumps(data).encode("utf-8") if data else None
        if body:
            req_headers["Content-Type"] = "application/json"
            
        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                resp_body = resp.read().decode("utf-8")
                return status, json.loads(resp_body) if resp_body else {}
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode("utf-8")
            try:
                parsed = json.loads(resp_body)
            except Exception:
                parsed = {"error": resp_body}
            return e.code, parsed

    def test_localhost_only_security(self):
        # Malicious Host header must be rejected with 400
        headers = {"Host": "attacker.com"}
        status, res = self.request("/api/health", headers=headers)
        self.assertEqual(status, 400)
        self.assertIn("Invalid Host header", res.get("error", ""))

    def test_health_endpoint_empty_db(self):
        status, res = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("tools", res)
        # All 7 tools must be reported even in empty db without crashing
        self.assertIn("gsd", res["tools"])
        self.assertIn("coderabbit", res["tools"])
        self.assertEqual(res["tools"]["gsd"]["result_status"], "Unknown")

    def test_record_and_get_events(self):
        event = {
            "id": "test-evt-001",
            "tool_id": "gsd",
            "event_type": "skill_invocation",
            "status": "success",
            "duration_ms": 150,
            "evidence_source": "hook_post_tool"
        }
        status, res = self.request("/api/events", method="POST", data=event)
        self.assertEqual(status, 201)
        self.assertTrue(res["recorded"])

        # Idempotency test: duplicate ID must not create duplicate entry
        status, res2 = self.request("/api/events", method="POST", data=event)
        self.assertEqual(status, 201)
        self.assertFalse(res2["recorded"])

        # Fetch events
        status, get_res = self.request("/api/events")
        self.assertEqual(status, 200)
        events = get_res["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], "test-evt-001")

        # Usage summary must reflect the single recorded event
        usage = get_res["usage_summary"]
        self.assertEqual(usage["gsd"]["total_recorded_invocations"], 1)
        self.assertEqual(usage["gsd"]["successful_invocations"], 1)
        self.assertEqual(usage["coderabbit"]["total_recorded_invocations"], 0)

    def test_malformed_requests_handled(self):
        # Tool ID validation
        bad_event = {"tool_id": "malicious_tool_unknown", "status": "success"}
        status, res = self.request("/api/events", method="POST", data=bad_event)
        self.assertEqual(status, 400)

        # Missing required task_name
        bad_session = {"duration": 100}
        status, res = self.request("/api/sessions", method="POST", data=bad_session)
        self.assertEqual(status, 400)

    def test_work_sessions_and_metrics(self):
        # Configure hourly rate
        cfg = {"hourly_rate_inr": 2500, "attributable_costs_inr": 1000}
        status, _ = self.request("/api/config", method="POST", data=cfg)
        self.assertEqual(status, 200)

        # Record work session
        session = {
            "task_name": "Auth refactoring",
            "actual_duration_seconds": 1800,   # 0.5 hr
            "baseline_duration_seconds": 5400,  # 1.5 hr (saved 1 hr)
            "tools_used": ["gsd", "coderabbit"],
            "completion_status": "completed",
            "measurement_method": "timer"
        }
        status, res = self.request("/api/sessions", method="POST", data=session)
        self.assertEqual(status, 201)

        # Fetch metrics
        status, metrics = self.request("/api/metrics")
        self.assertEqual(status, 200)
        self.assertEqual(metrics["total_tasks_completed"], 1)
        self.assertEqual(metrics["estimated_time_difference_hours"], 1.0)
        self.assertEqual(metrics["estimated_labour_value_inr"], 2500.0) # 1 hr * 2500
        self.assertEqual(metrics["estimated_net_value_inr"], 1500.0)    # 2500 - 1000
        # Combined workflow attribution without double counting
        self.assertIn("coderabbit + gsd", metrics["workflow_breakdown"])

    def test_secret_redaction(self):
        sensitive_text = "Running with token: ghp_1234567890abcdef1234567890abcdef1234 and api_key='secret123456'"
        sanitized = sanitize_text(sensitive_text)
        self.assertNotIn("ghp_1234567890abcdef", sanitized)
        self.assertNotIn("secret123456", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)

    def test_export_and_clear_database(self):
        # Export must work
        status, exp = self.request("/api/export")
        self.assertEqual(status, 200)
        self.assertIn("events", exp)
        self.assertIn("work_sessions", exp)

        # Clear without confirm must fail
        status, res = self.request("/api/clear", method="POST", data={"confirm": False})
        self.assertEqual(status, 400)

        # Clear with confirm
        status, res = self.request("/api/clear", method="POST", data={"confirm": True})
        self.assertEqual(status, 200)

        # Verify tables emptied
        _, ev_res = self.request("/api/events")
        self.assertEqual(len(ev_res["events"]), 0)

if __name__ == "__main__":
    unittest.main()
