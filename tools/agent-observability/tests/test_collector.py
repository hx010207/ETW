"""
Acceptance tests for event collector and live observability integration.
Tests transcript parsing, GSD progress collection, idempotency, and server integration.
"""
import unittest
import tempfile
import json
import shutil
import threading
import time
import urllib.request
from pathlib import Path
import sys

# Add parent directory to sys.path
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))

from database import init_db, get_events, get_connection
from collector import (
    find_active_transcripts, parse_transcript_events,
    collect_gsd_progress, sync_all, BackgroundSyncRunner
)
from server import HTTPServer, ObservabilityHandler

class TestCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws_dir = Path(self.temp_dir.name) / "workspace"
        self.ws_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.ws_dir / "observability.db"
        init_db(self.db_path)

        # Setup mock brain storage
        self.brain_dir = Path(self.temp_dir.name) / "brain"
        self.conv_dir = self.brain_dir / "test-conv-123" / ".system_generated" / "logs"
        self.conv_dir.mkdir(parents=True, exist_ok=True)
        self.transcript_file = self.conv_dir / "transcript.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_find_active_transcripts(self):
        # Write dummy transcript
        self.transcript_file.write_text('{"step_index": 0}\n', encoding="utf-8")
        found = find_active_transcripts(self.ws_dir, brain_dir=self.brain_dir)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0], self.transcript_file)

    def test_parse_transcript_events(self):
        # Create multi-step synthetic transcript
        lines = [
            # Step 0: User input
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "<USER_REQUEST>Run tests and review code</USER_REQUEST>",
                "created_at": "2026-10-11T10:00:00Z"
            },
            # Step 1: PLANNER_RESPONSE with pytest
            {
                "step_index": 1,
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-10-11T10:00:05Z",
                "tool_calls": [
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "pytest tests/ --cov"}
                    }
                ]
            },
            # Step 2: RUN_COMMAND output
            {
                "step_index": 2,
                "type": "RUN_COMMAND",
                "exit_code": 0,
                "content": "=== 26 passed in 0.50s ===",
                "created_at": "2026-10-11T10:00:10Z"
            },
            # Step 3: PLANNER_RESPONSE with file edits & CodeRabbit
            {
                "step_index": 3,
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-10-11T10:01:00Z",
                "tool_calls": [
                    {
                        "name": "write_to_file",
                        "args": {"TargetFile": "src/etw/models/case.py"}
                    },
                    {
                        "name": "run_command",
                        "args": {"CommandLine": "coderabbit review --yes"}
                    },
                    {
                        "name": "call_mcp_tool",
                        "args": {"ServerName": "gsd", "ToolName": "gsd_read_state"}
                    }
                ]
            },
            # Step 4: RUN_COMMAND exit code 1 (failure)
            {
                "step_index": 4,
                "type": "RUN_COMMAND",
                "exit_code": 1,
                "content": "Review failed: authentication required",
                "created_at": "2026-10-11T10:01:10Z"
            }
        ]

        with open(self.transcript_file, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(json.dumps(line) + "\n")

        events = parse_transcript_events(self.transcript_file, conv_id="test-conv-123")
        self.assertEqual(len(events), 5)

        # 1. User prompt
        user_evt = events[0]
        self.assertEqual(user_evt["event_type"], "user_prompt")
        self.assertEqual(user_evt["tool_id"], "antigravity")
        self.assertIn("Run tests and review code", user_evt["details"])

        # 2. Pytest test run
        test_evt = events[1]
        self.assertEqual(test_evt["event_type"], "test_run")
        self.assertEqual(test_evt["tool_id"], "antigravity")
        self.assertEqual(test_evt["status"], "success")
        self.assertIn("26 passed", test_evt["details"])

        # 3. File write
        write_evt = events[2]
        self.assertEqual(write_evt["event_type"], "file_write")
        self.assertEqual(write_evt["tool_id"], "antigravity")
        self.assertIn("case.py", write_evt["details"])

        # 4. CodeRabbit review (failed exit code 1)
        cr_evt = events[3]
        self.assertEqual(cr_evt["event_type"], "cli_review")
        self.assertEqual(cr_evt["tool_id"], "coderabbit")
        self.assertEqual(cr_evt["status"], "failed")
        self.assertEqual(cr_evt["exit_code"], 1)

        # 5. GSD MCP tool call
        mcp_evt = events[4]
        self.assertEqual(mcp_evt["event_type"], "mcp_tool_call")
        self.assertEqual(mcp_evt["tool_id"], "gsd")

    def test_collect_gsd_progress(self):
        plan_dir = self.ws_dir / ".planning"
        plan_dir.mkdir(parents=True, exist_ok=True)
        state_file = plan_dir / "STATE.md"
        state_file.write_text("""# GSD State
**Current Milestone:** v0.2 Credential MVP
**Current Phase:** Phase 3 — Ingestion & Normalization
**Phase Status:** Complete
**Last Updated:** 2026-10-11

## Phase Execution Checklist
- [x] Implement streaming common module
- [x] Implement TruffleHog adapter
- [ ] Implement Gitleaks adapter
""", encoding="utf-8")

        events = collect_gsd_progress(self.ws_dir)
        self.assertEqual(len(events), 3)

        # Phase status
        phase_evt = events[0]
        self.assertEqual(phase_evt["tool_id"], "gsd")
        self.assertEqual(phase_evt["event_type"], "phase_status")
        self.assertEqual(phase_evt["status"], "success")

        # Checklist tasks
        task_1 = events[1]
        self.assertEqual(task_1["tool_id"], "gsd")
        self.assertEqual(task_1["event_type"], "task_progress")
        self.assertIn("streaming common module", task_1["details"])

        task_2 = events[2]
        self.assertIn("TruffleHog adapter", task_2["details"])

    def test_idempotent_sync_all(self):
        # Setup transcript
        lines = [
            {"step_index": 0, "type": "USER_INPUT", "content": "hello", "created_at": "2026-10-11T12:00:00Z"},
            {"step_index": 1, "type": "PLANNER_RESPONSE", "tool_calls": [{"name": "view_file", "args": {"AbsolutePath": "foo.py"}}]}
        ]
        with open(self.transcript_file, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(json.dumps(line) + "\n")

        # Setup GSD
        plan_dir = self.ws_dir / ".planning"
        plan_dir.mkdir(parents=True, exist_ok=True)
        (plan_dir / "STATE.md").write_text("**Current Milestone:** v0.1\n**Current Phase:** P1\n**Phase Status:** In Progress\n- [x] Task A\n", encoding="utf-8")

        # 1st sync
        res1 = sync_all(self.ws_dir, self.db_path, brain_dir=self.brain_dir)
        self.assertGreater(res1["new_inserted"], 0)

        # 2nd sync must insert 0 duplicates
        res2 = sync_all(self.ws_dir, self.db_path, brain_dir=self.brain_dir)
        self.assertEqual(res2["new_inserted"], 0)

        # Verify database total
        stored = get_events(self.db_path, limit=1000)
        self.assertEqual(len(stored), res1["new_inserted"])

    def test_background_sync_runner(self):
        # Write 1 event
        self.transcript_file.write_text(json.dumps({
            "step_index": 0, "type": "USER_INPUT", "content": "Initial", "created_at": "2026-10-11T12:00:00Z"
        }) + "\n", encoding="utf-8")

        runner = BackgroundSyncRunner(self.ws_dir, self.db_path, interval_seconds=0.2, brain_dir=self.brain_dir)
        runner.start()
        try:
            time.sleep(0.5)
            evts = get_events(self.db_path, limit=1000)
            self.assertEqual(len(evts), 1)

            # Append another line live
            with open(self.transcript_file, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "step_index": 1, "type": "USER_INPUT", "content": "Second line", "created_at": "2026-10-11T12:00:05Z"
                }) + "\n")

            time.sleep(0.5)
            evts_updated = get_events(self.db_path, limit=1000)
            self.assertEqual(len(evts_updated), 2)
        finally:
            runner.stop()

class TestServerSyncIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.ws_dir = Path(cls.temp_dir.name) / "test_isolated_ws"
        cls.ws_dir.mkdir(parents=True, exist_ok=True)
        cls.db_path = cls.ws_dir / "test_observability.db"
        init_db(cls.db_path)


        cls.port = 8798
        cls.host = "127.0.0.1"

        ObservabilityHandler.db_path = cls.db_path
        ObservabilityHandler.workspace_root = cls.ws_dir

        cls.server = HTTPServer((cls.host, cls.port), ObservabilityHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp_dir.cleanup()

    def test_post_sync_and_get_events(self):
        # Setup GSD state in workspace
        plan_dir = self.ws_dir / ".planning"
        plan_dir.mkdir(parents=True, exist_ok=True)
        (plan_dir / "STATE.md").write_text("""# State
**Current Milestone:** v0.2 MVP
**Current Phase:** Phase 4
**Phase Status:** In Progress
- [x] Automated Integration Test
""", encoding="utf-8")

        # Trigger POST /api/sync
        url_sync = f"http://{self.host}:{self.port}/api/sync"
        req_sync = urllib.request.Request(url_sync, data=b"{}", headers={"Host": f"{self.host}:{self.port}", "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req_sync) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertIn("sync", data)

        # GET /api/events must now reflect the synced GSD tasks
        url_events = f"http://{self.host}:{self.port}/api/events"
        req_events = urllib.request.Request(url_events, headers={"Host": f"{self.host}:{self.port}"})
        with urllib.request.urlopen(req_events) as resp:
            self.assertEqual(resp.status, 200)
            evts_data = json.loads(resp.read().decode("utf-8"))
            events = evts_data["events"]
            self.assertGreater(len(events), 0)
            self.assertTrue(any("Automated Integration Test" in e.get("details", "") for e in events))
            self.assertEqual(evts_data["usage_summary"]["gsd"]["total_recorded_invocations"], len(events))

if __name__ == "__main__":
    unittest.main()
