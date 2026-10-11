import unittest
import sys
from pathlib import Path

# Add parent directory to sys.path so we can import metrics
parent_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(parent_dir))

from metrics import calculate_tool_usage_summary, calculate_productivity_summary

class TestMetrics(unittest.TestCase):

    def test_tool_usage_empty(self):
        tools = ["gsd", "coderabbit"]
        summary = calculate_tool_usage_summary([], tools)
        self.assertEqual(summary["gsd"]["total_recorded_invocations"], 0)
        self.assertEqual(summary["gsd"]["successful_invocations"], 0)
        self.assertEqual(summary["gsd"]["failed_invocations"], 0)
        self.assertIsNone(summary["gsd"]["success_rate"])
        self.assertIsNone(summary["gsd"]["last_recorded_use"])

    def test_tool_usage_mixed(self):
        tools = ["gsd"]
        events = [
            {"tool_id": "gsd", "status": "success", "duration_ms": 100, "timestamp": "2026-10-11T01:00:00Z", "evidence_source": "hook"},
            {"tool_id": "gsd", "status": "failed", "duration_ms": 200, "timestamp": "2026-10-11T02:00:00Z", "evidence_source": "hook"},
            {"tool_id": "gsd", "status": "success", "duration_ms": 300, "timestamp": "2026-10-11T03:00:00Z", "evidence_source": "cli"}
        ]
        summary = calculate_tool_usage_summary(events, tools)
        self.assertEqual(summary["gsd"]["total_recorded_invocations"], 3)
        self.assertEqual(summary["gsd"]["successful_invocations"], 2)
        self.assertEqual(summary["gsd"]["failed_invocations"], 1)
        self.assertAlmostEqual(summary["gsd"]["success_rate"], 66.7, places=1)
        self.assertEqual(summary["gsd"]["last_recorded_use"], "2026-10-11T03:00:00Z")
        self.assertEqual(summary["gsd"]["last_successful_use"], "2026-10-11T03:00:00Z")
        self.assertEqual(summary["gsd"]["total_duration_ms"], 600)
        self.assertEqual(summary["gsd"]["average_duration_ms"], 200.0)
        self.assertEqual(summary["gsd"]["evidence_sources"], ["cli", "hook"])

    def test_productivity_positive_savings(self):
        sessions = [
            {
                "completion_status": "completed",
                "actual_duration_seconds": 1800,  # 0.5 hours
                "baseline_duration_seconds": 7200, # 2.0 hours (saved 1.5 hours)
                "tools_used": ["gsd", "superpowers"]
            }
        ]
        res = calculate_productivity_summary(sessions, hourly_rate_inr=2000.0, attributable_costs_inr=500.0)
        self.assertEqual(res["total_tasks_completed"], 1)
        self.assertEqual(res["total_assisted_seconds"], 1800)
        self.assertEqual(res["total_baseline_seconds"], 7200)
        self.assertEqual(res["estimated_time_difference_hours"], 1.5)
        self.assertTrue(res["is_positive_time_saved"])
        self.assertEqual(res["estimated_labour_value_inr"], 3000.0) # 1.5 * 2000
        self.assertEqual(res["estimated_net_value_inr"], 2500.0) # 3000 - 500

    def test_productivity_negative_time_difference(self):
        # When assisted took LONGER than baseline (no savings)
        sessions = [
            {
                "completion_status": "completed",
                "actual_duration_seconds": 7200,  # 2 hours
                "baseline_duration_seconds": 3600, # 1 hour
                "tools_used": ["ponytail"]
            }
        ]
        res = calculate_productivity_summary(sessions, hourly_rate_inr=2000.0, attributable_costs_inr=500.0)
        self.assertEqual(res["estimated_time_difference_hours"], -1.0)
        self.assertFalse(res["is_positive_time_saved"])
        # Crucial requirement: Do NOT convert negative time difference into savings!
        self.assertEqual(res["estimated_labour_value_inr"], 0.0)
        # Net value after costs is -500.0
        self.assertEqual(res["estimated_net_value_inr"], -500.0)

    def test_productivity_missing_hourly_rate(self):
        sessions = [
            {
                "completion_status": "completed",
                "actual_duration_seconds": 1800,
                "baseline_duration_seconds": 3600,
                "tools_used": ["coderabbit"]
            }
        ]
        res = calculate_productivity_summary(sessions, hourly_rate_inr=None)
        self.assertIsNone(res["estimated_labour_value_inr"])
        self.assertIn("Financial value not calculated: configure an hourly value.", res["financial_status_message"])
        self.assertIsNone(res["estimated_net_value_inr"])

    def test_productivity_missing_costs(self):
        sessions = [
            {
                "completion_status": "completed",
                "actual_duration_seconds": 1800,
                "baseline_duration_seconds": 3600,
                "tools_used": ["coderabbit"]
            }
        ]
        res = calculate_productivity_summary(sessions, hourly_rate_inr=1500.0, attributable_costs_inr=None)
        self.assertEqual(res["estimated_labour_value_inr"], 750.0)
        self.assertIsNone(res["estimated_net_value_inr"])
        self.assertIn("Net value incomplete: attributable costs missing.", res["net_value_status_message"])

    def test_no_double_counting_multi_tool(self):
        sessions = [
            {
                "completion_status": "completed",
                "actual_duration_seconds": 3600,
                "baseline_duration_seconds": 7200,
                "tools_used": ["gsd", "superpowers", "ponytail"]
            }
        ]
        res = calculate_productivity_summary(sessions, hourly_rate_inr=1000.0)
        # Total difference must be exactly 1 hour (3600s), NOT 3 hours (1h * 3 tools)
        self.assertEqual(res["estimated_time_difference_hours"], 1.0)
        self.assertEqual(res["total_assisted_hours"], 1.0)
        self.assertEqual(res["total_baseline_hours"], 2.0)
        self.assertIn("gsd + ponytail + superpowers", res["workflow_breakdown"])

if __name__ == "__main__":
    unittest.main()
