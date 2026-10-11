"""
Productivity and usage metrics calculation engine.
Follows strict non-invented telemetry and non-double-counting rules.
"""
from typing import List, Dict, Any, Optional

def calculate_tool_usage_summary(events: List[Dict[str, Any]], tools: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Computes usage statistics per tool from recorded events.
    Never invents invocations or success rates.
    """
    summary: Dict[str, Dict[str, Any]] = {}
    
    for tool_id in tools:
        tool_events = [e for e in events if e.get("tool_id") == tool_id]
        total = len(tool_events)
        
        if total == 0:
            summary[tool_id] = {
                "total_recorded_invocations": 0,
                "successful_invocations": 0,
                "failed_invocations": 0,
                "last_recorded_use": None,
                "last_successful_use": None,
                "success_rate": None,
                "total_duration_ms": 0,
                "average_duration_ms": None,
                "evidence_sources": []
            }
            continue
            
        successful = sum(1 for e in tool_events if e.get("status") == "success")
        failed = sum(1 for e in tool_events if e.get("status") == "failed")
        
        # Sort chronologically
        sorted_events = sorted(tool_events, key=lambda x: x.get("timestamp", ""))
        last_recorded = sorted_events[-1].get("timestamp")
        
        successful_events = [e for e in sorted_events if e.get("status") == "success"]
        last_successful = successful_events[-1].get("timestamp") if successful_events else None
        
        durations = [e.get("duration_ms") for e in tool_events if isinstance(e.get("duration_ms"), (int, float))]
        total_duration = sum(durations) if durations else 0
        avg_duration = (total_duration / len(durations)) if durations else None
        
        success_rate = (successful / total) * 100.0 if total > 0 else None
        evidence_sources = list(set(e.get("evidence_source", "unknown") for e in tool_events if e.get("evidence_source")))
        
        summary[tool_id] = {
            "total_recorded_invocations": total,
            "successful_invocations": successful,
            "failed_invocations": failed,
            "last_recorded_use": last_recorded,
            "last_successful_use": last_successful,
            "success_rate": round(success_rate, 1) if success_rate is not None else None,
            "total_duration_ms": total_duration,
            "average_duration_ms": round(avg_duration, 1) if avg_duration is not None else None,
            "evidence_sources": sorted(evidence_sources)
        }
        
    return summary


def calculate_productivity_summary(
    sessions: List[Dict[str, Any]],
    hourly_rate_inr: Optional[float] = None,
    attributable_costs_inr: Optional[float] = None
) -> Dict[str, Any]:
    """
    Computes honest productivity and estimated financial value.
    
    Formula:
    - Estimated time difference = baseline duration - actual assisted duration
    - Estimated labour value = max(0, positive estimated time difference in hours) * user-configured hourly value
    - Estimated net value = estimated labour value - recorded attributable costs
    
    Rules:
    - Negative differences are shown clearly and NOT converted into savings.
    - If hourly_rate_inr is not configured, financial value is not calculated.
    - If costs are missing, net value is marked as incomplete.
    - Tasks using multiple tools are grouped by combined workflow; time is never double-counted.
    """
    completed_sessions = [s for s in sessions if s.get("completion_status") == "completed"]
    total_completed = len(completed_sessions)
    
    total_assisted_seconds = sum(float(s.get("actual_duration_seconds", 0)) for s in completed_sessions)
    total_baseline_seconds = sum(float(s.get("baseline_duration_seconds", 0)) for s in completed_sessions)
    
    diff_seconds = total_baseline_seconds - total_assisted_seconds
    diff_hours = diff_seconds / 3600.0
    
    # Financial calculations
    labour_value_inr = None
    financial_status_message = None
    
    if hourly_rate_inr is None or hourly_rate_inr <= 0:
        financial_status_message = "Financial value not calculated: configure an hourly value."
    else:
        # Only positive time difference yields financial value
        positive_diff_hours = max(0.0, diff_hours)
        labour_value_inr = round(positive_diff_hours * hourly_rate_inr, 2)
        
    net_value_inr = None
    net_value_status_message = None
    
    if labour_value_inr is not None:
        if attributable_costs_inr is not None and attributable_costs_inr >= 0:
            net_value_inr = round(labour_value_inr - attributable_costs_inr, 2)
        else:
            net_value_status_message = "Net value incomplete: attributable costs missing."
    else:
        net_value_status_message = "Net value incomplete: labour value not calculated."
        
    # Workflow breakdown without double-counting
    workflow_breakdown: Dict[str, Dict[str, Any]] = {}
    for s in completed_sessions:
        tools = s.get("tools_used")
        if isinstance(tools, list):
            wf_key = " + ".join(sorted(tools)) if tools else "Single / Unspecified"
        elif isinstance(tools, str):
            wf_key = tools
        else:
            wf_key = "Unspecified"
            
        if wf_key not in workflow_breakdown:
            workflow_breakdown[wf_key] = {
                "tasks_count": 0,
                "assisted_seconds": 0.0,
                "baseline_seconds": 0.0,
                "diff_seconds": 0.0
            }
            
        dur = float(s.get("actual_duration_seconds", 0))
        base = float(s.get("baseline_duration_seconds", 0))
        workflow_breakdown[wf_key]["tasks_count"] += 1
        workflow_breakdown[wf_key]["assisted_seconds"] += dur
        workflow_breakdown[wf_key]["baseline_seconds"] += base
        workflow_breakdown[wf_key]["diff_seconds"] += (base - dur)
        
    for k, v in workflow_breakdown.items():
        v["diff_hours"] = round(v["diff_seconds"] / 3600.0, 2)
        v["assisted_hours"] = round(v["assisted_seconds"] / 3600.0, 2)
        v["baseline_hours"] = round(v["baseline_seconds"] / 3600.0, 2)

    return {
        "total_tasks_completed": total_completed,
        "total_assisted_seconds": round(total_assisted_seconds, 1),
        "total_baseline_seconds": round(total_baseline_seconds, 1),
        "total_assisted_hours": round(total_assisted_seconds / 3600.0, 2),
        "total_baseline_hours": round(total_baseline_seconds / 3600.0, 2),
        "estimated_time_difference_seconds": round(diff_seconds, 1),
        "estimated_time_difference_hours": round(diff_hours, 2),
        "is_positive_time_saved": diff_seconds > 0,
        "hourly_rate_inr": hourly_rate_inr,
        "attributable_costs_inr": attributable_costs_inr,
        "estimated_labour_value_inr": labour_value_inr,
        "estimated_net_value_inr": net_value_inr,
        "financial_status_message": financial_status_message,
        "net_value_status_message": net_value_status_message,
        "workflow_breakdown": workflow_breakdown
    }
