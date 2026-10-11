"""
Event Collector for Coding-Agent Toolchain Observability.
Extracts verified, real events from:
1. Antigravity transcript logs (.system_generated/logs/transcript.jsonl)
   - Agent runs, user prompts, tool invocations
   - File edits, writes, inspections
   - Commands, git actions, test runs (pytest), review invocations (CodeRabbit), GSD commands
2. GSD state and execution checklists (.planning/STATE.md, .planning/ROADMAP.md)
   - Phase progress, milestone status, completed tasks

All events are persisted into SQLite idempotently with secret redaction.
"""
import os
import sys
import json
import re
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from database import record_events_batch

def sanitize_slug(text: str) -> str:
    """Creates a URL-safe, compact slug."""
    clean = re.sub(r'[^a-zA-Z0-9_\-]+', '-', text.strip().lower())
    return clean.strip('-')[:50]

def find_active_transcripts(workspace_root: Path, brain_dir: Optional[Path] = None) -> List[Path]:
    """
    Finds active transcript.jsonl files within Antigravity's brain storage.
    If brain_dir is explicitly specified, only that directory is searched.
    Otherwise, discovers transcripts from the environment and filters by workspace relevance.
    """
    search_dirs: List[Path] = []

    if brain_dir is not None:
        if brain_dir.exists():
            search_dirs.append(brain_dir)
        # When brain_dir is explicitly given, do not scan external system directories
    else:
        env_brain = os.environ.get("ANTIGRAVITY_BRAIN_DIR")
        if env_brain and Path(env_brain).exists():
            search_dirs.append(Path(env_brain))

        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            p = Path(user_profile) / ".gemini" / "antigravity-ide" / "brain"
            if p.exists() and p not in search_dirs:
                search_dirs.append(p)

        home_brain = Path.home() / ".gemini" / "antigravity-ide" / "brain"
        if home_brain.exists() and home_brain not in search_dirs:
            search_dirs.append(home_brain)

    candidates: List[tuple[Path, float]] = []
    ws_name = workspace_root.name.lower()

    for base in search_dirs:
        try:
            for item in base.iterdir():
                if not item.is_dir():
                    continue
                # Transcript path convention
                t_file = item / ".system_generated" / "logs" / "transcript.jsonl"
                if not t_file.exists():
                    t_file = item / "logs" / "transcript.jsonl"
                if t_file.exists() and t_file.stat().st_size > 0:
                    # If brain_dir was explicitly provided (e.g. In tests), accept it directly
                    if brain_dir is not None:
                        candidates.append((t_file, t_file.stat().st_mtime))
                    else:
                        # For system scans, ensure transcript references this workspace
                        try:
                            sample = t_file.read_text(encoding="utf-8", errors="ignore")[:16384].lower()
                            if ws_name in sample:
                                candidates.append((t_file, t_file.stat().st_mtime))
                        except Exception:
                            continue
        except Exception:
            continue

    # Sort newest first
    candidates.sort(key=lambda x: x[1], reverse=True)
    return [c[0] for c in candidates]


def parse_transcript_events(
    transcript_path: Path,
    conv_id: Optional[str] = None,
    max_steps: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Parses an Antigravity transcript.jsonl file into structured, verified events.
    """
    if not transcript_path.exists():
        return []

    if not conv_id:
        # Transcript is typically at brain/<conv_id>/.system_generated/logs/transcript.jsonl
        conv_id = transcript_path.parents[2].name if len(transcript_path.parents) >= 3 else transcript_path.parent.name

    events: List[Dict[str, Any]] = []

    try:
        raw_text = transcript_path.read_text(encoding="utf-8", errors="replace")
        lines = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
    except Exception:
        return []

    if max_steps and len(lines) > max_steps:
        lines = lines[-max_steps:]

    for i, item in enumerate(lines):
        step_type = item.get("type")
        step_idx = item.get("step_index", i)
        created_at = item.get("created_at") or datetime.now(timezone.utc).isoformat()

        # 1. User prompts (Agent Run initiation)
        if step_type == "USER_INPUT":
            content = item.get("content", "")
            # Clean XML tags
            clean_content = re.sub(r'<[^>]+>', ' ', content).strip()
            clean_content = re.sub(r'\s+', ' ', clean_content)
            events.append({
                "id": f"transcript-{conv_id}-step-{step_idx}-user",
                "timestamp": created_at,
                "tool_id": "antigravity",
                "event_type": "user_prompt",
                "task_id": f"step-{step_idx}",
                "phase_id": None,
                "duration_ms": None,
                "exit_code": 0,
                "status": "success",
                "evidence_source": "transcript_log",
                "details": f"User request: {clean_content[:180]}"
            })

        # 2. Agent tool invocations (PLANNER_RESPONSE)
        elif step_type == "PLANNER_RESPONSE":
            tool_calls = item.get("tool_calls", [])
            # Look ahead for execution result
            next_item = lines[i + 1] if i + 1 < len(lines) else {}
            next_type = next_item.get("type")
            next_exit = next_item.get("exit_code", 0) if next_type == "RUN_COMMAND" else 0
            next_content = next_item.get("content", "") if next_type == "RUN_COMMAND" else ""

            for call_idx, tc in enumerate(tool_calls):
                name = tc.get("name", "")
                args = tc.get("args", {})
                
                tool_id = "antigravity"
                event_type = f"tool_{name}"
                status = "failed" if next_exit != 0 else "success"
                exit_code = next_exit
                details = name

                if name == "run_command":
                    cmd = args.get("CommandLine", "")
                    if "pytest" in cmd:
                        tool_id = "antigravity"
                        event_type = "test_run"
                        # Extract pytest summary if available in output
                        m = re.search(r'(=+ [0-9]+ passed.*? =+)', next_content)
                        if m:
                            summary = m.group(1).replace('=', '').strip()
                            details = f"pytest: {summary}"
                        else:
                            details = f"pytest: {cmd[:140]}"
                    elif "coderabbit" in cmd:
                        tool_id = "coderabbit"
                        event_type = "cli_review"
                        details = f"CodeRabbit: {cmd[:140]}"
                    elif "gsd" in cmd or "@opengsd" in cmd:
                        tool_id = "gsd"
                        event_type = "cli_invocation"
                        details = f"GSD: {cmd[:140]}"
                    elif "git" in cmd:
                        tool_id = "antigravity"
                        event_type = "git_command"
                        details = f"git: {cmd[:140]}"
                    else:
                        tool_id = "antigravity"
                        event_type = "run_command"
                        details = f"Command: {cmd[:140]}"

                elif name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
                    target = args.get("TargetFile", "")
                    fname = Path(target).name if target else ""
                    tool_id = "antigravity"
                    event_type = "file_edit" if "replace" in name else "file_write"
                    details = f"{name}: {fname}"
                    status = "success"
                    exit_code = 0

                elif name in ("view_file", "list_dir", "grep_search"):
                    target = args.get("AbsolutePath") or args.get("DirectoryPath") or args.get("Query") or ""
                    fname = Path(target).name if target else ""
                    tool_id = "antigravity"
                    event_type = "inspect_code"
                    details = f"{name}: {fname or str(target)[:40]}"
                    status = "success"
                    exit_code = 0

                elif name == "call_mcp_tool":
                    server = args.get("ServerName", "")
                    tool = args.get("ToolName", "")
                    tool_id = "gsd" if server == "gsd" or "gsd" in tool.lower() else "antigravity"
                    event_type = "mcp_tool_call"
                    details = f"MCP: {server}.{tool}"
                    status = "success"
                    exit_code = 0

                elif name in ("manage_task", "schedule"):
                    tool_id = "antigravity"
                    event_type = "task_management"
                    details = f"{name}: {args.get('Action') or args.get('toolSummary') or ''}"
                    status = "success"
                    exit_code = 0

                events.append({
                    "id": f"transcript-{conv_id}-step-{step_idx}-call-{call_idx}",
                    "timestamp": created_at,
                    "tool_id": tool_id,
                    "event_type": event_type,
                    "task_id": f"step-{step_idx}",
                    "phase_id": None,
                    "duration_ms": None,
                    "exit_code": exit_code,
                    "status": status,
                    "evidence_source": "transcript_log",
                    "details": details
                })

    return events

def collect_gsd_progress(workspace_root: Path) -> List[Dict[str, Any]]:
    """
    Extracts milestone, phase progress, and completed checklist tasks from GSD files.
    """
    events: List[Dict[str, Any]] = []
    state_file = workspace_root / ".planning" / "STATE.md"

    if not state_file.exists():
        return events

    try:
        content = state_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return events

    m_milestone = re.search(r'\*\*Current Milestone:\*\*\s*(.+)', content)
    m_phase = re.search(r'\*\*Current Phase:\*\*\s*(.+)', content)
    m_status = re.search(r'\*\*Phase Status:\*\*\s*(.+)', content)
    m_updated = re.search(r'\*\*Last Updated:\*\*\s*(.+)', content)

    milestone = m_milestone.group(1).strip() if m_milestone else "Active Milestone"
    phase = m_phase.group(1).strip() if m_phase else "Active Phase"
    phase_status = m_status.group(1).strip() if m_status else "In Progress"
    ts = datetime.now(timezone.utc).isoformat()

    # Phase Status Event
    phase_slug = sanitize_slug(phase)
    events.append({
        "id": f"gsd-phase-{sanitize_slug(milestone)}-{phase_slug}",
        "timestamp": ts,
        "tool_id": "gsd",
        "event_type": "phase_status",
        "task_id": None,
        "phase_id": phase[:50],
        "duration_ms": None,
        "exit_code": 0,
        "status": "in_progress" if "progress" in phase_status.lower() else "success",
        "evidence_source": "gsd_state",
        "details": f"{milestone} | {phase} ({phase_status})"
    })

    # Completed checklist tasks
    checked_tasks = re.findall(r'- \[x\]\s*(.+)', content)
    for task_text in checked_tasks:
        task_clean = task_text.strip()
        slug = sanitize_slug(task_clean)
        events.append({
            "id": f"gsd-task-{slug}",
            "timestamp": ts,
            "tool_id": "gsd",
            "event_type": "task_progress",
            "task_id": slug,
            "phase_id": phase[:50],
            "duration_ms": None,
            "exit_code": 0,
            "status": "success",
            "evidence_source": "gsd_state",
            "details": f"Completed: {task_clean}"
        })

    return events

def sync_all(
    workspace_root: Path,
    db_path: Path,
    brain_dir: Optional[Path] = None,
    max_transcripts: int = 2
) -> Dict[str, int]:
    """
    Collects events from all sources and persists them to SQLite database in a batch.
    """
    all_events: List[Dict[str, Any]] = []

    # 1. Transcript events
    transcripts = find_active_transcripts(workspace_root, brain_dir)
    for t_path in transcripts[:max_transcripts]:
        t_events = parse_transcript_events(t_path)
        all_events.extend(t_events)

    # 2. GSD progress events
    gsd_events = collect_gsd_progress(workspace_root)
    all_events.extend(gsd_events)

    # Batch insert into database
    inserted = record_events_batch(db_path, all_events)

    return {
        "transcripts_found": len(transcripts),
        "total_parsed": len(all_events),
        "new_inserted": inserted
    }

class BackgroundSyncRunner:
    """
    Runs periodic synchronization in a lightweight daemon thread.
    """
    def __init__(
        self,
        workspace_root: Path,
        db_path: Path,
        interval_seconds: float = 2.0,
        brain_dir: Optional[Path] = None
    ):
        self.workspace_root = workspace_root
        self.db_path = db_path
        self.interval_seconds = interval_seconds
        self.brain_dir = brain_dir
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, daemon=True, name="ObservabilitySyncThread")
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2.0)

    def _run(self):
        while not self.stop_event.is_set():
            try:
                sync_all(self.workspace_root, self.db_path, self.brain_dir)
            except Exception:
                pass
            self.stop_event.wait(self.interval_seconds)
