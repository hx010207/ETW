"""
Antigravity PostToolUse hook listener.
Receives JSON context on stdin, outputs {} on stdout.
Extracts non-sensitive metadata for tools (Antigravity, GSD, CodeRabbit, etc.) and logs usage.
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Add current folder to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database import init_db, record_event
try:
    import collector
except ImportError:
    collector = None

def main():
    try:
        # Antigravity hook sends JSON payload on stdin
        if sys.stdin.isatty():
            payload = {}
        else:
            raw_input = sys.stdin.read()
            if raw_input.strip():
                payload = json.loads(raw_input)
            else:
                payload = {}
    except Exception:
        payload = {}


    try:
        repo_root = Path(__file__).resolve().parent.parent.parent
        db_path = Path(__file__).resolve().parent / "data" / "observability.db"
        init_db(db_path)

        # Detect tool from payload
        step_idx = payload.get("stepIdx")
        conv_id = payload.get("conversationId")
        err = payload.get("error")
        tool_call = payload.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        args = tool_call.get("args", {})
        cmd = args.get("CommandLine", "")

        tool_id = "antigravity"
        event_type = f"tool_{tool_name}" if tool_name else "hook_invocation"
        details = tool_name or "tool_execution"

        if tool_name == "run_command" or cmd:
            if "pytest" in cmd:
                tool_id = "antigravity"
                event_type = "test_run"
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
        elif tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
            target = args.get("TargetFile", "")
            tool_id = "antigravity"
            event_type = "file_edit" if "replace" in tool_name else "file_write"
            details = f"{tool_name}: {Path(target).name if target else ''}"
        elif tool_name in ("view_file", "list_dir", "grep_search"):
            target = args.get("AbsolutePath") or args.get("DirectoryPath") or args.get("Query") or ""
            tool_id = "antigravity"
            event_type = "inspect_code"
            details = f"{tool_name}: {Path(target).name if target else ''}"
        elif tool_name == "call_mcp_tool":
            server = args.get("ServerName", "")
            tname = args.get("ToolName", "")
            tool_id = "gsd" if server == "gsd" or "gsd" in tname.lower() else "antigravity"
            event_type = "mcp_tool_call"
            details = f"MCP: {server}.{tname}"

        event_id = f"hook-{conv_id}-{step_idx}" if (conv_id and step_idx is not None) else None
        status = "failed" if err else "success"
        record_event(db_path, {
            "id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_id": tool_id,
            "event_type": event_type,
            "task_id": conv_id,
            "exit_code": 1 if err else 0,
            "status": status,
            "evidence_source": "hook_post_tool",
            "details": details
        })

        # Also trigger transcript sync if collector is available
        if collector:
            collector.sync_all(workspace_root=repo_root, db_path=db_path)

    except Exception:
        # Never crash or block agent execution
        pass

    # PostToolUse contract requires empty JSON object on stdout
    sys.stdout.write("{}\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
