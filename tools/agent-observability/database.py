"""
SQLite database storage and query layer for Agent Observability.
Thread-safe, handles idempotency, redacts sensitive secrets.
"""
import sqlite3
import json
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

SECRET_PATTERNS = [
    re.compile(r'(?i)(?:key|token|secret|password|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?'),
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    re.compile(r'glpat-[a-zA-Z0-9\-]{20,}'),
    re.compile(r'AIza[0-9A-Za-z\-_]{35}')
]

def sanitize_text(text: Optional[str]) -> Optional[str]:
    """Redacts secrets and auth tokens from text."""
    if not text:
        return text
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized

def get_connection(db_path: Path) -> sqlite3.Connection:
    """Returns a SQLite connection with dict row access."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Path) -> None:
    """Initializes tables and indexes."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            check_type TEXT NOT NULL,
            result_status TEXT NOT NULL,
            runtime_status TEXT NOT NULL,
            exit_code INTEGER,
            version TEXT,
            diagnostic_message TEXT,
            telemetry_source TEXT
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            task_id TEXT,
            phase_id TEXT,
            duration_ms INTEGER,
            exit_code INTEGER,
            status TEXT NOT NULL,
            evidence_source TEXT NOT NULL,
            details TEXT
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS work_sessions (
            id TEXT PRIMARY KEY,
            task_name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            actual_duration_seconds REAL NOT NULL,
            baseline_duration_seconds REAL NOT NULL,
            tools_used TEXT NOT NULL,
            completion_status TEXT NOT NULL,
            measurement_method TEXT NOT NULL,
            notes TEXT
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hc_tool_time ON health_checks(tool_id, timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_tool_time ON events(tool_id, timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_time ON work_sessions(start_time);")
        conn.commit()

def record_health_check(
    db_path: Path,
    tool_id: str,
    check_type: str,
    result_status: str,
    runtime_status: str,
    exit_code: Optional[int] = None,
    version: Optional[str] = None,
    diagnostic_message: Optional[str] = None,
    telemetry_source: str = "cli_doctor",
    timestamp: Optional[str] = None
) -> int:
    """Inserts a health check record."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    msg = sanitize_text(diagnostic_message)
    ver = sanitize_text(version)
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO health_checks (
            tool_id, timestamp, check_type, result_status, runtime_status,
            exit_code, version, diagnostic_message, telemetry_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tool_id, ts, check_type, result_status, runtime_status, exit_code, ver, msg, telemetry_source))
        conn.commit()
        return cursor.lastrowid

def get_latest_health_checks(db_path: Path, tools: List[str]) -> Dict[str, Dict[str, Any]]:
    """Gets the most recent health check for each registered tool."""
    results: Dict[str, Dict[str, Any]] = {}
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        for tool_id in tools:
            cursor.execute("""
            SELECT * FROM health_checks
            WHERE tool_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """, (tool_id,))
            row = cursor.fetchone()
            if row:
                results[tool_id] = dict(row)
            else:
                results[tool_id] = {
                    "tool_id": tool_id,
                    "timestamp": None,
                    "check_type": "none",
                    "result_status": "Unknown",
                    "runtime_status": "Unknown",
                    "exit_code": None,
                    "version": None,
                    "diagnostic_message": "No health check recorded yet.",
                    "telemetry_source": "none"
                }
    return results

def record_event(db_path: Path, event: Dict[str, Any]) -> bool:
    """
    Inserts a usage event with idempotency.
    Returns True if inserted, False if skipped (duplicate ID).
    """
    event_id = event.get("id") or str(uuid.uuid4())
    ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    tool_id = event.get("tool_id", "unknown")
    event_type = event.get("event_type", "invocation")
    task_id = event.get("task_id")
    phase_id = event.get("phase_id")
    duration_ms = event.get("duration_ms")
    exit_code = event.get("exit_code")
    status = event.get("status", "success")
    evidence_source = event.get("evidence_source", "manual_entry")
    details = sanitize_text(event.get("details"))

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
            INSERT INTO events (
                id, timestamp, tool_id, event_type, task_id, phase_id,
                duration_ms, exit_code, status, evidence_source, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_id, ts, tool_id, event_type, task_id, phase_id, duration_ms, exit_code, status, evidence_source, details))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Duplicate ID
            return False

def record_events_batch(db_path: Path, events: List[Dict[str, Any]]) -> int:
    """
    Inserts a batch of usage events with idempotency within a single transaction.
    Returns the count of successfully inserted records.
    """
    if not events:
        return 0

    inserted_count = 0
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        for event in events:
            event_id = event.get("id") or str(uuid.uuid4())
            ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
            tool_id = event.get("tool_id", "unknown")
            event_type = event.get("event_type", "invocation")
            task_id = event.get("task_id")
            phase_id = event.get("phase_id")
            duration_ms = event.get("duration_ms")
            exit_code = event.get("exit_code")
            status = event.get("status", "success")
            evidence_source = event.get("evidence_source", "manual_entry")
            details = sanitize_text(event.get("details"))

            try:
                cursor.execute("""
                INSERT INTO events (
                    id, timestamp, tool_id, event_type, task_id, phase_id,
                    duration_ms, exit_code, status, evidence_source, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (event_id, ts, tool_id, event_type, task_id, phase_id, duration_ms, exit_code, status, evidence_source, details))
                inserted_count += 1
            except sqlite3.IntegrityError:
                continue
        conn.commit()
    return inserted_count


def get_events(
    db_path: Path,
    tool_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Retrieves filtered events."""
    query = "SELECT * FROM events WHERE 1=1"
    params: List[Any] = []
    
    if tool_id and tool_id != "all":
        query += " AND tool_id = ?"
        params.append(tool_id)
    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def record_work_session(db_path: Path, session: Dict[str, Any]) -> str:
    """Inserts a work session for productivity measurement."""
    session_id = session.get("id") or str(uuid.uuid4())
    task_name = session.get("task_name", "Untitled Task")
    start_time = session.get("start_time") or datetime.now(timezone.utc).isoformat()
    end_time = session.get("end_time")
    actual_dur = float(session.get("actual_duration_seconds", 0.0))
    base_dur = float(session.get("baseline_duration_seconds", 0.0))
    tools = session.get("tools_used", [])
    if isinstance(tools, list):
        tools_json = json.dumps(tools)
    else:
        tools_json = json.dumps([str(tools)])
    status = session.get("completion_status", "completed")
    method = session.get("measurement_method", "manual")
    notes = sanitize_text(session.get("notes", ""))
    
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO work_sessions (
            id, task_name, start_time, end_time, actual_duration_seconds,
            baseline_duration_seconds, tools_used, completion_status,
            measurement_method, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, task_name, start_time, end_time, actual_dur, base_dur, tools_json, status, method, notes))
        conn.commit()
        return session_id

def get_work_sessions(db_path: Path, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieves work sessions."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM work_sessions ORDER BY start_time DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["tools_used"] = json.loads(d["tools_used"])
            except Exception:
                d["tools_used"] = []
            result.append(d)
        return result

def get_config(db_path: Path, key: str, default: Optional[str] = None) -> Optional[str]:
    """Gets config value."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else default

def set_config(db_path: Path, key: str, value: str) -> None:
    """Sets config value."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()

def clear_database(db_path: Path) -> None:
    """Clears all records from tables after explicit confirmation."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM health_checks;")
        cursor.execute("DELETE FROM events;")
        cursor.execute("DELETE FROM work_sessions;")
        conn.commit()

def export_data(db_path: Path, tools: List[str]) -> Dict[str, Any]:
    """Returns sanitized export of database content."""
    events = get_events(db_path, limit=1000)
    sessions = get_work_sessions(db_path, limit=1000)
    health = get_latest_health_checks(db_path, tools)
    
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "health_checks": health,
        "events": events,
        "work_sessions": sessions,
        "config": {
            "hourly_rate_inr": get_config(db_path, "hourly_rate_inr"),
            "attributable_costs_inr": get_config(db_path, "attributable_costs_inr")
        }
    }
