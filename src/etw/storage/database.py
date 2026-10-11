"""
SQLite persistence service for Exposure Triage Workbench (ETW).

Guarantees:
1. Strict zero raw secret persistence: the schema contains no secret columns.
2. SQLite with WAL mode and foreign key enforcement enabled.
3. Schema migrations tracked in `schema_migrations`.
4. Transactional atomicity for run ingestion and case correlation.
5. Versioned audit event logging for case disposition transitions.
6. Local-first file security with restricted file creation permissions.
"""

import json
import os
import sqlite3
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from etw.models.case import AuditEvent, Case
from etw.models.enums import (
    ClassificationState,
    DispositionState,
    EvidenceLevel,
    ReviewPriority,
    SourceValidity,
)
from etw.models.evidence import AssetCandidate, LocationEvidence
from etw.models.observation import Observation


SCHEMA_VERSION = 1

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    source_file TEXT,
    scanner_type TEXT,
    total_records INTEGER DEFAULT 0,
    valid_records INTEGER DEFAULT 0,
    quarantined_records INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    detector TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    source_reported_validity TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    commit_hash TEXT,
    commit_author TEXT,
    repo_name TEXT,
    asset_scope TEXT NOT NULL,
    candidate_fingerprint TEXT NOT NULL,
    redacted_match TEXT NOT NULL,
    extracted_assets_json TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    asset_scope TEXT NOT NULL,
    classification TEXT NOT NULL,
    disposition TEXT NOT NULL,
    priority TEXT NOT NULL,
    priority_factors_json TEXT NOT NULL,
    classification_reasons_json TEXT NOT NULL,
    observations_count INTEGER DEFAULT 1,
    related_cases_json TEXT NOT NULL,
    asset_candidates_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_observations (
    case_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    PRIMARY KEY (case_id, observation_id),
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
    FOREIGN KEY (observation_id) REFERENCES observations (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS quarantined_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    record_index INTEGER,
    redacted_preview TEXT,
    reason TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_obs_fingerprint ON observations(candidate_fingerprint);
CREATE INDEX IF NOT EXISTS idx_obs_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority);
CREATE INDEX IF NOT EXISTS idx_cases_disposition ON cases(disposition);
CREATE INDEX IF NOT EXISTS idx_cases_fingerprint ON cases(fingerprint);
"""


def _set_restricted_permissions(file_path: Path) -> None:
    """Apply strict permissions (0600 on POSIX)."""
    try:
        if sys.platform != "win32":
            file_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


class Database:
    """Manages SQLite storage for ETW runs, observations, cases, and audit history."""

    def __init__(self, db_path: str = "./.etw/etw.db"):
        self.db_path = Path(db_path)
        self._ensure_directory()
        self.initialize_schema()

    def _ensure_directory(self) -> None:
        """Ensure parent directory exists with safe permissions."""
        parent = self.db_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform != "win32":
                parent.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Create and yield a SQLite connection with WAL mode, closing it upon exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        _set_restricted_permissions(self.db_path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Executes schema migrations and sets up initial tables."""
        with self.get_connection() as conn:
            conn.executescript(CREATE_TABLES_SQL)
            # Check migration status
            cur = conn.execute("SELECT version FROM schema_migrations WHERE version = ?", (SCHEMA_VERSION,))
            if not cur.fetchone():
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
                )
            conn.commit()

    def save_run(
        self,
        run_id: str,
        source_file: Optional[str],
        scanner_type: str,
        total_records: int,
        valid_records: int,
        quarantined_records: int,
    ) -> None:
        """Save a scan ingestion run record."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    id, created_at, source_file, scanner_type, total_records, valid_records, quarantined_records
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    datetime.now(timezone.utc).isoformat(),
                    source_file,
                    scanner_type,
                    total_records,
                    valid_records,
                    quarantined_records,
                ),
            )
            conn.commit()

    def save_observations(self, run_id: str, observations: List[Observation]) -> None:
        """Persist normalized observations. Raw secrets are NEVER written."""
        if not observations:
            return

        with self.get_connection() as conn:
            for obs in observations:
                extracted_json = json.dumps([a.model_dump() for a in obs.extracted_assets])
                conn.execute(
                    """
                    INSERT OR REPLACE INTO observations (
                        id, run_id, detector, rule_id, source_reported_validity,
                        file_path, line_start, line_end, column_start, column_end,
                        commit_hash, commit_author, repo_name, asset_scope,
                        candidate_fingerprint, redacted_match, extracted_assets_json, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        obs.id,
                        run_id,
                        obs.detector,
                        obs.rule_id,
                        obs.source_reported_validity.value,
                        obs.location.file_path,
                        obs.location.line_start,
                        obs.location.line_end,
                        obs.location.column_start,
                        obs.location.column_end,
                        obs.location.commit_hash,
                        obs.location.commit_author,
                        obs.location.repo_name,
                        obs.asset_scope,
                        obs.candidate_fingerprint,
                        obs.redacted_match,
                        extracted_json,
                        obs.timestamp,
                    ),
                )
            conn.commit()

    def save_quarantined_records(self, run_id: str, quarantined: List[Dict[str, Any]]) -> None:
        """Persist quarantined records with redacted previews for auditable failure tracking."""
        if not quarantined:
            return

        with self.get_connection() as conn:
            for q in quarantined:
                conn.execute(
                    """
                    INSERT INTO quarantined_records (
                        run_id, record_index, redacted_preview, reason, timestamp
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        q.get("index", 0),
                        q.get("preview", ""),
                        q.get("reason", "unknown error"),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            conn.commit()

    def save_cases(self, cases: List[Case]) -> None:
        """Persist or update cases along with their observation links and initial audit events."""
        if not cases:
            return

        with self.get_connection() as conn:
            for c in cases:
                factors_json = json.dumps(c.priority_factors)
                reasons_json = json.dumps(c.classification_reasons)
                related_json = json.dumps(c.related_cases)
                assets_json = json.dumps([a.model_dump() for a in c.asset_candidates])

                conn.execute(
                    """
                    INSERT OR REPLACE INTO cases (
                        id, fingerprint, credential_type, asset_scope, classification,
                        disposition, priority, priority_factors_json, classification_reasons_json,
                        observations_count, related_cases_json, asset_candidates_json,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c.id,
                        c.fingerprint,
                        c.credential_type,
                        c.asset_scope,
                        c.classification.value,
                        c.disposition.value,
                        c.priority.value,
                        factors_json,
                        reasons_json,
                        c.observations_count,
                        related_json,
                        assets_json,
                        c.created_at,
                        c.updated_at,
                    ),
                )

                # Link observations
                for obs_id in c.observation_ids:
                    conn.execute(
                        "INSERT OR IGNORE INTO case_observations (case_id, observation_id) VALUES (?, ?)",
                        (c.id, obs_id),
                    )

                # Save audit history events
                for event in c.audit_history:
                    # Check if event already exists to prevent duplicate insertion
                    cur = conn.execute(
                        """
                        SELECT id FROM audit_events 
                        WHERE case_id = ? AND timestamp = ? AND from_status = ? AND to_status = ?
                        """,
                        (c.id, event.timestamp, event.from_status.value, event.to_status.value),
                    )
                    if not cur.fetchone():
                        conn.execute(
                            """
                            INSERT INTO audit_events (case_id, timestamp, from_status, to_status, actor, note)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                c.id,
                                event.timestamp,
                                event.from_status.value,
                                event.to_status.value,
                                event.actor,
                                event.note,
                            ),
                        )
            conn.commit()

    def get_case(self, case_id: str) -> Optional[Case]:
        """Retrieve a Case by ID with full observation links and audit history."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return None

            obs_rows = conn.execute(
                "SELECT observation_id FROM case_observations WHERE case_id = ?",
                (case_id,),
            ).fetchall()
            obs_ids = [r["observation_id"] for r in obs_rows]

            audit_rows = conn.execute(
                "SELECT * FROM audit_events WHERE case_id = ? ORDER BY id ASC",
                (case_id,),
            ).fetchall()
            audit_events = [
                AuditEvent(
                    timestamp=r["timestamp"],
                    from_status=DispositionState(r["from_status"]),
                    to_status=DispositionState(r["to_status"]),
                    actor=r["actor"],
                    note=r["note"],
                )
                for r in audit_rows
            ]

            raw_assets = json.loads(row["asset_candidates_json"])
            asset_candidates = [AssetCandidate(**a) for a in raw_assets]

            return Case(
                id=row["id"],
                fingerprint=row["fingerprint"],
                credential_type=row["credential_type"],
                asset_scope=row["asset_scope"],
                classification=ClassificationState(row["classification"]),
                disposition=DispositionState(row["disposition"]),
                priority=ReviewPriority(row["priority"]),
                priority_factors=json.loads(row["priority_factors_json"]),
                classification_reasons=json.loads(row["classification_reasons_json"]),
                observation_ids=obs_ids,
                observations_count=row["observations_count"],
                related_cases=json.loads(row["related_cases_json"]),
                asset_candidates=asset_candidates,
                audit_history=audit_events,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_cases(
        self,
        priority: Optional[ReviewPriority] = None,
        disposition: Optional[DispositionState] = None,
    ) -> List[Case]:
        """List cases with optional priority and disposition filtering."""
        with self.get_connection() as conn:
            query = "SELECT id FROM cases WHERE 1=1"
            params: List[Any] = []
            if priority:
                query += " AND priority = ?"
                params.append(priority.value)
            if disposition:
                query += " AND disposition = ?"
                params.append(disposition.value)
            query += " ORDER BY priority ASC, created_at DESC"

            rows = conn.execute(query, params).fetchall()

        cases: List[Case] = []
        for r in rows:
            c = self.get_case(r["id"])
            if c:
                cases.append(c)
        return cases

    def update_case_disposition(
        self,
        case_id: str,
        new_status: DispositionState,
        actor: str = "analyst",
        note: str = "",
    ) -> Optional[Case]:
        """
        Record an analyst disposition change on a case with immutable audit event tracking.
        """
        case = self.get_case(case_id)
        if not case:
            return None

        old_status = case.disposition
        now_iso = datetime.now(timezone.utc).isoformat()

        audit_event = AuditEvent(
            timestamp=now_iso,
            from_status=old_status,
            to_status=new_status,
            actor=actor,
            note=note,
        )

        with self.get_connection() as conn:
            conn.execute(
                "UPDATE cases SET disposition = ?, updated_at = ? WHERE id = ?",
                (new_status.value, now_iso, case_id),
            )
            conn.execute(
                """
                INSERT INTO audit_events (case_id, timestamp, from_status, to_status, actor, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    audit_event.timestamp,
                    audit_event.from_status.value,
                    audit_event.to_status.value,
                    audit_event.actor,
                    audit_event.note,
                ),
            )
            conn.commit()

        return self.get_case(case_id)

    def get_observations_for_case(self, case_id: str) -> List[Observation]:
        """Retrieve all Observation objects associated with a specific Case."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT o.* FROM observations o
                JOIN case_observations co ON o.id = co.observation_id
                WHERE co.case_id = ?
                ORDER BY o.timestamp ASC
                """,
                (case_id,),
            ).fetchall()

        observations: List[Observation] = []
        for r in rows:
            extracted_assets = [
                AssetCandidate(**a) for a in json.loads(r["extracted_assets_json"] or "[]")
            ]
            loc = LocationEvidence(
                file_path=r["file_path"],
                line_start=r["line_start"],
                line_end=r["line_end"],
                column_start=r["column_start"],
                column_end=r["column_end"],
                commit_hash=r["commit_hash"],
                commit_author=r["commit_author"],
                repo_name=r["repo_name"],
            )
            obs = Observation(
                id=r["id"],
                detector=r["detector"],
                rule_id=r["rule_id"],
                source_reported_validity=SourceValidity(r["source_reported_validity"]),
                location=loc,
                asset_scope=r["asset_scope"],
                candidate_fingerprint=r["candidate_fingerprint"],
                redacted_match=r["redacted_match"],
                raw_secret=None,  # Zero raw secret guarantee: DB never stores or loads raw secrets
                extracted_assets=extracted_assets,
                timestamp=r["timestamp"],
            )
            observations.append(obs)
        return observations

    def purge_run(self, run_id: str) -> bool:
        """Safely purge a run and its cascaded records, cleaning up orphaned cases."""
        with self.get_connection() as conn:
            cur = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
            # Clean up orphaned cases where all linked observations have been purged
            conn.execute(
                """
                DELETE FROM cases
                WHERE id NOT IN (SELECT DISTINCT case_id FROM case_observations)
                """
            )
            conn.commit()
            return cur.rowcount > 0

