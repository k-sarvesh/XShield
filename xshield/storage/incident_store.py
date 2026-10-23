"""SQLite-backed persistent store for XShield security incidents and flow history.

Provides ACID persistence, thread-safe query/update interfaces, and full analyst state management.
"""

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("data") / "xshield_incidents.db"


@dataclass
class IncidentRecord:
    """Represents an analyst-actionable security incident."""
    incident_id: str
    created_at: str
    last_seen: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    severity: str                 # 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    detection_source: str         # 'ml_model', 'heuristic_indicator', 'hybrid'
    raw_score: Optional[float]
    model_name: Optional[str]
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    status: str = "New"           # 'New', 'Investigating', 'Benign', 'Confirmed Suspicious', 'Resolved'
    analyst_notes: str = ""
    response_action: str = "None" # 'None', 'Simulated Block', 'Enforced Block', 'Rolled Back'
    occurrence_count: int = 1


class IncidentStore:
    """Thread-safe SQLite database manager for persistent security incidents."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes database tables and performance indices."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS incidents (
                            incident_id TEXT PRIMARY KEY,
                            created_at TEXT NOT NULL,
                            last_seen TEXT NOT NULL,
                            src_ip TEXT NOT NULL,
                            dst_ip TEXT NOT NULL,
                            src_port INTEGER NOT NULL,
                            dst_port INTEGER NOT NULL,
                            proto TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            detection_source TEXT NOT NULL,
                            raw_score REAL,
                            model_name TEXT,
                            evidence_json TEXT,
                            limitations_json TEXT,
                            status TEXT NOT NULL,
                            analyst_notes TEXT,
                            response_action TEXT,
                            occurrence_count INTEGER DEFAULT 1
                        )
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_dst ON incidents(dst_ip, dst_port)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
            finally:
                conn.close()


    def save_incident(self, inc: IncidentRecord) -> None:
        """Inserts or updates an incident record."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO incidents (
                            incident_id, created_at, last_seen, src_ip, dst_ip, src_port, dst_port,
                            proto, severity, detection_source, raw_score, model_name, evidence_json,
                            limitations_json, status, analyst_notes, response_action, occurrence_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(incident_id) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            occurrence_count=excluded.occurrence_count,
                            evidence_json=excluded.evidence_json,
                            response_action=excluded.response_action,
                            status=excluded.status,
                            analyst_notes=excluded.analyst_notes
                        """,
                        (
                            inc.incident_id,
                            inc.created_at,
                            inc.last_seen,
                            inc.src_ip,
                            inc.dst_ip,
                            inc.src_port,
                            inc.dst_port,
                            inc.proto,
                            inc.severity,
                            inc.detection_source,
                            inc.raw_score,
                            inc.model_name,
                            json.dumps(inc.evidence),
                            json.dumps(inc.limitations),
                            inc.status,
                            inc.analyst_notes,
                            inc.response_action,
                            inc.occurrence_count,
                        ),
                    )
            finally:
                conn.close()

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        """Fetches an incident by its unique ID."""
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._row_to_record(row)
            finally:
                conn.close()

    def find_active_incident(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[IncidentRecord]:
        """Searches for an open/investigating incident on matching endpoint pair."""
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT * FROM incidents 
                    WHERE src_ip = ? AND dst_ip = ? AND dst_port = ? 
                    AND status IN ('New', 'Investigating')
                    ORDER BY last_seen DESC LIMIT 1
                    """,
                    (src_ip, dst_ip, dst_port),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return self._row_to_record(row)
            finally:
                conn.close()

    def list_incidents(
        self,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
    ) -> List[IncidentRecord]:
        """Queries incidents matching optional filters and text search."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status_filter and status_filter != "All":
            query += " AND status = ?"
            params.append(status_filter)

        if severity_filter and severity_filter != "All":
            query += " AND severity = ?"
            params.append(severity_filter)

        if search_query:
            q_clean = f"%{search_query.strip()}%"
            query += " AND (incident_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR analyst_notes LIKE ?)"
            params.extend([q_clean, q_clean, q_clean, q_clean])

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(query, tuple(params))
                rows = cur.fetchall()
                return [self._row_to_record(r) for r in rows]
            finally:
                conn.close()

    def update_status(
        self, incident_id: str, new_status: str, notes: Optional[str] = None, action: Optional[str] = None
    ) -> bool:
        """Updates analyst status, notes, or response action."""
        with self._lock:
            conn = self._get_connection()
            try:
                updates = ["status = ?"]
                params: List[Any] = [new_status]

                if notes is not None:
                    updates.append("analyst_notes = ?")
                    params.append(notes)
                if action is not None:
                    updates.append("response_action = ?")
                    params.append(action)

                params.append(incident_id)
                with conn:
                    cur = conn.execute(
                        f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?", tuple(params)
                    )
                    return cur.rowcount > 0
            finally:
                conn.close()

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Computes aggregate incident metrics for high-level dashboard display."""
        with self._lock:
            conn = self._get_connection()
            try:
                total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                high_sev = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'HIGH'").fetchone()[0]
                active = conn.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('New', 'Investigating')").fetchone()[0]
                resolved = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'Resolved'").fetchone()[0]
                blocks = conn.execute("SELECT COUNT(*) FROM incidents WHERE response_action LIKE '%Block%'").fetchone()[0]

                return {
                    "total_incidents": total,
                    "high_severity": high_sev,
                    "active_investigations": active,
                    "resolved": resolved,
                    "blocks_recorded": blocks,
                }
            finally:
                conn.close()

    def _row_to_record(self, row: sqlite3.Row) -> IncidentRecord:
        """Converts a SQLite Row to a typed IncidentRecord."""
        evidence = []
        limitations = []
        try:
            if row["evidence_json"]:
                evidence = json.loads(row["evidence_json"])
        except Exception:
            pass

        try:
            if row["limitations_json"]:
                limitations = json.loads(row["limitations_json"])
        except Exception:
            pass

        return IncidentRecord(
            incident_id=row["incident_id"],
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            proto=row["proto"],
            severity=row["severity"],
            detection_source=row["detection_source"],
            raw_score=row["raw_score"],
            model_name=row["model_name"],
            evidence=evidence,
            limitations=limitations,
            status=row["status"],
            analyst_notes=row["analyst_notes"] or "",
            response_action=row["response_action"] or "None",
            occurrence_count=row["occurrence_count"],
        )
