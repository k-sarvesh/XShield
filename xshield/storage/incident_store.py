"""SQLite-backed persistent store for XShield security incidents and flow history.

Provides ACID persistence, thread-safe query/update interfaces, and full analyst state management.
"""

from dataclasses import asdict, dataclass, field
import datetime
import json
import logging
from pathlib import Path
import re
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
    is_synthetic: bool = False


class IncidentStore:
    """Thread-safe SQLite database manager for persistent security incidents."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
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
                            occurrence_count INTEGER DEFAULT 1,
                            is_synthetic INTEGER DEFAULT 0
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
                            limitations_json, status, analyst_notes, response_action, occurrence_count,
                            is_synthetic
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(incident_id) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            occurrence_count=excluded.occurrence_count,
                            evidence_json=excluded.evidence_json,
                            response_action=excluded.response_action,
                            status=excluded.status,
                            analyst_notes=excluded.analyst_notes,
                            is_synthetic=excluded.is_synthetic
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
                            1 if inc.is_synthetic else 0,
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

    def find_active_incident(
        self, src_ip: str, dst_ip: str, dst_port: int, proto: Optional[str] = None
    ) -> Optional[IncidentRecord]:
        """Searches for an open/investigating incident on matching endpoint pair and protocol."""
        with self._lock:
            conn = self._get_connection()
            try:
                query = (
                    "SELECT * FROM incidents "
                    "WHERE src_ip = ? AND dst_ip = ? AND dst_port = ? "
                    "AND status IN ('New', 'Investigating')"
                )
                params: List[Any] = [src_ip, dst_ip, dst_port]
                if proto:
                    query += " AND LOWER(proto) = LOWER(?)"
                    params.append(proto)

                query += " ORDER BY last_seen DESC LIMIT 1"
                cur = conn.execute(query, tuple(params))
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

    def seed_sample_incidents(self, force: bool = False) -> int:
        """Seeds realistic cybersecurity incident records derived from network traffic analysis."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                    if count >= 4 and not force:
                        return count

                now = datetime.datetime.now(datetime.timezone.utc)
                samples = [
                    IncidentRecord(
                        incident_id="INC-C2-COBALT",
                        created_at=(now - datetime.timedelta(hours=2)).isoformat(),
                        last_seen=(now - datetime.timedelta(minutes=5)).isoformat(),
                        src_ip="10.237.120.166",
                        dst_ip="198.51.100.24",
                        src_port=52840,
                        dst_port=8443,
                        proto="tcp",
                        severity="CRITICAL",
                        detection_source="hybrid",
                        raw_score=0.892,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "C2_BEACONING_PERIODICITY", "description": "High regularity beaconing detected (jitter < 5%) over non-standard TLS port 8443.", "confidence": "HIGH"},
                            {"indicator": "SUSPICIOUS_JA4_FINGERPRINT", "description": "Client TLS fingerprint matches known Cobalt Strike / Sliver C2 implant profile.", "confidence": "HIGH"},
                            {"indicator": "ML_ENSEMBLE_DETECTION", "description": "Model 'xshield_tqh_c2_port_excluded' scored flow at 0.892 (Threshold: 0.65).", "confidence": "HIGH"},
                        ],
                        limitations=["Model operating in experimental telemetry mode."],
                        status="New",
                        analyst_notes="Beaconing pattern detected to external untrusted VPS. High probability of command & control channel.",
                        response_action="None",
                        occurrence_count=84,
                        is_synthetic=True,
                    ),
                    IncidentRecord(
                        incident_id="INC-SCAN-SMB",
                        created_at=(now - datetime.timedelta(hours=4)).isoformat(),
                        last_seen=(now - datetime.timedelta(minutes=45)).isoformat(),
                        src_ip="192.168.1.189",
                        dst_ip="10.237.120.166",
                        src_port=41920,
                        dst_port=445,
                        proto="tcp",
                        severity="HIGH",
                        detection_source="model",
                        raw_score=0.784,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "INTERNAL_SMB_RECON", "description": "Rapid SYN attempts across local endpoint port 445 indicating lateral movement reconnaissance.", "confidence": "HIGH"},
                        ],
                        limitations=["Heuristic port scan detector."],
                        status="Investigating",
                        analyst_notes="Host 192.168.1.189 scanning internal workstations.",
                        response_action="Simulated Block",
                        occurrence_count=31,
                        is_synthetic=True,
                    ),
                    IncidentRecord(
                        incident_id="INC-DNS-EXFIL",
                        created_at=(now - datetime.timedelta(hours=1)).isoformat(),
                        last_seen=(now - datetime.timedelta(minutes=15)).isoformat(),
                        src_ip="10.237.120.166",
                        dst_ip="203.0.113.88",
                        src_port=58102,
                        dst_port=53,
                        proto="udp",
                        severity="HIGH",
                        detection_source="hybrid",
                        raw_score=0.741,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "DNS_TUNNEL_EXFILTRATION", "description": "Anomalous high-entropy base64 subdomain queries detected exceeding standard DNS payload limits.", "confidence": "HIGH"},
                        ],
                        limitations=["Heuristic DNS entropy scoring."],
                        status="Investigating",
                        analyst_notes="Investigating suspicious DNS TXT query volume.",
                        response_action="None",
                        occurrence_count=19,
                        is_synthetic=True,
                    ),
                    IncidentRecord(
                        incident_id="INC-TLS-ABRUPT",
                        created_at=(now - datetime.timedelta(hours=6)).isoformat(),
                        last_seen=(now - datetime.timedelta(hours=2)).isoformat(),
                        src_ip="10.237.120.166",
                        dst_ip="198.51.100.99",
                        src_port=51442,
                        dst_port=443,
                        proto="tcp",
                        severity="MEDIUM",
                        detection_source="heuristic",
                        raw_score=0.612,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "ABRUPT_TLS_RESET", "description": "TCP connection terminated abruptly after client handshake with zero application response bytes.", "confidence": "MEDIUM"},
                        ],
                        limitations=["Network jitter / middlebox reset."],
                        status="New",
                        analyst_notes="Triage required for aborted TLS session.",
                        response_action="None",
                        occurrence_count=12,
                        is_synthetic=True,
                    ),
                    IncidentRecord(
                        incident_id="INC-SSDP-DISCOV",
                        created_at=(now - datetime.timedelta(hours=12)).isoformat(),
                        last_seen=(now - datetime.timedelta(hours=1)).isoformat(),
                        src_ip="10.237.120.166",
                        dst_ip="239.255.255.250",
                        src_port=52350,
                        dst_port=1900,
                        proto="udp",
                        severity="LOW",
                        detection_source="model",
                        raw_score=0.345,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "MULTICAST_LOCAL_DISCOVERY", "description": "SSDP device discovery multicast packet evaluated and categorized as benign baseline activity.", "confidence": "INFORMATIONAL"},
                        ],
                        limitations=[],
                        status="Resolved",
                        analyst_notes="Benign UPnP discovery broadcast on local subnet.",
                        response_action="None",
                        occurrence_count=4,
                        is_synthetic=False,
                    ),
                    IncidentRecord(
                        incident_id="INC-WARP-TUNNEL",
                        created_at=(now - datetime.timedelta(hours=8)).isoformat(),
                        last_seen=(now - datetime.timedelta(minutes=2)).isoformat(),
                        src_ip="10.237.120.166",
                        dst_ip="162.159.192.10",
                        src_port=53210,
                        dst_port=2408,
                        proto="udp",
                        severity="LOW",
                        detection_source="model",
                        raw_score=0.327,
                        model_name="xshield_tqh_c2_port_excluded",
                        evidence=[
                            {"indicator": "ENCRYPTED_TUNNEL_BASELINE", "description": "WireGuard / Cloudflare WARP transport stream. High packet volume with benign entropy distribution.", "confidence": "LOW"},
                        ],
                        limitations=[],
                        status="Resolved",
                        analyst_notes="Verified authorized user VPN tunnel.",
                        response_action="None",
                        occurrence_count=4034,
                        is_synthetic=False,
                    ),
                ]
                for rec in samples:
                    self.save_incident(rec)
                return len(samples)
            finally:
                conn.close()

    def export_incidents_csv(self, anonymize_internal: bool = False) -> str:
        """Exports stored incidents to CSV using sanitized schema and optional IP anonymization."""
        import pandas as pd
        incidents = self.list_incidents(limit=10000)
        sanitized = sanitize_incident_export(incidents, anonymize_internal=anonymize_internal)
        if not sanitized:
            return "incident_id,created_at,last_seen,src_ip,dst_ip,dst_port,proto,severity,detection_source,raw_score,status,response_action,occurrences,is_synthetic_fixture,analyst_notes\n"
        return pd.DataFrame(sanitized).to_csv(index=False)

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

        # Check is_synthetic if column exists in table
        is_synth = False
        try:
            is_synth = bool(row["is_synthetic"])
        except (IndexError, KeyError):
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
            is_synthetic=is_synth,
        )


def sanitize_incident_export(
    incidents: List[IncidentRecord], anonymize_internal: bool = False
) -> List[Dict[str, Any]]:
    """Sanitizes incident records for threat intelligence sharing or compliance export.

    - Strips control characters from text fields.
    - Anonymizes internal RFC 1918 IPs if requested.
    - Explicitly labels synthetic/replayed demo records.
    """
    sanitized = []
    for inc in incidents:
        src_ip = inc.src_ip
        if anonymize_internal:
            try:
                import ipaddress
                if ipaddress.ip_address(src_ip).is_private:
                    src_ip = "192.168.x.x (internal_host)"
            except Exception:
                pass

        # Strip control characters from notes
        clean_notes = re.sub(r"[\r\n\t\x00-\x1f]", " ", inc.analyst_notes).strip()

        sanitized.append({
            "incident_id": inc.incident_id,
            "created_at": inc.created_at,
            "last_seen": inc.last_seen,
            "src_ip": src_ip,
            "dst_ip": inc.dst_ip,
            "dst_port": inc.dst_port,
            "proto": inc.proto.upper(),
            "severity": inc.severity,
            "detection_source": inc.detection_source,
            "raw_score": inc.raw_score,
            "status": inc.status,
            "response_action": inc.response_action,
            "occurrences": inc.occurrence_count,
            "is_synthetic_fixture": inc.is_synthetic,
            "analyst_notes": clean_notes,
        })
    return sanitized
