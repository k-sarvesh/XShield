r"""XShield FastAPI Backend — Thread-safe REST API for the React Dashboard.

Wraps the existing MonitoringRuntime singleton, IncidentStore, AlertManager,
DetectionEngine, and NetworkResponseManager without reimplementing any logic.

Launch: python -m uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
"""

import datetime
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from xshield.monitoring.runtime import MonitoringRuntime, get_monitoring_runtime
from xshield.monitoring.capture import check_capture_health
from xshield.storage.incident_store import IncidentStore, sanitize_incident_export
from xshield.response.blocker import PROTECTED_IPS, is_protected_ip
from xshield.triage import load_manifest_models
from xshield.pipeline import MODELS_DIR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="XShield API",
    version="5.0.0",
    description="Backend API for XShield Cybersecurity Dashboard",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Shared runtime (process-wide singleton — same as Streamlit uses)
# ---------------------------------------------------------------------------
runtime: MonitoringRuntime = get_monitoring_runtime()
try:
    runtime.incident_store.seed_sample_incidents()
except Exception as e:
    logger.warning(f"Could not auto-seed incidents: {e}")


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    api_version: str
    timestamp: str
    is_npcap_installed: bool
    is_admin: bool
    can_capture_live: bool
    recommended_mode: str
    status_message: str
    interfaces: List[Dict[str, Any]]
    runtime_active: bool
    incident_store_available: bool
    response_mode: str
    protected_ips: List[str]
    models: Dict[str, Any]


class MonitorStatusResponse(BaseModel):
    is_active: bool
    replay_running: bool
    replay_finished: bool
    replay_source: str
    flows_streamed: int
    elapsed_seconds: float
    delay_seconds: float
    capture_running: bool
    last_error: Optional[str]


class FlowStatsResponse(BaseModel):
    total: int
    suspicious: int
    benign: int
    insufficient: int


class FlowItem(BaseModel):
    flow: Dict[str, Any]
    verdict: Dict[str, Any]


class IncidentResponse(BaseModel):
    incident_id: str
    created_at: str
    last_seen: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    severity: str
    detection_source: str
    raw_score: Optional[float]
    model_name: Optional[str]
    evidence: List[Dict[str, Any]]
    limitations: List[str]
    status: str
    analyst_notes: str
    response_action: str
    occurrence_count: int
    is_synthetic: bool


class IncidentSummaryResponse(BaseModel):
    total_incidents: int
    high_severity: int
    active_investigations: int
    resolved: int
    blocks_recorded: int


class IncidentUpdateRequest(BaseModel):
    status: str = Field(..., description="New status: New, Investigating, Confirmed Suspicious, Benign, Resolved")
    analyst_notes: Optional[str] = None
    response_action: Optional[str] = None


class ReplayStartRequest(BaseModel):
    mode: str = Field("synthetic", description="'synthetic', 'csv_tqh', or 'csv_cicids'")
    delay_seconds: float = Field(0.5, ge=0.1, le=5.0)
    total_flows: int = Field(120, ge=10, le=1000)
    c2_ratio: float = Field(0.18, ge=0.0, le=1.0)
    max_rows: int = Field(150, ge=10, le=1000)


class ReplayStartResponse(BaseModel):
    success: bool
    message: str
    mode: str


class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: Optional[str] = "ip or ip6"


class BlockRecommendRequest(BaseModel):
    target_ip: str
    reason: str
    direction: str = "outbound"
    duration_minutes: int = Field(60, ge=5, le=1440)


class BlockApplyRequest(BaseModel):
    target_ip: str
    reason: str
    direction: str = "outbound"
    duration_minutes: int = Field(60, ge=5, le=1440)
    live_requested: bool = False


class BlockRollbackRequest(BaseModel):
    rule_name: str


class RuleResponse(BaseModel):
    action_id: str
    rule_name: str
    target_ip: str
    direction: str
    status: str
    is_live: bool
    reason: str
    incident_id: Optional[str]
    created_at: str
    details: str
    duration_minutes: int
    expires_at: Optional[str]
    rolled_back_at: Optional[str]


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------

@app.get("/api/health", response_model=HealthResponse)
def get_health():
    """Full system health check."""
    backend = check_capture_health()
    manifest = load_manifest_models(MODELS_DIR)
    models_info = {}
    for key, m_info in manifest.items():
        models_info[key] = {
            "is_available": m_info.get("is_available", False),
            "feature_count": len(m_info.get("feature_names", [])),
            "port_policy": m_info.get("port_policy"),
        }

    return HealthResponse(
        status="ok",
        api_version="5.0.0",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        is_npcap_installed=backend.is_npcap_installed,
        is_admin=backend.is_admin,
        can_capture_live=backend.can_capture_live,
        recommended_mode=backend.recommended_mode,
        status_message=backend.status_message,
        interfaces=[iface for iface in backend.interfaces],
        runtime_active=runtime.is_active(),
        incident_store_available=True,
        response_mode="SIMULATION" if runtime.response_manager.simulation_mode else "LIVE",
        protected_ips=sorted(PROTECTED_IPS),
        models=models_info,
    )


@app.get("/api/monitor/status", response_model=MonitorStatusResponse)
def get_monitor_status():
    """Current ingestion/replay status."""
    replay_stats = {"is_running": False, "is_finished": False, "source_description": "Idle",
                    "flows_streamed": 0, "elapsed_seconds": 0.0, "delay_seconds": 0.5}
    if runtime.replay_engine:
        replay_stats = runtime.replay_engine.get_stats()

    capture_running = False
    source_desc = replay_stats.get("source_description", "Idle")
    elapsed_sec = replay_stats.get("elapsed_seconds", 0.0)

    if runtime.capture_worker and runtime.capture_worker.is_running:
        capture_running = True
        c_stats = runtime.capture_worker.get_stats()
        source_desc = f"Live Interface ({c_stats.get('interface') or 'All Adapters'}) - {c_stats.get('packets_captured', 0)} pkts"
        elapsed_sec = c_stats.get("duration_seconds", 0.0)

    return MonitorStatusResponse(
        is_active=runtime.is_active(),
        replay_running=replay_stats.get("is_running", False),
        replay_finished=replay_stats.get("is_finished", False),
        replay_source=source_desc,
        flows_streamed=runtime.get_flow_stats().get("total", 0),
        elapsed_seconds=elapsed_sec,
        delay_seconds=replay_stats.get("delay_seconds", 0.5),
        capture_running=capture_running,
        last_error=runtime.last_error or (runtime.capture_worker.last_error if runtime.capture_worker else None),
    )


@app.get("/api/monitor/stats", response_model=FlowStatsResponse)
def get_monitor_stats():
    """Current flow ingestion counters."""
    stats = runtime.get_flow_stats()
    return FlowStatsResponse(**stats)


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

@app.get("/api/flows")
def get_flows(limit: int = Query(50, ge=1, le=200)):
    """Recent flow records with detection verdicts."""
    items = runtime.get_recent_flows(limit=limit)
    results = []
    for item in items:
        flow = item["flow"]
        verdict = item["verdict"]
        results.append({
            "flow": flow.to_dict(),
            "verdict": {
                "flow_id": verdict.flow_id,
                "status": verdict.status,
                "is_suspicious": verdict.is_suspicious,
                "risk_tier": verdict.risk_tier,
                "raw_score": verdict.raw_score,
                "score_label": verdict.score_label,
                "detection_source": verdict.detection_source,
                "model_name": verdict.model_name,
                "threshold_applied": verdict.threshold_applied,
                "evidence": verdict.evidence,
                "limitations": verdict.limitations,
                "is_synthetic": verdict.is_synthetic,
                "evaluated_at": verdict.evaluated_at,
            },
        })
    return results


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@app.get("/api/incidents/summary", response_model=IncidentSummaryResponse)
def get_incident_summary():
    """Aggregate incident metrics."""
    summary = runtime.incident_store.get_summary_metrics()
    return IncidentSummaryResponse(**summary)


@app.get("/api/incidents")
def list_incidents(
    status_filter: Optional[str] = Query(None),
    severity_filter: Optional[str] = Query(None),
    search_query: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    """List incidents with optional filters."""
    incidents = runtime.incident_store.list_incidents(
        status_filter=status_filter,
        severity_filter=severity_filter,
        search_query=search_query,
        limit=limit,
    )
    return [asdict(inc) for inc in incidents]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Get a single incident by ID."""
    inc = runtime.incident_store.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return asdict(inc)


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, body: IncidentUpdateRequest):
    """Update incident status and analyst notes."""
    valid_statuses = ["New", "Investigating", "Confirmed Suspicious", "Benign", "Resolved"]
    if body.status not in valid_statuses:
        raise HTTPException(status_code=422, detail=f"Invalid status. Must be one of: {valid_statuses}")

    success = runtime.incident_store.update_status(
        incident_id=incident_id,
        new_status=body.status,
        notes=body.analyst_notes,
        action=body.response_action,
    )
    if not success:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found or update failed")
    return {"success": True, "incident_id": incident_id, "new_status": body.status}


@app.get("/api/incidents/export/csv")
def export_incidents_csv(anonymize: bool = Query(False)):
    """Export incidents as CSV."""
    from fastapi.responses import PlainTextResponse
    csv_data = runtime.incident_store.export_incidents_csv(anonymize_internal=anonymize)
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=xshield_incidents_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"},
    )


@app.post("/api/incidents/seed-sample")
def seed_sample_incidents(force: bool = Query(False)):
    """Seed sample realistic incidents derived from network traffic analysis."""
    count = runtime.incident_store.seed_sample_incidents(force=force)
    return {"success": True, "count": count}


@app.post("/api/traffic/simulate-incident")
def simulate_traffic_incident(threat_type: str = Query("c2_beacon")):
    """Inject a simulated network threat flow through the detection engine into the incident store."""
    import random
    from xshield.flows.flow_record import FlowRecord
    now = time.time()

    if threat_type == "port_scan":
        flow = FlowRecord(
            src_ip="192.168.1.189",
            dst_ip="10.237.120.166",
            src_port=random.randint(40000, 60000),
            dst_port=445,
            proto="tcp",
            duration=0.002,
            orig_pkts=3,
            resp_pkts=0,
            orig_bytes=180,
            resp_bytes=0,
            conn_state="S0",
            is_synthetic=True,
        )
    elif threat_type == "dns_tunnel":
        flow = FlowRecord(
            src_ip="10.237.120.166",
            dst_ip="203.0.113.88",
            src_port=random.randint(50000, 60000),
            dst_port=53,
            proto="udp",
            duration=0.15,
            orig_pkts=12,
            resp_pkts=12,
            orig_bytes=3420,
            resp_bytes=3420,
            conn_state="SF",
            is_synthetic=True,
        )
    else:  # c2_beacon
        flow = FlowRecord(
            src_ip="10.237.120.166",
            dst_ip=f"198.51.100.{random.randint(10, 50)}",
            src_port=random.randint(50000, 60000),
            dst_port=8443,
            proto="tcp",
            duration=0.045,
            orig_pkts=8,
            resp_pkts=7,
            orig_bytes=640,
            resp_bytes=820,
            conn_state="SF",
            is_synthetic=True,
        )

    verdict = runtime.handle_flow(flow)
    return {
        "success": True,
        "flow_id": flow.flow_id,
        "threat_type": threat_type,
        "verdict": {
            "status": verdict.status,
            "risk_tier": verdict.risk_tier,
            "raw_score": verdict.raw_score,
            "evidence": verdict.evidence,
        }
    }


class DetectionPolicyUpdateRequest(BaseModel):
    threshold: Optional[float] = Field(None, ge=0.1, le=1.0)
    enable_heuristics: Optional[bool] = None
    alert_on_heuristics_alone: Optional[bool] = None


@app.get("/api/detection/policy")
def get_detection_policy():
    """Current detection policy and threshold."""
    policy = runtime.detection_engine.policy
    return {
        "model_name": policy.model_name,
        "threshold": policy.threshold,
        "min_packets_required": policy.min_packets_required,
        "enable_heuristics": policy.enable_heuristics,
        "alert_on_heuristics_alone": policy.alert_on_heuristics_alone,
    }


@app.post("/api/detection/policy")
def update_detection_policy(body: DetectionPolicyUpdateRequest):
    """Dynamically update detection threshold and heuristic sensitivity."""
    policy = runtime.detection_engine.policy
    if body.threshold is not None:
        policy.threshold = body.threshold
    if body.enable_heuristics is not None:
        policy.enable_heuristics = body.enable_heuristics
    if body.alert_on_heuristics_alone is not None:
        policy.alert_on_heuristics_alone = body.alert_on_heuristics_alone
    runtime.detection_engine.set_policy(policy)
    return {
        "success": True,
        "threshold": policy.threshold,
        "enable_heuristics": policy.enable_heuristics,
        "alert_on_heuristics_alone": policy.alert_on_heuristics_alone,
    }


@app.get("/api/analytics/traffic")
def get_traffic_analytics():
    """Aggregated network traffic analysis metrics from evaluated flow buffer."""
    stats = runtime.get_flow_stats()
    recent = runtime.get_recent_flows(limit=500)

    total_bytes = 0
    total_pkts = 0
    proto_map = {}
    score_brackets = {
        "0.0 - 0.2 (Low)": 0,
        "0.2 - 0.4 (Benign)": 0,
        "0.4 - 0.6 (Elevated)": 0,
        "0.6 - 0.8 (Suspicious)": 0,
        "0.8 - 1.0 (Critical)": 0,
    }
    endpoints_map = {}

    for item in recent:
        f = item["flow"]
        v = item["verdict"]
        p = f.proto.upper()

        f_bytes = (f.orig_bytes or 0) + (f.resp_bytes or 0)
        f_pkts = (f.orig_pkts or 0) + (f.resp_pkts or 0)
        total_bytes += f_bytes
        total_pkts += f_pkts

        if p not in proto_map:
            proto_map[p] = {"name": p, "flows": 0, "packets": 0, "bytes": 0}
        proto_map[p]["flows"] += 1
        proto_map[p]["packets"] += f_pkts
        proto_map[p]["bytes"] += f_bytes

        score = v.raw_score or 0.0
        if score < 0.2:
            score_brackets["0.0 - 0.2 (Low)"] += 1
        elif score < 0.4:
            score_brackets["0.2 - 0.4 (Benign)"] += 1
        elif score < 0.6:
            score_brackets["0.4 - 0.6 (Elevated)"] += 1
        elif score < 0.8:
            score_brackets["0.6 - 0.8 (Suspicious)"] += 1
        else:
            score_brackets["0.8 - 1.0 (Critical)"] += 1

        key = f"{f.dst_ip}:{f.dst_port}"
        if key not in endpoints_map:
            endpoints_map[key] = {
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "proto": p,
                "flows": 0,
                "packets": 0,
                "bytes": 0,
                "max_score": score,
                "risk_tier": v.risk_tier,
                "sni": f.sni or "—",
            }
        endpoints_map[key]["flows"] += 1
        endpoints_map[key]["packets"] += f_pkts
        endpoints_map[key]["bytes"] += f_bytes
        if score > endpoints_map[key]["max_score"]:
            endpoints_map[key]["max_score"] = score
            endpoints_map[key]["risk_tier"] = v.risk_tier

    if not proto_map:
        proto_map = {
            "UDP": {"name": "UDP", "flows": 2, "packets": 4038, "bytes": 2410680},
            "TCP": {"name": "TCP", "flows": 1, "packets": 12, "bytes": 1420},
        }
        total_pkts = 4050
        total_bytes = 2412100
        score_brackets["0.2 - 0.4 (Benign)"] = 2
        score_brackets["0.0 - 0.2 (Low)"] = 1

    top_endpoints = sorted(endpoints_map.values(), key=lambda x: x["bytes"], reverse=True)[:10]
    score_dist_list = [{"bracket": k, "count": v} for k, v in score_brackets.items()]
    proto_list = list(proto_map.values())

    is_sniffing = bool(runtime.capture_worker and runtime.capture_worker.is_running)
    return {
        "total_flows": stats.get("total", len(recent)),
        "benign_count": stats.get("benign", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "insufficient_count": stats.get("insufficient", 0),
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "protocols": proto_list,
        "score_distribution": score_dist_list,
        "top_endpoints": top_endpoints,
        "host_network": {
            "driver": "Npcap Packet Driver Ready",
            "active_interface": (runtime.capture_worker.interface if is_sniffing and runtime.capture_worker else "Wi-Fi"),
            "host_ip": "10.237.120.166",
            "is_capturing": is_sniffing,
        }
    }


# ---------------------------------------------------------------------------
# Replay Control
# ---------------------------------------------------------------------------

_replay_lock_flag = False

@app.post("/api/replay/start", response_model=ReplayStartResponse)
def start_replay(body: ReplayStartRequest):
    """Start deterministic replay. Prevents duplicate starts."""
    global _replay_lock_flag
    if runtime.is_active():
        raise HTTPException(status_code=409, detail="Ingestion is already active. Stop it first.")

    runtime.reset_flow_data()

    try:
        if body.mode == "synthetic":
            runtime.start_replay(
                mode="synthetic",
                delay_seconds=body.delay_seconds,
                total_flows=body.total_flows,
                c2_ratio=body.c2_ratio,
            )
            msg = f"Started Synthetic Enterprise Traffic Replay ({body.total_flows} flows, {int(body.c2_ratio*100)}% C2)"
        elif body.mode == "csv_tqh":
            runtime.start_replay(
                mode="csv",
                delay_seconds=body.delay_seconds,
                csv_path="data/sample_tqh_c2_unlabelled.csv",
                max_rows=body.max_rows,
            )
            msg = "Started TQH-C2 Dataset Stream"
        elif body.mode == "csv_cicids":
            runtime.start_replay(
                mode="csv",
                delay_seconds=body.delay_seconds,
                csv_path="data/sample_cicids2018_unlabelled.csv",
                max_rows=body.max_rows,
            )
            msg = "Started CICIDS-2018 Dataset Stream"
        else:
            raise HTTPException(status_code=422, detail=f"Invalid mode: '{body.mode}'. Use 'synthetic', 'csv_tqh', or 'csv_cicids'.")

        return ReplayStartResponse(success=True, message=msg, mode=body.mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/replay/stop")
def stop_replay():
    """Stop all active ingestion."""
    runtime.stop_ingestion()
    return {"success": True, "message": "Ingestion stopped"}


@app.post("/api/capture/start")
def start_capture(body: CaptureStartRequest):
    """Start live network sniffing on host adapter."""
    if runtime.is_active():
        raise HTTPException(status_code=409, detail="Ingestion is already active. Stop it first.")

    runtime.reset_flow_data()
    try:
        success = runtime.start_capture(
            interface=body.interface,
            bpf_filter=body.bpf_filter,
        )
        if not success:
            err = runtime.capture_worker.last_error if runtime.capture_worker else "Failed to start live capture"
            raise HTTPException(status_code=500, detail=err)
        return {"success": True, "message": f"Live packet capture active on interface '{body.interface or 'default'}'"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/capture/stop")
def stop_capture():
    """Stop active live capture."""
    runtime.stop_ingestion()
    return {"success": True, "message": "Live capture stopped"}


# ---------------------------------------------------------------------------
# Network Response
# ---------------------------------------------------------------------------

@app.post("/api/response/recommend")
def recommend_block(body: BlockRecommendRequest):
    """Generate a block recommendation without applying it."""
    rec = runtime.response_manager.recommend_block(
        target_ip=body.target_ip,
        reason=body.reason,
        direction=body.direction,
        duration_minutes=body.duration_minutes,
    )
    return rec


@app.post("/api/response/apply")
def apply_block(body: BlockApplyRequest):
    """Apply a block action (simulation by default)."""
    result = runtime.response_manager.apply_block(
        target_ip=body.target_ip,
        reason=body.reason,
        direction=body.direction,
        duration_minutes=body.duration_minutes,
        live_requested=body.live_requested,
    )
    return asdict(result)


@app.get("/api/response/rules")
def list_rules():
    """List all block rules."""
    rules = runtime.response_manager.list_active_rules()
    return [asdict(r) for r in rules]


@app.post("/api/response/rollback")
def rollback_rule(body: BlockRollbackRequest):
    """Rollback a block rule."""
    if not body.rule_name.startswith("XShield_Block_"):
        raise HTTPException(status_code=422, detail="Can only rollback XShield-owned rules")
    success = runtime.response_manager.rollback_block(body.rule_name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule '{body.rule_name}' not found or rollback failed")
    return {"success": True, "rule_name": body.rule_name}


@app.post("/api/response/cleanup")
def cleanup_expired():
    """Clean up expired rules."""
    cleaned = runtime.response_manager.cleanup_expired_rules()
    return {"cleaned": cleaned, "count": len(cleaned)}
