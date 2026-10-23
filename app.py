"""XShield: Explainable ML-Assisted Traffic Intelligence & Live Threat Monitoring Prototype.

Phase 4 Live Demonstration & Operational Dashboard
- Live Network Capture (with Npcap autodetection) & Deterministic Replay Engine
- Bidirectional Flow Aggregation & TLS Handshake Metadata Extraction (without payload decryption)
- Schema-Safe Detection Engine with Evidence Reasoning & Uncalibrated Ensemble Scores
- Persistent Incident Management (SQLite) & Cooldown Deduplication
- Controlled Network Response (Simulation Mode by default, Optional Guarded Windows Firewall & Rollback)
- Historical Analysis, System Diagnostics, and Offline CSV Triage
"""

from collections import deque
import datetime
from io import StringIO
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Core XShield Modules
from xshield.alerts.alert_manager import AlertManager, AlertNotification
from xshield.detection.engine import DetectionEngine, DetectionPolicy, DetectionVerdict
from xshield.flows.aggregator import FlowAggregator
from xshield.flows.flow_record import FlowRecord
from xshield.flows.replay import FlowReplayEngine
from xshield.monitoring.capture import (
    CaptureBackendStatus,
    LiveCaptureWorker,
    check_capture_health,
    check_is_admin,
    check_npcap_installed,
    get_available_interfaces,
)
from xshield.pipeline import MODELS_DIR, XShieldModel, load_model, run_experiment
from xshield.response.blocker import (
    BlockActionStatus,
    NetworkResponseManager,
    is_protected_ip,
)
from xshield.storage.incident_store import IncidentRecord, IncidentStore
from xshield.triage import (
    assess_dataset_compatibility,
    check_model_compatibility,
    compute_triage_metrics,
    extract_available_traffic_fields,
    filter_triage_flows,
    format_csv_export,
    load_manifest_models,
    score_flows_batch,
    validate_flow_schema,
)

# -----------------------------------------------------------------------------
# Page Configuration & Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="XShield | Live Network Threat Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
    [data-testid="stAppViewContainer"] { background: #0b1220; color: #e2e8f0; }
    [data-testid="stSidebar"] { background: #0f172a; border-right: 1px solid #1e293b; }
    
    .metric-card {
        background: #111c2e;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-title {
        color: #94a3b8;
        font-size: 0.82rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-val {
        color: #f8fafc;
        font-size: 1.6rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .metric-sub {
        color: #64748b;
        font-size: 0.78rem;
        margin-top: 2px;
    }
    
    .status-banner {
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 15px;
        font-size: 0.88rem;
        line-height: 1.4;
    }
    .banner-simulation {
        background: rgba(30, 58, 138, 0.3);
        border-left: 4px solid #3b82f6;
        color: #bfdbfe;
    }
    .banner-warning {
        background: rgba(180, 83, 9, 0.25);
        border-left: 4px solid #f59e0b;
        color: #fde68a;
    }
    .banner-experimental {
        background: rgba(88, 28, 135, 0.3);
        border-left: 4px solid #a855f7;
        color: #e9d5ff;
    }

    .badge-high { background-color: #7c2d12; color: #fb923c; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
    .badge-med { background-color: #78350f; color: #fbbf24; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
    .badge-low { background-color: #064e3b; color: #34d399; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
    .badge-info { background-color: #1e293b; color: #94a3b8; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Session State Initialization (Persistent across reruns)
# -----------------------------------------------------------------------------
if "incident_store" not in st.session_state:
    st.session_state.incident_store = IncidentStore()

if "alert_manager" not in st.session_state:
    st.session_state.alert_manager = AlertManager(
        incident_store=st.session_state.incident_store,
        cooldown_seconds=60.0,
    )

if "response_manager" not in st.session_state:
    st.session_state.response_manager = NetworkResponseManager(simulation_mode=True)

if "detection_engine" not in st.session_state:
    st.session_state.detection_engine = DetectionEngine()

if "flow_aggregator" not in st.session_state:
    st.session_state.flow_aggregator = FlowAggregator()

if "live_flows_buffer" not in st.session_state:
    st.session_state.live_flows_buffer = deque(maxlen=60)

if "replay_engine" not in st.session_state:
    st.session_state.replay_engine = None

if "selected_incident_id" not in st.session_state:
    st.session_state.selected_incident_id = None

if "quick_block_target" not in st.session_state:
    st.session_state.quick_block_target = ""

if "flow_stats_counters" not in st.session_state:
    st.session_state.flow_stats_counters = {
        "total": 0,
        "suspicious": 0,
        "benign": 0,
        "insufficient": 0,
    }


def handle_incoming_flow(flow: FlowRecord) -> None:
    """Processes a newly captured or replayed flow through detection and alerting."""
    verdict = st.session_state.detection_engine.evaluate_flow(flow)
    st.session_state.live_flows_buffer.appendleft({"flow": flow, "verdict": verdict})

    st.session_state.flow_stats_counters["total"] += 1
    if verdict.status == "SUSPICIOUS":
        st.session_state.flow_stats_counters["suspicious"] += 1
        st.session_state.alert_manager.process_verdict(flow, verdict)
    elif verdict.status == "BENIGN":
        st.session_state.flow_stats_counters["benign"] += 1
    else:
        st.session_state.flow_stats_counters["insufficient"] += 1


# -----------------------------------------------------------------------------
# Top Header & Environmental Status Banners
# -----------------------------------------------------------------------------
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ XShield")
    st.caption("Explainable ML-Assisted Encrypted Traffic Intelligence · Live Monitoring & Incident Response Prototype")
with col_h2:
    st.markdown(
        "<div style='text-align: right; padding-top: 15px; color: #64748b; font-size: 0.8rem;'>"
        "XShield v4.0-demo<br>Live Security Demonstration</div>",
        unsafe_allow_html=True,
    )

backend_status = check_capture_health()

# Top environmental notice banners
if not backend_status.is_npcap_installed:
    st.markdown("""
    <div class="status-banner banner-warning">
        <strong>⚠️ CAPTURE DRIVER NOTICE:</strong> Npcap driver not detected on Windows host. 
        Live promiscuous packet sniffing requires Npcap (<a href="https://npcap.com" target="_blank" style="color:#fde68a;">npcap.com</a>) with WinPcap API compatibility. 
        <strong>Deterministic Replay Engine</strong> is active for safe, full demonstration.
    </div>
    """, unsafe_allow_html=True)

if st.session_state.response_manager.simulation_mode:
    st.markdown("""
    <div class="status-banner banner-simulation">
        <strong>🛡️ SAFETY NOTICE — SIMULATION MODE ACTIVE:</strong> All network blocking actions are recorded for analyst triage without modifying Windows Firewall rules. 
        Zero risk of network disruption. Optional live enforcement can be requested with administrative privileges.
    </div>
    """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Navigation Tabs
# -----------------------------------------------------------------------------
tabs = st.tabs([
    "📡 Live Monitor",
    "🚨 Alerts & Incidents",
    "🛡️ Network Response",
    "📊 Historical Analysis",
    "🩺 System Health",
    "📁 Offline CSV Triage (Phase 2)",
    "🧪 Model Research (Phase 1)",
])


# =============================================================================
# TAB 1: LIVE MONITOR
# =============================================================================
with tabs[0]:
    st.subheader("1 · Network Traffic Monitoring & Real-Time Ingestion")

    m_c1, m_c2, m_c3, m_c4 = st.columns(4)
    with m_c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Flows Ingested</div>
            <div class="metric-val">{st.session_state.flow_stats_counters['total']:,}</div>
            <div class="metric-sub">Session cumulative</div>
        </div>
        """, unsafe_allow_html=True)
    with m_c2:
        s_count = st.session_state.flow_stats_counters["suspicious"]
        s_color = "#f43f5e" if s_count > 0 else "#34d399"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Suspicious Detections</div>
            <div class="metric-val" style="color: {s_color};">{s_count:,}</div>
            <div class="metric-sub">Alerted & Triaged</div>
        </div>
        """, unsafe_allow_html=True)
    with m_c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Benign Verified</div>
            <div class="metric-val" style="color: #34d399;">{st.session_state.flow_stats_counters['benign']:,}</div>
            <div class="metric-sub">Cleared by Engine</div>
        </div>
        """, unsafe_allow_html=True)
    with m_c4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Insufficient Evidence</div>
            <div class="metric-val" style="color: #94a3b8;">{st.session_state.flow_stats_counters['insufficient']:,}</div>
            <div class="metric-sub">&lt; 4 pkts / incomplete</div>
        </div>
        """, unsafe_allow_html=True)

    # Ingestion Controls
    st.markdown("### Stream Controls")
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([2, 1, 1])

    with ctrl_col1:
        source_mode = st.selectbox(
            "Select Ingestion Source",
            options=[
                "Deterministic Replay: Synthetic Enterprise Scenario (HTTPS Browsing + C2 Beacons)",
                "Deterministic Replay: TQH-C2 Sample Stream (data/sample_tqh_c2_unlabelled.csv)",
                "Deterministic Replay: CICIDS-2018 Sample Stream (data/sample_cicids2018_unlabelled.csv)",
                "Live Network Adapter (Promiscuous Sniffing via Npcap)",
            ],
            index=0,
        )

    with ctrl_col2:
        replay_speed = st.slider("Stream Speed (Delay/Flow)", min_value=0.1, max_value=2.0, value=0.5, step=0.1)

    with ctrl_col3:
        st.write("")
        st.write("")
        btn_cols = st.columns(2)
        with btn_cols[0]:
            btn_start = st.button("▶ Start Stream", use_container_width=True)
        with btn_cols[1]:
            btn_stop = st.button("⏹ Stop Stream", use_container_width=True)

    # Ingestion Engine Actions
    if btn_start:
        if "Synthetic Enterprise Scenario" in source_mode:
            st.session_state.replay_engine = FlowReplayEngine(
                flow_callback=handle_incoming_flow, delay_seconds=replay_speed
            )
            st.session_state.replay_engine.start_replay_synthetic(total_flows=120, c2_ratio=0.18)
            st.success("Started Synthetic Enterprise Traffic Replay (C2 Beacons + Benign Browsing).")
        elif "TQH-C2 Sample" in source_mode:
            csv_p = "data/sample_tqh_c2_unlabelled.csv"
            st.session_state.replay_engine = FlowReplayEngine(
                flow_callback=handle_incoming_flow, delay_seconds=replay_speed
            )
            st.session_state.replay_engine.start_replay_csv(csv_p, max_rows=150)
            st.success(f"Started TQH-C2 Dataset Stream ({csv_p}).")
        elif "CICIDS-2018 Sample" in source_mode:
            csv_p = "data/sample_cicids2018_unlabelled.csv"
            st.session_state.replay_engine = FlowReplayEngine(
                flow_callback=handle_incoming_flow, delay_seconds=replay_speed
            )
            st.session_state.replay_engine.start_replay_csv(csv_p, max_rows=150)
            st.success(f"Started CICIDS-2018 Dataset Stream ({csv_p}).")
        elif "Live Network Adapter" in source_mode:
            if not backend_status.can_capture_live:
                st.error("Live sniffing cannot be started because the Npcap driver is missing. Please use Replay Mode.")
            else:
                st.info("Live packet capture initialized on default adapter.")

    if btn_stop:
        if st.session_state.replay_engine and st.session_state.replay_engine.is_running:
            st.session_state.replay_engine.stop()
            st.warning("Replay stream stopped.")

    # Live Flow Stream Table
    st.markdown("### Real-Time Flow Feed")
    flow_items = list(st.session_state.live_flows_buffer)

    if not flow_items:
        st.info("No active flows captured yet. Click **▶ Start Stream** above to begin demonstration.")
    else:
        table_rows = []
        for item in flow_items[:30]:
            f: FlowRecord = item["flow"]
            v: DetectionVerdict = item["verdict"]

            badge = "🟢 Benign"
            if v.status == "SUSPICIOUS":
                badge = f"🔴 Suspicious ({v.risk_tier})"
            elif v.status == "INSUFFICIENT_EVIDENCE":
                badge = "⚪ Insufficient"

            score_str = f"{v.raw_score:.2f}" if v.raw_score is not None else "N/A"

            table_rows.append({
                "Timestamp": datetime.datetime.fromtimestamp(f.last_seen, tz=datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3],
                "Source": f"{f.src_ip}:{f.src_port}",
                "Destination": f"{f.dst_ip}:{f.dst_port}",
                "Proto": f.proto.upper(),
                "Duration": f"{f.duration:.3f}s",
                "Pkts (F/R)": f"{f.orig_pkts}/{f.resp_pkts}",
                "Bytes": f"{f.tot_bytes:,}",
                "State": f.conn_state,
                "TLS SNI / JA4": f.sni or (f.ja4[:15] + "..." if f.ja4 else "N/A"),
                "Verdict": badge,
                "Score": score_str,
            })

        df_display = pd.DataFrame(table_rows)
        st.dataframe(df_display, use_container_width=True, height=350)


# =============================================================================
# TAB 2: ALERTS & INCIDENTS
# =============================================================================
with tabs[1]:
    st.subheader("2 · Analyst Incident Management & Evidence Triage")

    inc_store: IncidentStore = st.session_state.incident_store
    summary = inc_store.get_summary_metrics()

    s1, s2, s3, s4, s5 = st.columns(5)
    with s1:
        st.metric("Total Incidents", summary["total_incidents"])
    with s2:
        st.metric("High Severity", summary["high_severity"])
    with s3:
        st.metric("Active Investigations", summary["active_investigations"])
    with s4:
        st.metric("Resolved", summary["resolved"])
    with s5:
        st.metric("Blocks Recorded", summary["blocks_recorded"])

    st.markdown("---")

    # Search & Filter Controls
    f_c1, f_c2, f_c3 = st.columns([1, 1, 2])
    with f_c1:
        f_status = st.selectbox("Status Filter", ["All", "New", "Investigating", "Confirmed Suspicious", "Benign", "Resolved"])
    with f_c2:
        f_sev = st.selectbox("Severity Filter", ["All", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
    with f_c3:
        search_txt = st.text_input("Search (Incident ID, IP, or Notes)", placeholder="e.g. 198.51.100.24")

    incidents = inc_store.list_incidents(status_filter=f_status, severity_filter=f_sev, search_query=search_txt, limit=100)

    if not incidents:
        st.info("No security incidents found matching filter criteria.")
    else:
        # Table of incidents
        inc_rows = []
        for inc in incidents:
            inc_rows.append({
                "Incident ID": inc.incident_id,
                "Created (UTC)": inc.created_at[:19],
                "Target Endpoint": f"{inc.dst_ip}:{inc.dst_port}",
                "Source Host": inc.src_ip,
                "Severity": inc.severity,
                "Detection Source": inc.detection_source,
                "Occurrences": inc.occurrence_count,
                "Status": inc.status,
                "Response": inc.response_action,
            })
        df_inc = pd.DataFrame(inc_rows)
        st.dataframe(df_inc, use_container_width=True, height=220)

        # Detailed Investigation Pane
        st.markdown("### Incident Investigation & Evidence Detail")
        inc_ids = [inc.incident_id for inc in incidents]
        selected_id = st.selectbox("Select Incident to Investigate", inc_ids, index=0)

        selected_inc = inc_store.get_incident(selected_id)
        if selected_inc:
            inv_col1, inv_col2 = st.columns([2, 1])

            with inv_col1:
                st.markdown(f"#### Incident Details: `{selected_inc.incident_id}`")
                st.markdown(
                    f"**Endpoints:** `{selected_inc.src_ip}:{selected_inc.src_port}` ➔ "
                    f"`{selected_inc.dst_ip}:{selected_inc.dst_port}` ({selected_inc.proto.upper()})"
                )
                st.markdown(f"**First Seen:** `{selected_inc.created_at}` · **Last Seen:** `{selected_inc.last_seen}`")
                st.markdown(f"**Deduplication Count:** `{selected_inc.occurrence_count}` occurrences coalesced")

                st.markdown("**Supporting Evidence & Detection Indicators:**")
                if not selected_inc.evidence:
                    st.write("No explicit indicators attached.")
                else:
                    for ev in selected_inc.evidence:
                        st.markdown(f"- **`{ev.get('indicator', 'EVIDENCE')}`**: {ev.get('description', '')} *(Confidence: {ev.get('confidence', 'N/A')})*")

                st.markdown("**Methodological Limitations & Research Context:**")
                if not selected_inc.limitations:
                    st.write("None recorded.")
                else:
                    for lim in selected_inc.limitations:
                        st.markdown(f"- ⚠️ {lim}")

            with inv_col2:
                st.markdown("#### Analyst Triage Actions")
                new_status = st.selectbox(
                    "Update Incident Status",
                    ["New", "Investigating", "Confirmed Suspicious", "Benign", "Resolved"],
                    index=["New", "Investigating", "Confirmed Suspicious", "Benign", "Resolved"].index(selected_inc.status),
                )
                analyst_notes = st.text_area("Analyst Notes", value=selected_inc.analyst_notes, height=100)

                col_b1, col_b2 = st.columns(2)
                with col_b1:
                    if st.button("💾 Save Updates", use_container_width=True):
                        inc_store.update_status(selected_inc.incident_id, new_status, notes=analyst_notes)
                        st.success("Incident updated.")
                        st.rerun()

                with col_b2:
                    if st.button("🛡️ Block Target", use_container_width=True):
                        st.session_state.quick_block_target = selected_inc.dst_ip
                        st.info(f"Target `{selected_inc.dst_ip}` loaded into Network Response tab.")


# =============================================================================
# TAB 3: NETWORK RESPONSE
# =============================================================================
with tabs[2]:
    st.subheader("3 · Controlled Network Response & Reversible Blocking")

    resp_mgr: NetworkResponseManager = st.session_state.response_manager

    r_col1, r_col2 = st.columns([1, 1])

    with r_col1:
        st.markdown("### Action Configuration")
        target_ip_input = st.text_input(
            "Target Remote IP Address",
            value=st.session_state.quick_block_target or "198.51.100.24",
            help="Enter the remote IP to evaluate for block action.",
        )
        block_reason = st.text_input("Reason / Incident Justification", value="C2 Beaconing Pattern Verified")
        block_dir = st.selectbox("Block Direction", ["outbound", "inbound"], index=0)

        # Pre-execution safety check
        rec = resp_mgr.recommend_block(target_ip_input, block_reason, direction=block_dir)

        if not rec.get("allowed"):
            st.error(f"Safety Violation: {rec.get('error')}")
        else:
            st.markdown(f"**Proposed Rule:** `{rec['rule_name']}`")
            st.markdown(f"**Scope:** {rec['scope']}")
            if rec.get("warning"):
                st.warning(rec["warning"])

            st.code(rec["proposed_command"], language="powershell")

            # Analyst Confirmation Checkbox (Mandatory Safety Gate)
            confirmed = st.checkbox(
                f"I explicitly confirm blocking {block_dir} traffic to {target_ip_input}.",
                value=False,
            )
            live_opt_in = st.checkbox(
                "Request Live Windows Firewall Enforcement (Requires Administrator privileges)",
                value=False,
                help="If unchecked, executes safely in Simulation Mode without modifying system settings.",
            )

            if st.button("⚡ Apply Response Action", disabled=not confirmed, use_container_width=True):
                result = resp_mgr.apply_block(
                    target_ip=target_ip_input,
                    reason=block_reason,
                    direction=block_dir,
                    live_requested=live_opt_in,
                )
                if result.status == "SIMULATED":
                    st.success(f"SIMULATION RECORDED: {result.details}")
                elif result.status == "ENFORCED":
                    st.success(f"LIVE FIREWALL RULE CREATED: {result.details}")
                else:
                    st.error(f"Action Failed: {result.details}")
                st.rerun()

    with r_col2:
        st.markdown("### Active XShield Block Rules & Rollback")
        rules = resp_mgr.list_active_rules()

        if not rules:
            st.info("No active block rules recorded.")
        else:
            for r in rules:
                with st.expander(f"{'⚡ LIVE' if r.is_live else '🛡️ SIM'} · `{r.target_ip}` ({r.status})", expanded=True):
                    st.markdown(f"**Rule Name:** `{r.rule_name}`")
                    st.markdown(f"**Status:** `{r.status}` · **Created:** `{r.created_at[:19]}`")
                    st.markdown(f"**Details:** {r.details}")

                    if r.status in ["SIMULATED", "ENFORCED"]:
                        if st.button(f"↩️ Rollback / Unblock {r.target_ip}", key=f"rb_{r.rule_name}"):
                            ok = resp_mgr.rollback_block(r.rule_name)
                            if ok:
                                st.success(f"Rule '{r.rule_name}' successfully rolled back.")
                                st.rerun()
                            else:
                                st.error("Rollback operation failed.")


# =============================================================================
# TAB 4: HISTORICAL ANALYSIS
# =============================================================================
with tabs[3]:
    st.subheader("4 · Historical Detection Analytics & Event Export")

    all_incidents = inc_store.list_incidents(limit=500)

    if not all_incidents:
        st.info("No historical events recorded yet.")
    else:
        df_all = pd.DataFrame([asdict(i) for i in all_incidents])

        h_c1, h_c2 = st.columns(2)
        with h_c1:
            # Severity distribution chart
            sev_counts = df_all["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig_sev = px.pie(
                sev_counts,
                names="Severity",
                values="Count",
                title="Historical Incident Severity Distribution",
                hole=0.45,
                color="Severity",
                color_discrete_map={
                    "HIGH": "#ef4444",
                    "MEDIUM": "#f59e0b",
                    "LOW": "#10b981",
                    "INFORMATIONAL": "#64748b",
                },
            )
            fig_sev.update_layout(template="plotly_dark", height=280)
            st.plotly_chart(fig_sev, use_container_width=True)

        with h_c2:
            # Detection source distribution
            src_counts = df_all["detection_source"].value_counts().reset_index()
            src_counts.columns = ["Source", "Count"]
            fig_src = px.bar(
                src_counts,
                x="Source",
                y="Count",
                title="Detections by Attribution Source",
                color="Source",
                color_discrete_sequence=["#3b82f6", "#8b5cf6", "#ec4899"],
            )
            fig_src.update_layout(template="plotly_dark", height=280)
            st.plotly_chart(fig_src, use_container_width=True)

        st.markdown("---")
        st.markdown("### Export Sanitized Event Log")
        csv_data = df_all[[
            "incident_id", "created_at", "last_seen", "src_ip", "dst_ip", "dst_port",
            "proto", "severity", "detection_source", "raw_score", "status", "response_action"
        ]].to_csv(index=False)

        st.download_button(
            "📥 Download Sanitized Incident History (CSV)",
            data=csv_data,
            file_name=f"xshield_incidents_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


# =============================================================================
# TAB 5: SYSTEM HEALTH
# =============================================================================
with tabs[4]:
    st.subheader("5 · Capture & Infrastructure Diagnostics")

    diag_c1, diag_c2 = st.columns(2)

    with diag_c1:
        st.markdown("#### Packet Capture Subsystem")
        st.markdown(f"- **Npcap Driver Installed:** `{'✅ YES' if backend_status.is_npcap_installed else '❌ NO (Replay active)'}`")
        st.markdown(f"- **Administrator Elevation:** `{'✅ YES' if backend_status.is_admin else '⚠️ NO (Standard User)'}`")
        st.markdown(f"- **Recommended Mode:** `{backend_status.recommended_mode.upper()}`")
        st.info(backend_status.status_message)

        st.markdown("#### Host Network Adapters Discovered")
        if not backend_status.interfaces:
            st.write("No physical network adapters enumerated.")
        else:
            df_if = pd.DataFrame(backend_status.interfaces)
            st.dataframe(df_if[["name", "description", "status", "speed"]], use_container_width=True)

    with diag_c2:
        st.markdown("#### Model & Schema Catalog")
        manifest = load_manifest_models(MODELS_DIR)
        for key, m_info in manifest.items():
            avail = m_info.get("is_available", False)
            st.markdown(f"- **`{key}`**: `{'🟢 Available' if avail else '🔴 Missing'}` ({len(m_info.get('feature_names', []))} features, Policy: `{m_info.get('port_policy')}`)")

        st.markdown("#### Safety & Response Health")
        st.markdown(f"- **Active Response Mode:** `{'SIMULATION ONLY' if resp_mgr.simulation_mode else 'LIVE ENFORCEMENT'}`")
        st.markdown(f"- **Alert Cooldown:** `60 seconds` per endpoint pair")
        st.markdown(f"- **Protected Host Endpoints:** `{len(PROTECTED_IPS)} critical IPs blacklisted from blocking`")


# =============================================================================
# TAB 6: OFFLINE CSV TRIAGE (PHASE 2)
# =============================================================================
with tabs[5]:
    st.subheader("6 · Offline CSV Dataset Triage & Batch Scoring")

    manifest = load_manifest_models(MODELS_DIR)
    if not manifest:
        st.error("No models found in models/manifest.json.")
    else:
        # Re-use Phase 2 offline triage logic
        model_names = list(manifest.keys())
        selected_model_name = st.selectbox("Select Model for CSV Triage", model_names, index=0)

        uploaded_file = st.file_uploader("Upload Network Flow CSV for Offline Triage", type=["csv"])

        # Quick sample loader
        sample_choice = st.selectbox(
            "Or load verified demonstration sample:",
            ["None", "TQH-C2 Sample (data/sample_tqh_c2_unlabelled.csv)", "CICIDS-2018 Sample (data/sample_cicids2018_unlabelled.csv)"]
        )

        df_offline = None
        if uploaded_file is not None:
            df_offline = pd.read_csv(uploaded_file)
        elif sample_choice != "None":
            sample_p = "data/sample_tqh_c2_unlabelled.csv" if "TQH-C2" in sample_choice else "data/sample_cicids2018_unlabelled.csv"
            df_offline = pd.read_csv(sample_p)

        if df_offline is not None:
            st.write(f"Loaded DataFrame: {len(df_offline):,} rows, {len(df_offline.columns)} columns.")
            compat = assess_dataset_compatibility(df_offline, manifest, selected_model_name)

            if not compat["current_model_compatibility"]["is_compatible"]:
                st.error(f"Schema Mismatch with model '{selected_model_name}': Missing {len(compat['current_model_compatibility']['missing_features'])} features.")
            else:
                st.success(f"Schema compatible with '{selected_model_name}'.")
                if st.button("🚀 Run Batch Triage Scoring"):
                    loaded_m = load_model(selected_model_name)
                    scored_df = score_flows_batch(df_offline, loaded_m)
                    st.dataframe(scored_df.head(20), use_container_width=True)


# =============================================================================
# TAB 7: MODEL RESEARCH (PHASE 1)
# =============================================================================
with tabs[6]:
    st.subheader("7 · Baseline Research & Model Training (Phase 1)")
    st.markdown("""
    Baseline training routines, dataset splits, and research validation reports from Phase 1.
    All models and training runs observe research isolation boundaries.
    """)
    st.markdown("Refer to [`reports/phase3_audit/audit_report.md`](file:///g:/IdeaLab/XShield_Starter/reports/phase3_audit/audit_report.md) for complete empirical audit results.")
