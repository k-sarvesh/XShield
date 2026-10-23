"""XShield: Explainable ML-assisted Detection for Suspicious Encrypted Network Traffic.

Operational Inference & Triage Dashboard (Phase 2)
Integrates saved model inference, schema validation, triage workflows,
and baseline research evaluation.
"""

from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from xshield.pipeline import MODELS_DIR, XShieldModel, load_model, run_experiment
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

# Page configuration
st.set_page_config(
    page_title="XShield | Traffic Intelligence & Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber-Intelligence Dark Styling
st.markdown("""
<style>
    .block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
    [data-testid="stAppViewContainer"] { background: #0b1220; color: #e2e8f0; }
    [data-testid="stSidebar"] { background: #0f172a; border-right: 1px solid #1e293b; }
    
    /* Sleek card containers */
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
    
    /* Integrity banner */
    .integrity-banner {
        background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
        border-left: 4px solid #38bdf8;
        border-radius: 6px;
        padding: 12px 18px;
        margin-bottom: 20px;
        font-size: 0.88rem;
        color: #cbd5e1;
        line-height: 1.5;
    }
    .integrity-badge {
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.03em;
    }

    /* Risk badges */
    .badge-low { background-color: #064e3b; color: #34d399; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    .badge-med { background-color: #78350f; color: #fbbf24; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    .badge-high { background-color: #7c2d12; color: #fb923c; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
    .badge-crit { background-color: #881337; color: #f43f5e; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource(show_spinner="Loading verified model artifact...")
def get_cached_model(model_name: str) -> XShieldModel:
    """Loads a verified model from disk with resource caching."""
    return load_model(model_name)


# -----------------------------------------------------------------------------
# Top Navigation & Header
# -----------------------------------------------------------------------------
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ XShield")
    st.caption("Explainable ML-Assisted Traffic Intelligence & Operational Triage · Research Build")
with col_h2:
    st.markdown("<div style='text-align: right; padding-top: 15px; color: #64748b; font-size: 0.8rem;'>"
                "XShield v2.0-rc<br>Phase 2 Operational Dashboard</div>", unsafe_allow_html=True)

# Visible Risk and Research Integrity Note (Mandatory Section 6)
st.markdown("""
<div class="integrity-banner">
    <span class="integrity-badge">RESEARCH INTEGRITY & RISK NOTICE:</span>
    XShield produces ML-based suspiciousness indicators from the features available to the selected model. 
    Predictions are not confirmed malware verdicts. Model scores are uncalibrated Random Forest class confidence scores, 
    not calibrated probabilities unless calibration has been validated. High scores indicate statistical divergence, 
    not proof of compromise. Low scores do not guarantee safety. Benchmark results do not imply generalization to arbitrary Internet traffic.
</div>
""", unsafe_allow_html=True)

# Top-level Tabs: Operational Triage vs Research Baseline
tab_triage, tab_research = st.tabs([
    "🛡️ Operational Inference & Triage",
    "🧪 Baseline Model Training & Evaluation (Phase 1)",
])


# =============================================================================
# TAB 1: OPERATIONAL INFERENCE & TRIAGE
# =============================================================================
with tab_triage:
    # -------------------------------------------------------------------------
    # 1. Model Selection & Inspection
    # -------------------------------------------------------------------------
    manifest = load_manifest_models(MODELS_DIR)
    
    st.subheader("1 · Model Selection & Verification")
    
    if not manifest:
        st.error(f"No models found in manifest at '{MODELS_DIR / 'manifest.json'}'. Please ensure models are trained.")
        st.stop()

    model_options = list(manifest.keys())
    
    # Friendly labels for model selection
    def format_model_label(key: str) -> str:
        info = manifest.get(key, {})
        ds = info.get("dataset_name", "Unknown Dataset")
        policy = info.get("port_policy", "default").replace("_", " ").title()
        features = info.get("feature_count", len(info.get("feature_names", [])))
        return f"{key}  [{ds} · {policy} · {features} features]"

    if "selected_model_key" not in st.session_state or st.session_state["selected_model_key"] not in model_options:
        st.session_state["selected_model_key"] = model_options[0]

    current_idx = model_options.index(st.session_state["selected_model_key"])

    def on_model_select_change():
        st.session_state["selected_model_key"] = st.session_state["model_select_dropdown"]

    selected_model_key = st.selectbox(
        "Select Saved XShield Model",
        options=model_options,
        format_func=format_model_label,
        index=current_idx,
        key="model_select_dropdown",
        on_change=on_model_select_change,
        help="Select a model artifact from models/manifest.json. Safe loading ensures no arbitrary code execution.",
    )
    st.session_state["selected_model_key"] = selected_model_key

    model_meta = manifest.get(selected_model_key, {})
    if not model_meta.get("is_available", False):
        st.error(f"Model artifact '{selected_model_key}' is unavailable or missing companion files: "
                 f"{model_meta.get('missing_files', [])}. Please select another model.")
        st.stop()

    try:
        active_model = get_cached_model(selected_model_key)
    except Exception as e:
        st.error(f"Failed to load model '{selected_model_key}': {type(e).__name__}: {e}")
        st.info("Please select another valid model or re-verify model artifacts.")
        st.stop()

    # Model Architecture Summary Bar
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Dataset & Policy</div>
            <div class="metric-val" style="font-size: 1.15rem;">{model_meta.get('port_policy', '').replace('_', ' ').title()}</div>
            <div class="metric-sub">{model_meta.get('dataset_name', '')}</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Required Schema</div>
            <div class="metric-val">{len(active_model.feature_names)} <span style="font-size:0.9rem;font-weight:400;color:#94a3b8;">features</span></div>
            <div class="metric-sub">{len(active_model.metadata.get('numeric_features', []))} numeric · {len(active_model.metadata.get('categorical_features', []))} categorical</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Classification Task</div>
            <div class="metric-val" style="font-size: 1.15rem;">{model_meta.get('task_type', '').title()}</div>
            <div class="metric-sub">Classes: {', '.join(active_model.classes)}</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        eval_summary = model_meta.get("evaluation_summary", {})
        f1_str = f"{eval_summary.get('macro_f1') or eval_summary.get('out_of_fold_macro_f1', 0.0):.4f}" if eval_summary else "N/A"
        roc_str = f"{eval_summary.get('roc_auc') or eval_summary.get('out_of_fold_roc_auc', 0.0):.4f}" if eval_summary else "N/A"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Validation Performance</div>
            <div class="metric-val" style="font-size: 1.15rem;">F1: {f1_str}</div>
            <div class="metric-sub">ROC-AUC: {roc_str}</div>
        </div>
        """, unsafe_allow_html=True)

    with st.expander("🔍 Inspect Model Feature Schema & Excluded Fields", expanded=False):
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown(f"**Required Features ({len(active_model.feature_names)}):**")
            st.write(active_model.feature_names)
        with c_right:
            st.markdown(f"**Excluded Leakage Guard Fields ({len(active_model.metadata.get('excluded_features', []))}):**")
            st.write(active_model.metadata.get("excluded_features", []))

    st.markdown("---")

    # -------------------------------------------------------------------------
    # 2. Input Ingestion & Schema Validation
    # -------------------------------------------------------------------------
    st.subheader("2 · Traffic Flow Ingestion (CSV)")
    
    # Active model context beside ingestion controls
    st.markdown(f"""
    <div style="background: #111c2e; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
        <div>
            <span style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Selected Target Model:</span>
            <strong style="color: #38bdf8; margin-left: 6px; font-size: 0.95rem;">{selected_model_key}</strong>
        </div>
        <div style="font-size: 0.85rem; color: #cbd5e1;">
            <span>Dataset: <strong style="color: #f8fafc;">{model_meta.get('dataset_name', '')}</strong></span>
            <span style="color: #64748b; margin: 0 8px;">|</span>
            <span>Port Policy: <strong style="color: #f8fafc;">{model_meta.get('port_policy', '').replace('_', ' ').title()}</strong></span>
            <span style="color: #64748b; margin: 0 8px;">|</span>
            <span>Required Features: <strong style="color: #f8fafc;">{len(active_model.feature_names)}</strong></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.info("Upload an unlabelled or labelled network-flow CSV. "
            "Raw PCAP parsing is out of scope for this phase. "
            "If a ground-truth label column is present in the CSV, it will be preserved for reference only "
            "and will strictly NEVER influence model predictions.")

    col_up, col_samples = st.columns([3, 2])
    with col_up:
        uploaded_file = st.file_uploader(
            "Upload flow records (CSV)",
            type=["csv"],
            key="triage_file_uploader",
            help="Upload a CSV with network flow features matching the selected model's schema.",
        )
    with col_samples:
        st.markdown("<p style='font-size:0.85rem;color:#94a3b8;margin-bottom:8px;'>Or load benchmark demonstration fixtures:</p>", unsafe_allow_html=True)
        s_col1, s_col2 = st.columns(2)
        with s_col1:
            load_tqh_sample = st.button("📂 Load TQH-C2 Demo (50 flows)", width="stretch")
        with s_col2:
            load_cic_sample = st.button("📂 Load CICIDS Demo (50 flows)", width="stretch")

    # Determine input data source
    input_df = None
    input_source_desc = ""

    if uploaded_file is not None:
        try:
            # Read safe CSV
            input_df = pd.read_csv(uploaded_file, low_memory=False)
            input_source_desc = f"Uploaded file: {uploaded_file.name} ({len(input_df):,} rows)"
        except Exception as e:
            st.error(f"Malformed or unreadable CSV file: {type(e).__name__}: {e}")
            st.stop()
    elif load_tqh_sample:
        tqh_sample_path = Path("data/sample_tqh_c2_unlabelled.csv")
        if tqh_sample_path.exists():
            input_df = pd.read_csv(tqh_sample_path)
            input_source_desc = f"Demo Fixture: TQH-C2 Testbed A ({len(input_df)} flows)"
        else:
            st.warning("Demo fixture data/sample_tqh_c2_unlabelled.csv not found.")
    elif load_cic_sample:
        cic_sample_path = Path("data/sample_cicids2018_unlabelled.csv")
        if cic_sample_path.exists():
            input_df = pd.read_csv(cic_sample_path)
            input_source_desc = f"Demo Fixture: CICIDS-2018 Botnet ({len(input_df)} flows)"
        else:
            st.warning("Demo fixture data/sample_cicids2018_unlabelled.csv not found.")

    if input_df is None:
        st.markdown("<div style='text-align: center; padding: 40px; color: #64748b;'>"
                    "<i>Waiting for traffic flow CSV. Please upload a file or click a demo fixture above.</i></div>",
                    unsafe_allow_html=True)
        st.stop()

    # Basic shape checks
    if input_df.empty or len(input_df) == 0:
        st.error("Uploaded CSV contains 0 rows. Please provide a non-empty CSV.")
        st.stop()

    # Dataset Diagnostics & Schema Inspection
    diag = assess_dataset_compatibility(input_df, manifest=manifest, current_model_key=selected_model_key)
    validation = validate_flow_schema(input_df, active_model, manifest=manifest)

    st.markdown("##### Dataset Diagnostics & Schema Inspection")
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Row Count</div>
            <div class="metric-val">{len(input_df):,} <span style="font-size:0.85rem;font-weight:400;color:#94a3b8;">flows</span></div>
            <div class="metric-sub">{input_source_desc[:38]}</div>
        </div>
        """, unsafe_allow_html=True)
    with d2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Column Count</div>
            <div class="metric-val">{len(input_df.columns)} <span style="font-size:0.85rem;font-weight:400;color:#94a3b8;">columns</span></div>
            <div class="metric-sub">CSV header fields</div>
        </div>
        """, unsafe_allow_html=True)
    with d3:
        schema_color = "#34d399" if "known" in diag["schema_classification"] else ("#fbbf24" if "partial" in diag["schema_classification"] else "#f43f5e")
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Detected Schema</div>
            <div class="metric-val" style="font-size: 1.05rem; color: {schema_color};">{diag['detected_schema']}</div>
            <div class="metric-sub">{diag['evidence'][:42]}...</div>
        </div>
        """, unsafe_allow_html=True)
    with d4:
        match_color = "#34d399" if validation["is_valid"] else "#f43f5e"
        match_status = "COMPATIBLE ✅" if validation["is_valid"] else "MISMATCH ❌"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Selected Model Match</div>
            <div class="metric-val" style="font-size: 1.05rem; color: {match_color};">{match_status}</div>
            <div class="metric-sub">{selected_model_key}</div>
        </div>
        """, unsafe_allow_html=True)

    if not validation["is_valid"]:
        st.error(f"❌ {validation['message']}")

        # Show missing required columns and additional columns separately
        col_m, col_e = st.columns(2)
        with col_m:
            st.markdown(f"**🔻 Missing Required Columns for `{selected_model_key}` ({len(validation['missing_features'])}):**")
            st.caption("Required by the selected model's saved metadata. Features are never invented or zero-filled.")
            st.dataframe(pd.DataFrame({"Missing Required Feature": validation["missing_features"]}), width="stretch", height=200)

        with col_e:
            st.markdown(f"**➕ Additional / Auxiliary Columns in Uploaded CSV ({len(validation['extra_features'])}):**")
            st.caption("Preserved for inspection; strictly excluded from model feature inputs.")
            st.dataframe(pd.DataFrame({"Auxiliary Column": validation["extra_features"]}), width="stretch", height=200)

        # Cross-model compatibility catalog table
        compat_rows = []
        for m_key, comp_info in diag["model_compatibilities"].items():
            compat_rows.append({
                "Model": m_key,
                "Benchmark Dataset": comp_info["dataset_name"],
                "Port Policy": comp_info["port_policy"].replace("_", " ").title(),
                "Compatible": "✅ Compatible" if comp_info["is_compatible"] else "❌ Incompatible",
                "Schema Coverage": f"{comp_info['present_count']}/{comp_info['total_required']} ({comp_info['match_percentage']}%)",
                "Missing Columns": len(comp_info["missing_features"]),
            })

        with st.expander("📋 View Compatibility with All Catalog Models", expanded=True):
            st.dataframe(pd.DataFrame(compat_rows), width="stretch")

        # Actionable resolution without silent modification
        if diag["compatible_models"]:
            rec_model = diag["recommended_model"]
            st.warning(
                f"💡 **Compatible Model Available:** The uploaded CSV matches **{diag['detected_schema']}** "
                f"and is compatible with **{len(diag['compatible_models'])}** catalog model(s).\n\n"
                f"Recommended model: **`{rec_model}`** "
                f"({manifest[rec_model]['dataset_name']} · {manifest[rec_model]['port_policy'].replace('_', ' ').title()}).\n\n"
                f"Click below to switch the active model selection and proceed to triage."
            )
            if st.button(f"👉 Switch to Compatible Model: {format_model_label(rec_model)}", width="stretch", type="primary", key="btn_switch_rec_model"):
                st.session_state["selected_model_key"] = rec_model
                st.rerun()
        else:
            st.error(
                f"🚫 **Unsupported Dataset Schema:** The uploaded CSV does not match any existing model in the XShield catalog.\n\n"
                f"**Why:** Current models were trained specifically on the **TQH-C2** (Sliver TLS) and "
                f"**CICIDS-2018** (CICFlowMeter flow statistics) benchmark schemas. Arbitrary network-flow formats "
                f"are not supported without training a dedicated model."
            )

        st.stop()
    else:
        status_extra = f" (+ {len(validation['extra_features'])} auxiliary columns preserved for inspection)" if validation["extra_features"] else ""
        target_info = f" · Target column '{validation['target_column']}' detected & isolated as ground-truth reference" if validation.get("target_column") else ""
        st.success(f"✅ Schema Verified: All {len(active_model.feature_names)} required features present{status_extra}{target_info}.")

        with st.expander("🔍 Inspect Validated Schema & Auxiliary Columns", expanded=False):
            c_req, c_aux = st.columns(2)
            with c_req:
                st.markdown(f"**Required Model Features ({len(active_model.feature_names)}):**")
                st.dataframe(pd.DataFrame({"Feature": active_model.feature_names}), width="stretch", height=220)
            with c_aux:
                st.markdown(f"**Auxiliary Columns Preserved for Inspection ({len(validation['extra_features'])}):**")
                if validation["extra_features"]:
                    st.dataframe(pd.DataFrame({"Auxiliary Column": validation["extra_features"]}), width="stretch", height=220)
                else:
                    st.info("No auxiliary columns in input.")

    st.markdown("---")

    # -------------------------------------------------------------------------
    # 3. Operational Triage Controls & Batch Inference
    # -------------------------------------------------------------------------
    st.subheader("3 · Suspiciousness Scoring & Triage Policy")
    
    # Active model context beside inference controls
    st.markdown(f"""
    <div style="background: #111c2e; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 16px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
        <div>
            <span style="color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">Scoring Engine:</span>
            <strong style="color: #38bdf8; margin-left: 6px; font-size: 0.95rem;">{selected_model_key}</strong>
        </div>
        <div style="font-size: 0.85rem; color: #cbd5e1;">
            <span>Dataset: <strong style="color: #f8fafc;">{model_meta.get('dataset_name', '')}</strong></span>
            <span style="color: #64748b; margin: 0 8px;">|</span>
            <span>Port Policy: <strong style="color: #f8fafc;">{model_meta.get('port_policy', '').replace('_', ' ').title()}</strong></span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    col_t1, col_t2 = st.columns([2, 1])
    with col_t1:
        risk_threshold = st.slider(
            "Triage Suspiciousness Threshold",
            min_value=0.05,
            max_value=0.95,
            value=0.50,
            step=0.05,
            help="Flows with uncalibrated risk score >= this threshold will be flagged for analyst review.",
        )
    with col_t2:
        st.markdown("<div style='font-size:0.8rem;color:#94a3b8;padding-top:15px;'>"
                    "Default: 0.50.<br>Lower threshold: Higher sensitivity (catches subtle beacons).<br>"
                    "Higher threshold: Higher precision (focuses on critical alerts).</div>", unsafe_allow_html=True)

    # Run / Retrieve Inference Results
    # Use session_state caching to avoid repeated inference on widget changes
    sig = f"{selected_model_key}_{len(input_df)}_{tuple(input_df.columns)}_{risk_threshold}"
    
    if st.session_state.get("inference_sig") != sig or "scored_df" not in st.session_state:
        with st.spinner("Executing operational inference pipeline (NO retraining)..."):
            try:
                scored_df = score_flows_batch(input_df, active_model, threshold=risk_threshold)
                st.session_state["scored_df"] = scored_df
                st.session_state["inference_sig"] = sig
            except Exception as e:
                st.error(f"Inference execution failed: {type(e).__name__}: {e}")
                st.stop()
    else:
        scored_df = st.session_state["scored_df"]
        # Update is_flagged with current slider threshold
        scored_df["is_flagged"] = scored_df["risk_score"] >= risk_threshold

    # Calculate metrics
    metrics = compute_triage_metrics(scored_df, threshold=risk_threshold)

    # -------------------------------------------------------------------------
    # 4. Triage Overview & Visualizations
    # -------------------------------------------------------------------------
    st.subheader("4 · Executive Triage Overview")
    
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Analyzed Flows</div>
            <div class="metric-val">{metrics['total_flows']:,}</div>
            <div class="metric-sub">Single inference pass</div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        flag_color = "#f43f5e" if metrics["flagged_count"] > 0 else "#34d399"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Flagged for Triage</div>
            <div class="metric-val" style="color: {flag_color};">{metrics['flagged_count']:,} <span style="font-size:1rem;color:#94a3b8;">({metrics['flagged_pct']}%)</span></div>
            <div class="metric-sub">Score ≥ {risk_threshold:.2f}</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        high_crit_count = metrics["tier_distribution"].get("HIGH", 0) + metrics["tier_distribution"].get("CRITICAL", 0)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">High / Critical Tiers</div>
            <div class="metric-val" style="color: #fb923c;">{high_crit_count:,}</div>
            <div class="metric-sub">Score ≥ 0.65</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Risk Score Range</div>
            <div class="metric-val">{metrics['mean_risk_score']:.3f} <span style="font-size:0.85rem;color:#94a3b8;">mean</span></div>
            <div class="metric-sub">Min: {metrics['min_risk_score']:.3f} · Max: {metrics['max_risk_score']:.3f}</div>
        </div>
        """, unsafe_allow_html=True)

    # Charts: Class Distribution and Risk Tier Breakdown
    c_chart1, c_chart2 = st.columns(2)
    with c_chart1:
        class_df = pd.DataFrame(list(metrics["class_distribution"].items()), columns=["Class", "Count"])
        if not class_df.empty:
            fig_class = px.pie(
                class_df,
                names="Class",
                values="Count",
                title="Predicted Class Distribution",
                hole=0.45,
                color_discrete_sequence=["#10b981", "#ef4444", "#3b82f6", "#f59e0b"],
            )
            fig_class.update_layout(template="plotly_dark", height=280, margin=dict(t=40, b=10, l=10, r=10))
            st.plotly_chart(fig_class, width="stretch")

    with c_chart2:
        tier_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        tier_counts = [metrics["tier_distribution"].get(t, 0) for t in tier_order]
        tier_colors = ["#10b981", "#f59e0b", "#f97316", "#ef4444"]
        
        fig_tier = go.Figure(data=[
            go.Bar(
                x=tier_order,
                y=tier_counts,
                marker_color=tier_colors,
                text=tier_counts,
                textposition="auto",
            )
        ])
        fig_tier.update_layout(
            title="Risk Tier Distribution",
            template="plotly_dark",
            height=280,
            xaxis_title="Risk Tier",
            yaxis_title="Flow Count",
            margin=dict(t=40, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_tier, width="stretch")

    st.markdown("---")

    # -------------------------------------------------------------------------
    # 5. Flow Inspection Table & Multi-Criteria Filtering
    # -------------------------------------------------------------------------
    st.subheader("5 · Flow Inspection Table")
    
    # Filter Controls Bar
    f_c1, f_c2, f_c3, f_c4 = st.columns(4)
    with f_c1:
        class_options = ["ALL"] + sorted(list(metrics["class_distribution"].keys()))
        selected_class_filter = st.selectbox("Filter by Predicted Class", class_options, index=0)
    with f_c2:
        tier_options = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        selected_tier_filter = st.selectbox("Filter by Risk Tier", tier_options, index=0)
    with f_c3:
        flagged_only_toggle = st.checkbox("Show Flagged Flows Only", value=False)
    with f_c4:
        sort_option = st.selectbox(
            "Sort Order",
            options=["Risk Score (High → Low)", "Risk Score (Low → High)", "Original Flow Order"],
            index=0,
        )
        sort_map = {
            "Risk Score (High → Low)": "risk_desc",
            "Risk Score (Low → High)": "risk_asc",
            "Original Flow Order": "flow_id_asc",
        }

    search_query = st.text_input("🔍 Search Traffic (IP, Port, Protocol, or Label)", "")

    # Apply filters
    filtered_df = filter_triage_flows(
        scored_df,
        label_filter=selected_class_filter,
        tier_filter=selected_tier_filter,
        flagged_only=flagged_only_toggle,
        search_query=search_query,
        sort_by=sort_map[sort_option],
    )

    st.caption(f"Showing **{len(filtered_df):,}** of **{len(scored_df):,}** flows.")

    # Determine display columns (present fields only)
    traffic_fields = extract_available_traffic_fields(scored_df)
    
    primary_display_cols = ["flow_id", "risk_level", "risk_score", "predicted_label", "is_flagged"]
    if "ground_truth_label" in scored_df.columns:
        primary_display_cols.append("ground_truth_label")

    # Append relevant traffic columns that actually exist
    for _, col_name in traffic_fields.items():
        if col_name and col_name in scored_df.columns and col_name not in primary_display_cols:
            primary_display_cols.append(col_name)

    # Any remaining columns (up to 5 more)
    remaining_cols = [c for c in scored_df.columns if c not in primary_display_cols and not c.startswith("prob_")]
    display_cols = primary_display_cols + remaining_cols[:5]

    st.dataframe(
        filtered_df[display_cols].style.format({"risk_score": "{:.4f}"}),
        width="stretch",
        height=320,
    )

    st.markdown("---")

    # -------------------------------------------------------------------------
    # 6. Flow Details Drill-Down
    # -------------------------------------------------------------------------
    st.subheader("6 · Flow Detail Drill-Down")
    
    if len(filtered_df) == 0:
        st.info("No flows match current filter criteria.")
    else:
        flow_ids = filtered_df["flow_id"].tolist()
        selected_flow_id = st.selectbox("Select Flow to Inspect (# ID)", options=flow_ids, index=0)
        
        flow_row = scored_df[scored_df["flow_id"] == selected_flow_id].iloc[0]
        
        d_col1, d_col2 = st.columns([1, 2])
        with d_col1:
            st.markdown(f"#### Flow #{selected_flow_id} Summary")
            st.markdown(f"- **Predicted Label**: `{flow_row['predicted_label']}`")
            st.markdown(f"- **Risk Score**: `{flow_row['risk_score']:.4f}` (Uncalibrated)")
            st.markdown(f"- **Risk Tier**: `{flow_row['risk_level']}`")
            st.markdown(f"- **Triage Status**: `{'FLAGGED 🚨' if flow_row['is_flagged'] else 'NORMAL 🟢'}`")
            
            if "ground_truth_label" in flow_row:
                st.markdown(f"- **Ground Truth (Reference)**: `{flow_row['ground_truth_label']}`")

            # Display probabilities
            st.markdown("**Model Class Probabilities:**")
            for c in active_model.classes:
                clean_c = f"prob_{c.replace(' ', '_').lower()}"
                if clean_c in flow_row:
                    st.progress(float(flow_row[clean_c]), text=f"{c}: {flow_row[clean_c]:.4f}")

            st.caption("ℹ️ *Notice: Per-flow SHAP explanations are not fabricated. A validated explanation methodology will be integrated in a subsequent phase.*")

        with d_col2:
            st.markdown("#### Flow Feature Attributes")
            # Present all feature values for this flow
            feat_data = []
            for feat in active_model.feature_names:
                if feat in flow_row:
                    feat_data.append({"Feature": feat, "Value": str(flow_row[feat])})
            
            # Auxiliary metadata
            aux_data = []
            for col, val in flow_row.items():
                if col not in active_model.feature_names and col not in ["flow_id", "predicted_label", "risk_score", "risk_level", "is_flagged"] and not str(col).startswith("prob_"):
                    aux_data.append({"Field": col, "Value": str(val)})

            tab_features, tab_aux = st.tabs(["Required Model Features", "Auxiliary Traffic Metadata"])
            with tab_features:
                st.dataframe(pd.DataFrame(feat_data), width="stretch", height=260)
            with tab_aux:
                if aux_data:
                    st.dataframe(pd.DataFrame(aux_data), width="stretch", height=260)
                else:
                    st.info("No additional auxiliary metadata columns present in input.")

    st.markdown("---")

    # -------------------------------------------------------------------------
    # 7. Results Export Actions
    # -------------------------------------------------------------------------
    st.subheader("7 · Export Triage Results")
    
    st.markdown("Download scored flow records as CSV. Predictions, uncalibrated risk scores, risk levels, and original columns are included. "
                "Source files are never overwritten.")

    exp_col1, exp_col2 = st.columns(2)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    with exp_col1:
        all_csv = format_csv_export(scored_df, flagged_only=False)
        st.download_button(
            label=f"📥 Download All Scored Flows ({len(scored_df):,} flows)",
            data=all_csv,
            file_name=f"xshield_scored_flows_{selected_model_key}_{timestamp_str}.csv",
            mime="text/csv",
            width="stretch",
        )
    with exp_col2:
        flagged_count = int(scored_df["is_flagged"].sum())
        flagged_csv = format_csv_export(scored_df, flagged_only=True)
        st.download_button(
            label=f"🚨 Download Flagged Flows Only ({flagged_count:,} flows)",
            data=flagged_csv,
            file_name=f"xshield_flagged_flows_{selected_model_key}_{timestamp_str}.csv",
            mime="text/csv",
            width="stretch",
            disabled=(flagged_count == 0),
        )


# =============================================================================
# TAB 2: RESEARCH BASELINE EVALUATION (PHASE 1 PRESERVED WORKFLOW)
# =============================================================================
with tab_research:
    st.subheader("🧪 Baseline Model Training & Empirical Evaluation")
    st.info("Upload labelled CSV data to train and evaluate a real baseline. No demo metrics are fabricated.")

    uploaded_research = st.file_uploader("Upload a labelled network-flow CSV", type=["csv"], key="research_uploader")
    if uploaded_research is None:
        r_a, r_b, r_c = st.columns(3)
        r_a.metric("Analysis status", "Waiting for data")
        r_b.metric("Model status", "Not trained")
        r_c.metric("Explainability", "Not available yet")
        st.markdown("### Workflow")
        st.markdown("1. Upload a labelled CSV.\n2. Select the target label.\n3. Choose usable input features.\n4. Run the baseline and inspect measured results.")
        st.warning("Flow-only data cannot validate the Flow + TLS hypothesis. TLS-only and Combined experiments require real TLS metadata for the same labelled flows.")
    else:
        try:
            df_res = pd.read_csv(uploaded_research, low_memory=False)
        except Exception as e:
            st.error(f"Could not read CSV: {e}")
            st.stop()

        if df_res.empty or len(df_res.columns) < 2:
            st.error("The file needs at least one feature column and one target-label column.")
        else:
            st.markdown("#### 1 · Inspect Dataset")
            r_a, r_b, r_c = st.columns(3)
            r_a.metric("Rows", f"{len(df_res):,}")
            r_b.metric("Columns", len(df_res.columns))
            r_c.metric("Missing cells", f"{int(df_res.isna().sum().sum()):,}")
            
            with st.expander("Preview data", expanded=True):
                st.dataframe(df_res.head(8), width="stretch")
            
            res_label_col = st.selectbox(
                "Target label column",
                list(df_res.columns),
                index=len(df_res.columns) - 1,
                key="res_label_col",
            )
            candidate_features = [col for col in df_res.columns if col != res_label_col]
            res_features = st.multiselect(
                "Input feature columns",
                candidate_features,
                default=candidate_features[:min(20, len(candidate_features))],
                key="res_features",
            )
            res_test_size = st.slider("Test-set proportion", 0.15, 0.40, 0.20, 0.05, key="res_test_size")
            st.caption("The basic random split is a first baseline, not proof of generalisation to unseen networks or capture sessions.")

            if st.button("Train and evaluate baseline", type="primary", width="stretch", key="res_train_btn"):
                if not res_features:
                    st.error("Select at least one feature.")
                else:
                    with st.spinner("Training and evaluating Random Forest..."):
                        st.session_state["research_result"] = run_experiment(df_res, res_label_col, res_features, res_test_size)

            res_result = st.session_state.get("research_result")
            if res_result:
                if res_result.get("error"):
                    st.error(res_result["error"])
                else:
                    st.markdown("#### 2 · Evaluation Results")
                    rm = res_result["metrics"]
                    ra, rb, rc, rd = st.columns(4)
                    ra.metric("Accuracy", f'{rm["accuracy"]:.3f}')
                    rb.metric("Precision (weighted)", f'{rm["precision"]:.3f}')
                    rc.metric("Recall (weighted)", f'{rm["recall"]:.3f}')
                    rd.metric("F1 (weighted)", f'{rm["f1"]:.3f}')
                    st.caption(f'Rows used: {res_result["n_rows"]:,} · Features: {res_result["n_features"]} · Model: Random Forest')
                    
                    left, right = st.columns(2)
                    with left:
                        st.markdown("##### Confusion matrix")
                        st.dataframe(
                            pd.DataFrame(res_result["confusion"], index=res_result["class_names"], columns=res_result["class_names"]),
                            width="stretch",
                        )
                        st.caption("Rows are actual classes; columns are predicted classes.")
                    with right:
                        st.markdown("##### Most influential features")
                        imp = pd.DataFrame(res_result["importance"], columns=["Feature", "Importance"]).head(15).sort_values("Importance")
                        if not imp.empty:
                            fig = px.bar(imp, x="Importance", y="Feature", orientation="h")
                            fig.update_layout(template="plotly_dark", height=430)
                            st.plotly_chart(fig, width="stretch")
                    
                    st.markdown("##### Classification report")
                    st.dataframe(pd.DataFrame(res_result["report"]).T, width="stretch")
                    st.warning("Metrics describe this dataset and split only. Check duplicates, leakage-prone columns, class balance and capture/session grouping before making research claims.")
                    st.download_button(
                        "Download evaluation report (JSON)",
                        json.dumps(res_result["export"], indent=2),
                        "xshield_evaluation_report.json",
                        "application/json",
                    )
