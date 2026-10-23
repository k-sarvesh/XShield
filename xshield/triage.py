"""Operational inference, schema validation, and triage processing for XShield.

Provides:
- load_manifest_models(): catalog and health check of models from models/manifest.json.
- validate_flow_schema(): strict schema validation against model requirements with helpful guidance.
- score_flows_batch(): batch inference preserving row association, traffic metadata, and scores.
- filter_triage_flows(): multi-criteria filtering (class, risk tier, search query, sorting).
- compute_triage_metrics(): executive summary metrics for triage overview.
- extract_available_traffic_fields(): safe extraction of present network traffic fields.
- format_csv_export(): formatted CSV generation for all or flagged flows.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Collection, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from xshield.pipeline import MODELS_DIR, XShieldModel, load_model

# Well-known candidate column names for network traffic flow inspection
COMMON_TRAFFIC_FIELDS = {
    "source_ip": ["orig_h", "src ip", "src_ip", "source ip", "source address", "src address"],
    "destination_ip": ["resp_h", "dst ip", "dst_ip", "destination ip", "destination address", "dst address"],
    "source_port": ["orig_p", "src port", "src_port", "source port"],
    "destination_port": ["resp_p", "Dst Port", "dst port", "dst_port", "destination port"],
    "protocol": ["proto", "Protocol", "protocol"],
    "duration": ["duration", "Flow Duration", "flow duration"],
    "forward_packets": ["orig_pkts", "Tot Fwd Pkts", "tot fwd pkts", "fwd pkts"],
    "backward_packets": ["resp_pkts", "Tot Bwd Pkts", "tot bwd pkts", "bwd pkts"],
    "forward_bytes": ["orig_bytes", "TotLen Fwd Pkts", "totlen fwd pkts", "orig_ip_bytes"],
    "backward_bytes": ["resp_bytes", "TotLen Bwd Pkts", "totlen bwd pkts", "resp_ip_bytes"],
    "timestamp": ["ts", "Timestamp", "timestamp", "flow timestamp"],
    "connection_state": ["conn_state", "conn state", "state"],
}


def load_manifest_models(models_dir: Path = MODELS_DIR) -> Dict[str, Dict[str, Any]]:
    """Loads and verifies model catalog from models/manifest.json.

    Populates authoritative feature requirements and settings from each model's
    saved metadata JSON companion file, avoiding hardcoded assumptions.

    Returns:
        Dict mapping model_name to its manifest metadata dictionary,
        including artifact status ('is_available', 'missing_files') and feature schemas.
    """
    manifest_path = Path(models_dir) / "manifest.json"
    if not manifest_path.exists():
        return {}

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    raw_models = data.get("models", {})
    verified = {}

    for key, info in raw_models.items():
        artifact_name = info.get("artifact_file", f"{key}.joblib")
        meta_name = info.get("metadata_file", f"{key}_metadata.json")

        artifact_path = Path(models_dir) / artifact_name
        meta_path = Path(models_dir) / meta_name

        missing_files = []
        if not artifact_path.exists():
            missing_files.append(artifact_name)
        if not meta_path.exists():
            missing_files.append(meta_name)

        entry = dict(info)
        entry["is_available"] = len(missing_files) == 0
        entry["missing_files"] = missing_files
        entry["artifact_path"] = str(artifact_path)
        entry["metadata_path"] = str(meta_path)

        # Inspect model required features and settings from saved metadata JSON
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as mf:
                    comp = json.load(mf)
                    entry["feature_names"] = comp.get("feature_names", [])
                    entry["numeric_features"] = comp.get("numeric_features", [])
                    entry["categorical_features"] = comp.get("categorical_features", [])
                    entry["target_column"] = comp.get("target_column")
                    entry["excluded_features"] = comp.get("excluded_features", [])
            except Exception:
                pass

        verified[key] = entry

    return verified


def check_model_compatibility(
    columns_or_df: Union[pd.DataFrame, Collection[str]],
    model_metadata_or_model: Union[Dict[str, Any], XShieldModel],
) -> Dict[str, Any]:
    """Evaluates whether an input schema satisfies a model's required feature set.

    Inspects the model's required features from its authoritative saved metadata,
    never from hardcoded assumptions. Does not modify input data.

    Args:
        columns_or_df: Input DataFrame or collection of column names.
        model_metadata_or_model: Model metadata dictionary (from load_manifest_models)
                                 or an XShieldModel instance.

    Returns:
        Dict detailing compatibility:
        - model_name: str
        - dataset_name: str
        - port_policy: str
        - is_compatible: bool
        - total_required: int
        - present_count: int
        - missing_features: List[str]
        - extra_features: List[str]
        - match_percentage: float
    """
    if isinstance(columns_or_df, pd.DataFrame):
        input_cols = list(columns_or_df.columns)
    else:
        input_cols = list(columns_or_df)

    if isinstance(model_metadata_or_model, XShieldModel):
        model_name = model_metadata_or_model.model_name
        expected_features = model_metadata_or_model.feature_names
        dataset_name = model_metadata_or_model.metadata.get("dataset_name", "Unknown Dataset")
        port_policy = model_metadata_or_model.metadata.get("port_policy", "unknown")
    elif isinstance(model_metadata_or_model, dict):
        model_name = model_metadata_or_model.get("model_name", "unknown")
        expected_features = list(model_metadata_or_model.get("feature_names", []))
        dataset_name = model_metadata_or_model.get("dataset_name", "Unknown Dataset")
        port_policy = model_metadata_or_model.get("port_policy", "unknown")
    else:
        raise TypeError(f"Unsupported model metadata type: {type(model_metadata_or_model)}")

    current_set = set(input_cols)
    missing = [c for c in expected_features if c not in current_set]
    extra = [c for c in input_cols if c not in expected_features]

    total_req = len(expected_features)
    present_cnt = total_req - len(missing)
    match_pct = (present_cnt / total_req * 100.0) if total_req > 0 else 0.0
    is_compat = (len(missing) == 0 and total_req > 0)

    return {
        "model_name": model_name,
        "dataset_name": dataset_name,
        "port_policy": port_policy,
        "is_compatible": is_compat,
        "total_required": total_req,
        "present_count": present_cnt,
        "missing_features": missing,
        "extra_features": extra,
        "match_percentage": round(match_pct, 2),
    }


def assess_dataset_compatibility(
    columns_or_df: Union[pd.DataFrame, Collection[str]],
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    current_model_key: Optional[str] = None,
    models_dir: Path = MODELS_DIR,
) -> Dict[str, Any]:
    """Diagnoses an input CSV/DataFrame against all available manifest models.

    Identifies:
    - Compatibility with each registered model
    - The detected dataset schema based strictly on empirical column evidence
      (distinguishing known TQH-C2, known CICIDS-2018, and unknown schemas)
    - Compatible models and recommended model when an unambiguous match exists.
    - Never mutates the input data or silently switches active models.
    """
    if manifest is None:
        manifest = load_manifest_models(models_dir)

    if isinstance(columns_or_df, pd.DataFrame):
        input_cols = list(columns_or_df.columns)
        row_count = len(columns_or_df)
    else:
        input_cols = list(columns_or_df)
        row_count = None

    column_count = len(input_cols)
    input_set = set(input_cols)

    # Check compatibility against each manifest model
    model_compatibilities = {}
    compatible_models = []
    incompatible_models = []

    for key, info in manifest.items():
        comp = check_model_compatibility(input_cols, info)
        model_compatibilities[key] = comp
        if comp["is_compatible"]:
            compatible_models.append(key)
        else:
            incompatible_models.append(key)

    # Evidence-based schema detection
    # Distinctive signature markers from benchmark definitions:
    tqh_signature_markers = {
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "proto", "conn_state", "history", "orig_ip_bytes", "resp_ip_bytes",
        "missed_bytes", "ja4", "ja4s",
    }
    cicids_signature_markers = {
        "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts",
        "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean",
        "Fwd Header Len", "Bwd Header Len", "Protocol",
    }

    tqh_markers_present = tqh_signature_markers.intersection(input_set)
    cicids_markers_present = cicids_signature_markers.intersection(input_set)

    # Identify models by dataset family from saved metadata
    tqh_models = [m for m in manifest.values() if "TQH-C2" in m.get("dataset_name", "")]
    cic_models = [m for m in manifest.values() if "CICIDS" in m.get("dataset_name", "")]

    tqh_fully_compatible = any(
        model_compatibilities[m["model_name"]]["is_compatible"]
        for m in tqh_models if m["model_name"] in model_compatibilities
    )
    cic_fully_compatible = any(
        model_compatibilities[m["model_name"]]["is_compatible"]
        for m in cic_models if m["model_name"] in model_compatibilities
    )

    if tqh_fully_compatible:
        detected_schema = "TQH-C2 (Sliver TLS)"
        schema_classification = "known_tqh_c2"
        evidence = "Input columns satisfy all required features of TQH-C2 Testbed A benchmark."
    elif cic_fully_compatible:
        detected_schema = "CICIDS-2018 (CICFlowMeter)"
        schema_classification = "known_cicids2018"
        evidence = "Input columns satisfy all required features of CICIDS-2018 Botnet benchmark."
    elif len(tqh_markers_present) >= 4 or (
        tqh_models and any(model_compatibilities[m["model_name"]]["match_percentage"] >= 50.0 for m in tqh_models)
    ):
        detected_schema = "TQH-C2 (Incomplete)"
        schema_classification = "partial_tqh_c2"
        missing_sample = tqh_models[0].get("feature_names", []) if tqh_models else []
        missing_tqh = [c for c in missing_sample if c not in input_set]
        evidence = (
            f"Input contains signature TQH-C2/Zeek TLS fields ({len(tqh_markers_present)} signature markers present), "
            f"but is missing required columns: {missing_tqh[:5]}..."
        )
    elif len(cicids_markers_present) >= 4 or (
        cic_models and any(model_compatibilities[m["model_name"]]["match_percentage"] >= 50.0 for m in cic_models)
    ):
        detected_schema = "CICIDS-2018 (Incomplete)"
        schema_classification = "partial_cicids2018"
        missing_sample = cic_models[0].get("feature_names", []) if cic_models else []
        missing_cic = [c for c in missing_sample if c not in input_set]
        evidence = (
            f"Input contains signature CICFlowMeter fields ({len(cicids_markers_present)} signature markers present), "
            f"but is missing required columns: {missing_cic[:5]}..."
        )
    else:
        detected_schema = "Unknown / Unsupported"
        schema_classification = "unknown"
        evidence = (
            "Columns do not match known TQH-C2 or CICIDS-2018 benchmark schemas. "
            "Arbitrary network-flow formats are not supported by the current models."
        )

    # Determine recommended model when an unambiguous match exists
    recommended_model = None
    if compatible_models:
        if current_model_key and current_model_key in compatible_models:
            recommended_model = current_model_key
        else:
            comp_datasets = {manifest[m].get("dataset_name") for m in compatible_models if m in manifest}
            if len(comp_datasets) == 1:
                # Unambiguous dataset match
                preferred_policy = "port_inclusive"
                if current_model_key and current_model_key in manifest:
                    preferred_policy = manifest[current_model_key].get("port_policy", "port_inclusive")
                matching_policy = [m for m in compatible_models if manifest[m].get("port_policy") == preferred_policy]
                recommended_model = matching_policy[0] if matching_policy else compatible_models[0]
            else:
                recommended_model = compatible_models[0]

    return {
        "row_count": row_count,
        "column_count": column_count,
        "input_columns": input_cols,
        "detected_schema": detected_schema,
        "schema_classification": schema_classification,
        "evidence": evidence,
        "model_compatibilities": model_compatibilities,
        "compatible_models": compatible_models,
        "incompatible_models": incompatible_models,
        "recommended_model": recommended_model,
        "is_supported": len(compatible_models) > 0,
    }


def validate_flow_schema(
    df: Optional[pd.DataFrame],
    model: XShieldModel,
    manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    models_dir: Path = MODELS_DIR,
) -> Dict[str, Any]:
    """Validates an uploaded DataFrame against the model's required feature schema.

    Enforces:
    - Non-empty input
    - Presence of all required feature columns
    - Permissibility of extra columns (treated as non-model metadata)
    - Detection of target columns (isolated from model inference)
    - Cross-catalog diagnostics if the selected model is incompatible

    Returns:
        Dict with keys:
        - is_valid (bool)
        - error_type (Optional[str])
        - missing_features (List[str])
        - extra_features (List[str])
        - target_column (Optional[str])
        - message (str)
        - detected_schema (str)
        - schema_classification (str)
        - compatible_models (List[str])
        - recommended_model (Optional[str])
        - diagnostic_summary (Dict[str, Any])
    """
    if df is None:
        return {
            "is_valid": False,
            "error_type": "NoneInput",
            "missing_features": model.feature_names,
            "extra_features": [],
            "target_column": None,
            "message": "No input DataFrame provided for schema validation.",
            "detected_schema": "None",
            "schema_classification": "unknown",
            "compatible_models": [],
            "recommended_model": None,
            "diagnostic_summary": {},
        }

    if len(df) == 0:
        return {
            "is_valid": False,
            "error_type": "EmptyDataFrame",
            "missing_features": [],
            "extra_features": list(df.columns),
            "target_column": None,
            "message": "The uploaded CSV contains 0 rows. Please upload a file with network flow records.",
            "detected_schema": "Empty",
            "schema_classification": "unknown",
            "compatible_models": [],
            "recommended_model": None,
            "diagnostic_summary": {},
        }

    expected_features = model.feature_names
    current_columns = set(df.columns)

    missing = [c for c in expected_features if c not in current_columns]
    extra = [c for c in df.columns if c not in expected_features]

    # Detect if any target/label column is present (strictly isolated from estimator)
    target_candidates = ["label", "label_raw", "Label", "y"]
    model_target = model.metadata.get("target_column")
    if model_target:
        target_candidates.insert(0, model_target)

    detected_target = None
    for cand in target_candidates:
        if cand in df.columns:
            detected_target = cand
            break

    # Run catalog diagnostics
    diag = assess_dataset_compatibility(
        df,
        manifest=manifest,
        current_model_key=model.model_name,
        models_dir=models_dir,
    )
    compatible_models = diag["compatible_models"]
    recommended_model = diag["recommended_model"]

    if missing:
        if compatible_models:
            msg = (
                f"Schema Mismatch: Selected model '{model.model_name}' "
                f"({model.metadata.get('dataset_name', 'Unknown')}, {model.metadata.get('port_policy', 'unknown')}) "
                f"requires {len(expected_features)} features, but {len(missing)} column(s) are missing from the uploaded CSV:\n"
                f"Missing columns: {missing}\n\n"
                f"Detected Dataset Schema: {diag['detected_schema']}.\n"
                f"Compatible model(s) available in catalog: {compatible_models}.\n"
                f"Recommended model: '{recommended_model}'.\n"
                f"How to resolve: Switch to a compatible model to evaluate this dataset without retraining."
            )
        else:
            msg = (
                f"Schema Mismatch: Selected model '{model.model_name}' "
                f"({model.metadata.get('dataset_name', 'Unknown')}, {model.metadata.get('port_policy', 'unknown')}) "
                f"requires {len(expected_features)} features, but {len(missing)} column(s) are missing from the uploaded CSV:\n"
                f"Missing columns: {missing}\n\n"
                f"Detected Schema: {diag['detected_schema']}.\n"
                f"No existing model in the catalog is compatible with this dataset. "
                f"The uploaded CSV format is unsupported by current XShield models.\n"
                f"How to resolve: Upload network-flow records matching either the TQH-C2 benchmark or CICIDS-2018 benchmark schema."
            )
        return {
            "is_valid": False,
            "error_type": "MissingFeatures",
            "missing_features": missing,
            "extra_features": extra,
            "target_column": detected_target,
            "message": msg,
            "detected_schema": diag["detected_schema"],
            "schema_classification": diag["schema_classification"],
            "compatible_models": compatible_models,
            "recommended_model": recommended_model,
            "diagnostic_summary": diag,
        }

    return {
        "is_valid": True,
        "error_type": None,
        "missing_features": [],
        "extra_features": extra,
        "target_column": detected_target,
        "message": f"Schema Valid: All {len(expected_features)} required features present.",
        "detected_schema": diag["detected_schema"],
        "schema_classification": diag["schema_classification"],
        "compatible_models": compatible_models,
        "recommended_model": recommended_model,
        "diagnostic_summary": diag,
    }


def score_flows_batch(
    df: pd.DataFrame,
    model: XShieldModel,
    threshold: float = 0.50,
) -> pd.DataFrame:
    """Runs batch inference using the loaded model and builds a structured triage table.

    Guarantees:
    - Does not retrain the model
    - Validates schema strictly
    - Target label column (if present) does NOT influence predictions
    - Original row association and order are preserved
    - Output row count strictly equals input row count
    - Adds risk score, risk level, predicted label, class probabilities, and flag status

    Returns:
        DataFrame containing input columns, triage indicators, and predictions.
    """
    validation = validate_flow_schema(df, model)
    if not validation["is_valid"]:
        raise ValueError(validation["message"])

    # Predict using model's authoritative inference pipeline
    # Note: XShieldModel.validate_features inside predict_flows selects ONLY model.feature_names
    # in exact training order; target columns and extra columns are never fed to the classifier.
    preds = model.predict_flows(df)

    if len(preds) != len(df):
        raise RuntimeError(
            f"Inference row count mismatch: Expected {len(df)} predictions, got {len(preds)}."
        )

    triage_df = df.copy()

    # Prepend stable 1-indexed flow identifier
    triage_df.insert(0, "flow_id", range(1, len(df) + 1))

    # Attach model predictions
    triage_df["predicted_label"] = preds["predicted_label"].values
    triage_df["risk_score"] = preds["risk_score"].values
    triage_df["risk_level"] = preds["risk_level"].values

    # Determine flagged status by threshold
    scores = preds["risk_score"].values
    triage_df["is_flagged"] = np.where(np.isnan(scores), False, scores >= threshold)

    # Attach per-class probabilities
    for col in preds.columns:
        if col.startswith("prob_"):
            triage_df[col] = preds[col].values

    # Preserve target column as reference only if detected
    target_col = validation.get("target_column")
    if target_col and target_col in df.columns:
        triage_df["ground_truth_label"] = df[target_col].astype(str).values

    return triage_df


def extract_available_traffic_fields(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    """Discovers which standard traffic metadata columns exist in the input.

    Does NOT invent missing metadata: only reports columns actually present.
    """
    found = {}
    lower_map = {col.lower().strip(): col for col in df.columns}

    for standard_name, aliases in COMMON_TRAFFIC_FIELDS.items():
        matched = None
        for alias in aliases:
            if alias.lower() in lower_map:
                matched = lower_map[alias.lower()]
                break
        found[standard_name] = matched

    return found


def filter_triage_flows(
    triage_df: pd.DataFrame,
    label_filter: Optional[str] = None,
    tier_filter: Optional[str] = None,
    flagged_only: bool = False,
    search_query: Optional[str] = None,
    sort_by: str = "risk_desc",
) -> pd.DataFrame:
    """Filters and sorts a scored triage DataFrame according to analyst criteria."""
    filtered = triage_df.copy()

    # Filter by predicted label
    if label_filter and label_filter.upper() != "ALL":
        filtered = filtered[filtered["predicted_label"].astype(str) == str(label_filter)]

    # Filter by risk tier
    if tier_filter and tier_filter.upper() != "ALL":
        filtered = filtered[filtered["risk_level"].astype(str).str.upper() == str(tier_filter).upper()]

    # Filter by flagged status
    if flagged_only:
        filtered = filtered[filtered["is_flagged"] == True]

    # Search across available addresses, ports, and text fields
    if search_query and search_query.strip():
        q = search_query.strip().lower()
        search_cols = []
        traffic_fields = extract_available_traffic_fields(triage_df)
        for _, col in traffic_fields.items():
            if col and col in filtered.columns:
                search_cols.append(col)

        # Also search in predicted_label and risk_level
        for c in ["predicted_label", "risk_level"]:
            if c in filtered.columns and c not in search_cols:
                search_cols.append(c)

        if search_cols:
            mask = pd.Series(False, index=filtered.index)
            for c in search_cols:
                mask |= filtered[c].astype(str).str.lower().str.contains(q, na=False)
            filtered = filtered[mask]

    # Sorting
    if sort_by == "risk_desc" and "risk_score" in filtered.columns:
        filtered = filtered.sort_values(by="risk_score", ascending=False, na_position="last")
    elif sort_by == "risk_asc" and "risk_score" in filtered.columns:
        filtered = filtered.sort_values(by="risk_score", ascending=True, na_position="last")
    elif sort_by == "flow_id_asc" and "flow_id" in filtered.columns:
        filtered = filtered.sort_values(by="flow_id", ascending=True)

    return filtered


def compute_triage_metrics(triage_df: pd.DataFrame, threshold: float = 0.50) -> Dict[str, Any]:
    """Computes executive metrics for the triage dashboard overview."""
    total_flows = len(triage_df)
    if total_flows == 0:
        return {
            "total_flows": 0,
            "flagged_count": 0,
            "flagged_pct": 0.0,
            "class_distribution": {},
            "tier_distribution": {},
            "mean_risk_score": 0.0,
            "max_risk_score": 0.0,
            "min_risk_score": 0.0,
            "threshold": threshold,
        }

    flagged_mask = triage_df["risk_score"] >= threshold
    flagged_count = int(flagged_mask.sum())
    flagged_pct = (flagged_count / total_flows) * 100.0

    class_dist = triage_df["predicted_label"].value_counts().to_dict()
    tier_dist = triage_df["risk_level"].value_counts().to_dict()

    valid_scores = triage_df["risk_score"].dropna()
    mean_score = float(valid_scores.mean()) if not valid_scores.empty else 0.0
    max_score = float(valid_scores.max()) if not valid_scores.empty else 0.0
    min_score = float(valid_scores.min()) if not valid_scores.empty else 0.0

    # Ground truth alignment if present
    ground_truth_alignment = None
    if "ground_truth_label" in triage_df.columns:
        matches = (triage_df["predicted_label"].astype(str) == triage_df["ground_truth_label"].astype(str)).sum()
        ground_truth_alignment = {
            "available": True,
            "match_count": int(matches),
            "match_rate": float((matches / total_flows) * 100.0),
        }

    return {
        "total_flows": total_flows,
        "flagged_count": flagged_count,
        "flagged_pct": round(flagged_pct, 2),
        "class_distribution": class_dist,
        "tier_distribution": tier_dist,
        "mean_risk_score": round(mean_score, 4),
        "max_risk_score": round(max_score, 4),
        "min_risk_score": round(min_score, 4),
        "threshold": threshold,
        "ground_truth_alignment": ground_truth_alignment,
    }


def format_csv_export(triage_df: pd.DataFrame, flagged_only: bool = False) -> str:
    """Generates formatted CSV content for downloading triage results.

    Includes predictions, risk scores, risk levels, class probabilities, and input columns.
    Does not overwrite or alter source files.
    """
    export_df = triage_df.copy()
    if flagged_only:
        export_df = export_df[export_df["is_flagged"] == True]

    return export_df.to_csv(index=False)
