"""XShield: Explainable ML-assisted Detection for Suspicious Encrypted Network Traffic."""

from xshield.pipeline import (
    XShieldModel,
    build_pipeline,
    evaluate_model,
    load_model,
    predict_flows,
    run_experiment,
    train_and_save_model,
)

from xshield.datasets import (
    load_cicids2018_sample,
    load_tqh_c2_testbed_a,
)

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

__all__ = [
    "XShieldModel",
    "build_pipeline",
    "train_and_save_model",
    "load_model",
    "predict_flows",
    "evaluate_model",
    "run_experiment",
    "load_tqh_c2_testbed_a",
    "load_cicids2018_sample",
    "load_manifest_models",
    "check_model_compatibility",
    "assess_dataset_compatibility",
    "validate_flow_schema",
    "score_flows_batch",
    "filter_triage_flows",
    "compute_triage_metrics",
    "format_csv_export",
    "extract_available_traffic_fields",
]

