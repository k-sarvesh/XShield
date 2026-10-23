"""Reproducible execution script for XShield Phase 3 Research Audit experiments.

Executes:
1. TQH-C2 Testbed A 4-fold GroupKFold audits:
   - Config 1: Full approved features (14 features)
   - Config 2: Port excluded (13 features)
   - Config 3: TLS fingerprints excluded (ja4, ja4s removed) (12 features)
   - Config 4: Port AND TLS fingerprints excluded (11 features)
   - Config 5: Pure flow statistics only (all protocol/state shortcuts removed: duration, bytes, pkts) (8 features)
   - Config 6: Standalone shortcuts (resp_p only, ja4 only, conn_state only)
   - Cross-Testbed evaluation: Train on Testbed A, evaluate on Testbed B and C
2. CICIDS-2018 benchmark audits:
   - Config C1: Random 80/20 stratified split with Dst Port (Phase 1 replication)
   - Config C2: Random 80/20 stratified split without Dst Port
   - Config C3: Single-feature Dst Port
   - Config C4: De-duplicated 80/20 evaluation (exact duplicate feature rows removed)
   - Config C5: Strict chronological 70/30 split (train earlier, test later)
3. Outputs comprehensive JSON and CSV reports to reports/phase3_audit/.
"""

from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import time
import warnings
import zipfile

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

warnings.filterwarnings("ignore")

PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_DIR / "data"
AUDIT_DIR = PROJECT_DIR / "reports" / "phase3_audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

TQH_ZIP = DATA_DIR / "TQH-C2_features_v110.zip"
CIC_CSV = DATA_DIR / "sample_clean.csv"
CIC_SAMPLE_TS = DATA_DIR / "sample.csv"

RANDOM_STATE = 42


def compute_metrics(y_true, y_pred, y_prob=None, positive_label=1):
    """Computes comprehensive classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = accuracy_score(y_true, y_pred)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    prec_macro, rec_macro, _, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    prec_pos, rec_pos, f1_pos, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=[positive_label], average=None, zero_division=0
    )
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    auc = np.nan
    if y_prob is not None and len(np.unique(y_true)) == 2:
        try:
            auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            auc = np.nan

    return {
        "accuracy": float(acc),
        "balanced_accuracy": float(bal_acc),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "precision_macro": float(prec_macro),
        "recall_macro": float(rec_macro),
        "precision_positive": float(prec_pos[0]) if len(prec_pos) > 0 else 0.0,
        "recall_positive": float(rec_pos[0]) if len(rec_pos) > 0 else 0.0,
        "f1_positive": float(f1_pos[0]) if len(f1_pos) > 0 else 0.0,
        "fpr": fpr,
        "fnr": fnr,
        "roc_auc": auc,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total": int(len(y_true)),
    }


def build_audit_pipeline(numeric_cols, categorical_cols, n_estimators=100, min_samples_leaf=2):
    """Builds preprocessor and RF model fitting strictly on train folds."""
    transformers = []
    if numeric_cols:
        num_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
        ])
        transformers.append(("num", num_pipe, numeric_cols))
    if categorical_cols:
        cat_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent", missing_values=np.nan)),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])
        transformers.append(("cat", cat_pipe, categorical_cols))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        min_samples_leaf=min_samples_leaf,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier),
    ])


def run_tqh_group_experiment(X_df, y_ser, groups_ser, feature_list, config_name, description):
    """Executes 4-fold GroupKFold by capture_id with zero group leakage."""
    print(f"\n>>> Running TQH Experiment: {config_name} ({len(feature_list)} features)")
    print(f"    Features: {feature_list}")
    
    cv = GroupKFold(n_splits=4)
    fold_metrics = []
    oof_y_true = []
    oof_y_pred = []
    oof_y_prob = []
    
    fold_details = []

    # Identify categorical vs numeric within selected features
    cat_candidates = ["resp_p", "proto", "conn_state", "history", "ja4", "ja4s"]
    selected_cat = [c for c in feature_list if c in cat_candidates]
    selected_num = [c for c in feature_list if c not in cat_candidates]

    for fold, (train_idx, test_idx) in enumerate(cv.split(X_df, y_ser, groups=groups_ser), start=1):
        X_train = X_df[feature_list].iloc[train_idx].copy()
        X_test = X_df[feature_list].iloc[test_idx].copy()
        y_train = y_ser.iloc[train_idx].values
        y_test = y_ser.iloc[test_idx].values

        train_groups = sorted(list(set(groups_ser.iloc[train_idx])))
        test_groups = sorted(list(set(groups_ser.iloc[test_idx])))

        # Verify strict group separation
        overlap = set(train_groups).intersection(set(test_groups))
        if overlap:
            raise RuntimeError(f"Group leakage detected in fold {fold}: {overlap}")

        pipe = build_audit_pipeline(selected_num, selected_cat)
        pipe.fit(X_train, y_train)

        preds = pipe.predict(X_test)
        probs = pipe.predict_proba(X_test)[:, 1]

        m = compute_metrics(y_test, preds, probs, positive_label=1)
        m["fold"] = fold
        m["train_rows"] = len(train_idx)
        m["test_rows"] = len(test_idx)
        m["train_groups"] = len(train_groups)
        m["test_groups"] = len(test_groups)
        m["test_benign_count"] = int((y_test == 0).sum())
        m["test_c2_count"] = int((y_test == 1).sum())
        fold_metrics.append(m)

        fold_details.append({
            "fold": fold,
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
            "train_benign": int((y_train == 0).sum()),
            "train_c2": int((y_train == 1).sum()),
            "test_benign": int((y_test == 0).sum()),
            "test_c2": int((y_test == 1).sum()),
            "train_captures": train_groups,
            "test_captures": test_groups,
            "accuracy": m["accuracy"],
            "balanced_accuracy": m["balanced_accuracy"],
            "macro_f1": m["macro_f1"],
            "roc_auc": m["roc_auc"],
            "fpr": m["fpr"],
        })

        oof_y_true.extend(y_test)
        oof_y_pred.extend(preds)
        oof_y_prob.extend(probs)

    oof_metrics = compute_metrics(np.array(oof_y_true), np.array(oof_y_pred), np.array(oof_y_prob), positive_label=1)

    mean_acc = np.mean([f["accuracy"] for f in fold_metrics])
    std_acc = np.std([f["accuracy"] for f in fold_metrics], ddof=1)
    mean_bal_acc = np.mean([f["balanced_accuracy"] for f in fold_metrics])
    std_bal_acc = np.std([f["balanced_accuracy"] for f in fold_metrics], ddof=1)
    mean_f1 = np.mean([f["macro_f1"] for f in fold_metrics])
    std_f1 = np.std([f["macro_f1"] for f in fold_metrics], ddof=1)
    mean_auc = np.mean([f["roc_auc"] for f in fold_metrics])
    std_auc = np.std([f["roc_auc"] for f in fold_metrics], ddof=1)

    print(f"    Out-of-Fold Balanced Acc: {oof_metrics['balanced_accuracy']:.4f}, Macro F1: {oof_metrics['macro_f1']:.4f}, FPR: {oof_metrics['fpr']:.6f}")

    return {
        "config_name": config_name,
        "description": description,
        "feature_count": len(feature_list),
        "features": feature_list,
        "mean_accuracy": float(mean_acc),
        "std_accuracy": float(std_acc),
        "mean_balanced_accuracy": float(mean_bal_acc),
        "std_balanced_accuracy": float(std_bal_acc),
        "mean_macro_f1": float(mean_f1),
        "std_macro_f1": float(std_f1),
        "mean_roc_auc": float(mean_auc),
        "std_roc_auc": float(std_auc),
        "oof_metrics": oof_metrics,
        "fold_details": fold_details,
    }


def main():
    print("=" * 70)
    print("XSHIELD PHASE 3 RESEARCH VALIDITY, LEAKAGE AND GENERALIZATION AUDIT")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    # =========================================================================
    # PART 1: TQH-C2 TESTBED A (SLIVER TLS) AUDIT & CONTROLLED ABLATIONS
    # =========================================================================
    with zipfile.ZipFile(TQH_ZIP, "r") as archive:
        with archive.open("features/testbed_A.parquet") as f:
            df_tqh_raw = pd.read_parquet(BytesIO(f.read()))

    # Filter binary task
    df_tqh = df_tqh_raw[df_tqh_raw["label_raw"].isin(["benign", "malicious_c2"])].copy()
    df_tqh = df_tqh.dropna(subset=["label_raw", "capture_id"]).reset_index(drop=True)

    y_tqh = (df_tqh["label_raw"] == "malicious_c2").astype(int)
    groups_tqh = df_tqh["capture_id"].astype(str)

    # Pre-clean string representations
    for col in ["resp_p", "proto", "conn_state", "history", "ja4", "ja4s"]:
        if col in df_tqh.columns:
            df_tqh[col] = df_tqh[col].astype(object).where(pd.notna(df_tqh[col]), np.nan)
            df_tqh[col] = df_tqh[col].map(lambda v: v.strip() if isinstance(v, str) else v).replace("", np.nan)

    for col in ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"]:
        if col in df_tqh.columns:
            df_tqh[col] = pd.to_numeric(df_tqh[col], errors="coerce").replace([np.inf, -np.inf], np.nan)

    tqh_configs = [
        (
            "TQH_1_all_approved_features",
            "Existing Phase 1 approved feature set (14 features including port and TLS fingerprints)",
            [
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "resp_p", "proto", "conn_state", "history", "orig_ip_bytes",
                "resp_ip_bytes", "missed_bytes", "ja4", "ja4s"
            ],
        ),
        (
            "TQH_2_port_excluded",
            "Port features removed (resp_p excluded, keeping ja4/ja4s and flow stats)",
            [
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "proto", "conn_state", "history", "orig_ip_bytes",
                "resp_ip_bytes", "missed_bytes", "ja4", "ja4s"
            ],
        ),
        (
            "TQH_3_tls_fingerprints_excluded",
            "JA4 and JA4S fingerprints removed (keeping resp_p and flow stats)",
            [
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "resp_p", "proto", "conn_state", "history", "orig_ip_bytes",
                "resp_ip_bytes", "missed_bytes"
            ],
        ),
        (
            "TQH_4_port_and_tls_fingerprints_excluded",
            "Both destination port (resp_p) and TLS fingerprints (ja4, ja4s) removed",
            [
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "proto", "conn_state", "history", "orig_ip_bytes",
                "resp_ip_bytes", "missed_bytes"
            ],
        ),
        (
            "TQH_5_pure_flow_statistics_only",
            "Pure flow volume/packet size statistics only (all identity, port, fingerprints, proto, and conn_state/history removed)",
            [
                "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
            ],
        ),
        (
            "TQH_6_resp_p_only",
            "Standalone destination port shortcut check (resp_p only)",
            ["resp_p"],
        ),
        (
            "TQH_7_ja4_only",
            "Standalone JA4 fingerprint shortcut check (ja4 only)",
            ["ja4"],
        ),
        (
            "TQH_8_conn_state_only",
            "Standalone connection state shortcut check (conn_state only)",
            ["conn_state"],
        ),
    ]

    tqh_results = []
    for cfg_key, cfg_desc, feats in tqh_configs:
        res = run_tqh_group_experiment(df_tqh, y_tqh, groups_tqh, feats, cfg_key, cfg_desc)
        tqh_results.append(res)

    # =========================================================================
    # PART 2: CROSS-TESTBED GENERALIZATION AUDIT (A -> B, A -> C)
    # =========================================================================
    print("\n" + "=" * 70)
    print("PART 2: CROSS-TESTBED EVALUATION (TRAIN ON TESTBED A, TEST ON B & C)")
    print("=" * 70)

    # Common flow features present across Testbeds A, B, and C
    # Note: Testbed B is QUIC (UDP), Testbed C is HTTP (TCP), so proto differs.
    # JA4 is absent in C (HTTP has JA4H instead).
    # Common numeric flow features: duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes, missed_bytes
    common_flow_features = [
        "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
        "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
    ]

    with zipfile.ZipFile(TQH_ZIP, "r") as archive:
        with archive.open("features/testbed_B.parquet") as f:
            df_b_raw = pd.read_parquet(BytesIO(f.read()))
        with archive.open("features/testbed_C.parquet") as f:
            df_c_raw = pd.read_parquet(BytesIO(f.read()))

    df_b = df_b_raw[df_b_raw["label_raw"].isin(["benign", "malicious_c2"])].copy()
    df_c = df_c_raw[df_c_raw["label_raw"].isin(["benign", "malicious_c2"])].copy()

    for col in common_flow_features:
        df_b[col] = pd.to_numeric(df_b[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
        df_c[col] = pd.to_numeric(df_c[col], errors="coerce").replace([np.inf, -np.inf], np.nan)

    y_b = (df_b["label_raw"] == "malicious_c2").astype(int)
    y_c = (df_c["label_raw"] == "malicious_c2").astype(int)

    # Train model on Testbed A using common flow features
    pipe_cross = build_audit_pipeline(common_flow_features, [])
    pipe_cross.fit(df_tqh[common_flow_features], y_tqh)

    # Predict on Testbed B
    preds_b = pipe_cross.predict(df_b[common_flow_features])
    probs_b = pipe_cross.predict_proba(df_b[common_flow_features])[:, 1]
    metrics_cross_b = compute_metrics(y_b.values, preds_b, probs_b, positive_label=1)

    # Predict on Testbed C
    preds_c = pipe_cross.predict(df_c[common_flow_features])
    probs_c = pipe_cross.predict_proba(df_c[common_flow_features])[:, 1]
    metrics_cross_c = compute_metrics(y_c.values, preds_c, probs_c, positive_label=1)

    print(f"Testbed A -> Testbed B (Merlin / QUIC):")
    print(f"  Rows: {len(df_b)} (Benign: {(y_b==0).sum()}, C2: {(y_b==1).sum()})")
    print(f"  Accuracy: {metrics_cross_b['accuracy']:.4f}, Bal Acc: {metrics_cross_b['balanced_accuracy']:.4f}, Macro F1: {metrics_cross_b['macro_f1']:.4f}, FPR: {metrics_cross_b['fpr']:.4f}")
    print(f"  Confusion: TN={metrics_cross_b['tn']}, FP={metrics_cross_b['fp']}, FN={metrics_cross_b['fn']}, TP={metrics_cross_b['tp']}")

    print(f"Testbed A -> Testbed C (Mythic / HTTP+AES):")
    print(f"  Rows: {len(df_c)} (Benign: {(y_c==0).sum()}, C2: {(y_c==1).sum()})")
    print(f"  Accuracy: {metrics_cross_c['accuracy']:.4f}, Bal Acc: {metrics_cross_c['balanced_accuracy']:.4f}, Macro F1: {metrics_cross_c['macro_f1']:.4f}, FPR: {metrics_cross_c['fpr']:.4f}")
    print(f"  Confusion: TN={metrics_cross_c['tn']}, FP={metrics_cross_c['fp']}, FN={metrics_cross_c['fn']}, TP={metrics_cross_c['tp']}")

    cross_testbed_results = {
        "A_to_B": {
            "source_testbed": "A (Sliver / TLS)",
            "target_testbed": "B (Merlin / QUIC)",
            "features_used": common_flow_features,
            "metrics": metrics_cross_b,
        },
        "A_to_C": {
            "source_testbed": "A (Sliver / TLS)",
            "target_testbed": "C (Mythic / HTTP+AES)",
            "features_used": common_flow_features,
            "metrics": metrics_cross_c,
        }
    }

    # =========================================================================
    # PART 3: CICIDS-2018 BENCHMARK AUDIT & SPLIT EXPERIMENTS
    # =========================================================================
    print("\n" + "=" * 70)
    print("PART 3: CICIDS-2018 AUDIT & EXPERIMENTS")
    print("=" * 70)

    df_cic = pd.read_csv(CIC_CSV, low_memory=False)
    df_cic.columns = df_cic.columns.str.strip()
    df_cic = df_cic.dropna(subset=["Label"]).copy()

    excluded_terms = [
        "timestamp", "flow id", "flow_id",
        "src ip", "dst ip", "source ip", "destination ip",
        "src address", "dst address",
        "source address", "destination address",
    ]
    cic_feat_all = [
        c for c in df_cic.columns
        if c != "Label" and not any(t in c.lower() for t in excluded_terms)
    ]
    cic_feat_no_port = [c for c in cic_feat_all if c != "Dst Port"]

    for c in cic_feat_all:
        df_cic[c] = pd.to_numeric(df_cic[c], errors="coerce").replace([np.inf, -np.inf], np.nan)

    y_cic = (df_cic["Label"] == "Bot").astype(int)

    cic_experiments = {}

    # Experiment C1: Standard Stratified 80/20 Random Split (Full 68 features)
    X_train_c1, X_test_c1, y_train_c1, y_test_c1 = train_test_split(
        df_cic[cic_feat_all], y_cic, test_size=0.20, random_state=RANDOM_STATE, stratify=y_cic
    )
    pipe_c1 = build_audit_pipeline(cic_feat_all, [])
    pipe_c1.fit(X_train_c1, y_train_c1)
    preds_c1 = pipe_c1.predict(X_test_c1)
    probs_c1 = pipe_c1.predict_proba(X_test_c1)[:, 1]
    m_c1 = compute_metrics(y_test_c1.values, preds_c1, probs_c1, positive_label=1)
    print(f"CICIDS C1 (Random 80/20, all 68 features): Acc={m_c1['accuracy']:.5f}, F1={m_c1['macro_f1']:.5f}, ROC-AUC={m_c1['roc_auc']:.6f}")
    cic_experiments["C1_random_80_20_with_port"] = {
        "description": "Standard Stratified 80/20 random split (68 features including Dst Port)",
        "feature_count": len(cic_feat_all),
        "test_rows": len(y_test_c1),
        "metrics": m_c1,
    }

    # Experiment C2: Standard Stratified 80/20 Random Split (Port Excluded, 67 features)
    X_train_c2, X_test_c2, y_train_c2, y_test_c2 = train_test_split(
        df_cic[cic_feat_no_port], y_cic, test_size=0.20, random_state=RANDOM_STATE, stratify=y_cic
    )
    pipe_c2 = build_audit_pipeline(cic_feat_no_port, [])
    pipe_c2.fit(X_train_c2, y_train_c2)
    preds_c2 = pipe_c2.predict(X_test_c2)
    probs_c2 = pipe_c2.predict_proba(X_test_c2)[:, 1]
    m_c2 = compute_metrics(y_test_c2.values, preds_c2, probs_c2, positive_label=1)
    print(f"CICIDS C2 (Random 80/20, port excluded): Acc={m_c2['accuracy']:.5f}, F1={m_c2['macro_f1']:.5f}, ROC-AUC={m_c2['roc_auc']:.6f}")
    cic_experiments["C2_random_80_20_port_excluded"] = {
        "description": "Standard Stratified 80/20 random split (67 features, Dst Port excluded)",
        "feature_count": len(cic_feat_no_port),
        "test_rows": len(y_test_c2),
        "metrics": m_c2,
    }

    # Experiment C3: Standalone Dst Port Single-Feature Decision Tree / Random Forest
    X_train_c3, X_test_c3, y_train_c3, y_test_c3 = train_test_split(
        df_cic[["Dst Port"]], y_cic, test_size=0.20, random_state=RANDOM_STATE, stratify=y_cic
    )
    pipe_c3 = build_audit_pipeline(["Dst Port"], [])
    pipe_c3.fit(X_train_c3, y_train_c3)
    preds_c3 = pipe_c3.predict(X_test_c3)
    probs_c3 = pipe_c3.predict_proba(X_test_c3)[:, 1]
    m_c3 = compute_metrics(y_test_c3.values, preds_c3, probs_c3, positive_label=1)
    print(f"CICIDS C3 (Dst Port ONLY): Acc={m_c3['accuracy']:.5f}, F1={m_c3['macro_f1']:.5f}, ROC-AUC={m_c3['roc_auc']:.6f}")
    cic_experiments["C3_dst_port_only"] = {
        "description": "Single-feature model using only Dst Port (evaluating shortcut power)",
        "feature_count": 1,
        "test_rows": len(y_test_c3),
        "metrics": m_c3,
    }

    # Experiment C4: De-duplicated Evaluation (exact duplicate feature rows removed)
    print("\n--- De-duplicated CICIDS Evaluation ---")
    df_dedup = df_cic.drop_duplicates(subset=cic_feat_all).copy()
    y_dedup = (df_dedup["Label"] == "Bot").astype(int)
    print(f"De-duplicated rows: {len(df_dedup)} (Benign: {(y_dedup==0).sum()}, Bot: {(y_dedup==1).sum()})")

    X_train_c4, X_test_c4, y_train_c4, y_test_c4 = train_test_split(
        df_dedup[cic_feat_no_port], y_dedup, test_size=0.20, random_state=RANDOM_STATE, stratify=y_dedup
    )
    pipe_c4 = build_audit_pipeline(cic_feat_no_port, [])
    pipe_c4.fit(X_train_c4, y_train_c4)
    preds_c4 = pipe_c4.predict(X_test_c4)
    probs_c4 = pipe_c4.predict_proba(X_test_c4)[:, 1]
    m_c4 = compute_metrics(y_test_c4.values, preds_c4, probs_c4, positive_label=1)
    print(f"CICIDS C4 (De-duplicated, port excluded): Acc={m_c4['accuracy']:.5f}, F1={m_c4['macro_f1']:.5f}, ROC-AUC={m_c4['roc_auc']:.6f}")
    cic_experiments["C4_deduplicated_port_excluded"] = {
        "description": "De-duplicated dataset with exact duplicate feature rows removed (67 features, port excluded)",
        "feature_count": len(cic_feat_no_port),
        "test_rows": len(y_test_c4),
        "metrics": m_c4,
    }

    # Experiment C5: Strict Chronological Split (Train 70% earlier, Test 30% later)
    print("\n--- Chronological Split CICIDS Evaluation ---")
    df_sample = pd.read_csv(CIC_SAMPLE_TS, low_memory=False)
    df_sample.columns = df_sample.columns.str.strip()
    df_sample["ts_parsed"] = pd.to_datetime(df_sample["Timestamp"], errors="coerce")
    df_sample = df_sample.dropna(subset=["ts_parsed", "Label"]).sort_values("ts_parsed").reset_index(drop=True)

    for c in cic_feat_no_port:
        if c in df_sample.columns:
            df_sample[c] = pd.to_numeric(df_sample[c], errors="coerce").replace([np.inf, -np.inf], np.nan)

    split_idx = int(len(df_sample) * 0.70)
    train_chrono = df_sample.iloc[:split_idx]
    test_chrono = df_sample.iloc[split_idx:]

    y_train_chrono = (train_chrono["Label"] == "Bot").astype(int)
    y_test_chrono = (test_chrono["Label"] == "Bot").astype(int)

    pipe_chrono = build_audit_pipeline(cic_feat_no_port, [])
    pipe_chrono.fit(train_chrono[cic_feat_no_port], y_train_chrono)
    preds_chrono = pipe_chrono.predict(test_chrono[cic_feat_no_port])
    probs_chrono = pipe_chrono.predict_proba(test_chrono[cic_feat_no_port])[:, 1]
    m_c5 = compute_metrics(y_test_chrono.values, preds_chrono, probs_chrono, positive_label=1)
    print(f"CICIDS C5 (Strict Chronological 70/30, port excluded): Acc={m_c5['accuracy']:.5f}, Bal Acc={m_c5['balanced_accuracy']:.5f}, F1={m_c5['macro_f1']:.5f}")
    cic_experiments["C5_chronological_70_30_port_excluded"] = {
        "description": "Strict Chronological 70/30 split (train earlier 70%, test later 30%, port excluded)",
        "feature_count": len(cic_feat_no_port),
        "train_rows": len(train_chrono),
        "test_rows": len(test_chrono),
        "train_time_range": f"{train_chrono['ts_parsed'].min()} to {train_chrono['ts_parsed'].max()}",
        "test_time_range": f"{test_chrono['ts_parsed'].min()} to {test_chrono['ts_parsed'].max()}",
        "metrics": m_c5,
    }

    # =========================================================================
    # PART 4: SAVE MACHINE-READABLE AUDIT RESULTS
    # =========================================================================
    audit_summary = {
        "audit_version": "3.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tqh_c2_testbed_a_ablations": tqh_results,
        "cross_testbed_evaluation": cross_testbed_results,
        "cicids2018_evaluations": cic_experiments,
    }

    json_path = AUDIT_DIR / "phase3_audit_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2)
    print(f"\nSaved comprehensive JSON results to: {json_path}")

    # Build comparative summary CSV table for TQH ablations
    tqh_summary_rows = []
    for r in tqh_results:
        oof = r["oof_metrics"]
        tqh_summary_rows.append({
            "Experiment": r["config_name"],
            "Description": r["description"],
            "Features": r["feature_count"],
            "Mean_Accuracy": r["mean_accuracy"],
            "Std_Accuracy": r["std_accuracy"],
            "Mean_Bal_Accuracy": r["mean_balanced_accuracy"],
            "Std_Bal_Accuracy": r["std_balanced_accuracy"],
            "Mean_Macro_F1": r["mean_macro_f1"],
            "Std_Macro_F1": r["std_macro_f1"],
            "Mean_ROC_AUC": r["mean_roc_auc"],
            "Std_ROC_AUC": r["std_roc_auc"],
            "OOF_FPR": oof["fpr"],
            "OOF_FN": oof["fn"],
            "OOF_FP": oof["fp"],
        })
    df_tqh_summary = pd.DataFrame(tqh_summary_rows)
    tqh_csv_path = AUDIT_DIR / "tqh_c2_ablation_summary.csv"
    df_tqh_summary.to_csv(tqh_csv_path, index=False)
    print(f"Saved TQH ablation summary CSV to: {tqh_csv_path}")

    # Build comparative summary CSV table for CICIDS evaluations
    cic_summary_rows = []
    for k, v in cic_experiments.items():
        m = v["metrics"]
        cic_summary_rows.append({
            "Experiment": k,
            "Description": v["description"],
            "Features": v["feature_count"],
            "Test_Rows": v.get("test_rows"),
            "Accuracy": m["accuracy"],
            "Balanced_Accuracy": m["balanced_accuracy"],
            "Macro_F1": m["macro_f1"],
            "Precision_Macro": m["precision_macro"],
            "Recall_Macro": m["recall_macro"],
            "FPR": m["fpr"],
            "ROC_AUC": m["roc_auc"],
            "TN": m["tn"],
            "FP": m["fp"],
            "FN": m["fn"],
            "TP": m["tp"],
        })
    df_cic_summary = pd.DataFrame(cic_summary_rows)
    cic_csv_path = AUDIT_DIR / "cicids2018_audit_summary.csv"
    df_cic_summary.to_csv(cic_csv_path, index=False)
    print(f"Saved CICIDS summary CSV to: {cic_csv_path}")

    print("\nPhase 3 Audit Experiment Suite successfully executed.")


if __name__ == "__main__":
    main()
