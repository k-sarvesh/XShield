"""Reproducible training and honest cross-validation evaluation script for Phase 1 models.

Trains, evaluates, and saves 4 distinct models under models/:
1. xshield_tqh_c2_port_inclusive.joblib
2. xshield_tqh_c2_port_excluded.joblib
3. xshield_cicids2018_port_inclusive.joblib
4. xshield_cicids2018_port_excluded.joblib

Also generates models/manifest.json and reports/phase1_port_comparison.json.
"""

import json
from pathlib import Path
import time
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, train_test_split

from xshield.datasets import load_cicids2018_sample, load_tqh_c2_testbed_a
from xshield.pipeline import build_pipeline, train_and_save_model

PROJECT_DIR = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_DIR / "models"
REPORTS_DIR = PROJECT_DIR / "reports"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def evaluate_tqh_c2_group_cv(X: pd.DataFrame, y: pd.Series, groups: pd.Series, port_policy: str, n_splits: int = 4):
    """Executes capture-group-aware cross-validation using GroupKFold."""
    print(f"\n{'='*70}")
    print(f"EVALUATING TQH-C2 ({port_policy.upper()}) VIA {n_splits}-FOLD GROUP-KFOLD")
    print(f"{'='*70}")
    print(f"Total flows: {len(X):,} | Capture sessions: {groups.nunique()}")
    print(f"Features ({X.shape[1]}): {X.columns.tolist()}")

    cat_cols = [c for c in X.columns if X[c].dtype == "object"]
    num_cols = [c for c in X.columns if c not in cat_cols]

    gkf = GroupKFold(n_splits=n_splits)
    classes = sorted(y.unique().tolist())
    pos_idx = classes.index("malicious_c2")

    fold_metrics = []
    all_y_true = []
    all_y_pred = []
    all_y_prob = []

    for fold, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups), start=1):
        X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
        y_tr, y_te = y.iloc[train_idx], y.iloc[test_idx]

        train_grps = set(groups.iloc[train_idx])
        test_grps = set(groups.iloc[test_idx])
        overlap = train_grps.intersection(test_grps)
        if overlap:
            raise RuntimeError(f"Group leakage detected in fold {fold}: {overlap}")

        pipe = build_pipeline(numeric_features=num_cols, categorical_features=cat_cols, random_state=42)
        pipe.fit(X_tr, y_tr)

        preds = pipe.predict(X_te)
        probs = pipe.predict_proba(X_te)[:, pos_idx]

        acc = accuracy_score(y_te, preds)
        bal_acc = balanced_accuracy_score(y_te, preds)
        p_mac, r_mac, f_mac, _ = precision_recall_fscore_support(y_te, preds, average="macro", zero_division=0)
        p_wt, r_wt, f_wt, _ = precision_recall_fscore_support(y_te, preds, average="weighted", zero_division=0)

        auc = roc_auc_score(y_te == "malicious_c2", probs) if y_te.nunique() == 2 else np.nan

        fold_metrics.append({
            "fold": fold,
            "train_samples": len(X_tr),
            "test_samples": len(X_te),
            "train_captures": len(train_grps),
            "test_captures": len(test_grps),
            "accuracy": float(acc),
            "balanced_accuracy": float(bal_acc),
            "macro_f1": float(f_mac),
            "weighted_f1": float(f_wt),
            "precision_weighted": float(p_wt),
            "recall_weighted": float(r_wt),
            "roc_auc": float(auc),
        })

        all_y_true.extend(y_te.tolist())
        all_y_pred.extend(preds.tolist())
        all_y_prob.extend(probs.tolist())

        print(f"Fold {fold}: Acc={acc:.4f} | BalAcc={bal_acc:.4f} | MacroF1={f_mac:.4f} | ROC-AUC={auc:.4f} "
              f"(Test captures: {sorted(list(test_grps))})")

    # Overall out-of-fold metrics
    oof_acc = accuracy_score(all_y_true, all_y_pred)
    oof_bal_acc = balanced_accuracy_score(all_y_true, all_y_pred)
    oof_p_mac, oof_r_mac, oof_f_mac, _ = precision_recall_fscore_support(all_y_true, all_y_pred, average="macro", zero_division=0)
    oof_p_wt, oof_r_wt, oof_f_wt, _ = precision_recall_fscore_support(all_y_true, all_y_pred, average="weighted", zero_division=0)
    oof_auc = roc_auc_score([1 if y == "malicious_c2" else 0 for y in all_y_true], all_y_prob)
    oof_cm = confusion_matrix(all_y_true, all_y_pred, labels=classes)
    oof_rep = classification_report(all_y_true, all_y_pred, labels=classes, target_names=classes, output_dict=True, zero_division=0)

    summary = {
        "evaluation_strategy": f"GroupKFold (n_splits={n_splits}, grouped by capture_id)",
        "folds": fold_metrics,
        "mean_accuracy": float(np.mean([f["accuracy"] for f in fold_metrics])),
        "std_accuracy": float(np.std([f["accuracy"] for f in fold_metrics])),
        "mean_balanced_accuracy": float(np.mean([f["balanced_accuracy"] for f in fold_metrics])),
        "std_balanced_accuracy": float(np.std([f["balanced_accuracy"] for f in fold_metrics])),
        "mean_macro_f1": float(np.mean([f["macro_f1"] for f in fold_metrics])),
        "std_macro_f1": float(np.std([f["macro_f1"] for f in fold_metrics])),
        "mean_roc_auc": float(np.nanmean([f["roc_auc"] for f in fold_metrics])),
        "std_roc_auc": float(np.nanstd([f["roc_auc"] for f in fold_metrics])),
        "out_of_fold_accuracy": float(oof_acc),
        "out_of_fold_balanced_accuracy": float(oof_bal_acc),
        "out_of_fold_macro_f1": float(oof_f_mac),
        "out_of_fold_weighted_f1": float(oof_f_wt),
        "out_of_fold_roc_auc": float(oof_auc),
        "confusion_matrix": oof_cm.tolist(),
        "classification_report": oof_rep,
        "classes": classes,
    }

    print("\n--- Out-of-fold aggregate summary ---")
    print(f"Accuracy:          {oof_acc:.4f} (folds mean: {summary['mean_accuracy']:.4f} +/- {summary['std_accuracy']:.4f})")
    print(f"Balanced Accuracy: {oof_bal_acc:.4f}")
    print(f"Macro F1:          {oof_f_mac:.4f}")
    print(f"Weighted F1:       {oof_f_wt:.4f}")
    print(f"ROC-AUC:           {oof_auc:.4f}")

    return summary


def evaluate_cicids_stratified(X: pd.DataFrame, y: pd.Series, port_policy: str):
    """Evaluates CICIDS-2018 benchmark using stratified train/test split."""
    print(f"\n{'='*70}")
    print(f"EVALUATING CICIDS-2018 ({port_policy.upper()}) VIA STRATIFIED 80/20 SPLIT")
    print(f"{'='*70}")
    print(f"Total flows: {len(X):,} | Features ({X.shape[1]}): {X.columns[:5].tolist()}... (+{X.shape[1]-5} more)")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    pipe = build_pipeline(numeric_features=list(X.columns), categorical_features=[], random_state=42)
    pipe.fit(X_tr, y_tr)

    classes = sorted(y.unique().tolist())
    preds = pipe.predict(X_te)
    probs = pipe.predict_proba(X_te)
    pos_idx = classes.index("Bot") if "Bot" in classes else 1

    acc = accuracy_score(y_te, preds)
    bal_acc = balanced_accuracy_score(y_te, preds)
    p_mac, r_mac, f_mac, _ = precision_recall_fscore_support(y_te, preds, average="macro", zero_division=0)
    p_wt, r_wt, f_wt, _ = precision_recall_fscore_support(y_te, preds, average="weighted", zero_division=0)
    auc = roc_auc_score(y_te == "Bot", probs[:, pos_idx])
    cm = confusion_matrix(y_te, preds, labels=classes)
    rep = classification_report(y_te, preds, labels=classes, target_names=classes, output_dict=True, zero_division=0)

    summary = {
        "evaluation_strategy": "Stratified train_test_split (test_size=0.20, random_state=42)",
        "train_samples": len(X_tr),
        "test_samples": len(X_te),
        "accuracy": float(acc),
        "balanced_accuracy": float(bal_acc),
        "macro_f1": float(f_mac),
        "weighted_f1": float(f_wt),
        "precision_weighted": float(p_wt),
        "recall_weighted": float(r_wt),
        "roc_auc": float(auc),
        "confusion_matrix": cm.tolist(),
        "classification_report": rep,
        "classes": classes,
    }

    print("\n--- Test set results ---")
    print(f"Accuracy:          {acc:.4f}")
    print(f"Balanced Accuracy: {bal_acc:.4f}")
    print(f"Macro F1:          {f_mac:.4f}")
    print(f"Weighted F1:       {f_wt:.4f}")
    print(f"ROC-AUC:           {auc:.4f}")

    return summary, pipe


def run_all_experiments():
    start_total = time.perf_counter()
    results_comparison = {}

    # ---------------------------------------------------------
    # 1. TQH-C2 Port-Inclusive
    # ---------------------------------------------------------
    X_tqh_inc, y_tqh_inc, groups_tqh_inc, meta_tqh_inc = load_tqh_c2_testbed_a(port_policy="port_inclusive")
    cv_tqh_inc = evaluate_tqh_c2_group_cv(X_tqh_inc, y_tqh_inc, groups_tqh_inc, "port_inclusive")

    model_tqh_inc = train_and_save_model(
        X=X_tqh_inc,
        y=y_tqh_inc,
        dataset_name="TQH-C2 Testbed A (Sliver TLS)",
        task_type="binary",
        port_policy="port_inclusive",
        model_name="xshield_tqh_c2_port_inclusive",
        excluded_features=meta_tqh_inc["excluded_features"],
        target_column="label_raw",
        positive_class="malicious_c2",
        evaluation_metrics=cv_tqh_inc,
        limitations=[
            "TQH-C2 Testbed A has Sliver C2 listening exclusively on port 8443, creating a strong shortcut in port-inclusive models.",
            "JA4 fingerprint for Sliver is static and distinct from benign clients in this capture environment.",
            "Group-aware cross-validation across 12 capture sessions demonstrates separation, but high scores reflect testbed consistency.",
        ],
    )
    results_comparison["tqh_c2_port_inclusive"] = {
        "dataset": "TQH-C2 Testbed A",
        "port_policy": "port_inclusive",
        "features_count": X_tqh_inc.shape[1],
        "accuracy": cv_tqh_inc["out_of_fold_accuracy"],
        "balanced_accuracy": cv_tqh_inc["out_of_fold_balanced_accuracy"],
        "macro_f1": cv_tqh_inc["out_of_fold_macro_f1"],
        "roc_auc": cv_tqh_inc["out_of_fold_roc_auc"],
        "evaluation": cv_tqh_inc["evaluation_strategy"],
    }

    # ---------------------------------------------------------
    # 2. TQH-C2 Port-Excluded
    # ---------------------------------------------------------
    X_tqh_exc, y_tqh_exc, groups_tqh_exc, meta_tqh_exc = load_tqh_c2_testbed_a(port_policy="port_excluded")
    cv_tqh_exc = evaluate_tqh_c2_group_cv(X_tqh_exc, y_tqh_exc, groups_tqh_exc, "port_excluded")

    model_tqh_exc = train_and_save_model(
        X=X_tqh_exc,
        y=y_tqh_exc,
        dataset_name="TQH-C2 Testbed A (Sliver TLS)",
        task_type="binary",
        port_policy="port_excluded",
        model_name="xshield_tqh_c2_port_excluded",
        excluded_features=meta_tqh_exc["excluded_features"],
        target_column="label_raw",
        positive_class="malicious_c2",
        evaluation_metrics=cv_tqh_exc,
        limitations=[
            "Excludes destination port (resp_p) and source port (orig_p) to prevent port memorization.",
            "JA4 client/server fingerprints remain visible features; fingerprint disparity can still provide strong separation.",
            "Demonstrates that detection without port numbers is viable using flow dynamics and TLS handshake fingerprints.",
        ],
    )
    results_comparison["tqh_c2_port_excluded"] = {
        "dataset": "TQH-C2 Testbed A",
        "port_policy": "port_excluded",
        "features_count": X_tqh_exc.shape[1],
        "accuracy": cv_tqh_exc["out_of_fold_accuracy"],
        "balanced_accuracy": cv_tqh_exc["out_of_fold_balanced_accuracy"],
        "macro_f1": cv_tqh_exc["out_of_fold_macro_f1"],
        "roc_auc": cv_tqh_exc["out_of_fold_roc_auc"],
        "evaluation": cv_tqh_exc["evaluation_strategy"],
    }

    # ---------------------------------------------------------
    # 3. CICIDS-2018 Port-Inclusive
    # ---------------------------------------------------------
    X_cic_inc, y_cic_inc, meta_cic_inc = load_cicids2018_sample(port_policy="port_inclusive")
    eval_cic_inc, fitted_pipe_inc = evaluate_cicids_stratified(X_cic_inc, y_cic_inc, "port_inclusive")

    model_cic_inc = train_and_save_model(
        X=X_cic_inc,
        y=y_cic_inc,
        dataset_name="CICIDS-2018 Botnet Sample",
        task_type="binary",
        port_policy="port_inclusive",
        model_name="xshield_cicids2018_port_inclusive",
        excluded_features=meta_cic_inc["excluded_features"],
        target_column="Label",
        positive_class="Bot",
        evaluation_metrics=eval_cic_inc,
        limitations=[
            "Port 8080 carries 98.6% of Bot flows and 0% of Benign flows, functioning as an artificial shortcut.",
            "Random split exhibits session/flow leakage (623 identical feature-row hashes across train and test).",
            "Near-100% metrics reflect dataset artifacts, not real-world botnet detection efficacy.",
        ],
    )
    results_comparison["cicids2018_port_inclusive"] = {
        "dataset": "CICIDS-2018",
        "port_policy": "port_inclusive",
        "features_count": X_cic_inc.shape[1],
        "accuracy": eval_cic_inc["accuracy"],
        "balanced_accuracy": eval_cic_inc["balanced_accuracy"],
        "macro_f1": eval_cic_inc["macro_f1"],
        "roc_auc": eval_cic_inc["roc_auc"],
        "evaluation": eval_cic_inc["evaluation_strategy"],
    }

    # ---------------------------------------------------------
    # 4. CICIDS-2018 Port-Excluded
    # ---------------------------------------------------------
    X_cic_exc, y_cic_exc, meta_cic_exc = load_cicids2018_sample(port_policy="port_excluded")
    eval_cic_exc, fitted_pipe_exc = evaluate_cicids_stratified(X_cic_exc, y_cic_exc, "port_excluded")

    model_cic_exc = train_and_save_model(
        X=X_cic_exc,
        y=y_cic_exc,
        dataset_name="CICIDS-2018 Botnet Sample",
        task_type="binary",
        port_policy="port_excluded",
        model_name="xshield_cicids2018_port_excluded",
        excluded_features=meta_cic_exc["excluded_features"],
        target_column="Label",
        positive_class="Bot",
        evaluation_metrics=eval_cic_exc,
        limitations=[
            "Destination port ('Dst Port') is strictly excluded from features.",
            "Flow statistical rate features (Flow Pkts/s, Fwd Pkts/s) still allow strong separation due to batch attack generation.",
            "Benchmark only; does not contain TLS handshake metadata.",
        ],
    )
    results_comparison["cicids2018_port_excluded"] = {
        "dataset": "CICIDS-2018",
        "port_policy": "port_excluded",
        "features_count": X_cic_exc.shape[1],
        "accuracy": eval_cic_exc["accuracy"],
        "balanced_accuracy": eval_cic_exc["balanced_accuracy"],
        "macro_f1": eval_cic_exc["macro_f1"],
        "roc_auc": eval_cic_exc["roc_auc"],
        "evaluation": eval_cic_exc["evaluation_strategy"],
    }

    # Save summary report
    report_file = REPORTS_DIR / "phase1_port_comparison.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results_comparison, f, indent=2)

    total_time = time.perf_counter() - start_total
    print(f"\n{'='*70}")
    print(f"ALL 4 PHASE 1 EXPERIMENTS COMPLETED IN {total_time:.2f}s")
    print(f"Report saved to: {report_file}")
    print(f"{'='*70}")
    print(pd.DataFrame(results_comparison).T.to_string())


if __name__ == "__main__":
    run_all_experiments()
