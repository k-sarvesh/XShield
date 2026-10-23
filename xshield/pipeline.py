"""Core ML pipeline, model persistence, and inference engine for XShield.

Provides:
- XShieldModel: composite estimator + authoritative schema metadata wrapper.
- train_and_save_model(): fits and persists pipeline + metadata.
- load_model(): safe, verified loading of model artifacts.
- predict_flows(): unlabelled flow scoring, class probability, and risk score generation.
- evaluate_model(): comprehensive metrics evaluation.
- run_experiment(): backward-compatible baseline execution for app.py.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
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
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
MODELS_DIR = PROJECT_DIR / "models"


class XShieldModel:
    """Encapsulates a fitted scikit-learn Pipeline and its metadata.

    Ensures strict schema validation, column order preservation,
    and safe inference on unlabelled network traffic.
    """

    def __init__(self, pipeline: Pipeline, metadata: Dict[str, Any]):
        self.pipeline = pipeline
        self.metadata = metadata

    @property
    def model_name(self) -> str:
        return self.metadata.get("model_name", "unnamed_model")

    @property
    def feature_names(self) -> List[str]:
        return list(self.metadata.get("feature_names", []))

    @property
    def classes(self) -> List[str]:
        return list(self.metadata.get("classes", []))

    @property
    def positive_class(self) -> Optional[str]:
        return self.metadata.get("positive_class")

    @property
    def task_type(self) -> str:
        return self.metadata.get("task_type", "binary")

    @property
    def port_policy(self) -> str:
        return self.metadata.get("port_policy", "unknown")

    def validate_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Validates that all required feature columns exist and orders them exactly.

        Args:
            df: Input dataframe (labelled or unlabelled).

        Returns:
            Preprocessed DataFrame with exact feature columns in model order.

        Raises:
            ValueError: If input is empty or required features are missing.
        """
        if df is None or len(df) == 0:
            raise ValueError("Input DataFrame is empty or None; cannot run inference.")

        expected = self.feature_names
        current_cols = set(df.columns)
        missing = [c for c in expected if c not in current_cols]
        if missing:
            raise ValueError(
                f"Missing {len(missing)} required feature column(s) for model '{self.model_name}':\n"
                f"  Missing: {missing}\n"
                f"  Expected schema ({len(expected)} features): {expected}"
            )

        # Select only expected columns in authoritative training order
        X = df[expected].copy()

        # Sanitize types according to metadata
        cat_features = set(self.metadata.get("categorical_features", []))
        num_features = set(self.metadata.get("numeric_features", []))

        for col in X.columns:
            if col in cat_features:
                X[col] = X[col].astype(object)
                X[col] = X[col].where(pd.notna(X[col]), np.nan)
                X[col] = X[col].map(lambda val: val.strip() if isinstance(val, str) else val)
                X[col] = X[col].replace("", np.nan)
            elif col in num_features or col not in cat_features:
                X[col] = pd.to_numeric(X[col], errors="coerce")
                X[col] = X[col].replace([np.inf, -np.inf], np.nan)

        return X

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Predicts discrete class labels for input flows."""
        X_valid = self.validate_features(df)
        return self.pipeline.predict(X_valid)

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Predicts class probability distributions for input flows."""
        X_valid = self.validate_features(df)
        if not hasattr(self.pipeline, "predict_proba"):
            raise AttributeError(f"Model '{self.model_name}' does not support probability estimation.")
        return self.pipeline.predict_proba(X_valid)

    def predict_flows(self, df: pd.DataFrame) -> pd.DataFrame:
        """Performs structured inference on unlabelled or labelled network flows.

        Returns:
            DataFrame containing:
            - predicted_label: Most likely class name
            - risk_score: Uncalibrated confidence score in [0.0, 1.0] indicating suspicion
            - risk_level: Categorical risk tier ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            - prob_<class>: Probability for each known class
        """
        X_valid = self.validate_features(df)
        preds = self.pipeline.predict(X_valid)

        results = pd.DataFrame(index=df.index)
        results["predicted_label"] = preds

        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(X_valid)
            model_classes = list(self.pipeline.named_steps["classifier"].classes_)

            # Store per-class probabilities
            for idx, cls_name in enumerate(model_classes):
                clean_cls = str(cls_name).replace(" ", "_").lower()
                results[f"prob_{clean_cls}"] = probs[:, idx]

            # Compute uncalibrated risk score
            # If positive_class is known, risk_score is probability of that class.
            # Otherwise, if 'benign' exists, risk_score is 1.0 - prob_benign.
            pos_cls = self.positive_class
            if pos_cls and pos_cls in model_classes:
                pos_idx = model_classes.index(pos_cls)
                results["risk_score"] = probs[:, pos_idx]
            else:
                benign_matches = [i for i, c in enumerate(model_classes) if str(c).lower() == "benign"]
                if benign_matches:
                    results["risk_score"] = 1.0 - probs[:, benign_matches[0]]
                else:
                    results["risk_score"] = probs.max(axis=1)

            # Assign human-readable risk levels
            def assign_risk_tier(score: float) -> str:
                if score < 0.35:
                    return "LOW"
                elif score < 0.65:
                    return "MEDIUM"
                elif score < 0.85:
                    return "HIGH"
                else:
                    return "CRITICAL"

            results["risk_level"] = results["risk_score"].map(assign_risk_tier)
        else:
            results["risk_score"] = np.nan
            results["risk_level"] = "UNKNOWN"

        return results

    def save(
        self,
        filepath: Optional[Union[str, Path]] = None,
        models_dir: Path = MODELS_DIR,
        output_dir: Optional[Path] = None,
    ) -> Tuple[Path, Path]:
        """Persists the fitted pipeline via joblib and metadata via companion JSON."""
        target_dir = output_dir if output_dir is not None else models_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        if filepath is None:
            joblib_path = target_dir / f"{self.model_name}.joblib"
        else:
            joblib_path = Path(filepath)
            if not joblib_path.is_absolute():
                joblib_path = target_dir / joblib_path

        if not joblib_path.name.endswith(".joblib"):
            joblib_path = joblib_path.with_suffix(".joblib")

        json_path = joblib_path.with_name(f"{joblib_path.stem}_metadata.json")

        joblib.dump(self.pipeline, joblib_path)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        _update_manifest(target_dir, self.metadata, joblib_path)
        return joblib_path, json_path

    @classmethod
    def load(cls, filepath: Union[str, Path], models_dir: Path = MODELS_DIR) -> "XShieldModel":
        """Safely loads a verified XShield model artifact from disk."""
        target = Path(filepath)
        if not target.is_absolute():
            target = models_dir / target

        if not target.name.endswith(".joblib"):
            target = target.with_suffix(".joblib")

        # Security check: Ensure resolved target is within trusted models directory
        resolved_models_dir = models_dir.resolve()
        resolved_target = target.resolve()

        if not str(resolved_target).startswith(str(resolved_models_dir)):
            # If specified outside models_dir, only permit if file exists and is explicitly trusted
            if not resolved_target.exists():
                raise PermissionError(f"Attempted to load model from outside models directory: {resolved_target}")

        if not resolved_target.exists():
            raise FileNotFoundError(f"Model artifact not found: {resolved_target}")

        json_path = resolved_target.with_name(f"{resolved_target.stem}_metadata.json")
        if not json_path.exists():
            raise FileNotFoundError(f"Model metadata companion file not found: {json_path}")

        pipeline = joblib.load(resolved_target)
        with open(json_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        return cls(pipeline, metadata)


def build_pipeline(
    numeric_features: List[str],
    categorical_features: List[str],
    n_estimators: int = 150,
    random_state: int = 42,
    min_samples_leaf: int = 2,
    class_weight: str = "balanced_subsample",
) -> Pipeline:
    """Constructs a composite preprocessing + classifier pipeline.

    - Fits imputers and encoders only on training data.
    - Handles numeric missing values with median imputation.
    - Handles categorical missing values with most-frequent imputation and ignore-unknown one-hot encoding.
    """
    transformers = []
    if numeric_features:
        num_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
        ])
        transformers.append(("num", num_pipe, numeric_features))

    if categorical_features:
        cat_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent", missing_values=np.nan)),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])
        transformers.append(("cat", cat_pipe, categorical_features))

    preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")

    classifier = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        min_samples_leaf=min_samples_leaf,
        class_weight=class_weight,
        n_jobs=-1,
    )

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier),
    ])


def train_and_save_model(
    X: pd.DataFrame,
    y: Union[pd.Series, np.ndarray],
    dataset_name: str,
    task_type: str,
    port_policy: str,
    model_name: Optional[str] = None,
    excluded_features: Optional[List[str]] = None,
    target_column: Optional[str] = "label",
    positive_class: Optional[str] = None,
    evaluation_metrics: Optional[Dict[str, Any]] = None,
    limitations: Optional[List[str]] = None,
    random_state: int = 42,
    output_dir: Path = MODELS_DIR,
) -> XShieldModel:
    """Trains a complete model pipeline on provided data and persists artifact with metadata."""
    if model_name is None:
        clean_ds = dataset_name.lower().replace(" ", "_").replace("-", "_")
        model_name = f"xshield_{clean_ds}_{port_policy}"

    feature_names = list(X.columns)

    # Determine numeric vs categorical
    cat_features = [
        col for col in feature_names
        if (
            pd.api.types.is_object_dtype(X[col])
            or isinstance(X[col].dtype, pd.CategoricalDtype)
            or pd.api.types.is_string_dtype(X[col])
            or col in ["orig_p", "resp_p", "proto"]
        )
    ]
    num_features = [c for c in feature_names if c not in cat_features]

    pipeline = build_pipeline(
        numeric_features=num_features,
        categorical_features=cat_features,
        random_state=random_state,
    )

    start_time = time.perf_counter()
    pipeline.fit(X, y)
    fit_duration = time.perf_counter() - start_time

    classes = [str(c) for c in pipeline.named_steps["classifier"].classes_]

    if positive_class is None:
        for c in classes:
            if str(c).lower() in ["malicious_c2", "bot", "malicious", "attack", "1"]:
                positive_class = str(c)
                break

    metadata = {
        "model_name": model_name,
        "model_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_name": dataset_name,
        "task_type": task_type,
        "port_policy": port_policy,
        "target_column": target_column,
        "classes": classes,
        "positive_class": positive_class,
        "train_rows": len(X),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "numeric_features": num_features,
        "categorical_features": cat_features,
        "excluded_features": excluded_features or [],
        "training_config": {
            "algorithm": "RandomForestClassifier",
            "n_estimators": 150,
            "min_samples_leaf": 2,
            "random_state": random_state,
            "class_weight": "balanced_subsample",
            "fit_seconds": round(fit_duration, 3),
        },
        "evaluation_metrics": evaluation_metrics or {},
        "limitations": limitations or [
            "Model scores are uncalibrated probabilities, not ground-truth verdicts.",
            "Predictions indicate statistical suspicion based on metadata; does not decrypt payload.",
            "Trained and evaluated on controlled capture testbeds.",
        ],
    }

    model = XShieldModel(pipeline, metadata)
    model.save(output_dir=output_dir)
    return model


def load_model(model_name_or_path: Union[str, Path], models_dir: Path = MODELS_DIR) -> XShieldModel:
    """Loads an XShield model by name (e.g. 'xshield_tqh_c2_port_inclusive') or path."""
    return XShieldModel.load(model_name_or_path, models_dir=models_dir)


def predict_flows(model_or_path: Union[XShieldModel, str, Path], df: pd.DataFrame) -> pd.DataFrame:
    """Convenience function to run inference using either a loaded model or artifact name."""
    if isinstance(model_or_path, (str, Path)):
        model = load_model(model_or_path)
    else:
        model = model_or_path
    return model.predict_flows(df)


def evaluate_model(
    model: XShieldModel,
    X_test: pd.DataFrame,
    y_test: Union[pd.Series, np.ndarray],
) -> Dict[str, Any]:
    """Computes comprehensive evaluation metrics on held-out test data."""
    preds = model.predict(X_test)
    y_test_str = pd.Series(y_test).astype(str).tolist()
    preds_str = [str(p) for p in preds]

    classes = model.classes
    acc = accuracy_score(y_test_str, preds_str)
    bal_acc = balanced_accuracy_score(y_test_str, preds_str)

    p_macro, r_macro, f_macro, _ = precision_recall_fscore_support(
        y_test_str, preds_str, average="macro", zero_division=0
    )
    p_wt, r_wt, f_wt, _ = precision_recall_fscore_support(
        y_test_str, preds_str, average="weighted", zero_division=0
    )

    cm = confusion_matrix(y_test_str, preds_str, labels=classes)
    rep = classification_report(
        y_test_str, preds_str, labels=classes, target_names=classes, output_dict=True, zero_division=0
    )

    roc_auc = None
    if hasattr(model.pipeline, "predict_proba") and len(classes) == 2:
        try:
            probs = model.predict_proba(X_test)
            pos_cls = model.positive_class or classes[1]
            pos_idx = classes.index(pos_cls)
            y_binary = [1 if val == pos_cls else 0 for val in y_test_str]
            if len(set(y_binary)) == 2:
                roc_auc = float(roc_auc_score(y_binary, probs[:, pos_idx]))
        except Exception:
            pass

    return {
        "accuracy": float(acc),
        "balanced_accuracy": float(bal_acc),
        "precision_macro": float(p_macro),
        "recall_macro": float(r_macro),
        "macro_f1": float(f_macro),
        "precision_weighted": float(p_wt),
        "recall_weighted": float(r_wt),
        "weighted_f1": float(f_wt),
        "roc_auc": roc_auc,
        "confusion_matrix": cm.tolist(),
        "classification_report": rep,
        "classes": classes,
        "test_samples": len(X_test),
    }


def run_experiment(
    df: pd.DataFrame,
    label_col: str,
    feature_cols: List[str],
    test_size: float = 0.2,
    save_model: bool = False,
    model_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Backward-compatible experiment runner for app.py.

    Trains and evaluates on a user-uploaded CSV with live metric output.
    """
    try:
        data = df[list(feature_cols) + [label_col]].copy()
        data = data.replace([np.inf, -np.inf], np.nan).dropna(subset=[label_col]).drop_duplicates()
        if len(data) < 20:
            return {
                "error": "Too few usable rows. Use at least 20 for a smoke test; meaningful research needs substantially more."
            }

        y = data[label_col].astype(str)
        if y.nunique() < 2:
            return {"error": "The selected label column has fewer than two classes."}

        X = data[list(feature_cols)].copy()
        X = X.dropna(axis=1, how="all")
        X = X.loc[:, X.nunique(dropna=False) > 1]
        if X.shape[1] == 0:
            return {"error": "No usable feature columns remain after removing empty/constant columns."}

        stratify = y if y.value_counts().min() >= 2 else None
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=test_size, random_state=42, stratify=stratify)

        active_features = list(X.columns)
        cat_features = [
            c for c in active_features
            if pd.api.types.is_object_dtype(X[c]) or str(X[c].dtype) in ["category", "string"]
        ]
        num_features = [c for c in active_features if c not in cat_features]

        pipeline = build_pipeline(
            numeric_features=num_features,
            categorical_features=cat_features,
            random_state=42,
        )

        start = time.perf_counter()
        pipeline.fit(Xtr, ytr)
        elapsed = time.perf_counter() - start

        preds = pipeline.predict(Xte)
        classes = sorted(y.unique().tolist())
        p, r, f, _ = precision_recall_fscore_support(yte, preds, average="weighted", zero_division=0)
        cm = confusion_matrix(yte, preds, labels=classes)
        report = classification_report(yte, preds, output_dict=True, zero_division=0)

        importance_rows = []
        try:
            names = pipeline.named_steps["preprocessor"].get_feature_names_out()
            vals = pipeline.named_steps["classifier"].feature_importances_
            tmp = pd.DataFrame({"encoded": names, "Importance": vals})

            def raw_name(name):
                name = name.split("__", 1)[-1]
                matches = [col for col in X.columns if name == col or name.startswith(str(col) + "_")]
                return max(matches, key=len) if matches else name

            tmp["Feature"] = tmp["encoded"].map(raw_name)
            grouped = tmp.groupby("Feature", as_index=False)["Importance"].sum().sort_values("Importance", ascending=False)
            importance_rows = grouped[["Feature", "Importance"]].values.tolist()
        except Exception:
            pass

        metrics = {
            "accuracy": float(accuracy_score(yte, preds)),
            "precision": float(p),
            "recall": float(r),
            "f1": float(f),
            "fit_and_predict_seconds": float(elapsed),
        }

        export = {
            "model": "RandomForestClassifier",
            "label_column": label_col,
            "feature_columns": list(X.columns),
            "rows_used": int(len(data)),
            "train_rows": int(len(Xtr)),
            "test_rows": int(len(Xte)),
            "classes": classes,
            "metrics": metrics,
            "confusion_matrix": cm.tolist(),
            "evaluation_note": "Baseline random split; inspect duplicates, leakage and group/time splitting before research claims.",
        }

        if save_model:
            model_wrapper = XShieldModel(
                pipeline,
                {
                    "model_name": model_name or "xshield_custom_baseline",
                    "model_version": "1.0.0",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "dataset_name": "User Upload",
                    "task_type": "binary" if len(classes) == 2 else "multiclass",
                    "port_policy": "custom",
                    "feature_names": list(X.columns),
                    "numeric_features": num_features,
                    "categorical_features": cat_features,
                    "classes": classes,
                    "evaluation_metrics": metrics,
                },
            )
            model_wrapper.save()

        return {
            "error": None,
            "metrics": metrics,
            "confusion": cm.tolist(),
            "class_names": classes,
            "report": report,
            "importance": importance_rows,
            "n_rows": len(data),
            "n_features": X.shape[1],
            "export": export,
        }
    except Exception as e:
        return {"error": f"Experiment failed: {type(e).__name__}: {e}"}


def _update_manifest(models_dir: Path, metadata: Dict[str, Any], joblib_path: Path):
    """Updates models/manifest.json with catalog of saved models."""
    manifest_path = models_dir / "manifest.json"
    manifest = {"models": {}, "last_updated": datetime.now(timezone.utc).isoformat()}
    if manifest_path.exists():
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            pass

    model_key = metadata.get("model_name", joblib_path.stem)
    manifest.setdefault("models", {})[model_key] = {
        "model_name": model_key,
        "artifact_file": joblib_path.name,
        "metadata_file": f"{joblib_path.stem}_metadata.json",
        "dataset_name": metadata.get("dataset_name"),
        "port_policy": metadata.get("port_policy"),
        "task_type": metadata.get("task_type"),
        "feature_count": metadata.get("feature_count"),
        "classes": metadata.get("classes"),
        "created_at": metadata.get("created_at"),
        "evaluation_summary": {
            k: v for k, v in metadata.get("evaluation_metrics", {}).items()
            if isinstance(v, (int, float, str))
        },
    }
    manifest["last_updated"] = datetime.now(timezone.utc).isoformat()

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
