
from pathlib import Path
import json

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

# ----------------------------
# 1. Paths and configuration
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "sample_clean.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

TARGET = "Label"
RANDOM_STATE = 42

# ----------------------------
# 2. Load and validate data
# ----------------------------
if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATA_PATH}\n"
        "Check that data/sample_clean.csv exists."
    )

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

if TARGET not in df.columns:
    raise ValueError(
        f"Target column '{TARGET}' not found. "
        f"Available columns: {df.columns.tolist()}"
    )

df = df.dropna(subset=[TARGET]).copy()
df[TARGET] = df[TARGET].astype(str).str.strip()

# Exclude identifiers that can encourage memorization.
excluded_terms = [
    "timestamp",
    "flow id",
    "flow_id",
    "src ip",
    "dst ip",
    "source ip",
    "destination ip",
    "src address",
    "dst address",
    "source address",
    "destination address",
]

excluded_columns = [
    col for col in df.columns
    if col != TARGET
    and any(term in col.lower() for term in excluded_terms)
]

candidate_features = [
    col for col in df.columns
    if col != TARGET and col not in excluded_columns
]

# Use numeric traffic features for this first baseline.
X = df[candidate_features].copy()

for col in X.columns:
    X[col] = pd.to_numeric(X[col], errors="coerce")

X = X.replace([np.inf, -np.inf], np.nan)

# Drop columns that contain no usable numeric values.
unusable_columns = [
    col for col in X.columns if X[col].notna().sum() == 0
]
X = X.drop(columns=unusable_columns)

if X.shape[1] == 0:
    raise ValueError("No usable numeric features remain after cleaning.")

y_text = df[TARGET]
encoder = LabelEncoder()
y = encoder.fit_transform(y_text)

if len(encoder.classes_) < 2:
    raise ValueError("At least two label classes are required.")

class_counts = y_text.value_counts().to_dict()

print("\n========== XSHIELD BASELINE ==========")
print(f"Dataset: {DATA_PATH.name}")
print(f"Rows: {len(df):,}")
print(f"Features used: {X.shape[1]}")
print(f"Excluded identifier columns: {excluded_columns}")
print(f"Unusable columns dropped: {unusable_columns}")
print(f"Class distribution: {class_counts}")

# ----------------------------
# 3. Split data
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y,
)

# ----------------------------
# 4. Train baseline model
# ----------------------------
model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("classifier", RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )),
])

model.fit(X_train, y_train)

# ----------------------------
# 5. Evaluate on held-out test set
# ----------------------------
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)

class_ids = list(range(len(encoder.classes_)))

report = classification_report(
    y_test,
    predictions,
    labels=class_ids,
    target_names=encoder.classes_.tolist(),
    output_dict=True,
    zero_division=0,
)

matrix = confusion_matrix(
    y_test,
    predictions,
    labels=class_ids,
)

accuracy = accuracy_score(y_test, predictions)
balanced_accuracy = balanced_accuracy_score(y_test, predictions)
macro_f1 = f1_score(
    y_test, predictions, average="macro", zero_division=0
)
weighted_f1 = f1_score(
    y_test, predictions, average="weighted", zero_division=0
)

roc_auc = None
if len(encoder.classes_) == 2:
    roc_auc = roc_auc_score(y_test, probabilities[:, 1])

print("\n========== TEST RESULTS ==========")
print(f"Train rows: {len(X_train):,}")
print(f"Test rows:  {len(X_test):,}")
print(f"Accuracy:          {accuracy:.4f}")
print(f"Balanced accuracy: {balanced_accuracy:.4f}")
print(f"Macro F1:          {macro_f1:.4f}")
print(f"Weighted F1:       {weighted_f1:.4f}")

if roc_auc is not None:
    print(f"ROC-AUC:           {roc_auc:.4f}")

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=class_ids,
    target_names=encoder.classes_.tolist(),
    zero_division=0,
))

print("Confusion matrix (rows = actual, columns = predicted):")
print("Class order:", encoder.classes_.tolist())
print(matrix)

# ----------------------------
# 6. Save results as JSON
# ----------------------------
results = {
    "experiment": "random_forest_numeric_flow_baseline",
    "dataset": DATA_PATH.name,
    "random_state": RANDOM_STATE,
    "test_size": 0.20,
    "rows": int(len(df)),
    "train_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "feature_count": int(X.shape[1]),
    "features": X.columns.tolist(),
    "excluded_identifier_columns": excluded_columns,
    "unusable_columns_dropped": unusable_columns,
    "class_distribution": {
        str(k): int(v) for k, v in class_counts.items()
    },
    "class_order": encoder.classes_.tolist(),
    "accuracy": float(accuracy),
    "balanced_accuracy": float(balanced_accuracy),
    "macro_f1": float(macro_f1),
    "weighted_f1": float(weighted_f1),
    "roc_auc": float(roc_auc) if roc_auc is not None else None,
    "confusion_matrix": matrix.tolist(),
    "classification_report": report,
    "evaluation_note": (
        "Preliminary random split; not a session-aware or "
        "independent-dataset generalization evaluation."
    ),
}

report_path = REPORT_DIR / "baseline_validation.json"
with open(report_path, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)

print(f"\nSaved report to: {report_path}")
print("Baseline evaluation complete.")
