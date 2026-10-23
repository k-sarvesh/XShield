
from pathlib import Path

import numpy as np
import pandas as pd

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

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "sample.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

required = {"Label", "Timestamp"}
missing = required - set(df.columns)
if missing:
    raise ValueError(f"Missing required columns: {missing}")

df["Timestamp"] = pd.to_datetime(
    df["Timestamp"], errors="coerce"
)
df["Label"] = df["Label"].astype(str).str.strip()
df = df.dropna(subset=["Timestamp", "Label"]).copy()

# Sort chronologically before choosing the cutoff.
df = df.sort_values("Timestamp").reset_index(drop=True)

# Use time for splitting only, never as a model feature.
excluded_terms = [
    "timestamp", "flow id", "flow_id",
    "src ip", "dst ip", "source ip", "destination ip",
    "src address", "dst address",
    "source address", "destination address",
]

excluded = [
    c for c in df.columns
    if c != "Label"
    and any(term in c.lower() for term in excluded_terms)
]

X = df.drop(columns=["Label"] + excluded).copy()
for col in X.columns:
    X[col] = pd.to_numeric(X[col], errors="coerce")

X = X.replace([np.inf, -np.inf], np.nan)
X = X.drop(columns=[
    c for c in X.columns if X[c].notna().sum() == 0
])

encoder = LabelEncoder()
y = encoder.fit_transform(df["Label"])

# Chronological 70/30 split.
cutoff_index = int(len(df) * 0.70)
if cutoff_index <= 0 or cutoff_index >= len(df):
    raise ValueError("Not enough rows for temporal evaluation.")

X_train = X.iloc[:cutoff_index]
X_test = X.iloc[cutoff_index:]
y_train = y[:cutoff_index]
y_test = y[cutoff_index:]

train_labels = df["Label"].iloc[:cutoff_index]
test_labels = df["Label"].iloc[cutoff_index:]

print("\n========== TEMPORAL EVALUATION ==========")
print("Rows:", len(df))
print("Features:", X.shape[1])
print("Train period:", df["Timestamp"].iloc[0],
      "to", df["Timestamp"].iloc[cutoff_index - 1])
print("Test period:", df["Timestamp"].iloc[cutoff_index],
      "to", df["Timestamp"].iloc[-1])
print("Train label counts:")
print(train_labels.value_counts())
print("Test label counts:")
print(test_labels.value_counts())

if len(np.unique(y_train)) < 2:
    raise ValueError(
        "Training period contains only one class. "
        "A meaningful binary classifier cannot be trained. "
        "Inspect the time distribution before changing the split."
    )

if len(np.unique(y_test)) < 2:
    print(
        "\nWARNING: Test period contains only one class. "
        "ROC-AUC and balanced evaluation may be uninformative."
    )

model = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("classifier", RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )),
])

model.fit(X_train, y_train)
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)

print("\n========== TEST RESULTS ==========")
print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
print(
    "Balanced accuracy: "
    f"{balanced_accuracy_score(y_test, predictions):.4f}"
)
print(
    "Macro F1: "
    f"{f1_score(y_test, predictions, average='macro', zero_division=0):.4f}"
)

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=list(range(len(encoder.classes_))),
    target_names=encoder.classes_.tolist(),
    zero_division=0,
))

print("Confusion matrix:")
print("Class order:", encoder.classes_.tolist())
print(confusion_matrix(
    y_test,
    predictions,
    labels=list(range(len(encoder.classes_))),
))

auc = None
if len(np.unique(y_test)) == 2:
    # Locate the probability column for encoded class 1.
    auc = roc_auc_score(y_test, probabilities[:, 1])
    print(f"ROC-AUC: {auc:.4f}")
else:
    print("ROC-AUC: not calculated (test has one class)")

results = {
    "experiment": "chronological_70_30_split",
    "dataset": DATA_PATH.name,
    "train_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "train_start": str(df["Timestamp"].iloc[0]),
    "train_end": str(df["Timestamp"].iloc[cutoff_index - 1]),
    "test_start": str(df["Timestamp"].iloc[cutoff_index]),
    "test_end": str(df["Timestamp"].iloc[-1]),
    "train_label_counts": {
        str(k): int(v) for k, v in train_labels.value_counts().items()
    },
    "test_label_counts": {
        str(k): int(v) for k, v in test_labels.value_counts().items()
    },
    "features": X.columns.tolist(),
    "accuracy": float(accuracy_score(y_test, predictions)),
    "balanced_accuracy": float(
        balanced_accuracy_score(y_test, predictions)
    ),
    "macro_f1": float(
        f1_score(y_test, predictions, average="macro", zero_division=0)
    ),
    "roc_auc": float(auc) if auc is not None else None,
    "class_order": encoder.classes_.tolist(),
    "confusion_matrix": confusion_matrix(
        y_test, predictions,
        labels=list(range(len(encoder.classes_)))
    ).tolist(),
    "note": (
        "Chronological split within one sampled dataset file; "
        "not an independent-dataset evaluation."
    ),
}

report_path = REPORT_DIR / "temporal_evaluation.json"
pd.Series(results).to_json(report_path, indent=2)
print(f"\nSaved report to: {report_path}")
