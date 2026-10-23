
from pathlib import Path

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
    f1_score,
    roc_auc_score,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "sample_clean.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()
df = df.dropna(subset=["Label"]).copy()
df["Label"] = df["Label"].astype(str).str.strip()

# Exclude identifiers, not ordinary numeric traffic features.
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

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Create feature groups based on column names.
dst_port_cols = [
    c for c in X.columns if c.strip().lower() == "dst port"
]

packet_rate_cols = [
    c for c in X.columns
    if any(term in c.lower() for term in [
        "pkts/s", "pkt/s", "bytes/s", "byts/s",
        "packet rate", "flow rate",
    ])
]

experiments = {
    "all_features": list(X.columns),
    "without_dst_port": [
        c for c in X.columns if c not in dst_port_cols
    ],
    "dst_port_only": dst_port_cols,
    "without_dst_port_and_rate_features": [
        c for c in X.columns
        if c not in set(dst_port_cols + packet_rate_cols)
    ],
}

results = []

print("Classes:", encoder.classes_.tolist())
print("Rows:", len(X))
print("Detected Dst Port columns:", dst_port_cols)
print("Detected packet-rate columns:", packet_rate_cols)

for experiment_name, columns in experiments.items():
    if not columns:
        print(f"\nSkipping {experiment_name}: no features available")
        continue

    train_subset = X_train[columns]
    test_subset = X_test[columns]

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        )),
    ])

    model.fit(train_subset, y_train)
    predictions = model.predict(test_subset)
    probabilities = model.predict_proba(test_subset)

    accuracy = accuracy_score(y_test, predictions)
    balanced_acc = balanced_accuracy_score(y_test, predictions)
    macro_f1 = f1_score(
        y_test, predictions, average="macro", zero_division=0
    )
    auc = roc_auc_score(y_test, probabilities[:, 1])

    row = {
        "experiment": experiment_name,
        "feature_count": len(columns),
        "accuracy": accuracy,
        "balanced_accuracy": balanced_acc,
        "macro_f1": macro_f1,
        "roc_auc": auc,
    }
    results.append(row)

    print(f"\n--- {experiment_name} ---")
    print("Feature count:", len(columns))
    print(f"Accuracy:          {accuracy:.4f}")
    print(f"Balanced accuracy: {balanced_acc:.4f}")
    print(f"Macro F1:          {macro_f1:.4f}")
    print(f"ROC-AUC:           {auc:.4f}")

results_df = pd.DataFrame(results)
print("\n========== COMPARISON ==========")
print(results_df.to_string(index=False))

output_path = REPORT_DIR / "feature_ablation.csv"
results_df.to_csv(output_path, index=False)
print(f"\nSaved comparison to: {output_path}")
