
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.pipeline import make_pipeline
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.preprocessing import LabelEncoder

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "sample_clean.csv"

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()
df = df.dropna(subset=["Label"]).copy()
df["Label"] = df["Label"].astype(str).str.strip()

# Match the numeric-feature approach used in the baseline.
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
    X, y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\n========== DATASET AUDIT ==========")
print("Classes:", encoder.classes_.tolist())
print("Rows:", len(X))
print("Numeric features:", X.shape[1])

# 1. Check identical feature vectors across train/test.
# Hashes are used to avoid copying a large dataframe into Python sets.
train_hashes = pd.util.hash_pandas_object(
    X_train, index=False
)
test_hashes = pd.util.hash_pandas_object(
    X_test, index=False
)

train_set = set(train_hashes.tolist())
test_set = set(test_hashes.tolist())
overlap = train_set.intersection(test_set)

print("\n--- Exact feature-row overlap ---")
print("Unique train feature rows:", len(train_set))
print("Unique test feature rows:", len(test_set))
print("Hash values shared across splits:", len(overlap))
print(
    "Note: shared feature rows can be legitimate repeated "
    "traffic patterns; investigate before deciding."
)

# 2. See how well a shallow tree performs.
# A very strong shallow tree may indicate easy dataset-specific
# separation, but does not by itself prove label leakage.
print("\n--- Shallow decision-tree checks ---")

for depth in [1, 3]:
    simple_model = make_pipeline(
        SimpleImputer(strategy="median"),
        DecisionTreeClassifier(
            max_depth=depth,
            random_state=42,
            class_weight="balanced",
        ),
    )

    simple_model.fit(X_train, y_train)
    pred = simple_model.predict(X_test)

    print(
        f"Depth {depth}: "
        f"accuracy={accuracy_score(y_test, pred):.4f}"
    )

# 3. Identify features with suspiciously high single-feature AUC.
# This is a screening signal, not proof of leakage.
print("\n--- Strong individual features ---")
single_feature_results = []

for col in X.columns:
    train_col = X_train[col]
    test_col = X_test[col]

    # Skip features with no usable variation.
    if train_col.nunique(dropna=True) < 2:
        continue

    imputer = SimpleImputer(strategy="median")
    train_values = imputer.fit_transform(
        train_col.to_frame()
    ).ravel()
    test_values = imputer.transform(
        test_col.to_frame()
    ).ravel()

    if np.unique(train_values).size < 2:
        continue

    tree = DecisionTreeClassifier(
        max_depth=1, random_state=42
    )
    tree.fit(train_values.reshape(-1, 1), y_train)

    # Use predicted probabilities for the encoded positive class.
    probs = tree.predict_proba(
        test_values.reshape(-1, 1)
    )[:, 1]

    try:
        auc = roc_auc_score(y_test, probs)
        auc = max(auc, 1 - auc)
    except ValueError:
        continue

    single_feature_results.append((col, auc))

single_feature_results.sort(
    key=lambda item: item[1], reverse=True
)

for col, auc in single_feature_results[:15]:
    print(f"{col}: AUC={auc:.4f}")

print("\nAudit complete.")
print(
    "High scores are investigation clues, not automatic proof "
    "of data leakage."
)
