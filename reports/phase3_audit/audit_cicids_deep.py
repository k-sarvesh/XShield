"""Deep audit of CICIDS-2018 dataset for Phase 3 Research Audit."""

from pathlib import Path
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_DIR / "data"

# Check sample_clean.csv and sample.csv
clean_path = DATA_DIR / "sample_clean.csv"
sample_path = DATA_DIR / "sample.csv"

df_clean = pd.read_csv(clean_path, low_memory=False)
df_clean.columns = df_clean.columns.str.strip()

print(f"CICIDS-2018 sample_clean.csv rows: {len(df_clean)}, cols: {len(df_clean.columns)}")
print("Label distribution in sample_clean.csv:")
print(df_clean["Label"].value_counts())

# Check excluded terms
excluded_terms = [
    "timestamp", "flow id", "flow_id",
    "src ip", "dst ip", "source ip", "destination ip",
    "src address", "dst address",
    "source address", "destination address",
]
feature_cols_all = [
    c for c in df_clean.columns
    if c != "Label" and not any(term in c.lower() for term in excluded_terms)
]
print(f"\nFeature columns count: {len(feature_cols_all)}")
print(f"'Dst Port' in features: {'Dst Port' in feature_cols_all}")

# 1. Duplicate flow analysis
exact_full_dups = df_clean.duplicated().sum()
feature_dups = df_clean.duplicated(subset=feature_cols_all).sum()
print(f"\n--- 1. Duplicate Analysis ---")
print(f"Exact full-row duplicates in sample_clean.csv: {exact_full_dups} / {len(df_clean)} ({exact_full_dups/len(df_clean)*100:.2f}%)")
print(f"Exact duplicate feature vectors in sample_clean.csv: {feature_dups} / {len(df_clean)} ({feature_dups/len(df_clean)*100:.2f}%)")

dups_by_label = df_clean.groupby("Label").apply(lambda g: g.duplicated(subset=feature_cols_all).sum())
print("Duplicates within each class:")
print(dups_by_label)

# 2. Train/Test Overlap under 80/20 random stratified split
y = df_clean["Label"]
X = df_clean[feature_cols_all]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
train_hashes = pd.util.hash_pandas_object(X_train, index=False)
test_hashes = pd.util.hash_pandas_object(X_test, index=False)
train_hash_set = set(train_hashes.tolist())
test_hash_set = set(test_hashes.tolist())
overlap_hashes = train_hash_set.intersection(test_hash_set)
test_rows_in_train = test_hashes.isin(train_hash_set).sum()

print(f"\n--- 2. Random 80/20 Split Leakage ---")
print(f"Train rows: {len(X_train)}, Test rows: {len(X_test)}")
print(f"Unique feature vectors in train: {len(train_hash_set)}")
print(f"Unique feature vectors in test: {len(test_hash_set)}")
print(f"Shared feature vector hashes between train and test: {len(overlap_hashes)}")
print(f"Test rows that have an exact identical feature twin in the training set: {test_rows_in_train} / {len(X_test)} ({test_rows_in_train/len(X_test)*100:.2f}%)")

# 3. Destination Port analysis
print(f"\n--- 3. Destination Port (Dst Port) Shortcut Analysis ---")
port_ct = pd.crosstab(df_clean["Dst Port"], df_clean["Label"])
port_ct["Total"] = port_ct.sum(axis=1)
port_ct = port_ct.sort_values("Total", ascending=False)
print("Top 15 destination ports in CICIDS sample:")
print(port_ct.head(15))

# Check Bot concentration in ports
bot_total = (df_clean["Label"] == "Bot").sum()
benign_total = (df_clean["Label"] == "Benign").sum()
if 8080 in port_ct.index:
    print(f"\nPort 8080 flows: {port_ct.loc[8080].to_dict()}")
if 80 in port_ct.index:
    print(f"Port 80 flows: {port_ct.loc[80].to_dict()}")

# 4. Temporal inspection from sample.csv (which contains Timestamp)
if sample_path.exists():
    print(f"\n--- 4. Temporal Distribution in sample.csv ---")
    df_sample = pd.read_csv(sample_path, low_memory=False)
    df_sample.columns = df_sample.columns.str.strip()
    if "Timestamp" in df_sample.columns:
        ts = pd.to_datetime(df_sample["Timestamp"], errors="coerce")
        print(f"Valid timestamps: {ts.notna().sum()}/{len(ts)}")
        print(f"Min timestamp: {ts.min()}")
        print(f"Max timestamp: {ts.max()}")
        df_sample["ts_hour"] = ts.dt.floor("h")
        hour_cross = pd.crosstab(df_sample["ts_hour"], df_sample["Label"])
        print("\nFlows per hour by Label:")
        print(hour_cross)
