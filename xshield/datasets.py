"""Dataset loaders and schema definitions for XShield research experiments.

Maintains strict separation between:
1. TQH-C2 (Primary Encrypted C2 Traffic Dataset across TLS/QUIC/HTTP)
2. CICIDS-2018 (Secondary Statistical Flow Benchmark)
"""

from io import BytesIO
from pathlib import Path
from typing import Literal, Tuple
import zipfile
import numpy as np
import pandas as pd

# Default project paths
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
DATA_DIR = PROJECT_DIR / "data"

TQH_C2_ZIP_DEFAULT = DATA_DIR / "TQH-C2_features_v110.zip"
CICIDS_CSV_DEFAULT = DATA_DIR / "sample_clean.csv"

# Columns that MUST NEVER be used as model features
TQH_C2_EXCLUDED_ALWAYS = [
    "ts",                   # Raw timestamp
    "uid",                  # Zeek connection UID
    "orig_h",               # Originator (source) IP address
    "resp_h",               # Responder (destination) IP address
    "orig_p",               # Originator (client) ephemeral source port (identifier)
    "capture_id",           # Group identifier (used only for GroupKFold)
    "label_raw",            # Target label
    "y",                    # Target label (encoded)
    "profile",              # Experimental profile tag
    "encryption_profile",   # Experimental encryption tag
    "interval_s",           # Grid cell ground truth: beacon interval
    "jitter_pct",           # Grid cell ground truth: jitter percentage
    "ja4h",                 # Empty in Testbed A (HTTP only)
]

TQH_C2_PORT_COLUMNS = ["resp_p"]  # Destination / service port

CICIDS_IDENTIFIER_TERMS = [
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

CICIDS_PORT_COLUMNS = ["Dst Port"]


def load_tqh_c2_testbed_a(
    zip_path: Path = TQH_C2_ZIP_DEFAULT,
    port_policy: Literal["port_inclusive", "port_excluded"] = "port_inclusive",
) -> Tuple[pd.DataFrame, pd.Series, pd.Series, dict]:
    """Loads Testbed A from the TQH-C2 zip archive with strict leakage guards.

    Args:
        zip_path: Path to TQH-C2 zip file containing features/testbed_A.parquet.
        port_policy: 'port_inclusive' to keep resp_p and orig_p,
                     'port_excluded' to remove all port features.

    Returns:
        X: Feature DataFrame with clean dtypes and explicit ordering.
        y: Target Series (string classes: 'benign' and 'malicious_c2').
        groups: Group Series ('capture_id') for GroupKFold splitting.
        metadata: Summary dictionary documenting rows kept, dropped, and features.
    """
    if not zip_path.exists():
        raise FileNotFoundError(f"TQH-C2 dataset archive not found: {zip_path}")

    with zipfile.ZipFile(zip_path, "r") as archive:
        matches = [name for name in archive.namelist() if name.endswith("testbed_A.parquet")]
        if not matches:
            raise FileNotFoundError(f"testbed_A.parquet not found inside {zip_path}")
        with archive.open(matches[0]) as f:
            raw_df = pd.read_parquet(BytesIO(f.read()))

    initial_rows = len(raw_df)

    # Strictly filter for the binary task: benign vs malicious_c2
    allowed_labels = ["benign", "malicious_c2"]
    filtered_df = raw_df[raw_df["label_raw"].isin(allowed_labels)].copy()
    dropped_external_rows = initial_rows - len(filtered_df)

    # Drop any rows with missing essential identifiers
    filtered_df = filtered_df.dropna(subset=["label_raw", "capture_id"]).reset_index(drop=True)

    y = filtered_df["label_raw"].astype(str).str.strip()
    groups = filtered_df["capture_id"].astype(str)

    # Determine columns to exclude
    exclude_set = set(TQH_C2_EXCLUDED_ALWAYS)
    if port_policy == "port_excluded":
        exclude_set.update(TQH_C2_PORT_COLUMNS)

    feature_cols = [c for c in filtered_df.columns if c not in exclude_set]

    # Build X
    X = filtered_df[feature_cols].copy()

    # Distinguish categorical and numeric features
    cat_cols = []
    num_cols = []
    for col in X.columns:
        if (
            pd.api.types.is_object_dtype(X[col])
            or isinstance(X[col].dtype, pd.CategoricalDtype)
            or pd.api.types.is_string_dtype(X[col])
            or col in ["orig_p", "resp_p", "proto"]
        ):
            cat_cols.append(col)
        else:
            num_cols.append(col)

    # Clean categorical columns: convert pd.NA / empty strings to np.nan
    for col in cat_cols:
        X[col] = X[col].astype(object)
        X[col] = X[col].where(pd.notna(X[col]), np.nan)
        X[col] = X[col].map(lambda val: val.strip() if isinstance(val, str) else val)
        X[col] = X[col].replace("", np.nan)

    # Clean numeric columns: coerce non-numeric strings to np.nan, replace inf with nan
    for col in num_cols:
        X[col] = pd.to_numeric(X[col], errors="coerce")
        X[col] = X[col].replace([np.inf, -np.inf], np.nan)

    meta = {
        "dataset": "TQH-C2 Testbed A (Sliver TLS)",
        "initial_rows": initial_rows,
        "retained_rows": len(X),
        "dropped_rows": dropped_external_rows,
        "dropped_labels": ["benign_external"],
        "class_counts": y.value_counts().to_dict(),
        "capture_groups_count": groups.nunique(),
        "port_policy": port_policy,
        "feature_count": X.shape[1],
        "feature_names": X.columns.tolist(),
        "numeric_features": num_cols,
        "categorical_features": cat_cols,
        "excluded_features": sorted(list(exclude_set)),
    }

    return X, y, groups, meta


def load_cicids2018_sample(
    data_path: Path = CICIDS_CSV_DEFAULT,
    port_policy: Literal["port_inclusive", "port_excluded"] = "port_inclusive",
) -> Tuple[pd.DataFrame, pd.Series, dict]:
    """Loads the CICIDS-2018 sample benchmark dataset with strict leakage guards.

    Args:
        data_path: Path to sample_clean.csv.
        port_policy: 'port_inclusive' to keep 'Dst Port',
                     'port_excluded' to remove 'Dst Port'.

    Returns:
        X: Feature DataFrame with clean dtypes and explicit ordering.
        y: Target Series (string classes: e.g. 'Benign', 'Bot').
        metadata: Summary dictionary documenting features and configuration.
    """
    if not data_path.exists():
        raise FileNotFoundError(f"CICIDS-2018 dataset file not found: {data_path}")

    df = pd.read_csv(data_path, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError("Dataset missing 'Label' target column.")

    df = df.dropna(subset=["Label"]).copy()
    y = df["Label"].astype(str).str.strip()

    # Exclude identifiers
    excluded_columns = [
        col for col in df.columns
        if col != "Label" and any(term in col.lower() for term in CICIDS_IDENTIFIER_TERMS)
    ]

    if port_policy == "port_excluded":
        for col in CICIDS_PORT_COLUMNS:
            if col in df.columns and col not in excluded_columns:
                excluded_columns.append(col)

    feature_cols = [c for c in df.columns if c != "Label" and c not in excluded_columns]
    X = df[feature_cols].copy()

    # All CICIDS features are numeric flow statistics
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    meta = {
        "dataset": "CICIDS-2018 Botnet Sample",
        "rows": len(X),
        "class_counts": y.value_counts().to_dict(),
        "port_policy": port_policy,
        "feature_count": X.shape[1],
        "feature_names": X.columns.tolist(),
        "numeric_features": X.columns.tolist(),
        "categorical_features": [],
        "excluded_features": excluded_columns,
    }

    return X, y, meta
