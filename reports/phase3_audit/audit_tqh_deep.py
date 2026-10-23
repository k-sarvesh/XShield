"""Deep audit of TQH-C2 Testbed A dataset for Phase 3 Research Audit."""

from pathlib import Path
from io import BytesIO
import zipfile
import json
import pandas as pd
import numpy as np

PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_DIR / "data"
ZIP_PATH = DATA_DIR / "TQH-C2_features_v110.zip"

with zipfile.ZipFile(ZIP_PATH, "r") as archive:
    with archive.open("features/testbed_A.parquet") as f:
        df = pd.read_parquet(BytesIO(f.read()))

print(f"Total raw rows in testbed_A: {len(df)}")
print("Raw label counts:")
print(df["label_raw"].value_counts(dropna=False))

# Filter binary task
df_binary = df[df["label_raw"].isin(["benign", "malicious_c2"])].copy()
print(f"Retained binary rows: {len(df_binary)}")

print("\n--- 1. Capture Group Distribution ---")
capture_stats = []
for cid, grp in df_binary.groupby("capture_id"):
    b_count = (grp["label_raw"] == "benign").sum()
    c2_count = (grp["label_raw"] == "malicious_c2").sum()
    capture_stats.append({
        "capture_id": cid,
        "total_rows": len(grp),
        "benign_rows": int(b_count),
        "malicious_c2_rows": int(c2_count),
        "c2_ratio": round(c2_count / len(grp), 4)
    })
df_cap = pd.DataFrame(capture_stats)
print(df_cap.to_string(index=False))

print("\n--- 2. Port Analysis (resp_p) ---")
print("Top destination ports by label:")
port_cross = pd.crosstab(df_binary["resp_p"], df_binary["label_raw"], margins=True)
print(port_cross)

print("\n--- 3. JA4 and JA4S Fingerprint Analysis ---")
print(f"Unique JA4 in benign: {df_binary[df_binary['label_raw']=='benign']['ja4'].nunique(dropna=False)}")
print(f"Unique JA4 in malicious_c2: {df_binary[df_binary['label_raw']=='malicious_c2']['ja4'].nunique(dropna=False)}")
ja4_b = set(df_binary[df_binary['label_raw']=='benign']['ja4'].dropna().unique())
ja4_m = set(df_binary[df_binary['label_raw']=='malicious_c2']['ja4'].dropna().unique())
ja4_overlap = ja4_b.intersection(ja4_m)
print(f"JA4 overlap between classes: {len(ja4_overlap)} ({ja4_overlap})")
print(f"JA4 top values in malicious_c2:\n{df_binary[df_binary['label_raw']=='malicious_c2']['ja4'].value_counts(dropna=False).head(5)}")

print("\nJA4S Fingerprints:")
ja4s_b = set(df_binary[df_binary['label_raw']=='benign']['ja4s'].dropna().unique())
ja4s_m = set(df_binary[df_binary['label_raw']=='malicious_c2']['ja4s'].dropna().unique())
ja4s_overlap = ja4s_b.intersection(ja4s_m)
print(f"JA4S overlap between classes: {len(ja4s_overlap)} ({ja4s_overlap})")
print(f"JA4S top values in malicious_c2:\n{df_binary[df_binary['label_raw']=='malicious_c2']['ja4s'].value_counts(dropna=False).head(5)}")

print("\n--- 4. Connection State (conn_state) and History ---")
print("conn_state by label:")
print(pd.crosstab(df_binary["conn_state"], df_binary["label_raw"], normalize="columns") * 100)

print("\n--- 5. IP Addresses (orig_h, resp_h) ---")
ip_b = set(df_binary[df_binary['label_raw']=='benign']['resp_h'].dropna().unique())
ip_m = set(df_binary[df_binary['label_raw']=='malicious_c2']['resp_h'].dropna().unique())
print(f"Unique resp_h in benign: {len(ip_b)}")
print(f"Unique resp_h in malicious_c2: {len(ip_m)}: {ip_m}")
print(f"Shared resp_h: {len(ip_b.intersection(ip_m))}")

orig_b = set(df_binary[df_binary['label_raw']=='benign']['orig_h'].dropna().unique())
orig_m = set(df_binary[df_binary['label_raw']=='malicious_c2']['orig_h'].dropna().unique())
print(f"Unique orig_h in benign: {len(orig_b)}: {sorted(list(orig_b))}")
print(f"Unique orig_h in malicious_c2: {len(orig_m)}: {sorted(list(orig_m))}")
print(f"Shared orig_h: {len(orig_b.intersection(orig_m))}")

print("\n--- 6. Duplicate Feature Vectors in TQH-C2 ---")
feature_cols = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "resp_p", "proto", "conn_state", "history", "orig_ip_bytes",
    "resp_ip_bytes", "missed_bytes", "ja4", "ja4s"
]
dup_count = df_binary.duplicated(subset=feature_cols).sum()
print(f"Exact duplicate feature vectors in Testbed A (14 features): {dup_count} / {len(df_binary)} ({dup_count/len(df_binary)*100:.2f}%)")
dup_by_label = df_binary.groupby("label_raw").apply(lambda g: g.duplicated(subset=feature_cols).sum())
print("Duplicates within each label:")
print(dup_by_label)
