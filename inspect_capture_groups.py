
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
ZIP_PATH = BASE_DIR / "data" / "TQH-C2_features_v110.zip"

with ZipFile(ZIP_PATH, "r") as archive:
    parquet_files = [
        name for name in archive.namelist()
        if name.lower().endswith(".parquet")
    ]

    print("Parquet files found:")
    for name in parquet_files:
        print(" ", repr(name))

    matches = [
        name for name in parquet_files
        if Path(name).name.lower() == "testbed_a.parquet"
    ]

    if not matches:
        raise FileNotFoundError(
            "Could not locate testbed_A.parquet. "
            "Check the filenames printed above."
        )

    table_path = matches[0]
    print(f"\nReading: {table_path}")

    with archive.open(table_path) as file:
        df = pd.read_parquet(BytesIO(file.read()))

print("\n========== CAPTURE GROUP AUDIT ==========")
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())

# Find column names without assuming their exact capitalization.
columns_lower = {col.lower(): col for col in df.columns}
capture_col = columns_lower.get("capture_id")
label_col = columns_lower.get("label_raw")

if capture_col is None or label_col is None:
    print("\nCapture or label column was not found.")
    print("Please share the printed column names.")
    raise SystemExit(1)

print("\n--- Rows per capture ---")
print(
    df.groupby(capture_col)
    .size()
    .sort_values(ascending=False)
    .to_string()
)

print("\n--- Labels within each capture ---")
counts = pd.crosstab(df[capture_col], df[label_col])
print(counts.to_string())

print("\n--- Capture-level label purity ---")
for capture_id, part in df.groupby(capture_col):
    label_counts = part[label_col].value_counts()
    purity = label_counts.max() / len(part)

    print(
        f"Capture {capture_id!r}: rows={len(part)}, "
        f"labels={label_counts.to_dict()}, "
        f"majority_fraction={purity:.3f}"
    )

print("\nAudit complete.")
