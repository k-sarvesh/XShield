
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
ZIP_PATH = BASE_DIR / "data" / "TQH-C2_features_v110.zip"

if not ZIP_PATH.exists():
    raise FileNotFoundError(f"Dataset ZIP not found: {ZIP_PATH}")

try:
    import pyarrow  # noqa: F401
except ImportError:
    raise SystemExit(
        "Parquet support is missing.\n"
        "Install it with:\n"
        ".\\.venv\\Scripts\\python.exe -m pip install pyarrow"
    )

with ZipFile(ZIP_PATH, "r") as archive:
    names = [
        name for name in archive.namelist()
        if name.lower().endswith(".parquet")
    ]

    print(f"Parquet files found: {len(names)}")

    # Inspect combined testbed tables first.
    selected = [
        name for name in names
        if name.lower().endswith((
            "testbed_a.parquet",
            "testbed_b.parquet",
            "testbed_c.parquet",
        ))
    ]

    if not selected:
        selected = names[:3]

    for name in selected:
        print(f"\n{'=' * 65}")
        print(f"FILE: {name}")

        with archive.open(name) as file:
            df = pd.read_parquet(BytesIO(file.read()))

        print("Shape:", df.shape)
        print("\nColumn names and data types:")
        print(df.dtypes.to_string())

        print("\nFirst 3 rows:")
        print(df.head(3).to_string(index=False))

        print("\nPotential label / identifier columns:")
        for col in df.columns:
            if any(
                term in col.lower()
                for term in [
                    "label", "class", "malicious", "uid",
                    "src", "dst", "orig", "resp",
                    "ja4", "ja4s", "ja4h", "profile",
                    "cell", "interval", "jitter",
                ]
            ):
                print(f"  {col}: {df[col].head(3).tolist()}")

        # Print distinct values for likely categorical fields.
        print("\nLikely categorical fields:")
        for col in df.columns:
            if (
                df[col].dtype == "object"
                or str(df[col].dtype) == "category"
                or str(df[col].dtype).startswith("string")
            ):
                print(
                    f"  {col}: "
                    f"{df[col].nunique(dropna=True)} distinct values"
                )

print("\nParquet inspection complete.")
