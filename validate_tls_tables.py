
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
ZIP_PATH = BASE_DIR / "data" / "TQH-C2_features_v110.zip"

tables = [
    "features/testbed_A.parquet",
    "features/testbed_B.parquet",
    "features/testbed_C.parquet",
]

with ZipFile(ZIP_PATH, "r") as archive:
    available = set(archive.namelist())

    for table in tables:
        if table not in available:
            matches = [
                name for name in available
                if name.endswith(table.split("/")[-1])
            ]
            if not matches:
                print(f"\nNot found: {table}")
                continue
            table = matches[0]

        with archive.open(table) as file:
            df = pd.read_parquet(BytesIO(file.read()))

        print("\n" + "=" * 65)
        print("TABLE:", table)
        print("Shape:", df.shape)

        print("\nFull label distribution:")
        print(df["label_raw"].value_counts(dropna=False))

        print("\nEncoded label distribution:")
        print(df["y"].value_counts(dropna=False))

        print("\nLabel consistency check:")
        if "y" in df.columns:
            print(
                pd.crosstab(
                    df["label_raw"],
                    df["y"],
                    dropna=False
                )
            )

        print("\nMissing percentage by column:")
        missing = (
            df.isna().mean().mul(100)
            .sort_values(ascending=False)
        )
        print(missing[missing > 0].round(2).to_string())

        print("\nFingerprint availability by label:")
        for col in ["ja4", "ja4s", "ja4h"]:
            if col not in df.columns:
                continue

            populated = (
                df[col].notna()
                & df[col].astype(str).str.strip().ne("")
            )

            summary = (
                df.assign(_populated=populated)
                .groupby("label_raw")["_populated"]
                .agg(["sum", "count", "mean"])
            )
            summary["percent_populated"] = (
                summary["mean"] * 100
            )
            print(f"\n{col}:")
            print(summary.round(2).to_string())

        print("\nCapture IDs per label:")
        if "capture_id" in df.columns:
            print(
                df.groupby("label_raw")["capture_id"]
                .nunique()
                .to_string()
            )

print("\nValidation complete.")
