
import pandas as pd
import numpy as np
from pathlib import Path

source = Path("data/sample.csv")
destination = Path("data/sample_clean.csv")

df = pd.read_csv(source, low_memory=False)
df.columns = df.columns.str.strip()

if "Label" not in df.columns:
    raise ValueError("The dataset must contain a 'Label' column.")

# Clean target labels
df["Label"] = df["Label"].astype("string").str.strip()
df = df.dropna(subset=["Label"])

# Remove columns that should not be model inputs
excluded = [
    col for col in ["Timestamp"] if col in df.columns
]

# Replace infinite numeric values with missing values
numeric_cols = df.select_dtypes(include="number").columns
df[numeric_cols] = df[numeric_cols].replace(
    [np.inf, -np.inf], np.nan
)

# Remove exact duplicate rows
before = len(df)
df = df.drop_duplicates()
duplicates_removed = before - len(df)

# Remove columns that are constant in this sample,
# except the target label
constant_cols = [
    col for col in df.columns
    if col != "Label" and df[col].nunique(dropna=False) <= 1
]

df = df.drop(columns=constant_cols + excluded, errors="ignore")

# Save a separate cleaned copy
df.to_csv(destination, index=False)

print("========== XSHIELD DATA PREPARATION ==========")
print(f"Rows saved: {len(df):,}")
print(f"Features/columns excluding target: {len(df.columns) - 1}")
print(f"Duplicate rows removed: {duplicates_removed:,}")
print(f"Constant columns removed: {constant_cols}")
print(f"Excluded columns: {excluded}")
print(f"Missing cells remaining: {df.isna().sum().sum():,}")
print("\nLabel distribution:")
print(df["Label"].value_counts())
print(f"\nSaved to: {destination.resolve()}")
