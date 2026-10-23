
import pandas as pd
from pathlib import Path

file_path = Path("data/sample.csv")

if not file_path.exists():
    raise FileNotFoundError(f"Dataset not found: {file_path.resolve()}")

print("\n========== XSHIELD DATA VALIDATION ==========")

# Load the sample
df = pd.read_csv(file_path, low_memory=False)

print("\n1. DATASET SHAPE")
print(f"Rows: {len(df):,}")
print(f"Columns: {len(df.columns)}")

# Clean accidental spaces in column names and labels
df.columns = df.columns.str.strip()

print("\n2. LABEL DISTRIBUTION")
if "Label" in df.columns:
    print(df["Label"].astype(str).str.strip().value_counts(dropna=False))
else:
    print("ERROR: No 'Label' column found.")

print("\n3. MISSING VALUES")
missing = df.isna().sum()
print(f"Total missing cells: {missing.sum():,}")
print(missing[missing > 0].sort_values(ascending=False).head(15))

print("\n4. DUPLICATE ROWS")
print(f"Exact duplicate rows: {df.duplicated().sum():,}")

print("\n5. CONSTANT COLUMNS")
constant_cols = [
    col for col in df.columns
    if df[col].nunique(dropna=False) <= 1
]
print(constant_cols if constant_cols else "None found")

print("\n6. POTENTIALLY SENSITIVE COLUMNS")
for col in df.columns:
    if any(word in col.lower() for word in
           ["label", "timestamp", "flow id", "src ip", "dst ip"]):
        print("-", col)

print("\n7. NUMERIC INFINITY CHECK")
numeric = df.select_dtypes(include="number")
if not numeric.empty:
    print("Infinite values:", int(numeric.isin([float("inf"), float("-inf")]).sum().sum()))
else:
    print("No numeric columns found.")

print("\n========== VALIDATION COMPLETE ==========")
