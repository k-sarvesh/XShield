
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "sample.csv"

df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

df["Label"] = df["Label"].astype(str).str.strip()
df["Dst Port"] = pd.to_numeric(df["Dst Port"], errors="coerce")

print("\n========== PORT BIAS INVESTIGATION ==========")
print("Rows:", len(df))
print("\nOverall label distribution:")
print(df["Label"].value_counts())

print("\n--- Most common destination ports ---")
print(df["Dst Port"].value_counts(dropna=False).head(20))

print("\n--- Label distribution by destination port ---")
port_label = pd.crosstab(df["Dst Port"], df["Label"])
port_label["Total"] = port_label.sum(axis=1)
port_label = port_label.sort_values("Total", ascending=False)

print(port_label.head(25).to_string())

# For each port, calculate the majority-label proportion.
label_columns = [
    col for col in port_label.columns if col != "Total"
]
port_label["Majority proportion"] = (
    port_label[label_columns].max(axis=1) / port_label["Total"]
)

print("\n--- Ports with strongest label association ---")
print(
    port_label.sort_values(
        ["Majority proportion", "Total"],
        ascending=[False, False],
    ).head(20).to_string()
)

print("\n--- Ports appearing in only one label ---")
for port, row in port_label.iterrows():
    present_labels = [
        label for label in label_columns if row[label] > 0
    ]
    if len(present_labels) == 1 and row["Total"] >= 20:
        print(
            f"Port {port}: label={present_labels[0]}, "
            f"rows={int(row['Total'])}"
        )

# Inspect timestamps without using them as model features.
if "Timestamp" in df.columns:
    print("\n--- Timestamp coverage ---")
    timestamps = pd.to_datetime(
        df["Timestamp"], errors="coerce", dayfirst=False
    )
    print("Parseable timestamps:", int(timestamps.notna().sum()))
    print("Earliest timestamp:", timestamps.min())
    print("Latest timestamp:", timestamps.max())

    df["Parsed Timestamp"] = timestamps
    print("\nRows by timestamp and label (hourly):")
    hourly = (
        df.dropna(subset=["Parsed Timestamp"])
        .assign(Hour=lambda x: x["Parsed Timestamp"].dt.floor("h"))
        .groupby(["Hour", "Label"])
        .size()
        .unstack(fill_value=0)
    )
    print(hourly.head(15).to_string())

print("\nInvestigation complete.")
