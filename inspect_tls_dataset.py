
from pathlib import Path
from zipfile import ZipFile
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

readme_path = DATA_DIR / "README_v122.md"
zip_path = DATA_DIR / "TQH-C2_features_v110.zip"

# 1. Read dataset documentation
print("\n========== DATASET README ==========")

if readme_path.exists():
    readme = readme_path.read_text(
        encoding="utf-8", errors="replace"
    )
    print(readme[:14000])
else:
    print(f"README not found: {readme_path}")

# 2. Inspect archive contents without extracting
print("\n========== ZIP CONTENTS ==========")

if not zip_path.exists():
    print(f"ZIP not found: {zip_path}")
else:
    with ZipFile(zip_path, "r") as archive:
        entries = [
            item for item in archive.infolist()
            if not item.is_dir()
        ]

        print(f"Files inside ZIP: {len(entries)}")

        for item in entries[:100]:
            print(
                f"{item.filename} "
                f"({item.file_size / 1024:.1f} KB)"
            )

        # 3. Preview CSV files, if present
        print("\n========== TABULAR FILE PREVIEW ==========")

        tabular = [
            item for item in entries
            if item.filename.lower().endswith(
                (".csv", ".tsv")
            )
        ]

        if not tabular:
            print(
                "No CSV/TSV files found in the archive preview. "
                "Check the listed file types above."
            )

        for item in tabular[:5]:
            print(f"\n--- {item.filename} ---")
            try:
                with archive.open(item) as file:
                    if item.filename.lower().endswith(".tsv"):
                        df = pd.read_csv(
                            file, sep="\t", nrows=5,
                            low_memory=False
                        )
                    else:
                        df = pd.read_csv(
                            file, nrows=5,
                            low_memory=False
                        )

                print("Columns:")
                print(df.columns.tolist())
                print("\nSample rows:")
                print(df.head(3).to_string(index=False))
            except Exception as exc:
                print(f"Preview failed: {exc}")

print("\nInspection complete.")
