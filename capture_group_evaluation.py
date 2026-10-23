
from pathlib import Path
from io import BytesIO
import zipfile
import warnings

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

warnings.filterwarnings("ignore", category=FutureWarning)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DATA_DIR = Path("data")
REPORT_DIR = Path("reports")
ZIP_PATH = DATA_DIR / "TQH-C2_features_v110.zip"
TABLE_NAME = "testbed_A.parquet"
N_SPLITS = 4
RANDOM_STATE = 42

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# LOAD PARQUET DIRECTLY FROM ZIP
# --------------------------------------------------

def load_parquet_from_zip(zip_path, table_name):
    if not zip_path.exists():
        raise FileNotFoundError(
            f"Dataset ZIP not found: {zip_path.resolve()}"
        )

    with zipfile.ZipFile(zip_path, "r") as archive:
        matches = [
            name for name in archive.namelist()
            if name.replace("\\", "/").endswith(
                f"features/{table_name}"
            )
        ]

        if not matches:
            raise FileNotFoundError(
                f"{table_name} was not found inside {zip_path}"
            )

        # Prefer the combined testbed table if multiple paths match.
        matches.sort(
            key=lambda name: (
                "capture" in name.lower(),
                name.count("/"),
                len(name),
            )
        )

        selected_file = matches[0]
        print(f"Reading: {selected_file}")

        with archive.open(selected_file) as file:
            return pd.read_parquet(BytesIO(file.read()))


# --------------------------------------------------
# LOAD AND FILTER DATA
# --------------------------------------------------

df = load_parquet_from_zip(ZIP_PATH, TABLE_NAME)

required_columns = {"label_raw", "capture_id"}
missing_required = required_columns - set(df.columns)

if missing_required:
    raise ValueError(
        f"Dataset is missing required columns: {missing_required}"
    )

# Keep only the two clearly defined classes.
# benign_external is excluded from this binary experiment.
df = df[
    df["label_raw"].isin(["benign", "malicious_c2"])
].copy()

df = df.dropna(subset=["capture_id", "label_raw"])

# Target: benign = 0, malicious C2 = 1
y = (df["label_raw"] == "malicious_c2").astype(int)

# Group IDs are used only to keep each capture in one fold.
groups = df["capture_id"].astype(str)

# Remove identifiers, timestamps and dataset metadata that could
# create leakage or encode the experimental setup.
exclude_columns = [
    "ts",
    "uid",
    "orig_h",
    "resp_h",
    "capture_id",
    "label_raw",
    "y",
    "profile",
    "encryption_profile",
]

X = df.drop(
    columns=[c for c in exclude_columns if c in df.columns],
    errors="ignore",
).copy()

# Remove columns that contain no usable values.
X = X.dropna(axis=1, how="all")

# Remove constant columns.
constant_columns = [
    col for col in X.columns
    if X[col].nunique(dropna=True) <= 1
]
X = X.drop(columns=constant_columns)

# Identify categorical and numeric columns.
# Ports are categorical here because port values are identifiers,
# not continuous measurements.
categorical_features = [
    col for col in X.columns
    if (
        pd.api.types.is_object_dtype(X[col])
        or isinstance(X[col].dtype, pd.CategoricalDtype)
        or pd.api.types.is_string_dtype(X[col])
        or col in ["orig_p", "resp_p", "proto"]
    )
]

numeric_features = [
    col for col in X.columns
    if col not in categorical_features
]

# --------------------------------------------------
# FIX MISSING VALUES AND DATA TYPES
# --------------------------------------------------

# Convert nullable pandas strings / pd.NA to ordinary np.nan.
# This prevents the SimpleImputer TypeError.
for col in categorical_features:
    X[col] = X[col].astype(object)
    X[col] = X[col].where(pd.notna(X[col]), np.nan)
    X[col] = X[col].map(
        lambda value: value.strip()
        if isinstance(value, str) else value
    )
    X[col] = X[col].replace("", np.nan)

for col in numeric_features:
    X[col] = pd.to_numeric(X[col], errors="coerce")
    X[col] = X[col].replace([np.inf, -np.inf], np.nan)

# Drop rows with missing target/group alignment issues.
valid_rows = X.index.intersection(y.index).intersection(groups.index)
X = X.loc[valid_rows].reset_index(drop=True)
y = y.loc[valid_rows].reset_index(drop=True)
groups = groups.loc[valid_rows].reset_index(drop=True)

if X.empty:
    raise ValueError("No usable feature rows remain after preprocessing.")

if y.nunique() != 2:
    raise ValueError(
        f"Expected two target classes, found: {y.value_counts().to_dict()}"
    )

if groups.nunique() < N_SPLITS:
    raise ValueError(
        f"Need at least {N_SPLITS} distinct capture groups; "
        f"found {groups.nunique()}."
    )

# Recalculate column lists after preprocessing.
categorical_features = [
    col for col in X.columns
    if (
        pd.api.types.is_object_dtype(X[col])
        or isinstance(X[col].dtype, pd.CategoricalDtype)
        or pd.api.types.is_string_dtype(X[col])
        or col in ["orig_p", "resp_p", "proto"]
    )
]

numeric_features = [
    col for col in X.columns
    if col not in categorical_features
]

print("\n========== CAPTURE-GROUP EVALUATION ==========")
print(f"Rows: {len(X)}")
print(f"Capture groups: {groups.nunique()}")
print("Label counts:")
print(df.loc[valid_rows, "label_raw"].value_counts())
print(f"\nNumeric features: {numeric_features}")
print(f"Categorical features: {categorical_features}")
print(f"Removed constant columns: {constant_columns}")

# --------------------------------------------------
# PREPROCESSING PIPELINE
# --------------------------------------------------

numeric_pipeline = Pipeline(
    steps=[
        (
            "imputer",
            SimpleImputer(strategy="median"),
        )
    ]
)

categorical_pipeline = Pipeline(
    steps=[
        (
            "imputer",
            SimpleImputer(
                strategy="most_frequent",
                missing_values=np.nan,
            ),
        ),
        (
            "onehot",
            OneHotEncoder(handle_unknown="ignore"),
        ),
    ]
)

transformers = []

if numeric_features:
    transformers.append(
        ("numeric", numeric_pipeline, numeric_features)
    )

if categorical_features:
    transformers.append(
        ("categorical", categorical_pipeline, categorical_features)
    )

preprocessor = ColumnTransformer(
    transformers=transformers,
    remainder="drop",
)

model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=150,
                class_weight="balanced_subsample",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        ),
    ]
)

# --------------------------------------------------
# GROUP CROSS-VALIDATION
# --------------------------------------------------

cv = GroupKFold(n_splits=N_SPLITS)

fold_results = []
all_y_true = []
all_y_pred = []
all_y_prob = []

for fold, (train_idx, test_idx) in enumerate(
    cv.split(X, y, groups=groups), start=1
):
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_groups = set(groups.iloc[train_idx])
    test_groups = set(groups.iloc[test_idx])

    overlap = train_groups.intersection(test_groups)

    if overlap:
        raise RuntimeError(
            f"Data leakage: groups overlap in fold {fold}: {overlap}"
        )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    classes = list(model.named_steps["classifier"].classes_)
    positive_class_index = classes.index(1)
    y_prob = probabilities[:, positive_class_index]

    accuracy = accuracy_score(y_test, y_pred)
    balanced_acc = balanced_accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(
        y_test, y_pred, average="macro", zero_division=0
    )

    # ROC-AUC requires both classes in the test fold.
    auc = (
        roc_auc_score(y_test, y_prob)
        if y_test.nunique() == 2
        else np.nan
    )

    fold_results.append(
        {
            "fold": fold,
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
            "train_groups": len(train_groups),
            "test_groups": len(test_groups),
            "accuracy": accuracy,
            "balanced_accuracy": balanced_acc,
            "macro_f1": macro_f1,
            "roc_auc": auc,
        }
    )

    all_y_true.extend(y_test.tolist())
    all_y_pred.extend(y_pred.tolist())
    all_y_prob.extend(y_prob.tolist())

    print(f"\n--- Fold {fold} ---")
    print(f"Train rows: {len(train_idx)}")
    print(f"Test rows: {len(test_idx)}")
    print(f"Train captures: {sorted(train_groups)}")
    print(f"Test captures: {sorted(test_groups)}")
    print(f"Accuracy:          {accuracy:.4f}")
    print(f"Balanced accuracy: {balanced_acc:.4f}")
    print(f"Macro-F1:          {macro_f1:.4f}")
    print(f"ROC-AUC:           {auc:.4f}")

# --------------------------------------------------
# AGGREGATE RESULTS
# --------------------------------------------------

results_df = pd.DataFrame(fold_results)

results_path = REPORT_DIR / "capture_group_evaluation.csv"
results_df.to_csv(results_path, index=False)

print("\n========== FOLD SUMMARY ==========")
print(results_df.to_string(index=False))

print("\n========== MEAN AND STANDARD DEVIATION ==========")
for metric in [
    "accuracy",
    "balanced_accuracy",
    "macro_f1",
    "roc_auc",
]:
    print(
        f"{metric}: "
        f"{results_df[metric].mean():.4f} "
        f"+/- {results_df[metric].std(ddof=1):.4f}"
    )

print("\n========== OVERALL OUT-OF-FOLD REPORT ==========")
print(
    classification_report(
        all_y_true,
        all_y_pred,
        labels=[0, 1],
        target_names=["Benign", "Malicious C2"],
        zero_division=0,
        digits=4,
    )
)

print("Overall confusion matrix:")
print(
    confusion_matrix(
        all_y_true,
        all_y_pred,
        labels=[0, 1],
    )
)

print(f"\nSaved fold results to: {results_path.resolve()}")
print("\nEvaluation completed.")
