"""Automated acceptance test suite for XShield Phase 2.

Covers:
1. Application and module compilation.
2. Selection and loading of all valid manifest models.
3. Inference on unlabelled CSV without retraining.
4. Prediction count strictly equals input row count.
5. Missing required features produce clear, actionable error.
6. Extra columns follow documented policy (preserved for inspection, ignored by model).
7. Target label column does not influence predictions.
8. CSV exports contain predictions, risk scores, and tiers.
9. Flagged-flow export contains only rows meeting documented threshold.
10. Empty or malformed CSV inputs handled gracefully.
11. Missing model artifact produces clear error without silent substitution.
12. Filtering and traffic field identification semantics.
"""

from io import StringIO
from pathlib import Path
import py_compile
import unittest

import numpy as np
import pandas as pd

from xshield.pipeline import MODELS_DIR, XShieldModel, load_model
from xshield.triage import (
    compute_triage_metrics,
    extract_available_traffic_fields,
    filter_triage_flows,
    format_csv_export,
    load_manifest_models,
    score_flows_batch,
    validate_flow_schema,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent


class TestPhase2Acceptance(unittest.TestCase):
    """Phase 2 operational inference and triage acceptance tests."""

    @classmethod
    def setUpClass(cls):
        """Loads valid models and prepares sample data fixtures."""
        cls.manifest = load_manifest_models(MODELS_DIR)

        # Ensure at least the primary TQH-C2 and CICIDS models exist
        cls.tqh_inc_model = load_model("xshield_tqh_c2_port_inclusive")
        cls.cic_inc_model = load_model("xshield_cicids2018_port_inclusive")

        # Load sample unlabelled CSVs if present, else create synthetic fixture
        sample_tqh_path = PROJECT_DIR / "data" / "sample_tqh_c2_unlabelled.csv"
        if sample_tqh_path.exists():
            cls.df_tqh_sample = pd.read_csv(sample_tqh_path)
        else:
            # Synthetic fallback matching TQH-C2 feature names
            cls.df_tqh_sample = pd.DataFrame({
                feat: [1.0] * 10 for feat in cls.tqh_inc_model.feature_names
            })

    def test_01_app_and_modules_compile(self):
        """1. Verify that all application files compile without syntax or import errors."""
        files = [
            PROJECT_DIR / "app.py",
            PROJECT_DIR / "xshield" / "pipeline.py",
            PROJECT_DIR / "xshield" / "datasets.py",
            PROJECT_DIR / "xshield" / "triage.py",
            PROJECT_DIR / "xshield" / "__init__.py",
        ]
        for f in files:
            self.assertTrue(f.exists(), f"File does not exist: {f}")
            # py_compile will raise PyCompileError if syntax is invalid
            compiled = py_compile.compile(str(f), doraise=True)
            self.assertIsNotNone(compiled)

    def test_02_each_valid_model_can_be_selected_and_loaded(self):
        """2. Verify each model in manifest.json can be selected, loaded, and has valid metadata."""
        self.assertGreaterEqual(len(self.manifest), 4, "Expected at least 4 models in manifest.")
        expected_keys = [
            "xshield_tqh_c2_port_inclusive",
            "xshield_tqh_c2_port_excluded",
            "xshield_cicids2018_port_inclusive",
            "xshield_cicids2018_port_excluded",
        ]
        for key in expected_keys:
            self.assertIn(key, self.manifest, f"Model key '{key}' not in manifest.")
            meta_entry = self.manifest[key]
            self.assertTrue(meta_entry["is_available"], f"Model files missing for {key}")

            loaded = load_model(key)
            self.assertIsInstance(loaded, XShieldModel)
            self.assertEqual(loaded.model_name, key)
            self.assertGreater(len(loaded.feature_names), 0)
            self.assertGreater(len(loaded.classes), 0)

    def test_03_unlabelled_csv_scored_without_retraining(self):
        """3. An unlabelled CSV can be scored; model estimators are not re-fitted."""
        model = self.tqh_inc_model
        input_data = self.df_tqh_sample.copy()

        # Record tree references or attributes to prove no retraining occurs
        initial_n_estimators = len(model.pipeline.named_steps["classifier"].estimators_)
        initial_classes = list(model.pipeline.named_steps["classifier"].classes_)

        scored = score_flows_batch(input_data, model, threshold=0.50)

        # Estimators should remain identical
        self.assertEqual(
            len(model.pipeline.named_steps["classifier"].estimators_), initial_n_estimators
        )
        self.assertEqual(
            list(model.pipeline.named_steps["classifier"].classes_), initial_classes
        )

        self.assertIn("predicted_label", scored.columns)
        self.assertIn("risk_score", scored.columns)
        self.assertIn("risk_level", scored.columns)
        self.assertIn("is_flagged", scored.columns)

    def test_04_prediction_count_equals_input_rows(self):
        """4. The number of predictions strictly equals the number of input rows."""
        model = self.tqh_inc_model
        for n_rows in [5, 17, 33]:
            slice_df = self.df_tqh_sample.iloc[:n_rows].copy()
            scored = score_flows_batch(slice_df, model)
            self.assertEqual(len(scored), n_rows)
            self.assertEqual(list(scored["flow_id"]), list(range(1, n_rows + 1)))

    def test_05_missing_required_features_produce_useful_error(self):
        """5. Missing required features produce a descriptive error and explain resolution."""
        model = self.tqh_inc_model
        # Drop two required features
        bad_df = self.df_tqh_sample.drop(columns=["duration", "resp_bytes"])

        validation = validate_flow_schema(bad_df, model)
        self.assertFalse(validation["is_valid"])
        self.assertEqual(validation["error_type"], "MissingFeatures")
        self.assertIn("duration", validation["missing_features"])
        self.assertIn("resp_bytes", validation["missing_features"])
        self.assertIn("Schema Mismatch", validation["message"])
        self.assertIn("How to resolve", validation["message"])

        # Attempting batch scoring must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            score_flows_batch(bad_df, model)
        self.assertIn("duration", str(ctx.exception))

    def test_06_extra_columns_follow_policy(self):
        """6. Extra columns (traffic metadata/tags) are safely accepted and preserved for inspection."""
        model = self.tqh_inc_model
        augmented_df = self.df_tqh_sample.copy()
        augmented_df["analyst_comment"] = "suspicious high frequency"
        augmented_df["sensor_id"] = "zeek_sensor_alpha"
        augmented_df["arbitrary_metric"] = 123.456

        validation = validate_flow_schema(augmented_df, model)
        self.assertTrue(validation["is_valid"])
        self.assertIn("analyst_comment", validation["extra_features"])
        self.assertIn("sensor_id", validation["extra_features"])

        scored = score_flows_batch(augmented_df, model)
        # Extra columns must be preserved in the triage view
        self.assertIn("analyst_comment", scored.columns)
        self.assertIn("sensor_id", scored.columns)
        self.assertIn("arbitrary_metric", scored.columns)
        self.assertEqual(len(scored), len(augmented_df))

    def test_07_target_label_column_does_not_influence_predictions(self):
        """7. A target label column in uploaded CSV does NOT influence model inference."""
        model = self.tqh_inc_model

        df_base = self.df_tqh_sample.copy()
        # Clean any existing ground truth columns
        for c in ["label", "label_raw", "Label", "y"]:
            if c in df_base.columns:
                df_base = df_base.drop(columns=[c])

        scored_no_label = score_flows_batch(df_base, model)

        # Version A: Target column filled with 'benign'
        df_with_benign = df_base.copy()
        df_with_benign["label_raw"] = "benign"
        scored_benign = score_flows_batch(df_with_benign, model)

        # Version B: Target column filled with 'malicious_c2'
        df_with_malicious = df_base.copy()
        df_with_malicious["label_raw"] = "malicious_c2"
        scored_malicious = score_flows_batch(df_with_malicious, model)

        # Risk scores and predicted labels must be 100% identical regardless of label_raw
        np.testing.assert_allclose(
            scored_no_label["risk_score"].values,
            scored_benign["risk_score"].values,
            err_msg="Label column influenced risk scores (benign case)!",
        )
        np.testing.assert_allclose(
            scored_no_label["risk_score"].values,
            scored_malicious["risk_score"].values,
            err_msg="Label column influenced risk scores (malicious case)!",
        )
        self.assertEqual(
            list(scored_no_label["predicted_label"]),
            list(scored_benign["predicted_label"]),
        )
        self.assertEqual(
            list(scored_no_label["predicted_label"]),
            list(scored_malicious["predicted_label"]),
        )

        # Also confirm target column is isolated to 'ground_truth_label' reference
        self.assertIn("ground_truth_label", scored_benign.columns)
        self.assertEqual(list(scored_benign["ground_truth_label"]), ["benign"] * len(df_base))

    def test_08_csv_exports_contain_predictions_and_scores(self):
        """8. CSV export contains predictions, risk scores, tiers, and input features."""
        model = self.tqh_inc_model
        scored = score_flows_batch(self.df_tqh_sample.iloc[:10], model)

        csv_str = format_csv_export(scored, flagged_only=False)
        exported_df = pd.read_csv(StringIO(csv_str))

        self.assertEqual(len(exported_df), 10)
        self.assertIn("flow_id", exported_df.columns)
        self.assertIn("predicted_label", exported_df.columns)
        self.assertIn("risk_score", exported_df.columns)
        self.assertIn("risk_level", exported_df.columns)
        self.assertIn("is_flagged", exported_df.columns)
        # Required features must also be preserved
        self.assertIn("duration", exported_df.columns)

    def test_09_flagged_flow_export_threshold(self):
        """9. Flagged-flow export contains only rows meeting the documented threshold."""
        model = self.tqh_inc_model
        threshold = 0.40
        scored = score_flows_batch(self.df_tqh_sample.iloc[:30], model, threshold=threshold)

        flagged_csv = format_csv_export(scored, flagged_only=True)
        flagged_df = pd.read_csv(StringIO(flagged_csv))

        # Every exported row must have risk_score >= threshold
        expected_count = (scored["risk_score"] >= threshold).sum()
        self.assertEqual(len(flagged_df), expected_count)
        if len(flagged_df) > 0:
            self.assertTrue(np.all(flagged_df["risk_score"] >= threshold))
            self.assertTrue(np.all(flagged_df["is_flagged"] == True))

    def test_10_empty_or_malformed_csv_handled_gracefully(self):
        """10. Empty DataFrames, None input, or NaN values are handled gracefully."""
        model = self.tqh_inc_model

        # Case A: None input
        val_none = validate_flow_schema(None, model)
        self.assertFalse(val_none["is_valid"])
        self.assertEqual(val_none["error_type"], "NoneInput")

        # Case B: Empty DataFrame (0 rows)
        empty_df = pd.DataFrame(columns=model.feature_names)
        val_empty = validate_flow_schema(empty_df, model)
        self.assertFalse(val_empty["is_valid"])
        self.assertEqual(val_empty["error_type"], "EmptyDataFrame")
        self.assertIn("0 rows", val_empty["message"])

        # Case C: DataFrame with NaNs and corrupted numeric strings (graceful imputation)
        corrupted_df = self.df_tqh_sample.iloc[:10].copy()
        corrupted_df["orig_bytes"] = corrupted_df["orig_bytes"].astype(object)
        corrupted_df.loc[0, "duration"] = np.nan
        corrupted_df.loc[1, "orig_bytes"] = "NOT_A_NUMBER"
        corrupted_df.loc[2, "resp_bytes"] = np.inf

        # Pipeline imputer should coerce and handle without error
        scored_corrupted = score_flows_batch(corrupted_df, model)
        self.assertEqual(len(scored_corrupted), 10)
        self.assertTrue(np.all(np.isfinite(scored_corrupted["risk_score"])))

    def test_11_missing_model_artifact_produces_clear_error(self):
        """11. Attempting to load an invalid or missing model produces an explicit FileNotFoundError."""
        with self.assertRaises((FileNotFoundError, PermissionError)):
            load_model("nonexistent_phantom_model_9999")

    def test_12_filtering_and_traffic_fields(self):
        """12. Flow filtering and traffic metadata extraction behave as specified."""
        model = self.tqh_inc_model
        scored = score_flows_batch(self.df_tqh_sample.iloc[:20], model)

        # Field discovery
        fields = extract_available_traffic_fields(scored)
        self.assertIn("duration", fields)
        self.assertEqual(fields["duration"], "duration")

        # Filtering by tier
        low_only = filter_triage_flows(scored, tier_filter="LOW")
        self.assertTrue(all(low_only["risk_level"] == "LOW"))

        # Sorting
        sorted_desc = filter_triage_flows(scored, sort_by="risk_desc")
        scores = sorted_desc["risk_score"].tolist()
        self.assertEqual(scores, sorted(scores, reverse=True))

        # Metrics computation
        metrics = compute_triage_metrics(scored, threshold=0.50)
        self.assertEqual(metrics["total_flows"], 20)
        self.assertIn("flagged_count", metrics)
        self.assertIn("class_distribution", metrics)


if __name__ == "__main__":
    unittest.main()
