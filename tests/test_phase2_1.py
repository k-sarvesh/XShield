"""Automated test suite for XShield Phase 2.1 — Dataset Compatibility and Schema-Aware Model Selection.

Covers:
1. Compatible TQH-C2 CSV evaluation with matching models.
2. Compatible CICIDS-2018 CSV evaluation with matching models.
3. Cross-benchmark mismatch: TQH-C2 CSV uploaded with CICIDS model selected.
4. Cross-benchmark mismatch: CICIDS-2018 CSV uploaded with TQH model selected.
5. Unknown / unsupported schema handling (arbitrary network flow CSV).
6. Missing features handling (partial schema; features are never invented or zero-filled).
7. Extra columns handling (separated, preserved for inspection, never fed to estimator).
8. Target label isolation (ground-truth labels never influence predictions).
9. Incompatible uploads strictly never reach model estimator inference.
10. Schema checks strictly do not mutate or modify source CSV DataFrames.
11. Model requirements are extracted from authoritative saved metadata, not hardcoded assumptions.
12. Unambiguous model recommendation when a compatible model exists.
"""

from pathlib import Path
import unittest
from unittest.mock import MagicMock

import numpy as np
import pandas as pd

from xshield.pipeline import MODELS_DIR, XShieldModel, load_model
from xshield.triage import (
    assess_dataset_compatibility,
    check_model_compatibility,
    load_manifest_models,
    score_flows_batch,
    validate_flow_schema,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent


class TestPhase21DatasetCompatibility(unittest.TestCase):
    """Phase 2.1 acceptance tests for dataset compatibility and schema-aware model selection."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest_models(MODELS_DIR)

        # Load models
        cls.tqh_inc_model = load_model("xshield_tqh_c2_port_inclusive")
        cls.tqh_exc_model = load_model("xshield_tqh_c2_port_excluded")
        cls.cic_inc_model = load_model("xshield_cicids2018_port_inclusive")
        cls.cic_exc_model = load_model("xshield_cicids2018_port_excluded")

        # Load real benchmark unlabelled fixtures
        tqh_csv_path = PROJECT_DIR / "data" / "sample_tqh_c2_unlabelled.csv"
        cic_csv_path = PROJECT_DIR / "data" / "sample_cicids2018_unlabelled.csv"

        cls.df_tqh = pd.read_csv(tqh_csv_path)
        cls.df_cic = pd.read_csv(cic_csv_path)

        # Arbitrary network flow fixture (unsupported schema)
        cls.df_unknown = pd.DataFrame({
            "timestamp": ["2026-10-23 12:00:00", "2026-10-23 12:00:01"],
            "src_ip": ["192.168.1.10", "192.168.1.11"],
            "dst_ip": ["10.0.0.1", "10.0.0.2"],
            "src_port": [54321, 54322],
            "dst_port": [443, 80],
            "protocol": ["TCP", "TCP"],
            "bytes_transferred": [1024, 2048],
            "packet_count": [10, 20],
        })

    def test_01_compatible_tqh_c2_csv(self):
        """1. A compatible TQH-C2 CSV is validated, identified, and scored with matching TQH model."""
        model = self.tqh_inc_model
        val = validate_flow_schema(self.df_tqh, model, manifest=self.manifest)

        self.assertTrue(val["is_valid"])
        self.assertIsNone(val["error_type"])
        self.assertEqual(len(val["missing_features"]), 0)
        self.assertEqual(val["detected_schema"], "TQH-C2 (Sliver TLS)")
        self.assertEqual(val["schema_classification"], "known_tqh_c2")
        self.assertIn("xshield_tqh_c2_port_inclusive", val["compatible_models"])
        self.assertIn("xshield_tqh_c2_port_excluded", val["compatible_models"])
        self.assertIn("Schema Valid", val["message"])

        # Batch scoring executes successfully
        scored = score_flows_batch(self.df_tqh, model)
        self.assertEqual(len(scored), len(self.df_tqh))
        self.assertIn("risk_score", scored.columns)
        self.assertTrue(np.all(np.isfinite(scored["risk_score"])))

    def test_02_compatible_cicids2018_csv(self):
        """2. A compatible CICIDS-2018 CSV is validated, identified, and scored with matching CICIDS model."""
        model = self.cic_inc_model
        val = validate_flow_schema(self.df_cic, model, manifest=self.manifest)

        self.assertTrue(val["is_valid"])
        self.assertIsNone(val["error_type"])
        self.assertEqual(len(val["missing_features"]), 0)
        self.assertEqual(val["detected_schema"], "CICIDS-2018 (CICFlowMeter)")
        self.assertEqual(val["schema_classification"], "known_cicids2018")
        self.assertIn("xshield_cicids2018_port_inclusive", val["compatible_models"])
        self.assertIn("xshield_cicids2018_port_excluded", val["compatible_models"])
        self.assertIn("Schema Valid", val["message"])

        # Batch scoring executes successfully
        scored = score_flows_batch(self.df_cic, model)
        self.assertEqual(len(scored), len(self.df_cic))
        self.assertIn("risk_score", scored.columns)
        self.assertTrue(np.all(np.isfinite(scored["risk_score"])))

    def test_03_tqh_csv_with_cicids_model_selected(self):
        """3. When TQH-C2 CSV is uploaded with CICIDS model, clear mismatch explains missing columns and recommends TQH."""
        model = self.cic_inc_model  # Incompatible with TQH data
        val = validate_flow_schema(self.df_tqh, model, manifest=self.manifest)

        self.assertFalse(val["is_valid"])
        self.assertEqual(val["error_type"], "MissingFeatures")
        self.assertGreater(len(val["missing_features"]), 0)
        self.assertEqual(val["detected_schema"], "TQH-C2 (Sliver TLS)")
        self.assertIn("xshield_tqh_c2_port_inclusive", val["compatible_models"])
        self.assertIn("xshield_tqh_c2_port_excluded", val["compatible_models"])
        self.assertEqual(val["recommended_model"], "xshield_tqh_c2_port_inclusive")
        self.assertIn("Schema Mismatch", val["message"])
        self.assertIn("Detected Dataset Schema", val["message"])
        self.assertIn("Recommended model", val["message"])

        # Must raise ValueError and never execute inference
        with self.assertRaises(ValueError) as ctx:
            score_flows_batch(self.df_tqh, model)
        self.assertIn("Schema Mismatch", str(ctx.exception))

    def test_04_cicids_csv_with_tqh_model_selected(self):
        """4. When CICIDS CSV is uploaded with TQH model, clear mismatch explains missing columns and recommends CICIDS."""
        model = self.tqh_inc_model  # Incompatible with CICIDS data
        val = validate_flow_schema(self.df_cic, model, manifest=self.manifest)

        self.assertFalse(val["is_valid"])
        self.assertEqual(val["error_type"], "MissingFeatures")
        self.assertGreater(len(val["missing_features"]), 0)
        self.assertEqual(val["detected_schema"], "CICIDS-2018 (CICFlowMeter)")
        self.assertIn("xshield_cicids2018_port_inclusive", val["compatible_models"])
        self.assertIn("xshield_cicids2018_port_excluded", val["compatible_models"])
        self.assertEqual(val["recommended_model"], "xshield_cicids2018_port_inclusive")
        self.assertIn("Schema Mismatch", val["message"])
        self.assertIn("Detected Dataset Schema", val["message"])
        self.assertIn("Recommended model", val["message"])

        # Must raise ValueError and never execute inference
        with self.assertRaises(ValueError) as ctx:
            score_flows_batch(self.df_cic, model)
        self.assertIn("Schema Mismatch", str(ctx.exception))

    def test_05_unknown_unsupported_schema(self):
        """5. Arbitrary network-flow CSV is recognized as unsupported without false benchmark claims."""
        model = self.tqh_inc_model
        val = validate_flow_schema(self.df_unknown, model, manifest=self.manifest)

        self.assertFalse(val["is_valid"])
        self.assertEqual(val["error_type"], "MissingFeatures")
        self.assertEqual(val["detected_schema"], "Unknown / Unsupported")
        self.assertEqual(val["schema_classification"], "unknown")
        self.assertEqual(len(val["compatible_models"]), 0)
        self.assertIsNone(val["recommended_model"])
        self.assertIn("unsupported by current XShield models", val["message"])

        # Must raise ValueError on scoring attempt
        with self.assertRaises(ValueError):
            score_flows_batch(self.df_unknown, model)

    def test_06_missing_features_never_invented_or_zero_filled(self):
        """6. Missing features produce explicit failure; features are never invented or zero-filled."""
        model = self.tqh_inc_model
        # Intentionally drop 'ja4' and 'ja4s'
        incomplete_df = self.df_tqh.drop(columns=["ja4", "ja4s"])

        val = validate_flow_schema(incomplete_df, model, manifest=self.manifest)
        self.assertFalse(val["is_valid"])
        self.assertIn("ja4", val["missing_features"])
        self.assertIn("ja4s", val["missing_features"])
        self.assertEqual(val["detected_schema"], "TQH-C2 (Incomplete)")
        self.assertEqual(val["schema_classification"], "partial_tqh_c2")

        # Incomplete schema cannot be scored by any model expecting ja4/ja4s
        with self.assertRaises(ValueError) as ctx:
            score_flows_batch(incomplete_df, model)
        self.assertIn("ja4", str(ctx.exception))

        # Model validate_features must also refuse incomplete data
        with self.assertRaises(ValueError) as ctx2:
            model.validate_features(incomplete_df)
        self.assertIn("ja4", str(ctx2.exception))

    def test_07_extra_columns_separated_and_not_passed_to_estimator(self):
        """7. Extra columns are separated in diagnostics and excluded from the classifier features."""
        model = self.tqh_inc_model
        augmented_df = self.df_tqh.copy()
        augmented_df["sensor_region"] = "eu-west-1"
        augmented_df["analyst_tag"] = "test_review"

        val = validate_flow_schema(augmented_df, model, manifest=self.manifest)
        self.assertTrue(val["is_valid"])
        self.assertIn("sensor_region", val["extra_features"])
        self.assertIn("analyst_tag", val["extra_features"])
        # Required features list must NOT include extra features
        self.assertEqual(set(model.feature_names).intersection({"sensor_region", "analyst_tag"}), set())

        # Validate that validate_features extracts ONLY expected columns
        X_validated = model.validate_features(augmented_df)
        self.assertEqual(list(X_validated.columns), model.feature_names)
        self.assertNotIn("sensor_region", X_validated.columns)
        self.assertNotIn("analyst_tag", X_validated.columns)

    def test_08_ground_truth_label_isolated(self):
        """8. Ground-truth label column in input is strictly isolated from model features."""
        model = self.tqh_inc_model
        df_clean = self.df_tqh.copy()
        for col in ["label_raw", "label", "Label", "y"]:
            if col in df_clean.columns:
                df_clean = df_clean.drop(columns=[col])

        # Test with differing label values
        df_benign = df_clean.copy()
        df_benign["label_raw"] = "benign"

        df_mal = df_clean.copy()
        df_mal["label_raw"] = "malicious_c2"

        val_benign = validate_flow_schema(df_benign, model)
        self.assertEqual(val_benign["target_column"], "label_raw")
        self.assertIn("label_raw", val_benign["extra_features"])

        # Confirm model feature schema does not contain label
        self.assertNotIn("label_raw", model.feature_names)
        X_val = model.validate_features(df_benign)
        self.assertNotIn("label_raw", X_val.columns)

        # Scored predictions and risk scores must be identical
        scored_benign = score_flows_batch(df_benign, model)
        scored_mal = score_flows_batch(df_mal, model)
        np.testing.assert_allclose(
            scored_benign["risk_score"].values,
            scored_mal["risk_score"].values,
            err_msg="Label influenced model risk scores!",
        )

    def test_09_incompatible_uploads_never_reach_inference(self):
        """9. Incompatible CSV uploads fail early and never invoke the model estimator."""
        model = self.cic_inc_model

        # Mock the underlying classifier predict and predict_proba
        classifier = model.pipeline.named_steps["classifier"]
        orig_predict = classifier.predict
        orig_predict_proba = classifier.predict_proba

        mock_predict = MagicMock(side_effect=RuntimeError("Estimator predict should NOT be called!"))
        mock_predict_proba = MagicMock(side_effect=RuntimeError("Estimator predict_proba should NOT be called!"))

        classifier.predict = mock_predict
        classifier.predict_proba = mock_predict_proba

        try:
            # Score incompatible TQH data with CICIDS model
            with self.assertRaises(ValueError):
                score_flows_batch(self.df_tqh, model)

            mock_predict.assert_not_called()
            mock_predict_proba.assert_not_called()
        finally:
            classifier.predict = orig_predict
            classifier.predict_proba = orig_predict_proba

    def test_10_schema_checks_do_not_modify_source_csv(self):
        """10. Schema validation and compatibility assessments do not modify the input DataFrame."""
        df_original = self.df_tqh.copy(deep=True)
        df_test = self.df_tqh.copy(deep=True)

        # Run all validation and diagnostic functions
        validate_flow_schema(df_test, self.tqh_inc_model, manifest=self.manifest)
        assess_dataset_compatibility(df_test, manifest=self.manifest)
        check_model_compatibility(df_test, self.tqh_inc_model)

        # Verify exact equality of shape, columns, types, and values
        self.assertEqual(df_test.shape, df_original.shape)
        self.assertEqual(list(df_test.columns), list(df_original.columns))
        pd.testing.assert_frame_equal(df_test, df_original)

    def test_11_model_requirements_from_saved_metadata(self):
        """11. Manifest catalog inspects each model's required features from saved metadata JSON."""
        manifest = load_manifest_models(MODELS_DIR)

        for model_name, info in manifest.items():
            self.assertTrue(info["is_available"])
            self.assertIn("feature_names", info)
            self.assertGreater(len(info["feature_names"]), 0)
            self.assertEqual(len(info["feature_names"]), info["feature_count"])

            # Verify against actual loaded model
            loaded = load_model(model_name)
            self.assertEqual(info["feature_names"], loaded.feature_names)
            self.assertEqual(info["port_policy"], loaded.port_policy)

    def test_12_port_policy_differentiation(self):
        """12. A dataset lacking port features matches port_excluded models but not port_inclusive models."""
        # Create TQH dataset without 'resp_p'
        tqh_no_port = self.df_tqh.drop(columns=["resp_p"])

        diag = assess_dataset_compatibility(tqh_no_port, manifest=self.manifest)
        self.assertIn("xshield_tqh_c2_port_excluded", diag["compatible_models"])
        self.assertNotIn("xshield_tqh_c2_port_inclusive", diag["compatible_models"])
        # Unambiguous recommendation must be port_excluded
        self.assertEqual(diag["recommended_model"], "xshield_tqh_c2_port_excluded")


if __name__ == "__main__":
    unittest.main()
