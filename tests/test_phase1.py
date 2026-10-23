"""Automated acceptance test suite for XShield Phase 1.

Covers:
- Test A: Train and save pipeline + metadata
- Test B: Reload artifact and verify schema
- Test C: Prediction on unlabelled data and score semantics
- Test D: Exact reproducibility between in-memory and reloaded models
- Test E: Schema validation (missing columns, extra columns, reordering)
- Test F: Missing value imputation handling
- Test G: Leakage safeguards (target, grouping ID, and port exclusions)
"""

import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from xshield.datasets import (
    TQH_C2_EXCLUDED_ALWAYS,
    TQH_C2_PORT_COLUMNS,
    load_cicids2018_sample,
    load_tqh_c2_testbed_a,
)
from xshield.pipeline import (
    XShieldModel,
    build_pipeline,
    load_model,
    predict_flows,
    train_and_save_model,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_DIR / "models"


class TestPhase1Acceptance(unittest.TestCase):
    """Rigorous acceptance test cases for Phase 1 ML pipeline and inference."""

    @classmethod
    def setUpClass(cls):
        """Creates a realistic, small synthetic fixture containing numeric and categorical features."""
        np.random.seed(42)
        cls.n_samples = 60
        cls.feature_names = ["duration", "orig_bytes", "resp_bytes", "proto", "conn_state"]
        cls.numeric_features = ["duration", "orig_bytes", "resp_bytes"]
        cls.categorical_features = ["proto", "conn_state"]

        cls.fixture_X = pd.DataFrame({
            "duration": np.random.exponential(scale=1.5, size=cls.n_samples),
            "orig_bytes": np.random.gamma(shape=2, scale=100, size=cls.n_samples),
            "resp_bytes": np.random.gamma(shape=3, scale=200, size=cls.n_samples),
            "proto": np.random.choice(["tcp", "udp"], size=cls.n_samples),
            "conn_state": np.random.choice(["SF", "S0", "OTH"], size=cls.n_samples),
        })

        cls.fixture_y = pd.Series(
            np.random.choice(["benign", "malicious_c2"], size=cls.n_samples, p=[0.7, 0.3])
        )

    def test_a_train_and_save(self):
        """Test A: Model trains cleanly, persists joblib and metadata JSON."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_a",
                output_dir=tmp_path,
            )

            joblib_file = tmp_path / "test_model_a.joblib"
            json_file = tmp_path / "test_model_a_metadata.json"
            manifest_file = tmp_path / "manifest.json"

            self.assertTrue(joblib_file.exists(), "Model .joblib file was not saved.")
            self.assertTrue(json_file.exists(), "Metadata .json file was not saved.")
            self.assertTrue(manifest_file.exists(), "manifest.json was not updated.")

            with open(json_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            self.assertEqual(meta["model_name"], "test_model_a")
            self.assertEqual(meta["feature_names"], self.feature_names)
            self.assertEqual(sorted(meta["classes"]), ["benign", "malicious_c2"])

    def test_b_reload(self):
        """Test B: Saved artifact can be reloaded in a fresh session with preserved schema."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            orig_model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_b",
                output_dir=tmp_path,
            )

            # Reload via XShieldModel.load
            reloaded = XShieldModel.load("test_model_b", models_dir=tmp_path)
            self.assertIsInstance(reloaded.pipeline, Pipeline)
            self.assertEqual(reloaded.feature_names, self.feature_names)
            self.assertEqual(reloaded.classes, orig_model.classes)
            self.assertEqual(reloaded.positive_class, orig_model.positive_class)

    def test_c_prediction_on_unlabelled_data(self):
        """Test C: Valid unlabelled DataFrame can be scored; risk scores are finite in [0, 1]."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_c",
                output_dir=tmp_path,
            )

            # Prepare unlabelled data (NO label column present)
            unlabelled_df = self.fixture_X.iloc[:10].copy()
            self.assertNotIn("label", unlabelled_df.columns)
            self.assertNotIn("label_raw", unlabelled_df.columns)

            scored = model.predict_flows(unlabelled_df)

            self.assertEqual(len(scored), 10)
            self.assertIn("predicted_label", scored.columns)
            self.assertIn("risk_score", scored.columns)
            self.assertIn("risk_level", scored.columns)
            self.assertIn("prob_benign", scored.columns)
            self.assertIn("prob_malicious_c2", scored.columns)

            # Verify risk score bounds and finiteness
            self.assertTrue(np.all(np.isfinite(scored["risk_score"])))
            self.assertTrue(np.all(scored["risk_score"] >= 0.0))
            self.assertTrue(np.all(scored["risk_score"] <= 1.0))
            self.assertTrue(set(scored["risk_level"]).issubset({"LOW", "MEDIUM", "HIGH", "CRITICAL"}))

    def test_d_prediction_reproducibility(self):
        """Test D: Loaded model produces identical predictions and scores to fitted model."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            orig_model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_d",
                output_dir=tmp_path,
            )
            reloaded_model = XShieldModel.load("test_model_d", models_dir=tmp_path)

            test_input = self.fixture_X.iloc[:15].copy()
            orig_preds = orig_model.predict_flows(test_input)
            reloaded_preds = reloaded_model.predict_flows(test_input)

            pd.testing.assert_frame_equal(orig_preds, reloaded_preds)

    def test_e_schema_validation(self):
        """Test E: Missing columns error; extra columns ignored; reordered columns work."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_e",
                output_dir=tmp_path,
            )

            # 1. Missing required column -> must raise clear ValueError
            missing_df = self.fixture_X.drop(columns=["duration"])
            with self.assertRaises(ValueError) as ctx:
                model.predict_flows(missing_df)
            self.assertIn("Missing 1 required feature", str(ctx.exception))
            self.assertIn("duration", str(ctx.exception))

            # 2. Extra columns -> safely ignored
            extra_df = self.fixture_X.copy()
            extra_df["unrelated_sensor_data"] = 999.9
            extra_df["user_id"] = "agent_007"
            extra_res = model.predict_flows(extra_df)
            self.assertEqual(len(extra_res), len(self.fixture_X))

            # 3. Reordered columns -> produces identical predictions to standard order
            reordered_cols = list(reversed(self.fixture_X.columns))
            reordered_df = self.fixture_X[reordered_cols]
            res_standard = model.predict_flows(self.fixture_X)
            res_reordered = model.predict_flows(reordered_df)
            pd.testing.assert_frame_equal(res_standard, res_reordered)

    def test_f_missing_values(self):
        """Test F: Preprocessing handles NaN/missing values gracefully using median/mode imputation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            model = train_and_save_model(
                X=self.fixture_X,
                y=self.fixture_y,
                dataset_name="Synthetic_Test",
                task_type="binary",
                port_policy="port_excluded",
                model_name="test_model_f",
                output_dir=tmp_path,
            )

            # Input with several NaNs across numeric and categorical features
            df_with_nans = self.fixture_X.iloc[:10].copy()
            df_with_nans.loc[0, "duration"] = np.nan
            df_with_nans.loc[1, "orig_bytes"] = np.nan
            df_with_nans.loc[2, "proto"] = np.nan
            df_with_nans.loc[3, "conn_state"] = None

            res = model.predict_flows(df_with_nans)
            self.assertEqual(len(res), 10)
            self.assertTrue(np.all(np.isfinite(res["risk_score"])))

    def test_g_leakage_safeguards(self):
        """Test G: Target, capture group ID, and ports cannot leak into feature schema."""
        # 1. Test TQH-C2 loader port-inclusive
        X_inc, y_inc, grp_inc, meta_inc = load_tqh_c2_testbed_a(port_policy="port_inclusive")
        self.assertNotIn("capture_id", X_inc.columns, "capture_id leaked into features!")
        self.assertNotIn("label_raw", X_inc.columns, "label_raw leaked into features!")
        self.assertNotIn("y", X_inc.columns, "y leaked into features!")
        self.assertNotIn("ts", X_inc.columns, "timestamp leaked into features!")
        self.assertNotIn("orig_h", X_inc.columns, "orig_h leaked into features!")
        self.assertNotIn("resp_h", X_inc.columns, "resp_h leaked into features!")
        self.assertNotIn("profile", X_inc.columns, "profile leaked into features!")
        self.assertNotIn("interval_s", X_inc.columns, "interval_s leaked into features!")
        self.assertNotIn("orig_p", X_inc.columns, "orig_p ephemeral port leaked into features!")
        self.assertIn("resp_p", X_inc.columns, "resp_p expected in port-inclusive!")

        # 2. Test TQH-C2 loader port-excluded
        X_exc, y_exc, grp_exc, meta_exc = load_tqh_c2_testbed_a(port_policy="port_excluded")
        self.assertNotIn("resp_p", X_exc.columns, "resp_p leaked into port-excluded features!")
        self.assertNotIn("orig_p", X_exc.columns, "orig_p leaked into port-excluded features!")

        # 3. Test CICIDS-2018 port exclusion
        X_cic_inc, y_cic_inc, meta_cic_inc = load_cicids2018_sample(port_policy="port_inclusive")
        self.assertIn("Dst Port", X_cic_inc.columns)
        self.assertNotIn("Label", X_cic_inc.columns)

        X_cic_exc, y_cic_exc, meta_cic_exc = load_cicids2018_sample(port_policy="port_excluded")
        self.assertNotIn("Dst Port", X_cic_exc.columns, "Dst Port leaked into port-excluded CICIDS features!")
        self.assertNotIn("Label", X_cic_exc.columns)


if __name__ == "__main__":
    unittest.main()
