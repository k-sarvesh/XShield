"""Automated regression test suite for XShield Phase 4.2.

Covers:
1. Protected-IP information renders without NameError.
2. Detection engine is available before replay starts.
3. A replayed flow reaches the detection engine.
4. Flow and incident data are persisted and become visible to the UI.
5. Benign and synthetic suspicious scenarios follow the intended verdict paths.
6. Worker exceptions are surfaced and handled safely without silent suppression.
7. Repeated starts do not create duplicate workers.
8. Stop and restart behavior remains correct and clean.
9. Existing protected-IP and simulated-blocking safeguards still pass.
"""

from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from xshield.alerts.alert_manager import AlertManager
from xshield.detection.engine import DetectionEngine, DetectionPolicy, DetectionVerdict
from xshield.flows.flow_record import FlowRecord
from xshield.monitoring.runtime import MonitoringRuntime, get_monitoring_runtime
from xshield.response.blocker import (
    BlockActionStatus,
    NetworkResponseManager,
    PROTECTED_IPS,
    is_protected_ip,
)
from xshield.storage.incident_store import IncidentRecord, IncidentStore


class TestPhase42Regression(unittest.TestCase):
    """Phase 4.2 regression test suite covering runtime stabilization and replay integration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_p42.db"
        self.store = IncidentStore(db_path=self.db_path)
        self.alert_mgr = AlertManager(incident_store=self.store, cooldown_seconds=5.0)
        self.resp_mgr = NetworkResponseManager(simulation_mode=True)
        self.runtime = MonitoringRuntime(
            incident_store=self.store,
            alert_manager=self.alert_mgr,
            response_manager=self.resp_mgr,
        )

    def tearDown(self):
        self.runtime.stop_ingestion()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. Protected-IP information renders without NameError
    # -------------------------------------------------------------------------
    def test_01_protected_ip_rendering_and_configuration(self):
        """Verifies PROTECTED_IPS is defined, imported, and renders without NameError."""
        from app import PROTECTED_IPS as APP_PROTECTED_IPS

        # Must be the identical authoritative set from blocker module
        self.assertIs(APP_PROTECTED_IPS, PROTECTED_IPS)
        self.assertIsInstance(PROTECTED_IPS, set)
        self.assertGreater(len(PROTECTED_IPS), 0)

        # Core critical infrastructure must be present
        for critical_ip in ["127.0.0.1", "::1", "8.8.8.8", "1.1.1.1", "9.9.9.9"]:
            self.assertIn(critical_ip, PROTECTED_IPS)

        # Simulate rendering string from app.py line 727
        rendered_str = f"- **Protected Host Endpoints:** `{len(PROTECTED_IPS)} critical IPs blacklisted from blocking`"
        self.assertIn("critical IPs blacklisted from blocking", rendered_str)
        self.assertIn(str(len(PROTECTED_IPS)), rendered_str)

    # -------------------------------------------------------------------------
    # 2. Detection engine is available before replay starts
    # -------------------------------------------------------------------------
    def test_02_detection_engine_available_before_replay_starts(self):
        """Verifies DetectionEngine is initialized and usable prior to starting replay."""
        fresh_runtime = MonitoringRuntime()
        self.assertIsNotNone(fresh_runtime.detection_engine)
        self.assertIsInstance(fresh_runtime.detection_engine, DetectionEngine)
        self.assertIsNotNone(fresh_runtime.incident_store)
        self.assertIsNotNone(fresh_runtime.alert_manager)
        self.assertIsNotNone(fresh_runtime.response_manager)

        # Engine is ready before any replay engine exists
        self.assertIsNone(fresh_runtime.replay_engine)
        self.assertFalse(fresh_runtime.is_active())

    # -------------------------------------------------------------------------
    # 3. A replayed flow reaches the detection engine
    # -------------------------------------------------------------------------
    def test_03_replayed_flow_reaches_detection_engine(self):
        """Verifies a flow passed to runtime.handle_flow is evaluated and buffered."""
        flow = FlowRecord(
            src_ip="192.168.1.101",
            dst_ip="142.250.190.46",
            src_port=52001,
            dst_port=443,
            proto="tcp",
            start_time=100.0,
            last_seen=101.0,
            duration=1.0,
            orig_pkts=10,
            resp_pkts=12,
            is_replayed=True,
            is_synthetic=True,
        )
        verdict = self.runtime.handle_flow(flow)
        self.assertIsInstance(verdict, DetectionVerdict)
        self.assertEqual(verdict.flow_id, flow.flow_id)

        stats = self.runtime.get_flow_stats()
        self.assertEqual(stats["total"], 1)

        recent = self.runtime.get_recent_flows(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["flow"].src_ip, "192.168.1.101")
        self.assertEqual(recent[0]["verdict"].flow_id, flow.flow_id)

    # -------------------------------------------------------------------------
    # 4. Flow and incident data are persisted and become visible to the UI
    # -------------------------------------------------------------------------
    def test_04_flow_and_incident_data_persisted_and_visible(self):
        """Verifies suspicious replayed flows create persistent incidents accessible to the UI."""
        flow = FlowRecord(
            src_ip="192.168.1.145",
            dst_ip="198.51.100.24",
            src_port=52341,
            dst_port=8443,
            proto="tcp",
            start_time=100.0,
            last_seen=101.05,
            duration=1.05,
            orig_pkts=24,
            resp_pkts=16,
            orig_bytes=2622,
            resp_bytes=2432,
            orig_ip_bytes=3866,
            resp_ip_bytes=3272,
            conn_state="RSTO",
            history="ShADadFR",
            ja4="t13i131000_f57a46bbacb6_e5728521abd4",
            ja4s="t130200_1301_a56c5b993250",
            is_synthetic=True,
        )
        verdict = self.runtime.handle_flow(flow)
        self.assertEqual(verdict.status, "SUSPICIOUS")

        # Incident must be persisted in SQLite incident store
        incidents = self.runtime.incident_store.list_incidents()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.dst_ip, "198.51.100.24")
        self.assertEqual(inc.dst_port, 8443)
        self.assertEqual(inc.is_synthetic, 1)

        # UI metrics must reflect the persisted incident
        summary = self.runtime.incident_store.get_summary_metrics()
        self.assertEqual(summary["total_incidents"], 1)
        self.assertEqual(summary["high_severity"], 1)

    # -------------------------------------------------------------------------
    # 5. Benign and synthetic suspicious scenarios follow intended verdict paths
    # -------------------------------------------------------------------------
    def test_05_benign_and_suspicious_verdict_paths(self):
        """Verifies benign flows clear cleanly while suspicious flows trigger alerts."""
        benign = FlowRecord(
            src_ip="192.168.1.50",
            dst_ip="142.250.190.46",
            src_port=51234,
            dst_port=443,
            proto="tcp",
            start_time=100.0,
            last_seen=101.2,
            duration=1.2,
            orig_pkts=25,
            resp_pkts=30,
            orig_bytes=2400,
            resp_bytes=28500,
            orig_ip_bytes=3400,
            resp_ip_bytes=29700,
            conn_state="SF",
            history="ShADadFf",
            sni="www.google.com",
            ja4="t13d151600_8daaf6152771_0271d4a04d2e",
            ja4s="t130200_1302_234ea6891581",
            is_synthetic=True,
        )
        v_benign = self.runtime.handle_flow(benign)
        self.assertEqual(v_benign.status, "BENIGN")
        self.assertFalse(v_benign.is_suspicious)
        # Benign flow must not create an incident
        self.assertEqual(len(self.runtime.incident_store.list_incidents()), 0)

        suspicious = FlowRecord(
            src_ip="192.168.1.145",
            dst_ip="198.51.100.24",
            src_port=52341,
            dst_port=8443,
            proto="tcp",
            start_time=100.0,
            last_seen=101.05,
            duration=1.05,
            orig_pkts=24,
            resp_pkts=16,
            orig_bytes=2622,
            resp_bytes=2432,
            orig_ip_bytes=3866,
            resp_ip_bytes=3272,
            conn_state="RSTO",
            history="ShADadFR",
            ja4="t13i131000_f57a46bbacb6_e5728521abd4",
            ja4s="t130200_1301_a56c5b993250",
            is_synthetic=True,
        )
        v_suspicious = self.runtime.handle_flow(suspicious)
        self.assertEqual(v_suspicious.status, "SUSPICIOUS")
        self.assertTrue(v_suspicious.is_suspicious)
        self.assertEqual(len(self.runtime.incident_store.list_incidents()), 1)

        stats = self.runtime.get_flow_stats()
        self.assertEqual(stats["benign"], 1)
        self.assertEqual(stats["suspicious"], 1)
        self.assertEqual(stats["total"], 2)

    # -------------------------------------------------------------------------
    # 6. Worker exceptions are surfaced and handled safely
    # -------------------------------------------------------------------------
    def test_06_worker_exceptions_surfaced_safely(self):
        """Verifies runtime records exceptions transparently without silent suppression."""
        flow = FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="198.51.100.5",
            src_port=50000,
            dst_port=443,
            proto="tcp",
        )
        with patch.object(
            self.runtime.detection_engine,
            "evaluate_flow",
            side_effect=RuntimeError("Simulated engine failure"),
        ):
            with self.assertRaises(RuntimeError):
                self.runtime.handle_flow(flow)

        self.assertIsNotNone(self.runtime.last_error)
        self.assertIn("Simulated engine failure", self.runtime.last_error)
        self.assertEqual(len(self.runtime.processing_errors), 1)

    # -------------------------------------------------------------------------
    # 7. Repeated starts do not create duplicate workers
    # -------------------------------------------------------------------------
    def test_07_repeated_starts_prevent_duplicate_workers(self):
        """Verifies calling start_replay repeatedly terminates previous worker cleanly."""
        self.runtime.start_replay(mode="synthetic", delay_seconds=0.02, total_flows=10)
        worker1 = self.runtime.replay_engine
        self.assertIsNotNone(worker1)
        self.assertTrue(self.runtime.is_active())

        # Start a second replay immediately
        self.runtime.start_replay(mode="synthetic", delay_seconds=0.02, total_flows=10)
        worker2 = self.runtime.replay_engine
        self.assertIsNotNone(worker2)
        self.assertIsNot(worker1, worker2)

        # Worker 1 must have been stopped
        self.assertTrue(worker1._stop_event.is_set())

        self.runtime.stop_ingestion()
        self.assertFalse(self.runtime.is_active())

    # -------------------------------------------------------------------------
    # 8. Stop and restart behavior remains correct
    # -------------------------------------------------------------------------
    def test_08_stop_and_restart_behavior(self):
        """Verifies clean stop and restart cycle without deadlocks or thread leaks."""
        # Cycle 1: Start and stop
        self.runtime.start_replay(mode="synthetic", delay_seconds=0.01, total_flows=5)
        self.assertTrue(self.runtime.is_active())
        self.runtime.stop_ingestion()
        self.assertFalse(self.runtime.is_active())
        self.assertIsNone(self.runtime.replay_engine)

        # Cycle 2: Restart and stop
        self.runtime.start_replay(mode="synthetic", delay_seconds=0.01, total_flows=5)
        self.assertTrue(self.runtime.is_active())
        self.runtime.stop_ingestion()
        self.assertFalse(self.runtime.is_active())
        self.assertIsNone(self.runtime.replay_engine)

    # -------------------------------------------------------------------------
    # 9. Existing protected-IP and simulated-blocking safeguards still pass
    # -------------------------------------------------------------------------
    def test_09_protected_ip_and_simulation_safeguards(self):
        """Verifies critical infrastructure protection and simulated-only blocking."""
        self.assertTrue(is_protected_ip("127.0.0.1"))
        self.assertTrue(is_protected_ip("8.8.8.8"))
        self.assertTrue(is_protected_ip("169.254.100.5"))  # RFC 3927 link-local

        # Block recommendation must reject protected IPs
        rec_loopback = self.runtime.response_manager.recommend_block("127.0.0.1", "C2 Block")
        self.assertFalse(rec_loopback["allowed"])
        self.assertIn("protected infrastructure", rec_loopback["error"])

        rec_dns = self.runtime.response_manager.recommend_block("8.8.8.8", "C2 Block")
        self.assertFalse(rec_dns["allowed"])

        # Simulated block on valid test target
        rec_valid = self.runtime.response_manager.recommend_block("198.51.100.24", "C2 Block", duration_minutes=30)
        self.assertTrue(rec_valid["allowed"])
        self.assertEqual(rec_valid["duration_minutes"], 30)

        status = self.runtime.response_manager.apply_block("198.51.100.24", "C2 Block", duration_minutes=30)
        self.assertEqual(status.status, "SIMULATED")
        self.assertFalse(status.is_live)

        # Rollback
        rolled_back = self.runtime.response_manager.rollback_block(status.rule_name)
        self.assertTrue(rolled_back)


if __name__ == "__main__":
    unittest.main()
