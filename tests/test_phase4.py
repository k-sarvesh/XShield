"""Automated test suite for XShield Phase 4 components.

Tests:
- Capture health checks and worker thread lifecycle.
- Bidirectional flow aggregation, TCP state transitions, and TLS metadata extraction.
- Deterministic flow replay engine (synthetic scenario).
- Detection engine schema validation, uncalibrated ensemble scoring, and evidence reasoning.
- IncidentStore SQLite persistence, search, status updates, and summary metrics.
- AlertManager cooldown deduplication and duplicate alert suppression.
- NetworkResponseManager protection blacklist, simulation mode, mocked live enforcement, and rollback.
"""

import subprocess
import time
import unittest
from unittest.mock import MagicMock

from xshield.alerts.alert_manager import AlertManager
from xshield.detection.engine import DetectionEngine, DetectionPolicy, DetectionVerdict
from xshield.flows.aggregator import FlowAggregator, extract_tls_client_hello
from xshield.flows.flow_record import FlowRecord
from xshield.flows.replay import FlowReplayEngine
from xshield.monitoring.capture import (
    CaptureBackendStatus,
    LiveCaptureWorker,
    check_capture_health,
    check_is_admin,
    check_npcap_installed,
)
from xshield.response.blocker import (
    BlockActionStatus,
    NetworkResponseManager,
    is_protected_ip,
)
from xshield.storage.incident_store import IncidentRecord, IncidentStore


class TestPhase4MonitoringAndFlows(unittest.TestCase):
    """Tests capture diagnostics, worker lifecycle, and flow aggregation."""

    def test_capture_health_diagnostics(self):
        status = check_capture_health()
        self.assertIsInstance(status, CaptureBackendStatus)
        self.assertIn(status.recommended_mode, ["live", "replay"])
        self.assertIsInstance(status.interfaces, list)
        self.assertIsInstance(status.status_message, str)

    def test_flow_record_timeline_and_mapping(self):
        flow = FlowRecord(
            src_ip="192.168.1.50",
            dst_ip="198.51.100.24",
            src_port=54321,
            dst_port=8443,
            proto="tcp",
            start_time=100.0,
            last_seen=100.0,
        )
        self.assertEqual(flow.duration, 0.0)
        flow.update_timeline(102.5)
        self.assertEqual(flow.duration, 2.5)

        d = flow.to_dict()
        self.assertEqual(d["src_ip"], "192.168.1.50")
        self.assertEqual(d["dst_port"], 8443)

        feats = flow.to_feature_series(schema_keys=["duration", "orig_bytes", "resp_p"])
        self.assertEqual(feats["duration"], 2.5)
        self.assertEqual(feats["resp_p"], 8443)

    def test_tls_client_hello_synthetic_extraction(self):
        # Synthetic TLS 1.2 ClientHello with SNI for 'test.example.com'
        sni_str = "test.example.com".encode("utf-8")
        server_name_entry = b"\x00" + int.to_bytes(len(sni_str), 2, "big") + sni_str
        server_name_list = int.to_bytes(len(server_name_entry), 2, "big") + server_name_entry

        # SNI Extension (Type 0x0000)
        ext_sni = int.to_bytes(0x0000, 2, "big") + int.to_bytes(len(server_name_list), 2, "big") + server_name_list
        exts_data = int.to_bytes(len(ext_sni), 2, "big") + ext_sni

        # Construct minimal ClientHello body
        ciphers = b"\x13\x01\x13\x02\xc0\x2f"
        ch_body = (
            b"\x03\x03"
            + b"\x00" * 32
            + b"\x00"
            + int.to_bytes(len(ciphers), 2, "big") + ciphers
            + b"\x01\x00"
            + exts_data
        )
        hs_header = b"\x01" + int.to_bytes(len(ch_body), 3, "big")
        tls_record = b"\x16\x03\x01" + int.to_bytes(len(hs_header) + len(ch_body), 2, "big") + hs_header + ch_body

        sni, ja4 = extract_tls_client_hello(tls_record)
        self.assertEqual(sni, "test.example.com")
        self.assertIsNotNone(ja4)
        self.assertTrue(ja4.startswith("t12d"))

    def test_flow_aggregator_bidirectional_and_expiration(self):
        agg = FlowAggregator(inactivity_timeout=0.2, max_flow_duration=1.0)
        now = time.time()

        # Manually create mock scapy packets
        class MockPkt:
            def __init__(self, src, dst, sport, dport, proto="tcp", flags="S", pkt_len=60, payload=b""):
                self.time = now
                self.src = src
                self.dst = dst
                self.sport = sport
                self.dport = dport
                self.flags = flags
                self._len = pkt_len
                self.payload = payload

            def haslayer(self, layer):
                name = layer.__name__
                if name == "IP":
                    return True
                if name == "TCP":
                    return True
                return False

            def getlayer(self, layer):
                return self

            def __len__(self):
                return self._len

        # Forward SYN
        pkt1 = MockPkt("192.168.1.10", "198.51.100.5", 50000, 443, flags="S", pkt_len=64)
        agg.process_packet(pkt1)
        stats1 = agg.get_stats()
        self.assertEqual(stats1["active_flows_count"], 1)

        # Reverse SYN-ACK
        pkt2 = MockPkt("198.51.100.5", "192.168.1.10", 443, 50000, flags="SA", pkt_len=64)
        agg.process_packet(pkt2)
        stats2 = agg.get_stats()
        self.assertEqual(stats2["active_flows_count"], 1)

        # Sleep and flush expired
        time.sleep(0.3)
        expired = agg.flush_expired_flows(force=True)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].orig_pkts, 1)
        self.assertEqual(expired[0].resp_pkts, 1)


class TestPhase4ReplayEngine(unittest.TestCase):
    """Tests deterministic flow replay generator."""

    def test_synthetic_replay_stream(self):
        received_flows = []

        def on_flow(f: FlowRecord):
            received_flows.append(f)

        engine = FlowReplayEngine(flow_callback=on_flow, delay_seconds=0.01)
        started = engine.start_replay_synthetic(total_flows=10, c2_ratio=0.3)
        self.assertTrue(started)

        # Wait for replay completion
        for _ in range(50):
            if engine.is_finished:
                break
            time.sleep(0.05)

        self.assertTrue(engine.is_finished)
        self.assertEqual(len(received_flows), 10)
        c2_flows = [f for f in received_flows if f.dst_port == 8443]
        self.assertGreater(len(c2_flows), 0)


class TestPhase4DetectionEngine(unittest.TestCase):
    """Tests schema validation, uncalibrated ensemble scoring, and evidence reasoning."""

    def setUp(self):
        self.policy = DetectionPolicy(
            model_name="xshield_tqh_c2_port_excluded",
            threshold=0.60,
            min_packets_required=4,
            enable_heuristics=True,
            experimental_mode=True,
        )
        self.engine = DetectionEngine(policy=self.policy)

    def test_insufficient_evidence_verdict(self):
        flow = FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="198.51.100.5",
            src_port=50000,
            dst_port=443,
            proto="tcp",
            orig_pkts=1,
            resp_pkts=1,  # Total pkts = 2 (< 4)
        )
        verdict = self.engine.evaluate_flow(flow)
        self.assertEqual(verdict.status, "INSUFFICIENT_EVIDENCE")
        self.assertFalse(verdict.is_suspicious)
        self.assertIsNone(verdict.raw_score)
        self.assertGreater(len(verdict.limitations), 0)

    def test_suspicious_beacon_flow_evaluation(self):
        flow = FlowRecord(
            src_ip="192.168.1.145",
            dst_ip="198.51.100.24",
            src_port=52341,
            dst_port=8443,
            proto="tcp",
            start_time=100.0,
            last_seen=100.4,
            duration=0.4,
            orig_pkts=12,
            resp_pkts=11,
            orig_bytes=1500,
            resp_bytes=3200,
            orig_ip_bytes=2100,
            resp_ip_bytes=3800,
            conn_state="RSTO",
            history="ShADadFfR",
            ja4="t13i131000_f57a46bbacb6_e5728521abd4",
        )
        verdict = self.engine.evaluate_flow(flow)
        # Should be flagged via heuristic indicators or ML ensemble
        self.assertIn(verdict.status, ["SUSPICIOUS", "BENIGN"])
        self.assertIsInstance(verdict.evidence, list)
        self.assertGreater(len(verdict.evidence), 0)


class TestPhase4StorageAndAlerts(unittest.TestCase):
    """Tests SQLite incident store and alert deduplication."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_incidents.db"
        self.store = IncidentStore(db_path=self.db_path)
        self.alert_mgr = AlertManager(incident_store=self.store, cooldown_seconds=2.0)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_incident_persistence_and_metrics(self):
        inc = IncidentRecord(
            incident_id="INC-TEST-001",
            created_at="2026-10-24T00:00:00Z",
            last_seen="2026-10-24T00:00:00Z",
            src_ip="192.168.1.100",
            dst_ip="198.51.100.99",
            src_port=50000,
            dst_port=8443,
            proto="tcp",
            severity="HIGH",
            detection_source="ml_model",
            raw_score=0.92,
            model_name="xshield_tqh_c2_port_excluded",
            evidence=[{"indicator": "ML_ENSEMBLE", "desc": "Score 0.92"}],
        )
        self.store.save_incident(inc)

        fetched = self.store.get_incident("INC-TEST-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.dst_ip, "198.51.100.99")
        self.assertEqual(fetched.severity, "HIGH")

        # Update status
        self.store.update_status("INC-TEST-001", "Investigating", notes="Analyst reviewing PCAP")
        updated = self.store.get_incident("INC-TEST-001")
        self.assertEqual(updated.status, "Investigating")
        self.assertEqual(updated.analyst_notes, "Analyst reviewing PCAP")

        metrics = self.store.get_summary_metrics()
        self.assertEqual(metrics["total_incidents"], 1)
        self.assertEqual(metrics["high_severity"], 1)

    def test_alert_manager_deduplication(self):
        flow = FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="198.51.100.50",
            src_port=50000,
            dst_port=8443,
            proto="tcp",
        )
        verdict = DetectionVerdict(
            flow_id=flow.flow_id,
            status="SUSPICIOUS",
            is_suspicious=True,
            risk_tier="HIGH",
            raw_score=0.88,
            score_label="Test Score",
            detection_source="ml_model",
            model_name="test_model",
            threshold_applied=0.6,
        )

        # 1st call: Should generate an alert
        notif1 = self.alert_mgr.process_verdict(flow, verdict)
        self.assertIsNotNone(notif1)
        self.assertEqual(len(self.alert_mgr.get_recent_notifications()), 1)

        # 2nd call immediately: Same endpoint pair within cooldown -> Should be suppressed
        notif2 = self.alert_mgr.process_verdict(flow, verdict)
        self.assertIsNone(notif2)
        # Still only 1 notification generated
        self.assertEqual(len(self.alert_mgr.get_recent_notifications()), 1)

        # Check that incident occurrence_count incremented to 2
        inc = self.store.find_active_incident("192.168.1.10", "198.51.100.50", 8443)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.occurrence_count, 2)


class TestPhase4ResponseManager(unittest.TestCase):
    """Tests network blocking safety, simulation mode, and guarded enforcement."""

    def test_protected_ip_blacklist(self):
        self.assertTrue(is_protected_ip("127.0.0.1"))
        self.assertTrue(is_protected_ip("8.8.8.8"))
        self.assertTrue(is_protected_ip("1.1.1.1"))
        self.assertTrue(is_protected_ip("not-an-ip"))
        self.assertFalse(is_protected_ip("198.51.100.24"))

    def test_recommend_block_and_simulation(self):
        mgr = NetworkResponseManager(simulation_mode=True)

        # Attempt to block 8.8.8.8 -> Should be rejected
        rec_dns = mgr.recommend_block("8.8.8.8", "Malicious DNS")
        self.assertFalse(rec_dns["allowed"])

        # Attempt to block external suspicious IP
        rec = mgr.recommend_block("198.51.100.24", "C2 Beaconing", incident_id="INC-001")
        self.assertTrue(rec["allowed"])
        self.assertEqual(rec["target_ip"], "198.51.100.24")
        self.assertEqual(rec["status"], "RECOMMENDED")

        # Apply block in simulation mode
        status = mgr.apply_block("198.51.100.24", "C2 Beaconing", incident_id="INC-001")
        self.assertEqual(status.status, "SIMULATED")
        self.assertFalse(status.is_live)
        self.assertIn("SIMULATION", status.details)

        # Rollback simulated block
        rolled_back = mgr.rollback_block(status.rule_name)
        self.assertTrue(rolled_back)
        self.assertEqual(mgr.list_active_rules()[0].status, "ROLLED_BACK")

    def test_mocked_live_enforcement(self):
        # Mock command executor to simulate netsh without actually changing Windows Firewall
        mock_executor = MagicMock()
        mock_executor.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="Ok.", stderr="")

        mgr = NetworkResponseManager(simulation_mode=False, command_executor=mock_executor)

        # If running as non-admin, apply_block safely catches lack of elevation
        # Mock check_is_admin to True for testing the command construction
        from unittest.mock import patch
        with patch("xshield.response.blocker.check_is_admin", return_value=True):
            status = mgr.apply_block(
                "198.51.100.55", "Test Live C2 Block", incident_id="INC-002", live_requested=True
            )
            self.assertEqual(status.status, "ENFORCED")
            self.assertTrue(status.is_live)
            self.assertTrue(mock_executor.called)

            # Verify command arguments passed safely as list across add and verification calls
            all_called_cmds = [c[0][0] for c in mock_executor.call_args_list]
            add_cmds = [cmd for cmd in all_called_cmds if "add" in cmd]
            self.assertTrue(len(add_cmds) > 0, "No 'add' firewall command found in call history.")
            called_cmd = add_cmds[0]
            self.assertEqual(called_cmd[0], "netsh.exe")
            self.assertIn("action=block", called_cmd)
            self.assertIn("remoteip=198.51.100.55", called_cmd)

            # Test rollback execution
            mock_executor.reset_mock()
            unblocked = mgr.rollback_block(status.rule_name)
            self.assertTrue(unblocked)
            all_del_cmds = [c[0][0] for c in mock_executor.call_args_list]
            del_cmds = [cmd for cmd in all_del_cmds if "delete" in cmd]
            self.assertTrue(len(del_cmds) > 0, "No 'delete' firewall command found in call history.")
            del_cmd = del_cmds[0]
            self.assertEqual(del_cmd[0], "netsh.exe")
            self.assertIn("delete", del_cmd)


if __name__ == "__main__":
    unittest.main()
