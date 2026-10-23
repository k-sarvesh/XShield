"""Deterministic End-to-End Demo Acceptance Test for XShield Phase 4.1.

Validates the full 10-step demonstration chain:
1. Start replay mode with deterministic generator.
2. Ingest and evaluate known benign fixture (TLS browsing).
3. Ingest and evaluate documented synthetic suspicious fixture (C2 beacon).
4. Verify detection source and explicit evidence attribution.
5. Persist an incident in the incident store.
6. Query and confirm the incident appears in the store/dashboard.
7. Demonstrate cooldown duplicate alert suppression.
8. Recommend containment block and verify safety protections.
9. Execute simulated firewall block and demonstrate clean rollback.
10. Export, sanitize, and verify incident history.
"""

import tempfile
import time
import unittest
from pathlib import Path

from xshield.alerts.alert_manager import AlertManager
from xshield.detection.engine import DetectionEngine, DetectionPolicy, DetectionVerdict
from xshield.flows.flow_record import FlowRecord
from xshield.flows.replay import FlowReplayEngine
from xshield.response.blocker import (
    BlockActionStatus,
    NetworkResponseManager,
    is_protected_ip,
)
from xshield.storage.incident_store import (
    IncidentRecord,
    IncidentStore,
    sanitize_incident_export,
)


class TestDemoAcceptance(unittest.TestCase):
    """End-to-end acceptance tests verifying the 10-step demonstration chain."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "demo_acceptance_store.db"
        self.store = IncidentStore(db_path=self.db_path)
        self.alert_mgr = AlertManager(incident_store=self.store, cooldown_seconds=3.0)
        self.policy = DetectionPolicy(
            model_name="xshield_tqh_c2_port_excluded",
            threshold=0.60,
            min_packets_required=4,
            enable_heuristics=True,
            experimental_mode=True,
        )
        self.engine = DetectionEngine(policy=self.policy)
        self.response_mgr = NetworkResponseManager(simulation_mode=True)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_full_10_step_demo_acceptance_chain(self):
        """Executes the full 10-step deterministic sequence in a single continuous chain."""

        # -------------------------------------------------------------
        # STEP 1: Start Replay Mode
        # -------------------------------------------------------------
        replayed_flows = []

        def on_replay_flow(f: FlowRecord):
            replayed_flows.append(f)

        replay_engine = FlowReplayEngine(flow_callback=on_replay_flow, delay_seconds=0.005)
        replay_started = replay_engine.start_replay_synthetic(total_flows=5, c2_ratio=0.4)
        self.assertTrue(replay_started, "Step 1 Failed: Replay engine could not be started.")

        for _ in range(40):
            if replay_engine.is_finished:
                break
            time.sleep(0.02)

        self.assertTrue(replay_engine.is_finished, "Step 1 Failed: Replay engine did not complete.")
        self.assertEqual(len(replayed_flows), 5, "Step 1 Failed: Did not receive expected flow count.")
        self.assertTrue(all(f.is_synthetic for f in replayed_flows), "Step 1 Failed: Replayed flows must be marked synthetic.")

        # -------------------------------------------------------------
        # STEP 2: Process Known Benign Fixture
        # -------------------------------------------------------------
        benign_flow = FlowRecord(
            src_ip="192.168.1.45",
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
        verdict_benign = self.engine.evaluate_flow(benign_flow)
        self.assertEqual(verdict_benign.status, "BENIGN", "Step 2 Failed: Benign flow was not classified as BENIGN.")
        self.assertFalse(verdict_benign.is_suspicious, "Step 2 Failed: Benign flow flagged as suspicious.")
        self.assertTrue(verdict_benign.is_synthetic, "Step 2 Failed: Synthetic flag was lost on benign verdict.")

        notif_benign = self.alert_mgr.process_verdict(benign_flow, verdict_benign)
        self.assertIsNone(notif_benign, "Step 2 Failed: Benign flow generated an alert.")

        # -------------------------------------------------------------
        # STEP 3: Process Synthetic Suspicious Fixture
        # -------------------------------------------------------------
        suspicious_flow = FlowRecord(
            src_ip="192.168.1.145",
            dst_ip="198.51.100.24",  # RFC 5737 TEST-NET-2 documentation IP
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
        verdict_suspicious = self.engine.evaluate_flow(suspicious_flow)
        self.assertTrue(verdict_suspicious.is_suspicious, "Step 3 Failed: Suspicious flow was not flagged.")
        self.assertEqual(verdict_suspicious.status, "SUSPICIOUS", "Step 3 Failed: Status must be SUSPICIOUS.")

        # -------------------------------------------------------------
        # STEP 4: Show Detection Source and Evidence
        # -------------------------------------------------------------
        self.assertIn(
            verdict_suspicious.detection_source,
            ["hybrid", "heuristic", "ml_model"],
            "Step 4 Failed: Detection source was not specified.",
        )
        self.assertTrue(verdict_suspicious.is_synthetic, "Step 4 Failed: Synthetic flag lost on suspicious verdict.")
        self.assertGreater(len(verdict_suspicious.evidence), 0, "Step 4 Failed: Missing evidence records.")

        evidence_indicators = [e["indicator"] for e in verdict_suspicious.evidence]
        self.assertTrue(
            any("SYNTHETIC_REPLAY" in ind for ind in evidence_indicators),
            "Step 4 Failed: Synthetic evidence tag missing.",
        )
        # Evidence must provide actionable details
        for item in verdict_suspicious.evidence:
            self.assertTrue("description" in item or "desc" in item)
            self.assertTrue("confidence" in item or "weight" in item)

        # -------------------------------------------------------------
        # STEP 5: Persist an Incident
        # -------------------------------------------------------------
        notif = self.alert_mgr.process_verdict(suspicious_flow, verdict_suspicious)
        self.assertIsNotNone(notif, "Step 5 Failed: Suspicious verdict did not produce an alert notification.")
        self.assertTrue(notif.is_synthetic, "Step 5 Failed: Notification must reflect synthetic origin.")
        self.assertIn("198.51.100.24", notif.dst_endpoint)

        persisted_inc = self.store.get_incident(notif.incident_id)
        self.assertIsNotNone(persisted_inc, "Step 5 Failed: Incident was not saved to SQLite store.")
        self.assertEqual(persisted_inc.dst_ip, "198.51.100.24")
        self.assertEqual(persisted_inc.is_synthetic, 1, "Step 5 Failed: SQLite is_synthetic column must be 1.")

        # -------------------------------------------------------------
        # STEP 6: Confirm Incident Appears in Dashboard/Store Query
        # -------------------------------------------------------------
        incidents = self.store.list_incidents(limit=10)
        self.assertEqual(len(incidents), 1, "Step 6 Failed: Active incident not returned in incident listing.")
        self.assertEqual(incidents[0].incident_id, notif.incident_id)
        self.assertEqual(incidents[0].status, "New")

        # Analyst updates incident state
        updated = self.store.update_status(notif.incident_id, "Investigating", notes="Analyst confirmed C2 pattern.")
        self.assertTrue(updated, "Step 6 Failed: Incident status update failed.")
        refetched = self.store.get_incident(notif.incident_id)
        self.assertEqual(refetched.status, "Investigating")
        self.assertIn("Analyst confirmed C2 pattern.", refetched.analyst_notes)

        # -------------------------------------------------------------
        # STEP 7: Demonstrate Duplicate Alert Suppression
        # -------------------------------------------------------------
        # Send twin flow within cooldown window (cooldown is 3.0s)
        twin_flow = FlowRecord(
            src_ip="192.168.1.145",
            dst_ip="198.51.100.24",
            src_port=52342,
            dst_port=8443,
            proto="tcp",
            start_time=101.0,
            last_seen=101.4,
            duration=0.4,
            orig_pkts=10,
            resp_pkts=8,
            is_synthetic=True,
        )
        notif_dup = self.alert_mgr.process_verdict(twin_flow, verdict_suspicious)
        self.assertIsNone(notif_dup, "Step 7 Failed: Duplicate alert was not suppressed by cooldown.")

        # Confirm incident occurrence count was incremented in storage
        coalesced_inc = self.store.find_active_incident("192.168.1.145", "198.51.100.24", 8443, proto="tcp")
        self.assertIsNotNone(coalesced_inc, "Step 7 Failed: Active incident not found for coalesced flow.")
        self.assertEqual(coalesced_inc.occurrence_count, 2, "Step 7 Failed: Occurrence count was not incremented.")

        # -------------------------------------------------------------
        # STEP 8: Simulate Block Recommendation & Safety Verification
        # -------------------------------------------------------------
        # Verify protected addresses are safely rejected
        rec_local = self.response_mgr.recommend_block("127.0.0.1", "Localhost Block Attempt")
        self.assertFalse(rec_local["allowed"], "Step 8 Failed: Localhost must be protected from blocking.")
        rec_dns = self.response_mgr.recommend_block("8.8.8.8", "DNS Block Attempt")
        self.assertFalse(rec_dns["allowed"], "Step 8 Failed: Google DNS must be protected from blocking.")

        # Generate block recommendation for synthetic C2 target
        rec_c2 = self.response_mgr.recommend_block(
            target_ip="198.51.100.24",
            reason="Synthetic C2 Beaconing Activity",
            incident_id=notif.incident_id,
            duration_minutes=30,
        )
        self.assertTrue(rec_c2["allowed"], "Step 8 Failed: Valid RFC 5737 test IP was unexpectedly rejected.")
        self.assertEqual(rec_c2["status"], "RECOMMENDED")
        self.assertEqual(rec_c2["target_ip"], "198.51.100.24")
        self.assertEqual(rec_c2["duration_minutes"], 30)
        self.assertIn("potential_impact", rec_c2)

        # -------------------------------------------------------------
        # STEP 9: Record Response and Demonstrate Rollback
        # -------------------------------------------------------------
        block_status = self.response_mgr.apply_block(
            target_ip="198.51.100.24",
            reason="Synthetic C2 Beaconing Activity",
            incident_id=notif.incident_id,
            duration_minutes=30,
        )
        self.assertEqual(block_status.status, "SIMULATED", "Step 9 Failed: Response was not marked SIMULATED.")
        self.assertFalse(block_status.is_live, "Step 9 Failed: Simulated block claimed live enforcement.")
        self.assertIsNotNone(block_status.expires_at, "Step 9 Failed: Expiration timestamp missing.")

        active_rules = self.response_mgr.list_active_rules()
        self.assertEqual(len(active_rules), 1)
        self.assertEqual(active_rules[0].rule_name, block_status.rule_name)

        # Demonstrate rollback
        rollback_success = self.response_mgr.rollback_block(block_status.rule_name)
        self.assertTrue(rollback_success, "Step 9 Failed: Rollback failed.")
        active_rules_post = self.response_mgr.list_active_rules()
        self.assertEqual(len(active_rules_post), 1)
        self.assertEqual(active_rules_post[0].status, "ROLLED_BACK")

        # -------------------------------------------------------------
        # STEP 10: Export and Inspect Resulting Event History
        # -------------------------------------------------------------
        raw_csv = self.store.export_incidents_csv()
        for col in ["incident_id", "created_at", "last_seen", "src_ip", "dst_ip", "severity", "status"]:
            self.assertIn(col, raw_csv, f"Step 10 Failed: CSV header '{col}' missing.")
        self.assertIn(notif.incident_id, raw_csv)
        self.assertIn("198.51.100.24", raw_csv)

        # Sanitize export with internal IP anonymization
        sanitized_csv = self.store.export_incidents_csv(anonymize_internal=True)
        # RFC 1918 192.168.1.145 should be anonymized to internal placeholder
        self.assertNotIn("192.168.1.145", sanitized_csv, "Step 10 Failed: Internal IP was not anonymized.")
        # Target external test IP 198.51.100.24 should remain visible
        self.assertIn("198.51.100.24", sanitized_csv, "Step 10 Failed: External test IP was lost.")
        # Status 'Investigating' should be preserved
        self.assertIn("Investigating", sanitized_csv)
        # Verify no control character or formula injection
        lines = sanitized_csv.splitlines()
        for line in lines[1:]:
            parts = line.split(",")
            for part in parts:
                self.assertFalse(part.startswith(("=", "+", "-", "@")), f"Potential formula injection: {part}")

    def test_rule_expiration_and_cleanup(self):
        """Verifies that expired temporary block rules are safely rolled back and cleaned up."""
        import datetime
        status = self.response_mgr.apply_block(
            "198.51.100.33", "Temporary Containment Test", duration_minutes=30
        )
        self.assertEqual(status.status, "SIMULATED")

        # Artificially expire the rule by setting expires_at to 10 minutes in the past
        past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).isoformat()
        with self.response_mgr._lock:
            if status.rule_name in self.response_mgr._active_rules:
                self.response_mgr._active_rules[status.rule_name].expires_at = past_time

        cleaned = self.response_mgr.cleanup_expired_rules()
        self.assertIn(status.rule_name, cleaned)
        rules = self.response_mgr.list_active_rules()
        matching = [r for r in rules if r.rule_name == status.rule_name]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].status, "EXPIRED")

    def test_schema_incompatible_insufficient_evidence(self):
        """Verifies that flows lacking model features produce INSUFFICIENT_EVIDENCE rather than BENIGN."""
        # Flow with adequate packet count (12 pkts) but benign attributes and schema mismatch simulation
        flow = FlowRecord(
            src_ip="192.168.1.55",
            dst_ip="93.184.216.34",
            src_port=51111,
            dst_port=443,
            proto="tcp",
            orig_pkts=6,
            resp_pkts=6,
            conn_state="SF",
            history="ShADadFf",
        )
        # Use a model requiring features not on this raw flow, with heuristics disabled
        policy = DetectionPolicy(
            model_name="xshield_tqh_c2_port_excluded",
            threshold=0.60,
            min_packets_required=4,
            enable_heuristics=False,
        )
        engine = DetectionEngine(policy=policy)
        # Monkeypatch flow.to_feature_series to simulate missing features
        flow.to_feature_series = lambda schema_keys=None: {"duration": 0.5, "proto": "tcp"}
        verdict = engine.evaluate_flow(flow)
        self.assertEqual(verdict.status, "INSUFFICIENT_EVIDENCE")
        self.assertFalse(verdict.is_suspicious)
        self.assertEqual(verdict.detection_source, "insufficient_evidence")

    def test_webhook_failure_resilience(self):
        """Verifies that webhook failures do not crash alert manager and are recorded honestly."""
        bad_mgr = AlertManager(
            incident_store=self.store,
            cooldown_seconds=1.0,
            webhook_url="http://127.0.0.1:54321/nonexistent_webhook",
        )
        flow = FlowRecord(
            src_ip="192.168.1.188",
            dst_ip="198.51.100.88",
            src_port=52000,
            dst_port=8443,
            proto="tcp",
        )
        verdict = DetectionVerdict(
            flow_id=flow.flow_id,
            status="SUSPICIOUS",
            is_suspicious=True,
            risk_tier="HIGH",
            raw_score=0.95,
            score_label="Test",
            detection_source="ml_model",
            model_name="test_model",
            threshold_applied=0.6,
        )
        # Must not raise an exception
        notif = bad_mgr.process_verdict(flow, verdict)
        self.assertIsNotNone(notif)

        # Allow background dispatch thread to attempt connection (up to 3.0s)
        for _ in range(60):
            if notif.webhook_delivered is False and notif.webhook_error is not None:
                break
            time.sleep(0.05)

        self.assertFalse(notif.webhook_delivered)
        self.assertIsNotNone(notif.webhook_error)
        # Incident should still be persisted
        inc = self.store.get_incident(notif.incident_id)
        self.assertIsNotNone(inc)


if __name__ == "__main__":
    unittest.main()

