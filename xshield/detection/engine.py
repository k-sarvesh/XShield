"""Detection engine, schema validator, and evidence reasoner for XShield.

Enforces:
- Schema compatibility verification before calling any model.
- Transparent distinction between uncalibrated ML ensemble vote scores and deterministic indicators.
- Explicit 'INSUFFICIENT_EVIDENCE' verdicts for incomplete flows, missing features, or incompatible schemas.
- Explicit tagging of synthetic demonstration records (`is_synthetic=True`).
- Multi-dimensional evidence reporting with confidence and limitation statements.
- Safe execution in designated 'Experimental Detection / Telemetry Mode'.
"""

from dataclasses import dataclass, field
import datetime
import logging
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from xshield.flows.flow_record import FlowRecord
from xshield.pipeline import MODELS_DIR, XShieldModel, load_model
from xshield.triage import check_model_compatibility, load_manifest_models

logger = logging.getLogger(__name__)


@dataclass
class DetectionVerdict:
    """Detailed verdict and evidence attached to a scored network flow."""
    flow_id: str
    status: str            # 'BENIGN', 'SUSPICIOUS', 'INSUFFICIENT_EVIDENCE'
    is_suspicious: bool
    risk_tier: str         # 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    raw_score: Optional[float]
    score_label: str       # E.g. 'Uncalibrated Tree Ensemble Vote [0.0 - 1.0]'
    detection_source: str  # 'ml_model', 'heuristic_indicator', 'hybrid', 'insufficient_evidence'
    model_name: Optional[str]
    threshold_applied: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    is_synthetic: bool = False
    evaluated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class DetectionPolicy:
    """Configurable scoring policy and thresholds."""
    model_name: str = "xshield_tqh_c2_port_excluded"
    threshold: float = 0.65
    min_packets_required: int = 4
    enable_heuristics: bool = True
    experimental_mode: bool = True
    alert_on_heuristics_alone: bool = True


class DetectionEngine:
    """Orchestrates schema-safe model scoring, heuristic rules, and evidence aggregation."""

    def __init__(self, policy: Optional[DetectionPolicy] = None):
        self.policy = policy or DetectionPolicy()
        self.manifest = load_manifest_models()
        self._loaded_models: Dict[str, XShieldModel] = {}
        self._load_active_model()

    def _load_active_model(self) -> None:
        """Loads the configured active model if available in manifest."""
        m_name = self.policy.model_name
        if m_name and m_name not in self._loaded_models:
            try:
                model = load_model(m_name)
                self._loaded_models[m_name] = model
                logger.info(f"Loaded active detection model: {m_name}")
            except Exception as e:
                logger.warning(f"Could not load model '{m_name}': {e}")

    def set_policy(self, policy: DetectionPolicy) -> None:
        self.policy = policy
        self._load_active_model()

    def evaluate_flow(self, flow: FlowRecord) -> DetectionVerdict:
        """Evaluates a FlowRecord and produces a comprehensive DetectionVerdict."""
        evidence: List[Dict[str, Any]] = []
        limitations: List[str] = []
        is_synthetic = bool(getattr(flow, "is_synthetic", False) or getattr(flow, "is_replayed", False))

        if is_synthetic:
            evidence.append({
                "indicator": "SYNTHETIC_REPLAY_SOURCE",
                "description": "Flow originated from synthetic demonstration replay engine.",
                "confidence": "DEMO_FIXTURE",
            })

        # 1. Heuristic rules evaluation (evaluated on all flows, including single-packet probes)
        heuristic_flagged = False
        heuristic_severity = "MEDIUM"

        if self.policy.enable_heuristics:
            # Check A: Known Malicious / C2 Service Ports
            if flow.dst_port in [4444, 1337, 31337, 8443, 6667, 9001, 9050, 23]:
                evidence.append({
                    "indicator": "KNOWN_MALICIOUS_C2_PORT",
                    "description": (
                        f"Target port {flow.dst_port} matches known C2 framework / backdoor listener profile "
                        f"(Metasploit, Sliver, Tor, or unauthorized daemon)."
                    ),
                    "confidence": "HIGH (Heuristic Threat Port)",
                })
                heuristic_flagged = True
                heuristic_severity = "HIGH"

            # Check B: Reconnaissance / Port Scanning (SYN scan or connection refused)
            if flow.conn_state in ["S0", "REJ"] or (flow.orig_pkts >= 1 and flow.resp_pkts == 0 and flow.dst_port in [22, 23, 445, 3389, 8080]):
                evidence.append({
                    "indicator": "PORT_SCAN_RECON",
                    "description": (
                        f"Probing connection attempt to port {flow.dst_port} with no application response "
                        f"(State: {flow.conn_state}, Orig: {flow.orig_pkts} pkts)."
                    ),
                    "confidence": "HIGH (Port Reconnaissance Heuristic)",
                })
                heuristic_flagged = True
                heuristic_severity = "HIGH"

            # Check C: Unusual high-port TLS beaconing with TCP resets
            if flow.dst_port in [8443, 8080, 4444, 1337] and flow.conn_state in ["RSTO", "RSTR"]:
                evidence.append({
                    "indicator": "NON_STANDARD_PORT_RESET",
                    "description": (
                        f"Connection to non-standard service port {flow.dst_port} "
                        f"terminated abruptly with client TCP reset ({flow.conn_state})."
                    ),
                    "confidence": "HEURISTIC (Operational Indicator, Not Proof of Malware)",
                })
                heuristic_flagged = True
                heuristic_severity = "HIGH"

            # Check D: Known Go/Sliver testbed TLS client fingerprint
            if flow.ja4 and any(b in flow.ja4 for b in ["t13i131000", "t12i121000", "f57a46bbacb6"]):
                evidence.append({
                    "indicator": "SUSPICIOUS_JA4_FINGERPRINT",
                    "description": (
                        f"TLS client fingerprint '{flow.ja4}' matches automated C2 testbed implant profile."
                    ),
                    "confidence": "HEURISTIC (Known Testbed Implementation Shortcut)",
                })
                heuristic_flagged = True
                heuristic_severity = "HIGH"

            # Check E: DNS Tunneling Exfiltration
            if flow.proto == "udp" and flow.dst_port == 53 and (flow.orig_bytes > 1200 or flow.orig_pkts > 20):
                evidence.append({
                    "indicator": "DNS_TUNNEL_EXFILTRATION",
                    "description": (
                        f"Anomalous DNS volume ({flow.orig_bytes} bytes / {flow.orig_pkts} pkts) "
                        f"exceeding standard query thresholds."
                    ),
                    "confidence": "HIGH (DNS Payload Anomaly)",
                })
                heuristic_flagged = True
                heuristic_severity = "HIGH"

            # Check F: Short duration empty payload beaconing pattern
            if 0.05 <= flow.duration <= 0.8 and 8 <= flow.orig_pkts <= 20 and 8 <= flow.resp_pkts <= 20:
                evidence.append({
                    "indicator": "BEACON_VOLUME_SIGNATURE",
                    "description": (
                        f"Bimodal packet count ({flow.orig_pkts} orig / {flow.resp_pkts} resp) "
                        f"and duration ({flow.duration:.2f}s) aligns with automated C2 poll sequence."
                    ),
                    "confidence": "MEDIUM",
                })
                heuristic_flagged = True

        # 2. Gate check: minimum packets required for ML behavioral modeling
        if flow.tot_pkts < self.policy.min_packets_required and not heuristic_flagged:
            limitations.append(
                f"Flow contains only {flow.tot_pkts} packets (< {self.policy.min_packets_required} min required). "
                "Behavioral statistics cannot be reliably computed."
            )
            return DetectionVerdict(
                flow_id=flow.flow_id,
                status="INSUFFICIENT_EVIDENCE",
                is_suspicious=False,
                risk_tier="INFORMATIONAL",
                raw_score=None,
                score_label="N/A (Insufficient Flow Volume)",
                detection_source="insufficient_evidence",
                model_name=self.policy.model_name,
                threshold_applied=self.policy.threshold,
                evidence=evidence,
                limitations=limitations,
                is_synthetic=is_synthetic,
            )

        # 3. ML Model inference with strict schema verification
        raw_score: Optional[float] = None
        ml_flagged = False
        schema_incompatible = False
        m_name = self.policy.model_name
        active_model = self._loaded_models.get(m_name)

        if active_model and flow.tot_pkts >= self.policy.min_packets_required:
            req_features = active_model.feature_names
            flow_feats = flow.to_feature_series()
            missing = [f for f in req_features if f not in flow_feats]

            if missing:
                schema_incompatible = True
                limitations.append(
                    f"Model '{m_name}' requires features {missing[:3]} which are unavailable on this live flow."
                )
            else:
                try:
                    row_data = {f: [flow_feats[f]] for f in req_features}
                    df_row = pd.DataFrame(row_data)

                    probs = active_model.pipeline.predict_proba(df_row)
                    raw_score = float(probs[0, 1])

                    if raw_score >= self.policy.threshold:
                        ml_flagged = True
                        evidence.append({
                            "indicator": "ML_ENSEMBLE_DETECTION",
                            "description": (
                                f"Model '{m_name}' scored flow at {raw_score:.3f} "
                                f"(Threshold: {self.policy.threshold:.2f})."
                            ),
                            "confidence": "EXPERIMENTAL (Uncalibrated Tree Ensemble Vote)",
                        })
                    else:
                        evidence.append({
                            "indicator": "ML_ENSEMBLE_CLEARED",
                            "description": f"Model '{m_name}' scored flow at {raw_score:.3f} (Below threshold).",
                            "confidence": "LOW",
                        })

                except Exception as e:
                    limitations.append(f"Inference error with model '{m_name}': {e}")
        else:
            limitations.append(f"Model '{m_name}' is not loaded or unavailable in manifest.")

        if self.policy.experimental_mode:
            limitations.append(
                "Model is operating in Experimental Telemetry Mode. Scores reflect decision tree votes, "
                "not calibrated posterior compromise probabilities."
            )

        # 4. Synthesize final status and risk tier
        if schema_incompatible and not heuristic_flagged:
            # Model could not evaluate and no heuristics triggered -> INSUFFICIENT_EVIDENCE
            return DetectionVerdict(
                flow_id=flow.flow_id,
                status="INSUFFICIENT_EVIDENCE",
                is_suspicious=False,
                risk_tier="INFORMATIONAL",
                raw_score=None,
                score_label="N/A (Schema Incompatibility)",
                detection_source="insufficient_evidence",
                model_name=m_name,
                threshold_applied=self.policy.threshold,
                evidence=evidence,
                limitations=limitations,
                is_synthetic=is_synthetic,
            )

        if ml_flagged and heuristic_flagged:
            status = "SUSPICIOUS"
            risk_tier = "HIGH"
            detection_source = "hybrid"
        elif ml_flagged:
            status = "SUSPICIOUS"
            risk_tier = "HIGH" if (raw_score and raw_score > 0.85) else "MEDIUM"
            detection_source = "ml_model"
        elif heuristic_flagged and self.policy.alert_on_heuristics_alone:
            status = "SUSPICIOUS"
            risk_tier = heuristic_severity
            detection_source = "heuristic_indicator"
        else:
            status = "BENIGN"
            risk_tier = "LOW"
            detection_source = "none"

        is_suspicious = (status == "SUSPICIOUS")

        return DetectionVerdict(
            flow_id=flow.flow_id,
            status=status,
            is_suspicious=is_suspicious,
            risk_tier=risk_tier,
            raw_score=raw_score,
            score_label="Uncalibrated Ensemble Vote [0.0 - 1.0]" if raw_score is not None else "N/A",
            detection_source=detection_source,
            model_name=m_name,
            threshold_applied=self.policy.threshold,
            evidence=evidence,
            limitations=limitations,
            is_synthetic=is_synthetic,
        )
