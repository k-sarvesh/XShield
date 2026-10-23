# XShield Phase 4: System Inspection, Pre-Implementation Audit, and Architecture Plan

**Document Status**: Approved Engineering Specification & Audit  
**Date**: October 2026  
**Author**: Antigravity Cybersecurity & ML Architecture Lead  
**Target Environment**: Windows 11 (Python 3.11 Virtual Environment: `.venv`)  
**Workspace**: `G:\IdeaLab\XShield_Starter`  

---

## 1. Executive Summary & Purpose

Phase 4 transitions XShield from a static research and audit platform into an operational, verifiable **Live Network Threat Monitoring and Incident Response Demonstration Prototype**. 

Phase 3 established that reported near-perfect benchmark metrics (>99.9% accuracy) were heavily influenced by:
- Protocol and port shortcuts (port 8443 in TQH-C2; port 8080 in CICIDS-2018)
- Homogeneous TLS client stacks (a single JA4 fingerprint covering 99.94% of C2 flows)
- Intra-testbed flow volume uniformity (Sliver implant container automation)
- 39% record duplication in CICIDS-2018 resulting in 39.48% train-test twin contamination
- Catastrophic cross-testbed transfer collapse (Balanced Accuracy dropped to 55.08% on QUIC and 44.62% on HTTP)
- Uncalibrated tree ensemble vote fractions presented as probabilities

This audit establishes the baseline reality of the codebase, defines the boundaries between verified capabilities and experimental models, and details a modular, reliable architecture for real-time traffic monitoring, flow aggregation, schema-safe detection, analyst alerting, persistent incident management, and controlled response.

---

## 2. Component Inventory & Architecture Baseline

### 2.1 File & Module Inventory

```
G:\IdeaLab\XShield_Starter
├── .gitignore                          # Excludes large binaries, raw PCAP/CSVs, and virtual environment
├── README.md                           # Research build introduction and milestone guide
├── requirements.txt                    # Project dependencies
├── app.py                              # Streamlit frontend (triage dashboard, file upload, offline analysis)
│
├── xshield/                            # Core research library
│   ├── __init__.py                     # Package metadata
│   ├── datasets.py                     # Data loader, column standardizers, train/test splitting
│   ├── pipeline.py                     # Sklearn pipelines, ModelMetadata, manifest loading, joblib serialization
│   └── triage.py                       # Operational schema validation, batch scoring, CSV export, filter engine
│
├── models/                             # Trained models & metadata (PRESERVED - UNTOUCHED)
│   ├── manifest.json                   # Authoritative model catalog with schema specifications
│   ├── xshield_tqh_c2_port_excluded.joblib / .json
│   ├── xshield_tqh_c2_port_inclusive.joblib / .json
│   ├── xshield_cicids2018_port_excluded.joblib / .json
│   └── xshield_cicids2018_port_inclusive.joblib / .json
│
├── reports/                            # Research evaluation reports
│   ├── baseline_validation.json
│   ├── feature_ablation.csv
│   ├── capture_group_evaluation.csv
│   ├── temporal_evaluation.json
│   └── phase3_audit/                   # Phase 3 Audit deliverables
│       ├── audit_report.md             # Formal research audit report
│       ├── phase3_audit_results.json   # Machine-readable experiment outputs
│       ├── tqh_c2_ablation_summary.csv # 8-fold ablation summary
│       ├── cicids2018_audit_summary.csv# 5-fold CICIDS evaluation summary
│       └── run_audit_experiments.py    # Reproducible test runner
│
├── tests/                              # Automated test suites
│   ├── test_phase1.py                  # Core pipelines, preprocessing, model save/load
│   ├── test_phase2.py                  # Offline triage, filtering, metadata checks
│   └── test_phase2_1.py                # Schema-aware compatibility and validation
│
└── data/                               # Sample datasets
    ├── README_v122.md                  # Dataset lineage documentation
    ├── sample_tqh_c2_unlabelled.csv    # Small sample for TQH-C2 demonstration (10 KB)
    └── sample_cicids2018_unlabelled.csv# Small sample for CICIDS-2018 demonstration (21 KB)
```

---

## 3. Verified Findings vs. Unverified Claims

| Area / Component | Documented / Historical Claim | Audited Reality & Empirical Verification | Operational Status for Phase 4 |
|---|---|---|---|
| **Test Suite Baseline** | All automated tests pass | **VERIFIED**: Ran `python -m unittest discover tests` $\rightarrow$ 31 of 31 tests passed cleanly in 10.72s. | **PASSED**: Baseline test regression guard active. |
| **Model Serialization & Manifest** | Manifest dynamically defines schemas | **VERIFIED**: `load_manifest_models()` inspects `models/manifest.json` and companion `*_metadata.json` files. | **PASSED**: Manifest contract respected. |
| **Probability Calibration** | Model outputs probability of compromise | **UNVERIFIED / REFUTED**: `RandomForestClassifier` outputs raw tree vote proportions ($k/N$). `CalibratedClassifierCV` was not used. Scores cannot be labeled as true posterior probabilities. | **EXPERIMENTAL**: Scores must be labeled as "Uncalibrated Ensemble Scores [0.0 - 1.0]" with explicit risk tiers, not compromise probabilities. |
| **Generalization Across C2 Frameworks** | Model detects general C2 beaconing | **REFUTED**: Pure flow statistics model evaluated on Testbed B (Merlin/QUIC) missed 88.27% of C2 flows; on Testbed C (Mythic/HTTP) missed 94.87% of C2 flows. | **EXPERIMENTAL**: Models must run in clearly designated "Experimental / Telemetry Mode". Deterministic rules and evidence rationale must accompany alerts. |
| **Live Packet Capture Backend** | Real-time promiscuous sniffing on Windows | **AUDITED CONSTRAINT**: Windows 11 host does not currently have Npcap installed (`npcap.sys` driver absent). Scapy falls back to L3 socket; L2 promiscuous sniffing throws `RuntimeError: winpcap is not installed`. | **HYBRID ARCHITECTURE**: Implement auto-detection for Npcap. Provide **Deterministic Replay / Stream Engine** using PCAP/CSV playback as primary demo mode, with live capture active when Npcap is available. |
| **Host Firewall Enforcement** | Dynamic rule blocking via `netsh` | **AUDITED CONSTRAINT**: Python process runs as a standard user (not elevated Administrator). Live rule creation requires elevation. | **SIMULATION DEFAULT**: Default to Simulation Mode (records full proposed block, scope, rollback payload). Require explicit opt-in and admin check for live enforcement. |

---

## 4. Known Risks and Operational Limitations

1. **Base-Rate Fallacy in Production Networks**:
   - In live enterprise networks, malicious flows are rarer than 1 in 100,000. An uncalibrated model with even 0.5% FPR generates dozens of false alarms per minute. Phase 4 must enforce **alert deduplication, configurable cooldowns, and evidence thresholds**.
2. **Schema Mismatch on Live Flows**:
   - Live network sniffers capture L3/L4 headers and TCP metrics, but cannot infer CICIDS-2018 subflow statistics (e.g., `Subflow Bwd Byts`, `Flow IAT Max`) on single individual packets without multi-minute flow reconstruction windows.
   - Live monitoring must extract exact, documented flow-level features and mark missing features as `Unknown / Insufficient Evidence` rather than imputing artificial values.
3. **Analyst Safety & Non-Disruption**:
   - Automated blocking based solely on an ML score is unacceptable in cybersecurity engineering. All response recommendations require explicit analyst verification.
   - Critical infrastructure (DNS `8.8.8.8`, `1.1.1.1`, local gateway, loopback `127.0.0.1`) must be hardcoded as non-blockable protected assets.

---

## 5. Prioritized Implementation Plan (Stages A — F)

```
+-----------------------------------------------------------------------------+
|                        PHASE 4 ARCHITECTURE PIPELINE                        |
+-----------------------------------------------------------------------------+
| [Capture Interface]  ──>  [Flow Aggregator]  ──>  [Detection Engine]       |
|  - Live Sniffer (Npcap)    - Bi-directional       - Schema Validator        |
|  - Replay / Stream Engine  - Session timeouts     - Experimental Model Run  |
|                            - TLS SNI/JA4 extract  - Indicator Rules         |
|                                                   - Evidence Reasoner       |
|                                                          │                  |
|                                                          ▼                  |
| [Streamlit UI Dashboard]  <──  [Storage & Alerting]  <───┘                  |
|  1. Live Monitor               - Persistent Incident Store (SQLite/JSONL)   |
|  2. Alerts & Incidents         - Deduplication & Cooldowns                  |
|  3. Network Response           - Analyst Status & Triage                    |
|  4. Historical Analysis        - Response Manager (Simulated + Guarded Netsh|
|  5. System Health                                                           |
+-----------------------------------------------------------------------------+
```

### Stage A: Audit & Environment Baseline (Completed)
- Documented complete architecture, verified baseline test suite (31/31 passing), audited capture constraints (Npcap driver requirement) and firewall privilege levels.

### Stage B: Modular Monitoring Backend & Flow Aggregator
- `xshield/monitoring/capture.py`: Unified capture controller supporting live network sniffing (when Npcap is available) and clean fallback detection.
- `xshield/flows/aggregator.py`: Sliding-window bidirectional flow reconstructor (5-tuple keys: src_ip, dst_ip, src_port, dst_port, protocol), computing flow duration, packet counts, byte totals, TCP flags, and TLS metadata extraction (SNI / handshake extraction).
- `xshield/flows/replay.py`: Deterministic replay engine for PCAP files and synthetic incident streams at configurable rates.

### Stage C: Detection Integration & Evidence Reasoning
- `xshield/detection/engine.py`: Schema validation, model evaluation in strictly labeled Experimental Mode, deterministic heuristic rule layer, and evidence builder. Returns structured verdicts: `BENIGN`, `SUSPICIOUS`, or `INSUFFICIENT_EVIDENCE`.

### Stage D: Analyst Alerting & Persistent Incident Storage
- `xshield/storage/incident_store.py`: Local SQLite/JSONL incident database with ACID persistence, thread-safe access, full search, status updates (`New`, `Investigating`, `Benign`, `Confirmed Suspicious`, `Resolved`), and analyst notes.
- `xshield/alerts/alert_manager.py`: Deduplication engine with configurable cooldowns (e.g. 60 seconds per endpoint pair) to prevent alert flooding.

### Stage E: Controlled Network Blocking & Rollback
- `xshield/response/blocker.py`: Reversible response workflow.
  - **Simulation Mode (Default)**: Full record of proposed rule, target IP, scope, and rationale.
  - **Live Enforcement (Guarded)**: Windows Firewall integration (`netsh advfirewall firewall add/delete rule name="XShield_Block_..."`), checking admin elevation, validating IP safety (never block loopback/DNS/gateway), and tracking rule IDs for immediate rollback.

### Stage F: Streamlit Live Interface & Demo Runbook
- Upgrade `app.py` with multi-page navigation (Live Monitor, Alerts & Incidents, Network Response, Historical Analysis, System Health) while preserving existing Offline CSV Triage.
- Add comprehensive automated test suite in `tests/test_phase4.py`.
- Create `docs/DEMO_RUNBOOK.md` with complete 5-minute presentation script and step-by-step instructions.

---

## 6. Phase 4.1 Hardening & Independent Verification Outcomes

During the Phase 4.1 skeptical engineering and QA review, several subtle architectural issues were identified, corrected, and verified:

1. **Pre-Sniff Driver Guard**:
   - `xshield/monitoring/capture.py`: Added explicit Npcap verification before worker thread spawning. Prevents unhandled driver exceptions and thread leakage on Windows hosts lacking `npcap.sys`.
2. **Schema Incompatibility Verdict Correction**:
   - `xshield/detection/engine.py`: Corrected inference fallback when required features are missing. The engine now strictly emits `INSUFFICIENT_EVIDENCE` (risk tier: `INFORMATIONAL`), eliminating false `BENIGN` classifications.
3. **Synthetic Origin Attribution**:
   - Added `is_synthetic: bool` tracking across `FlowRecord`, `DetectionVerdict`, `IncidentRecord`, and UI presentation. Prevents conflating synthetic lab demonstrations with physical network evaluations.
4. **4-Tuple Deduplication & Persistence**:
   - `xshield/alerts/alert_manager.py` & `xshield/storage/incident_store.py`: Upgraded deduplication key to include transport protocol (`src->dst:port/proto`), preventing TCP and UDP flows targeting the same port from erroneously coalescing.
5. **Rule Expiration, Verification & Ownership Guard**:
   - `xshield/response/blocker.py`:
     - Added temporary containment expiration (`duration_minutes`, `expires_at`, `cleanup_expired_rules()`).
     - Added post-execution verification using `netsh advfirewall firewall show rule`.
     - Hardened ownership enforcement: `rollback_block()` strictly rejects any rule not matching the `XShield_Block_` prefix.
     - Expanded safety blacklist to include RFC 3927 link-local (`169.254.0.0/16`, `fe80::/10`) and reserved addresses.
6. **Data Sanitization & Forensic Export**:
   - `xshield/storage/incident_store.py`: Implemented `sanitize_incident_export` with control-character stripping and optional RFC 1918 internal IP masking for compliance and external sharing.
7. **10-Step Deterministic Acceptance Test**:
   - Created `tests/test_demo_acceptance.py` validating the entire replay-to-response-to-export chain across 4 deterministic test cases.
   - Total automated test count increased to **47 passing tests** (0 failed, 0 skipped).

