# XShield Phase 4.1: Live Threat Monitoring & Incident Response Demo Runbook

**Audience**: University Project Examiners, Cybersecurity Analysts, Evaluation Committee  
**Version**: 4.1-Hardened (Independent Verification & Demo Acceptance)  
**Operating System**: Windows 11 / Windows 10 (PowerShell)  
**Workspace**: `G:\IdeaLab\XShield_Starter`  

---

## 1. Quick-Start Guide (Running the Application)

### Prerequisites
- Python 3.11 virtual environment at `.\.venv`
- Windows Terminal or PowerShell 5.1 / 7+
- Streamlit web server

### Launch Command
Open PowerShell in the project root directory and run:

```powershell
Set-Location -Path "G:\IdeaLab\XShield_Starter"
.\.venv\Scripts\python.exe -m streamlit run app.py
```

The application will launch in your default web browser at `http://localhost:8501`.

### Running Automated Verification Tests
To run the complete verified test suite (47 automated tests covering flow aggregation, detection, deduplication, SQLite persistence, firewall safety, and the 10-step demo chain):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v tests
```

Expected output:
```
Ran 47 tests in ~16s
OK
```

### Running Dedicated 10-Step Demo Acceptance Test
To run the deterministic end-to-end acceptance test validating the full replay-to-response-to-export chain:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests/test_demo_acceptance.py
```

Expected output:
```
test_full_10_step_demo_acceptance_chain ... ok
test_rule_expiration_and_cleanup ... ok
test_schema_incompatible_insufficient_evidence ... ok
test_webhook_failure_resilience ... ok
Ran 4 tests in ~2.5s
OK
```

---

## 2. Architectural Overview for Evaluators

```
+-----------------------------------------------------------------------------------+
|                     XSHIELD PHASE 4.1 HARDENED ARCHITECTURE                       |
+-----------------------------------------------------------------------------------+
|  INGESTION TIER:                                                                  |
|   - Deterministic Replay Engine (Synthetic C2 + Benign Browsing, or Offline CSV)  |
|   - Live Network Adapter Sniffing (Scapy + Npcap L2 provider when present)        |
|   - Explicit Origin Tagging (`is_synthetic=True` for testbed fixtures)           |
|                                     │                                             |
|  AGGREGATION TIER:                  ▼                                             |
|   - Sliding-Window Flow Aggregator (5-tuple canonicalization, TCP state tracking) |
|   - TLS Handshake Extractor (ClientHello SNI & JA4 hash WITHOUT payload decryption)|
|   - Memory Bounded Queues (Max 10,000 packets; orphan thread auto-cleanup)        |
|                                     │                                             |
|  DETECTION & REASONING TIER:        ▼                                             |
|   - Schema-Safe Detection Engine (Experimental Telemetry Mode)                    |
|   - Bounded ML Evaluation (Uncalibrated tree ensemble vote score [0.0 - 1.0])     |
|   - Deterministic Heuristic Indicators (non-standard ports, TCP resets, JA4)      |
|   - Honest 'INSUFFICIENT_EVIDENCE' verdicts (< 4 packets or schema mismatch)     |
|                                     │                                             |
|  TRIAGE & RESPONSE TIER:            ▼                                             |
|   - Persistent Incident Store (SQLite with ACID persistence & WAL mode)           |
|   - 4-Tuple Alert Deduplication (src -> dst:port/proto + cooldown coalescing)     |
|   - Controlled Response Manager:                                                  |
|       * Simulation Mode (Default: Zero network disruption risk)                   |
|       * Strict Blacklist (Protects localhost, loopback, RFC 3927 link-local, DNS) |
|       * Temporary Containment Expiration (15m, 30m, 60m, 2h, 24h + auto cleanup)  |
|       * Guarded Windows Firewall Enforcement (netsh parameterized, opt-in)        |
|       * One-Click Atomic Rollback & Rule Ownership Verification                   |
|       * Sanitized Forensic CSV Export (RFC 1918 internal IP masking toggle)       |
+-----------------------------------------------------------------------------------+
```

---

## 3. Step-by-Step 5-Minute Demonstration Walkthrough

Follow this 10-step script during your presentation to demonstrate the complete **Detection-to-Alert-to-Response Lifecycle**:

### Step 1: Open Live Monitor (`📡 Live Monitor` Tab)
1. Point out the top environmental notice banners:
   - **Capture Driver Status**: Transparently notes whether Npcap is installed or whether Replay Mode is active.
   - **Simulation Notice**: Explains that network response is safely running in Simulation Mode by default.
2. In **Select Ingestion Source**, select `Deterministic Replay: Synthetic Enterprise Scenario (HTTPS Browsing + C2 Beacons)`.
3. Set **Stream Speed** slider to `0.5s`.
4. Click **▶ Start Stream**. (Notice the green indicator: `🟢 Status: Ingestion stream actively running in background`).

### Step 2: Observe Real-Time Ingestion & Extraction
1. Point to the metrics cards updating dynamically:
   - *Flows Ingested* increments.
   - *Benign Verified* increments (e.g. connections to Google, GitHub, Microsoft).
   - *Insufficient Evidence* identifies incomplete handshakes (< 4 packets).
2. Point out the **Real-Time Flow Feed** table:
   - Note the **Type** column displaying `Synthetic` (or `Live`), ensuring clear provenance.
   - Highlight that flow duration, packet counts, bytes, TCP state (`SF`, `RSTO`), and **TLS SNI / JA4 fingerprints** are extracted **without decrypting user payload**.

### Step 3: Observe Suspicious C2 Beacon Detection
1. As the synthetic C2 beacon fires (outbound to `198.51.100.24:8443`), the table displays a red badge: `🔴 Suspicious (HIGH)`.
2. Notice the *Suspicious Detections* metric counter increment.
3. Explain: *"The engine detected anomalous behavior: periodic beaconing to non-standard port 8443, abnormal byte ratios, TCP RST socket teardown, and matching TLS fingerprint."*

### Step 4: Open Incident Management (`🚨 Alerts & Incidents` Tab)
1. Switch to the `🚨 Alerts & Incidents` tab.
2. Point out the top summary metrics (*Total Incidents*, *High Severity*, *Active Investigations*).
3. Point to the table and highlight **occurrence count** (e.g. `Occurrences: 2` or `3`).
4. Point out the detection source tag: `hybrid [SYNTHETIC]`.
5. Explain deduplication: *"Notice how repeated beacon checks from the same infected host did not spam the analyst with dozens of separate notifications. The cooldown engine coalesced them into a single ongoing incident."*

### Step 5: Review Evidence & Limitations
1. In the **Select Incident to Investigate** dropdown, pick the active incident.
2. Point out the `SYNTHETIC FIXTURE` badge in the header.
3. Inspect the **Supporting Evidence & Detection Indicators**:
   - `SYNTHETIC_REPLAY_SOURCE`: Explicit origin attribution.
   - `NON_STANDARD_PORT_RESET`: Connection to port 8443 terminated with TCP reset (`RSTO`).
   - `SUSPICIOUS_JA4_FINGERPRINT`: TLS client fingerprint matches automated C2 implant profile.
   - `ML_ENSEMBLE_DETECTION`: Uncalibrated model scored flow above threshold.
4. Show the **Methodological Limitations**:
   - Highlight the disclaimer: *"Scores reflect decision tree vote proportions, not calibrated posterior compromise probabilities."*

### Step 6: Triage the Incident
1. Change **Update Incident Status** to `Investigating` or `Confirmed Suspicious`.
2. In **Analyst Notes**, type: `Verified periodic Sliver beaconing. Recommending egress block.`
3. Click **💾 Save Updates**.
4. Click **🛡️ Block Target**. (Notice notification: *Target 198.51.100.24 loaded into Network Response tab*).

### Step 7: Controlled Network Response (`🛡️ Network Response` Tab)
1. Switch to the `🛡️ Network Response` tab.
2. Show that `198.51.100.24` is populated as the target.
3. Show the **Safety Blacklist**:
   - Type `8.8.8.8` or `127.0.0.1` into the target box $\rightarrow$ notice that XShield immediately displays a critical error: `Safety Violation: IP is protected infrastructure (loopback/DNS/gateway/link-local) and cannot be blocked.`
   - Re-enter `198.51.100.24`.
4. Select a **Temporary Containment Duration** (e.g., `30 minutes` or `1 hour`).
5. Point out the proposed rule name: `XShield_Block_198.51.100.24_<ID>`.
6. Point out the proposed command: `netsh.exe advfirewall firewall add rule ...`.
7. Emphasize safety: *"Notice that the 'Apply Response Action' button is disabled until the analyst explicitly checks the confirmation checkbox. We never automate firewall modifications without human-in-the-loop validation."*
8. Check the box: `I explicitly confirm blocking outbound traffic to 198.51.100.24`.
9. Click **⚡ Apply Response Action**.
10. Notice success message: `SIMULATION RECORDED: Block rule recorded for analyst review. No network firewall modifications were performed.`

### Step 8: Demonstrate Atomic Rollback / Unblock & Cleanup
1. In the **Active XShield Block Rules** panel on the right, show the new active rule.
2. Note the expiration timestamp displayed on the rule card.
3. Click **↩️ Rollback / Unblock 198.51.100.24**.
4. The rule status immediately transitions to `ROLLED_BACK`.
5. Point out the **🧹 Clean Up Expired Rules** button for automated background hygiene.
6. Explain: *"The analyst has full, immediate rollback capability. If an operational block impacts a legitimate business service, one click restores normal network state."*

### Step 9: Historical Analytics & Sanitized CSV Export (`📊 Historical Analysis` Tab)
1. Switch to the `📊 Historical Analysis` tab.
2. Review the Plotly distribution charts:
   - *Severity Breakdown* (Donut chart).
   - *Attribution Source Breakdown* (ML vs Heuristic vs Hybrid).
3. Under **Export Sanitized Event Log**:
   - Check the toggle: **Anonymize internal RFC 1918 IP addresses in export**.
   - Click **📥 Download Sanitized Incident History (CSV)**.
4. Inspect the CSV: internal IPs are masked (e.g. `192.168.x.x`), control characters stripped, and synthetic fixtures clearly labeled.

---

## 4. Five-Minute Presentation Script (For Academic Defense)

| Time | Slide / Tab | What to Say |
|---|---|---|
| **0:00 - 0:45** | Title / Context | *"Good morning. Today I am presenting XShield, an explainable network threat monitoring system designed to detect encrypted command-and-control communications without decrypting application payloads. In our Phase 3 research audit, we uncovered that academic intrusion datasets often suffer from severe shortcuts—such as static destination ports and homogeneous TLS client fingerprints. In Phase 4.1, we built an operational demonstration that addresses these realities directly: enforcing schema validation, distinguishing heuristic indicators from ML scores, preventing alert flooding, and providing a controlled, reversible response workflow."* |
| **0:45 - 1:45** | Live Monitor | *"Here on the Live Monitor tab, XShield ingests network traffic. On this demonstration machine, Npcap is not installed, so XShield automatically falls back to our deterministic replay stream. Notice the incoming flow stream: we extract 5-tuple socket information, byte and packet volume, TCP handshake termination states, and TLS ClientHello SNI and JA4 fingerprints. Right now, benign web browsing to Google, GitHub, and Microsoft is cleared. But when a host initiates periodic beaconing to an external C2 IP on port 8443, our detection engine flags it immediately."* |
| **1:45 - 2:45** | Alerts & Incidents | *"Moving to the Alerts and Incidents tab, we see the incident created in our persistent SQLite store. Notice the occurrence count: the infected machine beaconed multiple times, but our deduplication and cooldown engine coalesced them into a single incident, avoiding notification fatigue. When we inspect the incident, XShield presents clear evidence: the non-standard port, the TCP reset termination, and the uncalibrated ML ensemble vote. Crucially, we also display research limitations to ensure the analyst understands this is an operational indicator, not proof of compromise."* |
| **2:45 - 3:45** | Network Response | *"In modern SOC engineering, automated blocking based solely on machine learning models is dangerous due to the base-rate fallacy. Therefore, XShield implements a two-gate response system. By default, it operates in Simulation Mode. We protect critical infrastructure: if an analyst mistakenly tries to block 8.8.8.8 or loopback, the system rejects it. When we confirm blocking the C2 address, the action is logged with full scope and expiration duration. If live enforcement is authorized, it executes parameterized Windows Firewall netsh commands. And if a mistake is made, our atomic rollback button immediately restores connectivity."* |
| **3:45 - 4:45** | History & Diagnostics | *"Finally, our Historical Analysis tab visualizes incident trends and allows compliance export of sanitized logs. The System Health tab continuously monitors capture driver status and model schema compatibility. Even with Phase 2 offline CSV analysis still fully supported, XShield is now a reliable, hardened prototype."* |
| **4:45 - 5:00** | Conclusion & Q&A | *"In conclusion, XShield demonstrates how explainable AI and robust network security engineering can deliver trustworthy threat monitoring while being honest about ML limitations. Thank you, and I look forward to your questions."* |

---

## 5. Troubleshooting & FAQ

### Q1: Why does the system indicate "Replay Mode" instead of live sniffing?
**Answer**: Live promiscuous packet capture on Windows strictly requires the **Npcap driver** with WinPcap API-compatible mode enabled. If Npcap is not installed on the system, XShield cleanly detects this condition via `check_capture_health()` and activates the **Deterministic Replay Engine**. This ensures that project demonstrations, unit tests, and student evaluations run reliably on any Windows laptop without driver installation.

### Q2: How can I enable live physical packet capture?
1. Download and install Npcap from [https://npcap.com](https://npcap.com).
2. During installation, ensure the box **"Install Npcap in WinPcap API-compatible Mode"** is checked.
3. Open an elevated PowerShell prompt (`Run as Administrator`).
4. Launch XShield: `.\.venv\Scripts\python.exe -m streamlit run app.py`.
5. Under `Live Monitor`, select `Live Network Adapter` and choose your physical Wi-Fi or Ethernet adapter.

### Q3: Why does live firewall enforcement require Administrator privileges?
Windows Firewall rules are system-wide security policies. Modifying them requires elevation. If XShield is launched from a standard non-admin shell, it will gracefully record the action in **Simulation Mode** and report that elevation is required for live netsh enforcement.
