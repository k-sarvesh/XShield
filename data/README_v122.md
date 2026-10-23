# TQH-C2: An Encrypted Command-and-Control Traffic Dataset Across Protocols and Encryption Layers

**Version:** 1.2.2 · **License:** CC BY 4.0

**Authors:** Deokjo Jeon¹* (ORCID 0000-0002-0343-3384), DongGue Park² (ORCID 0000-0002-5864-8825)

¹ Department of AI Convergence Engineering, Seoul School of Integrated Sciences & Technologies, Seoul, Republic of Korea
² Department of Information and Communication Engineering, Soonchunhyang University, Asan, Republic of Korea

\* Corresponding author: Deokjo Jeon (dejeon@stud.assist.ac.kr)

This release supersedes 1.1.0 and 1.0.x. It was produced with the third-generation collection pipeline (`tqhc2_v3_tools`); the `v3` label in directory and tool names refers to that internal pipeline generation, not to the dataset release version. Some archive filenames retain a `_v110` suffix from the release in which their contents were last regenerated; those contents are current for 1.2.2.

---

## 1. Overview

TQH-C2 (TLS + QUIC + HTTP Command-and-Control) is a labeled network-traffic dataset for research on decryption-free detection of encrypted C2 channels. Its defining property is a controlled comparison across encryption profiles: the same MITRE ATT&CK kill-chain is executed identically over four different encrypted C2 transports, so that the only systematically varied factors are the encryption/transport profile and the beacon timing. This isolates the effect of the encryption layer on flow- and fingerprint-based detection, which mixed real-world captures cannot do.

The dataset is organized as a 48-cell grid:

```
4 encryption profiles  ×  4 beacon intervals  ×  3 jitter levels  =  48 cells
```

| Axis | Values |
|---|---|
| Encryption profile | A = TLS (Sliver), B = QUIC (Merlin), C = HTTP+AES (Mythic), D = HTTP/2-over-TLS (Merlin) |
| Beacon interval | 30 s, 300 s, 1800 s, 3600 s |
| Jitter | 0 %, 30 %, 70 % |

Each cell is an independent capture in which a fleet of victim agents beacons to a C2 server under the specified interval and jitter, while the same kill-chain and the same benign background traffic run concurrently.

---

## 2. Encryption Profiles (Testbeds)

| Profile | C2 framework | Transport / encryption | Fingerprint family | Zeek |
|---|---|---|---|---|
| A | Sliver v1.7.3 | TLS over TCP (tcp/8443) | JA4 / JA4S (TLS) | 7.0.11 |
| B | Merlin v2.1.4 | HTTP/3 over QUIC (udp/443) | JA4 / JA4S (QUIC-TLS) | 8.0.5 |
| C | Mythic v3.4.0.57 + Poseidon v0.0.3.16 | HTTP with AES-encrypted body (tcp/80) | JA4H (HTTP) | 7.0.11 |
| D | Merlin v2.1.4 | HTTP/2 over TLS (tcp/8443) | JA4 / JA4S (TLS) | 8.0.5 |

Testbeds **B and D** share the same Merlin framework, kill-chain, host and single C2 destination, and differ **only** in transport protocol (HTTP/3-over-QUIC vs HTTP/2-over-TLS). They therefore form a controlled protocol-comparison pair that separates the effect of the transport layer from the effect of the C2 framework.

A key measured characteristic is **fingerprint asymmetry**: application-layer JA4 fingerprints partition by profile — the TLS and QUIC profiles carry JA4/JA4S, while the HTTP profile carries JA4H. Detectors relying on one family do not transfer directly across profiles.

---

## 3. Distribution Package & File Layout

| File | Contents | Size |
|---|---|---|
| `TQH-C2_pcap_A_sliver_tls.zip` | Testbed A (TLS) — 12 raw `.pcap`, one per cell | 33.4 GB |
| `TQH-C2_pcap_B_merlin_quic_v110.zip` | Testbed B (QUIC) — 12 raw `.pcap`, one per cell | 4.3 GB |
| `TQH-C2_pcap_C_mythic_http.zip` | Testbed C (HTTP+AES) — 12 raw `.pcap`, one per cell | 379.2 MB |
| `TQH-C2_pcap_D_merlin_h2.zip` | Testbed D (HTTP/2-TLS) — 12 raw `.pcap`, one per cell | 1.8 GB |
| `TQH-C2_labels_v110.zip` | Testbeds A, B, C (36 cells): Zeek logs + per-flow labels + manifests | 31.0 MB |
| `TQH-C2_labels_D.zip` | Testbed D (12 cells): Zeek logs + per-flow labels + manifests | 2.2 MB |
| `TQH-C2_features_v110.zip` | Feature tables (Parquet) + JA4 fingerprint maps, Testbeds A, B, C | 12.1 MB |
| `TQH-C2_features_D.zip` | Feature tables (Parquet), Testbed D, 27-column schema | 1.2 MB |
| `TQH-C2_scripts.zip` | Sanitized collection / labeling / feature code | 114.5 kB |
| `README_v122.md` | This document | 21.4 kB |
| `SHA256SUMS_v122.txt` | SHA-256 checksums of every archive | 906 B |

Total record size: **39.9 GB**.

Inside every archive, files are organized by cell, named `<PROFILE>_i<INTERVAL>_j<JITTER>/` (e.g. `A_i30_j0/`, `B_i3600_j70/`, `C_i300_j30/`, `D_i1800_j0/`). The pcap archives contain only the `.pcap`; the labels archives contain, per cell:

```
<PROFILE>/<CELL>/
├── conn.log                     # Zeek connection log (JSON lines) — all profiles
├── ssl.log                      # Zeek TLS/SSL log
├── dns.log                      # Zeek DNS log
├── quic.log                     # Zeek QUIC log            (Testbeds B, D)
├── http.log                     # Zeek HTTP log            (Testbed C)
├── files.log                    # Zeek files log           (Testbed C)
├── ntp.log                      # Zeek NTP log             (where present)
├── weird.log                    # Zeek anomaly log         (where present)
├── ssh.log / ja4ssh.log         # Zeek SSH + JA4SSH fingerprint (where present)
├── labeled.jsonl                # per-flow records with label (see §4)
├── labeled.jsonl.counts.json    # label tally for the cell
├── gate.json                    # validation metadata
└── manifest.json                # cell provenance (timestamps UTC, config)
```

Which Zeek logs appear depends on the traffic in each profile (e.g. `http.log` and `files.log` only for the HTTP testbed; `quic.log` wherever QUIC traffic is present, i.e. Testbeds B and D). Internal collection-tool logs are not included. To recover any Zeek log not shipped here, re-run Zeek on the corresponding `.pcap`.

**Timestamps.** All `manifest.json` `start_utc` / `end_utc` fields are UTC (ISO-8601, `…Z`).

**Integrity.** After download, verify with `sha256sum -c SHA256SUMS_v122.txt`.

---

## 4. Labels

Labels are produced programmatically from deterministic, IP-based topology rules using the known layout of the isolated container networks — not by machine learning, statistical inference, or manual tagging. Each flow in `labeled.jsonl` carries exactly one label:

| Label | Meaning | Flows in 1.2.2 |
|---|---|---|
| `malicious_c2` | Victim → C2 beacon / tasking (**the positive class**) | 27,130 |
| `malicious_recon` | Reconnaissance within the kill-chain (Testbed C only) | 880 |
| `malicious_lateral` | Lateral movement between victim nodes | **0** |
| `benign` | Background benign traffic to external services | 124,295 |
| `benign_external` | Benign flow to an external host without generator involvement | 460 |
| `unknown` | Traffic matching no topology rule | **0** |

`malicious_lateral` and `unknown` are defined for completeness but **hold no flows in this release**. The `unknown` class was populated in releases 1.0.0–1.0.1 with traffic from stale victim containers that never beaconed; those flows were removed in 1.0.2, which is why the flow totals below differ from the pre-1.0.2 figures. No inter-victim non-ICMP signalling occurs in the released grid, so `malicious_lateral` is empty by design.

The released Zeek files carry the raw metadata fields but omit a dedicated label column: run the bundled `label_v3_topo.py` against `conn.log` to regenerate the exact ground truth from the topology.

---

## 5. Dataset Statistics

### Per testbed

| Profile | Cells | Total flows | `malicious_c2` | C2 ratio | Raw pcap (packaged) |
|---|---|---|---|---|---|
| A (Sliver / TLS) | 12 | 96,149 | 12,038 | 12.5 % | 33.4 GB |
| B (Merlin / QUIC) | 12 | 21,796 | 324 | 1.5 % | 4.3 GB |
| C (Mythic / HTTP+AES) | 12 | 23,292 | 12,804 | 55.0 % | 379.2 MB |
| D (Merlin / HTTP/2-TLS) | 12 | 11,528 | 1,964 | 17.0 % | 1.8 GB |
| **Total** | **48** | **152,765** | **27,130** | **17.8 %** | **39.9 GB** |

All flow counts are computed from the per-flow label files (`labeled.jsonl`). Every labeled flow joins to its Zeek `conn.log` record by `uid`, with **zero unmatched entries** across all 48 cells.

### Label distribution

| Label | A | B | C | D | Total |
|---|---|---|---|---|---|
| `malicious_c2` | 12,038 | 324 | 12,804 | 1,964 | 27,130 |
| `malicious_recon` | 0 | 0 | 880 | 0 | 880 |
| `malicious_lateral` | 0 | 0 | 0 | 0 | 0 |
| `benign` | 83,881 | 21,472 | 9,378 | 9,564 | 124,295 |
| `benign_external` | 230 | 0 | 230 | 0 | 460 |
| `unknown` | 0 | 0 | 0 | 0 | 0 |
| **Total** | **96,149** | **21,796** | **23,292** | **11,528** | **152,765** |

Testbed C's high C2 ratio (55.0 %) reflects the compactness of Mythic's per-beacon HTTP transactions: each callback opens a single short-lived TCP connection, so C2 flows accumulate quickly relative to the benign background. Testbed B's low count (1.5 %) is the mirror image: QUIC multiplexes an entire session into one long-lived UDP flow, so C2 is counted at connection-flow granularity, consistently with the other three profiles.

### Connection structure of the C2 class

| Property | A | B | C | D |
|---|---|---|---|---|
| Dominant `conn_state` | RSTO 94.3 % | SF 100 % | SF 93.1 % | RSTR 93.1 % |
| Service tag | `ssl` 99.9 % | `quic,ssl` 50.0 % | `http` 93.1 % | `ssl` 97.9 % |
| Median C2 duration | 1.01 s | 1,476.80 s | 0.00 s | 31.02 s |
| P99 C2 duration | 1.02 s | 9,703.45 s | 0.18 s | 31.09 s |

### Per-cell counts

Per-cell flow counts for all 48 cells are in `labeled.jsonl.counts.json` inside each cell directory, and are tabulated in the accompanying Data Descriptor. Within each testbed the `malicious_c2` count per cell falls monotonically as the interval lengthens from 30 s to 3600 s (Testbed A, for example, declines from 2,404 flows at `A_i30_j0` to 690 at `A_i3600_j30`), while the benign background grows with capture duration. A cell's class balance is therefore a controlled variable of the grid rather than an artefact.

---

## 6. Collection Methodology

Each profile runs in an isolated Docker testbed. Testbeds A and C were hosted on the server `gpusystem` and Testbeds B and D on `bird`; each uses a distinct bridge network with a private /24 subnet.

- Victims are containers running the corresponding C2 agent (Sliver for A, Merlin for B and D, Mythic/Poseidon for C) on a dedicated bridge subnet; the C2 server is reachable only from that subnet.
- A single orchestrator sweeps the interval × jitter grid, one capture per cell.
- Within each capture, victims re-handshake so that TLS/QUIC fingerprints are recorded inside the capture window; a kill-chain driver tasks the agents for the whole window so the C2 size distribution is realistic, not idle-only.
- Benign traffic runs concurrently from a generator container and from the victims themselves (external web requests), kept dense relative to the capture window.
- Captures are processed with Zeek (7.0.11 for A and C, 8.0.5 for B and D), producing per-cell logs, which are then labeled by topology and validated per cell.

Two processing behaviours affect downstream analysis. The hourly pcap rotation imposes a 3,600 s upper bound on observable flow durations, so sustained connections are split across consecutive `conn.log` entries. Zeek's default 25 s UDP inactivity timeout can split a continuous UDP session; Testbed B was re-collected in 1.1.0 so that each C2 session is captured as one complete bidirectional exchange.

QUIC (profile B) multiplexes many beacons into one long-lived UDP flow, so its C2 flow count is intentionally smaller than the beacon count; C2 is counted at the raw connection-flow granularity, consistently with A, C and D.

---

## 7. Reproducibility

The collection, labeling, and feature-extraction code is included as `TQH-C2_scripts.zip`. Recommended entry points:

| Script | Purpose |
|---|---|
| `orchestrator.py` | Grid sweep driver (interval × jitter) |
| `run_cell_A.sh`, `run_cell_B.sh`, `run_cell_C.sh` | Per-cell capture → label → validate (A, B, C) |
| `run_cell_h2.sh`, `run_D_all.sh` | Per-cell and batch drivers for Testbed D |
| `build_sliver.py`, `build_merlin.py`, `build_mythic.py` | Build the C2 agents and payloads |
| `label_v3_topo.py` | Deterministic topology-based labeling |
| `validate_capture.py` | Per-cell validation |
| `build_features_v3.py` | Rebuild per-cell and per-testbed Parquet feature tables — including the JA4/JA4S/JA4H columns — directly from `labeled.jsonl` and `conn.log` |
| `merlin_patch/jwt_lifetime.patch` | Diff against Merlin v2.1.4 documenting the JWT-lifetime modification used for Testbeds B and D (see Changelog) |

**Configuration placeholders.** Site-specific values in the published code are replaced with placeholders and must be set for your environment: `CHANGE_ME_C2_PSK` (C2 pre-shared key), `<C2_HOST_IP>` (C2 server address), `<CAPTURE_ROOT_AC>` / `<CAPTURE_ROOT_B>` (capture output roots), `<MYTHIC_DIR>`, `<TOOLS_ROOT>`, `youruser`. The code is intentionally not runnable as-is against the authors' private infrastructure. Regenerating logs from the raw pcaps needs a Zeek 7.x or 8.x install and Python 3.10+; the labeling and validation scripts use only the Python standard library.

---

## 8. Intended Use

- Cross-profile generalization of encrypted-C2 detectors (train on one profile, test on another).
- Feature-robustness studies under encryption-profile shift — which flow and fingerprint features survive across TLS, QUIC, HTTP+AES and HTTP/2-over-TLS.
- Controlled transport comparison using the B ↔ D pair, where framework, kill-chain, host and destination are held fixed.
- Interval and jitter sensitivity of beacon-detection methods.
- Continual learning under encryption shift, presenting the four profiles as a task sequence.

The controlled grid is designed so that differences in detector performance across cells are attributable to the encryption profile and beacon timing, not to confounded attack or environment differences.

---

## 9. Known Shortcuts & Recommended Evaluation

Naively trained detectors can exploit non-generalizable shortcuts in this dataset. They are documented explicitly so that users can evaluate meaningfully rather than memorize artifacts of the collection environment.

**Destination IP.** In every testbed the C2 host is a single internal address and benign destinations are external, so `id.orig_h` / `id.resp_h` alone separate the classes perfectly (zero shared IPs). **Exclude IP-address features**; otherwise reported scores reflect memorized addresses, not learned C2 behavior. The same applies to destination port, service tag and connection-history flags.

**Connection state / directionality.** In releases 1.0.x, Testbed B `malicious_c2` was unidirectional (`resp_bytes = 0`, `conn_state = S0/OTH`), which trivially separated it from benign SF flows. Release 1.1.0 fixes this: B's C2 is now bidirectional with `conn_state = SF`, statistically closer to benign.

**Per-testbed difficulty** (identity features removed; Random Forest, mean F₁ over five seeds, 80/20 stratified holdout):

| Testbed | F₁ |
|---|---|
| A (Sliver / TLS) | 1.000 |
| B (Merlin / QUIC) | 0.992 |
| C (Mythic / HTTP+AES) | 0.983 |
| D (Merlin / HTTP/2-TLS) | 1.000 |

Testbed B's score rests on only 65 positive flows in the holdout split and should be read as indicative.

**Controlled protocol comparison (B vs D).** Testbeds B and D use the same Merlin framework, kill-chain and single C2 destination, differing only in transport. Their flow structure differs sharply: B multiplexes each agent session into one long-lived QUIC flow (`conn_state` SF, median duration 1,476.80 s, median response payload 34.9 kB), while D opens a separate TCP connection per beacon (`conn_state` RSTR, median duration 31.02 s). Despite this, both remain near-perfectly separable by size and timing alone. This pair indicates that detection difficulty is governed by whether C2 traffic mimics benign size and timing distributions, not by the transport or encryption protocol itself: changing the protocol while holding the framework fixed does not make detection harder.

**Recommended evaluation.** Remove identity features, report per-testbed results rather than a pooled score, and treat Testbed C — or cross-testbed transfer — as the primary difficulty benchmark.

---

## 10. Ethics & Privacy

All traffic was generated in a closed, controlled laboratory environment.

- Internal addresses are private-range (172.16/12, 192.168/16) lab addresses.
- External destinations are public CDN and service endpoints (Google, Cloudflare, Ubuntu mirrors) contacted by automated benign traffic — no personal or third-party private data.
- C2 authentication material is not exposed in plaintext.
- No human-subject or personally identifiable data is present.
- No third-party systems were contacted and no evasion technique is developed or disclosed.

---

## 11. Citation

If you use TQH-C2, please cite:

> Jeon, D., & Park, D. (2026). *TQH-C2: An Encrypted Command-and-Control Traffic Dataset Across Protocols and Encryption Layers* (Version 1.2.2) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.22732327

The **Concept DOI** `10.5281/zenodo.21330094` always resolves to the latest version; the **version DOI** `10.5281/zenodo.22732327` pins release 1.2.2.

**Contact:** dejeon@stud.assist.ac.kr · ORCID 0000-0002-0343-3384

---

## 12. Changelog

**1.2.2 (2026-07; files corrected 2026-09-29)** — Added the feature-table builder `build_features_v3.py` to the scripts archive. Data records (pcap, labels, features) are byte-identical to 1.2.0.

> **File correction, 2026-09-29.** `TQH-C2_labels_D.zip` had been packaged from an incomplete staging directory and shipped only `labeled.jsonl` and `manifest.json` per cell. It has been repackaged with the per-cell Zeek logs (`conn.log`, `ssl.log`, `quic.log`), `gate.json` and `labeled.jsonl.counts.json`, in the `D/<cell>/` layout used by Testbeds A, B and C. No data values changed: the omitted files were restored from the original capture directories, and the `labeled.jsonl` files are byte-identical to those published before. `README_v122.md` and `SHA256SUMS_v122.txt` were updated accordingly. The version number and the DOI are unchanged. Users who downloaded `TQH-C2_labels_D.zip` before this date should re-download it; its SHA-256 is now `10d8e4ef6edd5416ae2d866d93e6165d174049c85a1ffa6861958784cabc2dc2`.

**Scripts update, 2026-09-30.** Added `merlin_patch/` to `TQH-C2_scripts.zip`, containing `jwt_lifetime.patch` and a short README. The patch records the two local modifications made to the Merlin v2.1.4 server for this dataset: a 2 h floor on the issued JWT lifetime in `pkg/listeners/http/jwt.go` and a 3 h floor on the validation leeway in `pkg/servers/http/jwt.go`. Upstream Merlin issues short-lived agent tokens, so on the 1,800 s and 3,600 s beacon intervals a token expired before the next check-in and kill-chain tasking stopped; the floors keep agents authenticated across the long intervals. A single patched server binary, built 2026-07-20, served both Testbed B and Testbed D, so the two remain a controlled transport-comparison pair; the agent binary is unchanged. No data values changed and the pcap, label and feature archives are byte-identical to 1.2.0. The version number and the DOI are unchanged. `README_v122.md` and `SHA256SUMS_v122.txt` were updated accordingly; the SHA-256 of `TQH-C2_scripts.zip` is now `78839520279036262c06f900c11d39604d4cf34eee2623ef513984314629da2b`.

**1.2.1 (2026-07)** — Added the Testbed D collection drivers `run_cell_h2.sh` and `run_D_all.sh` to the scripts archive. Data records byte-identical to 1.2.0.

**1.2.0 (2026-07-23)** — Added **Testbed D (Merlin / HTTP-2-over-TLS)** as a fourth profile: 12 cells, 11,528 flows, 1,964 `malicious_c2`. D uses the same Merlin framework, kill-chain and C2 destination as Testbed B and differs only in transport protocol, so B and D form a controlled protocol-comparison pair. The grid grows from 36 to 48 cells and the release totals 152,765 labeled flows. Testbeds A, B and C are unchanged from 1.1.0.

**1.1.0 (2026-07-21)** — Re-collected all 12 Testbed B (Merlin/QUIC) cells with a repaired kill-chain. In 1.0.x, B's `malicious_c2` flows were unidirectional (`resp_bytes = 0`, `conn_state = S0/OTH`), an artifact of the broken kill-chain rather than realistic C2 behaviour. C2 traffic is now fully bidirectional (324 of 324 flows with `resp_bytes > 0`, all `conn_state = SF`), matching the interactive tasking behaviour of a real C2 channel. The B pcap archive is correspondingly smaller (4.3 GB versus ~18 GB) because each cell is a single focused capture. Testbeds A and C unchanged.

**1.0.2 (2026-07-20)** — Removed stale-container flows that never beaconed and emptied the `unknown` class; this is the filtering rule behind the released flow counts. Added the previously missing Testbed B feature archive.

**1.0.1 (2026-07-19)** — Corrected the per-cell tally files (`labeled.jsonl.counts.json`) for 21 cells (all 12 Testbed B cells and 9 Testbed C cells), where `flows_malicious_c2` had been under-counted by a legacy tallying script. Per-flow label data, pcap archives, features and scripts unchanged.

**1.0.0 (2026-07-18)** — First public release: Testbeds A, B and C, 36 cells.
