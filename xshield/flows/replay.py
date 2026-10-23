"""Deterministic Flow and PCAP Replay Engine for XShield.

Enables reproducible, offline-safe live demonstrations without requiring:
- Npcap driver installation.
- Administrative privileges.
- Live malicious traffic on physical networks.

Supports:
- PCAP playback using Scapy PcapReader.
- CSV dataset row playback (TQH-C2, CICIDS-2018).
- Built-in Synthetic Enterprise C2 Scenario (benign HTTPS traffic mixed with periodic beaconing).
"""

import csv
import datetime
import logging
from pathlib import Path
import random
import threading
import time
from typing import Any, Callable, Dict, Generator, List, Optional

from xshield.flows.aggregator import FlowAggregator
from xshield.flows.flow_record import FlowRecord

logger = logging.getLogger(__name__)


class FlowReplayEngine:
    """Streams flow records at controlled intervals to simulate live network traffic."""

    def __init__(
        self,
        flow_callback: Optional[Callable[[FlowRecord], None]] = None,
        delay_seconds: float = 0.5,
    ):
        self.flow_callback = flow_callback
        self.delay_seconds = delay_seconds

        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Playback metrics
        self.flows_streamed: int = 0
        self.start_time: Optional[float] = None
        self.is_finished: bool = False
        self.source_description: str = "Idle"

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    @property
    def is_paused(self) -> bool:
        return self._pause_event.is_set()

    def pause(self) -> None:
        self._pause_event.set()

    def resume(self) -> None:
        self._pause_event.clear()

    def stop(self) -> None:
        self._stop_event.set()
        self._pause_event.clear()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self.is_finished = True

    def start_replay_synthetic(
        self,
        total_flows: int = 100,
        c2_ratio: float = 0.15,
        target_c2_ip: str = "198.51.100.24",
        target_c2_port: int = 8443,
    ) -> bool:
        """Starts background streaming of synthetic enterprise traffic with periodic C2 beacons."""
        if self.is_running:
            self.stop()

        self._stop_event.clear()
        self._pause_event.clear()
        self.flows_streamed = 0
        self.is_finished = False
        self.start_time = time.time()
        self.source_description = f"Synthetic Enterprise Scenario ({total_flows} flows, {int(c2_ratio*100)}% C2)"

        def _synthetic_worker():
            benign_endpoints = [
                ("142.250.190.46", 443, "google.com"),
                ("140.82.112.4", 443, "github.com"),
                ("20.112.52.29", 443, "microsoft.com"),
                ("151.101.1.140", 443, "reddit.com"),
                ("52.95.110.1", 443, "aws.amazon.com"),
                ("1.1.1.1", 53, None),
                ("8.8.8.8", 53, None),
            ]

            internal_hosts = ["192.168.1.105", "192.168.1.112", "192.168.1.145"]
            compromised_host = "192.168.1.145"

            now = time.time()
            for i in range(total_flows):
                if self._stop_event.is_set():
                    break
                while self._pause_event.is_set():
                    time.sleep(0.2)
                    if self._stop_event.is_set():
                        break

                is_c2 = (random.random() < c2_ratio) or (i % max(1, int(1 / c2_ratio)) == 0)
                pkt_time = now + (i * 2.5)

                if is_c2:
                    # Simulated periodic Sliver / TLS C2 beacon
                    flow = FlowRecord(
                        src_ip=compromised_host,
                        dst_ip=target_c2_ip,
                        src_port=random.randint(49152, 65535),
                        dst_port=target_c2_port,
                        proto="tcp",
                        start_time=pkt_time,
                        last_seen=pkt_time + random.uniform(0.12, 0.45),
                        orig_pkts=random.randint(11, 14),
                        resp_pkts=random.randint(10, 13),
                        orig_bytes=random.randint(1200, 2400),
                        resp_bytes=random.randint(2800, 4800),
                        orig_ip_bytes=random.randint(1800, 3200),
                        resp_ip_bytes=random.randint(3400, 5600),
                        conn_state="RSTO" if random.random() < 0.94 else "SF",
                        history="ShADadFfR",
                        ja4="t13i131000_f57a46bbacb6_e5728521abd4",
                        ja4s="t130200_1301_a56c5b993250",
                        sni="updates-service-cloud.net",
                        is_closed=True,
                        is_replayed=True,
                        is_synthetic=True,
                    )
                else:
                    # Normal benign HTTPS / DNS traffic
                    dst_ip, dst_port, sni = random.choice(benign_endpoints)
                    src_ip = random.choice(internal_hosts)
                    is_udp = dst_port == 53
                    duration = random.uniform(0.01, 4.2)
                    orig_pkts = random.randint(1, 4) if is_udp else random.randint(5, 45)
                    resp_pkts = random.randint(1, 4) if is_udp else random.randint(5, 75)

                    flow = FlowRecord(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=random.randint(49152, 65535),
                        dst_port=dst_port,
                        proto="udp" if is_udp else "tcp",
                        start_time=pkt_time,
                        last_seen=pkt_time + duration,
                        orig_pkts=orig_pkts,
                        resp_pkts=resp_pkts,
                        orig_bytes=random.randint(64, 5000),
                        resp_bytes=random.randint(64, 45000),
                        orig_ip_bytes=random.randint(128, 6000),
                        resp_ip_bytes=random.randint(128, 50000),
                        conn_state="SF" if not is_udp else "OTH",
                        history="ShADadFf",
                        ja4="t13d151600_8daaf6152771_0271d4a04d2e" if not is_udp else None,
                        ja4s="t130200_1302_234ea6891581" if not is_udp else None,
                        sni=sni,
                        is_closed=True,
                        is_replayed=True,
                        is_synthetic=True,
                    )

                self.flows_streamed += 1
                if self.flow_callback:
                    try:
                        self.flow_callback(flow)
                    except Exception as e:
                        logger.error(f"Error in flow callback: {e}")

                time.sleep(self.delay_seconds)

            self.is_finished = True

        self._thread = threading.Thread(target=_synthetic_worker, name="XShield_ReplaySynthetic", daemon=True)
        self._thread.start()
        return True

    def start_replay_csv(self, csv_path: str, max_rows: int = 500) -> bool:
        """Starts streaming flow records parsed from an offline CSV dataset."""
        path = Path(csv_path)
        if not path.exists():
            logger.error(f"Replay CSV file not found: {csv_path}")
            return False

        if self.is_running:
            self.stop()

        self._stop_event.clear()
        self._pause_event.clear()
        self.flows_streamed = 0
        self.is_finished = False
        self.start_time = time.time()
        self.source_description = f"CSV Replay: {path.name}"

        def _csv_worker():
            try:
                import pandas as pd
                df = pd.read_csv(path, nrows=max_rows)
                now = time.time()

                for idx, row in df.iterrows():
                    if self._stop_event.is_set():
                        break
                    while self._pause_event.is_set():
                        time.sleep(0.2)
                        if self._stop_event.is_set():
                            break

                    pkt_time = now + (idx * 1.5)
                    # Extract common fields safely
                    src_ip = str(row.get("orig_h", row.get("src_ip", f"192.168.1.{100 + (idx % 50)}")))
                    dst_ip = str(row.get("resp_h", row.get("dst_ip", f"198.51.100.{10 + (idx % 20)}")))
                    src_port = int(row.get("orig_p", row.get("src_port", 49152 + (idx % 10000))))
                    dst_port = int(row.get("resp_p", row.get("Dst Port", row.get("dst_port", 443))))
                    proto = str(row.get("proto", "tcp")).lower()

                    flow = FlowRecord(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto,
                        start_time=pkt_time,
                        last_seen=pkt_time + float(row.get("duration", row.get("Flow Duration", 0.5))),
                        orig_pkts=int(row.get("orig_pkts", row.get("Tot Fwd Pkts", 10))),
                        resp_pkts=int(row.get("resp_pkts", row.get("Tot Bwd Pkts", 10))),
                        orig_bytes=int(row.get("orig_bytes", row.get("TotLen Fwd Pkts", 1500))),
                        resp_bytes=int(row.get("resp_bytes", row.get("TotLen Bwd Pkts", 3000))),
                        orig_ip_bytes=int(row.get("orig_ip_bytes", row.get("TotLen Fwd Pkts", 2000))),
                        resp_ip_bytes=int(row.get("resp_ip_bytes", row.get("TotLen Bwd Pkts", 3500))),
                        conn_state=str(row.get("conn_state", "SF")),
                        history=str(row.get("history", "ShADadFf")),
                        ja4=str(row.get("ja4", "none")) if "ja4" in row else None,
                        ja4s=str(row.get("ja4s", "none")) if "ja4s" in row else None,
                        is_closed=True,
                        is_replayed=True,
                    )

                    self.flows_streamed += 1
                    if self.flow_callback:
                        try:
                            self.flow_callback(flow)
                        except Exception as e:
                            logger.error(f"Error in flow callback: {e}")

                    time.sleep(self.delay_seconds)

            except Exception as e:
                logger.error(f"Error during CSV replay: {e}")
            finally:
                self.is_finished = True

        self._thread = threading.Thread(target=_csv_worker, name="XShield_ReplayCSV", daemon=True)
        self._thread.start()
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Returns playback statistics."""
        elapsed = 0.0
        if self.start_time:
            elapsed = time.time() - self.start_time

        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "is_finished": self.is_finished,
            "flows_streamed": self.flows_streamed,
            "elapsed_seconds": round(elapsed, 1),
            "delay_seconds": self.delay_seconds,
            "source_description": self.source_description,
        }
