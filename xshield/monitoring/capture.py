"""Network capture controller and interface health diagnostics for XShield.

Handles:
- Live network interface discovery on Windows.
- Detection of packet-capture backend (Npcap driver & WinPcap API).
- Administrative privilege verification for raw packet sniffing.
- Safe, bounded-queue background packet capture thread.
- Graceful degradation to Deterministic Replay / Stream mode when Npcap is unavailable.
"""

from dataclasses import dataclass, field
import datetime
import logging
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CaptureBackendStatus:
    """Diagnostic state of the host packet capture subsystem."""
    is_npcap_installed: bool
    is_admin: bool
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    recommended_mode: str = "replay"  # 'live' or 'replay'
    status_message: str = ""
    can_capture_live: bool = False


def check_is_admin() -> bool:
    """Checks whether the current Python process has administrative privileges on Windows."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_npcap_installed() -> bool:
    """Checks whether the Npcap packet capture driver is installed on Windows."""
    npcap_paths = [
        Path(r"C:\Windows\System32\Npcap"),
        Path(r"C:\Program Files\Npcap"),
        Path(r"C:\Windows\System32\drivers\npcap.sys"),
        Path(r"C:\Windows\System32\wpcap.dll"),
    ]
    for p in npcap_paths:
        if p.exists():
            return True
    # Test scapy pcap provider status
    try:
        from scapy.config import conf
        if getattr(conf, "use_pcap", False):
            return True
    except Exception:
        pass
    return False


def get_available_interfaces() -> List[Dict[str, Any]]:
    """Retrieves available network adapters with their descriptive names and statuses."""
    interfaces: List[Dict[str, Any]] = []

    # Attempt Windows PowerShell Get-NetAdapter for human-readable adapter names
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object -Property Name, InterfaceDescription, ifIndex, Status, LinkSpeed | ConvertTo-Json -Compress"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for item in data:
                interfaces.append({
                    "name": item.get("Name", "Unknown"),
                    "description": item.get("InterfaceDescription", ""),
                    "if_index": item.get("ifIndex", 0),
                    "status": item.get("Status", "Unknown"),
                    "speed": item.get("LinkSpeed", "Unknown"),
                    "is_up": str(item.get("Status", "")).lower() == "up",
                })
    except Exception as e:
        logger.debug(f"PowerShell adapter query failed: {e}")

    # Fallback to Scapy get_if_list if PowerShell query produced nothing
    if not interfaces:
        try:
            from scapy.all import get_if_list
            raw_ifs = get_if_list()
            for idx, if_name in enumerate(raw_ifs):
                interfaces.append({
                    "name": if_name,
                    "description": f"Interface {idx}",
                    "if_index": idx,
                    "status": "Available",
                    "speed": "Unknown",
                    "is_up": True,
                })
        except Exception as e:
            logger.debug(f"Scapy get_if_list query failed: {e}")

    return interfaces


def check_capture_health() -> CaptureBackendStatus:
    """Performs full health check of the local capture environment."""
    is_npcap = check_npcap_installed()
    is_admin = check_is_admin()
    interfaces = get_available_interfaces()

    can_live = is_npcap and len(interfaces) > 0

    if can_live and is_admin:
        rec_mode = "live"
        msg = "Ready for live packet capture (Npcap driver verified, Administrator privileges confirmed)."
    elif can_live and not is_admin:
        rec_mode = "live"
        msg = "Npcap driver detected. Running as non-admin user; live capture may require Administrator privileges."
    else:
        rec_mode = "replay"
        msg = (
            "Npcap driver not detected on host. Live promiscuous packet capture requires Npcap "
            "(https://npcap.com). Deterministic Replay / Stream Mode is active for full demonstration."
        )

    return CaptureBackendStatus(
        is_npcap_installed=is_npcap,
        is_admin=is_admin,
        interfaces=interfaces,
        recommended_mode=rec_mode,
        status_message=msg,
        can_capture_live=can_live,
    )


class LiveCaptureWorker:
    """Background packet capture thread with bounded queues and clean shutdown."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        max_queue_size: int = 10000,
        packet_callback: Optional[Callable[[Any], None]] = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter or "ip or ip6"
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.packet_callback = packet_callback

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Telemetry
        self.packets_captured: int = 0
        self.packets_dropped: int = 0
        self.errors_count: int = 0
        self.last_error: Optional[str] = None
        self.start_time: Optional[datetime.datetime] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def start(self) -> bool:
        """Starts live packet capture in a background daemon thread."""
        if self.is_running:
            return True

        self._stop_event.clear()
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self.packets_captured = 0
        self.packets_dropped = 0
        self.errors_count = 0
        self.last_error = None

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="XShield_LiveCaptureWorker",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"Capture worker thread started on interface '{self.interface}'")
        return True

    def stop(self, timeout: float = 3.0) -> None:
        """Stops the capture worker cleanly."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("Capture worker thread stopped.")

    def _capture_loop(self) -> None:
        """Main sniff loop running inside the daemon thread."""
        try:
            from scapy.all import sniff

            def _handle_packet(pkt: Any) -> None:
                if self._stop_event.is_set():
                    return
                self.packets_captured += 1
                try:
                    self.packet_queue.put_nowait(pkt)
                except queue.Full:
                    self.packets_dropped += 1

                if self.packet_callback:
                    try:
                        self.packet_callback(pkt)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")

            # Run sniff in chunks with timeout to permit clean stop evaluation
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=_handle_packet,
                    count=50,
                    timeout=1.0,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
        except Exception as e:
            self.errors_count += 1
            self.last_error = str(e)
            logger.error(f"Live capture error: {e}")
        finally:
            self._stop_event.set()

    def get_stats(self) -> Dict[str, Any]:
        """Returns current operational statistics of the capture thread."""
        duration = 0.0
        if self.start_time:
            now = datetime.datetime.now(datetime.timezone.utc)
            duration = (now - self.start_time).total_seconds()

        return {
            "is_running": self.is_running,
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "queue_depth": self.packet_queue.qsize(),
            "errors_count": self.errors_count,
            "last_error": self.last_error,
            "duration_seconds": round(duration, 1),
            "interface": self.interface,
            "filter": self.bpf_filter,
        }
