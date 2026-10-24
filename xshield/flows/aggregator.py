"""Sliding-window bidirectional flow aggregator with TLS handshake metadata extraction.

Aggregates raw L3/L4 packets into bidirectional FlowRecord objects.
Performs:
- Canonical 5-tuple flow matching.
- TCP handshake and termination tracking (Zeek-style conn_state).
- TLS ClientHello SNI and JA4 fingerprint extraction (without payload decryption).
- Flow timeout management and thread-safe flushing.
"""

from collections import OrderedDict
import datetime
import hashlib
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from xshield.flows.flow_record import FlowRecord

logger = logging.getLogger(__name__)


def extract_tls_client_hello(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Extracts SNI and JA4 client fingerprint from TLS ClientHello bytes without payload decryption.

    Returns:
        (sni, ja4_fingerprint) if present, else (None, None).
    """
    if not payload or len(payload) < 43:
        return None, None

    # Check TLS Record header: ContentType == 0x16 (Handshake), Version == 0x03, 0x01/0x02/0x03
    if payload[0] != 0x16 or payload[1] != 0x03:
        return None, None

    record_len = int.from_bytes(payload[3:5], byteorder="big")
    if len(payload) < 5 + record_len:
        # Partial record
        pass

    # Check HandshakeType == 0x01 (ClientHello)
    hs_offset = 5
    if len(payload) <= hs_offset or payload[hs_offset] != 0x01:
        return None, None

    sni: Optional[str] = None
    ciphers: List[int] = []
    extensions: List[int] = []

    try:
        # Handshake length (3 bytes)
        hs_len = int.from_bytes(payload[hs_offset + 1 : hs_offset + 4], byteorder="big")
        # Client Version (2 bytes)
        tls_client_ver = payload[hs_offset + 4 : hs_offset + 6]
        # Random (32 bytes)
        sess_id_offset = hs_offset + 6 + 32
        if sess_id_offset >= len(payload):
            return None, None

        sess_id_len = payload[sess_id_offset]
        cipher_suites_offset = sess_id_offset + 1 + sess_id_len
        if cipher_suites_offset + 2 > len(payload):
            return None, None

        cipher_suites_len = int.from_bytes(
            payload[cipher_suites_offset : cipher_suites_offset + 2], byteorder="big"
        )
        ciphers_end = cipher_suites_offset + 2 + cipher_suites_len
        if ciphers_end > len(payload):
            return None, None

        # Parse ciphers (2 bytes each)
        for i in range(cipher_suites_offset + 2, ciphers_end, 2):
            c_val = int.from_bytes(payload[i : i + 2], byteorder="big")
            # Exclude GREASE values (0x?a?a)
            if (c_val & 0x0F0F) != 0x0A0A:
                ciphers.append(c_val)

        # Parse Compression methods
        comp_offset = ciphers_end
        if comp_offset >= len(payload):
            return None, None
        comp_len = payload[comp_offset]
        exts_offset = comp_offset + 1 + comp_len

        # Parse Extensions
        if exts_offset + 2 <= len(payload):
            exts_len = int.from_bytes(payload[exts_offset : exts_offset + 2], byteorder="big")
            curr_ext = exts_offset + 2
            exts_end = curr_ext + exts_len

            while curr_ext + 4 <= min(exts_end, len(payload)):
                ext_type = int.from_bytes(payload[curr_ext : curr_ext + 2], byteorder="big")
                ext_data_len = int.from_bytes(payload[curr_ext + 2 : curr_ext + 4], byteorder="big")
                ext_data_start = curr_ext + 4
                ext_data_end = ext_data_start + ext_data_len

                if (ext_type & 0x0F0F) != 0x0A0A:
                    extensions.append(ext_type)

                # Check Extension 0x0000 (server_name / SNI)
                if ext_type == 0x0000 and ext_data_end <= len(payload):
                    # SNI list length (2 bytes)
                    if ext_data_len > 5:
                        sni_name_type = payload[ext_data_start + 2]
                        if sni_name_type == 0:  # host_name
                            sni_len = int.from_bytes(
                                payload[ext_data_start + 3 : ext_data_start + 5], byteorder="big"
                            )
                            sni_bytes = payload[ext_data_start + 5 : ext_data_start + 5 + sni_len]
                            sni = sni_bytes.decode("utf-8", errors="replace")

                curr_ext = ext_data_end

        # Synthesize JA4 client fingerprint
        # JA4 format: [protocol][version][sni_ind][num_ciphers][num_exts]_[hash_ciphers]_[hash_exts]
        proto_flag = "t"  # TCP
        ver_flag = "13" if tls_client_ver == b"\x03\x04" else "12"
        d_sni = "d" if sni else "i"
        c_count = f"{min(99, len(ciphers)):02d}"
        e_count = f"{min(99, len(extensions)):02d}"
        a_part = f"{proto_flag}{ver_flag}{d_sni}{c_count}{e_count}00"

        ciphers_str = ",".join(f"{c:04x}" for c in sorted(ciphers))
        b_part = hashlib.sha256(ciphers_str.encode()).hexdigest()[:12]

        exts_str = ",".join(f"{e:04x}" for e in sorted(extensions))
        c_part = hashlib.sha256(exts_str.encode()).hexdigest()[:12]

        ja4 = f"{a_part}_{b_part}_{c_part}"
        return sni, ja4

    except Exception:
        return sni, None


class FlowAggregator:
    """Thread-safe flow aggregator that reconstructs streaming packets into bidirectional FlowRecords."""

    def __init__(
        self,
        inactivity_timeout: float = 30.0,
        max_flow_duration: float = 120.0,
        max_active_flows: int = 20000,
    ):
        self.inactivity_timeout = inactivity_timeout
        self.max_flow_duration = max_flow_duration
        self.max_active_flows = max_active_flows

        # Map canonical 5-tuple key -> FlowRecord
        self._active_flows: OrderedDict[Tuple, FlowRecord] = OrderedDict()
        self._lock = threading.Lock()

        # Telemetry
        self.total_packets_processed: int = 0
        self.total_flows_completed: int = 0

    def _canonical_key(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
    ) -> Tuple[Tuple, bool]:
        """Returns standard canonical flow key and direction flag (True if forward, False if reverse)."""
        forward_key = (src_ip, dst_ip, src_port, dst_port, proto.lower())
        reverse_key = (dst_ip, src_ip, dst_port, src_port, proto.lower())

        if forward_key in self._active_flows:
            return forward_key, True
        if reverse_key in self._active_flows:
            return reverse_key, False

        # If new flow, use forward key by default
        return forward_key, True

    def process_packet(self, packet: Any) -> Optional[FlowRecord]:
        """Processes a single Scapy packet into active flows.

        Returns:
            Completed FlowRecord if connection closed (e.g. TCP FIN/RST), else None.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
        except ImportError:
            return None

        now = time.time()
        pkt_time = float(getattr(packet, "time", now))

        # Extract L3 info
        src_ip = None
        dst_ip = None
        ip_len = len(packet)

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ip_len = int(getattr(ip_layer, "len", None) or len(packet))
        elif packet.haslayer(IPv6):
            ip6_layer = packet.getlayer(IPv6)
            src_ip = str(ip6_layer.src)
            dst_ip = str(ip6_layer.dst)
            ip_len = int(getattr(ip6_layer, "plen", 0) + 40)
        else:
            return None

        # Extract L4 info
        proto = "other"
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        payload_bytes = b""

        if packet.haslayer(TCP):
            proto = "tcp"
            tcp_layer = packet.getlayer(TCP)
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = str(tcp_layer.flags)
            if hasattr(tcp_layer, "payload") and tcp_layer.payload:
                payload_bytes = bytes(tcp_layer.payload)
        elif packet.haslayer(UDP):
            proto = "udp"
            udp_layer = packet.getlayer(UDP)
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            if hasattr(udp_layer, "payload") and udp_layer.payload:
                payload_bytes = bytes(udp_layer.payload)
        elif packet.haslayer(ICMP):
            proto = "icmp"
        else:
            return None

        with self._lock:
            self.total_packets_processed += 1
            key, is_forward = self._canonical_key(src_ip, dst_ip, src_port, dst_port, proto)

            if key not in self._active_flows:
                # Evict oldest flow if reaching capacity limit
                if len(self._active_flows) >= self.max_active_flows:
                    self._active_flows.popitem(last=False)

                flow = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    start_time=pkt_time,
                    last_seen=pkt_time,
                )
                self._active_flows[key] = flow
                is_forward = True
            else:
                flow = self._active_flows[key]

            # Update packet and byte metrics
            flow.update_timeline(pkt_time)
            payload_len = len(payload_bytes)

            if is_forward:
                flow.orig_pkts += 1
                flow.orig_bytes += payload_len
                flow.orig_ip_bytes += ip_len
            else:
                flow.resp_pkts += 1
                flow.resp_bytes += payload_len
                flow.resp_ip_bytes += ip_len

            # Inspect for TLS ClientHello on ports 443 / 8443 or matching TLS header
            if is_forward and not flow.sni and payload_bytes:
                sni, ja4 = extract_tls_client_hello(payload_bytes)
                if sni:
                    flow.sni = sni
                if ja4:
                    flow.ja4 = ja4

            # Track TCP connection state
            completed_flow = None
            if proto == "tcp":
                if "S" in tcp_flags and "A" not in tcp_flags:
                    flow.history += "s" if is_forward else "h"
                if "F" in tcp_flags:
                    flow.history += "f" if is_forward else "F"
                    # FIN received: mark closed if both directions have sent data or after FIN exchange
                    if flow.orig_pkts > 0 and flow.resp_pkts > 0:
                        flow.conn_state = "SF"
                        flow.is_closed = True
                        completed_flow = self._active_flows.pop(key, None)
                elif "R" in tcp_flags:
                    flow.history += "r" if is_forward else "R"
                    flow.conn_state = "RSTO" if is_forward else "RSTR"
                    flow.is_closed = True
                    completed_flow = self._active_flows.pop(key, None)
                elif flow.orig_pkts > 0 and flow.resp_pkts > 0 and flow.conn_state == "OTH":
                    flow.conn_state = "SF"

            if completed_flow:
                self.total_flows_completed += 1
                return completed_flow

            return None

    def flush_expired_flows(self, force: bool = False) -> List[FlowRecord]:
        """Flushes flows that have exceeded inactivity timeout or maximum lifetime."""
        now = time.time()
        expired: List[FlowRecord] = []

        with self._lock:
            keys_to_remove = []
            for key, flow in self._active_flows.items():
                inactive = now - flow.last_seen
                total_duration = now - flow.start_time

                if force or inactive >= self.inactivity_timeout or total_duration >= self.max_flow_duration:
                    keys_to_remove.append(key)
                    flow.is_closed = True
                    expired.append(flow)

            for k in keys_to_remove:
                self._active_flows.pop(k, None)

            self.total_flows_completed += len(expired)

        return expired

    def flush_active_or_expired_flows(
        self, inactivity_timeout: float = 1.5, max_flow_duration: float = 5.0
    ) -> List[FlowRecord]:
        """Flushes flows that are inactive for >= 1.5s or duration >= 5s.
        Also returns active flows with >= 2 packets as snapshots so live monitor updates continuously."""
        import copy
        now = time.time()
        to_emit: List[FlowRecord] = []

        with self._lock:
            keys_to_remove = []
            for key, flow in list(self._active_flows.items()):
                inactive = now - flow.last_seen
                total_duration = now - flow.start_time

                if flow.is_closed or inactive >= inactivity_timeout or total_duration >= max_flow_duration:
                    keys_to_remove.append(key)
                    flow.is_closed = True
                    to_emit.append(flow)
                elif flow.tot_pkts >= 2:
                    to_emit.append(copy.copy(flow))

            for k in keys_to_remove:
                self._active_flows.pop(k, None)

            self.total_flows_completed += len(keys_to_remove)

        return to_emit

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics on current flow aggregator state."""
        with self._lock:
            return {
                "active_flows_count": len(self._active_flows),
                "total_packets_processed": self.total_packets_processed,
                "total_flows_completed": self.total_flows_completed,
            }
