"""Bidirectional network flow representation and feature mapping for XShield."""

from dataclasses import dataclass, field
import datetime
import hashlib
from typing import Any, Dict, Optional


@dataclass
class FlowRecord:
    """Represents a reconstructed bidirectional network flow."""

    # 5-tuple
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str  # 'tcp', 'udp', 'icmp', etc.

    # Timeline (epoch seconds)
    start_time: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    last_seen: float = field(default_factory=lambda: datetime.datetime.now().timestamp())
    duration: float = 0.0

    # Flow packet counts
    orig_pkts: int = 0   # Forward (client to server)
    resp_pkts: int = 0   # Reverse (server to client)

    # Flow byte counts
    orig_bytes: int = 0       # Forward payload bytes
    resp_bytes: int = 0       # Reverse payload bytes
    orig_ip_bytes: int = 0    # Forward total IP bytes
    resp_ip_bytes: int = 0    # Reverse total IP bytes
    missed_bytes: int = 0

    # TCP / Connection state
    conn_state: str = "OTH"   # 'SF', 'RSTO', 'RSTR', 'S0', 'REJ', 'OTH'
    history: str = ""         # Zeek-style state history string (e.g. 'ShADadFf')
    is_closed: bool = False

    # TLS metadata (extracted from unencrypted handshakes only; NO payload decryption)
    sni: Optional[str] = None
    ja4: Optional[str] = None
    ja4s: Optional[str] = None
    tls_version: Optional[str] = None

    # Incident & triage tracking
    flow_id: str = field(default="")
    is_replayed: bool = False

    def __post_init__(self) -> None:
        if not self.flow_id:
            # Deterministic flow ID based on 5-tuple and start timestamp
            seed = f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}_{self.proto}_{self.start_time}"
            self.flow_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    @property
    def tot_pkts(self) -> int:
        return self.orig_pkts + self.resp_pkts

    @property
    def tot_bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def tot_ip_bytes(self) -> int:
        return self.orig_ip_bytes + self.resp_ip_bytes

    def update_timeline(self, pkt_time: float) -> None:
        """Updates last_seen and flow duration given a new packet timestamp."""
        if pkt_time < self.start_time:
            self.start_time = pkt_time
        if pkt_time > self.last_seen:
            self.last_seen = pkt_time
        self.duration = max(0.0, self.last_seen - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        """Returns standard serialized dictionary representation of the flow."""
        dt_start = datetime.datetime.fromtimestamp(self.start_time, tz=datetime.timezone.utc).isoformat()
        dt_last = datetime.datetime.fromtimestamp(self.last_seen, tz=datetime.timezone.utc).isoformat()

        return {
            "flow_id": self.flow_id,
            "start_time": dt_start,
            "last_seen": dt_last,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "duration": round(self.duration, 4),
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "tot_pkts": self.tot_pkts,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "tot_bytes": self.tot_bytes,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_ip_bytes": self.resp_ip_bytes,
            "missed_bytes": self.missed_bytes,
            "conn_state": self.conn_state,
            "history": self.history,
            "is_closed": self.is_closed,
            "sni": self.sni or "N/A",
            "ja4": self.ja4 or "N/A",
            "ja4s": self.ja4s or "N/A",
            "is_replayed": self.is_replayed,
        }

    def to_feature_series(self, schema_keys: Optional[list] = None) -> Dict[str, Any]:
        """Maps flow properties to standard model feature names (supporting both TQH-C2 and CICIDS aliases)."""
        d = {
            # TQH-C2 feature names
            "duration": float(self.duration),
            "orig_bytes": float(self.orig_bytes),
            "resp_bytes": float(self.resp_bytes),
            "orig_pkts": float(self.orig_pkts),
            "resp_pkts": float(self.resp_pkts),
            "orig_ip_bytes": float(self.orig_ip_bytes),
            "resp_ip_bytes": float(self.resp_ip_bytes),
            "missed_bytes": float(self.missed_bytes),
            "proto": str(self.proto).lower(),
            "resp_p": int(self.dst_port),
            "orig_p": int(self.src_port),
            "conn_state": str(self.conn_state),
            "history": str(self.history or "ShADadFf"),
            "ja4": str(self.ja4 or "none"),
            "ja4s": str(self.ja4s or "none"),

            # CICIDS-2018 alias features
            "Dst Port": int(self.dst_port),
            "Protocol": 6 if self.proto.lower() == "tcp" else (17 if self.proto.lower() == "udp" else 0),
            "Flow Duration": float(self.duration * 1e6),  # microseconds in CICIDS
            "Tot Fwd Pkts": float(self.orig_pkts),
            "Tot Bwd Pkts": float(self.resp_pkts),
            "TotLen Fwd Pkts": float(self.orig_ip_bytes),
            "TotLen Bwd Pkts": float(self.resp_ip_bytes),
            "Fwd Pkts/s": float(self.orig_pkts / max(0.001, self.duration)),
            "Bwd Pkts/s": float(self.resp_pkts / max(0.001, self.duration)),
            "Flow Pkts/s": float(self.tot_pkts / max(0.001, self.duration)),
            "Flow Byts/s": float(self.tot_bytes / max(0.001, self.duration)),
        }
        if schema_keys:
            # Provide exact schema requested, filling unavailable features with 0.0 or 'none'
            out = {}
            for k in schema_keys:
                if k in d:
                    out[k] = d[k]
                else:
                    out[k] = 0.0
            return out
        return d
