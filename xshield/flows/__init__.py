"""Flow aggregation, representation, and replay utilities for XShield."""

from xshield.flows.flow_record import FlowRecord
from xshield.flows.aggregator import FlowAggregator, extract_tls_client_hello
from xshield.flows.replay import FlowReplayEngine

__all__ = [
    "FlowRecord",
    "FlowAggregator",
    "extract_tls_client_hello",
    "FlowReplayEngine",
]
