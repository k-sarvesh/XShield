"""Thread-safe application monitoring runtime for XShield.

Decouples background worker threads (FlowReplayEngine, LiveCaptureWorker)
from Streamlit's UI rendering lifecycle and st.session_state, ensuring:
- Safe, non-blocking ingestion callbacks from background threads.
- Deterministic initialization of DetectionEngine, IncidentStore, AlertManager,
  and NetworkResponseManager prior to traffic ingestion.
- Thread-safe buffer tracking of real-time flow feeds and metrics counters.
- Clean stop, restart, and duplicate-start prevention.
- Transparent surfacing of runtime errors without silent exception suppression.
"""

from collections import deque
import datetime
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from xshield.alerts.alert_manager import AlertManager
from xshield.detection.engine import DetectionEngine, DetectionVerdict
from xshield.flows.aggregator import FlowAggregator
from xshield.flows.flow_record import FlowRecord
from xshield.flows.replay import FlowReplayEngine
from xshield.monitoring.capture import LiveCaptureWorker
from xshield.response.blocker import NetworkResponseManager
from xshield.storage.incident_store import IncidentStore

logger = logging.getLogger(__name__)


class MonitoringRuntime:
    """Central thread-safe coordinator for traffic ingestion, detection, and state persistence."""

    def __init__(
        self,
        incident_store: Optional[IncidentStore] = None,
        alert_manager: Optional[AlertManager] = None,
        detection_engine: Optional[DetectionEngine] = None,
        response_manager: Optional[NetworkResponseManager] = None,
        max_buffer_size: int = 100,
    ):
        # 1. Authoritative Core Subsystems (Always initialized upfront)
        self.incident_store = incident_store or IncidentStore()
        self.alert_manager = alert_manager or AlertManager(
            incident_store=self.incident_store,
            cooldown_seconds=60.0,
        )
        self.detection_engine = detection_engine or DetectionEngine()
        self.response_manager = response_manager or NetworkResponseManager(simulation_mode=True)

        # 2. Thread Synchronization & Real-Time Buffers
        self._lock = threading.Lock()
        self._live_flows_buffer: deque = deque(maxlen=max_buffer_size)
        self._flow_stats_counters: Dict[str, int] = {
            "total": 0,
            "suspicious": 0,
            "benign": 0,
            "insufficient": 0,
        }

        # 3. Active Workers
        self.replay_engine: Optional[FlowReplayEngine] = None
        self.capture_worker: Optional[LiveCaptureWorker] = None

        # 4. Error Diagnostics
        self.last_error: Optional[str] = None
        self.processing_errors: List[Dict[str, Any]] = []

    def handle_flow(self, flow: FlowRecord) -> DetectionVerdict:
        """Processes an incoming flow record safely from any background or worker thread.

        Does NOT depend on Streamlit st.session_state or thread-local contexts.
        """
        try:
            # 1. Run detection engine inference and heuristic evidence reasoning
            verdict = self.detection_engine.evaluate_flow(flow)

            # 2. Update memory buffer and counters under lock
            with self._lock:
                self._live_flows_buffer.appendleft({"flow": flow, "verdict": verdict})
                self._flow_stats_counters["total"] += 1
                if verdict.status == "SUSPICIOUS":
                    self._flow_stats_counters["suspicious"] += 1
                elif verdict.status == "BENIGN":
                    self._flow_stats_counters["benign"] += 1
                else:
                    self._flow_stats_counters["insufficient"] += 1

            # 3. If suspicious, dispatch to alert manager for coalescing and SQLite persistence
            if verdict.status == "SUSPICIOUS":
                self.alert_manager.process_verdict(flow, verdict)

            return verdict
        except Exception as e:
            err_msg = f"Error processing flow '{getattr(flow, 'flow_id', 'unknown')}': {e}"
            logger.error(err_msg, exc_info=True)
            with self._lock:
                self.last_error = str(e)
                self.processing_errors.append({
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "flow_id": getattr(flow, "flow_id", "unknown"),
                    "error": str(e),
                })
                if len(self.processing_errors) > 50:
                    self.processing_errors.pop(0)
            raise e

    def start_replay(
        self,
        mode: str = "synthetic",
        delay_seconds: float = 0.5,
        csv_path: Optional[str] = None,
        total_flows: int = 120,
        c2_ratio: float = 0.18,
        max_rows: int = 150,
    ) -> bool:
        """Stops any existing ingestion worker and starts a deterministic replay session."""
        with self._lock:
            self.stop_ingestion()

            engine = FlowReplayEngine(
                flow_callback=self.handle_flow,
                delay_seconds=delay_seconds,
            )
            self.replay_engine = engine

            if mode == "synthetic":
                return engine.start_replay_synthetic(total_flows=total_flows, c2_ratio=c2_ratio)
            elif mode == "csv" and csv_path:
                return engine.start_replay_csv(csv_path=csv_path, max_rows=max_rows)
            else:
                raise ValueError(f"Unsupported replay mode: {mode}")

    def start_capture(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ) -> bool:
        """Stops any existing worker and starts live promiscuous packet capture on the host network."""
        with self._lock:
            self.stop_ingestion()

            aggregator = FlowAggregator(inactivity_timeout=1.5, max_flow_duration=5.0)

            def _packet_callback(pkt: Any) -> None:
                completed = aggregator.process_packet(pkt)
                if completed:
                    try:
                        self.handle_flow(completed)
                    except Exception as e:
                        logger.error(f"Error handling completed live flow: {e}")

            worker = LiveCaptureWorker(
                interface=interface,
                bpf_filter=bpf_filter or "ip or ip6",
                packet_callback=_packet_callback,
            )
            self.capture_worker = worker
            started = worker.start()

            if started:
                def _flush_thread_loop():
                    while worker.is_running:
                        time.sleep(1.0)
                        flows = aggregator.flush_active_or_expired_flows(inactivity_timeout=1.5, max_flow_duration=5.0)
                        for f in flows:
                            try:
                                self.handle_flow(f)
                            except Exception as e:
                                logger.error(f"Error handling live flow: {e}")

                flusher = threading.Thread(
                    target=_flush_thread_loop,
                    name="XShield_LiveFlowFlusher",
                    daemon=True,
                )
                flusher.start()

            return started

    def stop_ingestion(self) -> None:
        """Safely stops any active replay or capture worker without hanging."""
        if self.replay_engine is not None and self.replay_engine.is_running:
            self.replay_engine.stop()
            self.replay_engine = None

        if self.capture_worker is not None and self.capture_worker.is_running:
            self.capture_worker.stop()
            self.capture_worker = None

    def is_active(self) -> bool:
        """Returns True if any background ingestion worker is actively running."""
        replay_active = self.replay_engine is not None and self.replay_engine.is_running
        capture_active = self.capture_worker is not None and self.capture_worker.is_running
        return replay_active or capture_active

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns a snapshot of the most recent flows and verdicts in thread-safe manner."""
        with self._lock:
            return list(self._live_flows_buffer)[:limit]

    def get_flow_stats(self) -> Dict[str, int]:
        """Returns a snapshot copy of current ingestion metric counters."""
        with self._lock:
            return dict(self._flow_stats_counters)

    def reset_flow_data(self) -> None:
        """Clears recent flow buffer, counters, and error diagnostics."""
        with self._lock:
            self._live_flows_buffer.clear()
            self._flow_stats_counters = {
                "total": 0,
                "suspicious": 0,
                "benign": 0,
                "insufficient": 0,
            }
            self.last_error = None
            self.processing_errors.clear()


# Process-wide runtime singleton
_RUNTIME_INSTANCE: Optional[MonitoringRuntime] = None
_RUNTIME_LOCK = threading.Lock()


def get_monitoring_runtime(reset: bool = False) -> MonitoringRuntime:
    """Returns the process-wide MonitoringRuntime instance.

    Args:
        reset: If True, forces initialization of a fresh runtime instance.
    """
    global _RUNTIME_INSTANCE
    with _RUNTIME_LOCK:
        if _RUNTIME_INSTANCE is None or reset:
            _RUNTIME_INSTANCE = MonitoringRuntime()
        return _RUNTIME_INSTANCE
