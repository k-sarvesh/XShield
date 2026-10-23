"""Alert creation, deduplication, cooldown control, and notification dispatcher for XShield.

Ensures:
- Deduplication of repeated beacon events using configurable cooldown windows.
- Separation of flows by source, destination, port, and transport protocol.
- Creation and update of persistent IncidentRecords in IncidentStore.
- Transparent tracking of synthetic/replayed demonstration fixtures.
- Thread-safe notification caching for the analyst user interface.
- Safe webhook dispatch with delivery tracking and error logging.
"""

from dataclasses import dataclass, field
import datetime
import hashlib
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import urllib.request

from xshield.detection.engine import DetectionVerdict
from xshield.flows.flow_record import FlowRecord
from xshield.storage.incident_store import IncidentRecord, IncidentStore, sanitize_incident_export

logger = logging.getLogger(__name__)


@dataclass
class AlertNotification:
    """Ephemeral notification for real-time analyst display."""
    alert_id: str
    incident_id: str
    timestamp: str
    severity: str
    title: str
    message: str
    src_endpoint: str
    dst_endpoint: str
    is_synthetic: bool = False
    is_read: bool = False
    webhook_delivered: Optional[bool] = None
    webhook_error: Optional[str] = None


class AlertManager:
    """Manages alert deduplication, cooldowns, and notification delivery."""

    def __init__(
        self,
        incident_store: Optional[IncidentStore] = None,
        cooldown_seconds: float = 60.0,
        webhook_url: Optional[str] = None,
    ):
        self.store = incident_store or IncidentStore()
        self.cooldown_seconds = cooldown_seconds
        self.webhook_url = webhook_url or os.environ.get("XSHIELD_WEBHOOK_URL")

        # Map tracking last alert timestamp per target tuple: (src_ip, dst_ip, dst_port, proto) -> last_alert_time
        self._last_alert_time: Dict[str, float] = {}
        self._recent_notifications: List[AlertNotification] = []
        self._lock = threading.Lock()

    def process_verdict(self, flow: FlowRecord, verdict: DetectionVerdict) -> Optional[AlertNotification]:
        """Evaluates detection verdict, applies deduplication, and creates incident/notification if warranted."""
        if not verdict.is_suspicious:
            return None

        now = time.time()
        proto_clean = flow.proto.lower()
        dedup_key = f"{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}/{proto_clean}"
        is_synthetic = bool(getattr(flow, "is_replayed", False) or getattr(verdict, "is_synthetic", False))

        with self._lock:
            last_time = self._last_alert_time.get(dedup_key, 0.0)
            time_since_last = now - last_time

            # Check if active incident already exists in store for this endpoint pair and protocol
            existing_inc = self.store.find_active_incident(
                flow.src_ip, flow.dst_ip, flow.dst_port, proto=proto_clean
            )

            if existing_inc and time_since_last < self.cooldown_seconds:
                # Within cooldown: update existing incident frequency and last_seen without creating duplicate alert
                existing_inc.last_seen = datetime.datetime.now(datetime.timezone.utc).isoformat()
                existing_inc.occurrence_count += 1
                self.store.save_incident(existing_inc)
                logger.debug(f"Suppressed duplicate alert for {dedup_key} (occurrence {existing_inc.occurrence_count})")
                return None

            # New incident or cooldown elapsed
            self._last_alert_time[dedup_key] = now
            iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            if existing_inc:
                inc_id = existing_inc.incident_id
                inc_count = existing_inc.occurrence_count + 1
            else:
                inc_id = f"INC-{int(now)}-{hashlib.sha256(dedup_key.encode()).hexdigest()[:6].upper()}"
                inc_count = 1

            new_record = IncidentRecord(
                incident_id=inc_id,
                created_at=existing_inc.created_at if existing_inc else iso_now,
                last_seen=iso_now,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                proto=flow.proto,
                severity=verdict.risk_tier,
                detection_source=verdict.detection_source,
                raw_score=verdict.raw_score,
                model_name=verdict.model_name,
                evidence=verdict.evidence,
                limitations=verdict.limitations,
                status=existing_inc.status if existing_inc else "New",
                analyst_notes=existing_inc.analyst_notes if existing_inc else "",
                response_action=existing_inc.response_action if existing_inc else "None",
                occurrence_count=inc_count,
                is_synthetic=is_synthetic,
            )
            self.store.save_incident(new_record)

            # Generate analyst notification
            alert_id = f"ALT-{int(now)}-{hashlib.sha256(f'{inc_id}_{now}'.encode()).hexdigest()[:6].upper()}"
            title = f"{verdict.risk_tier} Severity Detection: {flow.dst_ip}:{flow.dst_port}"
            prefix = "[SYNTHETIC DEMO] " if is_synthetic else ""
            msg = (
                f"{prefix}Suspicious {flow.proto.upper()} traffic detected from {flow.src_ip} to {flow.dst_ip}:{flow.dst_port}. "
                f"Source: {verdict.detection_source}. "
            )
            if verdict.raw_score is not None:
                msg += f"Score: {verdict.raw_score:.2f} (Threshold: {verdict.threshold_applied:.2f})."

            notif = AlertNotification(
                alert_id=alert_id,
                incident_id=inc_id,
                timestamp=iso_now,
                severity=verdict.risk_tier,
                title=title,
                message=msg,
                src_endpoint=f"{flow.src_ip}:{flow.src_port}",
                dst_endpoint=f"{flow.dst_ip}:{flow.dst_port}",
                is_synthetic=is_synthetic,
            )

            self._recent_notifications.insert(0, notif)
            if len(self._recent_notifications) > 100:
                self._recent_notifications.pop()

            # Attempt optional external webhook dispatch in background
            if self.webhook_url:
                threading.Thread(
                    target=self._dispatch_webhook,
                    args=(notif, new_record),
                    daemon=True,
                ).start()

            return notif

    def get_recent_notifications(self, limit: int = 10) -> List[AlertNotification]:
        """Returns recent in-app notifications."""
        with self._lock:
            return list(self._recent_notifications[:limit])

    def clear_notifications(self) -> None:
        """Clears in-memory notifications list."""
        with self._lock:
            self._recent_notifications.clear()

    def _dispatch_webhook(self, notif: AlertNotification, inc: IncidentRecord) -> None:
        """Safely dispatches sanitized JSON alert to external webhook with status tracking."""
        if not self.webhook_url:
            return
        try:
            import json
            payload = {
                "alert_id": notif.alert_id,
                "incident_id": inc.incident_id,
                "timestamp": notif.timestamp,
                "severity": notif.severity,
                "title": notif.title,
                "message": notif.message,
                "src": notif.src_endpoint,
                "dst": notif.dst_endpoint,
                "is_synthetic": notif.is_synthetic,
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "XShield-AlertManager/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if 200 <= resp.status < 300:
                    notif.webhook_delivered = True
                else:
                    notif.webhook_delivered = False
                    notif.webhook_error = f"HTTP {resp.status}"
        except Exception as e:
            notif.webhook_delivered = False
            notif.webhook_error = str(e)
            logger.warning(f"Webhook dispatch failed: {e}")
