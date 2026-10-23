"""Storage subsystem for persistent incident and event logging in XShield."""

from xshield.storage.incident_store import IncidentStore, IncidentRecord

__all__ = [
    "IncidentStore",
    "IncidentRecord",
]
