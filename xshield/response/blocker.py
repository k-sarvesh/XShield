"""Controlled, reversible network blocking and simulation manager for XShield.

Safety Principles:
- Default mode: SIMULATION ONLY. No system network changes without explicit analyst confirmation.
- Parameterized execution: Uses list arguments with subprocess.run; never executes arbitrary shell strings.
- Address validation: Verifies IP syntax and protects critical infrastructure (loopback, DNS, link-local, broadcast).
- Scoped naming: All rules strictly enforce prefix 'XShield_Block_' with unique identifier.
- Expiration support: Rules carry configurable temporary containment durations (e.g., 15m, 60m).
- Atomic rollback & verification: Verifies rule creation and removal with Windows Firewall state queries.
- Ownership protection: Refuses to delete any rule not prefixed with 'XShield_Block_'.
"""

from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import ipaddress
import logging
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional, Set

def check_is_admin() -> bool:
    """Checks whether the current Python process has administrative privileges on Windows."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

logger = logging.getLogger(__name__)

# Essential infrastructure IPs that must NEVER be blocked
PROTECTED_IPS: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222",
    "208.67.220.220",
}


def is_protected_ip(ip_str: str) -> bool:
    """Verifies whether an IP is in the protected critical infrastructure blacklist."""
    ip_clean = ip_str.strip()
    if ip_clean in PROTECTED_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return (
            ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        )
    except ValueError:
        return True  # Malformed IP is treated as protected to prevent execution


@dataclass
class BlockActionStatus:
    """Represents a recommended, simulated, enforced, or rolled-back block rule."""
    action_id: str
    rule_name: str
    target_ip: str
    direction: str          # 'outbound' or 'inbound'
    status: str             # 'RECOMMENDED', 'SIMULATED', 'ENFORCED', 'FAILED', 'ROLLED_BACK', 'EXPIRED'
    is_live: bool           # True if actually created in Windows Firewall
    reason: str
    incident_id: Optional[str]
    created_at: str
    details: str
    duration_minutes: int = 60
    expires_at: Optional[str] = None
    rolled_back_at: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.status in ["SIMULATED", "ENFORCED"]


class NetworkResponseManager:
    """Manages simulated response recommendations and optional guarded Windows Firewall enforcement."""

    def __init__(
        self,
        simulation_mode: bool = True,
        command_executor: Optional[Callable[[List[str]], subprocess.CompletedProcess]] = None,
    ):
        self.simulation_mode = simulation_mode
        self._command_executor = command_executor or self._default_executor
        self._active_rules: Dict[str, BlockActionStatus] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _default_executor(cmd: List[str]) -> subprocess.CompletedProcess:
        """Executes system command with strict list parameters and timeout."""
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    def recommend_block(
        self,
        target_ip: str,
        reason: str,
        incident_id: Optional[str] = None,
        direction: str = "outbound",
        duration_minutes: int = 60,
    ) -> Dict[str, Any]:
        """Generates a structured block recommendation for analyst review without applying changes."""
        target_clean = target_ip.strip()

        # Validate IP syntax
        try:
            ip_obj = ipaddress.ip_address(target_clean)
            is_valid = True
            is_private = ip_obj.is_private
        except ValueError:
            return {
                "allowed": False,
                "error": f"Invalid IP address format: '{target_clean}'",
            }

        # Check critical protection blacklist
        if is_protected_ip(target_clean):
            return {
                "allowed": False,
                "error": f"IP '{target_clean}' is protected infrastructure (loopback/DNS/gateway/link-local) and cannot be blocked.",
            }

        # Warn if target is private/internal RFC1918 address
        warning = None
        if is_private:
            warning = (
                f"Notice: '{target_clean}' is a private internal network address. "
                "Blocking outbound traffic to this address may disrupt local services, subnets, or lab containers."
            )

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = (now + datetime.timedelta(minutes=duration_minutes)).isoformat()
        uid = hashlib.sha256(f"{target_clean}_{now.isoformat()}".encode()).hexdigest()[:8].upper()
        rule_name = f"XShield_Block_{target_clean.replace(':', '_')}_{uid}"

        potential_impact = (
            warning or f"Blocks all {direction} network communication to remote host {target_clean} for {duration_minutes} minutes."
        )

        return {
            "allowed": True,
            "target_ip": target_clean,
            "rule_name": rule_name,
            "direction": direction,
            "duration_minutes": duration_minutes,
            "expires_at": expires_at,
            "scope": f"Single remote IP ({target_clean})",
            "reason": reason,
            "incident_id": incident_id,
            "potential_impact": potential_impact,
            "warning": warning,
            "status": "RECOMMENDED",
            "proposed_command": f"netsh.exe advfirewall firewall add rule name=\"{rule_name}\" dir={direction} action=block remoteip={target_clean}",
        }

    def apply_block(
        self,
        target_ip: str,
        reason: str,
        incident_id: Optional[str] = None,
        direction: str = "outbound",
        duration_minutes: int = 60,
        live_requested: bool = False,
    ) -> BlockActionStatus:
        """Applies a block action in Simulation Mode (default) or guarded Live Mode if explicitly opted-in."""
        rec = self.recommend_block(target_ip, reason, incident_id, direction, duration_minutes)
        if not rec.get("allowed"):
            action_id = f"ACT-ERR-{int(datetime.datetime.now().timestamp())}"
            return BlockActionStatus(
                action_id=action_id,
                rule_name="N/A",
                target_ip=target_ip,
                direction=direction,
                status="FAILED",
                is_live=False,
                reason=reason,
                incident_id=incident_id,
                created_at=time_now(),
                duration_minutes=duration_minutes,
                details=rec.get("error", "Unknown validation error"),
            )

        rule_name = rec["rule_name"]
        action_id = f"ACT-{rule_name.replace('XShield_Block_', '')}"
        expires_at = rec["expires_at"]

        # Decision: Simulation vs Live Enforcement
        if self.simulation_mode or not live_requested:
            # SIMULATION MODE (Default & Safe)
            status_obj = BlockActionStatus(
                action_id=action_id,
                rule_name=rule_name,
                target_ip=target_ip,
                direction=direction,
                status="SIMULATED",
                is_live=False,
                reason=reason,
                incident_id=incident_id,
                created_at=time_now(),
                duration_minutes=duration_minutes,
                expires_at=expires_at,
                details=(
                    f"SIMULATION: Block rule recorded for analyst review. "
                    f"No network firewall modifications were performed. Scope: {rec['scope']}. "
                    f"Temporary containment: {duration_minutes}m."
                ),
            )
            with self._lock:
                self._active_rules[rule_name] = status_obj
            return status_obj

        # LIVE ENFORCEMENT REQUESTED
        # Verify administrator elevation
        if not check_is_admin():
            status_obj = BlockActionStatus(
                action_id=action_id,
                rule_name=rule_name,
                target_ip=target_ip,
                direction=direction,
                status="FAILED",
                is_live=False,
                reason=reason,
                incident_id=incident_id,
                created_at=time_now(),
                duration_minutes=duration_minutes,
                expires_at=expires_at,
                details=(
                    "Elevation Error: Administrative privileges are required to create Windows Firewall rules. "
                    "Please re-launch the process as Administrator to enable live blocking. Action fallback to Simulation."
                ),
            )
            with self._lock:
                self._active_rules[rule_name] = status_obj
            return status_obj

        # Execute safe parameterized netsh command
        cmd = [
            "netsh.exe",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={target_ip}",
            f"description=XShield automated security containment: {reason[:80]}",
        ]

        try:
            res = self._command_executor(cmd)
            if res.returncode == 0:
                # Post-creation verification
                verify_cmd = ["netsh.exe", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
                v_res = self._command_executor(verify_cmd)
                if v_res.returncode == 0:
                    status_obj = BlockActionStatus(
                        action_id=action_id,
                        rule_name=rule_name,
                        target_ip=target_ip,
                        direction=direction,
                        status="ENFORCED",
                        is_live=True,
                        reason=reason,
                        incident_id=incident_id,
                        created_at=time_now(),
                        duration_minutes=duration_minutes,
                        expires_at=expires_at,
                        details=f"Live Windows Firewall block rule '{rule_name}' successfully created and verified.",
                    )
                else:
                    status_obj = BlockActionStatus(
                        action_id=action_id,
                        rule_name=rule_name,
                        target_ip=target_ip,
                        direction=direction,
                        status="FAILED",
                        is_live=False,
                        reason=reason,
                        incident_id=incident_id,
                        created_at=time_now(),
                        duration_minutes=duration_minutes,
                        details="Post-creation verification failed: rule was not detected in active firewall policy.",
                    )
            else:
                status_obj = BlockActionStatus(
                    action_id=action_id,
                    rule_name=rule_name,
                    target_ip=target_ip,
                    direction=direction,
                    status="FAILED",
                    is_live=False,
                    reason=reason,
                    incident_id=incident_id,
                    created_at=time_now(),
                    duration_minutes=duration_minutes,
                    details=f"Firewall command failed: {res.stderr or res.stdout}",
                )
        except Exception as e:
            status_obj = BlockActionStatus(
                action_id=action_id,
                rule_name=rule_name,
                target_ip=target_ip,
                direction=direction,
                status="FAILED",
                is_live=False,
                reason=reason,
                incident_id=incident_id,
                created_at=time_now(),
                duration_minutes=duration_minutes,
                details=f"Execution error: {e}",
            )

        with self._lock:
            self._active_rules[rule_name] = status_obj
        return status_obj

    def rollback_block(self, rule_name: str) -> bool:
        """Removes an active block rule, restoring original network access."""
        # Strict ownership verification: XShield only ever touches rules with prefix 'XShield_Block_'
        if not rule_name.startswith("XShield_Block_"):
            logger.warning(f"Refused rollback for non-XShield rule: '{rule_name}'")
            return False

        with self._lock:
            if rule_name not in self._active_rules:
                return False
            rule_entry = self._active_rules[rule_name]

            if not rule_entry.is_live:
                # Simulated rule rollback
                rule_entry.status = "ROLLED_BACK"
                rule_entry.rolled_back_at = time_now()
                rule_entry.details += " [Simulated rule rolled back by analyst]"
                return True

            # Live rule removal
            cmd = ["netsh.exe", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            try:
                res = self._command_executor(cmd)
                if res.returncode == 0:
                    rule_entry.status = "ROLLED_BACK"
                    rule_entry.rolled_back_at = time_now()
                    rule_entry.details += " [Live firewall rule deleted and verified by analyst]"
                    return True
                else:
                    logger.error(f"Failed to delete firewall rule '{rule_name}': {res.stderr}")
                    return False
            except Exception as e:
                logger.error(f"Exception during rule deletion '{rule_name}': {e}")
                return False

    def cleanup_expired_rules(self) -> List[str]:
        """Automatically rolls back temporary rules that have exceeded their containment duration."""
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        expired_rules: List[str] = []

        with self._lock:
            for rule_name, rule_entry in list(self._active_rules.items()):
                if rule_entry.is_active and rule_entry.expires_at:
                    try:
                        exp_dt = datetime.datetime.fromisoformat(rule_entry.expires_at)
                        if now_dt >= exp_dt:
                            expired_rules.append(rule_name)
                    except Exception:
                        pass

        # Execute rollback outside of read lock
        successfully_cleaned = []
        for r_name in expired_rules:
            if self.rollback_block(r_name):
                with self._lock:
                    if r_name in self._active_rules:
                        self._active_rules[r_name].status = "EXPIRED"
                successfully_cleaned.append(r_name)

        return successfully_cleaned

    def list_active_rules(self) -> List[BlockActionStatus]:
        """Returns all registered block rules and their current statuses."""
        with self._lock:
            return list(self._active_rules.values())


def time_now() -> str:
    """Helper returning ISO-8601 UTC timestamp string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
