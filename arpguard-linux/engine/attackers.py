"""
attackers.py
------------
Groups attack events by attacker (keyed by MAC address). Attack-type
agnostic - ARP and DNS spoofing events from the same MAC land in the
same attacker record.

Important nuance handled here: once an attacker is blocked, raw packet
capture (what detectors/*.py use to see traffic) still observes their
packets - capture taps the network interface BEFORE the OS firewall
gets a chance to drop the packet, on both Linux and Windows. That is
expected and does not mean the block failed; the packet is still
rejected before it does anything real. But logging every single
rejected retry as a fresh "attack" makes the attempt counter climb
forever and makes a working block look broken on the dashboard. So
post-block retries are tracked in a SEPARATE counter
(blocked_retry_count) and logged with throttling, instead of
inflating attack_count.

Every event is also written through to SQLite (engine/db.py).
"""

import itertools
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional

from engine import db

_seq_counter = itertools.count(1)

BLOCKED_RETRY_LOG_THROTTLE_SECONDS = 5


@dataclass
class AttackEvent:
    seq: int
    timestamp: str
    attack_type: str
    gateway_ip: str   # reused generically: ARP -> gateway IP, DNS -> queried domain
    trusted_mac: str  # reused generically: ARP -> trusted gateway MAC, DNS -> trusted resolver(s)
    action: str
    success: bool


@dataclass
class AttackerRecord:
    mac: str
    ip: str = "resolving..."
    hostname: str = "Unknown"
    first_seen: str = ""
    last_seen: str = ""
    first_seen_dt: Optional[datetime] = None
    last_seen_dt: Optional[datetime] = None
    attack_count: int = 0
    attempts_before_block: int = 0
    blocked_retry_count: int = 0
    last_blocked_log_dt: Optional[datetime] = None
    blocked: bool = False
    blocked_by: str = ""  # "manual" or "auto"
    block_methods: List[str] = field(default_factory=list)
    events: List[AttackEvent] = field(default_factory=list)


class AttackerTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._attackers: Dict[str, AttackerRecord] = {}

    def record_attack(self, mac: str, ip: str, gateway_ip: str, trusted_mac: str,
                       action: str, success: bool, attack_type: str = "ARP Spoofing") -> AttackerRecord:
        now_dt = datetime.now()
        now = now_dt.strftime("%H:%M:%S")
        with self._lock:
            record = self._attackers.get(mac)
            if record is None:
                record = AttackerRecord(mac=mac, ip=ip, first_seen=now, first_seen_dt=now_dt)
                self._attackers[mac] = record

            record.ip = ip
            record.last_seen = now
            record.last_seen_dt = now_dt
            record.attack_count += 1
            record.events.insert(0, AttackEvent(
                seq=next(_seq_counter), timestamp=now, attack_type=attack_type,
                gateway_ip=gateway_ip, trusted_mac=trusted_mac, action=action, success=success,
            ))
            record.events = record.events[:100]
            hostname = record.hostname

        db.log_event(attack_type, mac, ip, hostname, gateway_ip, trusted_mac, action, success)
        return record

    def record_blocked_retry(self, mac: str, ip: str, action: str, success: bool,
                              attack_type: str = "ARP Spoofing"):
        """
        Called when a packet still arrives from an already-blocked
        attacker. Does NOT increment attack_count (that would make the
        counter climb forever and look like the block isn't working).
        Logged with throttling so the log/ticker doesn't spam once per
        packet either.
        """
        now_dt = datetime.now()
        with self._lock:
            record = self._attackers.get(mac)
            if record is None:
                return

            record.ip = ip
            record.last_seen = now_dt.strftime("%H:%M:%S")
            record.last_seen_dt = now_dt
            record.blocked_retry_count += 1

            should_log = (
                record.last_blocked_log_dt is None
                or (now_dt - record.last_blocked_log_dt).total_seconds() >= BLOCKED_RETRY_LOG_THROTTLE_SECONDS
            )
            if not should_log:
                return

            record.last_blocked_log_dt = now_dt
            full_action = f"{action} (retry #{record.blocked_retry_count} since block - rejected)"
            record.events.insert(0, AttackEvent(
                seq=next(_seq_counter), timestamp=record.last_seen, attack_type=attack_type,
                gateway_ip="-", trusted_mac="-", action=full_action, success=success,
            ))
            record.events = record.events[:100]
            hostname = record.hostname

        db.log_event(attack_type, mac, ip, hostname, "-", "-", full_action, success)

    def set_hostname(self, mac: str, hostname: str):
        with self._lock:
            if mac in self._attackers:
                self._attackers[mac].hostname = hostname

    def mark_blocked(self, mac: str, methods: List[str], blocked_by: str = "manual"):
        with self._lock:
            record = self._attackers.get(mac)
            if record is None:
                return
            record.blocked = True
            record.blocked_by = blocked_by
            record.block_methods = methods
            record.attempts_before_block = record.attack_count
            record.blocked_retry_count = 0
            record.last_blocked_log_dt = None
            label = "Auto-blocked (sustained attack)" if blocked_by == "auto" else "Manually blocked"
            action = f"{label} via {', '.join(methods) if methods else 'unknown method'}"
            record.events.insert(0, AttackEvent(
                seq=next(_seq_counter), timestamp=datetime.now().strftime("%H:%M:%S"),
                attack_type="Block Action", gateway_ip="-", trusted_mac="-", action=action, success=True,
            ))
            ip, hostname = record.ip, record.hostname

        db.log_event("Block Action", mac, ip, hostname, "-", "-", action, True)

    def mark_unblocked(self, mac: str):
        with self._lock:
            record = self._attackers.get(mac)
            if record is None:
                return
            record.blocked = False
            record.blocked_by = ""
            record.block_methods = []
            record.events.insert(0, AttackEvent(
                seq=next(_seq_counter), timestamp=datetime.now().strftime("%H:%M:%S"),
                attack_type="Block Action", gateway_ip="-", trusted_mac="-",
                action="Attacker unblocked", success=True,
            ))
            ip, hostname = record.ip, record.hostname

        db.log_event("Block Action", mac, ip, hostname, "-", "-", "Attacker unblocked", True)

    def get_ip(self, mac: str) -> Optional[str]:
        with self._lock:
            record = self._attackers.get(mac)
            return record.ip if record else None

    def exists(self, mac: str) -> bool:
        with self._lock:
            return mac in self._attackers

    def get_duration_seconds(self, mac: str) -> float:
        with self._lock:
            record = self._attackers.get(mac)
            if record is None or record.first_seen_dt is None or record.last_seen_dt is None:
                return 0.0
            return (record.last_seen_dt - record.first_seen_dt).total_seconds()

    def is_blocked(self, mac: str) -> bool:
        with self._lock:
            record = self._attackers.get(mac)
            return record.blocked if record else False

    def list_summaries(self):
        with self._lock:
            result = []
            for r in sorted(self._attackers.values(), key=lambda x: x.last_seen, reverse=True):
                duration = 0.0
                if r.first_seen_dt and r.last_seen_dt:
                    duration = (r.last_seen_dt - r.first_seen_dt).total_seconds()
                result.append({
                    "mac": r.mac, "ip": r.ip, "hostname": r.hostname,
                    "first_seen": r.first_seen, "last_seen": r.last_seen,
                    "attack_count": r.attack_count,
                    "attempts_before_block": r.attempts_before_block,
                    "blocked_retry_count": r.blocked_retry_count,
                    "blocked": r.blocked, "blocked_by": r.blocked_by,
                    "block_methods": r.block_methods,
                    "duration_seconds": round(duration, 1),
                })
            return result

    def get_events(self, mac: str):
        with self._lock:
            record = self._attackers.get(mac)
            if record is None:
                return None
            return [asdict(e) for e in record.events]

    def get_all_events(self):
        with self._lock:
            combined = []
            for r in self._attackers.values():
                for e in r.events:
                    row = asdict(e)
                    row["attacker_ip"] = r.ip
                    row["attacker_mac"] = r.mac
                    row["attacker_hostname"] = r.hostname
                    combined.append(row)
            combined.sort(key=lambda x: x["seq"], reverse=True)
            return combined


attacker_tracker = AttackerTracker()
