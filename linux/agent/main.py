"""
main.py
-------
Entry point for the ARP Guard agent WITH live dashboard.

Running this single file starts:
  1. SQLite init + whitelist load
  2. Network discovery (trusted gateway baseline)
  3. Background ARP sniffing/detection thread
  4. Background DNS sniffing/detection thread
  5. Local FastAPI dashboard server on http://127.0.0.1:8000
     (pages: /, /blocklist, /logs, /overview, /network, /whitelist)

Attacks (ARP or DNS) are grouped per attacker (by MAC) via
AttackerTracker - one attacker's activity across BOTH attack types
shows up as a single row. If an attacker keeps attacking continuously
past AUTO_BLOCK_AFTER_SECONDS (see engine/policy.py), they are blocked
automatically - otherwise, blocking is manual via the dashboard.

Run this BEFORE the attacker starts Bettercap, so discovery captures
a clean baseline.

Usage (Linux, needs root for ARP table changes, raw sockets, and
firewall rules):
    sudo python3 main.py
Then open http://127.0.0.1:8000 in a browser on the victim machine.
"""

import threading
import time
from enum import Enum, auto

import platform
import uvicorn

from discovery.gateway import discover_trusted_gateway
from discovery.dns_config import get_trusted_dns_servers
from detectors.arp_detector import ArpDetector, ArpConflictEvent
from detectors.dns_detector import DnsDetector, DnsConflictEvent
from protection.arp_protection import ArpProtector
from protection.dns_protection import flush_dns_cache
from engine.state import shared_state
from engine.attackers import attacker_tracker
from engine.policy import AUTO_BLOCK_ENABLED, AUTO_BLOCK_AFTER_SECONDS
from engine.runtime import set_protector
from engine import db
from engine import whitelist
from utils.hostname import resolve_hostname
from utils.block import block_attacker
from utils.network_scan import start_periodic_scan
from api.server import app


class DefenderState(Enum):
    DISCOVERING = auto()
    PROTECTED = auto()
    ATTACK_DETECTED = auto()
    RESTORING = auto()


class Defender:
    def __init__(self):
        self.state = DefenderState.DISCOVERING
        self.baseline = None
        self._hostname_resolved = set()

    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {msg}")

    def set_state(self, new_state: DefenderState):
        self.state = new_state
        shared_state.set_status(new_state.name)
        self.log(f"STATE -> {new_state.name}")

    def _resolve_hostname_background(self, mac, ip):
        hostname = resolve_hostname(ip)
        attacker_tracker.set_hostname(mac, hostname)
        self._hostname_resolved.add(mac)

    def _check_auto_block(self, mac: str):
        if not AUTO_BLOCK_ENABLED:
            return
        if attacker_tracker.is_blocked(mac):
            return

        duration = attacker_tracker.get_duration_seconds(mac)
        if duration < AUTO_BLOCK_AFTER_SECONDS:
            return

        ip = attacker_tracker.get_ip(mac)
        self.log(f"AUTO-BLOCK triggered: {mac} has attacked continuously "
                  f"for {duration:.0f}s (threshold {AUTO_BLOCK_AFTER_SECONDS}s)")
        result = block_attacker(mac, ip)
        if result.success:
            attacker_tracker.mark_blocked(mac, result.methods_applied, blocked_by="auto")
            self.protector.force_restore()
            shared_state.set_status("PROTECTED")
            self.log(f"AUTO-BLOCKED {mac} via {', '.join(result.methods_applied)} - endpoint PROTECTED")
        else:
            self.log(f"AUTO-BLOCK FAILED for {mac}: {result.detail}")

    # ---- ARP spoofing handling ----

    def on_arp_conflict(self, event: ArpConflictEvent):
        attacker_ip = self.detector.mac_to_ip.get(event.observed_mac, "resolving...")

        if attacker_tracker.is_blocked(event.observed_mac):
            self.protector.force_restore()
            attacker_tracker.record_blocked_retry(
                mac=event.observed_mac, ip=attacker_ip,
                action="Blocked attacker retried ARP spoof - gateway re-verified",
                success=True, attack_type="ARP Spoofing",
            )
            shared_state.set_status("PROTECTED")
            return

        self.set_state(DefenderState.ATTACK_DETECTED)
        self.log("!! ARP SPOOFING DETECTED !!")
        self.log(f"   Gateway IP:     {event.gateway_ip}")
        self.log(f"   Trusted MAC:    {event.trusted_mac}")
        self.log(f"   Attacker MAC:   {event.observed_mac}")
        self.log(f"   Attacker IP:    {attacker_ip}")

        self.set_state(DefenderState.RESTORING)
        success, results = self.protector.restore(event)

        for r in results:
            status = "OK" if r.success else "FAILED"
            self.log(f"   [{status}] {r.action} {r.detail}")

        attacker_tracker.record_attack(
            mac=event.observed_mac, ip=attacker_ip,
            gateway_ip=event.gateway_ip, trusted_mac=event.trusted_mac,
            action="Gateway mapping restored" if success else "Restore attempt failed",
            success=success, attack_type="ARP Spoofing",
        )

        self._maybe_resolve_hostname(event.observed_mac, attacker_ip)
        self._check_auto_block(event.observed_mac)

        if success:
            self.log("Gateway mapping restored. Endpoint protected.")
            shared_state.set_status("ATTACK_BLOCKED")
            self.set_state(DefenderState.PROTECTED)
        else:
            self.log("WARNING: restoration incomplete, remaining vulnerable.")

    # ---- DNS spoofing handling ----

    def on_dns_conflict(self, event: DnsConflictEvent):
        mac = event.attacker_mac
        trusted_list = ", ".join(event.trusted_dns_servers)

        if attacker_tracker.is_blocked(mac):
            result = flush_dns_cache()
            attacker_tracker.record_blocked_retry(
                mac=mac, ip=event.attacker_ip,
                action=f"Blocked attacker retried DNS spoof (queried: {event.queried_domain}) - cache flushed",
                success=result.success, attack_type="DNS Spoofing",
            )
            return

        self.log("!! DNS SPOOFING DETECTED !!")
        self.log(f"   Fake DNS reply from: {event.attacker_ip}")
        self.log(f"   Queried domain:      {event.queried_domain}")
        self.log(f"   Trusted resolver(s): {trusted_list}")
        self.log(f"   Attacker MAC:        {mac}")

        result = flush_dns_cache()
        self.log(f"   [{'OK' if result.success else 'FAILED'}] "
                  f"DNS cache flush {result.method or result.detail}")

        action = (
            f"DNS cache flushed (queried: {event.queried_domain})" if result.success
            else f"Cache flush failed: {result.detail} (queried: {event.queried_domain})"
        )
        attacker_tracker.record_attack(
            mac=mac, ip=event.attacker_ip,
            gateway_ip=event.queried_domain, trusted_mac=trusted_list,
            action=action, success=result.success, attack_type="DNS Spoofing",
        )

        self._maybe_resolve_hostname(mac, event.attacker_ip)
        self._check_auto_block(mac)

    def _maybe_resolve_hostname(self, mac, ip):
        if ip not in ("resolving...", "unknown") and mac not in self._hostname_resolved:
            threading.Thread(
                target=self._resolve_hostname_background,
                args=(mac, ip), daemon=True,
            ).start()

    def start_dashboard_server(self):
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

    def run(self):
        db.init_db()
        whitelist.load()
        self.log(f"Operating system: {platform.system()} {platform.release()}")
        self.log("Database initialized, whitelist loaded.")

        self.log("Starting network discovery on clean baseline...")
        self.baseline = discover_trusted_gateway()
        self.log(f"Trusted gateway: {self.baseline.gateway_ip} -> {self.baseline.gateway_mac}")
        self.log(f"Interface: {self.baseline.interface}  Local IP: {self.baseline.local_ip}")
        shared_state.update_baseline(self.baseline)

        trusted_dns = get_trusted_dns_servers()
        self.log(f"Trusted DNS servers: {trusted_dns if trusted_dns else 'none found - DNS module inactive'}")

        self.protector = ArpProtector(self.baseline)
        self.detector = ArpDetector(self.baseline, on_conflict=self.on_arp_conflict)
        self.dns_detector = DnsDetector(self.baseline.interface, trusted_dns, on_conflict=self.on_dns_conflict)
        set_protector(self.protector)

        self.set_state(DefenderState.PROTECTED)

        def _on_scan_result(mac, ip):
            if ip != self.baseline.gateway_ip:
                self.detector.mac_to_ip[mac] = ip

        start_periodic_scan(
            interface=self.baseline.interface,
            local_ip=self.baseline.local_ip,
            on_result=_on_scan_result,
        )

        dashboard_thread = threading.Thread(target=self.start_dashboard_server, daemon=True)
        dashboard_thread.start()
        self.log("Dashboard running at http://127.0.0.1:8000")
        self.log(f"Auto-block: {'ENABLED' if AUTO_BLOCK_ENABLED else 'DISABLED'} "
                  f"(threshold: {AUTO_BLOCK_AFTER_SECONDS}s)")

        threading.Thread(target=self.detector.start, daemon=True).start()
        threading.Thread(target=self.dns_detector.start, daemon=True).start()

        self.log("Monitoring ARP and DNS traffic. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("Shutting down.")


if __name__ == "__main__":
    Defender().run()
