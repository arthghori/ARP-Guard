"""
arp_protection.py
------------------
When arp_detector.py reports a conflict (gateway IP claimed by an
unexpected MAC), this module restores the victim's OWN ARP table entry
for the gateway back to the trusted mapping.

Important: this only fixes the LOCAL machine's ARP cache. It does not
touch, attack, or send anything to the attacker's machine. That's what
keeps this a defensive tool rather than a counterattack tool.
"""

import subprocess
import sys
import time
from dataclasses import dataclass
from scapy.all import ARP, Ether, sendp, conf

from discovery.gateway import TrustedGateway
from detectors.arp_detector import ArpConflictEvent


@dataclass
class ProtectionResult:
    success: bool
    action: str
    detail: str = ""


class ArpProtector:
    def __init__(self, baseline: TrustedGateway, on_result=None):
        self.baseline = baseline
        self.on_result = on_result  # optional callback(ProtectionResult)

    def _update_local_arp_table(self) -> ProtectionResult:
        """
        Forces the OS's own ARP table entry for the gateway back to the
        trusted mapping. This is the actual "restore" step.
        """
        try:
            if sys.platform.startswith("linux"):
                # Remove the poisoned entry, then set the correct static one.
                subprocess.run(
                    ["ip", "neigh", "del", self.baseline.gateway_ip,
                     "dev", self.baseline.interface],
                    check=False,  # ok if it didn't exist
                )
                subprocess.run(
                    ["ip", "neigh", "replace", self.baseline.gateway_ip,
                     "lladdr", self.baseline.gateway_mac,
                     "dev", self.baseline.interface, "nud", "permanent"],
                    check=True,
                )
                return ProtectionResult(
                    success=True,
                    action="restore_local_arp_table",
                    detail=f"{self.baseline.gateway_ip} -> {self.baseline.gateway_mac}",
                )
            else:
                return ProtectionResult(
                    success=False,
                    action="restore_local_arp_table",
                    detail="Not implemented for this OS in the prototype.",
                )
        except subprocess.CalledProcessError as e:
            return ProtectionResult(success=False, action="restore_local_arp_table", detail=str(e))

    def _broadcast_correction(self) -> ProtectionResult:
        """
        Sends a gratuitous ARP reply on the local machine's own interface,
        re-announcing the TRUE gateway mapping to itself. This helps
        overwrite the poisoned entry faster than waiting for the OS's
        normal ARP refresh timing.

        This only ever announces the legitimate mapping we ourselves
        verified at startup - never a forged one - and only affects our
        own machine's traffic path back to the real gateway.
        """
        conf.verb = 0
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=self.baseline.gateway_ip,
            hwsrc=self.baseline.gateway_mac,
            pdst=self.baseline.local_ip,
        )
        try:
            sendp(packet, iface=self.baseline.interface, count=3, inter=0.2)
            return ProtectionResult(success=True, action="broadcast_correction")
        except Exception as e:
            return ProtectionResult(success=False, action="broadcast_correction", detail=str(e))

    def restore(self, event: ArpConflictEvent):
        """
        Runs the full restore sequence in response to a detected ARP
        conflict event. Idempotent - safe to call repeatedly if the
        attacker keeps re-poisoning.
        """
        success, results = self.force_restore()

        if self.on_result:
            self.on_result(event, results, success)

        return success, results

    def force_restore(self):
        """
        Same restore actions as restore(), but callable directly
        without an ArpConflictEvent - used when we already know an
        attacker is blocked and just want to immediately re-verify/fix
        the gateway mapping (e.g. right after a manual block click, or
        when a blocked attacker's packet slips through before the
        firewall rule fully takes effect).
        """
        results = [
            self._update_local_arp_table(),
            self._broadcast_correction(),
        ]
        return all(r.success for r in results), results
