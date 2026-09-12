"""
arp_detector.py
----------------
Passively sniffs ARP packets and checks whether any ARP reply claims to be
the trusted gateway IP but comes from an unexpected MAC address.

This is DETECTION only. It does not modify anything - it just raises
an event when it sees a mismatch. arp_protection.py handles the response.
"""

from dataclasses import dataclass
from datetime import datetime
from scapy.all import sniff, ARP

from discovery.gateway import TrustedGateway


@dataclass
class ArpConflictEvent:
    timestamp: datetime
    gateway_ip: str
    trusted_mac: str
    observed_mac: str


class ArpDetector:
    def __init__(self, baseline: TrustedGateway, on_conflict):
        """
        baseline: the TrustedGateway established at clean startup
        on_conflict: callback function, called with an ArpConflictEvent
                     whenever a mismatch is detected
        """
        self.baseline = baseline
        self.on_conflict = on_conflict

        # Passively learned MAC -> real IP mappings, built from ALL normal
        # ARP traffic (not just the forged gateway claims). This lets us
        # later look up an attacker's real IP once we've seen it announce
        # itself elsewhere on the network - a forged gateway-claim packet
        # alone never reveals the attacker's own IP.
        self.mac_to_ip = {}

    def _handle_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        # Learn MAC->IP from any ARP traffic, but never trust a claim
        # about the gateway's own IP as someone's "real" IP - that's
        # exactly the field an attacker forges.
        if arp.psrc and arp.psrc != self.baseline.gateway_ip:
            self.mac_to_ip[arp.hwsrc.lower()] = arp.psrc

        # op=1 (who-has, sometimes used unsolicited by spoofing tools) or
        # op=2 (is-at, the classic forged reply) - both can carry a
        # forged claim about the gateway's IP.
        if arp.op not in (1, 2):
            return

        # We only care about claims regarding OUR trusted gateway's IP
        if arp.psrc != self.baseline.gateway_ip:
            return

        observed_mac = arp.hwsrc.lower()
        trusted_mac = self.baseline.gateway_mac.lower()

        if observed_mac != trusted_mac:
            event = ArpConflictEvent(
                timestamp=datetime.now(),
                gateway_ip=self.baseline.gateway_ip,
                trusted_mac=trusted_mac,
                observed_mac=observed_mac,
            )
            self.on_conflict(event)

    def start(self):
        """
        Blocking call - runs the sniff loop. In main.py this should be
        run in its own thread so it doesn't block the rest of the agent.
        """
        sniff(
            iface=self.baseline.interface,
            filter="arp",
            prn=self._handle_packet,
            store=False,
        )
