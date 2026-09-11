"""
dns_detector.py
---------------
Passively sniffs DNS response traffic and flags responses that come
from an unexpected source - i.e. NOT one of the trusted resolvers
recorded at startup. Same discover -> trust -> detect pattern used
for ARP, applied to DNS.

Scope note: this catches the classic case of an attacker on the LAN
injecting forged DNS responses (e.g. Bettercap's dns.spoof module)
impersonating the real resolver. It does not validate the actual
answer content (that would need DNSSEC-style checking) - only origin,
which is enough to catch spoofed source IPs.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List
from scapy.all import sniff, DNS, IP, Ether

from engine.whitelist import is_whitelisted


@dataclass
class DnsConflictEvent:
    timestamp: datetime
    attacker_ip: str
    attacker_mac: str
    queried_domain: str
    trusted_dns_servers: List[str]


class DnsDetector:
    def __init__(self, interface: str, trusted_dns_servers: List[str], on_conflict):
        self.interface = interface
        self.trusted_dns_servers = set(trusted_dns_servers)
        self.on_conflict = on_conflict

    def _handle_packet(self, packet):
        if not (packet.haslayer(DNS) and packet.haslayer(IP)):
            return

        dns = packet[DNS]
        if dns.qr != 1:  # qr=1 means this is a DNS RESPONSE, not a query
            return

        if not self.trusted_dns_servers:
            return  # no baseline known (resolv.conf unreadable) - nothing to compare

        src_ip = packet[IP].src
        if src_ip in self.trusted_dns_servers:
            return  # response from a trusted resolver, fine

        attacker_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else "unknown"
        if is_whitelisted(attacker_mac):
            return

        queried_domain = "unknown"
        try:
            if dns.qd is not None:
                queried_domain = dns.qd.qname.decode(errors="ignore")
        except Exception:
            pass

        event = DnsConflictEvent(
            timestamp=datetime.now(),
            attacker_ip=src_ip,
            attacker_mac=attacker_mac,
            queried_domain=queried_domain,
            trusted_dns_servers=list(self.trusted_dns_servers),
        )
        self.on_conflict(event)

    def start(self):
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._handle_packet,
            store=False,
        )
