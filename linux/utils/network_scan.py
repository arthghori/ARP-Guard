"""
network_scan.py
----------------
Periodically sends normal ARP "who-has" requests to every host in the
local /24 subnet, purely to build a reliable MAC -> IP map on our own
machine. This is standard, harmless local network discovery - the
same kind of traffic any OS generates routinely - not an attack.

Why this exists: a forged ARP packet claiming to be the gateway only
ever reveals the ATTACKER's MAC, never their real IP (that's the
nature of the spoof). Passively waiting to see the attacker's real IP
in unrelated traffic can take a while or never happen in a short demo.
Actively scanning our own subnet resolves it in seconds instead.
"""

import ipaddress
import threading
import time
from scapy.all import ARP, Ether, srp, conf


def _scan_subnet_once(interface: str, local_ip: str, on_result, subnet_prefix: int = 24):
    try:
        network = ipaddress.ip_network(f"{local_ip}/{subnet_prefix}", strict=False)
    except ValueError:
        return

    conf.verb = 0
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    try:
        answered, _ = srp(request, timeout=2, iface=interface, retry=0)
    except Exception:
        return

    for _, reply in answered:
        on_result(reply.hwsrc.lower(), reply.psrc)


def start_periodic_scan(interface: str, local_ip: str, on_result, interval_seconds: int = 15):
    """
    Runs the scan on a loop in a background daemon thread. Call once
    at startup - keeps running for the life of the process.
    """
    def loop():
        while True:
            _scan_subnet_once(interface, local_ip, on_result)
            time.sleep(interval_seconds)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return thread
