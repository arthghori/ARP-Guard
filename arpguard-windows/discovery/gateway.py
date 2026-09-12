"""
gateway.py
----------
Discovers the local network's real gateway (router) IP and MAC address,
and stores it as the TRUSTED baseline that the ARP defender will protect.

Cross-platform (Linux + Windows) via Scapy's own routing table reader,
instead of shelling out to OS-specific commands like `ip route` (Linux
only). Scapy already needs raw packet access on both platforms (Npcap
on Windows, raw sockets on Linux) and already reads the OS routing
table internally to know which interface to use - we just reuse that
instead of re-implementing OS-specific parsing.

Must be run before any attack starts, so the trust baseline is captured
from a clean (unpoisoned) network state.
"""

from dataclasses import dataclass
from scapy.all import ARP, Ether, srp, conf, get_if_addr


@dataclass
class TrustedGateway:
    interface: str
    local_ip: str
    gateway_ip: str
    gateway_mac: str


def get_default_interface_and_gateway_ip():
    """
    conf.route.route("0.0.0.0") asks Scapy's routing table "what
    interface and gateway would I use to reach the internet" - the
    same call works on Linux and Windows (Scapy parses each OS's
    native routing table under the hood).
    """
    try:
        iface, _, gateway_ip = conf.route.route("0.0.0.0")
    except Exception as e:
        raise RuntimeError(
            "Could not determine default gateway/interface via Scapy's "
            "routing table. On Windows, make sure Npcap is installed "
            f"and this is running as Administrator. Original error: {e}"
        )

    if not gateway_ip or gateway_ip == "0.0.0.0":
        raise RuntimeError("No default gateway found - is the network connected?")

    return iface, gateway_ip


def get_local_ip(interface: str):
    try:
        ip = get_if_addr(interface)
    except Exception as e:
        raise RuntimeError(f"Could not determine local IP for interface {interface}: {e}")
    if not ip or ip == "0.0.0.0":
        raise RuntimeError(f"Interface {interface} has no IPv4 address assigned.")
    return ip


def resolve_mac_via_arp_request(gateway_ip: str, interface: str, timeout: float = 3.0) -> str:
    """
    Sends a legitimate ARP request ("who has <gateway_ip>?") and waits
    for a reply - how a clean host normally discovers its gateway's
    MAC. Only trustworthy if run BEFORE an attacker starts spoofing.
    """
    conf.verb = 0
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    answered, _ = srp(request, timeout=timeout, iface=interface)

    if not answered:
        raise RuntimeError(
            f"No ARP reply from gateway {gateway_ip}. Is the network up? "
            f"Is {interface} correct? On Windows, make sure you're running "
            f"as Administrator and Npcap is installed."
        )

    _, reply = answered[0]
    return reply.src


def discover_trusted_gateway(interface: str = None, gateway_ip: str = None) -> TrustedGateway:
    """
    Main entry point. If interface/gateway_ip are not given, attempts
    auto-discovery (works on both Linux and Windows). Returns a
    TrustedGateway baseline the rest of the system treats as ground truth.
    """
    if interface is None or gateway_ip is None:
        interface, gateway_ip = get_default_interface_and_gateway_ip()

    local_ip = get_local_ip(interface)
    gateway_mac = resolve_mac_via_arp_request(gateway_ip, interface)

    return TrustedGateway(
        interface=interface,
        local_ip=local_ip,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
    )


if __name__ == "__main__":
    baseline = discover_trusted_gateway()
    print("Trusted gateway baseline established:")
    print(f"  Interface:   {baseline.interface}")
    print(f"  Local IP:    {baseline.local_ip}")
    print(f"  Gateway IP:  {baseline.gateway_ip}")
    print(f"  Gateway MAC: {baseline.gateway_mac}")
