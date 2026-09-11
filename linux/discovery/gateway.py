"""
gateway.py
----------
Discovers the local network's real gateway (router) IP and MAC address,
and stores it as the TRUSTED baseline that the ARP defender will protect.

Must be run before any attack starts, so the trust baseline is captured
from a clean (unpoisoned) network state.
"""

import subprocess
import re
import sys
from dataclasses import dataclass
from scapy.all import ARP, Ether, srp, conf


@dataclass
class TrustedGateway:
    interface: str
    local_ip: str
    gateway_ip: str
    gateway_mac: str


def get_default_interface_and_gateway_ip():
    """
    Cross-platform-ish: works on Linux via `ip route`.
    On Windows you'd swap this for `ipconfig` / `route print` parsing,
    or just hardcode interface/gateway in config for the demo.
    """
    if sys.platform.startswith("linux"):
        out = subprocess.check_output(["ip", "route"], text=True)
        # example line: "default via 192.168.1.1 dev wlan0 ..."
        match = re.search(r"default via (\S+) dev (\S+)", out)
        if not match:
            raise RuntimeError("Could not determine default gateway/interface. "
                                "Check `ip route` output manually.")
        gateway_ip, iface = match.group(1), match.group(2)
        return iface, gateway_ip
    else:
        raise NotImplementedError(
            "Auto-discovery only implemented for Linux in this prototype. "
            "On Windows, set interface/gateway_ip manually in config/defender.yaml."
        )


def get_local_ip(interface: str):
    if sys.platform.startswith("linux"):
        out = subprocess.check_output(["ip", "-4", "addr", "show", interface], text=True)
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if not match:
            raise RuntimeError(f"Could not determine local IP for interface {interface}")
        return match.group(1)
    raise NotImplementedError("Linux only in this prototype.")


def resolve_mac_via_arp_request(gateway_ip: str, interface: str, timeout: float = 3.0) -> str:
    """
    Sends a legitimate ARP request ("who has <gateway_ip>?") and waits for
    a reply. This is how a clean host normally discovers its gateway's MAC.

    NOTE: this is only trustworthy if run BEFORE an attacker starts spoofing.
    That's why discovery must happen at defender startup, on a clean network.
    """
    conf.verb = 0
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    answered, _ = srp(request, timeout=timeout, iface=interface)

    if not answered:
        raise RuntimeError(f"No ARP reply from gateway {gateway_ip}. "
                            f"Is the network up? Is {interface} correct?")

    # Take the first reply's source MAC as the trusted gateway MAC.
    _, reply = answered[0]
    return reply.src


def discover_trusted_gateway(interface: str = None, gateway_ip: str = None) -> TrustedGateway:
    """
    Main entry point. If interface/gateway_ip are not given, attempts
    auto-discovery (Linux only for now). Returns a TrustedGateway baseline
    that the rest of the system will treat as ground truth.
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
