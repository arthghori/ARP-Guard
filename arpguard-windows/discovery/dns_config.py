"""
dns_config.py
-------------
Reads the machine's currently configured DNS resolver(s) to use as the
trusted baseline for the DNS spoofing detector. Same principle as
gateway.py: read this once, at clean startup, before any attack can
happen.

Linux: parses /etc/resolv.conf.
Windows: parses `ipconfig /all` output for "DNS Servers" entries.
"""

import re
import subprocess
import sys


def get_trusted_dns_servers(resolv_path: str = "/etc/resolv.conf"):
    if sys.platform.startswith("win"):
        return _get_trusted_dns_servers_windows()

    servers = []
    try:
        with open(resolv_path, "r") as f:
            for line in f:
                match = re.match(r"^\s*nameserver\s+([\d.]+)", line)
                if match:
                    servers.append(match.group(1))
    except FileNotFoundError:
        pass
    return servers


def _get_trusted_dns_servers_windows():
    """
    Simplification: if multiple network adapters each have their own
    DNS servers configured, this returns the union of all of them
    rather than only the active adapter's - a reasonable approximation
    for a prototype where typically only one adapter is connected.
    """
    servers = []
    try:
        result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
        output = result.stdout
    except Exception:
        return servers

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    in_dns_block = False

    for line in output.splitlines():
        stripped = line.strip()

        if "DNS Servers" in line:
            in_dns_block = True
            # First DNS server usually sits on the same line, after the colon
            after_colon = line.split(":", 1)[1].strip() if ":" in line else ""
            if ip_pattern.match(after_colon):
                servers.append(after_colon)
            continue

        if in_dns_block:
            if ip_pattern.match(stripped):
                servers.append(stripped)  # continuation line: another DNS server
            else:
                in_dns_block = False  # block ended (new label reached)

    seen = set()
    unique_servers = []
    for s in servers:
        if s not in seen:
            seen.add(s)
            unique_servers.append(s)
    return unique_servers
