"""
dns_config.py
-------------
Reads the machine's currently configured DNS resolver(s) from
/etc/resolv.conf, to use as the trusted baseline for the DNS spoofing
detector. Same principle as gateway.py: read this once, at clean
startup, before any attack can happen.
"""

import re


def get_trusted_dns_servers(resolv_path: str = "/etc/resolv.conf"):
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
