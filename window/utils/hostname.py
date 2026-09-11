"""
hostname.py
-----------
Best-effort attempt to resolve a human-readable device name for an
attacker's IP address.

There is NO guaranteed way to do this on a local network without
cooperation from the attacker's own machine or a local DNS server that
tracks device names. Tries, in order:

  1. Reverse DNS (only works if your router/DNS server keeps PTR
     records for local devices - most home/lab networks don't)
  2. NetBIOS name lookup - `nbtstat -A` on Windows (built in, no
     install needed), `nmblookup -A` on Linux (needs samba-common-bin)

If neither responds, the hostname is reported as "Unknown" - that is
an expected, honest outcome on many networks, not a bug.
"""

import shutil
import socket
import subprocess
import sys


def resolve_hostname(ip: str, timeout: float = 1.5) -> str:
    if not ip or ip in ("resolving...", "unknown"):
        return "Unknown"

    # Method 1: reverse DNS (cross-platform)
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            return name
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        pass

    # Method 2: NetBIOS name
    if sys.platform.startswith("win"):
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=timeout + 2,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if "<00>" in line and "UNIQUE" in line:
                    return line.split()[0]
        except Exception:
            pass
    elif shutil.which("nmblookup"):
        try:
            result = subprocess.run(
                ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=timeout + 1,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and "<00>" in line and "GROUP" not in line:
                    return line.split()[0]
        except Exception:
            pass

    return "Unknown"
