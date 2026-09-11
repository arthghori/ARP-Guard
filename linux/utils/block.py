"""
block.py
--------
Best-effort LOCAL firewall blocking of a specific attacker, identified
by MAC address (and IP once known).

Important: this only blocks traffic FROM the attacker INTO this
machine. It is a local, defensive block - it never sends anything
toward the attacker's machine, and it never affects any other device
on the network.

Two layers are used:
  1. arptables - drops the attacker's ARP packets at the ARP layer
     specifically. This is the most direct way to stop ARP spoofing
     at the source, since it rejects the forged packets before they
     can even be considered.
  2. iptables  - drops the attacker's general IP traffic as a second
     layer, using both their MAC address and (once known) their IP.

Both are best-effort: if a tool isn't installed, that layer is simply
skipped and reported in the result - the other layer still applies.
"""

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BlockResult:
    success: bool
    methods_applied: List[str] = field(default_factory=list)
    detail: str = ""


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def block_attacker(mac: str, ip: Optional[str] = None) -> BlockResult:
    methods = []
    errors = []

    if shutil.which("arptables"):
        result = _run(["arptables", "-A", "INPUT", "--source-mac", mac, "-j", "DROP"])
        if result.returncode == 0:
            methods.append("arptables (ARP layer)")
        else:
            errors.append(f"arptables failed: {result.stderr.strip()}")
    else:
        errors.append("arptables not installed - ARP-layer block skipped "
                       "(install with: sudo apt install arptables)")

    if shutil.which("iptables"):
        result = _run(["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        if result.returncode == 0:
            methods.append("iptables (MAC-based)")
        else:
            errors.append(f"iptables (mac) failed: {result.stderr.strip()}")

        if ip and ip not in ("resolving...", "unknown", None):
            result = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            if result.returncode == 0:
                methods.append(f"iptables (IP {ip})")
            else:
                errors.append(f"iptables (ip) failed: {result.stderr.strip()}")
    else:
        errors.append("iptables not installed")

    return BlockResult(
        success=len(methods) > 0,
        methods_applied=methods,
        detail="; ".join(errors),
    )


def unblock_attacker(mac: str, ip: Optional[str] = None) -> BlockResult:
    methods = []
    errors = []

    if shutil.which("arptables"):
        result = _run(["arptables", "-D", "INPUT", "--source-mac", mac, "-j", "DROP"])
        if result.returncode == 0:
            methods.append("arptables")
        else:
            errors.append(f"arptables: {result.stderr.strip()}")

    if shutil.which("iptables"):
        result = _run(["iptables", "-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        if result.returncode == 0:
            methods.append("iptables (mac)")
        else:
            errors.append(f"iptables (mac): {result.stderr.strip()}")

        if ip and ip not in ("resolving...", "unknown", None):
            result = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            if result.returncode == 0:
                methods.append("iptables (ip)")
            else:
                errors.append(f"iptables (ip): {result.stderr.strip()}")

    return BlockResult(
        success=len(methods) > 0,
        methods_applied=methods,
        detail="; ".join(errors),
    )
