"""
block.py
--------
Best-effort LOCAL firewall blocking of a specific attacker.

This only blocks traffic FROM the attacker INTO this machine - it
never sends anything toward the attacker's machine, and never affects
any other device on the network.

Linux: arptables (ARP layer, blocks by MAC - most direct fix) +
       iptables (blocks by MAC and, once known, by IP).

Windows: Windows Firewall (netsh advfirewall) has NO equivalent to
       arptables - it cannot filter by MAC address, only by IP. This
       is a genuine platform limitation, not a bug: on Windows,
       blocking only takes effect once the attacker's real IP has
       been resolved (see utils/network_scan.py). The ARP table
       restoration in protection/arp_protection.py still runs
       regardless and still protects the endpoint even before a
       Windows block is possible.
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class BlockResult:
    success: bool
    methods_applied: List[str] = field(default_factory=list)
    detail: str = ""


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _rule_name(mac: str) -> str:
    return "ARPGuard_Block_" + mac.replace(":", "")


def block_attacker(mac: str, ip: Optional[str] = None) -> BlockResult:
    if sys.platform.startswith("win"):
        return _block_windows(mac, ip)
    return _block_linux(mac, ip)


def unblock_attacker(mac: str, ip: Optional[str] = None) -> BlockResult:
    if sys.platform.startswith("win"):
        return _unblock_windows(mac, ip)
    return _unblock_linux(mac, ip)


# ---- Linux ----

def _block_linux(mac, ip):
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

    return BlockResult(success=len(methods) > 0, methods_applied=methods, detail="; ".join(errors))


def _unblock_linux(mac, ip):
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

    return BlockResult(success=len(methods) > 0, methods_applied=methods, detail="; ".join(errors))


# ---- Windows ----

def _block_windows(mac, ip):
    if not ip or ip in ("resolving...", "unknown", None):
        return BlockResult(
            success=False, methods_applied=[],
            detail="Attacker IP not resolved yet - Windows Firewall can only block by IP "
                   "(no MAC-layer blocking is possible on Windows). Try again shortly, "
                   "or wait for the periodic subnet scan to resolve it.",
        )

    rule = _rule_name(mac)
    methods = []
    errors = []

    result_in = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={rule}_in", "dir=in", "action=block", f"remoteip={ip}"])
    if result_in.returncode == 0:
        methods.append(f"Windows Firewall (inbound, IP {ip})")
    else:
        errors.append(f"inbound rule failed: {result_in.stderr.strip() or result_in.stdout.strip()}")

    result_out = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule}_out", "dir=out", "action=block", f"remoteip={ip}"])
    if result_out.returncode == 0:
        methods.append(f"Windows Firewall (outbound, IP {ip})")
    else:
        errors.append(f"outbound rule failed: {result_out.stderr.strip() or result_out.stdout.strip()}")

    if not methods:
        errors.append("Make sure this terminal is running as Administrator.")

    return BlockResult(success=len(methods) > 0, methods_applied=methods, detail="; ".join(errors))


def _unblock_windows(mac, ip):
    rule = _rule_name(mac)
    methods = []
    errors = []

    for direction, suffix in [("inbound", "_in"), ("outbound", "_out")]:
        result = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}{suffix}"])
        if result.returncode == 0:
            methods.append(f"Windows Firewall ({direction})")
        else:
            errors.append(f"{direction} delete failed: {result.stderr.strip() or result.stdout.strip()}")

    return BlockResult(success=len(methods) > 0, methods_applied=methods, detail="; ".join(errors))
