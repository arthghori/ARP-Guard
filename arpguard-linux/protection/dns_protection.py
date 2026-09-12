"""
dns_protection.py
------------------
When DNS spoofing is detected, the practical local defensive action is
to flush the victim's own DNS cache so any poisoned entry is dropped
and future lookups go fresh to the trusted resolver. Unlike ARP, there
is no "undo" for a single spoofed UDP response - the packet already
arrived - so cache-flush plus blocking the attacker's traffic (reusing
the same ARP Guard block mechanism, since it works at the MAC/IP
level regardless of protocol) is the correct combined response.
"""

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class DnsProtectionResult:
    success: bool
    method: str = ""
    detail: str = ""


def flush_dns_cache() -> DnsProtectionResult:
    if shutil.which("resolvectl"):
        result = subprocess.run(["resolvectl", "flush-caches"], capture_output=True, text=True)
        if result.returncode == 0:
            return DnsProtectionResult(success=True, method="resolvectl flush-caches")
        return DnsProtectionResult(success=False, detail=result.stderr.strip())

    if shutil.which("systemd-resolve"):
        result = subprocess.run(["systemd-resolve", "--flush-caches"], capture_output=True, text=True)
        if result.returncode == 0:
            return DnsProtectionResult(success=True, method="systemd-resolve --flush-caches")
        return DnsProtectionResult(success=False, detail=result.stderr.strip())

    return DnsProtectionResult(
        success=False,
        detail="No supported DNS cache flush tool found (resolvectl/systemd-resolve) - "
               "this system may use a different resolver stack.",
    )
