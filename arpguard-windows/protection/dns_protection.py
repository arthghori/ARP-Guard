"""
dns_protection.py
------------------
When DNS spoofing is detected, the practical local defensive action is
to flush the victim's own DNS cache so any poisoned entry is dropped
and future lookups go fresh to the trusted resolver. Unlike ARP, there
is no "undo" for a single spoofed UDP response - the packet already
arrived - so cache-flush plus blocking the attacker's traffic (reusing
the same ARP Guard block mechanism) is the correct combined response.

Linux: resolvectl (systemd-resolved) or the older systemd-resolve.
Windows: ipconfig /flushdns (built into every version of Windows).
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class DnsProtectionResult:
    success: bool
    method: str = ""
    detail: str = ""


def flush_dns_cache() -> DnsProtectionResult:
    if sys.platform.startswith("win"):
        result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True)
        if result.returncode == 0:
            return DnsProtectionResult(success=True, method="ipconfig /flushdns")
        return DnsProtectionResult(
            success=False,
            detail=result.stderr.strip() or result.stdout.strip() or "ipconfig /flushdns failed",
        )

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
