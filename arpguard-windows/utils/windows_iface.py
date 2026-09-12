"""
windows_iface.py
-----------------
Windows-only helper: Scapy identifies interfaces internally by their
Npcap device path (e.g. \\Device\\NPF_{GUID}) - that's what's actually
needed for packet capture, but it's meaningless to look at on a
dashboard. This resolves the human-friendly adapter name (e.g. "Wi-Fi",
"Ethernet") for DISPLAY ONLY - the raw Scapy identifier is still what
gets used for actual sniffing/sending everywhere else in the codebase.
"""

import sys


def get_friendly_name(scapy_iface: str) -> str:
    if not sys.platform.startswith("win"):
        return scapy_iface

    try:
        from scapy.arch.windows import get_windows_if_list
        for iface_info in get_windows_if_list():
            guid = iface_info.get("guid", "")
            if guid and guid in scapy_iface:
                return iface_info.get("name") or scapy_iface
    except Exception:
        pass

    return scapy_iface
