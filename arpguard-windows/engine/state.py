"""
state.py
--------
Thread-safe shared state for the agent's overall status, trusted
baseline info, and host OS - so the dashboard can show a Linux/Windows
badge without every page needing its own platform-detection logic.
Per-attacker event logs live in engine/attackers.py instead of here.
"""

import platform
import threading


class SharedState:
    def __init__(self):
        self._lock = threading.Lock()
        self.status = "STARTING"
        self.interface = None
        self.interface_display = None
        self.local_ip = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.os_name = platform.system()      # "Linux" or "Windows"
        self.os_release = platform.release()

    def update_baseline(self, baseline, interface_display=None):
        with self._lock:
            self.interface = baseline.interface
            self.interface_display = interface_display or baseline.interface
            self.local_ip = baseline.local_ip
            self.gateway_ip = baseline.gateway_ip
            self.gateway_mac = baseline.gateway_mac

    def set_status(self, status: str):
        with self._lock:
            self.status = status

    def snapshot(self):
        with self._lock:
            return {
                "status": self.status,
                "interface": self.interface,
                "interface_display": self.interface_display,
                "local_ip": self.local_ip,
                "gateway_ip": self.gateway_ip,
                "gateway_mac": self.gateway_mac,
                "os_name": self.os_name,
                "os_release": self.os_release,
            }


shared_state = SharedState()
