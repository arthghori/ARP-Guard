"""
whitelist.py
------------
Trusted-device whitelist. MAC addresses on this list are never flagged
as attackers, even if their traffic looks like ARP/DNS spoofing - this
covers legitimate cases like a router replacement, a new access point,
or a known multi-homed device on the lab network.

Backed by SQLite (engine/db.py) for persistence across restarts,
cached in memory as a set for fast lookups on every sniffed packet.
"""

import threading
from engine import db

_lock = threading.Lock()
_cache = set()


def load():
    """Call once at startup to populate the in-memory cache from disk."""
    with _lock:
        _cache.clear()
        for row in db.list_whitelist():
            _cache.add(row["mac"].lower())


def is_whitelisted(mac: str) -> bool:
    with _lock:
        return mac.lower() in _cache


def add(mac: str, label: str = ""):
    db.add_whitelist(mac, label)
    with _lock:
        _cache.add(mac.lower())


def remove(mac: str):
    db.remove_whitelist(mac)
    with _lock:
        _cache.discard(mac.lower())


def list_all():
    return db.list_whitelist()
