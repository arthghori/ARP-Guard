"""
db.py
-----
SQLite persistence layer. Every attack/block event is also written
here, so the audit trail survives an agent restart - unlike the
in-memory AttackerTracker, which is deliberately reset on every fresh
run so demos start clean.

One file (arp_guard.db, created next to main.py), Python's built-in
sqlite3 - no extra dependency, no server to run.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "arp_guard.db"

_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = _connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                attacker_mac TEXT,
                attacker_ip TEXT,
                attacker_hostname TEXT,
                context_a TEXT,
                context_b TEXT,
                action TEXT,
                success INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                mac TEXT PRIMARY KEY,
                label TEXT,
                added_at TEXT
            )
        """)
        conn.commit()
        conn.close()


def log_event(attack_type, attacker_mac, attacker_ip, attacker_hostname,
              context_a, context_b, action, success):
    with _lock:
        conn = _connect()
        conn.execute(
            """INSERT INTO events
               (timestamp, attack_type, attacker_mac, attacker_ip, attacker_hostname,
                context_a, context_b, action, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                attack_type, attacker_mac, attacker_ip, attacker_hostname,
                context_a, context_b, action, 1 if success else 0,
            ),
        )
        conn.commit()
        conn.close()


def get_all_events(limit=1000):
    with _lock:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def add_whitelist(mac, label=""):
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (mac, label, added_at) VALUES (?, ?, ?)",
            (mac.lower(), label, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        conn.close()


def remove_whitelist(mac):
    with _lock:
        conn = _connect()
        conn.execute("DELETE FROM whitelist WHERE mac = ?", (mac.lower(),))
        conn.commit()
        conn.close()


def list_whitelist():
    with _lock:
        conn = _connect()
        rows = conn.execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
