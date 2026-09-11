"""
server.py
---------
Local API + multi-page dashboard server for ARP Guard.

Pages served (from dashboard/*.html):
  GET /            -> live dashboard (status + attacker list + drill-down)
  GET /blocklist   -> dedicated block/unblock management page
  GET /logs        -> full aggregated event log across all attackers
  GET /overview    -> project overview page
  GET /network     -> network map visualization
  GET /whitelist   -> trusted device whitelist management

API endpoints:
  GET    /api/status                    -> overall agent status + baseline
  GET    /api/policy                    -> auto-block policy settings
  GET    /api/attackers                 -> one summary row per attacker
  GET    /api/attackers/{id}/events     -> full event history for one attacker
  GET    /api/logs                      -> aggregated events, all attackers
  POST   /api/attackers/{id}/block      -> block that attacker locally
  POST   /api/attackers/{id}/unblock    -> remove the block
  GET    /api/whitelist                 -> list trusted devices
  POST   /api/whitelist                 -> add a trusted device
  DELETE /api/whitelist/{id}            -> remove a trusted device
  GET    /api/export/report             -> downloadable session report (.txt)

Attacker MAC addresses contain colons, which aren't URL-safe as a path
segment on all clients, so pages send them with colons replaced by
dashes (AA:BB:CC -> AA-BB-CC) and we convert back here.

Runs on 127.0.0.1 only by default - keep it that way for the demo. Do
not change host to 0.0.0.0 without adding authentication first.
"""

import os
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from engine.state import shared_state
from engine.attackers import attacker_tracker
from engine.policy import AUTO_BLOCK_ENABLED, AUTO_BLOCK_AFTER_SECONDS
from engine.runtime import get_protector
from engine import whitelist
from utils.block import block_attacker, unblock_attacker

app = FastAPI(title="ARP Guard API")

PAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboard")


class WhitelistEntry(BaseModel):
    mac: str
    label: str = ""


def _serve_page(filename: str) -> str:
    path = os.path.join(PAGE_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _mac_from_id(attacker_id: str) -> str:
    return attacker_id.replace("-", ":")


# ---- Pages ----

@app.get("/", response_class=HTMLResponse)
def dashboard_page():
    return _serve_page("index.html")


@app.get("/blocklist", response_class=HTMLResponse)
def blocklist_page():
    return _serve_page("blocklist.html")


@app.get("/logs", response_class=HTMLResponse)
def logs_page():
    return _serve_page("logs.html")


@app.get("/overview", response_class=HTMLResponse)
def overview_page():
    return _serve_page("overview.html")


@app.get("/network", response_class=HTMLResponse)
def network_page():
    return _serve_page("network.html")


@app.get("/whitelist", response_class=HTMLResponse)
def whitelist_page():
    return _serve_page("whitelist.html")


# ---- Core API ----

@app.get("/api/status")
def status():
    return shared_state.snapshot()


@app.get("/api/policy")
def policy():
    return {
        "auto_block_enabled": AUTO_BLOCK_ENABLED,
        "auto_block_after_seconds": AUTO_BLOCK_AFTER_SECONDS,
    }


@app.get("/api/attackers")
def list_attackers():
    return attacker_tracker.list_summaries()


@app.get("/api/attackers/{attacker_id}/events")
def attacker_events(attacker_id: str):
    mac = _mac_from_id(attacker_id)
    events = attacker_tracker.get_events(mac)
    if events is None:
        raise HTTPException(status_code=404, detail="Unknown attacker")
    return events


@app.get("/api/logs")
def all_logs():
    return attacker_tracker.get_all_events()


@app.post("/api/attackers/{attacker_id}/block")
def block(attacker_id: str):
    mac = _mac_from_id(attacker_id)
    if not attacker_tracker.exists(mac):
        raise HTTPException(status_code=404, detail="Unknown attacker")

    if attacker_tracker.is_blocked(mac):
        return {"success": True, "methods_applied": [], "detail": "Already blocked"}

    ip = attacker_tracker.get_ip(mac)
    result = block_attacker(mac, ip)
    if result.success:
        attacker_tracker.mark_blocked(mac, result.methods_applied, blocked_by="manual")
        protector = get_protector()
        if protector:
            protector.force_restore()
        shared_state.set_status("PROTECTED")
    return {
        "success": result.success,
        "methods_applied": result.methods_applied,
        "detail": result.detail,
    }


@app.post("/api/attackers/{attacker_id}/unblock")
def unblock(attacker_id: str):
    mac = _mac_from_id(attacker_id)
    if not attacker_tracker.exists(mac):
        raise HTTPException(status_code=404, detail="Unknown attacker")
    ip = attacker_tracker.get_ip(mac)
    result = unblock_attacker(mac, ip)
    if result.success:
        attacker_tracker.mark_unblocked(mac)
    return {
        "success": result.success,
        "methods_applied": result.methods_applied,
        "detail": result.detail,
    }


# ---- Whitelist ----

@app.get("/api/whitelist")
def get_whitelist():
    return whitelist.list_all()


@app.post("/api/whitelist")
def post_whitelist(entry: WhitelistEntry):
    whitelist.add(entry.mac, entry.label)
    return {"success": True}


@app.delete("/api/whitelist/{whitelist_id}")
def delete_whitelist(whitelist_id: str):
    mac = _mac_from_id(whitelist_id)
    whitelist.remove(mac)
    return {"success": True}


# ---- Export ----

@app.get("/api/export/report")
def export_report():
    lines = []
    lines.append("ARP GUARD - SESSION REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Auto-block enabled:   {AUTO_BLOCK_ENABLED}")
    lines.append(f"Auto-block threshold: {AUTO_BLOCK_AFTER_SECONDS} seconds")
    lines.append("")
    lines.append("ATTACKERS")
    lines.append("-" * 60)

    attackers = attacker_tracker.list_summaries()
    if not attackers:
        lines.append("(none detected this session)")
    for a in attackers:
        lines.append(f"IP: {a['ip']:<16} MAC: {a['mac']:<18} Hostname: {a['hostname']}")
        lines.append(f"  Attempts: {a['attack_count']}   "
                      f"Blocked: {a['blocked']} ({a['blocked_by'] or '-'})")
        lines.append(f"  First seen: {a['first_seen']}   Last seen: {a['last_seen']}")
        lines.append("")

    lines.append("FULL EVENT LOG")
    lines.append("-" * 60)
    events = attacker_tracker.get_all_events()
    if not events:
        lines.append("(no events this session)")
    for e in events:
        lines.append(
            f"[{e['timestamp']}] {e['attack_type']} | "
            f"{e['attacker_ip']} ({e['attacker_mac']}) | "
            f"{e['action']} | {'OK' if e['success'] else 'FAILED'}"
        )

    content = "\n".join(lines)
    filename = f"arp_guard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
