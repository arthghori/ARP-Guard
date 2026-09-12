# ARP Guard — System Architecture

> Host-based active defense agent against ARP spoofing, DNS spoofing,
> and MITM attacks. Cross-platform (Linux + Windows).

---

## 1. Overview

ARP Guard is a **host-based endpoint security agent**. It runs on the
machine it protects (the "victim" endpoint), continuously verifies the
endpoint's own view of the network against a trusted baseline, and
actively restores that trusted state when it detects tampering.

It is **not** a network-wide IDS and **not** a counterattack tool. It
only observes and corrects the local machine's own network state.

### Design goals
- Detect attacks in seconds, not minutes
- Actively restore the correct network state, not just alert
- Never trust the thing being attacked as the source of truth
- Never send offensive traffic toward an attacker
- Run identically on Linux and Windows from one codebase
- Modular: each attack type is its own pluggable module

### Non-goals
- Network-wide monitoring of other hosts
- Offensive/counter-attack capability
- Production-grade authentication on the local API (out of scope for
  an academic prototype — see [Section 10](#10-known-limitations))

---

## 2. High-Level Architecture

```
                        ┌───────────────────────────┐
                        │        ATTACKER            │
                        │   (Bettercap, lab-only)    │
                        └─────────────┬───────────────┘
                                      │
                    ARP spoof │ DNS spoof
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────┐
│                  VICTIM ENDPOINT (Linux or Windows)               │
│                                                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    ARP Guard Agent                          │  │
│  │                                                             │  │
│  │  ┌────────────┐  ┌───────────┐  ┌────────────┐  ┌────────┐│  │
│  │  │ Discovery   │─▶│ Detectors  │─▶│ Protection  │─▶│Attacker││  │
│  │  │ (ARP + DNS  │  │ (ARP + DNS │  │ (restore +  │  │Tracker ││  │
│  │  │  baseline)  │  │ + whitelist│  │  block)     │  │(per-MAC││  │
│  │  │             │  │  check)    │  │             │  │  both  ││  │
│  │  └────────────┘  └───────────┘  └────────────┘  │ attacks)││  │
│  │        │                                          └────────┘│  │
│  │        ▼                                              │      │  │
│  │  ┌─────────────────────────────────────────────────────┐   │  │
│  │  │   Shared State + SQLite (persistent audit log)        │◀──┘  │
│  │  └────────────────────────┬────────────────────────────┘      │
│  │                            │                                    │
│  │  ┌─────────────────────────▼────────────────────────────┐     │
│  │  │   Local API (FastAPI, 127.0.0.1)                       │     │
│  │  └────────────────────────┬────────────────────────────┘     │
│  └───────────────────────────┼────────────────────────────────┘  │
│                                │                                    │
│           ┌────────────────────▼────────────────────────┐         │
│           │  Dashboard: Live / Blocklist / Network Map /  │        │
│           │  Whitelist / Logs / Overview (6 pages)         │        │
│           └────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

The agent and dashboard run as **one process**: `main.py` starts
discovery, spins up the ARP and DNS detectors in background threads,
and serves the dashboard from the same process via FastAPI. The
dashboard is a convenience layer for visibility — the agent keeps
protecting the machine even with no browser open.

---

## 3. Trust Model

The core defensive principle of this project:

> **Never derive "trusted" state from the same data source you're
> defending.**

If the agent learned the gateway's MAC address only from the live ARP
cache, an attacker who poisons that cache *becomes* the trust source —
which defeats the entire purpose. The same applies to DNS: trusted
resolvers are read from the system's own configuration
(`/etc/resolv.conf` on Linux, `ipconfig /all` on Windows) at clean
startup, not inferred from traffic that could already be spoofed.

```
STARTUP (clean network assumed)
        │
        ▼
Actively query gateway via ARP request + read configured DNS servers
        │
        ▼
Store as TRUSTED BASELINE (in-memory, not re-derived from later traffic)
        │
        ▼
All future ARP/DNS traffic is checked AGAINST this baseline,
never used to silently replace it
```

This is why the agent **must start before the attack begins** — the
baseline can only be trusted if it was captured on a clean network.

**Whitelist exception:** devices on the trusted-device whitelist are
checked *before* this comparison — a whitelisted device is never
flagged, even if its traffic would otherwise look like spoofing. This
covers legitimate cases (router replacement, a second access point)
that the trust model alone can't distinguish from an attack.

---

## 4. Module Breakdown

| Module | Responsibility |
|---|---|
| `discovery/gateway.py` | Trusted gateway IP↔MAC baseline (cross-platform via Scapy's own routing table) |
| `discovery/dns_config.py` | Trusted DNS resolver baseline (Linux: resolv.conf, Windows: ipconfig) |
| `detectors/arp_detector.py` | Sniff ARP traffic, flag mismatches vs. baseline, check whitelist, passively learn MAC→IP |
| `detectors/dns_detector.py` | Sniff DNS responses, flag replies from untrusted sources, check whitelist |
| `protection/arp_protection.py` | Restore local ARP table (cross-platform: `ip neigh` / `arp -s`) + broadcast correction |
| `protection/dns_protection.py` | Flush local DNS cache (cross-platform: `resolvectl` / `ipconfig /flushdns`) |
| `engine/attackers.py` | Per-attacker tracking (by MAC) across BOTH attack types; throttled blocked-retry logging |
| `engine/policy.py` | Auto-block threshold configuration |
| `engine/whitelist.py` | Trusted-device checks, backed by SQLite |
| `engine/db.py` | SQLite persistence — every event survives an agent restart |
| `engine/runtime.py` | Shared reference so the API layer can trigger an immediate ARP restore |
| `engine/state.py` | Overall agent status, network baseline, OS info |
| `utils/block.py` | Attacker blocking (Linux: arptables/iptables, Windows: Windows Firewall) |
| `utils/hostname.py` | Best-effort hostname resolution (Linux: nmblookup, Windows: nbtstat) |
| `utils/network_scan.py` | Active subnet scan for fast attacker IP attribution |
| `utils/windows_iface.py` | Resolves friendly adapter name for display on Windows |
| `api/server.py` | FastAPI routes for all 6 dashboard pages + REST endpoints |
| `dashboard/*.html` | Live status, block management, network map, whitelist, logs, overview |

---

## 5. Data Flow: Attack → Detect → Protect → Log

```
 Attacker sends forged ARP/DNS packet
             │
             ▼
 Detector intercepts (ARP or DNS thread)
             │
             ▼
 Is source MAC whitelisted?  ──YES──▶ ignore, keep monitoring
             │ NO
             ▼
 Compare against trusted baseline
             │
     mismatch found? ──NO──▶ discard, keep monitoring
             │ YES
             ▼
 Is this attacker already blocked?
      ┌──────┴──────┐
      │ YES          │ NO
      ▼              ▼
 Silently restore   State → ATTACK_DETECTED (dashboard + sound alert)
 + log throttled            │
 "rejected retry"           ▼
 (no state cycling)   State → RESTORING
                             │
                             ▼
                     Restore action:
                     ARP → fix local ARP table
                     DNS → flush DNS cache
                             │
                             ▼
                     Record in AttackerTracker (grouped by MAC)
                     + write-through to SQLite
                             │
                             ▼
                     Auto-block policy check (duration >= threshold?)
                      ┌──────┴──────┐
                      │ YES          │ NO
                      ▼              ▼
               Auto-block via   State → PROTECTED
               utils/block.py   (repeats on next attack)
                      │
                      ▼
               State → PROTECTED (immediate force_restore)
```

This loop repeats every time the attacker re-poisons — which Bettercap
typically does every few seconds — making a live demo naturally show
several detect/restore cycles, then a block.

---

## 6. State Machine

```
        ┌───────────────┐
        │  DISCOVERING   │  (startup only, clean-network assumption)
        └───────┬────────┘
                │
                ▼
        ┌───────────────┐
   ┌───▶│   PROTECTED    │◀────────────────┐
   │    └───────┬────────┘                  │
   │            │ mismatch detected          │
   │            ▼                            │
   │    ┌────────────────┐                   │
   │    │ ATTACK_DETECTED │                  │
   │    └───────┬─────────┘                  │
   │            ▼                            │
   │    ┌────────────────┐                   │
   │    │   RESTORING     │                  │
   │    └───────┬─────────┘                  │
   │            │                            │
   │      success?                           │
   │       ┌────┴────┐                       │
   │       │  YES     │───────────────────────┘
   │       ▼
   │  ATTACK_BLOCKED
   │
   └── NO → stays degraded, logs failure, next detection cycle retries
```

**Once an attacker is blocked**, further packets from them do not
re-enter this cycle — they're silently corrected and logged separately
(see Section 5), so the dashboard reads a calm PROTECTED state instead
of flickering between states.

---

## 7. Cross-Platform Layer

Every OS-facing operation has a Linux and Windows implementation
behind a single shared interface — the rest of the codebase never
branches on platform itself:

| Operation | Linux | Windows |
|---|---|---|
| Gateway/interface discovery | Scapy's own routing table (`conf.route`) — same code both platforms | same |
| ARP table restore | `ip neigh` | `arp -d` / `arp -s` |
| DNS baseline | `/etc/resolv.conf` | `ipconfig /all` parsing |
| DNS cache flush | `resolvectl` / `systemd-resolve` | `ipconfig /flushdns` |
| Attacker blocking | `arptables` (MAC layer) + `iptables` (IP layer) | Windows Firewall via `netsh` (**IP layer only** — no MAC-layer equivalent exists on Windows) |
| Hostname resolution | `nmblookup` | `nbtstat` (built-in) |
| Interface display name | N/A (already friendly) | Resolved via `scapy.arch.windows.get_windows_if_list()` |

The Windows blocking limitation is a genuine platform constraint, not
an implementation gap: Windows Firewall has no concept of filtering by
MAC address, so blocking there only takes effect once the attacker's
IP is known (usually within seconds via the active subnet scan).

---

## 8. Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Packet capture / crafting | Python + Scapy | Cross-platform, readable, standard for ARP/DNS-level work |
| Agent runtime | Python 3, `threading` | Sniffing, dashboard server, and periodic scans all run concurrently |
| Persistence | SQLite (`engine/db.py`) | Zero-setup, single-file, survives restarts |
| Local API | FastAPI + Uvicorn | Minimal boilerplate, async-friendly |
| Dashboard | Plain HTML/CSS/JS, Space Grotesk + JetBrains Mono | No build step, works offline, distinct SOC-console aesthetic |
| Windows installer | Tkinter + PyInstaller | Self-contained GUI wizard, compiles to a single .exe |
| Data exchange | Polling `fetch()` every 1.5–2s | Simple, reliable for a demo; avoids WebSocket complexity |

---

## 9. Repository Structure

```
ARP-Guard/
├── README.md / ARCHITECTURE.md / ROADMAP.md / RUNBOOK.md
├── arpguard-linux/agent/       ← run on Linux
├── arpguard-windows/agent/     ← run on Windows (identical codebase)
└── arpguard-installer/         ← builds ARPGuard.exe (Windows one-click installer)
```

Each `agent/` folder contains:

```
agent/
├── main.py
├── requirements.txt
├── discovery/      (gateway.py, dns_config.py)
├── detectors/      (arp_detector.py, dns_detector.py)
├── protection/     (arp_protection.py, dns_protection.py)
├── engine/         (state, attackers, policy, runtime, db, whitelist)
├── api/            (server.py)
├── utils/          (block, hostname, network_scan, windows_iface)
└── dashboard/      (6 HTML pages)
```

---

## 10. Known Limitations

- **No authentication on the local API** — acceptable for a
  `127.0.0.1`-only demo, not acceptable if exposed beyond localhost
- **Attacker IP attribution is heuristic** — the forged packet only
  reveals the attacker's MAC; IP comes from passive observation and
  active subnet scanning, which takes a few seconds
- **Windows blocking is IP-only** (no MAC-layer equivalent to
  `arptables` exists on Windows)
- **Deauthentication detection requires monitor-mode-capable Wi-Fi
  hardware** not available in this build — architecturally scoped but
  not implemented
- **Single-host protection only** — defends the endpoint it runs on,
  not the whole network
- **DNS validation checks origin, not content** — a full DNSSEC-style
  answer-integrity check is out of scope for this prototype

---

## 11. Roadmap

See [ROADMAP.md](./ROADMAP.md) for the full phase-by-phase history and
what's planned next.
