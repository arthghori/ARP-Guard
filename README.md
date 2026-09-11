# ARP Guard

**A host-based endpoint defense agent that detects and automatically reverses ARP spoofing and DNS spoofing attacks in real time with a live dashboard, automatic blocking, and full cross-platform support (Linux + Windows).**

Built for Innovation Day as a working proof-of-concept, not just a monitoring dashboard: this agent actively restores the correct network state the moment an attack is detected, with no human action required.

---

## The problem

Every device on a WiFi network uses **ARP** to find its router and ARP has no built-in authentication. Any attacker on the same network can lie about being the router, redirecting a victim's traffic through themselves. This is the foundation of most real-world Man-in-the-Middle (MITM) attacks.

## What ARP Guard does

1. **Detects** ARP and DNS spoofing the moment they happen, by continuously verifying the endpoint's network state against a trusted baseline captured before any attack begins
2. **Automatically restores** the correct network state no human has to click anything
3. **Shows the entire fight live** attacker IP/MAC/hostname, a network map, full audit logs, and manual or automatic blocking
4. **Never attacks back** pure defense only, by design

---

## Repository structure

```
arp-guard/
├── README.md              ← you are here
├── ARCHITECTURE.md        ← system design, trust model, data flow
├── ROADMAP.md             ← project phases and objectives
├── RUNBOOK.md             ← lab setup and demo run order
│
├── linux/                 ← run this on the Linux victim machine
│   ├── README.md          ← Linux install & setup guide
│   └── ...                (identical codebase to window/)
│
└── window/                ← run this on the Windows victim machine
    ├── README.md          ← Windows install & setup guide
    └── ...                (identical codebase to linux/)
```

`linux/` and `window/` contain the **same cross-platform codebase** every file automatically detects which OS it's running on and uses the right system commands (e.g. `arptables` vs Windows Firewall, `ip neigh` vs `arp -s`). They're kept as separate folders here purely so both platforms can be demoed side by side without needing to reconfigure anything between runs.

---

## Quick start

Pick your platform and follow its guide:

- **[Linux setup guide →](./linux/README.md)**
- **[Windows setup guide →](./window/README.md)**

Both guides cover installation, running the agent, opening the dashboard, and resetting between demo runs.

---

## Core features

| Feature | Description |
|---|---|
| ARP spoofing detection & auto-restore | Verifies the gateway's real MAC against a trusted baseline; restores it automatically on mismatch |
| DNS spoofing detection | Flags DNS responses from untrusted sources; flushes the local DNS cache in response |
| Manual + automatic blocking | Block an attacker with one click, or let the agent auto-block after sustained attack (default: 90s) |
| Per-attacker tracking | ARP and DNS activity from the same attacker MAC merge into one row, not scattered logs |
| Trusted device whitelist | Mark known devices as safe so they're never flagged |
| Live dashboard | Status console, network map, full searchable logs, exportable session report |
| SQLite persistence | Every event is logged to disk, surviving an agent restart |
| Cross-platform | One codebase, runs natively on both Linux and Windows |

---

## Dashboard pages

| Page | Purpose |
|---|---|
| `/` | Live status, attacker feed, activity ticker |
| `/blocklist` | Manage blocks, see auto-block progress per attacker |
| `/network` | Visual network map gateway, endpoint, attackers |
| `/whitelist` | Add/remove trusted devices |
| `/logs` | Full searchable event log, export as a report |
| `/overview` | Project pitch objective, concepts, architecture, limitations |

---

## Technology stack

Python 3 · Scapy · FastAPI · Uvicorn · SQLite · arptables/iptables (Linux) · Windows Firewall (Windows) · HTML/CSS/JS

---

## Honest limitations

- Attacker IP attribution is heuristic the forged packet only reveals the attacker's MAC, so IP is learned via passive traffic and active subnet scanning
- Hostname resolution is best-effort (reverse DNS / NetBIOS) and may show "Unknown"
- Windows blocking is IP-based only (no MAC-layer blocking exists on Windows) see the Windows guide for detail
- WiFi deauthentication detection is architecturally planned but not implemented it requires monitor-mode-capable WiFi hardware not available in this build
- Protects the single endpoint it runs on, not the whole network

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design rationale, including the trust-verification model this project is built around.

---

## Authorized use only

This tool is intended for use in a lab environment you own or have explicit permission to test. It performs no offensive actions it only detects and restores state on the machine it runs on.
