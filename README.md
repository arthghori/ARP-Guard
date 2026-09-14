# ARP Guard

**ARP Guard is a host-based endpoint defense agent for detecting and responding to ARP spoofing, DNS spoofing, and local man-in-the-middle activity.** It monitors the machine it runs on, compares network traffic with a trusted startup baseline, automatically restores compromised state, and provides a live dashboard for investigation and response.

This project was built as a working Innovation Day proof of concept. It is designed to demonstrate active defensive behavior rather than passive alerting: detection, restoration, tracking, blocking, and audit logging happen on the protected endpoint.

> **Defensive scope:** ARP Guard protects one endpoint at a time. It does not monitor an entire network and never performs counter-attacks.

## Table of contents

- [Why it exists](#why-it-exists)
- [How it works](#how-it-works)
- [Features](#features)
- [Quick start](#quick-start)
- [Dashboard](#dashboard)
- [Repository layout](#repository-layout)
- [Architecture](#architecture)
- [Lab demonstration](#lab-demonstration)
- [Technology](#technology)
- [Limitations](#limitations)
- [Documentation](#documentation)
- [Authorized use](#authorized-use)

## Why it exists

ARP has no built-in authentication. A device on the same local network can send forged ARP messages claiming to be the gateway and redirect traffic through itself. DNS spoofing creates a similar problem by sending a victim false answers from an untrusted source. Together, these techniques are common foundations for local MITM attacks.

Most monitoring tools stop at raising an alert. ARP Guard is intended to close the response loop:

1. Capture a clean network baseline before an attack starts.
2. Detect changes that conflict with that baseline.
3. Restore the endpoint's correct ARP or DNS state automatically.
4. Track the activity and expose it in the dashboard.
5. Block persistent attackers manually or after the automatic threshold.

## How it works

At startup, ARP Guard discovers the local interface, endpoint address, default gateway, gateway MAC address, and configured DNS resolvers. These values form a trusted baseline and are not silently replaced by later observations.

During monitoring:

- The ARP detector watches for unexpected claims about the trusted gateway.
- The DNS detector checks responses against trusted resolver information.
- The protection layer restores the local network state and flushes the DNS cache when required.
- The attacker tracker groups ARP and DNS activity by attacker MAC address.
- The SQLite database records events, blocks, whitelist entries, and audit history.
- The local FastAPI server publishes current state to the dashboard.

The agent must start **before** the attack begins. If the baseline is captured after the network has already been compromised, the compromised values may be treated as trusted.

## Features

| Capability | Description |
|---|---|
| ARP spoofing detection | Compares gateway announcements with the trusted gateway MAC captured at startup. |
| Automatic ARP restoration | Repairs the local ARP mapping and broadcasts a correction when an unexpected mapping is detected. |
| DNS spoofing detection | Flags DNS responses from sources that are not part of the trusted resolver baseline. |
| Automatic DNS recovery | Flushes the local DNS cache after a suspicious DNS event. |
| Attacker tracking | Merges ARP and DNS activity from the same attacker into one record. |
| Manual blocking | Blocks an attacker from the dashboard. |
| Automatic blocking | Blocks an attacker after sustained activity, using a default threshold of 90 seconds. |
| Trusted-device whitelist | Prevents known legitimate devices from being flagged. |
| Live dashboard | Provides status, attacker activity, network context, and response history. |
| Persistent audit log | Stores events in SQLite so the history survives an agent restart. |
| Cross-platform operation | Uses the appropriate Linux or Windows networking and firewall commands. |
| Windows installer | Provides a one-click setup flow for Python, Npcap, dependencies, and launch. |

## Quick start

Choose the instructions for the operating system running on the protected endpoint. Both platform directories contain the same application design and dashboard; only operating-system integrations differ.

### Linux

Requirements:

- Python 3.8 or newer
- `sudo` or root access for packet capture and firewall rules
- A connected network interface

```bash
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard/arpguard-linux/agent
sudo apt update
sudo apt install -y python3 python3-pip python3-venv arptables samba-common-bin iproute2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo $(which python3) main.py
```

Open `http://127.0.0.1:8000` after the console reports that the dashboard is running. For reset commands and troubleshooting, see the [Linux setup guide](./arpguard-linux/README.md).

### Windows installer

The recommended Windows path is the latest packaged installer:

[Download ARPGuard.exe](https://github.com/arthghori/ARP-Guard/releases/latest/download/ARPGuard.exe)

Run it as administrator. On the first run, the setup wizard can install Python and Npcap, download the project, install dependencies, and launch the agent. Later runs use the saved installation and open the dashboard directly.

### Windows manual setup

Install Python and Npcap first. Npcap should be installed in WinPcap-compatible mode. Then open an Administrator PowerShell:

```powershell
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard\arpguard-windows\agent
python -m pip install -r requirements.txt
python main.py
```

Open `http://127.0.0.1:8000`. The complete [Windows setup guide](./arpguard-windows/README.md) includes Npcap, installer, reset, and troubleshooting details.

## Dashboard

The dashboard is served locally by the same process as the agent. Protection continues even when no browser window is open.

| Route | Purpose |
|---|---|
| `/` | Live protection state, attacker feed, and activity ticker |
| `/blocklist` | Manual blocks and automatic-block progress |
| `/network` | Gateway, endpoint, and attacker network map |
| `/whitelist` | Add or remove trusted devices |
| `/logs` | Searchable event history and session export |
| `/overview` | Project objective, concepts, architecture, and limitations |

## Repository layout

```text
ARP-Guard/
├── README.md
├── ARCHITECTURE.md              System design and trust model
├── ROADMAP.md                   Completed work and planned work
├── RUNBOOK.md                   Victim/attacker lab demonstration
├── arpguard-linux/
│   ├── README.md                Linux installation guide
│   ├── reset_demo.sh            Linux demo reset script
│   └── agent/                   Cross-platform agent source
├── arpguard-windows/
│   ├── README.md                Windows installation guide
│   ├── reset_demo.ps1           Windows demo reset script
│   ├── arpguard-installer/      Source for the Windows installer
│   └── agent/                   Cross-platform agent source
└── ...
```

The Linux and Windows agent directories intentionally mirror one another so both platforms can be demonstrated independently. Platform-specific behavior is selected at runtime, including ARP table updates, firewall blocking, DNS cache flushing, hostname lookup, and interface discovery.

Within each agent, the main areas are:

| Directory | Responsibility |
|---|---|
| `discovery/` | Gateway, interface, and DNS baseline discovery |
| `detectors/` | ARP and DNS packet inspection |
| `protection/` | ARP restoration and DNS cache recovery |
| `engine/` | State, policy, attacker tracking, whitelist, and SQLite persistence |
| `api/` | FastAPI routes and local API server |
| `utils/` | Blocking, hostname resolution, network scanning, and platform helpers |
| `dashboard/` | Six HTML dashboard pages |

## Architecture

The application runs as one Python process. `main.py` starts discovery, launches the ARP and DNS monitoring work, and serves the dashboard through FastAPI.

```text
Clean startup
    |
    v
Trusted gateway + DNS baseline
    |
    v
ARP/DNS detectors ---> whitelist check ---> baseline comparison
                                             |
                         +-------------------+-------------------+
                         |                                       |
                         v                                       v
                 Restore network state                    Track and log event
                         |                                       |
                         +-------------------+-------------------+
                                             |
                                             v
                                   Dashboard and policy
```

The central design principle is: **do not derive trusted state from the data source being defended.** The gateway baseline is actively discovered at clean startup, and configured DNS resolvers are read from the operating system rather than learned from suspicious traffic.

For the full module breakdown and data flow, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## Lab demonstration

Use two machines on a lab network that you own or are explicitly authorized to test:

- **Victim:** runs ARP Guard on Linux or Windows.
- **Attacker:** runs a controlled test tool such as Bettercap.

The high-level demonstration is:

1. Start ARP Guard and wait for the protected state.
2. Open the local dashboard.
3. Start a controlled ARP spoofing test from the attacker machine.
4. Observe detection, restoration, attacker tracking, and audit logging.
5. Optionally test DNS spoofing and verify that activity is merged into the same attacker record.
6. Use the dashboard block action or wait for the 90-second automatic threshold.
7. Reset firewall and ARP rules before the next run.

The [runbook](./RUNBOOK.md) contains the full lab topology, Bettercap commands, expected state transitions, and reset procedures.

## Technology

- Python 3
- Scapy for packet capture and network inspection
- FastAPI and Uvicorn for the local API and dashboard server
- SQLite for persistent state and audit logging
- HTML, CSS, and JavaScript for the dashboard
- Linux: `arptables`, `iptables`, `ip neigh`, `resolvectl`
- Windows: Windows Firewall, `arp`, `ipconfig /flushdns`, and Npcap
- PyInstaller for the Windows installer executable

## Limitations

- **Endpoint scope:** protects only the machine where the agent is running.
- **Baseline trust:** startup must occur on a clean network; the agent cannot independently prove that the initial network state is uncompromised.
- **IP attribution:** a forged packet primarily exposes an attacker MAC. The agent learns the corresponding IP through passive observation and subnet scanning, so attribution can take time or remain incomplete.
- **Hostname resolution:** reverse DNS and NetBIOS resolution are best effort and may report `Unknown`.
- **Windows blocking:** Windows Firewall blocks by IP, not MAC. The attacker IP must be resolved before a Windows block can take effect. Linux can block at the MAC layer with `arptables`.
- **Wi-Fi deauthentication:** detection is planned but not implemented because it requires monitor-mode-capable hardware.
- **Local API security:** the prototype API is bound to localhost and does not provide production-grade authentication.

## Documentation

- [Architecture](./ARCHITECTURE.md): trust model, modules, and data flow
- [Linux setup](./arpguard-linux/README.md): dependencies, launch, and reset
- [Windows setup](./arpguard-windows/README.md): installer, manual setup, and troubleshooting
- [Lab runbook](./RUNBOOK.md): controlled victim/attacker demonstration
- [Roadmap](./ROADMAP.md): project goals, completed phases, and future work

## Authorized use

Use ARP Guard only on systems and networks you own or have explicit permission to test. It is intended for defensive lab work and endpoint protection. It performs no offensive actions and does not attempt to retaliate against an attacker.