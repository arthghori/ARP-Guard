# ARP Guard Linux Setup Guide

This guide covers installing and running ARP Guard on Linux (tested on Kali Linux, works on any Debian/Ubuntu-based distro).

---

## Requirements

- Python 3.8 or newer
- Root/sudo access (needed for raw packet capture and firewall rules)
- A network interface connected to the same network as the attacker machine

---

## 1. Clone the repository

```bash
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard/arpguard-linux/agent
```

If you don't have `git` installed:

```bash
sudo apt update
sudo apt install -y git
```

**Alternative download without git:**

```bash
wget https://github.com/arthghori/ARP-Guard/archive/refs/heads/main.zip
unzip main.zip
cd ARP-Guard-main/arpguard-linux/agent
```

---

## 2. Install system dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv arptables samba-common-bin iproute2
```

What each package is for:

| Package | Used for |
|---|---|
| `python3`, `python3-pip` | Running the agent |
| `python3-venv` | Isolated Python environment (recommended) |
| `arptables` | ARP-layer attacker blocking (most direct fix for ARP spoofing) |
| `samba-common-bin` | Provides `nmblookup`, used for best-effort hostname resolution |
| `iproute2` | Provides `ip`, used for interface/route inspection |

---

## 3. Set up the Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

This installs `scapy`, `fastapi`, and `uvicorn` into the virtual environment.

---

## 4. Run the agent

**Must be started BEFORE the attacker begins spoofing** it captures a clean network baseline at startup, which is the foundation of how it detects tampering later.

```bash
sudo $(which python3) main.py
```

Using `sudo $(which python3)` (instead of plain `sudo python3`) makes sure the *virtual environment's* Python is used even with elevated privileges a common trip-up otherwise.

You should see output like:

```
[10:31:02] Operating system: Linux 6.x
[10:31:02] Database initialized, whitelist loaded.
[10:31:03] Starting network discovery on clean baseline...
[10:31:03] Trusted gateway: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
[10:31:03] Interface: eth0  Local IP: 192.168.1.50
[10:31:03] Dashboard running at http://127.0.0.1:8000
[10:31:03] Auto-block: ENABLED (threshold: 90s)
[10:31:03] Monitoring ARP and DNS traffic. Ctrl+C to stop.
```

---

## 5. Open the dashboard

On the same machine, open a browser to:

```
http://127.0.0.1:8000
```

---

## 6. Resetting between demo runs

Blocking rules (`arptables`/`iptables`) persist in the kernel even after you stop the agent. Clear them before each fresh run:

```bash
./reset_demo.sh
```

Or manually:

```bash
sudo arptables -F
sudo iptables -F INPUT
sudo ip neigh flush all
```

---

## Full command reference (copy-paste block)

```bash
# Clone and enter the project
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard/arpguard-linux/agent

# One-time system + Python setup
sudo apt update
sudo apt install -y python3 python3-pip python3-venv arptables samba-common-bin iproute2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Every time you run the demo
sudo $(which python3) main.py

# Between demo runs
./reset_demo.sh
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'discovery'` | You're not running from inside `arpguard-linux/agent`, or files got flattened out of their subfolders check with `ls -la` that `discovery/`, `detectors/`, etc. are actual folders sitting next to `main.py` |
| `No default gateway found` | Not connected to a network connect first |
| `No ARP reply from gateway` | Check the interface name, or the network hasn't finished coming up yet |
| `Permission denied` on startup | Forgot `sudo` |
| Attacker IP stuck on "resolving..." | Wait a few seconds the periodic subnet scan resolves it automatically |
| Attempt counter still climbing after block | Expected packet capture sees traffic before the firewall drops it. The real `attack_count` freezes on block; only a separate "rejected retries" counter climbs. See [ARCHITECTURE.md](../ARCHITECTURE.md) |