# ARP Guard Windows Setup Guide

This guide covers installing and running ARP Guard on Windows 10/11.

---

## Requirements

- Python 3.8 or newer
- [Npcap](https://npcap.com/) (packet capture driver Scapy needs this on Windows)
- Administrator access (needed for raw packet capture and firewall rules)
- A network adapter connected to the same network as the attacker machine

---

## 1. Install Python

1. Download from **https://www.python.org/downloads**
2. Run the installer
3. **Important:** on the first install screen, check the box:
   ☑ **"Add python.exe to PATH"**
4. Click **Install Now**
5. Verify: open Command Prompt and run:
   ```
   python --version
   ```
   Should print a version number, not "not recognized".

---

## 2. Install Npcap

This is what lets Scapy capture packets on Windows the project will not work without it.

1. Download from **https://npcap.com/#download**
2. Right-click the installer → **Run as administrator**
3. During install, confirm this box is checked:
   ☑ **"Install Npcap in WinPcap API-compatible Mode"**
4. Finish the install
5. Verify: open Command Prompt and run:
   ```
   sc query npcap
   ```
   Should show `STATE : RUNNING` or `STOPPED` not "service does not exist".

---

## 3. Set up the project

Open **Command Prompt or PowerShell as Administrator** (right-click → "Run as administrator"), then:

```powershell
cd window
pip install -r requirements.txt
```

This installs `scapy`, `fastapi`, and `uvicorn`.

---

## 4. Run the agent

**Must be started BEFORE the attacker begins spoofing** it captures a clean network baseline at startup.

Still in the Administrator terminal:

```powershell
python main.py
```

You should see output like:

```
[10:31:02] Operating system: Windows 10
[10:31:02] Database initialized, whitelist loaded.
[10:31:03] Starting network discovery on clean baseline...
[10:31:03] Trusted gateway: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
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

Firewall block rules persist even after you stop the agent. Clear them before each fresh run, from an Administrator PowerShell:

```powershell
.\reset_demo.ps1
```

---

## A note on blocking behavior on Windows

Windows Firewall (`netsh advfirewall`) can only block traffic by **IP address**, not by MAC address there's no Windows equivalent to Linux's `arptables`. This means:

- On Windows, blocking only takes full effect once the attacker's real IP has been resolved (usually within a few seconds via the automatic subnet scan)
- On Linux, blocking can act on the MAC address immediately, even before the IP is known

This is a genuine platform limitation, not a bug worth mentioning if asked during a demo or viva.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'discovery'` | Not running from inside the `window/` folder, or files got flattened check with `dir` that `discovery`, `detectors`, etc. are real folders |
| `Could not determine default gateway... make sure Npcap is installed` | Npcap missing, or WinPcap-compatible mode wasn't checked during install reinstall |
| `Access denied` / permission errors | Terminal isn't running as Administrator |
| `No default gateway found` | Not connected to Wi-Fi/Ethernet connect first |
| Block button says "Attacker IP not resolved yet" | Normal wait a few seconds for the subnet scan, then try again |
| `pip` not recognized | Try `python -m pip install -r requirements.txt` instead |

---

## Full command reference

```powershell
# One-time setup (as Administrator)
pip install -r requirements.txt

# Every time you run the demo (as Administrator)
python main.py

# Between demo runs (as Administrator)
.\reset_demo.ps1
```
