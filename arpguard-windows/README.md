# ARP Guard Windows Setup Guide

Two ways to run ARP Guard on Windows: the one-click installer (recommended), or manual setup if you want full control.

---

## Option A: One-click installer (recommended)

### 1. Download

**[⬇ Download ARPGuard.exe](https://github.com/arthghori/ARP-Guard/releases/latest/download/ARPGuard.exe)**

This link always points to the latest release, regardless of version number.

### 2. Run it

Double-click `ARPGuard.exe`. Windows will show a security prompt (since it's a new, unsigned executable) click **"More info" → "Run anyway"**. It will then ask for Administrator permission (required for packet capture and firewall rules) click **Yes**.

### 3. First run: setup wizard

- Pick an install folder (default: your user folder a subfolder named `ARPGuard` gets created there)
- Leave all checkboxes ticked (Install Python, Install Npcap, Download from GitHub, Install dependencies, Launch when done)
- Click **Start installation**
- Watch the log it downloads and installs everything, then launches the agent and opens the dashboard automatically

### 4. Every run after that

Double-click `ARPGuard.exe` again it remembers the install location and launches straight to the dashboard, no wizard, no clicks needed.

---

## Option B: Manual setup

If you'd rather set it up yourself without the installer:

### 1. Install Python

1. Download from **https://www.python.org/downloads**
2. Run the installer
3. **Important:** check the box **"Add python.exe to PATH"** on the first screen
4. Verify: `python --version` in Command Prompt should show a version number

### 2. Install Npcap

1. Download from **https://npcap.com/#download**
2. Right-click → **Run as administrator**
3. Confirm **"Install Npcap in WinPcap API-compatible Mode"** is checked
4. Verify: `sc query npcap` should show `RUNNING` or `STOPPED`, not "service does not exist"

### 3. Clone the repository

```powershell
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard\arpguard-windows\agent
```

Don't have git? Download the ZIP instead:
```powershell
# Extract Zip, then:
cd ARP-Guard-main\arpguard-windows\agent
```

### 4. Install dependencies

Open Command Prompt or PowerShell **as Administrator**:

```powershell
pip install -r requirements.txt
```

### 5. Run the agent

Still in the Administrator terminal:

```powershell
python main.py
```

### 6. Open the dashboard

```
http://127.0.0.1:8000
```

---

## Resetting between demo runs

Firewall block rules persist even after you stop the agent. From an Administrator PowerShell:

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
| Windows SmartScreen blocks the .exe | Click "More info" → "Run anyway" this is expected for a new, unsigned executable |
| `ModuleNotFoundError: No module named 'discovery'` | Not running from inside `arpguard-windows\agent`, or files got flattened check with `dir` that `discovery`, `detectors`, etc. are real folders next to `main.py` |
| `Could not determine default gateway... make sure Npcap is installed` | Npcap missing, or WinPcap-compatible mode wasn't checked reinstall |
| `Access denied` / permission errors | Terminal (or the .exe) isn't running as Administrator |
| `No default gateway found` | Not connected to Wi-Fi/Ethernet connect first |
| Block button says "Attacker IP not resolved yet" | Normal wait a few seconds for the subnet scan, then try again |
| `pip` not recognized | Try `python -m pip install -r requirements.txt` instead |
| Dashboard shows "site can't be reached" | Check the separate agent console window that opened it shows the real error (commonly Npcap or Administrator-related) |

---

## Full command reference (manual setup)

```powershell
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard\arpguard-windows\agent
pip install -r requirements.txt
python main.py
```

```powershell
# Between demo runs
.\reset_demo.ps1
```