# ARP Guard Run Guide (Victim + Attacker Lab)

This guide walks through running the full demo across two machines in
a lab you control. Do this only on your own VMs/hardware, never on a
network you don't have explicit permission to test.

---

## 0. Before you start network setup

You need two machines that can see each other's traffic:

- **Victim** runs ARP Guard (Linux or Windows)
- **Attacker** runs Bettercap

**VirtualBox/VMware:** put both VMs on the same **Host-only** or
**Bridged** network adapter, plus make sure both can reach a router/
gateway (a real one, or VirtualBox's built-in gateway on Host-only
networks).

Check connectivity first:

```bash
# on victim
ping <attacker_ip>
ping <gateway_ip>

# on attacker
ping <victim_ip>
ping <gateway_ip>
```

---

## 1. Victim machine setup

### Linux

```bash
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard/arpguard-linux/agent
sudo apt install -y python3 python3-pip python3-venv arptables samba-common-bin
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo $(which python3) main.py
```

Full details: [arpguard-linux/README.md](./arpguard-linux/README.md)

### Windows one-click installer

Download **[ARPGuard.exe](https://github.com/arthghori/ARP-Guard/releases/latest/download/ARPGuard.exe)**,
double-click it, follow the wizard.

### Windows manual

```powershell
git clone https://github.com/arthghori/ARP-Guard.git
cd ARP-Guard\arpguard-windows\agent
pip install -r requirements.txt
python main.py
```

Full details: [arpguard-windows/README.md](./arpguard-windows/README.md)

**This must be started BEFORE the attack begins** it captures a
clean ARP and DNS baseline at startup. If it starts after the network
is already compromised, it will trust the wrong values.

---

## 2. Open the dashboard

On the victim machine, open a browser to:

```
http://127.0.0.1:8000
```

Six pages are available: `/` (live), `/blocklist`, `/network`,
`/whitelist`, `/logs`, `/overview`.

---

## 3. Attacker machine setup

### Install Bettercap

```bash
sudo apt update
sudo apt install -y bettercap
```

### Run ARP spoofing

```bash
sudo bettercap -iface <your_interface>
```

Inside the Bettercap shell:

```
set arp.spoof.targets <victim_ip>
arp.spoof on
```

### Run DNS spoofing (needs ARP spoofing running first)

```
set dns.spoof.domains example.com
set dns.spoof.address <attacker_ip>
dns.spoof on
```

Trigger it from the victim:

```bash
nslookup example.com
```

---

## 4. Order of operations for the demo

```
1. VICTIM:   start the agent (wait for "STATE -> PROTECTED")
2. VICTIM:   open http://127.0.0.1:8000 in browser
3. ATTACKER: sudo bettercap -iface <interface>
4. ATTACKER: set arp.spoof.targets <victim_ip>
5. ATTACKER: arp.spoof on
6. VICTIM:   watch the dashboard - ATTACK DETECTED -> RESTORING ->
             PROTECTED, with a sound alert and a new attacker row
7. Optional: enable dns.spoof too, trigger nslookup on the victim -
             watch it appear in the SAME attacker row (merged tracking)
8. VICTIM:   click "Block" on the attacker row, or wait 90s for
             auto-block - confirm the counter freezes and further
             attempts show as "rejected retries", not fresh attacks
```

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'discovery'` | Wrong folder, or files flattened out of subfolders | Confirm `discovery/`, `detectors/`, etc. sit directly next to `main.py` |
| Dashboard shows "Agent unreachable" | Agent not running, or port 8000 in use | Check the agent's console/terminal for errors |
| No attack detected | Victim and attacker not on same broadcast domain | Recheck VM network mode |
| `Permission denied` (Linux) | Not run with `sudo` | `sudo $(which python3) main.py` |
| `Access denied` (Windows) | Terminal not Administrator | Re-open as Administrator |
| Attacker IP stuck on "resolving..." | Passive learning hasn't seen their real IP yet | Wait a few seconds for the periodic subnet scan |
| Attempt counter frozen after block | **Expected** | Real `attack_count` freezes on block by design; a separate "rejected retries" counter tracks anything after that see ARCHITECTURE.md |
| Windows: block button says IP not resolved | Windows can only block by IP, not MAC | Wait for the subnet scan, then retry |
| Windows: dashboard unreachable after installer runs | Agent crashed on startup | Check the separate agent console window for the actual error (commonly Npcap or Administrator-related) |

---

## 6. Resetting between demo runs

**Linux:**
```bash
./reset_demo.sh
```

**Windows:**
```powershell
.\reset_demo.ps1
```

Both clear firewall/ARP-table rules left over from a previous run so
the next demo starts clean.
