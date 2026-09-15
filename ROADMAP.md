# ARP Guard Project Roadmap

A simple, complete path of the project from start to finish what we
set out to do, what we built, and what comes next.

---

## 1. The Big Goal

> Stop ARP spoofing and DNS spoofing attacks automatically, on the
> victim's own machine, without a human having to do anything on
> both Linux and Windows.

---

## 2. The Problem

- Every device on WiFi uses ARP to find its router; ARP has no
  authentication, so any attacker can lie about being the router
- DNS has the same weakness a forged response from an untrusted
  source is indistinguishable from a real one unless you check its
  origin
- Both are the foundation of most real-world Man-in-the-Middle (MITM)
  attacks

## 3. The Objective

1. **Detect** the attack the moment it happens
2. **Fix it automatically** restore the correct network state
3. **Show it happening live** no black box, full visibility
4. **Block persistent attackers** manually or automatically
5. **Never attack back** pure defense only
6. **Run the same way on Linux and Windows** one codebase, no forks

---

## 4. Roadmap Step by Step

### Step 1 Understand the network (Foundation)
Find the interface, IP, and real gateway. Record the gateway's true
address as a trusted baseline before any attack can happen.

✅ Done

### Step 2 Detect ARP spoofing
Continuously watch ARP traffic; flag the instant the gateway's address
is claimed by an unexpected MAC.

✅ Done

### Step 3 Defend against ARP spoofing
Restore the correct router mapping on the victim's own machine;
broadcast a correction. Never send anything toward the attacker.

✅ Done

### Step 4 Make it visible
Live dashboard showing protection status and every attack event: time,
attacker IP/MAC, action taken, result.

✅ Done

### Step 5 Detect and defend against DNS spoofing
Same discover → trust → detect → restore pattern, applied to DNS: flag
responses from untrusted resolvers, flush the local cache in response.

✅ Done

### Step 6 Group attacks by attacker, not by event
Both ARP and DNS activity from the same attacker MAC merge into one
row no fragmented logs across attack types.

✅ Done

### Step 7 Add blocking
Manual block/unblock from the dashboard, plus automatic blocking after
an attacker sustains an attack past a configurable threshold (default
90 seconds).

✅ Done

### Step 8 Add a trusted device whitelist
Known-safe devices are never flagged, even if their traffic would
otherwise look like spoofing covers legitimate network changes.

✅ Done

### Step 9 Persist everything
SQLite logging so the audit trail survives an agent restart, not just
the current session's memory.

✅ Done

### Step 10 Expand the dashboard
Six pages: live status, block management, network map, whitelist,
full searchable logs with export, and a project overview page.

✅ Done

### Step 11 Go cross-platform
Every OS-facing operation (ARP table edits, firewall rules, DNS
flush, hostname lookup) gets a Linux and Windows implementation behind
one shared interface. Same codebase, same behavior, different system
commands underneath.

✅ Done

### Step 12 Build a one-click Windows installer
A GUI wizard that checks for Python and Npcap, installs them if
missing, downloads the project, installs dependencies, and launches
the dashboard compiled into a single portable `.exe`.

✅ Done

### Step 13 Extend to WiFi deauthentication
Detect and respond to deauth/disassociation attacks.

🔜 Planned requires monitor-mode-capable WiFi hardware not available
in this build; architecture is scoped for it (see ARCHITECTURE.md) but
not implemented

### Step 14 Test it for real
Real attacker + victim lab, real Bettercap ARP and DNS spoofing
against the running agent, confirmed detect → restore → block cycle
on both Linux and Windows.

✅ Done (repeatable demo)

---

## 5. One-Line Summary of Each Phase

| Step | In one line |
|---|---|
| 1. Understand | Learn what "normal" looks like, before trouble starts |
| 2–3. ARP | Detect the lie, fix it automatically |
| 4. Show | Make the whole fight visible, live |
| 5. DNS | Apply the same defense pattern to a second attack type |
| 6. Group | One attacker, one row regardless of attack type |
| 7. Block | Manual or automatic, once an attacker proves persistent |
| 8. Whitelist | Never flag devices you already trust |
| 9. Persist | Logs survive a restart, not just a session |
| 10. Dashboard | Six pages, not one crowded screen |
| 11. Cross-platform | Same code, same behavior, Linux or Windows |
| 12. Installer | One `.exe`, zero manual setup for end users |
| 13. Deauth | Scoped, not yet buildable without hardware |
| 14. Test | Prove it for real, against a real attack |

---

## 6. The Core Idea, in One Sentence

> **Never trust the thing you're defending always verify it against
> something you locked in before the attack began.**

That single idea is what makes this a real defense tool instead of
just a monitoring dashboard, and it's the same idea that scaled
cleanly from one attack type to two, and from one operating system to
two.
