# 🐕‍🦺 PacketHound

**A real-time Network Intrusion Detection System — live packet sniffing, three behavioral detection engines, one dashboard.**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=linux&logoColor=white)
![Scapy](https://img.shields.io/badge/Packet%20Capture-Scapy-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Built to practice real detection engineering, not just tool usage — every threshold, cooldown, and alert schema decision below came from testing against live attacks and fixing what actually broke, not from a tutorial.

```
Live Traffic (Scapy)  →  3 Parallel Detectors  →  Live Flask Dashboard
   (raw packet sniff)     (port scan / ARP /          (auto-refreshing,
                            brute-force)                severity color-coded)
```

---

## What It Does

PacketHound sniffs live packets off a network interface and runs three independent detection engines simultaneously, each watching for a distinct attack behavior:

| Detector | Catches | Real-World Signature |
|---|---|---|
| 🔴 **Port Scan** | Recon sweeps (e.g. Nmap) | One source IP touching many *different* ports on one target, fast |
| 🟠 **ARP Spoofing** | Man-in-the-Middle setup | An IP suddenly claimed by a *different* MAC than previously seen |
| 🟡 **Brute-Force Login** | Credential attacks (e.g. Hydra) | One source IP, many rapid failed attempts, one login service |

All three feed a unified `/api/alerts` endpoint, rendered live in a browser dashboard polling every 2 seconds — sensor status lights, per-type alert counts, and a live severity-tagged feed table.

---

## Why This Exists

Built as hands-on preparation for entry-level cybersecurity roles (SOC Analyst / Cybersecurity Analyst / Junior Penetration Tester). The goal wasn't to wrap Suricata or reimplement Snort — it was to build genuine threshold-based detection logic from raw packets up, hit real reliability problems (alert flooding, inconsistent data schemas), and fix them the way a real detection engineer would.

Every detector went through a real build → test → break → fix cycle against live traffic, not canned test data. Three of those cycles are documented below because they're the parts worth explaining in an interview.

---

## Proof of Concept — Three Real Attacks, Three Real Detections

### 1. Port Scan — `nmap -sS -p 1-100 127.0.0.1`

```
15 ports probed in under 10 seconds → 1 clean alert (after cooldown fix)
```

First run fired **six duplicate alerts for one scan** — same incident, reported six times. Root cause and fix documented below. After the fix, the identical scan produces exactly one alert with a clear suppression note.

### 2. ARP Spoofing — `arpspoof -i eth0 192.168.98.128` (Kali → Metasploitable2)

```
[ALERT] POSSIBLE ARP SPOOFING DETECTED
Target IP:       192.168.98.128
Previously seen: 00:0c:29:22:c0:70
Now claimed by:  00:0c:29:3b:fa:4f  ← SUSPICIOUS
```

Live ARP replies broadcast during the attack were correctly matched against the detector's trust table, firing in real time — this is real packet data off the wire, not a simulated event.

### 3. Brute-Force Login — Hydra against Metasploitable2's FTP service

```
[ALERT] POSSIBLE BRUTE-FORCE ATTACK DETECTED
Source IP:      192.168.98.129
Target service: FTP (port 21)
Attempts:       8 connections in 15s
Time:           2026-07-16 19:15:35
(Further alerts for this IP/port suppressed for 30s)
```

Hydra's rapid FTP login attempts were correctly detected and flagged in a single clean alert — no duplicate flooding, confirming the same cooldown/suppression fix built for the port scan detector works correctly here too.

---

## Architecture

```
PacketHound/
├── dashboard.py                     # Flask app — starts all 3 detectors as threads, serves live UI
├── modules/
│   ├── portscan_detect.py           # SYN-flood style port scan detection
│   ├── arpspoof_detect.py           # ARP cache poisoning / MITM detection
│   └── bruteforce_detect.py         # Rapid failed-login detection, 6 monitored services
├── templates/
│   └── index.html                   # Live dashboard — polling, severity colors, sensor status
├── samples/                         # Reserved for captured proof-of-concept evidence
├── requirements.txt
└── LICENSE                          # MIT
```

Each detector is fully self-contained and runnable standalone, or all three run together as daemon threads under `dashboard.py`.

---

## Usage

**Run an individual detector standalone:**
```bash
sudo python3 modules/portscan_detect.py
sudo python3 modules/arpspoof_detect.py
sudo python3 modules/bruteforce_detect.py
```

**Run the full live dashboard** (all three detectors + web UI):
```bash
sudo python3 dashboard.py -i eth0
```
Then open `http://127.0.0.1:5000`. Replace `eth0` with your actual interface (`ip addr show` to check).

> Root privileges are required — raw packet sniffing needs elevated permissions on Linux.

---

## Design Decisions Worth Noting

- **Lower threshold for brute-force (8) than port scan (15).** Legitimate SSH usage almost never retries 8 times in 15 seconds — a couple of typos, maybe. This is a tighter, more confident signal than port-touching behavior, so it can afford a lower bar before alerting.
- **Cooldown-based suppression, not hard resets.** After alerting on a source, the detector keeps tracking silently instead of going fully quiet — so an attack that pauses and resumes still gets caught, but the same continuous incident doesn't spam duplicate alerts.
- **ARP replies only, not requests.** ARP requests ("who has X?") are broadcast questions; replies are actual ownership claims. Filtering to `op == 2` avoids false signal from normal ARP chatter.
- **Consistent alert schema across all three detectors.** Every alert dict carries the same core fields (`type`, `severity`, `timestamp`, `readable_time`) so the dashboard can render and sort any detector's output identically — this consistency was *not* there from the start (see bug #2 below).

---

## Bugs Found & Fixed — Real Debugging History

### 1. Alert flooding from a single scan event
The first version of the port scan detector reset its port counter immediately after alerting. A single fast Nmap scan crossing the threshold multiple times in one burst produced **six duplicate alerts for one real incident** — verified with a live test, screenshot-documented, not theoretical.

**Fix:** added a 30-second cooldown per source IP after each alert. Re-ran the identical scan — one clean alert instead of six, with an explicit "further alerts suppressed" note. This mirrors *alert deduplication*, a real, well-known SOC engineering concern — analysts ignoring alerts because of duplicate noise is a documented failure mode in production security tools.

### 2. Missing `timestamp` field silently breaking dashboard sort order
The ARP spoof and brute-force detectors originally stored only a human-readable `readable_time` string, no numeric `timestamp`. The dashboard sorts every alert by `x.get('timestamp', 0)` — both detectors silently defaulted to `0`, meaning their alerts always sorted as "oldest" and sank to the bottom of the live feed regardless of when they actually fired. No crash, no error — just quietly wrong data.

**Fix:** added a numeric `timestamp` field to every alert dictionary across all three detectors, verified with `ast.parse()` syntax checks before committing.

### 3. SSH brute-force test blocked by legacy crypto incompatibility
Metasploitable2's SSH server only supports MAC algorithms (`hmac-md5`, `hmac-sha1`) that Kali's modern SSH client refuses by default. Rather than downgrading the client's crypto just to force a test through, the brute-force proof-of-concept was pivoted to FTP — the same detection logic, a more realistic target given the constraint.

---

## Skills Demonstrated

| Area | Where |
|---|---|
| Live packet capture & protocol analysis | Scapy-based sniffing across all three detectors |
| Behavioral / threshold-based detection design | Not signature matching — pattern recognition on live traffic |
| Alert reliability engineering | Cooldown/suppression logic, consistent alert schema across detectors |
| Concurrency | Each detector runs as an independent daemon thread |
| REST API design | Flask `/api/alerts` JSON endpoint |
| Front-end dashboard development | Live polling, dynamic per-alert-type rendering, severity color coding |
| Debugging against unpredictable real traffic | Every bug above was found against live packets, not test fixtures |
| Practical engineering judgment | SSH → FTP pivot when legacy target and modern tooling conflicted |

---

## Setup

```bash
git clone https://github.com/rajdeep-10/PacketHound.git
cd PacketHound
pip install -r requirements.txt --break-system-packages
sudo python3 dashboard.py -i eth0
```

Requires Python 3.8+. Tested on Kali Linux.

---

## Legal & Ethical Use

This tool was built and tested exclusively against infrastructure explicitly authorized for testing: the developer's own local machine (`127.0.0.1`) and an isolated, host-only Metasploitable2 VM with no internet exposure. Running port scans, ARP spoofing, or brute-force attacks against any system without **explicit written authorization** is illegal in most jurisdictions. This project is for educational and portfolio purposes only.

---

## License

MIT — see [LICENSE](./LICENSE).
