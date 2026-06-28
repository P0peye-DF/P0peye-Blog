---
title: "The Nerv System Breach"
date: 2026-06-28
draft: false
description: "CTF write-up: Linux forensics challenge involving a crypto-miner deployed by the Diicot threat group, analyzed using UAC artifacts to identify PIDs, C2 infrastructure, persistence via Systemd, and actor attribution."
categories:
  - Write-ups
tags:
  - CTF
  - forensics
  - Linux
  - crypto-miner
  - Diicot
  - threat-actor
  - Systemd
  - MITRE-ATT&CK
---

![](https://miro.medium.com/v2/resize:fit:700/1*owVmJle0bmNPI8HUjVpdew.png)

**Challenge Overview:** The Nerv System simulation was exhausted by an advanced attack. We were provided with forensic artifacts collected by the Magi System (UAC — Unix Artifact Collector). Our goal was to identify the specific processes causing the exhaustion, the network infrastructure involved, the persistence mechanism, and the threat actor responsible.

**Final Flag**
```
nexus{3106549_5.178.96.15_3106565_196.251.73.38_T1543.002_diicot_ElPatrono1337}
```

---

## Step 1: Scoping the Incident (Finding the "Exhaustion")

The challenge stated that the system was "exhausted." In Linux forensics, this typically points to a process consuming excessive CPU or memory. We began by analyzing the process listing.

- **File Analyzed:** `collected/live_response/process/ps_auxwwwf.txt`
- **Command:** `cat collected/live_response/process/ps_auxwwwf.txt`

![](https://miro.medium.com/v2/resize:fit:700/1*dQFPQfFydAQJ52Vg4e3v6Q.png)

**Finding:** We located a suspicious process running as user `nexus` with abnormally high CPU usage (`199%`) and a randomized binary name, which is characteristic of crypto-miners.

```
USER      PID    %CPU %MEM    VSZ     RSS  TTY STAT START    TIME COMMAND
nexus  3106565   199  14.6  2441708 2405028 ?  Ssl  Oct11 6489:10 ./293853dc
```

**PID 2 Identified:** `3106565` (The Miner)

---

## Step 2: Tracing the Infection Chain (Finding the Loader)

Malware rarely runs alone; a loader or watchdog process typically keeps the payload alive. Looking directly above the miner in the process tree (`ps_auxwwwf.txt`), we found its parent.

**Finding:** Immediately preceding the miner was a process named `cache`.

```
nexus  3106549  0.0  0.0 1227108 3544 ?  Sl  Oct11   0:01 cache
                                                            \_ ./293853dc
```

**PID 1 Identified:** `3106549` (The Loader)

---

## Step 3: Network Forensics (Mapping the Infrastructure)

We needed to find the IP addresses associated with these two PIDs by correlating them against the network connection logs.

- **File Analyzed:** `collected/live_response/network/netstat_-anp.txt`
- **Commands:** `grep "3106549" ...` and `grep "3106565" ...`

**Finding 1 — Loader Connection:** The Loader (`cache`) was actively connected to a Command and Control (C2) server on a non-standard SSH port (222).

```
tcp  0  0  82.29.168.70:48502  5.178.96.15:222  ESTABLISHED  3106549/cache
```

**IP 1 Identified:** `5.178.96.15`

**Finding 2 — Miner Connection:** The Miner (`./293853dc`) was connected to a known mining pool port (7777).

```
tcp  0  0  82.29.168.70:50572  196.251.73.38:7777  ESTABLISHED  3106565/./293853dc
```

**IP 2 Identified:** `196.251.73.38`

![](https://miro.medium.com/v2/resize:fit:700/1*QLn3P2ACHVlbk43MDi57jg.png)

---

## Step 4: Identifying Persistence (MITRE ATT&CK)

We needed to determine how the malware survived reboots. While `cron` was running on the system, a closer look at the process tree revealed a specific execution context for the user `nexus`.

- **File Analyzed:** `collected/live_response/process/ps_auxwwwf.txt`

**Finding:** The malware chain was running under a **Systemd User Instance**.

```
nexus  3099017  0.0  0.0  20160  11392  ?  Ts  Oct11  0:00  /usr/lib/systemd/systemd --user
```

The malware likely created a malicious `.service` file (e.g., in `~/.config/systemd/user/`) to ensure it auto-starts when the user's session is spawned or on boot. This technique maps to **T1543.002** (Create or Modify System Process: Systemd Service).

![](https://miro.medium.com/v2/resize:fit:700/1*E2udMFPgXDYFHE9dnnrbKA.png)

**MITRE ID Identified:** `T1543.002`

---

## Step 5: Attribution (Actor and Fingerprint)

Finally, we needed to attribute the attack to a specific group and find the unique SSH fingerprint.

### 1. Threat Actor Name

We inspected the environment variables of the Loader process (PID `3106549`) to look for hidden variables or file paths.

- **File Analyzed:** `collected/live_response/process/proc/3106549/environ.txt`

**Finding:**

```
_=/var/tmp/Documents/.diicot
```

The presence of the hidden artifact `.diicot` confirms the actor is the **Diicot** group — a Romanian crypto-jacking threat group also associated with the Kinsing malware family.

**Actor Identified:** `diicot`

Reference: [Tracking Diicot: An Emerging Romanian Threat Actor — Darktrace](https://www.darktrace.com/blog/tracking-diicot-an-emerging-romanian-threat-actor)

![](https://miro.medium.com/v2/resize:fit:700/1*gaBK_9ti2jOeuSWXko1E6w.png)

### 2. SSH Fingerprint

The Diicot group is known for leaving specific signatures in the `authorized_keys` files they modify. Cross-referencing OSINT and CTI reporting on this group:

Reference: [Tracking Diicot: An Emerging Romanian Threat Actor — Darktrace](https://www.darktrace.com/blog/tracking-diicot-an-emerging-romanian-threat-actor)

**Fingerprint Identified:** `ElPatrono1337`
