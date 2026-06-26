---
title: "Cyber Warriors CTF — Forensics: Investigation Nashmi APT"
date: 2025-08-16
draft: false
description: "Full memory forensics CTF walkthrough — AsyncRAT dropper chain, process injection via host.exe, olk.exe session hijacking, and AES-256 config decryption. First Blood on the full chain."
categories:
  - Write-ups
tags:
  - ctf
  - memory-forensics
  - volatility
  - asyncrat
  - dfir
  - malware-analysis
  - process-injection
---

![](https://miro.medium.com/v2/resize:fit:700/1*xmjWlgRCiaWpY7CiFRfAHg.png)

## Introduction

Our Security Operations Center (SOC) detected suspicious activity originating from an internal employee workstation. The employee — a finance team member — reported slow system performance and unexpected behavior. Shortly after, EDR logs showed signs of malware persistence and suspicious outbound traffic.

**Mission:** Analyze a full memory image of the compromised machine, identify the scope of the infection, and answer key investigation questions.

```
Image file: net use M: \\172.16.0.2\Shares /user:Shares Passw0rD@543
```

![](https://miro.medium.com/v2/resize:fit:499/1*vSig_Xq9H2R8kTxyB1lqyQ.png)

---

## Stage 1 — Identify the Executable That Infected the Device

**Flag format:** `NCSC{Executable_Name}`

Start by listing processes running at capture time using `pslist`:

```bash
python3 vol.py -f Nashme-APT.raw windows.pslist
```

![](https://miro.medium.com/v2/resize:fit:498/1*rMRsre22_Sv6Haoq87fuXQ.png)

**Suspicious finding:** `Zoom` was spawned by `cmd.exe`. Legitimate Zoom runs under `explorer.exe` or `ZoomInstaller.exe` — not CMD.

### Check the execution path

```bash
python3 vol.py -f Nashme-APT.raw windows.cmdline --pid 12692
```

![](https://miro.medium.com/v2/resize:fit:700/1*yq6sJepovoR1fpz2pvD10Q.png)

The path is abnormal. The legitimate Zoom client lives at:

```
C:\Users\<User>\AppData\Roaming\Zoom\bin\Zoom.exe
```

### Dump and analyse the binary

Get the virtual address via `filescan`:

```bash
python3 vol.py -f Nashme-APT.raw windows.filescan | grep "zoom.exe"
```

![](https://miro.medium.com/v2/resize:fit:700/1*IKNSLKXrE9gK0PcIMN2JWQ.png)

Dump the file:

```bash
sudo python3 vol.py -f Nashme-APT.raw -o sus_bin windows.dumpfiles
```

![](https://miro.medium.com/v2/resize:fit:670/1*fHdEk48Ogl7kAkvQl7Nyfw.png)

Upload to VirusTotal → **Confirmed: AsyncRAT**.

![](https://miro.medium.com/v2/resize:fit:700/1*JLerXdn6ZrWRjO6iAFr71Q.png)

But did CMD really execute Zoom directly? In forensics, you need the full story — especially the initial access vector. Check handles for the RAT to find what it's touching:

```bash
python3 vol.py -f Nashme-APT.raw windows.handles --pid 12692
```

![](https://miro.medium.com/v2/resize:fit:700/1*EG6jMRJdI-S3pREm7xVBKA.png)

The RAT has a handle open to the user's **Downloads** directory. Scan that path:

```bash
python3 vol.py -f Nashme-APT.raw windows.filescan | grep "Downloads"
```

![](https://miro.medium.com/v2/resize:fit:700/1*6b09BjHT3WjXe7fwWOMUKg.png)

Finding: **`Zoom-Installer.exe`** in Downloads. This is the dropper. Dump it and upload to VirusTotal → **Confirmed malicious.**

![](https://miro.medium.com/v2/resize:fit:700/1*4aBXETcsAGgilvuCKleWjA.png)

> **Flag 1:** `NCSC{Zoom-Installer.exe}`

---

## Stage 2 — Path of the Infection

The RAT dropped itself to:

```
C:\Users\Mohsen\AppData\Roaming\Zoom.exe
```

> **Flag 2:** `NCSC{C:\Users\Mohsen\AppData\Roaming\Zoom.exe}`

---

## Stage 3 — Network Connection

```bash
python3 vol.py -f Nashme-APT.raw windows.netstat
```

![](https://miro.medium.com/v2/resize:fit:700/1*_NwbQWuotng5jQjD6d17-Q.png)

`zoom.exe` has an **established** connection to the C2 server.

> **Flag 3:** `NCSC{192.168.0.100:8808}`

---

## Stage 4 — RAR File on Desktop

While scanning the filesystem I noticed:

```
Users\Mohsen\Desktop\Important.rar
```

![](https://miro.medium.com/v2/resize:fit:700/1*fS9_n1jlpLwpt4G-GaiI0g.png)

Dump the file and crack the password:

```bash
rar2john Important.rar > hash.txt
hashcat -m 13000 hash.txt /usr/share/wordlists/rockyou.txt
```

![](https://miro.medium.com/v2/resize:fit:700/1*7YjRoq7LeCDvPOqjX6RazQ.png)

Password: **`Rat9030`**

> **Flag 4:** `NCSC{R4T5_a43_4MaZ1nG_Cr34TuR3s!}`

---

## Stage 5 — Process Injection: olk.exe & host.exe

### Context

**`olk.exe`** is the executable for the new Outlook app on Windows. The victim had no saved credentials on the system — so the attacker couldn't steal a stored password. Instead, they hijacked an **already authenticated session** running inside `olk.exe`.

Classic technique:
- Inject into a running browser/mail client process
- Steal cookies or session tokens from memory
- No password needed — the session is already live

### Investigation

**Step 1:** Confirm `olk.exe` was running:

```bash
python3 vol.py -f Nashme-APT.raw windows.pslist
```

![](https://miro.medium.com/v2/resize:fit:500/1*DZR1Zj9Sqk9oBpXeCf-sXw.png)

```
PID: 2864   PPID: 6940   olk.exe
```

**Step 2:** Check the parent process (PPID 6940):

![](https://miro.medium.com/v2/resize:fit:501/1*VEzYaNTKx5JZcuOqu_-lLA.png)

**No process found.** The parent had already exited before the memory capture — classic evasion.

**Step 3:** Check handles on `olk.exe`:

```bash
python3 vol.py -f Nashme-APT.raw windows.handles | grep olk.exe
```

![](https://miro.medium.com/v2/resize:fit:700/1*bi5noI5Mm3Wmi1y1KCmL6g.png)

Everything seemed legitimate. Hit a wall — pivoted to **MemProcFS**:

```bash
MemProcFS.exe -device D:\Nashme-APT.raw -forensic 1
```

![](https://miro.medium.com/v2/resize:fit:496/1*HUOA6rD5kS0lYYzeEbO4Qg.png)

Reviewing the process list in MemProcFS, I spotted **`host.exe`** — initially overlooked. After research, `host.exe` is a known suspicious process. Checking its handles:

```
M:\name\host.exe-3144\handles\handles.txt
```

![](https://miro.medium.com/v2/resize:fit:700/1*dgDLAJOHH8hfTFM28mRqlw.png)

![](https://miro.medium.com/v2/resize:fit:700/1*-t6SCTLFdvmy6b14XXBqxg.png)

**Result:** `host.exe` (PID 3144) was reading memory from `olk.exe` (handle 8528).

![](https://miro.medium.com/v2/resize:fit:509/1*oUvXgnOqciezSeKfFJV7nQ.png)

> **Flag 5:** `NCSC{host.exe:3144:8528}`

---

## Stage 6 — AsyncRAT Reverse Engineering

### Binary identification

```bash
file zoom.exe
# zoom.exe: PE32 executable for MS Windows (GUI), Intel i386 Mono/.Net assembly
```

It's a **.NET assembly** — use **dnSpy** to decompile.

> **Warning:** This is real malware. Do **not** debug it on your main system.

### `InitializeClient()` — C2 Connection Logic

![](https://miro.medium.com/v2/resize:fit:498/1*YgxgM3yx2XUSpDZjfpqh9A.png)

![](https://miro.medium.com/v2/resize:fit:700/1*znzan1Lsgr6k-W8JwJXOHQ.png)

This function:
- Creates a TCP socket with 50KB buffers
- Randomly selects a host/port from the config (or fetches from Pastebin as a fallback C2)
- Wraps the connection in SSL/TLS with custom certificate validation
- Sends initial client info to the server
- Sets keepalive timers and begins asynchronous data read

### `InitializeSettings()` — AES-256 Config Decryption

![](https://miro.medium.com/v2/resize:fit:700/1*Ybbwmta5eRzCq3hACAS7fg.png)

![](https://miro.medium.com/v2/resize:fit:700/1*QjQgshHCZjiQag80311Miw.png)

Key observations:
- All config fields are AES-256 encrypted, stored as base64 strings
- `VerifyHash()` validates the decrypted key against the server's RSA signature
- `InstallFolder = "%AppData%"`, `InstallFile = "zoom.exe"` — confirms persistence location
- AES key (base64): `NHJxUXhJcE5NUklBNEhseExZbjNBblYyallxSEwyckQ=`

### Decrypting the Certificate

Used the [AsyncRAT config decoder](https://github.com/embee-research/asyncrat-config-decoder/tree/main) — modified by teammate **Omar Hijah**:

1. Set `$key` = `NHJxUXhJcE5NUklBNEhseExZbjNBblYyallxSEwyckQ=`
2. Set `$enc_list` = the encrypted Certificate base64 string from the Settings class

```powershell
powershell -ExecutionPolicy Bypass
.\decoder.ps1
```

![](https://miro.medium.com/v2/resize:fit:700/1*1nEy2HqnTKtivvMxPEPbeQ.png)

![](https://miro.medium.com/v2/resize:fit:700/1*oC_0vTIX9JnVyBc7p-igxA.png)

![](https://miro.medium.com/v2/resize:fit:700/1*2tVELakh7JQbVQyfeW2ThQ.png)

![](https://miro.medium.com/v2/resize:fit:700/1*PDGrk-sctjTF908ARPHvfQ.png)

![](https://miro.medium.com/v2/resize:fit:700/1*npnSuiFyNPQDNqoxw2yEvA.png)

Decrypted output → base64 → CyberChef → decoded certificate:

![](https://miro.medium.com/v2/resize:fit:498/1*FUPNeY0_tRdoHQt7wbnOZg.png)

![](https://miro.medium.com/v2/resize:fit:493/1*O96f0OuDcLmryVoADw_I7Q.png)

Extract certificate details:

```bash
openssl x509 -in download.cer -inform DER -text -noout
```

![](https://miro.medium.com/v2/resize:fit:700/1*Xf_QRjCW7caQxHXcTuYx5w.png)

![](https://miro.medium.com/v2/resize:fit:700/1*bP0Gs1IRGo7ayLHcA853DQ.png)

![](https://miro.medium.com/v2/resize:fit:700/1*1eYWoIXegBIZDPegXT65tA.png)

Certificate subject: **`AsyncRAT Server`**

![](https://miro.medium.com/v2/resize:fit:700/1*gAoM2BjfsfcvCa5UZepkSw.png)

![](https://miro.medium.com/v2/resize:fit:700/1*2GovmgWRuM3CVaVYvA411g.png)

![](https://miro.medium.com/v2/resize:fit:700/1*kQqlf6R_JLaWTWIn-CmhyA.png)

![](https://miro.medium.com/v2/resize:fit:700/1*p3x78OMFBSDiX7ZthFWggg.png)

![](https://miro.medium.com/v2/resize:fit:700/1*svJBplM4erIeIia7JUDXmQ.png)

> **Flag 6 (First Blood):** `NSCS{9ddecd9ad34bd6dfe5e67c33af6a5f}`

---

## Attack Chain Summary

```
Zoom-Installer.exe (dropper)
    └── drops zoom.exe (AsyncRAT) → C:\Users\Mohsen\AppData\Roaming\Zoom.exe
         ├── Spawned by cmd.exe from suspicious path
         ├── C2: 192.168.0.100:8808 (SSL/TLS, AES-256 encrypted config)
         ├── Downloads handle → confirms dropper origin
         └── host.exe (PID 3144) → injects into olk.exe (PID 2864, handle 8528)
              └── Session hijack of authenticated Outlook process
```

![](https://miro.medium.com/v2/resize:fit:700/1*Yc7gUq6furaq_buINJUeSw.png)

We were the **only team** that solved the entire chain.

![](https://miro.medium.com/v2/resize:fit:500/1*sddmOIhZ9Zu3PcT9-zDSow.png)

---

## IOC Summary

| Indicator | Type | Note |
|-----------|------|------|
| `Zoom-Installer.exe` | Filename | Initial dropper |
| `zoom.exe` | Filename | AsyncRAT payload |
| `C:\Users\Mohsen\AppData\Roaming\Zoom.exe` | Path | Persistence location |
| `192.168.0.100:8808` | IP:Port | AsyncRAT C2 |
| `host.exe` (PID 3144) | Process | Injector process |
| `olk.exe` (PID 2864) | Process | Injection target (Outlook) |
| `NHJxUXhJcE5NUklBNEhseExZbjNBblYyallxSEwyckQ=` | AES Key | AsyncRAT config key |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Volatility 3 | Memory analysis (pslist, cmdline, filescan, dumpfiles, netstat, handles) |
| MemProcFS | Alternative memory analysis — surfaced host.exe handles |
| VirusTotal | Binary reputation |
| dnSpy | .NET decompilation of AsyncRAT |
| rar2john + Hashcat | RAR password cracking (mode 13000) |
| AsyncRAT config decoder | AES-256 config decryption |
| CyberChef | Base64 certificate decode |
| OpenSSL | Certificate inspection |

---

## References

- [processlibrary.com — host.exe](https://www.processlibrary.com/en/directory/files/host/25545/)
- [AsyncRAT CyberChef decoder — baco.sk](https://www.baco.sk/posts/asyncrat-cyberchef/)
- [AsyncRAT overview — pointwild.com](https://www.pointwild.com/threat-intelligence/the-rise-of-asyncrat)
- [AsyncRAT technical analysis — Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2022/08/16/asyncrat-c2-framework-overview-technical-analysis-and-detection)
- [embee-research/asyncrat-config-decoder](https://github.com/embee-research/asyncrat-config-decoder/tree/main)
- [MemProcFS](https://github.com/ufrisk/MemProcFS)
