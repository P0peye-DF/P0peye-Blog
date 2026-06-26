---
title: "Aliens CTF — DFIR: 7 Oct"
date: 2025-08-20
draft: false
description: "DFIR CTF walkthrough — RTP audio stream analysis, Chrome DPAPI password decryption, and Facebook credential extraction from a disk image."
categories:
  - Write-ups
tags:
  - ctf
  - dfir
  - wireshark
  - rtp
  - dpapi
  - chrome
  - disk-forensics
---

## Challenge: 7 Oct

### Description

> We stormed one of the enemy's concentration areas and after completing the operation, we took some devices to investigate and obtain intelligence. One device belongs to a leader. We believe information is being leaked through a spy. Search the device to find the spy and location details — the enemy was planning a prisoner recovery operation and location information had been leaked to them.
>
> *"Whoever goes out to hunt will be hunted."*

**Required:**
1. Name of the spy
2. Name of the region
3. Street number
4. How many floors does the building have?

---

## Evidence

After extracting the zip file, two items are present:

- `pcap.pcapng` — network capture
- Disk image from partition C

---

## Step 1 — Network Analysis (Wireshark)

Opening the PCAP, **RTP (Real-Time Transport Protocol)** traffic is immediately visible — the leader was making a call.

![](https://miro.medium.com/v2/resize:fit:700/1*rFWR6epvyu_1J72KM8g3jg.png)

> **RTP** provides end-to-end transport for real-time data (audio, video). It's the protocol behind VoIP calls and audio streams.

Wireshark can reconstruct and play back RTP audio streams directly:

**Telephony → RTP → RTP Streams**

![](https://miro.medium.com/v2/resize:fit:700/1*oCExTZyIN4SLpgL5x2fl_g.png)

Listening to the audio reveals the leader discussing **social media applications** used to communicate. This tells us the communication channel — now we need to identify which app and extract the credentials.

---

## Step 2 — Disk Image Analysis (Browser History)

Mount the disk image and open the browser history file.

**Table → URLs**

![](https://miro.medium.com/v2/resize:fit:700/1*BI75bQSKCVQG7cLR_w1LVg.png)

The history shows a **Facebook login** search — the leader used Facebook to communicate with the spy. The browser used was **Chrome**.

---

## Step 3 — Decrypt Chrome Passwords (DPAPI)

Chrome encrypts saved passwords using Windows DPAPI. Decryption requires four steps.

### 3.1 — Find the Encryption Key

The encryption key is stored in Chrome's `Local State` JSON file:

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State
```

Search for `encrypted_key`.

![](https://miro.medium.com/v2/resize:fit:700/1*z7OxRM1f74mf-NGJEIDu0Q.png)

Extract the key value and save it as `download1.dat`. Open it in a hex editor and **remove the first 5 bytes** (the `DPAPI` prefix):

![](https://miro.medium.com/v2/resize:fit:700/1*cvEWGjpXcqInBz54zFJ0Ng.png)

![](https://miro.medium.com/v2/resize:fit:700/1*_NQ41Kasxhb0rlw6V8gaTg.png)

### 3.2 — Extract the Master Key

First, dump the SAM and SYSTEM hives from the disk image to extract the user's password hash:

```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

![](https://miro.medium.com/v2/resize:fit:700/1*ucsjM3eDQn-JQ-_z_6oWaw.png)

Crack the hash at [crackstation.net](https://crackstation.net/).

Now use **Mimikatz** to retrieve the DPAPI Master Key using the user's SID, password, and master key GUID:

```
dpapi::masterkey /in:<masterkey_file> /sid:<user_SID> /password:<cracked_password>
```

![](https://miro.medium.com/v2/resize:fit:700/1*5QqhkwYD33YvF6_g2JkisA.png)

### 3.3 — Decrypt the Chrome Key

Use Mimikatz's `dpapi` module to decrypt the encrypted blob from `download1.dat`:

```
dpapi::blob /in:download1.dat /masterkey:<masterkey>
```

![](https://miro.medium.com/v2/resize:fit:700/1*-ts6oW0LAJqbIVYoZJa12Q.png)

### 3.4 — Extract and Decrypt Saved Passwords

Chrome's encrypted passwords are stored in an SQLite database:

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

Extract with Python and decrypt using the recovered key:

![](https://miro.medium.com/v2/resize:fit:674/1*XDSuly3PUZvh-qWiUL_ybQ.png)

![](https://miro.medium.com/v2/resize:fit:676/1*7uqWgBDh4vr9ope8JjCLQg.png)

---

## Step 4 — Facebook Account Access

With the decrypted credentials, log into the Facebook account to retrieve the conversation with the spy.

![](https://miro.medium.com/v2/resize:fit:700/1*GgnwREGOisHNlwXIaGNpuA.png)

![](https://miro.medium.com/v2/resize:fit:700/1*QsyH58RcyDSnaKvoOzNKuQ.png)

The conversation contains all four required answers — spy name, region, street number, and building floor count.

![](https://miro.medium.com/v2/resize:fit:647/1*BKDBWA3vVAx0SdfO6r-9gQ.png)

---

## Methodology Summary

| Step | Action | Tool |
|------|--------|------|
| Network analysis | Reconstruct RTP audio stream | Wireshark |
| Browser history | Identify communication platform (Facebook) | Disk image |
| Credential extraction | Dump SAM/SYSTEM, crack hash | secretsdump.py, CrackStation |
| DPAPI decryption | Recover Chrome master key | Mimikatz |
| Password decryption | Decrypt Chrome SQLite passwords | Python + AES |
| Intelligence retrieval | Access Facebook messages | Browser |

---

## References

- [DPAPI — Extracting Passwords — HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
- [Mimikatz](https://github.com/ParrotSec/mimikatz)
