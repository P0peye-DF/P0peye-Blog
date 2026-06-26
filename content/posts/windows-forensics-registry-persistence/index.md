---
title: "Windows Registry Persistence: Key Locations Every Analyst Must Know"
date: 2025-06-15
draft: false
description: "A reference guide to the most commonly abused Windows registry keys for persistence — from Run keys to COM hijacking."
categories:
  - Windows Forensics
tags:
  - windows-forensics
  - persistence
  - registry
  - dfir
  - threat-hunting
---

Registry persistence is bread-and-butter for Windows malware. Knowing where to look — and what normal looks like — is a core DFIR skill. This is a living reference of the locations I check on every investigation.

---

## Run & RunOnce Keys

The most commonly abused. Execute on user logon.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**What to look for:** Entries pointing to `%AppData%`, `%Temp%`, or with Base64 PowerShell commands in the value data.

---

## Services

Malware registers itself as a service for SYSTEM-level persistence and auto-start.

```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

**Key values:** `ImagePath` (binary path), `Start` (2=Auto, 3=Manual, 4=Disabled), `Type`.

**Red flags:** Services with `ImagePath` pointing outside `System32`, or with random-looking names.

---

## Scheduled Tasks (Registry-backed)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```

Correlate with `C:\Windows\System32\Tasks\` for the XML definition.

---

## WMI Subscriptions

Persistent WMI event subscriptions are fileless and survive reboots.

```
HKLM\SOFTWARE\Microsoft\WBEM\ESS
```

Better queried live:

```powershell
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

---

## AppInit_DLLs

DLLs listed here are loaded into every process that loads `User32.dll` — effectively every GUI app.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

Should be empty on a clean system. Any value here is suspicious.

---

## Image File Execution Options (IFEO)

Designed for attaching debuggers; abused for persistence and hijacking.

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>\Debugger
```

If `notepad.exe` has a `Debugger` value pointing to malware, every time Notepad launches, malware runs instead.

---

## COM Hijacking

User-writable COM keys under `HKCU` override system-wide `HKLM` registrations.

```
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
```

**Hunt:** Compare `HKCU\Software\Classes\CLSID` against `HKLM\Software\Classes\CLSID`. Anything in HKCU overriding a legitimate CLSID is a hijack candidate.

---

## Quick Investigation Checklist

```powershell
# Dump all Run key entries
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# List services with auto-start
reg query HKLM\SYSTEM\CurrentControlSet\Services /s | findstr "ImagePath"

# Check AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
```

---

This reference grows with every case. Combine with Sysmon Event ID 13 (registry value set) for real-time detection coverage.
