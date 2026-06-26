---
title: "Understanding Process Injection Techniques"
date: 2025-06-01
draft: false
description: "A deep-dive into common Windows process injection techniques used by malware — DLL injection, process hollowing, and reflective loading."
categories:
  - Malware Analysis
tags:
  - process-injection
  - windows
  - malware-analysis
  - dfir
---

Process injection is one of the most abused techniques in the malware ecosystem. Attackers use it to execute code inside a legitimate process — evading AV/EDR, inheriting process privileges, and hiding under trusted process names.

This post covers three foundational techniques you will encounter during analysis.

---

## 1. Classic DLL Injection

The attacker allocates memory inside a target process, writes a DLL path into it, and calls `CreateRemoteThread` to force the target to load it via `LoadLibraryA`.

**Key API sequence:**

```c
OpenProcess(PROCESS_ALL_ACCESS, ...)
VirtualAllocEx(hProcess, ...)
WriteProcessMemory(hProcess, addr, dllPath, ...)
CreateRemoteThread(hProcess, ..., LoadLibraryA, addr, ...)
```

**Detection:** Look for cross-process `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` in the same handle chain. ETW and Sysmon Event ID 8 (CreateRemoteThread) are your friends.

---

## 2. Process Hollowing

The attacker spawns a legitimate process in suspended state (`CREATE_SUSPENDED`), unmaps its image from memory, maps malicious code into the same address space, and resumes execution.

**Key API sequence:**

```c
CreateProcess(..., CREATE_SUSPENDED, ...)
NtUnmapViewOfSection(hProcess, baseAddr)
VirtualAllocEx(hProcess, baseAddr, ...)
WriteProcessMemory(hProcess, ...)
SetThreadContext(hThread, ...)  // point EIP/RIP to injected code
ResumeThread(hThread)
```

**Detection:** Sysmon Event ID 1 (process create) where the image on disk does not match what is mapped in memory — Hollows Hunter, pe-sieve, and Volatility's `malfind` plugin surface this.

---

## 3. Reflective DLL Injection

The DLL carries its own mini-loader inside. The attacker writes the raw DLL bytes into the target process and jumps to the reflective loader — which maps the DLL into memory without ever touching the filesystem.

**Why it's stealthy:** No `LoadLibrary` call, no entry in the PEB's loaded modules list, no file on disk.

**Detection:** Memory regions that are `MZ`/`PE` executable but not backed by a file on disk. Volatility's `malfind` and `dlllist` discrepancy are key indicators.

---

## Quick Reference

| Technique | Suspicious APIs | Detection |
|-----------|----------------|-----------|
| DLL Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Sysmon EID 8 |
| Process Hollowing | `NtUnmapViewOfSection`, `SetThreadContext`, `ResumeThread` | pe-sieve, malfind |
| Reflective DLL | Raw PE write, no `LoadLibrary` | Unbacked executable memory |

---

Understanding these mechanics is the baseline for memory forensics. In the next post I'll walk through a real AsyncRAT sample that uses process injection to hijack an Outlook session.
