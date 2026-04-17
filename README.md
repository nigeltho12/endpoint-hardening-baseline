# Endpoint Hardening Baseline
### Windows & macOS | CIS Benchmark Controls | Audit Scripts

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS-blue)]()
[![Standard](https://img.shields.io/badge/Standard-CIS%20Benchmark-orange)]()
[![Scripts](https://img.shields.io/badge/Scripts-PowerShell%20%7C%20Bash-green)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()

---

## Overview

This repository documents a dual-platform endpoint hardening baseline aligned to the **CIS (Center for Internet Security) Benchmark** for both Windows and macOS. It is designed for use in enterprise environments where both platforms are managed in parallel; a common scenario in organizations running Microsoft Intune + Jamf.

The goal is not to run a script and call it done. Each control is documented with:
- **What it does** — the technical change being made
- **Why it matters** — the threat it mitigates
- **How to audit it** — a scripted check you can run without applying changes

This approach reflects real security engineering practice: understand the control, validate the current state, then enforce.

---

## Repository Structure

```
endpoint-hardening-baseline/
├── README.md                          ← You are here
├── windows/
│   ├── cis-windows-checklist.md       ← CIS L1 controls with rationale
│   └── audit-windows.ps1              ← PowerShell audit script (read-only)
├── macos/
│   ├── cis-macos-checklist.md         ← CIS L1 controls with rationale
│   └── audit-macos.sh                 ← Shell audit script (read-only)
└── comparison/
    └── platform-comparison.md         ← Side-by-side Windows vs macOS mapping
```

---

## Scope & Coverage

| Category | Windows | macOS |
|---|---|---|
| Account & Authentication | ✅ | ✅ |
| Screen Lock & Session Timeout | ✅ | ✅ |
| Firewall Configuration | ✅ | ✅ |
| Encryption (BitLocker / FileVault) | ✅ | ✅ |
| Remote Access Controls | ✅ | ✅ |
| Audit Logging | ✅ | ✅ |
| Software & Service Hardening | ✅ | ✅ |
| Automatic Updates | ✅ | ✅ |

---

## Audit Scripts

Both scripts are **read-only**. They check the current state and report findings; they do not make changes to the system.

| Script | Platform | Run As |
|---|---|---|
| `audit-windows.ps1` | Windows 10/11 | Administrator |
| `audit-macos.sh` | macOS 12+ (Monterey and later) | sudo |

### Quick Start

**Windows:**
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\windows\audit-windows.ps1
```

**macOS:**
```bash
chmod +x macos/audit-macos.sh
sudo ./macos/audit-macos.sh
```

Output is color-coded: `[PASS]`, `[FAIL]`, and `[MANUAL]` for controls that require human verification.

---

## Context & Use Cases

This baseline is relevant to any organization managing a mixed Windows/macOS fleet, particularly:

- **Insurance / Financial services** — where CIS controls map to HIPAA, PCI DSS, and SOC 2 requirements
- **MSP environments** — where consistent policy across client endpoints is a deliverable
- **Hybrid MDM environments** — organizations running Intune (Windows) and Jamf (macOS) in parallel

Controls are sourced from **CIS Benchmark v3.0 (Windows 11)** and **CIS Benchmark v3.0 (macOS 14 Sonoma)**, Level 1 profile. Level 1 controls are recommended for all enterprise environments and do not significantly impact usability.

---

## Related Projects

- [Agentic AI SOC Analyst](https://github.com/nigeltho12/Agentic_Soc_AI) — AI-driven SOC agent using Python + LLM API + Azure Log Analytics
- [Honeynet in Azure](https://github.com/nigeltho12/Honeynet-in-Azure) — Live attack traffic analysis with Microsoft Sentinel
- [KQL Threat Hunting](https://github.com/nigeltho12/ThreatHuntScenarios-CyberRange) — Detection engineering exercises in Microsoft Sentinel

---


