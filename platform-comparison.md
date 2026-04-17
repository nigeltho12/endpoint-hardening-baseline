# Platform Comparison: Windows vs macOS Hardening Controls
### CIS Benchmark Level 1 — Enterprise Endpoint Baseline

> This document maps equivalent hardening controls across Windows and macOS. It is designed for engineers managing a mixed-platform fleet — particularly environments running **Microsoft Intune** (Windows) and **Jamf** (macOS) in parallel.

---

## Why This Comparison Matters

Windows and macOS approach security configuration from fundamentally different architectural starting points. Windows relies heavily on Group Policy / Registry and has deep enterprise MDM integration through Intune. macOS uses a combination of `defaults` keys, system commands, configuration profiles, and an increasingly MDM-first enforcement model through Apple Business Manager.

Understanding which controls exist on both platforms, which are platform-unique, and where enforcement gaps tend to appear is essential for building a consistent security posture across a mixed fleet.

---

## Control-by-Control Comparison

### 1. Account & Authentication

| Control | Windows | macOS |
|---|---|---|
| Guest Account | `Get-LocalUser "Guest"` — disable via GPO or Intune | `defaults read com.apple.loginwindow GuestEnabled` — disable via MDM profile |
| Password Length | Group Policy: min 14 chars | MDM Passcode payload: min 15 chars |
| Password History | Group Policy: 24 previous | MDM Passcode payload: 15 previous |
| Account Lockout | Group Policy: 5 attempts | MDM Passcode payload: configurable |
| Complexity Requirements | Group Policy: enabled | MDM Passcode payload: enforced |

**Key Difference:** On macOS, password policy for local accounts is increasingly enforced only via MDM. Standalone `pwpolicy` commands work but are fragile — MDM-delivered passcode payloads are the reliable enforcement path.

---

### 2. Screen Lock & Session Controls

| Control | Windows | macOS |
|---|---|---|
| Timeout (Inactivity) | 900s (15 min) via GPO / Intune profile | 1200s (20 min) via MDM Login Window payload |
| Password on Resume | `ScreenSaverIsSecure = 1` via GPO | `require password to wake = true` via MDM |
| Enforcement Method | Registry / GPO / Intune Configuration Profile | MDM Login Window payload |
| Audit Command | `Get-ItemProperty "HKCU:\Control Panel\Desktop"` | `osascript` security preferences query |

**Key Difference:** CIS allows a slightly more permissive timeout on macOS (20 min vs 15 min for Windows). In practice, organizations should standardize on 15 minutes for both platforms.

---

### 3. Firewall

| Control | Windows | macOS |
|---|---|---|
| Firewall Enabled | Windows Defender Firewall — Domain, Private, Public profiles | Application Firewall via `socketfilterfw` |
| Stealth Mode | Partial via GPO — block ICMP probes | Explicit: `socketfilterfw --getstealthmode` |
| Block All Inbound | Public profile: block all (CIS recommended) | `socketfilterfw --getblockall` |
| Rule Management | Per-rule GPO / Intune Endpoint Security | Per-application via MDM profile |
| Audit Command | `Get-NetFirewallProfile` | `/usr/libexec/ApplicationFirewall/socketfilterfw` |

**Key Difference:** Windows firewall operates at the profile level (Domain/Private/Public) and applies different rules based on network classification. macOS uses a single application-level firewall without network profiles — simpler but less granular.

---

### 4. Full-Disk Encryption

| Control | Windows | macOS |
|---|---|---|
| Technology | BitLocker (TPM-backed) | FileVault 2 (T2/Apple Silicon) |
| Status Check | `Get-BitLockerVolume` / `manage-bde -status` | `fdesetup status` |
| Key Escrow | Azure AD / Active Directory | Jamf / Intune / iCloud |
| Recovery Key | Recovery Password protector | Personal or Institutional Recovery Key |
| Enforcement | Intune Endpoint Security > Disk Encryption | MDM FileVault payload |
| Hardware Dependency | TPM 2.0 chip | T2 chip or Apple Silicon (all modern Macs) |

**Key Difference:** Both solutions are hardware-accelerated on modern devices and effectively transparent to users. The main operational difference is key escrow management — Intune handles BitLocker recovery keys in Azure AD, while macOS requires Jamf or Intune for macOS to escrow FileVault keys reliably.

---

### 5. Remote Access

| Control | Windows | macOS |
|---|---|---|
| Primary Protocol | RDP (port 3389) | SSH (port 22) + ARD |
| Disable Remote Access | `fDenyTSConnections = 1` | `systemsetup -setremotelogin off` |
| Require Auth Before Session | NLA (Network Level Authentication) | Key-based SSH or password |
| Audit Command | Registry: `HKLM:\System\CurrentControlSet\Control\Terminal Server` | `systemsetup -getremotelogin` |
| Internet Sharing | N/A (ICS - Internet Connection Sharing) | `com.apple.nat` defaults key |

**Key Difference:** RDP is the dominant attack vector on Windows — it appears in virtually every ransomware playbook. SSH on macOS is lower-risk in enterprise environments but should still be disabled unless actively needed. The threat model differs significantly between platforms here.

---

### 6. Audit Logging

| Control | Windows | macOS |
|---|---|---|
| Logging Framework | Windows Event Log + Advanced Audit Policy | BSM (Basic Security Module) + Unified Log |
| Enable Audit | `auditpol` / GPO Advanced Audit | `/etc/security/audit_control` + `launchctl` |
| Key Events | Credential Validation, Logon, Process Creation | Authentication, privilege use, file access |
| SIEM Integration | Windows Event Forwarding / Defender for Endpoint | Jamf + log forwarding, or osquery |
| Audit Command | `auditpol /get /subcategory:` | `launchctl list \| grep auditd` |
| Log Location | Windows Event Viewer (`.evtx`) | `/var/audit/` + Unified Log (`log show`) |

**Key Difference:** Windows audit policy configuration is more granular and better understood in the enterprise world. macOS logging is sometimes overlooked in SIEM pipelines — ensure macOS endpoints are forwarding to your SIEM (Datadog, Sentinel, Splunk) with equal priority to Windows endpoints.

---

### 7. Software & Service Hardening

| Control | Windows | macOS |
|---|---|---|
| Execution Control | Windows Defender SmartScreen + AppLocker/WDAC | Gatekeeper + Notarization |
| System File Protection | Windows File Protection / Protected Processes | SIP (System Integrity Protection) |
| Removable Media | AutoRun/AutoPlay disabled via GPO | No AutoRun equivalent — lower risk |
| Malware Protection | Defender AV (or third-party EDR) | XProtect + MRT (built-in) + third-party EDR |
| Audit Command | `Get-MpComputerStatus` | `csrutil status` + `spctl --status` |

**Key Difference:** SIP on macOS is more powerful than its Windows equivalent — it protects system directories even from root. However, it cannot be remotely re-enabled once disabled, making detection critical. Any macOS endpoint where `csrutil status` returns disabled should be flagged immediately.

---

### 8. Automatic Updates

| Control | Windows | macOS |
|---|---|---|
| Update Mechanism | Windows Update / WSUS / Intune Update Rings | Software Update / MDM UpdateManifest |
| Security-Only Updates | Windows Update rings support deferral control | `CriticalUpdateInstall = 1` |
| Third-Party Apps | WSUS does not cover; requires SCCM or Intune | App Store auto-update via `com.apple.commerce` |
| Enforcement | Intune Update Ring policy | MDM Software Update payload |
| Audit Command | Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` | `defaults read com.apple.SoftwareUpdate` |

---

## MDM Enforcement Summary

| Capability | Intune (Windows) | Jamf / Intune for macOS |
|---|---|---|
| Password Policy | ✅ Configuration Profile | ✅ Passcode payload |
| Firewall | ✅ Endpoint Security | ✅ Security & Privacy profile |
| Disk Encryption | ✅ Disk Encryption policy | ✅ FileVault payload |
| Screen Lock | ✅ Configuration Profile | ✅ Login Window payload |
| Software Restriction | ✅ AppLocker / WDAC | ✅ Gatekeeper via Restrictions |
| Update Management | ✅ Update Rings | ✅ Software Update payload |
| Remote Access | ✅ Via script/policy | ✅ Via MDM command |

---

## Common Gaps in Mixed-Fleet Environments

These are the most frequently observed hardening gaps when managing Windows and macOS endpoints in parallel:

1. **FileVault not enforced** — BitLocker is often enforced via Intune Endpoint Security while macOS FileVault is left to user discretion. Both platforms need MDM-enforced encryption with key escrow.

2. **macOS audit logging not forwarded to SIEM** — Windows endpoints typically have robust Defender / Sentinel integration. macOS endpoints often have no equivalent pipeline into the SIEM, creating a blind spot.

3. **Screen lock inconsistency** — Windows screen lock may be GPO-enforced while macOS relies on user settings. Enforce via MDM on both platforms.

4. **Remote access residue** — SSH enabled on developer machines "temporarily" becomes permanent. Audit quarterly.

5. **SIP disabled on developer machines** — Developer workflows sometimes require SIP to be disabled. These endpoints need compensating controls and should be clearly inventoried.

---

*Last updated: April 2026 | References: CIS Benchmark Windows 11 v3.0, CIS Apple macOS 14 Sonoma v1.0*
