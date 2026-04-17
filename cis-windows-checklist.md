# Windows CIS Benchmark Hardening Checklist
### CIS Microsoft Windows 11 Benchmark v3.0 — Level 1 Profile

> **Scope:** These controls apply to enterprise-managed Windows 10/11 endpoints. In environments using Microsoft Intune, most of these settings can be enforced via Configuration Profiles or Security Baselines. Controls marked `[GPO]` can be enforced via Group Policy.

---

## 1. Account & Authentication Policies

### 1.1 — Password History
**CIS Control:** Enforce password history — 24 or more passwords remembered  
**Why it matters:** Prevents users from cycling back to previously compromised credentials. Attackers who obtain a hash from an old breach may attempt to reuse it.  
**Audit:**
```powershell
net accounts | Select-String "password history"
```
**Expected:** `Length of password history maintained: 24`  
**Enforcement:** `[GPO]` Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy

---

### 1.2 — Maximum Password Age
**CIS Control:** Maximum password age — 365 days or fewer  
**Why it matters:** Limits the window of exposure if credentials are silently compromised. Shorter rotation cycles reduce dwell time for credential-based attacks.  
**Audit:**
```powershell
net accounts | Select-String "Maximum password age"
```
**Expected:** `Maximum password age (days): 365` or less  
**Enforcement:** `[GPO]` Account Policies > Password Policy

---

### 1.3 — Minimum Password Length
**CIS Control:** Minimum password length — 14 or more characters  
**Why it matters:** Longer passwords increase the computational cost of brute-force and dictionary attacks dramatically. Each additional character multiplies the search space.  
**Audit:**
```powershell
net accounts | Select-String "Minimum password length"
```
**Expected:** `Minimum password length: 14`  
**Enforcement:** `[GPO]` Account Policies > Password Policy

---

### 1.4 — Account Lockout Policy
**CIS Control:** Account lockout threshold — 5 or fewer invalid attempts  
**Why it matters:** Prevents automated password spraying attacks. Without lockout, attackers can attempt thousands of passwords without detection.  
**Audit:**
```powershell
net accounts | Select-String "Lockout threshold"
```
**Expected:** `Lockout threshold: 5`  
**Enforcement:** `[GPO]` Account Policies > Account Lockout Policy

---

### 1.5 — Guest Account Disabled
**CIS Control:** Ensure Guest account is disabled  
**Why it matters:** The Guest account provides unauthenticated access to the system. Even with limited permissions, it represents an unnecessary attack surface.  
**Audit:**
```powershell
Get-LocalUser -Name "Guest" | Select-Object Name, Enabled
```
**Expected:** `Enabled: False`  
**Enforcement:** `[GPO]` Security Settings > Local Policies > Security Options

---

## 2. Screen Lock & Session Controls

### 2.1 — Screen Saver Timeout
**CIS Control:** Screen saver timeout — 900 seconds (15 minutes) or fewer  
**Why it matters:** Unattended unlocked sessions are a physical security risk. An unlocked workstation in a shared or office environment can be accessed by anyone.  
**Audit:**
```powershell
Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut"
```
**Expected:** Value of `900` or less  
**Enforcement:** `[GPO]` User Configuration > Administrative Templates > Control Panel > Personalization

---

### 2.2 — Screen Saver Password Protected
**CIS Control:** Require password on screen saver resume  
**Why it matters:** Screen saver alone without password protection provides no access control — any user can simply move the mouse to resume the session.  
**Audit:**
```powershell
Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure"
```
**Expected:** `ScreenSaverIsSecure: 1`  
**Enforcement:** `[GPO]` User Configuration > Administrative Templates > Control Panel > Personalization

---

## 3. Windows Firewall

### 3.1 — Domain Profile Firewall Enabled
**CIS Control:** Windows Firewall Domain Profile — State: On  
**Why it matters:** The domain profile controls firewall behavior when the device is connected to a corporate network. Disabling it exposes all services to lateral movement from compromised peers.  
**Audit:**
```powershell
(Get-NetFirewallProfile -Profile Domain).Enabled
```
**Expected:** `True`  
**Enforcement:** `[GPO]` Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall

---

### 3.2 — Private Profile Firewall Enabled
**CIS Control:** Windows Firewall Private Profile — State: On  
**Why it matters:** Protects the endpoint on home or trusted networks where other devices may be less secure. Remote workers are a common entry point for lateral movement.  
**Audit:**
```powershell
(Get-NetFirewallProfile -Profile Private).Enabled
```
**Expected:** `True`

---

### 3.3 — Public Profile Firewall Enabled
**CIS Control:** Windows Firewall Public Profile — State: On  
**Why it matters:** Public networks (coffee shops, hotels, airports) are high-risk. The public profile applies the most restrictive rules and should never be disabled.  
**Audit:**
```powershell
(Get-NetFirewallProfile -Profile Public).Enabled
```
**Expected:** `True`

---

## 4. Encryption — BitLocker

### 4.1 — BitLocker Enabled on OS Drive
**CIS Control:** Ensure BitLocker is enabled on the operating system drive  
**Why it matters:** Full-disk encryption prevents data access if a device is physically stolen or the drive is removed. Without it, an attacker with physical access can read the entire drive by booting from external media.  
**Audit:**
```powershell
manage-bde -status C:
```
**Expected:** `Protection Status: Protection On`  
**Enforcement:** Intune Endpoint Security > Disk Encryption Policy

---

### 4.2 — BitLocker Recovery Key Backed Up
**CIS Control:** BitLocker recovery information backed up to Azure AD / Active Directory  
**Why it matters:** Without a recovery key backup, a single TPM failure or Windows update can permanently lock users out of their data.  
**Audit:**
```powershell
(Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}
```
**Expected:** Recovery password protector present  
**Enforcement:** Intune Endpoint Security > Disk Encryption — configure escrow to Azure AD

---

## 5. Remote Access

### 5.1 — Remote Desktop Disabled (Unless Required)
**CIS Control:** Ensure Remote Desktop Services are disabled if not in use  
**Why it matters:** RDP (port 3389) is one of the most commonly exploited services in ransomware attacks and brute-force campaigns. If it is not needed, it should not be running.  
**Audit:**
```powershell
(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
```
**Expected:** `1` (RDP disabled)  
**Enforcement:** `[GPO]` Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services

---

### 5.2 — Remote Desktop NLA Required
**CIS Control:** Require Network Level Authentication for RDP  
**Why it matters:** NLA forces authentication before a full RDP session is established. This prevents unauthenticated exposure of the Windows login screen, which itself can be a vector for credential attacks.  
**Audit:**
```powershell
(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication").UserAuthentication
```
**Expected:** `1` (NLA required)

---

## 6. Audit Logging

### 6.1 — Audit Account Logon Events
**CIS Control:** Audit Credential Validation — Success and Failure  
**Why it matters:** Logon event auditing is the foundation of threat detection. Without it, you cannot identify brute-force attempts, credential stuffing, or lateral movement in your logs.  
**Audit:**
```powershell
auditpol /get /subcategory:"Credential Validation"
```
**Expected:** `Success and Failure`  
**Enforcement:** `[GPO]` Computer Configuration > Security Settings > Advanced Audit Policy

---

### 6.2 — Audit Logon Events
**CIS Control:** Audit Logon/Logoff — Success and Failure  
**Why it matters:** Captures interactive and network logons. Essential for correlating user activity with security events in a SIEM.  
**Audit:**
```powershell
auditpol /get /subcategory:"Logon"
```
**Expected:** `Success and Failure`

---

### 6.3 — Audit Process Creation
**CIS Control:** Audit Process Creation — Success  
**Why it matters:** Process creation logging is critical for detecting malware execution, LOLBins (living-off-the-land binaries), and PowerShell abuse. This feeds directly into EDR and SIEM detections.  
**Audit:**
```powershell
auditpol /get /subcategory:"Process Creation"
```
**Expected:** `Success`

---

## 7. Software & Service Hardening

### 7.1 — AutoRun Disabled for All Drives
**CIS Control:** Disable Autorun for all drive types  
**Why it matters:** AutoRun was the primary delivery mechanism for early USB malware (e.g., Stuxnet). Even on modern systems, automated execution from removable media is unnecessary and dangerous.  
**Audit:**
```powershell
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
```
**Expected:** `255` (all drives disabled)  
**Enforcement:** `[GPO]` Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies

---

### 7.2 — Windows Defender Antivirus — Real-Time Protection
**CIS Control:** Ensure real-time protection is enabled  
**Why it matters:** Real-time scanning is the last line of defense against malware execution. Disabling it is a common attacker technique after initial access.  
**Audit:**
```powershell
(Get-MpComputerStatus).RealTimeProtectionEnabled
```
**Expected:** `True`

---

## 8. Automatic Updates

### 8.1 — Windows Update — Automatic Download and Install
**CIS Control:** Configure automatic updates  
**Why it matters:** Unpatched systems are the most common root cause of successful exploits. Security patches for actively exploited vulnerabilities are often released days or weeks before attacks begin leveraging them.  
**Audit:**
```powershell
(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue).AUOptions
```
**Expected:** `4` (Auto download and schedule install)  
**Enforcement:** Intune Device Configuration > Windows Update Ring

---

*Last updated: April 2026 | Reference: CIS Microsoft Windows 11 Benchmark v3.0*
