# macOS CIS Benchmark Hardening Checklist
### CIS Apple macOS 14.0 Sonoma Benchmark v1.0 — Level 1 Profile

> **Scope:** These controls apply to enterprise-managed macOS endpoints. In environments using Jamf Pro or Microsoft Intune for macOS, most of these settings can be enforced via Configuration Profiles. Controls marked `[Profile]` can be deployed via MDM configuration profile.

---

## 1. Account & Authentication Policies

### 1.1 — Disable Guest Account
**CIS Control:** Ensure Guest account is disabled  
**Why it matters:** The macOS guest account allows unauthenticated access to a Safari session and certain applications. On shared or semi-public machines this creates data exposure risk and bypasses endpoint security controls.  
**Audit:**
```bash
sudo defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "Key not set (Guest may be enabled)"
```
**Expected:** `0`  
**Enforcement:** `[Profile]` Restrictions payload > Disable guest account

---

### 1.2 — Password Complexity Requirements
**CIS Control:** Require complex passwords — minimum 15 characters, upper, lower, number, special  
**Why it matters:** macOS local account passwords are a fallback authentication path even in environments using SSO. Weak local passwords can be exploited during offline attacks or when network authentication is unavailable.  
**Audit:**
```bash
pwpolicy -getaccountpolicies 2>/dev/null | grep -E "minChars|requiresAlpha|requiresNumeric"
```
**Expected:** Policy should include minimum length and complexity requirements  
**Enforcement:** `[Profile]` Passcode payload in MDM

---

### 1.3 — Password Reuse Restrictions
**CIS Control:** Prohibit password reuse — 15 or more previous passwords  
**Why it matters:** Password reuse allows compromised credentials to remain valid after a reset. This is particularly relevant in phishing and credential stuffing scenarios.  
**Audit:**
```bash
pwpolicy -getaccountpolicies | grep "policyAttributePasswordHistoryDepth"
```
**Expected:** Value of `15` or greater  
**Enforcement:** `[Profile]` Passcode payload > Password History

---

## 2. Screen Lock & Session Controls

### 2.1 — Screen Saver Inactivity Timeout
**CIS Control:** Screen saver timeout — 20 minutes or fewer  
**Why it matters:** Unattended unlocked sessions are one of the most overlooked physical security risks. An unlocked MacBook left at a desk or in a shared space is an open door.  
**Audit:**
```bash
osascript -e 'tell application "System Events" to tell security preferences to get screen saver delay'
```
**Expected:** `1200` (20 minutes) or less  
**Enforcement:** `[Profile]` Login Window payload > Screen Saver settings

---

### 2.2 — Require Password on Wake
**CIS Control:** Require password immediately after screen saver begins or display sleeps  
**Why it matters:** Screen lock without a password requirement is theater. This control ensures the session is actually protected when the screen locks.  
**Audit:**
```bash
osascript -e 'tell application "System Events" to tell security preferences to get require password to wake'
```
**Expected:** `true`  
**Enforcement:** `[Profile]` Login Window payload > Require password

---

## 3. macOS Firewall

### 3.1 — Application Firewall Enabled
**CIS Control:** Ensure Application Firewall is enabled  
**Why it matters:** The macOS Application Firewall controls inbound connections on a per-application basis. Enabling it prevents unauthorized applications and services from accepting inbound network connections.  
**Audit:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```
**Expected:** `Firewall is enabled.`  
**Enforcement:** `[Profile]` Security & Privacy > Firewall payload

---

### 3.2 — Stealth Mode Enabled
**CIS Control:** Enable Firewall Stealth Mode  
**Why it matters:** Stealth mode prevents the system from responding to ICMP ping requests and port probes from unauthorized networks. This makes the endpoint harder to discover and enumerate during reconnaissance.  
**Audit:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
```
**Expected:** `Stealth mode enabled`  
**Enforcement:** `[Profile]` Security & Privacy > Firewall > Enable Stealth Mode

---

### 3.3 — Block All Incoming Connections (Where Applicable)
**CIS Control:** Enable option to block all incoming connections  
**Why it matters:** On endpoints that do not need to accept inbound connections (most workstations), blocking all inbound traffic is the simplest and most effective firewall posture.  
**Audit:**
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
```
**Expected:** `Block all INCOMING connections enabled` (evaluate per use case)  
**Note:** May not be appropriate for endpoints running shared services. Evaluate before enforcing broadly.

---

## 4. Encryption — FileVault

### 4.1 — FileVault Enabled
**CIS Control:** Ensure FileVault is enabled  
**Why it matters:** FileVault encrypts the entire startup disk. On a stolen or lost MacBook, an attacker without the decryption key cannot read any data on the drive — including credentials stored in Keychain, corporate documents, or cached browser sessions.  
**Audit:**
```bash
fdesetup status
```
**Expected:** `FileVault is On.`  
**Enforcement:** `[Profile]` FileVault payload in MDM — configure key escrow to institutional key or iCloud

---

### 4.2 — FileVault Recovery Key Escrowed
**CIS Control:** Ensure FileVault recovery key is escrowed to MDM  
**Why it matters:** Without a recovery key in escrow, a forgotten password or hardware issue permanently destroys access to the encrypted data. Recovery key management is part of any enterprise encryption program.  
**Audit (Jamf):**
```bash
# Verify via Jamf Pro > Computer > FileVault Recovery Key
# Or check via API: /JSSResource/computers/id/{id}/FileVaultRecoveryKey
```
**Note:** This is a `[MANUAL]` check — verify in your MDM console  
**Enforcement:** `[Profile]` FileVault payload > Escrow key to MDM

---

## 5. Remote Access

### 5.1 — Remote Login (SSH) Disabled
**CIS Control:** Ensure Remote Login is disabled  
**Why it matters:** SSH open on an endpoint is a significant attack surface, especially on a portable device. If SSH is not required for day-to-day operations, it should be off. Attackers commonly scan for SSH on non-standard ports.  
**Audit:**
```bash
sudo systemsetup -getremotelogin
```
**Expected:** `Remote Login: Off`  
**Enforcement:** `[Profile]` System Preferences > Sharing — disable Remote Login

---

### 5.2 — Remote Management (ARD) Disabled
**CIS Control:** Ensure Remote Management is disabled unless required  
**Why it matters:** Apple Remote Desktop and remote management services provide full screen control and administrative access. If not actively managed and monitored, this is a high-value target for attackers seeking persistent access.  
**Audit:**
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>/dev/null || echo "ARD not running"
```
**Expected:** ARD not running or disabled  
**Enforcement:** System Preferences > Sharing > Remote Management — disable

---

### 5.3 — Internet Sharing Disabled
**CIS Control:** Ensure Internet Sharing is disabled  
**Why it matters:** Internet Sharing turns a macOS endpoint into a wireless access point or network bridge. On a corporate endpoint, this could allow untrusted devices to connect to the corporate network through a managed machine.  
**Audit:**
```bash
sudo systemsetup -getnetworktimeserver 2>/dev/null
defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -i enabled
```
**Expected:** Internet sharing not enabled  
**Enforcement:** System Preferences > Sharing — disable Internet Sharing

---

## 6. Audit Logging

### 6.1 — Audit Logging Enabled (auditd)
**CIS Control:** Ensure audit logging is enabled and configured  
**Why it matters:** macOS includes a BSM (Basic Security Module) audit subsystem. Without it enabled, there is no reliable log trail for security events — authentication, privilege escalation, file access — making incident response and forensics significantly harder.  
**Audit:**
```bash
sudo launchctl list | grep -i auditd
```
**Expected:** `com.apple.auditd` present and running  
**Enforcement:** Enable via `/etc/security/audit_control` configuration

---

### 6.2 — Audit Log Retention
**CIS Control:** Audit log files must not contain access control lists and must be owned by root  
**Why it matters:** If audit logs can be modified or deleted by non-root users, an attacker can cover their tracks by wiping the evidence of their activity.  
**Audit:**
```bash
ls -le /var/audit/
```
**Expected:** Files owned by `root:wheel`, no ACLs present  
**Enforcement:** Verify via cron or endpoint management tooling

---

### 6.3 — Unified Log — Security Events Retained
**CIS Control:** Ensure security audit logs are retained for sufficient duration  
**Why it matters:** Log retention is a compliance requirement for most frameworks (HIPAA, PCI, SOC 2). Short retention windows mean events needed for incident response may be gone before they are needed.  
**Audit:**
```bash
log show --predicate 'subsystem == "com.apple.securityd"' --last 7d | head -20
```
**Expected:** Events visible and retrievable for the past 7 days at minimum  
**Note:** For longer retention, forward to a SIEM (Splunk, Sentinel, Datadog)

---

## 7. Software & Service Hardening

### 7.1 — Automatic Login Disabled
**CIS Control:** Ensure Auto-login is disabled  
**Why it matters:** Auto-login bypasses all authentication controls. A lost or stolen MacBook with auto-login enabled gives immediate, full access to all data and applications.  
**Audit:**
```bash
sudo defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "Auto-login not configured (PASS)"
```
**Expected:** Key not present / error (auto-login not configured)  
**Enforcement:** `[Profile]` Login Window payload > Disable automatic login

---

### 7.2 — System Integrity Protection (SIP) Enabled
**CIS Control:** Ensure SIP is enabled  
**Why it matters:** SIP prevents even root-level processes from modifying protected system files and directories. Disabling it is a common persistence technique for malware on macOS. Legitimate enterprise use cases for disabling SIP are rare.  
**Audit:**
```bash
csrutil status
```
**Expected:** `System Integrity Protection status: enabled.`  
**Note:** SIP cannot be enforced via MDM profile — must be verified and cannot be remotely re-enabled if disabled. Flag any endpoint where SIP is disabled for immediate investigation.

---

### 7.3 — Gatekeeper Enabled
**CIS Control:** Ensure Gatekeeper is enabled  
**Why it matters:** Gatekeeper enforces code signing and notarization requirements for applications. It is the primary control preventing unsigned or malicious applications from running without user override.  
**Audit:**
```bash
spctl --status
```
**Expected:** `assessments enabled`  
**Enforcement:** `[Profile]` Restrictions payload > Gatekeeper settings

---

## 8. Automatic Updates

### 8.1 — Automatic Security Updates Enabled
**CIS Control:** Ensure automatic security updates are enabled  
**Why it matters:** macOS security updates patch actively exploited vulnerabilities. Security-only updates (as distinct from feature updates) carry low risk and high value — they should be applied automatically.  
**Audit:**
```bash
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null
defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null
```
**Expected:** Both values `1`  
**Enforcement:** `[Profile]` Software Update payload in MDM

---

### 8.2 — App Store Automatic Updates Enabled
**CIS Control:** Ensure App Store automatic updates are enabled  
**Why it matters:** Third-party applications installed via the App Store are a significant attack surface. Keeping them updated closes known vulnerabilities in browsers, productivity tools, and utilities.  
**Audit:**
```bash
defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null
```
**Expected:** `1`  
**Enforcement:** `[Profile]` Software Update payload > App Store updates

---

*Last updated: April 2026 | Reference: CIS Apple macOS 14.0 Sonoma Benchmark v1.0*
