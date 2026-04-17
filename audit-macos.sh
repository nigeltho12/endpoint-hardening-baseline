#!/usr/bin/env bash
# =============================================================================
# CIS Benchmark Audit Script - macOS
# Endpoint Hardening Baseline | github.com/nigeltho12/endpoint-hardening-baseline
#
# Description:
#   Read-only audit script that checks current endpoint state against CIS
#   Benchmark Level 1 controls for macOS 12+ (Monterey, Ventura, Sonoma).
#
#   This script makes NO changes to the system.
#   Output: PASS / FAIL / MANUAL for each control.
#
# Usage:
#   chmod +x audit-macos.sh
#   sudo ./audit-macos.sh
#
# Author:  Nigel Thompson | github.com/nigeltho12
# Version: 1.0
# Tested:  macOS 12 Monterey, macOS 13 Ventura, macOS 14 Sonoma
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

PASS=0
FAIL=0
MANUAL=0
RESULTS_FILE="./audit-results-macos.csv"

pass()   { echo -e "${GREEN}[PASS]  ${NC} $1"; echo "PASS,$1" >> "$RESULTS_FILE"; ((PASS++)); }
fail()   { echo -e "${RED}[FAIL]  ${NC} $1"; echo "FAIL,$1" >> "$RESULTS_FILE"; ((FAIL++)); }
manual() { echo -e "${YELLOW}[MANUAL]${NC} $1"; echo "MANUAL,$1" >> "$RESULTS_FILE"; ((MANUAL++)); }
section(){ echo -e "\n${CYAN}=== $1 ===${NC}"; }

# Require sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This script must be run with sudo.${NC}"
    exit 1
fi

# Init CSV
echo "Status,Control" > "$RESULTS_FILE"

echo ""
echo -e "${WHITE}CIS macOS Benchmark Audit — Endpoint Hardening Baseline${NC}"
echo -e "${GRAY}Run as: $(logname) | Host: $(hostname) | $(date '+%Y-%m-%d %H:%M')${NC}"
echo ""


# ─────────────────────────────────────────────────────────────────────────────
# 1. Account & Authentication
# ─────────────────────────────────────────────────────────────────────────────
section "1. ACCOUNT & AUTHENTICATION"

# 1.1 — Guest Account Disabled
GUEST=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$GUEST" = "0" ]; then
    pass "1.1 Guest Account: Disabled"
elif [ -z "$GUEST" ]; then
    # Key not present — check via dscl
    GUEST_DSC=$(dscl . read /Users/Guest AuthenticationAuthority 2>&1)
    if echo "$GUEST_DSC" | grep -q "No such key"; then
        pass "1.1 Guest Account: Not configured (disabled)"
    else
        fail "1.1 Guest Account: Key not set — verify manually in System Settings > Users & Groups"
        ((MANUAL--)); ((FAIL--)); manual "1.1 Guest Account: Verify in System Settings"
    fi
else
    fail "1.1 Guest Account: ENABLED (GuestEnabled = $GUEST)"
fi

# 1.2 — Password Complexity (MANUAL — requires MDM or pwpolicy)
PWPOL=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -c "minChars\|requiresAlpha\|requiresNumeric")
if [ "$PWPOL" -gt 0 ]; then
    pass "1.2 Password Policy: Complexity requirements found in pwpolicy"
else
    manual "1.2 Password Policy: No local policy found — verify via MDM/Jamf Passcode payload"
fi

# 1.3 — Password History (MANUAL — MDM enforced)
HIST=$(pwpolicy -getaccountpolicies 2>/dev/null | grep "policyAttributePasswordHistoryDepth")
if [ -n "$HIST" ]; then
    pass "1.3 Password History: Policy present — $HIST"
else
    manual "1.3 Password History: Not set locally — verify via MDM Passcode payload (CIS: 15+)"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 2. Screen Lock & Session Controls
# ─────────────────────────────────────────────────────────────────────────────
section "2. SCREEN LOCK & SESSION CONTROLS"

# 2.1 — Screen Saver Timeout
# Check per-user and system-level setting
SS_DELAY=$(osascript -e 'tell application "System Events" to tell security preferences to get screen saver delay' 2>/dev/null)
if [ -n "$SS_DELAY" ] && [ "$SS_DELAY" -le 1200 ] && [ "$SS_DELAY" -gt 0 ]; then
    pass "2.1 Screen Saver Timeout: ${SS_DELAY}s (CIS: 1200s / 20min or fewer)"
elif [ "$SS_DELAY" = "0" ]; then
    fail "2.1 Screen Saver Timeout: 0 — screen saver disabled"
else
    manual "2.1 Screen Saver Timeout: Could not query via osascript — verify in System Settings > Lock Screen (value: $SS_DELAY)"
fi

# 2.2 — Require Password on Wake
PW_WAKE=$(osascript -e 'tell application "System Events" to tell security preferences to get require password to wake' 2>/dev/null)
if [ "$PW_WAKE" = "true" ]; then
    pass "2.2 Password on Wake: Required"
elif [ "$PW_WAKE" = "false" ]; then
    fail "2.2 Password on Wake: NOT required — endpoints exposed when unattended"
else
    manual "2.2 Password on Wake: Could not query — verify in System Settings > Lock Screen"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 3. macOS Firewall
# ─────────────────────────────────────────────────────────────────────────────
section "3. MACOS FIREWALL"

# 3.1 — Application Firewall State
FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if echo "$FW_STATE" | grep -q "enabled"; then
    pass "3.1 Application Firewall: Enabled"
else
    fail "3.1 Application Firewall: DISABLED — $FW_STATE"
fi

# 3.2 — Stealth Mode
STEALTH=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
if echo "$STEALTH" | grep -q "enabled"; then
    pass "3.2 Stealth Mode: Enabled"
else
    fail "3.2 Stealth Mode: DISABLED — endpoints visible to network probes"
fi

# 3.3 — Block All Incoming (informational)
BLOCKALL=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null)
if echo "$BLOCKALL" | grep -q "ENABLED"; then
    pass "3.3 Block All Incoming: Enabled"
else
    manual "3.3 Block All Incoming: Not enabled — evaluate if appropriate for this endpoint's role"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 4. Encryption — FileVault
# ─────────────────────────────────────────────────────────────────────────────
section "4. ENCRYPTION — FILEVAULT"

# 4.1 — FileVault Status
FV_STATUS=$(fdesetup status 2>/dev/null)
if echo "$FV_STATUS" | grep -q "FileVault is On"; then
    pass "4.1 FileVault: ON — $FV_STATUS"
else
    fail "4.1 FileVault: NOT ENABLED — $FV_STATUS"
fi

# 4.2 — Recovery Key Escrow (MANUAL)
manual "4.2 FileVault Recovery Key Escrow: Verify institutional key or MDM escrow in Jamf/Intune console"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Remote Access
# ─────────────────────────────────────────────────────────────────────────────
section "5. REMOTE ACCESS"

# 5.1 — SSH / Remote Login
SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null)
if echo "$SSH_STATUS" | grep -qi "off"; then
    pass "5.1 Remote Login (SSH): Off"
else
    fail "5.1 Remote Login (SSH): ENABLED — $SSH_STATUS"
fi

# 5.2 — Remote Management (ARD)
ARD_CHECK=$(ps aux | grep -i "ARDAgent" | grep -v grep)
if [ -z "$ARD_CHECK" ]; then
    pass "5.2 Remote Management (ARD): Not running"
else
    manual "5.2 Remote Management (ARD): Process detected — verify if authorized: $ARD_CHECK"
fi

# 5.3 — Internet Sharing
INET_SHARE=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -i "enabled")
if echo "$INET_SHARE" | grep -q "1"; then
    fail "5.3 Internet Sharing: ENABLED — potential unauthorized network bridge"
else
    pass "5.3 Internet Sharing: Disabled or not configured"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 6. Audit Logging
# ─────────────────────────────────────────────────────────────────────────────
section "6. AUDIT LOGGING"

# 6.1 — auditd Running
AUDITD=$(launchctl list 2>/dev/null | grep -i "auditd")
if [ -n "$AUDITD" ]; then
    pass "6.1 Audit Daemon (auditd): Running — $AUDITD"
else
    fail "6.1 Audit Daemon (auditd): NOT running — security events not being captured"
fi

# 6.2 — Audit Log Ownership
if [ -d /var/audit ]; then
    BAD_OWNER=$(ls -l /var/audit/ 2>/dev/null | grep -v "^total" | grep -v "^root")
    ACL_CHECK=$(ls -le /var/audit/ 2>/dev/null | grep -i "access\|allow\|deny")
    if [ -z "$BAD_OWNER" ] && [ -z "$ACL_CHECK" ]; then
        pass "6.2 Audit Log Ownership: Files owned by root, no ACLs present"
    else
        fail "6.2 Audit Log Ownership: Unexpected owner or ACLs found — review /var/audit/"
    fi
else
    manual "6.2 Audit Log Directory: /var/audit not found — verify audit configuration"
fi

# 6.3 — Unified Log Retention
LOG_TEST=$(log show --predicate 'subsystem == "com.apple.securityd"' --last 1h 2>/dev/null | wc -l)
if [ "$LOG_TEST" -gt 5 ]; then
    pass "6.3 Unified Log: Security events retrievable (found $LOG_TEST lines from last 1hr)"
else
    manual "6.3 Unified Log: Few or no recent security events found — verify log retention settings"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 7. Software & Service Hardening
# ─────────────────────────────────────────────────────────────────────────────
section "7. SOFTWARE & SERVICE HARDENING"

# 7.1 — Auto-Login Disabled
AUTO_LOGIN=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -z "$AUTO_LOGIN" ]; then
    pass "7.1 Auto-Login: Disabled (key not set)"
else
    fail "7.1 Auto-Login: ENABLED for user: $AUTO_LOGIN — immediate risk if device is lost/stolen"
fi

# 7.2 — SIP Status
SIP=$(csrutil status 2>/dev/null)
if echo "$SIP" | grep -q "enabled"; then
    pass "7.2 System Integrity Protection (SIP): Enabled"
else
    fail "7.2 System Integrity Protection (SIP): DISABLED — $SIP — investigate immediately"
fi

# 7.3 — Gatekeeper
GK=$(spctl --status 2>/dev/null)
if echo "$GK" | grep -q "assessments enabled"; then
    pass "7.3 Gatekeeper: Enabled"
else
    fail "7.3 Gatekeeper: DISABLED — unsigned apps can execute without restriction"
fi


# ─────────────────────────────────────────────────────────────────────────────
# 8. Automatic Updates
# ─────────────────────────────────────────────────────────────────────────────
section "8. AUTOMATIC UPDATES"

# 8.1 — macOS Security Updates
AUTO_MACOS=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
CRITICAL=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
if [ "$AUTO_MACOS" = "1" ] && [ "$CRITICAL" = "1" ]; then
    pass "8.1 macOS Auto Updates: Enabled (AutomaticallyInstallMacOSUpdates=1, CriticalUpdateInstall=1)"
elif [ "$AUTO_MACOS" = "1" ] || [ "$CRITICAL" = "1" ]; then
    manual "8.1 macOS Auto Updates: Partially configured — AutoInstall=$AUTO_MACOS, Critical=$CRITICAL"
else
    fail "8.1 macOS Auto Updates: NOT configured — endpoints may miss critical security patches"
fi

# 8.2 — App Store Auto Updates
APP_UPDATE=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)
if [ "$APP_UPDATE" = "1" ]; then
    pass "8.2 App Store Auto Updates: Enabled"
else
    fail "8.2 App Store Auto Updates: NOT enabled — App Store apps may have unpatched vulnerabilities"
fi


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + MANUAL))
echo ""
echo -e "${GRAY}$(printf '─%.0s' {1..60})${NC}"
echo -e "${WHITE}AUDIT SUMMARY — $(date '+%Y-%m-%d %H:%M')${NC}"
echo -e "${GRAY}$(printf '─%.0s' {1..60})${NC}"
echo -e "  Total Controls Checked : $TOTAL"
echo -e "  ${GREEN}PASS${NC}                   : $PASS"
echo -e "  ${RED}FAIL${NC}                   : $FAIL"
echo -e "  ${YELLOW}MANUAL CHECK REQUIRED${NC}  : $MANUAL"

if [ $((PASS + FAIL)) -gt 0 ]; then
    SCORE=$(echo "scale=1; ($PASS * 100) / ($PASS + $FAIL)" | bc)
    echo -e "\n  ${CYAN}Compliance Score (Pass/Pass+Fail): ${SCORE}%${NC}"
fi

echo ""
echo -e "${GRAY}Detailed results saved to: $RESULTS_FILE${NC}"
echo -e "Review FAIL and MANUAL items against the CIS checklist:"
echo -e "  ${CYAN}macos/cis-macos-checklist.md${NC}"
echo ""
