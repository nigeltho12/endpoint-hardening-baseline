<#
.SYNOPSIS
    CIS Benchmark Audit Script - Windows
    Endpoint Hardening Baseline | github.com/nigeltho12/endpoint-hardening-baseline

.DESCRIPTION
    Read-only audit script that checks current endpoint state against CIS Benchmark
    Level 1 controls for Windows 10/11.
    
    This script makes NO changes to the system.
    Output: PASS / FAIL / MANUAL for each control.

.NOTES
    Run As:  Administrator
    Tested:  Windows 10 21H2+, Windows 11
    Author:  Nigel Thompson | github.com/nigeltho12
    Version: 1.0

.EXAMPLE
    # From an elevated PowerShell prompt:
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    .\audit-windows.ps1
#>

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

$pass  = 0
$fail  = 0
$manual = 0
$results = @()

function Write-Pass   { param($msg) Write-Host "[PASS]   $msg" -ForegroundColor Green  }
function Write-Fail   { param($msg) Write-Host "[FAIL]   $msg" -ForegroundColor Red    }
function Write-Manual { param($msg) Write-Host "[MANUAL] $msg" -ForegroundColor Yellow }
function Write-Section { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan  }

function Log-Result {
    param($Control, $Status, $Detail)
    $script:results += [PSCustomObject]@{
        Control = $Control
        Status  = $Status
        Detail  = $Detail
    }
    if ($Status -eq "PASS")   { $script:pass++   }
    if ($Status -eq "FAIL")   { $script:fail++   }
    if ($Status -eq "MANUAL") { $script:manual++ }
}

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "`nCIS Windows Benchmark Audit — Endpoint Hardening Baseline" -ForegroundColor White
Write-Host "Run as: $env:USERNAME | Host: $env:COMPUTERNAME | $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n" -ForegroundColor Gray


# ─────────────────────────────────────────────────────────────────────────────
# 1. Account & Authentication
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "1. ACCOUNT & AUTHENTICATION"

# 1.1 — Password History
try {
    $netAccounts = net accounts 2>&1
    $histLine = $netAccounts | Where-Object { $_ -match "password history" }
    $histValue = [int]($histLine -replace ".*:\s*", "")
    if ($histValue -ge 24) {
        Write-Pass "1.1 Password History: $histValue passwords remembered (CIS: 24+)"
        Log-Result "1.1 Password History" "PASS" "$histValue remembered"
    } else {
        Write-Fail "1.1 Password History: $histValue (CIS requires 24+)"
        Log-Result "1.1 Password History" "FAIL" "$histValue — needs 24+"
    }
} catch {
    Write-Manual "1.1 Password History: Could not parse — check manually"
    Log-Result "1.1 Password History" "MANUAL" "Parse error"
}

# 1.2 — Maximum Password Age
try {
    $maxAgeLine = $netAccounts | Where-Object { $_ -match "Maximum password age" }
    $maxAge = [int]($maxAgeLine -replace ".*:\s*", "")
    if ($maxAge -le 365 -and $maxAge -gt 0) {
        Write-Pass "1.2 Max Password Age: $maxAge days (CIS: 365 or fewer)"
        Log-Result "1.2 Max Password Age" "PASS" "$maxAge days"
    } else {
        Write-Fail "1.2 Max Password Age: $maxAge days (CIS: 365 or fewer)"
        Log-Result "1.2 Max Password Age" "FAIL" "$maxAge days"
    }
} catch {
    Write-Manual "1.2 Max Password Age: Could not parse — check manually"
    Log-Result "1.2 Max Password Age" "MANUAL" "Parse error"
}

# 1.3 — Minimum Password Length
try {
    $minLenLine = $netAccounts | Where-Object { $_ -match "Minimum password length" }
    $minLen = [int]($minLenLine -replace ".*:\s*", "")
    if ($minLen -ge 14) {
        Write-Pass "1.3 Min Password Length: $minLen characters (CIS: 14+)"
        Log-Result "1.3 Min Password Length" "PASS" "$minLen characters"
    } else {
        Write-Fail "1.3 Min Password Length: $minLen characters (CIS: 14+)"
        Log-Result "1.3 Min Password Length" "FAIL" "$minLen — needs 14+"
    }
} catch {
    Write-Manual "1.3 Min Password Length: Could not parse — check manually"
    Log-Result "1.3 Min Password Length" "MANUAL" "Parse error"
}

# 1.4 — Account Lockout Threshold
try {
    $lockoutLine = $netAccounts | Where-Object { $_ -match "Lockout threshold" }
    $lockoutVal = $lockoutLine -replace ".*:\s*", ""
    $lockoutNum = [int]$lockoutVal
    if ($lockoutNum -le 5 -and $lockoutNum -gt 0) {
        Write-Pass "1.4 Account Lockout: $lockoutNum attempts (CIS: 5 or fewer)"
        Log-Result "1.4 Account Lockout" "PASS" "$lockoutNum attempts"
    } else {
        Write-Fail "1.4 Account Lockout: $lockoutNum attempts (CIS: 5 or fewer, not 0)"
        Log-Result "1.4 Account Lockout" "FAIL" "$lockoutNum — needs 1-5"
    }
} catch {
    Write-Manual "1.4 Account Lockout: Could not parse — check manually"
    Log-Result "1.4 Account Lockout" "MANUAL" "Parse error"
}

# 1.5 — Guest Account Disabled
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
    if ($guest.Enabled -eq $false) {
        Write-Pass "1.5 Guest Account: Disabled"
        Log-Result "1.5 Guest Account" "PASS" "Disabled"
    } else {
        Write-Fail "1.5 Guest Account: ENABLED — should be disabled"
        Log-Result "1.5 Guest Account" "FAIL" "Account is enabled"
    }
} catch {
    Write-Pass "1.5 Guest Account: Not found (effectively disabled)"
    Log-Result "1.5 Guest Account" "PASS" "Account not present"
}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Screen Lock & Session Controls
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "2. SCREEN LOCK & SESSION CONTROLS"

# 2.1 — Screen Saver Timeout
try {
    $timeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction Stop).ScreenSaveTimeOut
    if ([int]$timeout -le 900) {
        Write-Pass "2.1 Screen Saver Timeout: $timeout seconds (CIS: 900s or fewer)"
        Log-Result "2.1 Screen Saver Timeout" "PASS" "$timeout seconds"
    } else {
        Write-Fail "2.1 Screen Saver Timeout: $timeout seconds (CIS: 900s or fewer)"
        Log-Result "2.1 Screen Saver Timeout" "FAIL" "$timeout seconds"
    }
} catch {
    Write-Fail "2.1 Screen Saver Timeout: Key not found — not configured"
    Log-Result "2.1 Screen Saver Timeout" "FAIL" "Registry key missing"
}

# 2.2 — Screen Saver Password Required
try {
    $ssSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction Stop).ScreenSaverIsSecure
    if ($ssSecure -eq "1") {
        Write-Pass "2.2 Screen Saver Password: Required on resume"
        Log-Result "2.2 Screen Saver Password" "PASS" "Password required"
    } else {
        Write-Fail "2.2 Screen Saver Password: NOT required on resume"
        Log-Result "2.2 Screen Saver Password" "FAIL" "ScreenSaverIsSecure = $ssSecure"
    }
} catch {
    Write-Fail "2.2 Screen Saver Password: Key not found — not configured"
    Log-Result "2.2 Screen Saver Password" "FAIL" "Registry key missing"
}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Windows Firewall
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "3. WINDOWS FIREWALL"

foreach ($profile in @("Domain", "Private", "Public")) {
    try {
        $fw = (Get-NetFirewallProfile -Profile $profile -ErrorAction Stop).Enabled
        if ($fw) {
            Write-Pass "3.$($profile) Firewall ($profile profile): Enabled"
            Log-Result "3. Firewall - $profile" "PASS" "Enabled"
        } else {
            Write-Fail "3.$($profile) Firewall ($profile profile): DISABLED"
            Log-Result "3. Firewall - $profile" "FAIL" "Disabled"
        }
    } catch {
        Write-Manual "3. Firewall ($profile): Could not query — check manually"
        Log-Result "3. Firewall - $profile" "MANUAL" "Query failed"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# 4. Encryption — BitLocker
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "4. ENCRYPTION — BITLOCKER"

# 4.1 — BitLocker on OS Drive
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($bl.ProtectionStatus -eq "On") {
        Write-Pass "4.1 BitLocker: Protection is ON for C:"
        Log-Result "4.1 BitLocker Status" "PASS" "Protection On"
    } else {
        Write-Fail "4.1 BitLocker: Protection is OFF for C: — Status: $($bl.ProtectionStatus)"
        Log-Result "4.1 BitLocker Status" "FAIL" "Protection Off or Suspended"
    }
} catch {
    Write-Manual "4.1 BitLocker: Could not query (BitLocker cmdlet not available). Run: manage-bde -status C:"
    Log-Result "4.1 BitLocker Status" "MANUAL" "Cmdlet unavailable"
}

# 4.2 — Recovery Key Present
try {
    $blVol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    $recoveryKey = $blVol.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
    if ($recoveryKey) {
        Write-Pass "4.2 BitLocker Recovery Key: Recovery password protector present"
        Log-Result "4.2 BitLocker Recovery Key" "PASS" "Recovery protector found"
    } else {
        Write-Fail "4.2 BitLocker Recovery Key: No recovery password protector found"
        Log-Result "4.2 BitLocker Recovery Key" "FAIL" "No recovery protector"
    }
} catch {
    Write-Manual "4.2 BitLocker Recovery Key: Verify recovery key escrow in Intune/Azure AD"
    Log-Result "4.2 BitLocker Recovery Key" "MANUAL" "Cmdlet unavailable"
}


# ─────────────────────────────────────────────────────────────────────────────
# 5. Remote Access
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "5. REMOTE ACCESS"

# 5.1 — RDP Disabled
try {
    $rdpKey = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections
    if ($rdpKey -eq 1) {
        Write-Pass "5.1 Remote Desktop: Disabled (fDenyTSConnections = 1)"
        Log-Result "5.1 RDP Status" "PASS" "RDP disabled"
    } else {
        Write-Fail "5.1 Remote Desktop: ENABLED (fDenyTSConnections = $rdpKey)"
        Log-Result "5.1 RDP Status" "FAIL" "RDP enabled — evaluate if required"
    }
} catch {
    Write-Manual "5.1 Remote Desktop: Registry key not found — check System Properties"
    Log-Result "5.1 RDP Status" "MANUAL" "Key not found"
}

# 5.2 — RDP Requires NLA
try {
    $nla = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction Stop).UserAuthentication
    if ($nla -eq 1) {
        Write-Pass "5.2 RDP NLA: Network Level Authentication required"
        Log-Result "5.2 RDP NLA" "PASS" "NLA required"
    } else {
        Write-Fail "5.2 RDP NLA: NLA NOT required — UserAuthentication = $nla"
        Log-Result "5.2 RDP NLA" "FAIL" "NLA not enforced"
    }
} catch {
    Write-Manual "5.2 RDP NLA: Could not read — check System Properties > Remote tab"
    Log-Result "5.2 RDP NLA" "MANUAL" "Key not found"
}


# ─────────────────────────────────────────────────────────────────────────────
# 6. Audit Logging
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "6. AUDIT LOGGING"

$auditChecks = @(
    @{ Name = "6.1 Credential Validation"; SubCategory = "Credential Validation" },
    @{ Name = "6.2 Logon Events";          SubCategory = "Logon" },
    @{ Name = "6.3 Process Creation";      SubCategory = "Process Creation" }
)

foreach ($check in $auditChecks) {
    try {
        $auditResult = (auditpol /get /subcategory:"$($check.SubCategory)" 2>&1) | Where-Object { $_ -match $check.SubCategory }
        if ($auditResult -match "Success and Failure" -or ($check.Name -match "Process" -and $auditResult -match "Success")) {
            Write-Pass "$($check.Name): $auditResult".Trim()
            Log-Result $check.Name "PASS" $auditResult.Trim()
        } else {
            Write-Fail "$($check.Name): $auditResult (insufficient)"
            Log-Result $check.Name "FAIL" $auditResult.Trim()
        }
    } catch {
        Write-Manual "$($check.Name): Could not query auditpol — check manually"
        Log-Result $check.Name "MANUAL" "auditpol query failed"
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# 7. Software & Service Hardening
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "7. SOFTWARE & SERVICE HARDENING"

# 7.1 — AutoRun Disabled
try {
    $autoRun = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction Stop).NoDriveTypeAutoRun
    if ($autoRun -eq 255) {
        Write-Pass "7.1 AutoRun: Disabled for all drive types (NoDriveTypeAutoRun = 255)"
        Log-Result "7.1 AutoRun" "PASS" "255 — all drives disabled"
    } else {
        Write-Fail "7.1 AutoRun: Value = $autoRun (CIS requires 255 for all drives)"
        Log-Result "7.1 AutoRun" "FAIL" "Value: $autoRun"
    }
} catch {
    Write-Fail "7.1 AutoRun: Registry key not found — AutoRun policy not configured"
    Log-Result "7.1 AutoRun" "FAIL" "Key missing"
}

# 7.2 — Defender Real-Time Protection
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($defenderStatus.RealTimeProtectionEnabled) {
        Write-Pass "7.2 Defender Real-Time Protection: Enabled"
        Log-Result "7.2 Defender RTP" "PASS" "Enabled"
    } else {
        Write-Fail "7.2 Defender Real-Time Protection: DISABLED"
        Log-Result "7.2 Defender RTP" "FAIL" "Disabled"
    }
} catch {
    Write-Manual "7.2 Defender Real-Time Protection: Could not query — check Windows Security"
    Log-Result "7.2 Defender RTP" "MANUAL" "Query failed"
}


# ─────────────────────────────────────────────────────────────────────────────
# 8. Automatic Updates
# ─────────────────────────────────────────────────────────────────────────────
Write-Section "8. AUTOMATIC UPDATES"

# 8.1 — Windows Update AU Options
try {
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $auOpt = (Get-ItemProperty -Path $wuPath -Name "AUOptions" -ErrorAction Stop).AUOptions
    if ($auOpt -eq 4) {
        Write-Pass "8.1 Windows Update: Auto-download and schedule install (AUOptions = 4)"
        Log-Result "8.1 Windows Update" "PASS" "AUOptions = 4"
    } else {
        Write-Fail "8.1 Windows Update: AUOptions = $auOpt (CIS requires 4)"
        Log-Result "8.1 Windows Update" "FAIL" "AUOptions = $auOpt"
    }
} catch {
    Write-Manual "8.1 Windows Update: Policy key not found — may be managed via Intune Update Ring"
    Log-Result "8.1 Windows Update" "MANUAL" "Policy key not present — verify in Intune"
}


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
$total = $pass + $fail + $manual

Write-Host "`n" + ("─" * 60) -ForegroundColor Gray
Write-Host "AUDIT SUMMARY — $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host ("─" * 60) -ForegroundColor Gray
Write-Host "  Total Controls Checked : $total" -ForegroundColor White
Write-Host "  PASS                   : $pass"   -ForegroundColor Green
Write-Host "  FAIL                   : $fail"   -ForegroundColor Red
Write-Host "  MANUAL CHECK REQUIRED  : $manual" -ForegroundColor Yellow

if ($total -gt 0) {
    $score = [math]::Round(($pass / ($pass + $fail)) * 100, 1)
    Write-Host "`n  Compliance Score (Pass/Pass+Fail): $score%" -ForegroundColor Cyan
}

Write-Host "`nDetailed results saved to: .\audit-results.csv" -ForegroundColor Gray
$results | Export-Csv -Path ".\audit-results.csv" -NoTypeInformation

Write-Host "`nReview FAIL and MANUAL items against the CIS checklist:"
Write-Host "  windows/cis-windows-checklist.md" -ForegroundColor Cyan
