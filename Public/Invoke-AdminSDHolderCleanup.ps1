<#
.SYNOPSIS
    Audits and remediates orphaned AdminSDHolder (AdminCount=1) accounts.

.DESCRIPTION
    Identifies users with AdminCount=1 who are no longer members of any protected
    group and optionally resets AdminCount to 0 and restores ACL inheritance.

    Uses Well-Known SIDs (not group names) for language-agnostic AD operations.
    Primary group membership is resolved by direct SID construction (no regex),
    and the protected-SID lookup uses a HashSet for O(1) per-user performance.

.PARAMETER Remediate
    Actively cleans up orphaned accounts. Prompts for confirmation.
    Without this switch the script runs read-only (audit mode).

.EXAMPLE
    .\Invoke-AdminSDHolderCleanup.ps1

.EXAMPLE
    .\Invoke-AdminSDHolderCleanup.ps1 -Remediate

.AUTHOR
    franckferman
#>

param (
    [switch]$Remediate
)

$AuditOnly = -not $Remediate.IsPresent

# Auto-load Private helpers when running from the standard toolkit layout
$_Private = Join-Path $PSScriptRoot '..' 'Private'
$_Constants = Join-Path $_Private 'Constants.ps1'
$_Helpers   = Join-Path $_Private 'Helpers.ps1'
if (Test-Path $_Constants) { . $_Constants }
if (Test-Path $_Helpers)   { . $_Helpers }

function Invoke-AdminSDHolderCleanup {
    param (
        [switch]$Remediate
    )

    $AuditOnly = -not $Remediate.IsPresent

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " AdminSDHolder Cleanup (SID-Based)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # Domain context
    try {
        if (Get-Command Get-DomainContext -ErrorAction SilentlyContinue) {
            $Ctx = Get-DomainContext
            $DomainSID = $Ctx.DomainSID
        }
        else {
            $Domain    = Get-ADDomain
            $DomainSID = $Domain.DomainSID.Value
        }
    }
    catch {
        Write-Host "[!] ERROR: Failed to query domain: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Protected group RIDs (load from Constants if available, else inline)
    if ($Script:ProtectedDomainRIDs) {
        $ProtectedDomainRIDs  = $Script:ProtectedDomainRIDs
        $ProtectedBuiltinRIDs = $Script:ProtectedBuiltinRIDs
        $SafeListRIDs         = $Script:SafeListRIDs
    }
    else {
        $ProtectedDomainRIDs  = @("512", "517", "518", "519")
        $ProtectedBuiltinRIDs = @("544", "548", "549", "550", "551")
        $SafeListRIDs         = @("500", "502")
    }

    # Build a flat list of all protected SIDs (used for PrimaryGroup lookup)
    $ProtectedSIDs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($RID in $ProtectedDomainRIDs)  { $ProtectedSIDs.Add("$DomainSID-$RID")   | Out-Null }
    foreach ($RID in $ProtectedBuiltinRIDs) { $ProtectedSIDs.Add("S-1-5-32-$RID")     | Out-Null }

    # SafeList: accounts never touched
    $SafeList = $SafeListRIDs | ForEach-Object { "$DomainSID-$_" }

    # Resolve protected groups to DNs (for MemberOf comparison)
    Write-Host "`n[*] Resolving protected groups... " -NoNewline
    $GroupsDN = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($SID in $ProtectedSIDs) {
        try {
            $g = Get-ADGroup -Identity $SID -ErrorAction Stop
            $GroupsDN.Add($g.DistinguishedName) | Out-Null
        }
        catch {
            Write-Host "`n  [!] Could not resolve SID: $SID" -ForegroundColor Yellow
        }
    }
    Write-Host "Done ($($GroupsDN.Count) groups)." -ForegroundColor Green

    # Fetch all AdminCount=1 users
    Write-Host "[*] Searching for users with AdminCount=1... " -NoNewline
    try {
        $AdminUsers = Get-ADUser -Filter { AdminCount -eq 1 } `
            -Properties AdminCount, MemberOf, PrimaryGroupId -ErrorAction Stop
    }
    catch {
        Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
    Write-Host "Found $($AdminUsers.Count) users." -ForegroundColor Yellow

    $UsersToClean = @()
    $LegitAdmins  = @()

    foreach ($User in $AdminUsers) {
        # Skip SafeList
        if ($SafeList -contains $User.SID.Value) {
            $LegitAdmins += $User
            continue
        }

        $IsProtected = $false

        # Check direct group membership (MemberOf)
        if ($User.MemberOf) {
            foreach ($DN in $User.MemberOf) {
                if ($GroupsDN.Contains($DN)) {
                    $IsProtected = $true
                    break
                }
            }
        }

        # Check Primary Group — construct SID directly, no regex
        if (-not $IsProtected -and $User.PrimaryGroupId) {
            $PrimaryGroupSID = "$DomainSID-$($User.PrimaryGroupId)"
            if ($ProtectedSIDs.Contains($PrimaryGroupSID)) {
                $IsProtected = $true
            }
        }

        if ($IsProtected) { $LegitAdmins  += $User }
        else              { $UsersToClean += $User }
    }

    # Results
    Write-Host "`n--- AUDIT RESULTS ---" -ForegroundColor Cyan
    Write-Host "Legitimate admins (still in protected group): $($LegitAdmins.Count)" -ForegroundColor Green
    Write-Host "Orphaned accounts (AdminCount=1, no protected group): $($UsersToClean.Count)" -ForegroundColor Red

    if ($UsersToClean.Count -eq 0) {
        Write-Host "`n[+] No orphaned accounts found." -ForegroundColor Green
        return
    }

    $UsersToClean | Select-Object Name, SamAccountName, SID | Format-Table -AutoSize

    if ($AuditOnly) {
        Write-Host "[i] Run with -Remediate to clean up these accounts." -ForegroundColor Yellow
        return
    }

    # Remediation
    $Confirm = Read-Host "Reset AdminCount and restore inheritance on $($UsersToClean.Count) accounts? (Y/N)"
    if ($Confirm -notmatch "^[Yy]$") {
        Write-Host "[-] Cancelled. No changes made." -ForegroundColor Yellow
        return
    }

    $SuccessCount = 0
    $FailCount    = 0
    foreach ($User in $UsersToClean) {
        Write-Host "   -> $($User.SamAccountName)... " -NoNewline
        try {
            Set-ADUser -Identity $User.DistinguishedName -Clear AdminCount -ErrorAction Stop
            $ADUser = [ADSI]"LDAP://$($User.DistinguishedName)"
            $UserACL = $ADUser.ObjectSecurity
            $UserACL.SetAccessRuleProtection($false, $false)
            $ADUser.CommitChanges()
            Write-Host "OK" -ForegroundColor Green
            $SuccessCount++
        }
        catch {
            Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
            $FailCount++
        }
    }
    Write-Host "`n[*] Finished: $SuccessCount succeeded, $FailCount failed." -ForegroundColor Cyan
}

# Auto-run when executed as a script (not dot-sourced or module-imported)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-AdminSDHolderCleanup @PSBoundParameters
}
