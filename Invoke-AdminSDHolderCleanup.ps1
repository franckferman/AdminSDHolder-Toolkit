<#
.SYNOPSIS
    Universally audits and cleans up orphaned AdminSDHolder (AdminCount=1) accounts.

.DESCRIPTION
    This script identifies users with AdminCount=1 who are no longer members of any
    privileged group and provides an option to clean them up (reset AdminCount=0 
    and restore ACL inheritance).
    
    Uses Well-Known SIDs (not group names) for universal language compatibility.

.PARAMETER AuditOnly
    Default mode. Lists orphaned accounts without making changes.

.PARAMETER Remediate
    Actively cleans up orphaned accounts. Asks for confirmation.

.EXAMPLE
    .\Invoke-AdminSDHolderCleanup.ps1 -AuditOnly

.EXAMPLE
    .\Invoke-AdminSDHolderCleanup.ps1 -Remediate

.AUTHOR
    Frank Ferman
#>

param (
    [switch]$AuditOnly = $true,
    [switch]$Remediate
)

if ($Remediate) { $AuditOnly = $false }

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Universal AdminSDHolder Cleanup (SID-Based)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Get Domain SID
$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value

# 2. Build Protected SIDs using Well-Known RIDs
# Domain-relative RIDs (prefixed with the domain SID)
$DomainRIDs = @("512", "517", "518", "519")
# Builtin RIDs (always under S-1-5-32)
$BuiltinRIDs = @("544", "548", "549", "550", "551")

$ProtectedSIDs = @()
foreach ($RID in $DomainRIDs) { $ProtectedSIDs += "$DomainSID-$RID" }
foreach ($RID in $BuiltinRIDs) { $ProtectedSIDs += "S-1-5-32-$RID" }

Write-Host "`n[*] Resolving $($ProtectedSIDs.Count) Protected Groups... " -NoNewline
$GroupsDN = @()
foreach ($SID in $ProtectedSIDs) {
    try {
        $Group = Get-ADGroup -Identity $SID -ErrorAction Stop
        $GroupsDN += $Group.DistinguishedName
    }
    catch {
        Write-Host "`n  [!] Could not resolve SID: $SID" -ForegroundColor Yellow
    }
}
Write-Host "Done ($($GroupsDN.Count) resolved)." -ForegroundColor Green

# 3. SafeList: built-in accounts to never touch (by SID)
$SafeListSIDs = @(
    "$DomainSID-500",  # Built-in Administrator
    "$DomainSID-502"   # krbtgt
)

# 4. Get all users with AdminCount=1
Write-Host "[*] Searching for users with AdminCount=1... " -NoNewline
$AdminUsers = Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount, MemberOf, PrimaryGroupId -ErrorAction Stop
Write-Host "Found $($AdminUsers.Count) users." -ForegroundColor Yellow

$UsersToClean = @()
$LegitAdmins = @()

foreach ($User in $AdminUsers) {
    # Skip safe-listed accounts
    if ($SafeListSIDs -contains $User.SID.Value) {
        $LegitAdmins += $User
        continue
    }

    $IsProtected = $false

    # Check direct group membership
    if ($User.MemberOf) {
        foreach ($MemberOfGroup in $User.MemberOf) {
            if ($GroupsDN -contains $MemberOfGroup) {
                $IsProtected = $true
                break
            }
        }
    }
    
    # Check Primary Group (not shown in MemberOf)
    if (-not $IsProtected -and $User.PrimaryGroupId) {
        foreach ($SID in $ProtectedSIDs) {
            try {
                $PG = Get-ADGroup -Identity $SID -ErrorAction Stop
                if ($PG.SID.Value -match "-$($User.PrimaryGroupId)$") {
                    $IsProtected = $true
                    break
                }
            }
            catch { }
        }
    }

    if ($IsProtected) { $LegitAdmins += $User }
    else { $UsersToClean += $User }
}

# 5. Display results
Write-Host "`n--- AUDIT RESULTS ---" -ForegroundColor Cyan
Write-Host "Legitimate admins: $($LegitAdmins.Count)" -ForegroundColor Green
Write-Host "Orphaned accounts (false positives): $($UsersToClean.Count)" -ForegroundColor Red

if ($UsersToClean.Count -eq 0) {
    Write-Host "`n[+] No orphaned accounts found. Your AD is clean!" -ForegroundColor Green
    Exit
}

$UsersToClean | Select-Object Name, SamAccountName | Format-Table -AutoSize

if ($AuditOnly) {
    Write-Host "[i] Run with -Remediate to clean up these accounts." -ForegroundColor Yellow
    Exit
}

# 6. Remediation
if ($Remediate) {
    Write-Host "[!] WARNING: This will modify $($UsersToClean.Count) AD objects." -ForegroundColor Red
    $Confirm = Read-Host "Proceed? (Y/N)"
    if ($Confirm -match "^[Yy]$") {
        $SuccessCount = 0
        $FailCount = 0
        foreach ($User in $UsersToClean) {
            Write-Host "   -> Cleaning $($User.SamAccountName)... " -NoNewline
            try {
                # Clear AdminCount attribute
                Set-ADUser -Identity $User.DistinguishedName -Clear AdminCount -ErrorAction Stop
                # Restore ACL inheritance
                $ADUser = [ADSI]"LDAP://$($User.DistinguishedName)"
                $ACL = $ADUser.ObjectSecurity
                $ACL.SetAccessRuleProtection($false, $false)
                $ADUser.CommitChanges()
                Write-Host "Success" -ForegroundColor Green
                $SuccessCount++
            }
            catch {
                Write-Host "Failed ($($_.Exception.Message))" -ForegroundColor Red
                $FailCount++
            }
        }
        Write-Host "`n[*] Cleanup finished: $SuccessCount succeeded, $FailCount failed." -ForegroundColor Green
    }
    else {
        Write-Host "[-] Cancelled." -ForegroundColor Yellow
    }
}
