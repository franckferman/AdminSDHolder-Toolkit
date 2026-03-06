<#
.SYNOPSIS
    Universal Audit and Cleanup tool for orphaned AdminSDHolder accounts (AdminCount=1).

.DESCRIPTION
    This script identifies "false positives" (users with AdminCount=1 who are no longer in
    any privileged group) and cleans them up (reset AdminCount=0 and restores ACL inheritance).
    
    [!] SUPERIORITY: This script uses Well-Known SIDs (Security Identifiers) completely 
    bypassing OS language barriers (English, French, German, etc.). It works flawlessly 
    on ANY Active Directory environment globally.

.PARAMETER AuditOnly
    Switch to run the script in Audit mode only (default). No changes are made to AD.

.PARAMETER Remediate
    Switch to actively clean up orphaned accounts. Asks for confirmation before execution.

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

# Force AuditOnly to false if Remediate is explicitly called
if ($Remediate) { $AuditOnly = $false }

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Universal AdminSDHolder Cleanup Tool (SID-Based Resolution)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Get the Domain SID dynamically (Works whatever the domain name is)
$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value

# 2. Define Well-Known RIDs (Relative IDs) that Microsoft hardcodes for privileged groups
# Docs: https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
$PrivilegedRIDs = @(
    "512", # Domain Admins
    "519", # Enterprise Admins
    "518", # Schema Admins
    "544", # Administrators (Built-in)
    "548", # Account Operators
    "549", # Server Operators
    "551", # Backup Operators
    "550"  # Print Operators
)

# 3. Build the absolute SIDs for the current domain
$ProtectedSIDs = @()
foreach ($RID in $PrivilegedRIDs) {
    # 544, 548, 549, 550, 551 belong to the Builtin domain (S-1-5-32) globally
    if ($RID -match "^54|55") {
        $ProtectedSIDs += "S-1-5-32-$RID"
    } else {
        # 512, 518, 519 belong to the specific Domain
        $ProtectedSIDs += "$DomainSID-$RID"
    }
}

Write-Host "`n[*] Resolving Protected Groups SIDs... " -NoNewline
$GroupsDN = @()
foreach ($SID in $ProtectedSIDs) {
    $Group = Get-ADGroup -Identity $SID -ErrorAction SilentlyContinue 
    if ($Group) {
        $GroupsDN += $Group.DistinguishedName
    }
}
Write-Host "Done." -ForegroundColor Green

# 4. Define SafeList by SIDs instead of Names (krbtgt = 502, Administrator = 500)
$SafeListSIDs = @(
    "$DomainSID-500", # Built-in Administrator
    "$DomainSID-502"  # krbtgt account
)


Write-Host "[*] Searching for Users with AdminCount=1... " -NoNewline
$AdminUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf, PrimaryGroupId -ErrorAction Stop
Write-Host "Found $($AdminUsers.Count) users." -ForegroundColor Yellow


$UsersToClean = @()
$LegitAdmins = @()

foreach ($User in $AdminUsers) {
    
    # Check if user is in the ultimate SafeList (by SID)
    if ($SafeListSIDs -contains $User.SID.Value) {
        $LegitAdmins += $User
        continue
    }

    $IsProtected = $false
    
    # Check standard MemberOf (Groups)
    if ($User.MemberOf) {
        foreach ($MemberOfGroup in $User.MemberOf) {
            if ($GroupsDN -contains $MemberOfGroup) {
                $IsProtected = $true
                break
            }
        }
    }
    
    # Check Primary Group if not already protected (usually SID ending in 512 for Domain Admins)
    if (-not $IsProtected -and $User.PrimaryGroupId) {
        $PrimaryGroup = Get-ADGroup -Filter {PrimaryGroupToken -eq $User.PrimaryGroupId} -ErrorAction SilentlyContinue
        if ($PrimaryGroup -and ($GroupsDN -contains $PrimaryGroup.DistinguishedName)) {
            $IsProtected = $true
        }
    }

    if ($IsProtected) {
        $LegitAdmins += $User
    } else {
        $UsersToClean += $User
    }
}

Write-Host "`n--- AUDIT RESULTS ---" -ForegroundColor Cyan
Write-Host "Legitimate protected users remaining: $($LegitAdmins.Count)" -ForegroundColor Green
Write-Host "Orphaned users (False Positives) needing cleanup: $($UsersToClean.Count)" -ForegroundColor Red

if ($UsersToClean.Count -gt 0) {
    Write-Host "`nThe following accounts are identified as false positives:"
    $UsersToClean | Select-Object Name, SamAccountName | Format-Table -AutoSize
} else {
    Write-Host "`n[+] No orphaned accounts found. Your AD is clean and healthy!" -ForegroundColor Green
    Exit
}


# --- REMEDIATION PHASE ---
if ($AuditOnly) {
    Write-Host "`n[i] Script ran in -AuditOnly mode. No changes were made." -ForegroundColor Yellow
    Write-Host "[i] To clean these accounts, run the script with the -Remediate switch." -ForegroundColor Yellow
    Exit
}

if ($Remediate) {
    Write-Host "`n[!] WARNING: You are about to modify Active Directory objects." -ForegroundColor Red
    $Confirm = Read-Host "Do you want to proceed and clean up these $($UsersToClean.Count) accounts? (Y/N)"
    
    if ($Confirm -match "^[Yy]$") {
        Write-Host "`n[*] Starting Cleanup Process..." -ForegroundColor Cyan
        
        $SuccessCount = 0
        $FailCount = 0

        foreach ($User in $UsersToClean) {
            Write-Host "   -> Cleaning up user: $($User.SamAccountName)... " -NoNewline
            try {
                # 1. Clear AdminCount Attribute
                Set-ADUser -Identity $User.DistinguishedName -Clear AdminCount -ErrorAction Stop
                
                # 2. Restore Permission Inheritance
                $ADUser = [ADSI]"LDAP://$($User.DistinguishedName)"
                $ACL = $ADUser.ObjectSecurity
                
                # SetAccessRuleProtection(isProtected, preserveInheritance)
                $ACL.SetAccessRuleProtection($false, $false)
                $ADUser.CommitChanges()
                
                Write-Host "Success" -ForegroundColor Green
                $SuccessCount++
            } catch {
                Write-Host "Failed ($($_.Exception.Message))" -ForegroundColor Red
                $FailCount++
            }
        }
        Write-Host "`n[*] Cleanup Summary: $SuccessCount succeeded, $FailCount failed." -ForegroundColor ($FailCount -gt 0 ? 'Yellow' : 'Green')
    } else {
        Write-Host "`n[-] Remediation Cancelled by user. No objects were modified." -ForegroundColor Yellow
    }
}
