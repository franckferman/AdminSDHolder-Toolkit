<#
.SYNOPSIS
    Removes unauthorized or suspicious ACL entries from the AdminSDHolder object.

.DESCRIPTION
    Identifies ACL entries on AdminSDHolder that are not in the default whitelist
    of Well-Known SIDs and provides an option to remove them.
    
    Uses SID-based whitelisting for universal language support.

.PARAMETER AuditOnly
    Default mode. Lists unauthorized entries without removing them.

.PARAMETER Remediate
    Removes unauthorized entries with confirmation prompt.

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -AuditOnly

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -Remediate

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
Write-Host " AdminSDHolder ACL Repair (Remediation)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"

Write-Host "`n[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

# Well-Known SIDs that are EXPECTED on AdminSDHolder by default
$LegitSIDs = @(
    "S-1-5-18",           # SYSTEM
    "S-1-5-10",           # SELF
    "S-1-5-11",           # Authenticated Users
    "S-1-1-0",            # Everyone
    "S-1-5-32-544",       # BUILTIN\Administrators
    "S-1-5-32-554",       # Pre-Windows 2000 Compatible Access
    "S-1-5-32-560",       # Windows Authorization Access Group
    "S-1-5-32-561",       # Terminal Server License Servers
    "$DomainSID-512",     # Domain Admins
    "$DomainSID-519",     # Enterprise Admins
    "$DomainSID-517"      # Cert Publishers
)

try {
    $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
    $ACL = $ADObject.ObjectSecurity
    $Rules = $ACL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
}
catch {
    Write-Host "[!] ERROR: Could not access AdminSDHolder: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

# Identify unauthorized rules
$Suspicious = @()
foreach ($Rule in $Rules) {
    $SID = $Rule.IdentityReference.Value
    if ($LegitSIDs -notcontains $SID) {
        try {
            $Acc = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $Acc = $SID
        }
        $Suspicious += [PSCustomObject]@{
            Account = $Acc
            SID     = $SID
            Rights  = $Rule.ActiveDirectoryRights.ToString()
            Rule    = $Rule
        }
    }
}

if ($Suspicious.Count -eq 0) {
    Write-Host "`n[+] AdminSDHolder ACL is clean. No unauthorized entries found." -ForegroundColor Green
    Exit
}

Write-Host "`n[!] Found $($Suspicious.Count) unauthorized ACL entries:" -ForegroundColor Red
$Suspicious | Select-Object Account, SID, Rights | Format-Table -AutoSize

if ($AuditOnly) {
    Write-Host "[i] Run with -Remediate to remove these entries." -ForegroundColor Yellow
    Exit
}

if ($Remediate) {
    Write-Host "[!] WARNING: You are about to modify the AdminSDHolder Security Descriptor." -ForegroundColor Red
    $Confirm = Read-Host "Remove $($Suspicious.Count) unauthorized entries? (Y/N)"
    if ($Confirm -match "^[Yy]$") {
        $SuccessCount = 0
        $FailCount = 0
        foreach ($s in $Suspicious) {
            Write-Host "   -> Removing $($s.Account) ($($s.Rights))... " -NoNewline
            try {
                $ACL.RemoveAccessRule($s.Rule) | Out-Null
                $SuccessCount++
                Write-Host "Done" -ForegroundColor Green
            }
            catch {
                $FailCount++
                Write-Host "Failed ($($_.Exception.Message))" -ForegroundColor Red
            }
        }

        # Commit only if at least one removal succeeded
        if ($SuccessCount -gt 0) {
            try {
                $ADObject.CommitChanges()
                Write-Host "`n[+] Changes committed: $SuccessCount removed, $FailCount failed." -ForegroundColor Green
            }
            catch {
                Write-Host "`n[!] FAILED to commit changes: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "`n[-] No changes to commit." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[-] Cancelled. No changes were made." -ForegroundColor Yellow
    }
}
