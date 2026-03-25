<#
.SYNOPSIS
    Removes unauthorized ACL entries from the AdminSDHolder object.

.DESCRIPTION
    Identifies ACE entries on AdminSDHolder that are not in the default whitelist
    of Well-Known SIDs, then optionally removes them.

    Collects all removals in-memory before committing a single atomic write.
    A CSV backup of the original ACL is saved before any changes are made.

    Uses SID-based whitelisting for language-agnostic operation.

.PARAMETER Remediate
    Removes unauthorized entries after confirmation. Creates a backup first.
    Without this switch the script runs read-only (audit mode).

.PARAMETER BackupPath
    Optional. Custom path for the pre-remediation ACL backup CSV.

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -Remediate

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -Remediate -BackupPath "C:\temp\backup.csv"

.AUTHOR
    franckferman
#>

param (
    [switch]$Remediate,
    [string]$BackupPath
)

$AuditOnly = -not $Remediate.IsPresent

# Auto-load Private helpers when running from the standard toolkit layout
$_Private = Join-Path $PSScriptRoot '..' 'Private'
$_Constants = Join-Path $_Private 'Constants.ps1'
$_Helpers   = Join-Path $_Private 'Helpers.ps1'
if (Test-Path $_Constants) { . $_Constants }
if (Test-Path $_Helpers)   { . $_Helpers }

function Repair-AdminSDHolderACL {
    param (
        [switch]$Remediate,
        [string]$BackupPath
    )

    $AuditOnly = -not $Remediate.IsPresent

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " AdminSDHolder ACL Repair" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # Domain context
    try {
        if (Get-Command Get-DomainContext -ErrorAction SilentlyContinue) {
            $Ctx = Get-DomainContext
            $DomainSID       = $Ctx.DomainSID
            $AdminSDHolderDN = $Ctx.AdminSDHolderDN
        }
        else {
            $Domain          = Get-ADDomain
            $DomainSID       = $Domain.DomainSID.Value
            $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
        }
    }
    catch {
        Write-Host "[!] ERROR: Failed to query domain: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "`n[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

    # Build whitelist
    if (Get-Command Get-LegitSIDs -ErrorAction SilentlyContinue) {
        $LegitSIDs = Get-LegitSIDs -DomainSID $DomainSID
    }
    else {
        $LegitSIDs = @(
            "S-1-5-18", "S-1-5-10", "S-1-5-11", "S-1-1-0",
            "S-1-5-32-544", "S-1-5-32-554", "S-1-5-32-560", "S-1-5-32-561",
            "$DomainSID-512", "$DomainSID-519", "$DomainSID-517"
        )
    }

    # Bind to AdminSDHolder — use $true, $true to match Get-AdminSDHolderACL view
    try {
        $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
        $ACL      = $ADObject.ObjectSecurity
        $Rules    = $ACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Host "[!] ERROR: Could not access AdminSDHolder: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Identify unauthorized rules
    $Suspicious = @()
    foreach ($Rule in $Rules) {
        $SID = $Rule.IdentityReference.Value
        if ($LegitSIDs -notcontains $SID) {
            if (Get-Command Resolve-SIDToName -ErrorAction SilentlyContinue) {
                $Acc = Resolve-SIDToName -SID $SID
            }
            else {
                try   { $Acc = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value }
                catch { $Acc = $SID }
            }
            $Suspicious += [PSCustomObject]@{
                Account   = $Acc
                SID       = $SID
                Rights    = $Rule.ActiveDirectoryRights.ToString()
                Inherited = $Rule.IsInherited
                Rule      = $Rule
            }
        }
    }

    if ($Suspicious.Count -eq 0) {
        Write-Host "`n[+] AdminSDHolder ACL is clean. No unauthorized entries found." -ForegroundColor Green
        return
    }

    Write-Host "`n[!] Found $($Suspicious.Count) unauthorized ACL entries:" -ForegroundColor Red
    $Suspicious | Select-Object Account, SID, Rights, Inherited | Format-Table -AutoSize

    if ($AuditOnly) {
        Write-Host "[i] Run with -Remediate to remove these entries." -ForegroundColor Yellow
        return
    }

    # Remediation
    $Confirm = Read-Host "Remove $($Suspicious.Count) unauthorized entries from AdminSDHolder? (Y/N)"
    if ($Confirm -notmatch "^[Yy]$") {
        Write-Host "[-] Cancelled. No changes made." -ForegroundColor Yellow
        return
    }

    # Backup before touching anything
    if (Get-Command Backup-AdminSDHolderACL -ErrorAction SilentlyContinue) {
        $BkPath = Backup-AdminSDHolderACL -ACL $ACL -Path $BackupPath
        Write-Host "[+] ACL backed up to: $BkPath" -ForegroundColor Green
    }

    # Stage all removals in-memory, then commit once
    $SuccessCount = 0
    $FailCount    = 0
    foreach ($s in $Suspicious) {
        try {
            $ACL.RemoveAccessRule($s.Rule) | Out-Null
            $SuccessCount++
        }
        catch {
            Write-Host "[-] Failed to stage removal for $($s.Account): $($_.Exception.Message)" -ForegroundColor Red
            $FailCount++
        }
    }

    if ($SuccessCount -gt 0) {
        try {
            $ADObject.CommitChanges()
            Write-Host "`n[+] Committed: $SuccessCount entries removed, $FailCount failed." -ForegroundColor Green
        }
        catch {
            Write-Host "`n[!] FAILED to commit changes: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "[!] Original ACL backup: $BkPath" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`n[-] No changes to commit." -ForegroundColor Yellow
    }
}

# Auto-run when executed as a script (not dot-sourced or module-imported)
if ($MyInvocation.InvocationName -ne '.') {
    Repair-AdminSDHolderACL @PSBoundParameters
}
