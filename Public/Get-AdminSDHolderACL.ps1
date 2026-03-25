<#
.SYNOPSIS
    Audits the AdminSDHolder object ACL for potential backdoors.

.DESCRIPTION
    Analyzes the Security Descriptor of the AdminSDHolder object and flags
    suspicious permissions (GenericAll, WriteDacl, WriteOwner) from unauthorized
    principals. Uses SID-based whitelisting for language-agnostic operation.

.PARAMETER ExportCSV
    Optional. Export findings to a CSV file at the specified path.

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1 -ExportCSV "C:\temp\AdminSDHolder_ACL.csv"

.AUTHOR
    franckferman
#>

param (
    [string]$ExportCSV
)

# Auto-load Private helpers when running from the standard toolkit layout
$_Private = Join-Path $PSScriptRoot '..' 'Private'
$_Constants = Join-Path $_Private 'Constants.ps1'
$_Helpers   = Join-Path $_Private 'Helpers.ps1'
if (Test-Path $_Constants) { . $_Constants }
if (Test-Path $_Helpers)   { . $_Helpers }

function Get-AdminSDHolderACL {
    param ([string]$ExportCSV)

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " AdminSDHolder Backdoor Hunter" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # Resolve domain context
    try {
        if (Get-Command Get-DomainContext -ErrorAction SilentlyContinue) {
            $Ctx = Get-DomainContext
            $DomainSID         = $Ctx.DomainSID
            $AdminSDHolderDN   = $Ctx.AdminSDHolderDN
        }
        else {
            $Domain            = Get-ADDomain
            $DomainSID         = $Domain.DomainSID.Value
            $AdminSDHolderDN   = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
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
    $DangerousRights = if ($Script:DangerousRights) { $Script:DangerousRights } else { "GenericAll|WriteDacl|WriteOwner" }

    # Bind to AdminSDHolder
    try {
        $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
        $ACL      = $ADObject.ObjectSecurity
    }
    catch {
        Write-Host "[!] ERROR: Could not access AdminSDHolder: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Read ACLs — include inherited entries ($true, $true) for a complete picture
    $Rules   = $ACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $Results = @()

    foreach ($Rule in $Rules) {
        if ($Rule.AccessControlType -ne "Allow") { continue }

        $SID    = $Rule.IdentityReference.Value
        $Rights = $Rule.ActiveDirectoryRights.ToString()

        if (Get-Command Resolve-SIDToName -ErrorAction SilentlyContinue) {
            $Account = Resolve-SIDToName -SID $SID
        }
        else {
            try   { $Account = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $Account = $SID }
        }

        $Threat = if ($Rights -match $DangerousRights -and $LegitSIDs -notcontains $SID) {
            "HIGH (Potential Backdoor)"
        }
        else {
            "Low/Standard"
        }

        $Results += [PSCustomObject]@{
            Account     = $Account
            SID         = $SID
            Permissions = $Rights
            Inherited   = $Rule.IsInherited
            ThreatLevel = $Threat
        }
    }

    # Report
    Write-Host "`n--- ACL AUDIT RESULTS ---" -ForegroundColor Cyan
    $Suspicious = $Results | Where-Object { $_.ThreatLevel -match "HIGH" }

    if ($Suspicious) {
        Write-Host "`n[!] SUSPICIOUS PERMISSIONS FOUND!" -ForegroundColor Red
        Write-Host "[!] Non-whitelisted principals with dangerous rights:" -ForegroundColor Red
        $Suspicious | Select-Object Account, SID, Permissions, ThreatLevel | Format-Table -AutoSize
    }
    else {
        Write-Host "[+] No high-threat backdoors detected." -ForegroundColor Green
    }

    Write-Host "`n--- FULL ACL LIST ---" -ForegroundColor Cyan
    $Results | Sort-Object ThreatLevel, Account | Select-Object Account, Permissions, Inherited, ThreatLevel | Format-Table -AutoSize

    if ($ExportCSV) {
        try {
            $Results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
            Write-Host "[+] Results exported to $ExportCSV" -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Failed to export: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Auto-run when executed as a script (not dot-sourced or module-imported)
if ($MyInvocation.InvocationName -ne '.') {
    Get-AdminSDHolderACL @PSBoundParameters
}
