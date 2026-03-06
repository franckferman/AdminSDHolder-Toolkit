<#
.SYNOPSIS
    Audits the AdminSDHolder object ACL for potential backdoors.

.DESCRIPTION
    Analyzes the Security Descriptor of the AdminSDHolder object and flags 
    suspicious permissions (GenericAll, WriteDacl, WriteOwner) from unauthorized accounts.
    
    Uses SID-based whitelisting for universal language support.

.PARAMETER ExportCSV
    Optional. Export findings to a CSV file.

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1 -ExportCSV "C:\temp\AdminSDHolder_ACL.csv"

.AUTHOR
    Frank Ferman
#>

param (
    [string]$ExportCSV
)

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AdminSDHolder Backdoor Hunter" -ForegroundColor Cyan
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
}
catch {
    Write-Host "[!] ERROR: Could not access AdminSDHolder: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

# Read ACLs using SIDs (language-agnostic)
$Rules = $ACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

$Results = @()
foreach ($Rule in $Rules) {
    if ($Rule.AccessControlType -eq "Allow") {
        $SID = $Rule.IdentityReference.Value
        $Rights = $Rule.ActiveDirectoryRights.ToString()
        
        # Resolve SID to friendly name
        try {
            $Account = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $Account = $SID
        }

        # Determine threat level
        $Threat = "Low/Standard"
        $IsLegit = $LegitSIDs -contains $SID
        if ($Rights -match "GenericAll|WriteDacl|WriteOwner" -and -not $IsLegit) {
            $Threat = "HIGH (Potential Backdoor)"
        }

        $Results += [PSCustomObject]@{
            Account     = $Account
            SID         = $SID
            Permissions = $Rights
            ThreatLevel = $Threat
        }
    }
}

# Display results
Write-Host "`n--- ACL AUDIT RESULTS ---" -ForegroundColor Cyan
$Suspicious = $Results | Where-Object { $_.ThreatLevel -match "HIGH" }

if ($Suspicious) {
    Write-Host "`n[!] SUSPICIOUS PERMISSIONS FOUND!" -ForegroundColor Red
    Write-Host "[!] The following entries are NOT in the default whitelist and have dangerous rights:" -ForegroundColor Red
    $Suspicious | Select-Object Account, SID, Permissions, ThreatLevel | Format-Table -AutoSize
}
else {
    Write-Host "[+] No high-threat backdoors detected." -ForegroundColor Green
}

Write-Host "`n--- FULL ACL LIST ---" -ForegroundColor Cyan
$Results | Sort-Object ThreatLevel, Account | Select-Object Account, Permissions, ThreatLevel | Format-Table -AutoSize

if ($ExportCSV) {
    try {
        $Results | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Results exported to $ExportCSV" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to export: $($_.Exception.Message)" -ForegroundColor Red
    }
}
