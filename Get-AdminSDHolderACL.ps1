<#
.SYNOPSIS
    Audits the Access Control List (ACL) of the AdminSDHolder object for backdoors.

.DESCRIPTION
    The AdminSDHolder object acts as a template for all privileged accounts in Active Directory.
    A common persistence technique (backdoor) is to grant a standard user "GenericAll" or 
    "WriteDacl" rights on this specific object. The SDProp process will then automatically 
    push this attacker-controlled permission to all Domain Admins every 60 minutes.
    
    This script retrieves and formats the ACL of the AdminSDHolder container, highlighting 
    potentially dangerous permissions to help Blue Teams spot persistence mechanisms.

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1
    Retrieves all explicit and inherited permissions on the AdminSDHolder object.

.EXAMPLE
    .\Get-AdminSDHolderACL.ps1 -ExportCSV "C:\temp\AdminSDHolder_ACL.csv"
    Exports the ACL audit results to a CSV file for reporting.

.AUTHOR
    Frank Ferman
#>

param (
    [string]$ExportCSV
)

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AdminSDHolder ACL Audit Tool (Backdoor Hunter)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Get Domain and build the AdminSDHolder Distinguished Name
$Domain = Get-ADDomain
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
Write-Host "`n[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

try {
    # 2. Retrieve the ADSI object and its Security Descriptor
    Write-Host "[*] Retrieving Security Descriptor... " -NoNewline
    $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
    $ACL = $ADObject.ObjectSecurity
    Write-Host "Success." -ForegroundColor Green
} catch {
    Write-Host "Failed!" -ForegroundColor Red
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    Exit
}

# 3. Parse and format the ACL rules
Write-Host "[*] Parsing Access Control Rules..." -NoNewline
$InterestingRights = @()
$AccessRules = $ACL.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

foreach ($Rule in $AccessRules) {
    # We focus only on "Allow" rules (Deny rules are rarely used for backdoors)
    if ($Rule.AccessControlType -eq "Allow") {
        
        $AccountName = $Rule.IdentityReference.Value
        $Rights = $Rule.ActiveDirectoryRights.ToString()
        
        # Determine Threat Level based on the rights granted
        $ThreatLevel = "Low/Standard"
        if ($Rights -match "GenericAll|WriteDacl|WriteOwner|CreateChild") {
            $ThreatLevel = "HIGH (Potential Backdoor)"
        }

        # Build PS Custom Object
        $Info = [PSCustomObject]@{
            "Account"       = $AccountName
            "Permissions"   = $Rights
            "IsInherited"   = $Rule.IsInherited
            "ThreatLevel"   = $ThreatLevel
        }
        $InterestingRights += $Info
    }
}
Write-Host " Done.`n" -ForegroundColor Green


# 4. Display Results
Write-Host "--- ACL AUDIT RESULTS ---" -ForegroundColor Cyan

# Highlight suspicious entries in Red if found
$Suspicious = $InterestingRights | Where-Object { $_.ThreatLevel -match "HIGH" -and $_.Account -notmatch "SYSTEM|Administrators" }

if ($Suspicious) {
    Write-Host "`n[!] WARNING: SUSPICIOUS HIGH-PRIVILEGE PERMISSIONS FOUND!" -ForegroundColor Red
    $Suspicious | Format-Table -AutoSize
} else {
    Write-Host "[+] No obvious non-standard backdoors detected. Review the full list below:`n" -ForegroundColor Green
}

# Display full table
$InterestingRights | Sort-Object Account | Format-Table -AutoSize

# 5. Export to CSV if requested
if ($ExportCSV) {
    try {
        $InterestingRights | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "`n[+] Results successfully exported to: $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Host "`n[-] Failed to export CSS: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n[i] HOW TO READ THIS REPORT:" -ForegroundColor Cyan
Write-Host " -> Standard Users/Service Accounts MUST NOT have 'GenericAll', 'WriteDacl', or 'WriteOwner'."
Write-Host " -> Only Built-in 'SYSTEM' and 'Administrators' groups typically require full control."
