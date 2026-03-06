<#
.SYNOPSIS
    Interactive manager for the AdminSDHolder-Toolkit.

.DESCRIPTION
    Central launcher that provides a menu-driven interface to all toolkit scripts:
    - Invoke-AdminSDHolderCleanup (Orphaned AdminCount cleanup)
    - Get-AdminSDHolderACL (Backdoor detection)
    - Repair-AdminSDHolderACL (Backdoor remediation)
    - Test-AdminSDHolderBackdoor (PoC simulation)
    
    Can also be used non-interactively with the -Action parameter.

.PARAMETER Action
    Optional. Run a specific action without the menu:
    "Audit", "Cleanup", "Detect", "Repair", "Test", "FullAudit"

.EXAMPLE
    .\AdminSDHolder-Manager.ps1
    Launches the interactive menu.

.EXAMPLE
    .\AdminSDHolder-Manager.ps1 -Action FullAudit
    Runs a complete audit (orphaned accounts + ACL backdoor check) non-interactively.

.AUTHOR
    Frank Ferman
#>

param (
    [ValidateSet("Audit", "Cleanup", "Detect", "Repair", "Test", "FullAudit")]
    [string]$Action
)

$ScriptRoot = $PSScriptRoot

# Verify all toolkit scripts are present
$RequiredScripts = @(
    "Invoke-AdminSDHolderCleanup.ps1",
    "Get-AdminSDHolderACL.ps1",
    "Repair-AdminSDHolderACL.ps1",
    "Test-AdminSDHolderBackdoor.ps1"
)

$Missing = @()
foreach ($Script in $RequiredScripts) {
    if (-not (Test-Path "$ScriptRoot\$Script")) { $Missing += $Script }
}

if ($Missing.Count -gt 0) {
    Write-Host "[!] Missing toolkit scripts:" -ForegroundColor Red
    $Missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host "[!] Please ensure all scripts are in the same directory." -ForegroundColor Red
    Exit 1
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host "  =                                                        =" -ForegroundColor Cyan
    Write-Host "  =        AdminSDHolder-Toolkit  v1.0                     =" -ForegroundColor Cyan
    Write-Host "  =        Active Directory Security Toolkit               =" -ForegroundColor Cyan
    Write-Host "  =                                                        =" -ForegroundColor Cyan
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  |  AUDIT                                                 |" -ForegroundColor DarkGray
    Write-Host "  |    [1] Audit orphaned AdminCount accounts              |" -ForegroundColor White
    Write-Host "  |    [2] Detect AdminSDHolder ACL backdoors              |" -ForegroundColor White
    Write-Host "  |    [3] Full Audit (1 + 2 combined)                     |" -ForegroundColor White
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |  REMEDIATION                                           |" -ForegroundColor DarkGray
    Write-Host "  |    [4] Cleanup orphaned AdminCount accounts            |" -ForegroundColor Yellow
    Write-Host "  |    [5] Repair AdminSDHolder ACL (remove backdoors)     |" -ForegroundColor Yellow
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |  TESTING                                               |" -ForegroundColor DarkGray
    Write-Host "  |    [6] Simulate backdoor (PoC)                         |" -ForegroundColor Red
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |    [Q] Quit                                            |" -ForegroundColor DarkGray
    Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-Action {
    param([string]$SelectedAction)

    Write-Host ""

    switch ($SelectedAction) {
        "1" { & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -AuditOnly }
        "Audit" { & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -AuditOnly }
        
        "2" { & "$ScriptRoot\Get-AdminSDHolderACL.ps1" }
        "Detect" { & "$ScriptRoot\Get-AdminSDHolderACL.ps1" }
        
        "3" {
            Write-Host "  === PHASE 1: Orphaned AdminCount Audit ===" -ForegroundColor Cyan
            & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -AuditOnly
            Write-Host ""
            Write-Host "  === PHASE 2: AdminSDHolder ACL Backdoor Scan ===" -ForegroundColor Cyan
            & "$ScriptRoot\Get-AdminSDHolderACL.ps1"
        }
        "FullAudit" {
            Write-Host "  === PHASE 1: Orphaned AdminCount Audit ===" -ForegroundColor Cyan
            & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -AuditOnly
            Write-Host ""
            Write-Host "  === PHASE 2: AdminSDHolder ACL Backdoor Scan ===" -ForegroundColor Cyan
            & "$ScriptRoot\Get-AdminSDHolderACL.ps1"
        }
        
        "4" { & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -Remediate }
        "Cleanup" { & "$ScriptRoot\Invoke-AdminSDHolderCleanup.ps1" -Remediate }
        
        "5" { & "$ScriptRoot\Repair-AdminSDHolderACL.ps1" -Remediate }
        "Repair" { & "$ScriptRoot\Repair-AdminSDHolderACL.ps1" -Remediate }
        
        "6" {
            $TestUser = Read-Host "  Enter test account SamAccountName"
            $CleanupChoice = Read-Host "  Auto-cleanup after test? (Y/N)"
            if ($CleanupChoice -match "^[Yy]$") {
                & "$ScriptRoot\Test-AdminSDHolderBackdoor.ps1" -TestAccount $TestUser -Cleanup
            }
            else {
                & "$ScriptRoot\Test-AdminSDHolderBackdoor.ps1" -TestAccount $TestUser
            }
        }
        "Test" {
            $TestUser = Read-Host "  Enter test account SamAccountName"
            & "$ScriptRoot\Test-AdminSDHolderBackdoor.ps1" -TestAccount $TestUser -Cleanup
        }
        
        default { Write-Host "  [!] Invalid selection." -ForegroundColor Red }
    }
}

# --- MAIN ---

# Non-interactive mode
if ($Action) {
    Show-Banner
    Write-Host "  [*] Running action: $Action" -ForegroundColor Yellow
    Invoke-Action -SelectedAction $Action
    Exit
}

# Interactive mode (Menu loop)
do {
    Show-Banner
    Show-Menu
    $Choice = Read-Host "  Select an option"
    
    if ($Choice -match "^[Qq]$") {
        Write-Host ""
        Write-Host "  Goodbye!" -ForegroundColor Cyan
        Write-Host ""
        break
    }

    Invoke-Action -SelectedAction $Choice

    Write-Host ""
    Read-Host "  Press ENTER to return to menu"

} while ($true)
