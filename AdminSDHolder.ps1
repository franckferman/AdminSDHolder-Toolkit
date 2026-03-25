<#
.SYNOPSIS
    Interactive manager for AdminSDHolder-Toolkit.

.DESCRIPTION
    Central launcher with menu-driven interface and non-interactive -Action mode.

    Actions:
      Audit      - Audit orphaned AdminCount accounts (read-only)
      Detect     - Scan AdminSDHolder ACL for backdoors (read-only)
      FullAudit  - Audit + Detect combined (read-only)
      Cleanup    - Remediate orphaned AdminCount accounts (writes to AD)
      Repair     - Remove unauthorized ACL entries from AdminSDHolder (writes to AD)
      Backdoor   - Insert a GenericAll backdoor ACE on AdminSDHolder (writes to AD)

.PARAMETER Action
    Optional. Run a specific action non-interactively.
    Valid values: Audit, Detect, FullAudit, Cleanup, Repair, Backdoor

.EXAMPLE
    .\AdminSDHolder.ps1

.EXAMPLE
    .\AdminSDHolder.ps1 -Action FullAudit

.AUTHOR
    franckferman
#>

param (
    [ValidateSet("Audit", "Detect", "FullAudit", "Cleanup", "Repair", "Backdoor")]
    [string]$Action
)

$ScriptRoot = $PSScriptRoot
$PublicPath = Join-Path $ScriptRoot 'Public'

# Verify all toolkit scripts are present
$RequiredScripts = @(
    "Get-AdminSDHolderACL.ps1",
    "Invoke-AdminSDHolderCleanup.ps1",
    "Repair-AdminSDHolderACL.ps1",
    "Add-AdminSDHolderBackdoor.ps1"
)

$Missing = $RequiredScripts | Where-Object { -not (Test-Path (Join-Path $PublicPath $_)) }
if ($Missing) {
    Write-Host "[!] Missing scripts in Public/:" -ForegroundColor Red
    $Missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Exit 1
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host "  =                                                        =" -ForegroundColor Cyan
    Write-Host "  =         AdminSDHolder-Toolkit                         =" -ForegroundColor Cyan
    Write-Host "  =         Active Directory Persistence Toolkit          =" -ForegroundColor Cyan
    Write-Host "  =                                                        =" -ForegroundColor Cyan
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  |  AUDIT (read-only)                                     |" -ForegroundColor DarkGray
    Write-Host "  |    [1] Audit orphaned AdminCount accounts              |" -ForegroundColor White
    Write-Host "  |    [2] Detect AdminSDHolder ACL backdoors              |" -ForegroundColor White
    Write-Host "  |    [3] Full Audit (1 + 2)                              |" -ForegroundColor White
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |  REMEDIATION (modifies AD)                             |" -ForegroundColor DarkGray
    Write-Host "  |    [4] Cleanup orphaned AdminCount accounts            |" -ForegroundColor Yellow
    Write-Host "  |    [5] Repair AdminSDHolder ACL                        |" -ForegroundColor Yellow
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |  OFFENSIVE                                             |" -ForegroundColor DarkGray
    Write-Host "  |    [6] Insert AdminSDHolder backdoor ACE               |" -ForegroundColor Red
    Write-Host "  |                                                        |" -ForegroundColor DarkGray
    Write-Host "  |    [Q] Quit                                            |" -ForegroundColor DarkGray
    Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-ToolkitAction {
    param([string]$SelectedAction)

    Write-Host ""

    switch ($SelectedAction) {
        { $_ -in "1", "Audit" } {
            & (Join-Path $PublicPath "Invoke-AdminSDHolderCleanup.ps1")
        }
        { $_ -in "2", "Detect" } {
            & (Join-Path $PublicPath "Get-AdminSDHolderACL.ps1")
        }
        { $_ -in "3", "FullAudit" } {
            Write-Host "  === PHASE 1: Orphaned AdminCount Audit ===" -ForegroundColor Cyan
            & (Join-Path $PublicPath "Invoke-AdminSDHolderCleanup.ps1")
            Write-Host ""
            Write-Host "  === PHASE 2: AdminSDHolder ACL Backdoor Scan ===" -ForegroundColor Cyan
            & (Join-Path $PublicPath "Get-AdminSDHolderACL.ps1")
        }
        { $_ -in "4", "Cleanup" } {
            & (Join-Path $PublicPath "Invoke-AdminSDHolderCleanup.ps1") -Remediate
        }
        { $_ -in "5", "Repair" } {
            & (Join-Path $PublicPath "Repair-AdminSDHolderACL.ps1") -Remediate
        }
        { $_ -in "6", "Backdoor" } {
            $TargetAccount = Read-Host "  Account SamAccountName"
            $RemoveChoice  = Read-Host "  Remove ACE after validation? (Y/N)"
            $RemoveSwitch  = if ($RemoveChoice -match "^[Yy]$") { @{ Remove = $true } } else { @{} }
            & (Join-Path $PublicPath "Add-AdminSDHolderBackdoor.ps1") -Account $TargetAccount @RemoveSwitch
        }
        default {
            Write-Host "  [!] Invalid selection." -ForegroundColor Red
        }
    }
}

# Non-interactive mode
if ($Action) {
    Show-Banner
    Write-Host "  [*] Running: $Action" -ForegroundColor Yellow
    Invoke-ToolkitAction -SelectedAction $Action
    Exit
}

# Interactive menu loop
do {
    Show-Banner
    Show-Menu
    $Choice = Read-Host "  Select an option"

    if ($Choice -match "^[Qq]$") {
        Write-Host ""
        Write-Host "  Goodbye." -ForegroundColor Cyan
        Write-Host ""
        break
    }

    Invoke-ToolkitAction -SelectedAction $Choice

    Write-Host ""
    Read-Host "  Press ENTER to return to menu"
} while ($true)
