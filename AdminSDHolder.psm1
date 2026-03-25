# AdminSDHolder.psm1
# Optional PowerShell module — dot-sources all Public scripts and exports their functions.
#
# Usage:
#   Import-Module .\AdminSDHolder.psm1
#   Get-AdminSDHolderACL
#   Invoke-AdminSDHolderCleanup
#   Repair-AdminSDHolderACL -Remediate
#   Add-AdminSDHolderBackdoor -Account "svc_backup" -Remove

$PrivatePath = Join-Path $PSScriptRoot 'Private'
$PublicPath  = Join-Path $PSScriptRoot 'Public'

# Load shared constants and helpers first
foreach ($File in @('Constants.ps1', 'Helpers.ps1')) {
    $FullPath = Join-Path $PrivatePath $File
    if (Test-Path $FullPath) { . $FullPath }
}

# Dot-source all Public scripts (defines functions, does not execute them)
Get-ChildItem -Path $PublicPath -Filter '*.ps1' -ErrorAction SilentlyContinue |
    ForEach-Object { . $_.FullName }

Export-ModuleMember -Function @(
    'Get-AdminSDHolderACL',
    'Invoke-AdminSDHolderCleanup',
    'Repair-AdminSDHolderACL',
    'Add-AdminSDHolderBackdoor'
)
