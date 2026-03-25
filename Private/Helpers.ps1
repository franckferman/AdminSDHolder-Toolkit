# Private/Helpers.ps1
# Shared helper functions for AdminSDHolder-Toolkit.
# Dot-sourced by Public scripts — do not invoke directly.
# Requires Constants.ps1 to be loaded first.

function Get-DomainContext {
    <#
    .SYNOPSIS
        Returns a context object with domain info used throughout the toolkit.
    #>
    $Domain = Get-ADDomain
    $DomainSID = $Domain.DomainSID.Value
    return [PSCustomObject]@{
        Domain            = $Domain
        DomainSID         = $DomainSID
        DN                = $Domain.DistinguishedName
        AdminSDHolderDN   = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"
    }
}

function Get-LegitSIDs {
    <#
    .SYNOPSIS
        Builds the full whitelist of legitimate ACE principals for AdminSDHolder.
    .PARAMETER DomainSID
        The domain SID string (e.g. "S-1-5-21-...").
    #>
    param([Parameter(Mandatory)][string]$DomainSID)

    $SIDs = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $Script:WellKnownSIDs)  { $SIDs.Add($s) | Out-Null }
    foreach ($r in $Script:LegitDomainRIDs) { $SIDs.Add("$DomainSID-$r") | Out-Null }
    return $SIDs
}

function Get-ProtectedGroupsDN {
    <#
    .SYNOPSIS
        Resolves all SDProp-protected groups to their DistinguishedNames.
    .PARAMETER DomainSID
        The domain SID string.
    #>
    param([Parameter(Mandatory)][string]$DomainSID)

    $DNs = [System.Collections.Generic.List[string]]::new()
    foreach ($RID in $Script:ProtectedDomainRIDs) {
        try {
            $g = Get-ADGroup -Identity "$DomainSID-$RID" -ErrorAction Stop
            $DNs.Add($g.DistinguishedName) | Out-Null
        }
        catch {
            Write-Warning "Could not resolve domain group SID $DomainSID-$RID"
        }
    }
    foreach ($RID in $Script:ProtectedBuiltinRIDs) {
        try {
            $g = Get-ADGroup -Identity "S-1-5-32-$RID" -ErrorAction Stop
            $DNs.Add($g.DistinguishedName) | Out-Null
        }
        catch {
            Write-Warning "Could not resolve builtin group S-1-5-32-$RID"
        }
    }
    return $DNs
}

function Resolve-SIDToName {
    <#
    .SYNOPSIS
        Translates a SID string to an NTAccount name. Returns SID on failure.
    .PARAMETER SID
        The SID string to resolve.
    #>
    param([Parameter(Mandatory)][string]$SID)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate(
            [System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $SID
    }
}

function Backup-AdminSDHolderACL {
    <#
    .SYNOPSIS
        Exports the current AdminSDHolder ACL to a CSV file before making changes.
    .PARAMETER ACL
        The ActiveDirectorySecurity object to backup.
    .PARAMETER Path
        Optional output path. Defaults to timestamped file in current directory.
    #>
    param(
        [Parameter(Mandatory)][System.DirectoryServices.ActiveDirectorySecurity]$ACL,
        [string]$Path
    )
    if (-not $Path) {
        $Path = "AdminSDHolder_ACL_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    $Rules = $ACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $Rows = foreach ($Rule in $Rules) {
        [PSCustomObject]@{
            SID       = $Rule.IdentityReference.Value
            Rights    = $Rule.ActiveDirectoryRights.ToString()
            Type      = $Rule.AccessControlType.ToString()
            Inherited = $Rule.IsInherited
        }
    }
    $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    return $Path
}
