# Private/Constants.ps1
# Shared constants for AdminSDHolder-Toolkit.
# Dot-sourced by Public scripts — do not invoke directly.

# Well-known fixed SIDs always legitimate on AdminSDHolder
$Script:WellKnownSIDs = @(
    "S-1-5-18",       # SYSTEM
    "S-1-5-10",       # SELF
    "S-1-5-11",       # Authenticated Users
    "S-1-1-0",        # Everyone
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-32-554",   # Pre-Windows 2000 Compatible Access
    "S-1-5-32-560",   # Windows Authorization Access Group
    "S-1-5-32-561"    # Terminal Server License Servers
)

# Domain-relative RIDs appended to $DomainSID at runtime -> legitimate ACE principals
$Script:LegitDomainRIDs = @(
    "512",   # Domain Admins
    "519",   # Enterprise Admins
    "517"    # Cert Publishers
)

# ACE rights pattern that constitutes a potential backdoor
$Script:DangerousRights = "GenericAll|WriteDacl|WriteOwner"

# Groups whose members are covered by SDProp (AdminCount=1)
$Script:ProtectedDomainRIDs = @(
    "512",   # Domain Admins
    "517",   # Cert Publishers
    "518",   # Schema Admins
    "519"    # Enterprise Admins
)
$Script:ProtectedBuiltinRIDs = @(
    "544",   # BUILTIN\Administrators
    "548",   # Account Operators
    "549",   # Server Operators
    "550",   # Print Operators
    "551"    # Backup Operators
)

# Accounts that must never be cleaned up (by domain RID)
$Script:SafeListRIDs = @(
    "500",   # Built-in Administrator
    "502"    # krbtgt
)
