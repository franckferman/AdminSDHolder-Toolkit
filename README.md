<div align="center">

# AD-AdminSDHolder-Toolkit

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://github.com/franckferman/AD-AdminSDHolder-Toolkit)
[![CI](https://github.com/franckferman/AD-AdminSDHolder-Toolkit/actions/workflows/ci.yml/badge.svg?branch=stable)](https://github.com/franckferman/AD-AdminSDHolder-Toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL--v3-16a34a)](LICENSE)

PowerShell toolkit covering two AdminSDHolder attack surfaces: ACL backdoor detection/remediation, and orphaned `AdminCount=1` account cleanup.

> **Language-agnostic.** All group resolution goes through Well-Known SIDs and domain-relative RIDs — never hardcoded names. Works on any AD locale (EN, FR, DE, ES, ...).

</div>

---

## Table of Contents

- [Background](#background)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Usage](#usage)
  - [In-Memory](#in-memory)
  - [Standalone](#standalone)
  - [Wrapper](#wrapper)
  - [Module](#module)
- [Script Reference](#script-reference)
  - [Get-AdminSDHolderACL](#get-adminsdholderacl)
  - [Repair-AdminSDHolderACL](#repair-adminsdholderacl)
  - [Invoke-AdminSDHolderCleanup](#invoke-adminsdholdercleanup)
  - [Add-AdminSDHolderBackdoor](#add-adminsdholderbackdoor)
- [Tools](#tools)
  - [Invoke-PSEncoder.py](#invoke-psencoderpy)
  - [Sign-Scripts.ps1](#sign-scriptsps1)
- [SID Reference](#sid-reference)
- [License](#license)

---

## Background

### SDProp and AdminSDHolder

Every 60 minutes, **SDProp** (running on the PDC Emulator) copies the Security Descriptor of `CN=AdminSDHolder,CN=System,<domain DN>` onto every account that belongs to a protected group. It also sets `AdminCount=1` on those accounts and disables ACL inheritance.

Protected groups covered by SDProp: Domain Admins, Enterprise Admins, Schema Admins, Cert Publishers, BUILTIN\Administrators, Account Operators, Server Operators, Print Operators, Backup Operators.

### AdminSDHolder ACL backdoor

An attacker with Domain Admin access grants a low-privilege account `GenericAll` (or `WriteDacl` / `WriteOwner`) on the AdminSDHolder object. SDProp then propagates that ACE to every protected account automatically — the target account gains persistent full control over the entire privileged tier without ever touching those accounts directly. The backdoor survives account password resets, DA session teardown, and most IR playbooks that focus on group membership rather than AdminSDHolder ACL.

### Orphaned AdminCount accounts

When a user is removed from a protected group, SDProp stops managing their ACL — but it does not revert `AdminCount` or restore inheritance. Over time this creates accounts with `AdminCount=1` and broken inheritance that are no longer in any protected group. Impact: PingCastle / BloodHound false positives, Helpdesk locked out of password resets and unlocks, operational noise masking real findings.

---

## Project Structure

```
AD-AdminSDHolder-Toolkit/
├── AdminSDHolder.ps1           Interactive wrapper + -Action non-interactive mode
├── AdminSDHolder.psm1          Optional PowerShell module
│
├── Private/
│   ├── Constants.ps1           Shared SID constants, RID tables, dangerous-rights pattern
│   └── Helpers.ps1             Shared functions: domain context, SID resolution, ACL backup
│
├── Public/
│   ├── Get-AdminSDHolderACL.ps1         Audit AdminSDHolder ACL for unauthorized ACEs
│   ├── Repair-AdminSDHolderACL.ps1      Remove unauthorized ACEs from AdminSDHolder
│   ├── Invoke-AdminSDHolderCleanup.ps1  Remediate orphaned AdminCount=1 accounts
│   └── Add-AdminSDHolderBackdoor.ps1    Insert a GenericAll backdoor ACE on AdminSDHolder
│
└── tools/
    ├── Invoke-PSEncoder.py     Generate -EncodedCommand oneliners (execution policy bypass)
    └── Sign-Scripts.ps1        Authenticode signing with RFC 3161 timestamp
```

Each `Public/` script auto-loads `Private/` when run from the standard layout, and falls back to inline definitions when run standalone from any directory.

---

## Requirements

| | |
|---|---|
| PowerShell | 5.1+ |
| AD module | `Import-Module ActiveDirectory` (RSAT) |
| Privileges | Domain Admin for `-Remediate` and `Add-AdminSDHolderBackdoor` |
| Network | Domain-joined machine, DC connectivity |

```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

---

## Usage

### In-Memory

Run directly from GitHub without cloning. `-EncodedCommand` bypasses `Restricted` and `AllSigned` execution policies.

```powershell
# IEX — detect AdminSDHolder ACL backdoors
iex (iwr 'https://raw.githubusercontent.com/franckferman/AD-AdminSDHolder-Toolkit/stable/Public/Get-AdminSDHolderACL.ps1' -UseBasicParsing).Content

# IEX — audit orphaned AdminCount=1 accounts
iex (iwr 'https://raw.githubusercontent.com/franckferman/AD-AdminSDHolder-Toolkit/stable/Public/Invoke-AdminSDHolderCleanup.ps1' -UseBasicParsing).Content

# IEX — audit AdminSDHolder ACL (repair mode, read-only by default)
iex (iwr 'https://raw.githubusercontent.com/franckferman/AD-AdminSDHolder-Toolkit/stable/Public/Repair-AdminSDHolderACL.ps1' -UseBasicParsing).Content

# -EncodedCommand — execution policy not enforced (UTF-16LE Base64)
powershell.exe -NonInteractive -NoProfile -NoLogo -EncodedCommand aQBlAHgAIAAoAGkAdwByACAAJwBoAHQAdABwAHMAOgAvAC8AcgBhAHcALgBnAGkAdABoAHUAYgB1AHMAZQByAGMAbwBuAHQAZQBuAHQALgBjAG8AbQAvAGYAcgBhAG4AYwBrAGYAZQByAG0AYQBuAC8AQQBEAC0AQQBkAG0AaQBuAFMARABIAG8AbABkAGUAcgAtAFQAbwBvAGwAawBpAHQALwBzAHQAYQBiAGwAZQAvAFAAdQBiAGwAaQBjAC8ARwBlAHQALQBBAGQAbQBpAG4AUwBEAEgAbwBsAGQAZQByAEEAQwBMAC4AcABzADEAJwAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAKQAuAEMAbwBuAHQAZQBuAHQA
```

Generate custom `-EncodedCommand` oneliners with `tools/Invoke-PSEncoder.py`.

### Standalone

```powershell
.\Public\Get-AdminSDHolderACL.ps1
.\Public\Get-AdminSDHolderACL.ps1 -ExportCSV C:\out\acl.csv

.\Public\Invoke-AdminSDHolderCleanup.ps1
.\Public\Invoke-AdminSDHolderCleanup.ps1 -Remediate

.\Public\Repair-AdminSDHolderACL.ps1
.\Public\Repair-AdminSDHolderACL.ps1 -Remediate

.\Public\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup"
.\Public\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup" -Remove
```

### Wrapper

**Interactive:**
```powershell
.\AdminSDHolder.ps1
```

```
  ==========================================================
  =                                                        =
  =         AdminSDHolder-Toolkit                         =
  =         Active Directory Persistence Toolkit          =
  =                                                        =
  ==========================================================

  ----------------------------------------------------------
  |  AUDIT (read-only)                                     |
  |    [1] Audit orphaned AdminCount accounts              |
  |    [2] Detect AdminSDHolder ACL backdoors              |
  |    [3] Full Audit (1 + 2)                              |
  |                                                        |
  |  REMEDIATION (modifies AD)                             |
  |    [4] Cleanup orphaned AdminCount accounts            |
  |    [5] Repair AdminSDHolder ACL                        |
  |                                                        |
  |  OFFENSIVE                                             |
  |    [6] Insert AdminSDHolder backdoor ACE               |
  |                                                        |
  |    [Q] Quit                                            |
  ----------------------------------------------------------
```

**Non-interactive (`-Action`):**
```powershell
.\AdminSDHolder.ps1 -Action FullAudit
.\AdminSDHolder.ps1 -Action Detect
.\AdminSDHolder.ps1 -Action Repair
.\AdminSDHolder.ps1 -Action Cleanup
.\AdminSDHolder.ps1 -Action Backdoor
```

| Action | |
|---|---|
| `Audit` | Orphaned AdminCount audit — read-only |
| `Detect` | AdminSDHolder ACL backdoor scan — read-only |
| `FullAudit` | Audit + Detect — read-only |
| `Cleanup` | Orphaned account remediation — writes to AD |
| `Repair` | Remove unauthorized ACEs — writes to AD |
| `Backdoor` | Insert GenericAll backdoor ACE — writes to AD |

### Module

```powershell
Import-Module .\AdminSDHolder.psm1

Get-AdminSDHolderACL
Get-AdminSDHolderACL -ExportCSV C:\reports\acl.csv

Invoke-AdminSDHolderCleanup
Invoke-AdminSDHolderCleanup -Remediate

Repair-AdminSDHolderACL
Repair-AdminSDHolderACL -Remediate -BackupPath C:\backups\acl_pre.csv

Add-AdminSDHolderBackdoor -Account "svc_backup"
Add-AdminSDHolderBackdoor -Account "svc_backup" -Remove
```

---

## Script Reference

### Get-AdminSDHolderACL

Reads the AdminSDHolder Security Descriptor and flags every ACE whose principal is not in the default whitelist.

| Parameter | Type | |
|---|---|---|
| `-ExportCSV` | String | Export findings to CSV |

**Threat detection:** any ACE with `GenericAll`, `WriteDacl`, or `WriteOwner` from a non-whitelisted SID is flagged `HIGH (Potential Backdoor)`.

**Whitelist:**

| SID | Principal |
|---|---|
| `S-1-5-18` | SYSTEM |
| `S-1-5-10` | SELF |
| `S-1-5-11` | Authenticated Users |
| `S-1-1-0` | Everyone |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-32-554` | Pre-Windows 2000 Compatible Access |
| `S-1-5-32-560` | Windows Authorization Access Group |
| `S-1-5-32-561` | Terminal Server License Servers |
| `<DomainSID>-512` | Domain Admins |
| `<DomainSID>-519` | Enterprise Admins |
| `<DomainSID>-517` | Cert Publishers |

---

### Repair-AdminSDHolderACL

Removes ACEs from AdminSDHolder that are not in the whitelist above.

| Parameter | Type | |
|---|---|---|
| `-Remediate` | Switch | Remove entries after confirmation. Default: read-only. |
| `-BackupPath` | String | Custom path for the pre-change ACL backup CSV. |

All removals are staged in-memory and committed in a single `CommitChanges()` call. A CSV backup of the ACL is written before any change is made. Uses `GetAccessRules($true, $true, ...)` — same scope as `Get-AdminSDHolderACL`.

---

### Invoke-AdminSDHolderCleanup

Identifies `AdminCount=1` users who are no longer in any SDProp-protected group and optionally remediates them.

| Parameter | Type | |
|---|---|---|
| `-Remediate` | Switch | Reset AdminCount and restore ACL inheritance. Default: read-only. |

**Protected groups resolved by SID:**

| SID | Group |
|---|---|
| `<DomainSID>-512` | Domain Admins |
| `<DomainSID>-517` | Cert Publishers |
| `<DomainSID>-518` | Schema Admins |
| `<DomainSID>-519` | Enterprise Admins |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-32-548` | Account Operators |
| `S-1-5-32-549` | Server Operators |
| `S-1-5-32-550` | Print Operators |
| `S-1-5-32-551` | Backup Operators |

**SafeList (never touched):** `-500` (Administrator), `-502` (krbtgt).

**Primary group handling:** resolved by direct SID construction `$DomainSID-$PrimaryGroupId` against a HashSet — no LDAP roundtrip per user, no regex.

**Per account remediation:**
1. `Set-ADUser -Clear AdminCount`
2. `SetAccessRuleProtection($false, $false)` — restores inheritance

---

### Add-AdminSDHolderBackdoor

Grants `GenericAll` to a specified account on AdminSDHolder. SDProp propagates the ACE to every protected group member within 60 minutes.

| Parameter | Type | |
|---|---|---|
| `-Account` | String (Mandatory) | SamAccountName of the target principal. |
| `-Remove` | Switch | After insertion, wait for ENTER, then pull the ACE. |

Idempotent — checks for an existing GenericAll ACE for the SID before inserting.

```powershell
# Insert — pull manually with Repair-AdminSDHolderACL -Remediate
.\Public\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup"

# Insert and pull on ENTER
.\Public\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup" -Remove
```

**Validation chain:**
```powershell
# 1. Confirm clean baseline
.\AdminSDHolder.ps1 -Action Detect

# 2. Insert backdoor ACE
.\Public\Add-AdminSDHolderBackdoor.ps1 -Account "svc_backup"

# 3. Confirm detection
.\AdminSDHolder.ps1 -Action Detect

# 4. Remediate
.\AdminSDHolder.ps1 -Action Repair

# 5. Confirm clean state
.\AdminSDHolder.ps1 -Action Detect
```

---

## Tools

### Invoke-PSEncoder.py

Encodes PS1 files or inline commands as Base64 UTF-16LE and outputs a `powershell.exe -EncodedCommand` oneliner. `-EncodedCommand` is evaluated as an in-memory string — execution policy (`Restricted`, `AllSigned`) is not enforced.

```
python3 tools/Invoke-PSEncoder.py <file>
python3 tools/Invoke-PSEncoder.py -c "STRING"

Options:
  --hidden    -WindowStyle Hidden
  --bypass    -ExecutionPolicy Bypass
  --32        SysWOW64 (32-bit PowerShell)
  --noexit    -NoExit
  -q          Oneliner only, no decoration
```

```bash
python3 tools/Invoke-PSEncoder.py Public/Get-AdminSDHolderACL.ps1

python3 tools/Invoke-PSEncoder.py -c "Invoke-AdminSDHolderCleanup"

python3 tools/Invoke-PSEncoder.py --hidden Public/Repair-AdminSDHolderACL.ps1

# Pipe to clipboard
python3 tools/Invoke-PSEncoder.py -q Public/Get-AdminSDHolderACL.ps1 | xclip -selection clipboard
python3 tools/Invoke-PSEncoder.py -q Public/Get-AdminSDHolderACL.ps1 | pbcopy
```

### Sign-Scripts.ps1

Authenticode signing with SHA-256 and RFC 3161 timestamp countersignature. A timestamped signature remains valid after the signing certificate expires — critical for EDR compatibility.

```powershell
# Sign with an existing cert (by thumbprint)
.\tools\Sign-Scripts.ps1 -CertThumbprint "ABCDEF1234..."

# Sign with a temporary self-signed cert (auto-created, auto-deleted after signing)
.\tools\Sign-Scripts.ps1
```

If no `-CertThumbprint` is provided, a `CodeSigningCert` valid for 24 hours is created in `Cert:\CurrentUser\My`, used for signing, then deleted immediately. The timestamp makes the signatures durable regardless.

---

## SID Reference

### Domain-relative RIDs

| RID | |
|---|---|
| `-500` | Built-in Administrator |
| `-501` | Guest |
| `-502` | krbtgt |
| `-512` | Domain Admins |
| `-513` | Domain Users |
| `-514` | Domain Guests |
| `-515` | Domain Computers |
| `-516` | Domain Controllers |
| `-517` | Cert Publishers |
| `-518` | Schema Admins |
| `-519` | Enterprise Admins |
| `-520` | Group Policy Creator Owners |
| `-521` | Read-only Domain Controllers |

### BUILTIN

| SID | |
|---|---|
| `S-1-5-32-544` | Administrators |
| `S-1-5-32-545` | Users |
| `S-1-5-32-546` | Guests |
| `S-1-5-32-548` | Account Operators |
| `S-1-5-32-549` | Server Operators |
| `S-1-5-32-550` | Print Operators |
| `S-1-5-32-551` | Backup Operators |
| `S-1-5-32-554` | Pre-Windows 2000 Compatible Access |
| `S-1-5-32-555` | Remote Desktop Users |
| `S-1-5-32-556` | Network Configuration Operators |
| `S-1-5-32-560` | Windows Authorization Access Group |
| `S-1-5-32-561` | Terminal Server License Servers |

### Universal

| SID | |
|---|---|
| `S-1-1-0` | Everyone |
| `S-1-5-10` | SELF |
| `S-1-5-11` | Authenticated Users |
| `S-1-5-18` | SYSTEM |
| `S-1-5-19` | Local Service |
| `S-1-5-20` | Network Service |

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

---

**franckferman**
