# 🛡️ AdminSDHolder-Toolkit

A complete PowerShell toolkit to **audit**, **detect backdoors**, and **clean up** orphaned AdminSDHolder (`AdminCount=1`) accounts in Active Directory.

> **🌍 Language-Agnostic:** Uses Well-Known SIDs instead of hardcoded group names. Works flawlessly on **any** Active Directory environment (English, French, German, Spanish, etc.).

---

## 📋 Table of Contents

- [The Problem](#-the-problem)
- [Toolkit Overview](#-toolkit-overview)
- [Scripts](#-scripts)
  - [Invoke-AdminSDHolderCleanup.ps1](#-invoke-adminsdholdercleanupp1)
  - [Get-AdminSDHolderACL.ps1](#-get-adminsdholderaclps1)
  - [Repair-AdminSDHolderACL.ps1](#-repair-adminsdholderaclps1)
  - [Test-AdminSDHolderBackdoor.ps1](#-test-adminsdholderbackdoorps1)
- [Requirements](#-requirements)
- [How it Works](#-how-it-works)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔥 The Problem

When a user is added to a privileged Active Directory group (e.g., Domain Admins), the **SDProp** background process automatically:

1. Sets `AdminCount = 1` on the user object.
2. **Disables ACL inheritance**, applying a highly restrictive Security Descriptor from the `AdminSDHolder` template.

When the user is later **removed** from the privileged group, Active Directory **does NOT revert these changes**. This creates two major issues:

### 🧹 Orphaned Accounts (False Positives)
Over time, dozens or hundreds of standard user accounts accumulate with `AdminCount=1` and broken inheritance. This:
- Generates **false positives** in security audits (PingCastle, BloodHound, Purple Knight).
- **Blocks Helpdesk teams** from managing these accounts (password resets, unlocks).
- Creates noise that masks real security issues.

### 🚪 Backdoor Persistence
Attackers who gain Domain Admin access can **poison the AdminSDHolder ACL** by granting a standard account `GenericAll` or `WriteDacl` rights on the `AdminSDHolder` object. The `SDProp` process will then **automatically propagate** these permissions to all privileged accounts every 60 minutes, giving the attacker persistent control even after remediation.

---

## 🧰 Toolkit Overview

| Script | Purpose | Mode |
|---|---|---|
| `Invoke-AdminSDHolderCleanup.ps1` | 🧹 Cleans orphaned `AdminCount=1` accounts | Defensive |
| `Get-AdminSDHolderACL.ps1` | 🔍 Audits AdminSDHolder ACLs for backdoors | Defensive |
| `Repair-AdminSDHolderACL.ps1` | 🛡️ Removes unauthorized ACL entries | Defensive |
| `Test-AdminSDHolderBackdoor.ps1` | 🧪 PoC to validate detection pipeline | Testing |

All scripts support two execution modes:
- **`-AuditOnly`** (default): Read-only. Lists findings without modifying anything.
- **`-Remediate`**: Applies fixes with confirmation prompt.

---

## 📜 Scripts

### 🧹 Invoke-AdminSDHolderCleanup.ps1

**Purpose:** Identifies users with `AdminCount=1` who are no longer members of any privileged group, and cleans them up by resetting `AdminCount` and restoring ACL inheritance.

**Why most scripts fail:** They rely on hardcoded group names like `"Domain Admins"` which won't match on a French AD (`"Admins du domaine"`) or German AD (`"Domänen-Admins"`). This script uses **Well-Known SIDs** (e.g., `-512` for Domain Admins) to resolve groups universally.

```powershell
# Audit mode - See what would be cleaned (no changes)
.\Invoke-AdminSDHolderCleanup.ps1 -AuditOnly

# Remediation mode - Clean orphaned accounts
.\Invoke-AdminSDHolderCleanup.ps1 -Remediate
```

**What it does for each orphaned account:**
1. Clears the `AdminCount` attribute (`Set-ADUser -Clear AdminCount`).
2. Restores ACL inheritance (`SetAccessRuleProtection($false, $false)`), allowing Helpdesk to manage the account again.

**What it does NOT touch:**
- Accounts currently in privileged groups (Domain Admins, Enterprise Admins, etc.).
- Built-in accounts (`Administrator`, `krbtgt`) — protected via SID-based SafeList.

---

### 🔍 Get-AdminSDHolderACL.ps1

**Purpose:** Reads and analyzes the Access Control List (ACL) of the `AdminSDHolder` object to detect potential backdoors.

```powershell
# Audit the AdminSDHolder ACL
.\Get-AdminSDHolderACL.ps1

# Export results to CSV for reporting
.\Get-AdminSDHolderACL.ps1 -ExportCSV "C:\temp\AdminSDHolder_ACL.csv"
```

**Threat detection logic:**
- Each ACL entry is evaluated against a whitelist of expected SIDs.
- Entries with `GenericAll`, `WriteDacl`, or `WriteOwner` from non-standard accounts are flagged as **`HIGH (Potential Backdoor)`**.
- A clear **red alert** is displayed if suspicious entries are found.

**How to read the results:**

| Permission | Threat Level | Expected On |
|---|---|---|
| `GenericRead` | Low | Authenticated Users |
| `ReadProperty` | Low | Pre-Windows 2000 Access, SELF |
| `GenericAll` | 🔴 **HIGH** | Only SYSTEM and Administrators |
| `WriteDacl` | 🔴 **HIGH** | Only SYSTEM and Administrators |
| `WriteOwner` | 🔴 **HIGH** | Only SYSTEM and Administrators |

---

### 🛡️ Repair-AdminSDHolderACL.ps1

**Purpose:** Removes unauthorized ACL entries from the `AdminSDHolder` object, neutralizing any detected backdoor.

```powershell
# See what would be removed (no changes)
.\Repair-AdminSDHolderACL.ps1 -AuditOnly

# Remove unauthorized entries
.\Repair-AdminSDHolderACL.ps1 -Remediate
```

**How it works:**
1. Builds a whitelist of legitimate SIDs expected on `AdminSDHolder` (SYSTEM, Administrators, Domain Admins, Enterprise Admins, Cert Publishers, etc.).
2. Compares every ACL entry against this whitelist.
3. Any entry **not** in the whitelist is flagged and removed upon confirmation.
4. Re-reads the ACL after remediation to verify cleanup success.

---

### 🧪 Test-AdminSDHolderBackdoor.ps1

**Purpose:** Proof of Concept (PoC) script to validate that the detection and remediation pipeline works correctly. Simulates a real-world AdminSDHolder backdoor by adding `GenericAll` for a test account.

```powershell
# Add a test backdoor (manual cleanup required)
.\Test-AdminSDHolderBackdoor.ps1 -TestAccount "testuser"

# Add a test backdoor with automatic cleanup
.\Test-AdminSDHolderBackdoor.ps1 -TestAccount "testuser" -Cleanup
```

**Recommended testing workflow:**
```
1. .\Test-AdminSDHolderBackdoor.ps1 -TestAccount "testuser"    # Create backdoor
2. .\Get-AdminSDHolderACL.ps1                                   # Verify detection ✅
3. .\Repair-AdminSDHolderACL.ps1 -Remediate                     # Remove backdoor
4. .\Get-AdminSDHolderACL.ps1                                   # Verify clean state ✅
```

> ⚠️ **Warning:** This script requires Domain Admin privileges and modifies the AdminSDHolder Security Descriptor. Only use in controlled test environments or with proper authorization.

---

## 📝 Requirements

- **PowerShell 5.1+**
- **Active Directory PowerShell Module** (RSAT: `Install-WindowsFeature RSAT-AD-PowerShell`)
- **Domain Admin** or equivalent privileges (for `-Remediate` and `Test-AdminSDHolderBackdoor.ps1`)
- Domain-joined machine with network access to a Domain Controller

---

## 🧠 How it Works

### The SID-Based Approach

Most AdminSDHolder scripts you'll find online use hardcoded group names:
```powershell
# ❌ Fragile - Fails on non-English Active Directory
Get-ADGroup -Identity "Domain Admins"
```

This toolkit uses **Well-Known Security Identifiers (SIDs)** that are universal across all AD languages:
```powershell
# ✅ Universal - Works on ANY Active Directory
# Domain Admins always ends with RID -512
$DomainAdminsSID = "$DomainSID-512"
Get-ADGroup -Identity $DomainAdminsSID
```

### Well-Known RIDs Used

| RID | Group |
|---|---|
| `-500` | Built-in Administrator |
| `-502` | krbtgt |
| `-512` | Domain Admins |
| `-517` | Cert Publishers |
| `-518` | Schema Admins |
| `-519` | Enterprise Admins |
| `S-1-5-32-544` | BUILTIN\Administrators |
| `S-1-5-32-548` | Account Operators |
| `S-1-5-32-549` | Server Operators |
| `S-1-5-32-550` | Print Operators |
| `S-1-5-32-551` | Backup Operators |

---

## 👤 Author

**Frank Ferman** — Security Engineer

Built with ❤️ to help Blue Teams secure Active Directory environments worldwide.
