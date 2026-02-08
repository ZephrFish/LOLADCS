<#
.SYNOPSIS
    Domain Reconnaissance - Comprehensive AD enumeration (LOLBAS).
.DESCRIPTION
    Performs automated domain reconnaissance using only native Windows tools.
    Collects domain info, privileged accounts, delegation, SPNs, GPOs, trusts,
    password policy, and attack surface information.
.PARAMETER OutputDir
    Directory for report output (default: $env:TEMP\domain-recon)
.PARAMETER Quick
    Run quick mode (skip slow enumeration like stale computers)
.EXAMPLE
    .\Invoke-DomainRecon.ps1
.EXAMPLE
    .\Invoke-DomainRecon.ps1 -Quick
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "$env:TEMP\domain-recon",
    [switch]$Quick
)

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$report = [System.Text.StringBuilder]::new()

function Log {
    param([string]$Msg, [string]$Color = 'Gray')
    Write-Host $Msg -ForegroundColor $Color
    [void]$report.AppendLine($Msg -replace '\x1b\[[0-9;]*m','')
}

Write-Host ""
Write-Host "  Domain Reconnaissance - Native LOLBAS" -ForegroundColor White
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
Write-Host ""

$ctx = Get-ADContext

# ============================================================
#  1. DOMAIN OVERVIEW
# ============================================================
Log "  [1/10] DOMAIN OVERVIEW" 'Cyan'
Log "  ========================"
Write-Host ""
Write-Host "    PS> Get-ADDomain | Select-Object DNSRoot, Forest, DomainMode" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADForest | Select-Object ForestMode, Domains" -ForegroundColor DarkYellow
Write-Host ""

$dom = Get-ADDomain
$forest = Get-ADForest
Log "    Domain          : $($dom.DNSRoot)"
Log "    NetBIOS         : $($dom.NetBIOSName)"
Log "    Domain SID      : $($dom.DomainSID)"
Log "    Forest          : $($forest.Name)"
Log "    Domain Mode     : $($dom.DomainMode)"
Log "    Forest Mode     : $($forest.ForestMode)"
Log "    Domain Controllers:"
Get-ADDomainController -Filter * | ForEach-Object {
    Log "      $($_.Name) ($($_.IPv4Address)) - $($_.OperatingSystem)"
}
Log ""

# ============================================================
#  2. PASSWORD POLICY
# ============================================================
Log "  [2/10] PASSWORD POLICY" 'Cyan'
Log "  ========================"
Write-Host ""
Write-Host "    PS> Get-ADDefaultDomainPasswordPolicy" -ForegroundColor DarkYellow
Write-Host ""

$pp = Get-ADDefaultDomainPasswordPolicy
Log "    Min Length      : $($pp.MinPasswordLength)"
Log "    History         : $($pp.PasswordHistoryCount)"
Log "    Complexity      : $($pp.ComplexityEnabled)"
Log "    Max Age         : $($pp.MaxPasswordAge)"
Log "    Lockout Thresh  : $($pp.LockoutThreshold)"
Log "    Lockout Window  : $($pp.LockoutObservationWindow)"
Log "    Lockout Dur     : $($pp.LockoutDuration)"

# FGPP
$fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
if ($fgpps) {
    Log "    Fine-Grained Policies:"
    foreach ($f in $fgpps) {
        Log "      $($f.Name) (Precedence: $($f.Precedence), MinLen: $($f.MinPasswordLength))"
    }
}
Log ""

# ============================================================
#  3. PRIVILEGED ACCOUNTS
# ============================================================
Log "  [3/10] PRIVILEGED ACCOUNTS" 'Cyan'
Log "  ============================"
Write-Host ""
Write-Host "    PS> Get-ADGroupMember 'Domain Admins' -Recursive" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADUser -Filter {adminCount -eq 1}" -ForegroundColor DarkYellow
Write-Host ""

foreach ($grp in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
    try {
        $members = Get-ADGroupMember $grp -Recursive -ErrorAction SilentlyContinue
        Log "    $grp ($($members.Count)):"
        foreach ($m in $members | Select-Object -First 20) {
            Log "      - $($m.SamAccountName) ($($m.objectClass))"
        }
        if ($members.Count -gt 20) { Log "      ... and $($members.Count - 20) more" }
    } catch {
        Log "    $grp : (not accessible)" 'Yellow'
    }
}

$adminCount = (Get-ADUser -Filter {adminCount -eq 1} -ErrorAction SilentlyContinue | Measure-Object).Count
Log "    AdminCount=1 users: $adminCount"

# Machine Account Quota
$maq = (Get-ADObject -Identity $ctx.DomainDN -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
Log "    Machine Account Quota: $maq"
Log ""

# ============================================================
#  4. KERBEROS TARGETS
# ============================================================
Log "  [4/10] KERBEROS ATTACK SURFACE" 'Cyan'
Log "  ================================="
Write-Host ""
Write-Host "    PS> Get-ADUser -Filter {servicePrincipalName -ne `$null} -Properties servicePrincipalName" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}" -ForegroundColor DarkYellow
Write-Host ""

$kerbUsers = Get-ADUser -Filter {servicePrincipalName -ne "$null"} -Properties servicePrincipalName, adminCount -ErrorAction SilentlyContinue |
    Where-Object { $_.SamAccountName -ne 'krbtgt' -and $_.Enabled -eq $true }
Log "    Kerberoastable Accounts: $($kerbUsers.Count)"
foreach ($k in $kerbUsers) {
    $tag = if ($k.adminCount -eq 1) { " [ADMIN]" } else { "" }
    Log "      $($k.SamAccountName)$tag : $($k.servicePrincipalName -join ', ')"
}

$asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties userPrincipalName -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq $true }
Log "    AS-REP Roastable: $($asrepUsers.Count)"
foreach ($a in $asrepUsers) {
    Log "      $($a.SamAccountName)"
}
Log ""

# ============================================================
#  5. DELEGATION
# ============================================================
Log "  [5/10] DELEGATION" 'Cyan'
Log "  ==================="
Write-Host ""
Write-Host "    PS> Get-ADComputer -Filter {TrustedForDelegation -eq `$true}" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne `$null}" -ForegroundColor DarkYellow
Write-Host ""

$unconst = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties operatingSystem -ErrorAction SilentlyContinue |
    Where-Object { $_.DistinguishedName -notmatch 'Domain Controllers' }
Log "    Unconstrained (non-DC): $($unconst.Count)"
foreach ($u in $unconst) { Log "      $($u.Name) - $($u.operatingSystem)" }

$constrained = Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties 'msDS-AllowedToDelegateTo', sAMAccountName -ErrorAction SilentlyContinue
Log "    Constrained: $($constrained.Count)"
foreach ($c in $constrained) {
    Log "      $($c.sAMAccountName) -> $($c.'msDS-AllowedToDelegateTo' -join ', ')"
}

$rbcd = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne "$null"} -Properties sAMAccountName -ErrorAction SilentlyContinue
Log "    RBCD Configured: $($rbcd.Count)"
foreach ($r in $rbcd) { Log "      $($r.sAMAccountName)" }
Log ""

# ============================================================
#  6. TRUSTS
# ============================================================
Log "  [6/10] DOMAIN TRUSTS" 'Cyan'
Log "  ======================"
Write-Host ""
Write-Host "    PS> Get-ADTrust -Filter *" -ForegroundColor DarkYellow
Write-Host ""

$trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
if ($trusts) {
    foreach ($t in $trusts) {
        $dir = switch ($t.Direction) { 'Inbound' { '<-' } 'Outbound' { '->' } 'Bidirectional' { '<->' } default { '?' } }
        Log "    $($t.Name) $dir ($($t.TrustType)) Transitive:$($t.IsTreeParent -or $t.IsTreeRoot)"
    }
} else {
    Log "    No domain trusts found"
}
Log ""

# ============================================================
#  7. GPOs
# ============================================================
Log "  [7/10] GROUP POLICY" 'Cyan'
Log "  ===================="
Write-Host ""
Write-Host "    PS> Get-GPO -All | Select-Object DisplayName, GpoStatus" -ForegroundColor DarkYellow
Write-Host ""

try {
    $gpos = Get-ADObject -SearchBase "CN=Policies,CN=System,$($ctx.DomainDN)" `
        -Filter {objectClass -eq 'groupPolicyContainer'} `
        -Properties displayName, gPCFileSysPath -ErrorAction Stop
    Log "    Total GPOs: $($gpos.Count)"
    foreach ($g in $gpos | Select-Object -First 15) {
        Log "      $($g.displayName) -> $($g.gPCFileSysPath)"
    }
    if ($gpos.Count -gt 15) { Log "      ... and $($gpos.Count - 15) more" }
} catch {
    Log "    GPO enumeration failed: $($_.Exception.Message)" 'Yellow'
}
Log ""

# ============================================================
#  8. INTERESTING ACCOUNTS
# ============================================================
Log "  [8/10] INTERESTING ACCOUNTS" 'Cyan'
Log "  =============================="
Write-Host ""
Write-Host "    PS> Get-ADUser -Filter {description -ne `$null} -Properties description" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADUser -Filter {PasswordNeverExpires -eq `$true}" -ForegroundColor DarkYellow
Write-Host ""

# Accounts with descriptions (may contain passwords)
$descUsers = Get-ADUser -Filter {description -ne "$null" -and Enabled -eq $true} -Properties description -ErrorAction SilentlyContinue
Log "    Users with descriptions: $($descUsers.Count)"
foreach ($d in $descUsers | Select-Object -First 10) {
    Log "      $($d.SamAccountName) : $($d.Description)"
}

# Password never expires
$neverExp = (Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue | Measure-Object).Count
Log "    Password Never Expires: $neverExp"

# PASSWD_NOTREQD
$noReq = (Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} -ErrorAction SilentlyContinue | Measure-Object).Count
Log "    PASSWD_NOTREQD: $noReq"

# Disabled accounts
$disabledCount = (Get-ADUser -Filter {Enabled -eq $false} -ErrorAction SilentlyContinue | Measure-Object).Count
Log "    Disabled accounts: $disabledCount"

# gMSAs
$gmsas = Get-ADServiceAccount -Filter * -Properties servicePrincipalName -ErrorAction SilentlyContinue
Log "    gMSA accounts: $(if ($gmsas) { $gmsas.Count } else { 0 })"
if ($gmsas) {
    foreach ($g in $gmsas) { Log "      $($g.SamAccountName)" }
}
Log ""

# ============================================================
#  9. COMPUTERS
# ============================================================
Log "  [9/10] COMPUTER LANDSCAPE" 'Cyan'
Log "  ==========================="
Write-Host ""
Write-Host "    PS> Get-ADComputer -Filter * -Properties operatingSystem | Group-Object operatingSystem" -ForegroundColor DarkYellow
Write-Host ""

$computers = Get-ADComputer -Filter * -Properties operatingSystem -ErrorAction SilentlyContinue
$osGroups = $computers | Group-Object operatingSystem | Sort-Object Count -Descending
Log "    Total Computers: $($computers.Count)"
foreach ($og in $osGroups) {
    $osName = if ($og.Name) { $og.Name } else { "(no OS set)" }
    Log "      $osName : $($og.Count)"
}

if (-not $Quick) {
    $staleThreshold = (Get-Date).AddDays(-90)
    $staleCount = ($computers | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $staleThreshold } | Measure-Object).Count
    Log "    Stale (90+ days): $staleCount"
}

# LAPS check
$lapsCount = (Get-ADComputer -Filter {ms-Mcs-AdmPwd -ne "$null"} -ErrorAction SilentlyContinue | Measure-Object).Count
$lapsV2Count = (Get-ADComputer -Filter {msLAPS-Password -ne "$null"} -ErrorAction SilentlyContinue | Measure-Object).Count
Log "    LAPS v1 deployed: $lapsCount"
Log "    LAPS v2 deployed: $lapsV2Count"
Log ""

# ============================================================
#  10. AD CS (Certificate Services)
# ============================================================
Log "  [10/10] AD CS OVERVIEW" 'Cyan'
Log "  ========================"
Write-Host ""
Write-Host "    PS> Get-ADObject -SearchBase `"$($ctx.EnrollBase)`" -Filter {objectClass -eq 'pKIEnrollmentService'}" -ForegroundColor DarkYellow
Write-Host ""

try {
    $cas = Get-ADObject -SearchBase $ctx.EnrollBase `
        -Filter {objectClass -eq 'pKIEnrollmentService'} `
        -Properties dNSHostName, cn, certificateTemplates -ErrorAction Stop
    Log "    Certificate Authorities: $($cas.Count)"
    foreach ($ca in $cas) {
        Log "      $($ca.cn) on $($ca.dNSHostName)"
        $tplCount = if ($ca.certificateTemplates) { $ca.certificateTemplates.Count } else { 0 }
        Log "        Published templates: $tplCount"
    }

    $templates = Get-ADObject -SearchBase $ctx.TemplateBase `
        -Filter {objectClass -eq 'pKICertificateTemplate'} -ErrorAction Stop
    Log "    Total Templates: $($templates.Count)"
    Log "    [i] Run .\Invoke-Enumerate.ps1 for detailed ESC vulnerability scan"
} catch {
    Log "    AD CS not found or not accessible" 'Yellow'
}
Log ""

# ============================================================
#  SUMMARY
# ============================================================
Log "  ============================================" 'DarkCyan'
Log "  RECONNAISSANCE COMPLETE" 'Green'
Log "  ============================================" 'DarkCyan'

# Save report
$reportFile = "$OutputDir\domain-recon-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$report.ToString() | Out-File -FilePath $reportFile -Encoding ASCII -Force
Write-Host ""
Write-Host "  [+] Report saved: $reportFile" -ForegroundColor Cyan
Write-Host ""

# Quick wins summary
Write-Host "  --- Quick Wins ---" -ForegroundColor Yellow
if ($kerbUsers.Count -gt 0) {
    Write-Host "  [!] $($kerbUsers.Count) kerberoastable accounts - run .\Invoke-Kerberoast.ps1" -ForegroundColor Red
}
if ($asrepUsers.Count -gt 0) {
    Write-Host "  [!] $($asrepUsers.Count) AS-REP roastable accounts" -ForegroundColor Red
}
if ($unconst.Count -gt 0) {
    Write-Host "  [!] $($unconst.Count) unconstrained delegation hosts (non-DC)" -ForegroundColor Red
}
if ($maq -gt 0) {
    Write-Host "  [!] MAQ=$maq - machine account creation possible" -ForegroundColor Yellow
}
if ($noReq -gt 0) {
    Write-Host "  [!] $noReq accounts with PASSWD_NOTREQD" -ForegroundColor Red
}
Write-Host ""
