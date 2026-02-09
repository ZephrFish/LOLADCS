<#
.SYNOPSIS
    AD CS Enumeration - Scan for all ESC1-ESC13 conditions.
.DESCRIPTION
    Discovers vulnerable certificate templates, CA misconfigurations,
    HTTP endpoints, ACL weaknesses, and certificate binding enforcement.

    Supports three modes:
      - Local (default)  : Uses AD PowerShell module on a domain-joined machine.
      - Remote (-Server) : Uses .NET LDAP with supplied credentials. No RSAT or domain join needed.
      - Snapshot (-Snapshot) : Parses an ADExplorer .dat file offline. No network needed.
.PARAMETER SkipHTTP
    Skip ESC8 HTTP endpoint probing (quieter, no outbound HTTP connections).
.PARAMETER Server
    Remote mode: DC hostname/FQDN/IP to connect to via LDAP.
.PARAMETER Credential
    Remote mode: PSCredential for LDAP authentication. Prompted if omitted with -Server.
.PARAMETER Port
    Remote mode: LDAP port (default 389, auto-set to 636 with -UseSSL).
.PARAMETER UseSSL
    Remote mode: Use LDAPS (SSL/TLS).
.PARAMETER Snapshot
    Snapshot mode: Path to an ADExplorer .dat snapshot file for offline analysis.
.PARAMETER VulnerableOnly
    Only display templates with at least one ESC finding (Remote/Snapshot modes).
.PARAMETER OutputFile
    Save the full report to a text file.
.EXAMPLE
    .\Invoke-Enumerate.ps1
    Domain-joined enumeration using AD PowerShell module.
.EXAMPLE
    .\Invoke-Enumerate.ps1 -Server dc01.corp.local
    Remote enumeration (prompts for credentials).
.EXAMPLE
    $cred = Get-Credential CORP\admin
    .\Invoke-Enumerate.ps1 -Server 10.0.0.5 -Credential $cred -UseSSL
.EXAMPLE
    .\Invoke-Enumerate.ps1 -Snapshot .\snapshot.dat
    Offline analysis of an ADExplorer snapshot.
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [switch]$SkipHTTP,
    [string]$Server,
    [PSCredential]$Credential,
    [int]$Port = 389,
    [switch]$UseSSL,
    [string]$Snapshot,
    [switch]$VulnerableOnly,
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

# ============================================================================
#  MODE DETECTION
# ============================================================================

$Mode = 'Local'
if ($Snapshot)  { $Mode = 'Snapshot' }
elseif ($Server) { $Mode = 'Remote' }

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# Only load adcs-common.ps1 for local mode (requires AD module + domain join)
if ($Mode -eq 'Local') {
    . "$_dir\adcs-common.ps1"
}

# ============================================================================
#  SHARED CONSTANTS
# ============================================================================

$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002
$CT_FLAG_NO_SECURITY_EXTENSION     = 0x00080000

$authEKUs  = @("1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.311.20.2.2","1.3.6.1.5.2.3.4","2.5.29.37.0")
$agentEKU  = "1.3.6.1.4.1.311.20.2.1"

$OID_MAP = @{
    "1.3.6.1.5.5.7.3.1"="Server Authentication";"1.3.6.1.5.5.7.3.2"="Client Authentication"
    "1.3.6.1.5.5.7.3.3"="Code Signing";"1.3.6.1.5.5.7.3.4"="Secure Email"
    "1.3.6.1.4.1.311.20.2.1"="Certificate Request Agent";"1.3.6.1.4.1.311.20.2.2"="Smart Card Logon"
    "1.3.6.1.5.2.3.4"="PKINIT Client Authentication";"2.5.29.37.0"="Any Purpose"
    "1.3.6.1.4.1.311.21.5"="CA Exchange";"1.3.6.1.4.1.311.10.3.4"="Encrypting File System"
}

$ADS_RIGHT_WRITE_DAC     = 0x00040000
$ADS_RIGHT_WRITE_OWNER   = 0x00080000
$ADS_RIGHT_GENERIC_ALL   = 0x10000000
$ADS_RIGHT_GENERIC_WRITE = 0x40000000
$ADS_RIGHT_DS_WRITE_PROP = 0x00000020
$ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
$DANGEROUS_MASK = $ADS_RIGHT_WRITE_DAC -bor $ADS_RIGHT_WRITE_OWNER -bor $ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_GENERIC_WRITE

$ENROLL_GUID     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
$PRIVILEGED_SIDS = @('S-1-5-18','S-1-5-9','S-1-5-32-544')
$PRIV_RID_SUFFIX = @('-512','-518','-519')
$WELLKNOWN_SIDS  = @{
    'S-1-1-0'='Everyone';'S-1-5-7'='Anonymous Logon';'S-1-5-11'='Authenticated Users'
    'S-1-5-18'='SYSTEM';'S-1-5-9'='Enterprise DCs';'S-1-5-32-544'='BUILTIN\Administrators'
    'S-1-5-32-545'='BUILTIN\Users'
}
$lowPrivGroups = @('Authenticated Users','Domain Users','Domain Computers','Everyone')

$script:ReportLines = [System.Collections.Generic.List[string]]::new()
$findings   = @()
$exploits   = @()
$caConfigs  = @()

# ============================================================================
#  SHARED HELPERS (available in all modes)
# ============================================================================

function Out-Line {
    param([string]$Text = '', [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
    $script:ReportLines.Add($Text)
}

function _WriteBanner {
    param([string]$ESC, [string]$Desc)
    $p1 = [Math]::Max(0,42-$ESC.Length); $p2 = [Math]::Max(0,58-$Desc.Length)
    Out-Line ""
    Out-Line "  +==============================================================+" 'DarkCyan'
    Out-Line "  |  AD CS LOLBAS - $ESC$(' '*$p1)|" 'DarkCyan'
    Out-Line "  |  $Desc$(' '*$p2)|" 'DarkCyan'
    Out-Line "  +==============================================================+" 'DarkCyan'
    Out-Line ""
}

function _WriteStage {
    param([int]$N,[string]$Name,[string]$Status='RUNNING')
    $c = switch($Status){'RUNNING'{'Cyan'}'COMPLETE'{'Green'}'SKIPPED'{'Yellow'}'FAILED'{'Red'}}
    $i = switch($Status){'RUNNING'{'>>>'}'COMPLETE'{'[+]'}'SKIPPED'{'[~]'}'FAILED'{'[-]'}}
    Out-Line "  $i STAGE $N - $Name" $c
}

function Resolve-SIDName {
    param([string]$SID,[string]$DomainSID)
    if ($WELLKNOWN_SIDS.ContainsKey($SID)) { return $WELLKNOWN_SIDS[$SID] }
    if ($DomainSID) {
        if ($SID -eq "$DomainSID-513") { return 'Domain Users' }
        if ($SID -eq "$DomainSID-515") { return 'Domain Computers' }
        if ($SID -eq "$DomainSID-512") { return 'Domain Admins' }
        if ($SID -eq "$DomainSID-519") { return 'Enterprise Admins' }
    }
    return $SID
}

function Test-PrivilegedSID {
    param([string]$SID,[string]$DomainSID)
    if ($SID -in $PRIVILEGED_SIDS) { return $true }
    if ($DomainSID) { foreach ($s in $PRIV_RID_SUFFIX) { if ($SID -eq "$DomainSID$s") { return $true } } }
    return $false
}

function Get-RawSDDangerousAces {
    param([byte[]]$SDBytes,[string]$DomainSID)
    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes,0) } catch { return ,@() }
    $results = @()
    if (-not $sd.DiscretionaryAcl) { return ,@() }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -notin @([System.Security.AccessControl.AceType]::AccessAllowed,
            [System.Security.AccessControl.AceType]::AccessAllowedObject)) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if (Test-PrivilegedSID $sid $DomainSID) { continue }
        $mask = $ace.AccessMask
        $pName = Resolve-SIDName $sid $DomainSID
        if ($mask -band $ADS_RIGHT_GENERIC_ALL)  { $results += @{P=$pName;R='GenericAll'} }
        if ($mask -band $ADS_RIGHT_GENERIC_WRITE) { $results += @{P=$pName;R='GenericWrite'} }
        if ($mask -band $ADS_RIGHT_WRITE_DAC)     { $results += @{P=$pName;R='WriteDacl'} }
        if ($mask -band $ADS_RIGHT_WRITE_OWNER)   { $results += @{P=$pName;R='WriteOwner'} }
        if (($mask -band $ADS_RIGHT_DS_WRITE_PROP) -and -not ($mask -band $DANGEROUS_MASK)) {
            $isObj = $ace -is [System.Security.AccessControl.ObjectAce]
            if (-not $isObj -or -not ($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
                $results += @{P=$pName;R='WriteAllProperties'}
            }
        }
    }
    return ,$results
}

function Get-RawSDEnrollPrincipals {
    param([byte[]]$SDBytes,[string]$DomainSID)
    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes,0) } catch { return ,@() }
    $results = @()
    if (-not $sd.DiscretionaryAcl) { return ,@() }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowedObject) {
            if (-not ($ace.AccessMask -band $ADS_RIGHT_DS_CONTROL_ACCESS)) { continue }
            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                $ot = $ace.ObjectAceType.ToString().ToLower()
                if ($ot -eq $ENROLL_GUID -or $ot -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2') {
                    $sid = $ace.SecurityIdentifier.Value
                    $results += "$(Resolve-SIDName $sid $DomainSID) ($sid)"
                }
            }
        }
        if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) {
            if ($ace.AccessMask -band ($ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_DS_CONTROL_ACCESS)) {
                $sid = $ace.SecurityIdentifier.Value
                $e = "$(Resolve-SIDName $sid $DomainSID) ($sid)"
                if ($e -notin $results) { $results += $e }
            }
        }
    }
    return ,$results
}

# Shared template analysis - returns array of finding strings
function Test-TemplateVulns {
    param(
        [string]$Name,
        [uint32]$NameFlag,
        [uint32]$EnrollFlag,
        [int]$RASignature,
        [string[]]$EKUs,
        [string[]]$CertPolicy,
        [byte[]]$SDBytes,
        [string]$DomainSID,
        [string]$OIDBase,          # for ESC13 OID lookup (local mode only)
        [switch]$LocalMode
    )

    $suppliesSAN = ($NameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
    $noApproval  = ($EnrollFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -eq 0
    $noSecExt    = ($EnrollFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) -ne 0
    $noSignature = ($RASignature -eq 0)

    $ekuArr = @(if ($EKUs) { $EKUs } else { })
    $hasAuthEKU   = ($ekuArr.Count -eq 0) -or ($ekuArr | Where-Object { $_ -in $authEKUs })
    $hasAnyOrNone = ($ekuArr.Count -eq 0) -or ($ekuArr -contains '2.5.29.37.0')
    $hasAgentEKU  = $ekuArr -contains $agentEKU

    $f = @(); $e = @()

    if ($suppliesSAN -and $hasAuthEKU -and $noApproval -and $noSignature) {
        $f += "    [!] ESC1  - ${Name}: ENROLLEE_SUPPLIES_SUBJECT + Auth EKU"
        $e += @{ ESC='ESC1'; Template=$Name }
    }
    if ($hasAnyOrNone -and $noApproval -and $noSignature) {
        $f += "    [!] ESC2  - ${Name}: Any Purpose / No EKU"
        $e += @{ ESC='ESC2'; Template=$Name }
    }
    if ($hasAgentEKU -and $noApproval -and $noSignature) {
        $f += "    [!] ESC3  - ${Name}: Certificate Request Agent EKU"
        $e += @{ ESC='ESC3'; Template=$Name }
    }
    if ($noSecExt -and $hasAuthEKU) {
        $f += "    [!] ESC9  - ${Name}: CT_FLAG_NO_SECURITY_EXTENSION"
        $e += @{ ESC='ESC9'; Template=$Name }
    }

    # ESC13 - OID group link
    $cpArr = @(if ($CertPolicy) { $CertPolicy } else { })
    if ($cpArr.Count -gt 0) {
        if ($LocalMode -and $OIDBase) {
            foreach ($oid in $CertPolicy) {
                try {
                    $oidObj = Get-ADObject -SearchBase $OIDBase `
                        -Filter "msPKI-Cert-Template-OID -eq '$oid'" `
                        -Properties 'msDS-OIDToGroupLink' -ErrorAction SilentlyContinue
                    if ($oidObj.'msDS-OIDToGroupLink') {
                        $f += "    [!] ESC13 - ${Name}: OID $oid -> group $($oidObj.'msDS-OIDToGroupLink')"
                        $e += @{ ESC='ESC13'; Template=$Name }
                    }
                } catch {}
            }
        } else {
            $f += "    [!] ESC13 - ${Name}: Has issuance policy OID ($($CertPolicy -join ', ')) - verify OID group link"
            $e += @{ ESC='ESC13'; Template=$Name }
        }
    }

    # ESC4 - ACL abuse
    if ($SDBytes) {
        $dangerousAces = Get-RawSDDangerousAces -SDBytes $SDBytes -DomainSID $DomainSID
        foreach ($da in $dangerousAces) {
            $f += "    [!] ESC4  - ${Name}: $($da.P) has $($da.R)"
            $e += @{ ESC='ESC4'; Template=$Name }
        }
    }

    return @{ Findings = $f; Exploits = $e }
}

# ============================================================================
#  REMOTE LDAP HELPERS
# ============================================================================

function New-LdapSearcher {
    param([string]$Srv,[int]$Pt,[string]$Base,[string]$Filter,[string[]]$Props,[PSCredential]$Cred,[bool]$SSL)
    $path = "LDAP://${Srv}:${Pt}/$Base"
    if ($Cred) {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path,$Cred.UserName,$Cred.GetNetworkCredential().Password)
    } else {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
    }
    $srch = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $srch.Filter = $Filter; $srch.PageSize = 1000
    $srch.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $srch.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
    foreach ($p in $Props) { $srch.PropertiesToLoad.Add($p) | Out-Null }
    return $srch
}

function Get-LP {
    param([System.DirectoryServices.SearchResult]$R,[string]$P,[switch]$Single)
    if (-not $R.Properties.Contains($P)) { return $null }
    if ($Single) { return $R.Properties[$P][0] }
    return @($R.Properties[$P])
}

# ============================================================================
#  SNAPSHOT BINARY PARSER (inline for snapshot mode)
# ============================================================================

$ADSTYPE_STRING_TYPES = @(1,2,3,4,5,12)

function Read-NullTermWchar {
    param([System.IO.BinaryReader]$R)
    $c = [System.Collections.Generic.List[char]]::new(64)
    while ($true) { $v = $R.ReadUInt16(); if ($v -eq 0) { break }; $c.Add([char]$v) }
    return (-join $c)
}

function Read-FixedWchar {
    param([System.IO.BinaryReader]$R,[int]$N)
    return [System.Text.Encoding]::Unicode.GetString($R.ReadBytes($N*2)).TrimEnd([char]0)
}

function Read-SnapAttribute {
    param([System.IO.BinaryReader]$R,[long]$ObjOff,[int]$AttrOff,[int]$AdsType,[string]$AName,[switch]$Raw)
    $fa = [long]$ObjOff + [long]$AttrOff
    $R.BaseStream.Seek($fa,[System.IO.SeekOrigin]::Begin) | Out-Null
    $nv = $R.ReadUInt32(); if ($nv -eq 0) { return ,@() }
    $vals = [System.Collections.Generic.List[object]]::new($nv)
    if ($AdsType -in $ADSTYPE_STRING_TYPES) {
        $offs = [uint32[]]::new($nv); for($i=0;$i -lt $nv;$i++){$offs[$i]=$R.ReadUInt32()}
        for($i=0;$i -lt $nv;$i++){$R.BaseStream.Seek($fa+$offs[$i],[System.IO.SeekOrigin]::Begin)|Out-Null;$vals.Add((Read-NullTermWchar $R))}
    } elseif ($AdsType -eq 8) {
        $lens=[uint32[]]::new($nv);for($i=0;$i -lt $nv;$i++){$lens[$i]=$R.ReadUInt32()}
        for($i=0;$i -lt $nv;$i++){
            $b=$R.ReadBytes($lens[$i])
            if(-not $Raw -and $b.Length -eq 16 -and $AName -like '*guid*'){$vals.Add(([guid]::new($b)).ToString());continue}
            if(-not $Raw -and ($AName -ieq 'objectSid')){try{$vals.Add((New-Object System.Security.Principal.SecurityIdentifier($b,0)).Value)}catch{$vals.Add($b)};continue}
            $vals.Add($b)
        }
    } elseif ($AdsType -eq 6) { for($i=0;$i -lt $nv;$i++){$vals.Add([bool]$R.ReadUInt32())} }
    elseif ($AdsType -eq 7) { for($i=0;$i -lt $nv;$i++){$vals.Add($R.ReadUInt32())} }
    elseif ($AdsType -eq 10) { for($i=0;$i -lt $nv;$i++){$vals.Add($R.ReadInt64())} }
    elseif ($AdsType -eq 25) { for($i=0;$i -lt $nv;$i++){$l=$R.ReadUInt32();$vals.Add($R.ReadBytes($l))} }
    return ,$vals.ToArray()
}

function Get-SnapAttr {
    param([System.IO.BinaryReader]$R,[long]$Off,[array]$Map,[hashtable]$PDict,[array]$Props,[string]$Attr,[switch]$Raw)
    $idx = $PDict[$Attr]; if ($null -eq $idx) { return $null }
    foreach ($e in $Map) { if ($e.Index -eq $idx) {
        $p = $Props[$idx]; $pa = @{R=$R;ObjOff=$Off;AttrOff=$e.Offset;AdsType=$p.AdsType;AName=$Attr}
        if($Raw){$pa['Raw']=$true}; return ,(Read-SnapAttribute @pa)
    }}; return $null
}

# ============================================================================
#  BANNER
# ============================================================================

$modeLabel = switch ($Mode) { 'Local'{'Domain-Joined'} 'Remote'{"Remote LDAP -> $Server"} 'Snapshot'{"Snapshot -> $(Split-Path $Snapshot -Leaf)"} }

Out-Line ""
Out-Line "  AD CS LOLBAS - Enumerate" 'White'
Out-Line "  Mode: $modeLabel" 'Gray'
Out-Line "  ---------------------------------------" 'DarkGray'
Out-Line ""

if ($Mode -eq 'Local') {
    _WriteBanner "ENUMERATE" "Scanning all ESC conditions"
} else {
    _WriteBanner "ENUMERATE ($($Mode.ToUpper()))" "Scanning all ESC conditions"
}

# ============================================================================
#  MODE: LOCAL (existing AD module logic)
# ============================================================================

if ($Mode -eq 'Local') {

    $ctx = Get-ADContext
    $domainSID = (Get-ADDomain).DomainSID.Value

    # -- Stage 1: Template Enumeration ------------------------------------
    Write-Stage -Number 1 -Name "TEMPLATE ENUMERATION"
    Write-Host ""
    Write-Host "    PS> Get-ADObject -SearchBase `"$($ctx.TemplateBase)`"  ``" -ForegroundColor DarkYellow
    Write-Host "            -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties *" -ForegroundColor DarkYellow
    Write-Host ""

    $templates = Get-ADObject -SearchBase $ctx.TemplateBase `
        -Filter {objectClass -eq 'pKICertificateTemplate'} `
        -Properties * |
        Select-Object Name, DistinguishedName,
            @{N='NameFlag';E={$_.'msPKI-Certificate-Name-Flag'}},
            @{N='EnrollFlag';E={$_.'msPKI-Enrollment-Flag'}},
            @{N='RASignature';E={$_.'msPKI-RA-Signature'}},
            @{N='EKUs';E={$_.'pKIExtendedKeyUsage'}},
            @{N='CertPolicy';E={$_.'msPKI-Certificate-Policy'}},
            @{N='SD';E={$_.nTSecurityDescriptor}}

    foreach ($t in $templates) {
        # Get raw SD bytes for shared analysis
        $sdBytes = $null
        if ($t.SD) { try { $b = [byte[]]::new($t.SD.GetSecurityDescriptorBinaryForm().Length); $t.SD.GetSecurityDescriptorBinaryForm($b,0); $sdBytes=$b } catch {} }

        $result = Test-TemplateVulns -Name $t.Name `
            -NameFlag ([uint32]($t.NameFlag -band 0xFFFFFFFF)) `
            -EnrollFlag ([uint32]($t.EnrollFlag -band 0xFFFFFFFF)) `
            -RASignature ([int]$(if($null -eq $t.RASignature){0}else{$t.RASignature})) `
            -EKUs @(if($t.EKUs){$t.EKUs}else{@()}) `
            -CertPolicy @(if($t.CertPolicy){$t.CertPolicy}else{@()}) `
            -SDBytes $sdBytes -DomainSID $domainSID `
            -OIDBase $ctx.OIDBase -LocalMode

        foreach ($f in $result.Findings) {
            $findings += $f
            $color = if ($f -match 'ESC1|ESC4') {'Red'} elseif ($f -match 'ESC13') {'Magenta'} else {'Yellow'}
            Write-Host $f -ForegroundColor $color
        }
        $exploits += $result.Exploits
    }

    # -- Stage 2: ACL on PKI containers (ESC5) ----------------------------
    Write-Host ""
    Write-Stage -Number 2 -Name "PKI CONTAINER ACLS (ESC5)"
    Write-Host ""

    $dangerousRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'
    $pkiTargets = @($ctx.PKIBase, $ctx.TemplateBase, $ctx.EnrollBase, $ctx.OIDBase, $ctx.NTAuthDN)
    foreach ($dn in $pkiTargets) {
        try {
            $obj = Get-ADObject -Identity $dn -Properties nTSecurityDescriptor -ErrorAction Stop
            foreach ($ace in $obj.nTSecurityDescriptor.Access) {
                if ($ace.ActiveDirectoryRights -match $dangerousRights) {
                    $id = $ace.IdentityReference.Value
                    if ($lowPrivGroups | Where-Object { $id -match $_ }) {
                        $shortDN = ($dn -split ',')[0]
                        $msg = "    [!] ESC5  - $shortDN : $id has $($ace.ActiveDirectoryRights)"
                        $findings += $msg
                        Write-Host $msg -ForegroundColor Red
                    }
                }
            }
        } catch { }
    }

    # -- Stage 3: CA Configuration (ESC6/ESC7/ESC11) ----------------------
    Write-Host ""
    Write-Stage -Number 3 -Name "CA CONFIGURATION (ESC6/ESC7/ESC11)"
    Write-Host ""

    foreach ($ca in (Get-CAConfigs)) {
        $caConfigs += $ca
        Write-Host "    [*] CA: $ca" -ForegroundColor Cyan

        $caName = ($ca -split '\\',2)[1]
        try {
            $caObj = Get-ADObject -SearchBase $ctx.EnrollBase `
                -Filter "cn -eq '$caName' -and objectClass -eq 'pKIEnrollmentService'" `
                -Properties nTSecurityDescriptor -ErrorAction Stop
            $esc7Found = $false
            if ($caObj -and $caObj.nTSecurityDescriptor) {
                foreach ($ace in $caObj.nTSecurityDescriptor.Access) {
                    $id = $ace.IdentityReference.Value
                    if ($lowPrivGroups | Where-Object { $id -match $_ }) {
                        $rights = $ace.ActiveDirectoryRights.ToString()
                        if ($rights -match 'GenericAll|WriteDacl|WriteOwner|ExtendedRight|WriteProperty') {
                            $msg = "    [!] ESC7  - $id has $rights on CA object (LDAP)"
                            $findings += $msg; Write-Host $msg -ForegroundColor Yellow
                            if (-not $esc7Found) { $exploits += @{ ESC='ESC7'; Template=''; CA=$ca }; $esc7Found=$true }
                        }
                    }
                }
            }
            if (-not $esc7Found) { Write-Host "    [+] ESC7  - No low-priv dangerous ACEs on CA object" -ForegroundColor Green }
        } catch { Write-Host "    [!] ESC7  - Could not read CA object ACL: $($_.Exception.Message)" -ForegroundColor Yellow }

        try {
            $editFlags = certutil -config $ca -getreg policy\EditFlags 2>$null
            if ($editFlags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
                $msg = "    [!] ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 ENABLED"
                $findings += $msg; $exploits += @{ ESC='ESC6'; Template=''; CA=$ca }
                Write-Host $msg -ForegroundColor Red
            } else { Write-Host "    [+] ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 not set" -ForegroundColor Green }
        } catch { Write-Host "    [!] ESC6  - certutil check failed (CA unreachable?)" -ForegroundColor Yellow }

        try {
            $intFlags = certutil -config $ca -getreg CA\InterfaceFlags 2>$null
            if ($intFlags -notmatch 'IF_ENFORCEENCRYPTICERTREQUEST') {
                $msg = "    [!] ESC11 - IF_ENFORCEENCRYPTICERTREQUEST NOT set (RPC relay possible)"
                $findings += $msg; $exploits += @{ ESC='ESC11'; Template=''; CA=$ca }
                Write-Host $msg -ForegroundColor Yellow
            } else { Write-Host "    [+] ESC11 - IF_ENFORCEENCRYPTICERTREQUEST set" -ForegroundColor Green }
        } catch { Write-Host "    [!] ESC11 - certutil check failed (CA unreachable?)" -ForegroundColor Yellow }
    }

    # -- Stage 4: HTTP Endpoints (ESC8) -----------------------------------
    Write-Host ""
    if ($SkipHTTP) {
        Write-Stage -Number 4 -Name "HTTP ENDPOINT DISCOVERY (ESC8)" -Status 'SKIPPED'
        Write-Host "    [i] Skipped (-SkipHTTP)" -ForegroundColor DarkGray
    } else {
        Write-Stage -Number 4 -Name "HTTP ENDPOINT DISCOVERY (ESC8)"
        Write-Host ""
        $enrollSvcs = Get-ADObject -SearchBase $ctx.EnrollBase `
            -Filter {objectClass -eq 'pKIEnrollmentService'} `
            -Properties dNSHostName, cn -ErrorAction SilentlyContinue
        foreach ($svc in $enrollSvcs) {
            $h = $svc.dNSHostName
            foreach ($url in @("http://$h/certsrv/","https://$h/certsrv/")) {
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $msg = "    [!] ESC8  - Web Enrollment: $url (HTTP $($resp.StatusCode))"
                    $findings += $msg; $exploits += @{ESC='ESC8';Template='';URL=$url}; Write-Host $msg -ForegroundColor Red
                } catch {
                    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
                        $msg = "    [!] ESC8  - Web Enrollment: $url (401 - exists)"
                        $findings += $msg; $exploits += @{ESC='ESC8';Template='';URL=$url}; Write-Host $msg -ForegroundColor Yellow
                    }
                }
            }
        }
    }

    # -- Stage 5: Registry (ESC9/ESC10) -----------------------------------
    Write-Host ""
    Write-Stage -Number 5 -Name "CERTIFICATE BINDING ENFORCEMENT (ESC9/ESC10)"
    Write-Host ""
    try {
        $regVal = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -ErrorAction Stop).StrongCertificateBindingEnforcement
        switch ($regVal) {
            0 { $msg = "    [!] StrongCertificateBindingEnforcement = 0 (DISABLED)"; Write-Host $msg -ForegroundColor Red; $findings += $msg }
            1 { $msg = "    [!] StrongCertificateBindingEnforcement = 1 (COMPATIBILITY)"; Write-Host $msg -ForegroundColor Yellow; $findings += $msg }
            2 { Write-Host "    [+] StrongCertificateBindingEnforcement = 2 (FULL)" -ForegroundColor Green }
        }
    } catch {
        $msg = "    [!] StrongCertificateBindingEnforcement not set (defaults to 1 - Compatibility)"
        Write-Host $msg -ForegroundColor Yellow; $findings += $msg
    }

}

# ============================================================================
#  MODE: REMOTE (pure .NET LDAP)
# ============================================================================

elseif ($Mode -eq 'Remote') {

    if ($UseSSL -and $Port -eq 389) { $Port = 636 }
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Enter domain credentials (DOMAIN\user or user@domain)"
        if (-not $Credential) { Out-Line "  [-] Credentials required." 'Red'; return }
    }

    # Connect to RootDSE
    _WriteStage 1 "CONNECTING TO $Server`:$Port"
    Out-Line ""
    try {
        $rootPath = "LDAP://${Server}:${Port}/RootDSE"
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($rootPath,$Credential.UserName,$Credential.GetNetworkCredential().Password)
        $configNC  = $rootDSE.Properties["configurationNamingContext"][0].ToString()
        $defaultNC = $rootDSE.Properties["defaultNamingContext"][0].ToString()
        $dnsHost   = try { $rootDSE.Properties["dnsHostName"][0].ToString() } catch { $Server }
        Out-Line "    [+] Connected to: $dnsHost" 'Green'
        Out-Line "    [i] Domain DN : $defaultNC" 'Gray'
        Out-Line "    [i] Config NC : $configNC" 'Gray'
    } catch {
        Out-Line "    [-] Failed: $($_.Exception.Message)" 'Red'
        return
    }

    # Domain SID
    $domainSID = $null
    try {
        $ds = New-LdapSearcher -Srv $Server -Pt $Port -Base $defaultNC -Filter "(&(objectClass=domain)(objectSid=*))" -Props @("objectSid") -Cred $Credential -SSL $UseSSL
        $dr = $ds.FindOne()
        if ($dr) { $domainSID = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$dr.Properties["objectsid"][0],0)).Value; Out-Line "    [i] Domain SID: $domainSID" 'Gray' }
    } catch {}
    Out-Line ""

    # -- Stage 2: Enumerate CAs -------------------------------------------
    _WriteStage 2 "ENUMERATING CERTIFICATE AUTHORITIES"
    Out-Line ""
    $enrollBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
    $caTemplateMap = @{}
    $caHosts = @{}
    try {
        $cas = New-LdapSearcher -Srv $Server -Pt $Port -Base $enrollBase -Filter "(objectClass=pKIEnrollmentService)" `
            -Props @("name","dNSHostName","certificateTemplates","nTSecurityDescriptor") -Cred $Credential -SSL $UseSSL
        $caResults = $cas.FindAll()
        foreach ($ca in $caResults) {
            $cn = (Get-LP $ca 'name' -Single).ToString()
            $dh = try { (Get-LP $ca 'dnshostname' -Single).ToString() } catch { $Server }
            $tpls = @(); $raw = Get-LP $ca 'certificatetemplates'; if ($raw) { $tpls = @($raw|ForEach-Object{$_.ToString()}) }
            $caTemplateMap[$cn] = $tpls
            $caHosts[$cn] = $dh
            $caConfigs += "$dh\$cn"
            Out-Line "    [+] $cn on $dh ($($tpls.Count) templates)" 'Green'

            # ESC7 check on CA object ACL
            $caSD = Get-LP $ca 'ntsecuritydescriptor' -Single
            if ($caSD) {
                $caAces = Get-RawSDDangerousAces -SDBytes ([byte[]]$caSD) -DomainSID $domainSID
                foreach ($a in $caAces) {
                    $msg = "    [!] ESC7  - $($a.P) has $($a.R) on CA object"
                    $findings += $msg; $exploits += @{ESC='ESC7';Template='';CA="$dh\$cn"}
                    Out-Line $msg 'Yellow'
                }
            }
        }
        $caResults.Dispose()
    } catch { Out-Line "    [-] CA enum error: $($_.Exception.Message)" 'Red' }

    $templateToCA = @{}
    foreach ($ca in $caTemplateMap.Keys) { foreach ($t in $caTemplateMap[$ca]) {
        if (-not $templateToCA.ContainsKey($t)){$templateToCA[$t]=@()}; $templateToCA[$t]+=$ca
    }}
    Out-Line ""

    # -- Stage 3: Template Analysis ---------------------------------------
    _WriteStage 3 "TEMPLATE ENUMERATION (ESC1/2/3/4/9/13)"
    Out-Line ""
    $templateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $tplProps = @("name","displayName","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
        "msPKI-RA-Signature","pKIExtendedKeyUsage","msPKI-Template-Schema-Version",
        "msPKI-Certificate-Policy","nTSecurityDescriptor")
    try {
        $ts = New-LdapSearcher -Srv $Server -Pt $Port -Base $templateBase `
            -Filter "(objectClass=pKICertificateTemplate)" -Props $tplProps -Cred $Credential -SSL $UseSSL
        $tplResults = $ts.FindAll()
        foreach ($r in $tplResults) {
            $tName = (Get-LP $r 'name' -Single).ToString()
            $nf = Get-LP $r 'mspki-certificate-name-flag' -Single
            $ef = Get-LP $r 'mspki-enrollment-flag' -Single
            $rs = Get-LP $r 'mspki-ra-signature' -Single
            $ek = Get-LP $r 'pkiextendedkeyusage'
            $cp = Get-LP $r 'mspki-certificate-policy'
            $sd = Get-LP $r 'ntsecuritydescriptor' -Single

            $result = Test-TemplateVulns -Name $tName `
                -NameFlag ([uint32]$(if($null -ne $nf){$nf}else{0})) `
                -EnrollFlag ([uint32]$(if($null -ne $ef){$ef}else{0})) `
                -RASignature ([int]$(if($null -ne $rs){$rs}else{0})) `
                -EKUs @(if($ek){$ek|ForEach-Object{$_.ToString()}}else{@()}) `
                -CertPolicy @(if($cp){$cp|ForEach-Object{$_.ToString()}}else{@()}) `
                -SDBytes $(if($sd){[byte[]]$sd}else{$null}) -DomainSID $domainSID

            foreach ($f in $result.Findings) {
                $findings += $f
                $color = if ($f -match 'ESC1|ESC4'){'Red'} elseif ($f -match 'ESC13'){'Magenta'} else{'Yellow'}
                Out-Line $f $color
            }
            $exploits += $result.Exploits
        }
        $tplResults.Dispose()
    } catch { Out-Line "    [-] Template enum error: $($_.Exception.Message)" 'Red' }

    # -- Stage 4: PKI Container ACLs (ESC5) --------------------------------
    Out-Line ""
    _WriteStage 4 "PKI CONTAINER ACLS (ESC5)"
    Out-Line ""
    $pkiBase = "CN=Public Key Services,CN=Services,$configNC"
    foreach ($dn in @($pkiBase, $templateBase, $enrollBase, "CN=OID,CN=Public Key Services,CN=Services,$configNC")) {
        try {
            $ps = New-LdapSearcher -Srv $Server -Pt $Port -Base $dn -Filter "(objectClass=*)" `
                -Props @("nTSecurityDescriptor","distinguishedName") -Cred $Credential -SSL $UseSSL
            $ps.SearchScope = [System.DirectoryServices.SearchScope]::Base
            $pr = $ps.FindOne()
            if ($pr) {
                $psd = Get-LP $pr 'ntsecuritydescriptor' -Single
                if ($psd) {
                    $pAces = Get-RawSDDangerousAces -SDBytes ([byte[]]$psd) -DomainSID $domainSID
                    foreach ($a in $pAces) {
                        $shortDN = ($dn -split ',')[0]
                        $msg = "    [!] ESC5  - $shortDN : $($a.P) has $($a.R)"
                        $findings += $msg; Out-Line $msg 'Red'
                    }
                }
            }
        } catch {}
    }

    # -- Stage 5: HTTP Endpoints (ESC8) -----------------------------------
    Out-Line ""
    if ($SkipHTTP) {
        _WriteStage 5 "HTTP ENDPOINT DISCOVERY (ESC8)" 'SKIPPED'
        Out-Line "    [i] Skipped (-SkipHTTP)" 'DarkGray'
    } else {
        _WriteStage 5 "HTTP ENDPOINT DISCOVERY (ESC8)"
        Out-Line ""
        foreach ($cn in $caHosts.Keys) {
            $h = $caHosts[$cn]
            foreach ($url in @("http://$h/certsrv/","https://$h/certsrv/")) {
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $msg = "    [!] ESC8  - Web Enrollment: $url (HTTP $($resp.StatusCode))"
                    $findings += $msg; $exploits += @{ESC='ESC8';Template='';URL=$url}; Out-Line $msg 'Red'
                } catch {
                    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
                        $msg = "    [!] ESC8  - Web Enrollment: $url (401 - exists)"
                        $findings += $msg; $exploits += @{ESC='ESC8';Template='';URL=$url}; Out-Line $msg 'Yellow'
                    }
                }
            }
        }
    }

    # -- Remote-skipped stages ---
    Out-Line ""
    _WriteStage 6 "CA REGISTRY (ESC6/ESC11)" 'SKIPPED'
    Out-Line "    [i] ESC6/ESC11 require certutil access to CA - not available remotely" 'DarkGray'
    Out-Line "    [i] Run locally or use: certutil -config `"<CA>`" -getreg policy\EditFlags" 'DarkGray'
    Out-Line ""
    _WriteStage 7 "CERTIFICATE BINDING (ESC9/ESC10)" 'SKIPPED'
    Out-Line "    [i] Registry checks require local DC access - not available remotely" 'DarkGray'
}

# ============================================================================
#  MODE: SNAPSHOT (offline binary parsing)
# ============================================================================

elseif ($Mode -eq 'Snapshot') {

    if (-not (Test-Path $Snapshot)) { Out-Line "  [-] File not found: $Snapshot" 'Red'; return }
    $Snapshot = (Resolve-Path $Snapshot).Path

    $stream = [System.IO.FileStream]::new($Snapshot,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)
    $reader = [System.IO.BinaryReader]::new($stream)

    try {
    # Parse header
    _WriteStage 1 "PARSING SNAPSHOT"
    $reader.BaseStream.Seek(0,[System.IO.SeekOrigin]::Begin) | Out-Null
    $null = $reader.ReadBytes(10); $null = $reader.ReadInt32()
    $filetime = $reader.ReadUInt64()
    $desc = Read-FixedWchar $reader 260; $srv = Read-FixedWchar $reader 260
    $numObj = $reader.ReadUInt32(); $numAttr = $reader.ReadUInt32()
    $metaOff = $reader.ReadUInt64(); $null = $reader.ReadUInt64()
    $snapTime = [datetime]::FromFileTimeUtc($filetime)
    Out-Line "    [i] Server : $srv | Time: $($snapTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC | Objects: $($numObj.ToString('N0'))" 'Gray'
    Out-Line ""

    # Parse properties
    $reader.BaseStream.Seek($metaOff,[System.IO.SeekOrigin]::Begin) | Out-Null
    $numProps = $reader.ReadUInt32()
    $props = [object[]]::new($numProps); $pDict = @{}
    for ($i=0;$i -lt $numProps;$i++) {
        $ln=$reader.ReadUInt32();$pn=(Read-FixedWchar $reader ($ln/2)).TrimEnd([char]0)
        $null=$reader.ReadInt32();$at=$reader.ReadUInt32()
        $ld=$reader.ReadUInt32();$pd=(Read-FixedWchar $reader ($ld/2)).TrimEnd([char]0)
        $null=$reader.ReadBytes(36)
        $props[$i]=@{Name=$pn;AdsType=$at};$pDict[$pn]=$i
        if($pd){$pDict[$pd]=$i;if($pd -match '^CN=([^,]+)'){$pDict[$Matches[1]]=$i}}
    }

    # Index object offsets
    $reader.BaseStream.Seek(0x43E,[System.IO.SeekOrigin]::Begin) | Out-Null
    $objOffs = [System.Collections.Generic.List[long]]::new($numObj)
    for ($i=0;$i -lt $numObj;$i++) {
        $pos=$reader.BaseStream.Position;$sz=$reader.ReadUInt32();$objOffs.Add($pos)
        $reader.BaseStream.Seek($pos+$sz,[System.IO.SeekOrigin]::Begin)|Out-Null
    }

    # Scan objects
    _WriteStage 2 "DISCOVERING AD CS OBJECTS"
    Out-Line ""
    $caMap=@{};$tplObjs=[System.Collections.Generic.List[hashtable]]::new();$domainSID=$null
    $prog=[Math]::Max(1,[Math]::Floor($numObj/40))

    for ($i=0;$i -lt $numObj;$i++) {
        if($i % $prog -eq 0){Write-Host "`r    [i] Scanning... $([Math]::Round(($i/$numObj)*100))%   " -NoNewline -ForegroundColor Gray}
        $off=$objOffs[$i]

        try {
            $reader.BaseStream.Seek($off,[System.IO.SeekOrigin]::Begin)|Out-Null
            $null=$reader.ReadUInt32();$ts=$reader.ReadUInt32()
            $map=[object[]]::new($ts);for($j=0;$j -lt $ts;$j++){$map[$j]=@{Index=$reader.ReadUInt32();Offset=$reader.ReadInt32()}}

            $oc = Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'objectClass'
            if(-not $oc){continue}
            $ocl=@(@($oc)|ForEach-Object{"$_".ToLower()})

            if('pkienrollmentservice' -in $ocl){
                $cn=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'name'
                $ct=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'certificateTemplates'
                if($cn){$caMap[@($cn)[0]]=@(if($ct){$ct}else{})}
            }
            if('pkicertificatetemplate' -in $ocl){
                $tn=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'name'
                $nf=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'msPKI-Certificate-Name-Flag'
                $ef=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'msPKI-Enrollment-Flag'
                $rs=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'msPKI-RA-Signature'
                $ek=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'pKIExtendedKeyUsage'
                $cp=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'msPKI-Certificate-Policy'
                $sd=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'nTSecurityDescriptor'
                $tplObjs.Add(@{
                    Name=if($tn){@($tn)[0]}else{''};NameFlag=if($nf){[uint32]@($nf)[0]}else{0}
                    EnrollFlag=if($ef){[uint32]@($ef)[0]}else{0};RASignature=if($rs){[int]@($rs)[0]}else{0}
                    EKUs=@(if($ek){$ek}else{});CertPolicy=@(if($cp){$cp}else{})
                    SDBytes=if($sd){@($sd)[0]}else{$null}
                })
            }
            if('domain' -in $ocl -and -not $domainSID){
                $osid=Get-SnapAttr -R $reader -Off $off -Map $map -PDict $pDict -Props $props -Attr 'objectSid'
                if($osid -and @($osid)[0] -is [string]){$domainSID=@($osid)[0]}
            }
        } catch { continue }
    }
    Write-Host "`r    [i] Scanning... 100%   " -ForegroundColor Gray

    $templateToCA=@{}
    foreach($c in $caMap.Keys){foreach($t in $caMap[$c]){if(-not $templateToCA.ContainsKey($t)){$templateToCA[$t]=@()};$templateToCA[$t]+=$c}}
    foreach($c in $caMap.Keys){$caConfigs+=$c;Out-Line "    [+] CA: $c ($($caMap[$c].Count) templates)" 'Green'}
    Out-Line "    [i] Templates: $($tplObjs.Count) | Domain SID: $(if($domainSID){$domainSID}else{'N/A'})" 'Gray'
    Out-Line ""

    # Analyze templates
    _WriteStage 3 "VULNERABILITY ANALYSIS"
    Out-Line ""
    foreach ($t in $tplObjs|Sort-Object{$_.Name}) {
        $result = Test-TemplateVulns -Name $t.Name -NameFlag $t.NameFlag -EnrollFlag $t.EnrollFlag `
            -RASignature $t.RASignature -EKUs $t.EKUs -CertPolicy $t.CertPolicy `
            -SDBytes $t.SDBytes -DomainSID $domainSID
        foreach ($f in $result.Findings) {
            $findings += $f
            $color = if($f -match 'ESC1|ESC4'){'Red'} elseif($f -match 'ESC13'){'Magenta'} else{'Yellow'}
            Out-Line $f $color
        }
        $exploits += $result.Exploits
    }

    Out-Line ""
    _WriteStage 4 "CA REGISTRY / HTTP / BINDING" 'SKIPPED'
    Out-Line "    [i] ESC6/7/8/10/11 require live access - not available from snapshot" 'DarkGray'

    } finally { $reader.Close(); $stream.Close() }
}

# ============================================================================
#  SUMMARY & EXPLOITATION COMMANDS (all modes)
# ============================================================================

Out-Line ""
Out-Line "  ============================================" 'DarkCyan'
Out-Line "  ENUMERATION COMPLETE - $($findings.Count) findings" $(if($findings.Count -gt 0){'Red'}else{'Green'})
Out-Line "  ============================================" 'DarkCyan'
Out-Line ""

if ($exploits.Count -gt 0) {
    $ca = if ($caConfigs.Count -gt 0) { $caConfigs[0] } else { '<CA\Name>' }
    $domainHint = if ($Mode -eq 'Local') { $ctx.Domain } else { 'domain.local' }

    Out-Line "  EXPLOITATION COMMANDS" 'White'
    Out-Line "  =====================" 'DarkGray'
    Out-Line ""
    Out-Line "  Replace <TARGET_UPN> with the user to impersonate (e.g., administrator@$domainHint)" 'DarkGray'
    Out-Line ""

    $seen = @{}
    foreach ($e in $exploits) {
        $key = "$($e.ESC)|$($e.Template)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        switch ($e.ESC) {
            'ESC1' {
                Out-Line "  # ESC1 - $($e.Template) (Enrollee Supplies Subject)" 'Red'
                Out-Line "  .\Invoke-ESC1.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC2' {
                Out-Line "  # ESC2 - $($e.Template) (Any Purpose / No EKU)" 'Yellow'
                Out-Line "  .\Invoke-ESC2.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`"" 'White'
                Out-Line ""
            }
            'ESC3' {
                Out-Line "  # ESC3 - $($e.Template) (Enrollment Agent)" 'Yellow'
                Out-Line "  .\Invoke-ESC3.ps1 -CAConfig `"$ca`" -AgentTemplate `"$($e.Template)`" -TargetTemplate `"User`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC4' {
                Out-Line "  # ESC4 - $($e.Template) (Template ACL Abuse -> ESC1)" 'Red'
                Out-Line "  .\Invoke-ESC4.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC6' {
                $u = if($e.CA){$e.CA}else{$ca}
                Out-Line "  # ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 on $u" 'Red'
                Out-Line "  .\Invoke-ESC6.ps1 -CAConfig `"$u`" -TemplateName `"User`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC7' {
                $u = if($e.CA){$e.CA}else{$ca}
                Out-Line "  # ESC7a - ManageCA on $u" 'Yellow'
                Out-Line "  .\Invoke-ESC7a.ps1 -CAConfig `"$u`" -TemplateName `"User`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC8' {
                $r = if($e.URL){$e.URL}else{"http://<CA>/certsrv/"}
                Out-Line "  # ESC8 - NTLM Relay: $r" 'Red'
                Out-Line "  .\Invoke-ESC8.ps1   # Discovery only - relay requires ntlmrelayx" 'White'
                Out-Line ""
            }
            'ESC9' {
                Out-Line "  # ESC9 - $($e.Template) (No Security Extension)" 'Yellow'
                Out-Line "  .\Invoke-ESC9.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -AccountToModify `"<CONTROLLED_USER>`" -TargetUPN `"<TARGET_UPN>`"" 'White'
                Out-Line ""
            }
            'ESC11' {
                $u = if($e.CA){$e.CA}else{$ca}
                Out-Line "  # ESC11 - RPC Relay on $u" 'Yellow'
                Out-Line "  .\Invoke-ESC11.ps1" 'White'
                Out-Line ""
            }
            'ESC13' {
                Out-Line "  # ESC13 - $($e.Template) (OID Group Link)" 'Magenta'
                Out-Line "  .\Invoke-ESC13.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`"" 'White'
                Out-Line ""
            }
        }
    }
} else {
    Out-Line "  [+] No exploitable conditions found" 'Green'
    Out-Line ""
}

if ($Mode -ne 'Local') {
    Out-Line "  MODE LIMITATIONS ($Mode):" 'DarkGray'
    if ($Mode -eq 'Remote') {
        Out-Line "    ESC6/ESC11 : Skipped (certutil registry access needed)" 'DarkGray'
        Out-Line "    ESC9/ESC10 : Skipped (local DC registry needed)" 'DarkGray'
    }
    if ($Mode -eq 'Snapshot') {
        Out-Line "    ESC5/6/7/8/10/11 : Skipped (live access needed)" 'DarkGray'
    }
    Out-Line ""
}

# Save report
if ($OutputFile) {
    $script:ReportLines | Out-File -FilePath $OutputFile -Encoding UTF8
    Out-Line "  [+] Report saved to: $OutputFile" 'Green'
    Out-Line ""
}
