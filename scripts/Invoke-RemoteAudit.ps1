<#
.SYNOPSIS
    AD CS Remote Audit - Enumerate vulnerable AD CS templates from a non-domain-joined machine.
.DESCRIPTION
    Connects to a Domain Controller via LDAP using supplied credentials (no RSAT or domain
    membership required) and identifies certificate templates vulnerable to ESC1-ESC13.
    Uses only built-in .NET classes (System.DirectoryServices).
.PARAMETER Server
    Hostname, FQDN, or IP address of the target Domain Controller.
.PARAMETER Credential
    PSCredential object. If omitted, you will be prompted. Use domain\user or user@domain format.
.PARAMETER Port
    LDAP port. Default: 389. Use 636 for LDAPS.
.PARAMETER UseSSL
    Use LDAPS (SSL/TLS) connection. Automatically sets port to 636 if not specified.
.PARAMETER VulnerableOnly
    Only display templates with at least one ESC finding.
.PARAMETER OutputFile
    Optional path to save the report as a text file.
.EXAMPLE
    .\Invoke-RemoteAudit.ps1 -Server dc01.corp.local
.EXAMPLE
    $cred = Get-Credential CORP\admin
    .\Invoke-RemoteAudit.ps1 -Server 10.0.0.5 -Credential $cred
.EXAMPLE
    .\Invoke-RemoteAudit.ps1 -Server dc01.corp.local -UseSSL -VulnerableOnly
.NOTES
    For authorised security testing and educational purposes only.
    Works from any Windows machine - no domain join or RSAT required.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Server,
    [PSCredential]$Credential,
    [int]$Port = 389,
    [switch]$UseSSL,
    [switch]$VulnerableOnly,
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'

# ============================================================================
#  CONSTANTS (shared with Invoke-SnapshotAudit.ps1)
# ============================================================================

$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
$CT_FLAG_PEND_ALL_REQUESTS      = 0x00000002
$CT_FLAG_NO_SECURITY_EXTENSION  = 0x00080000

$OID_MAP = @{
    "1.3.6.1.5.5.7.3.1"        = "Server Authentication"
    "1.3.6.1.5.5.7.3.2"        = "Client Authentication"
    "1.3.6.1.5.5.7.3.3"        = "Code Signing"
    "1.3.6.1.5.5.7.3.4"        = "Secure Email"
    "1.3.6.1.5.5.7.3.8"        = "Time Stamping"
    "1.3.6.1.4.1.311.10.3.4"   = "Encrypting File System"
    "1.3.6.1.4.1.311.20.2.1"   = "Certificate Request Agent"
    "1.3.6.1.4.1.311.20.2.2"   = "Smart Card Logon"
    "1.3.6.1.5.2.3.4"          = "PKINIT Client Authentication"
    "2.5.29.37.0"               = "Any Purpose"
    "1.3.6.1.4.1.311.21.5"     = "CA Exchange"
}
$AUTH_EKUS = @("1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.311.20.2.2","1.3.6.1.5.2.3.4","2.5.29.37.0")
$AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"

$ADS_RIGHT_WRITE_DAC      = 0x00040000
$ADS_RIGHT_WRITE_OWNER    = 0x00080000
$ADS_RIGHT_GENERIC_ALL    = 0x10000000
$ADS_RIGHT_GENERIC_WRITE  = 0x40000000
$ADS_RIGHT_DS_WRITE_PROP  = 0x00000020
$ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
$DANGEROUS_MASK = $ADS_RIGHT_WRITE_DAC -bor $ADS_RIGHT_WRITE_OWNER -bor $ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_GENERIC_WRITE

$ENROLL_GUID     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
$AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

$PRIVILEGED_SIDS = @('S-1-5-18','S-1-5-9','S-1-5-32-544')
$PRIVILEGED_RID_SUFFIXES = @('-512','-518','-519')

$WELLKNOWN_SIDS = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-7'      = 'Anonymous Logon'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-18'     = 'SYSTEM'
    'S-1-5-9'      = 'Enterprise Domain Controllers'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
}

$script:ReportLines = [System.Collections.Generic.List[string]]::new()

# ============================================================================
#  HELPERS
# ============================================================================

function Out-Line {
    param([string]$Text = '', [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
    $script:ReportLines.Add($Text)
}

function Test-PrivilegedSID {
    param([string]$SID, [string]$DomainSID)
    if ($SID -in $PRIVILEGED_SIDS) { return $true }
    if ($DomainSID) {
        foreach ($suffix in $PRIVILEGED_RID_SUFFIXES) {
            if ($SID -eq "$DomainSID$suffix") { return $true }
        }
    }
    return $false
}

function Resolve-SIDName {
    param([string]$SID, [string]$DomainSID)
    if ($WELLKNOWN_SIDS.ContainsKey($SID)) { return $WELLKNOWN_SIDS[$SID] }
    if ($DomainSID) {
        if ($SID -eq "$DomainSID-513") { return 'Domain Users' }
        if ($SID -eq "$DomainSID-515") { return 'Domain Computers' }
        if ($SID -eq "$DomainSID-512") { return 'Domain Admins' }
        if ($SID -eq "$DomainSID-519") { return 'Enterprise Admins' }
        if ($SID -eq "$DomainSID-518") { return 'Schema Admins' }
        if ($SID -eq "$DomainSID-516") { return 'Domain Controllers' }
    }
    return $SID
}

function Get-DangerousAces {
    param([byte[]]$SDBytes, [string]$DomainSID)
    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes, 0) }
    catch { return ,@() }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($sd.Owner) {
        $ownerStr = $sd.Owner.Value
        if (-not (Test-PrivilegedSID $ownerStr $DomainSID)) {
            $results.Add([PSCustomObject]@{
                Principal = (Resolve-SIDName $ownerStr $DomainSID); SID = $ownerStr
                Right = 'Owner'; Inherited = $false
            })
        }
    }

    if (-not $sd.DiscretionaryAcl) { return ,$results.ToArray() }

    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -notin @(
            [System.Security.AccessControl.AceType]::AccessAllowed,
            [System.Security.AccessControl.AceType]::AccessAllowedObject
        )) { continue }

        $sid = $ace.SecurityIdentifier.Value
        if (Test-PrivilegedSID $sid $DomainSID) { continue }

        $mask = $ace.AccessMask
        $principalName = Resolve-SIDName $sid $DomainSID
        $inherited = $ace.IsInherited

        if ($mask -band $ADS_RIGHT_GENERIC_ALL) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='GenericAll'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_GENERIC_WRITE) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='GenericWrite'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_WRITE_DAC) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteDacl'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_WRITE_OWNER) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteOwner'; Inherited=$inherited })
        }
        if (($mask -band $ADS_RIGHT_DS_WRITE_PROP) -and -not ($mask -band $DANGEROUS_MASK)) {
            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                if (-not ($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
                    $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteAllProperties'; Inherited=$inherited })
                }
            } else {
                $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteAllProperties'; Inherited=$inherited })
            }
        }
    }
    return ,$results.ToArray()
}

function Get-EnrollmentPrincipals {
    param([byte[]]$SDBytes, [string]$DomainSID)
    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes, 0) } catch { return ,@() }

    $results = [System.Collections.Generic.List[string]]::new()
    if (-not $sd.DiscretionaryAcl) { return ,@() }

    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowedObject) {
            if (-not ($ace.AccessMask -band $ADS_RIGHT_DS_CONTROL_ACCESS)) { continue }
            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                $objType = $ace.ObjectAceType.ToString().ToLower()
                if ($objType -eq $ENROLL_GUID -or $objType -eq $AUTOENROLL_GUID) {
                    $sid = $ace.SecurityIdentifier.Value
                    $results.Add("$(Resolve-SIDName $sid $DomainSID) ($sid)")
                }
            }
        }
        if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) {
            if ($ace.AccessMask -band ($ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_DS_CONTROL_ACCESS)) {
                $sid = $ace.SecurityIdentifier.Value
                $entry = "$(Resolve-SIDName $sid $DomainSID) ($sid)"
                if ($entry -notin $results) { $results.Add($entry) }
            }
        }
    }
    return ,$results.ToArray()
}

function ConvertTo-DurationString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 8) { return 'Unknown' }
    $ticks = [BitConverter]::ToInt64($Bytes, 0)
    if ($ticks -eq 0) { return 'Unknown' }
    $span = [TimeSpan]::FromTicks([Math]::Abs($ticks))
    if ($span.TotalDays -ge 365) { return "$([Math]::Round($span.TotalDays / 365, 1)) years" }
    if ($span.TotalDays -ge 1)   { return "$([int]$span.TotalDays) days" }
    return "$([int]$span.TotalHours) hours"
}

# ============================================================================
#  LDAP HELPERS (pure .NET - no RSAT required)
# ============================================================================

function New-LdapSearcher {
    param(
        [string]$Server,
        [int]$Port,
        [string]$BaseDN,
        [string]$Filter,
        [string[]]$PropertiesToLoad,
        [PSCredential]$Credential,
        [bool]$SSL
    )

    $protocol = if ($SSL) { "LDAP" } else { "LDAP" }
    $ldapPath = "${protocol}://${Server}:${Port}/$BaseDN"

    if ($Credential) {
        $username = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $username, $password)
        if ($SSL) {
            $entry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer -bor
                                        [System.DirectoryServices.AuthenticationTypes]::Signing
        }
    } else {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor
                              [System.DirectoryServices.SecurityMasks]::Owner

    foreach ($prop in $PropertiesToLoad) {
        $searcher.PropertiesToLoad.Add($prop) | Out-Null
    }

    return $searcher
}

function Get-LdapProperty {
    param(
        [System.DirectoryServices.SearchResult]$Result,
        [string]$PropertyName,
        [switch]$SingleValue
    )
    if (-not $Result.Properties.Contains($PropertyName)) { return $null }
    $vals = $Result.Properties[$PropertyName]
    if ($SingleValue) { return $vals[0] }
    return @($vals)
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

if ($UseSSL -and $Port -eq 389) { $Port = 636 }

# Prompt for credentials if not supplied
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter domain credentials (DOMAIN\user or user@domain)"
    if (-not $Credential) {
        Write-Host "  [-] Credentials required." -ForegroundColor Red
        return
    }
}

Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host "  |  AD CS LOLBAS - Remote Audit                                |" -ForegroundColor DarkCyan
Write-Host "  |  Enumerate AD CS templates via LDAP (no domain join needed) |" -ForegroundColor DarkCyan
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host ""
$script:ReportLines.Add("AD CS Remote Audit Report")
$script:ReportLines.Add("=" * 60)

# -- STAGE 1: Connect and discover naming context -------------------------
Out-Line "  >>> STAGE 1 - CONNECTING TO $Server`:$Port" 'Cyan'

try {
    $protocol = "LDAP"
    $rootPath = "${protocol}://${Server}:${Port}/RootDSE"
    if ($Credential) {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry(
            $rootPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($rootPath)
    }

    $configNC    = $rootDSE.Properties["configurationNamingContext"][0].ToString()
    $defaultNC   = $rootDSE.Properties["defaultNamingContext"][0].ToString()
    $dnsHostName = try { $rootDSE.Properties["dnsHostName"][0].ToString() } catch { $Server }

    Out-Line "    [+] Connected to: $dnsHostName" 'Green'
    Out-Line "    [i] Domain DN   : $defaultNC" 'Gray'
    Out-Line "    [i] Config NC   : $configNC" 'Gray'
} catch {
    Out-Line "    [-] Failed to connect: $($_.Exception.Message)" 'Red'
    Out-Line "    [i] Verify: server reachable, credentials correct, port open" 'Yellow'
    return
}

# Discover domain SID
$domainSID = $null
try {
    $domainSearcher = New-LdapSearcher -Server $Server -Port $Port -BaseDN $defaultNC `
        -Filter "(&(objectClass=domain)(objectSid=*))" `
        -PropertiesToLoad @("objectSid") -Credential $Credential -SSL $UseSSL
    $domainResult = $domainSearcher.FindOne()
    if ($domainResult) {
        $sidBytes = [byte[]]$domainResult.Properties["objectsid"][0]
        $domainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
        Out-Line "    [i] Domain SID  : $domainSID" 'Gray'
    }
} catch {
    Out-Line "    [~] Could not resolve domain SID: $($_.Exception.Message)" 'Yellow'
}
Out-Line ""

# -- STAGE 2: Enumerate Certificate Authorities ---------------------------
Out-Line "  >>> STAGE 2 - ENUMERATING CERTIFICATE AUTHORITIES" 'Cyan'

$enrollBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
$caTemplateMap = @{}

try {
    $caSearcher = New-LdapSearcher -Server $Server -Port $Port -BaseDN $enrollBase `
        -Filter "(objectClass=pKIEnrollmentService)" `
        -PropertiesToLoad @("name","dNSHostName","certificateTemplates") `
        -Credential $Credential -SSL $UseSSL

    $caResults = $caSearcher.FindAll()
    foreach ($ca in $caResults) {
        $caName = (Get-LdapProperty $ca 'name' -SingleValue).ToString()
        $caTpls = @()
        $raw = Get-LdapProperty $ca 'certificateTemplates'
        if ($raw) { $caTpls = @($raw | ForEach-Object { $_.ToString() }) }
        $caTemplateMap[$caName] = $caTpls
        Out-Line "    [+] $caName ($($caTpls.Count) published templates)" 'Green'
    }
    $caResults.Dispose()
} catch {
    Out-Line "    [-] Error enumerating CAs: $($_.Exception.Message)" 'Red'
}

if ($caTemplateMap.Count -eq 0) {
    Out-Line "    [~] No Certificate Authorities found" 'Yellow'
}

# Build reverse map: template name -> CAs
$templateToCA = @{}
foreach ($ca in $caTemplateMap.Keys) {
    foreach ($tpl in $caTemplateMap[$ca]) {
        if (-not $templateToCA.ContainsKey($tpl)) { $templateToCA[$tpl] = @() }
        $templateToCA[$tpl] += $ca
    }
}
Out-Line ""

# -- STAGE 3: Enumerate Certificate Templates -----------------------------
Out-Line "  >>> STAGE 3 - ENUMERATING CERTIFICATE TEMPLATES" 'Cyan'

$templateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$templateProps = @(
    "name","cn","displayName","distinguishedName",
    "msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
    "msPKI-RA-Signature","pKIExtendedKeyUsage",
    "msPKI-Template-Schema-Version","msPKI-Certificate-Policy",
    "nTSecurityDescriptor","pKIExpirationPeriod","pKIOverlapPeriod"
)

$certTemplates = [System.Collections.Generic.List[hashtable]]::new()

try {
    $tplSearcher = New-LdapSearcher -Server $Server -Port $Port -BaseDN $templateBase `
        -Filter "(objectClass=pKICertificateTemplate)" `
        -PropertiesToLoad $templateProps -Credential $Credential -SSL $UseSSL

    $tplResults = $tplSearcher.FindAll()
    foreach ($r in $tplResults) {
        $tplName    = (Get-LdapProperty $r 'name' -SingleValue)
        $tplDisplay = (Get-LdapProperty $r 'displayname' -SingleValue)
        $nameFlag   = (Get-LdapProperty $r 'mspki-certificate-name-flag' -SingleValue)
        $enrollFlag = (Get-LdapProperty $r 'mspki-enrollment-flag' -SingleValue)
        $raSig      = (Get-LdapProperty $r 'mspki-ra-signature' -SingleValue)
        $schemaVer  = (Get-LdapProperty $r 'mspki-template-schema-version' -SingleValue)
        $ekuRaw     = Get-LdapProperty $r 'pkiextendedkeyusage'
        $policyRaw  = Get-LdapProperty $r 'mspki-certificate-policy'
        $sdRaw      = Get-LdapProperty $r 'ntsecuritydescriptor' -SingleValue
        $validRaw   = Get-LdapProperty $r 'pkiexpirationperiod' -SingleValue
        $renewRaw   = Get-LdapProperty $r 'pkioverlapperiod' -SingleValue

        $certTemplates.Add(@{
            Name          = if ($tplName)    { $tplName.ToString() }    else { '' }
            DisplayName   = if ($tplDisplay) { $tplDisplay.ToString() } else { '' }
            NameFlag      = if ($null -ne $nameFlag)   { [uint32]$nameFlag }   else { 0 }
            EnrollFlag    = if ($null -ne $enrollFlag)  { [uint32]$enrollFlag } else { 0 }
            RASignature   = if ($null -ne $raSig)       { [int]$raSig }         else { 0 }
            SchemaVersion = if ($null -ne $schemaVer)   { [int]$schemaVer }     else { 0 }
            EKUs          = if ($ekuRaw)     { @($ekuRaw | ForEach-Object { $_.ToString() }) } else { @() }
            CertPolicy    = if ($policyRaw)  { @($policyRaw | ForEach-Object { $_.ToString() }) } else { @() }
            SDBytes       = if ($sdRaw)      { [byte[]]$sdRaw } else { $null }
            ValidityPeriod = if ($validRaw)  { [byte[]]$validRaw } else { $null }
            RenewalPeriod  = if ($renewRaw)  { [byte[]]$renewRaw } else { $null }
        })
    }
    $tplResults.Dispose()
} catch {
    Out-Line "    [-] Error enumerating templates: $($_.Exception.Message)" 'Red'
    return
}

$enabledCount = ($certTemplates | Where-Object { $templateToCA.ContainsKey($_.Name) }).Count
Out-Line "    [i] Found $($certTemplates.Count) templates ($enabledCount enabled)" 'Green'
Out-Line ""

# -- STAGE 4: Vulnerability Analysis --------------------------------------
Out-Line "  >>> STAGE 4 - VULNERABILITY ANALYSIS" 'Cyan'
Out-Line ""

$totalFindings = 0
$findingsSummary = [System.Collections.Generic.List[string]]::new()

foreach ($tpl in $certTemplates | Sort-Object { $_.Name }) {
    $name    = $tpl.Name
    $enabled = $templateToCA.ContainsKey($name)
    $caList  = if ($enabled) { $templateToCA[$name] -join ', ' } else { '(none)' }

    $suppliesSAN = ($tpl.NameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
    $noApproval  = ($tpl.EnrollFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -eq 0
    $noSecExt    = ($tpl.EnrollFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) -ne 0
    $noSignature = ($tpl.RASignature -eq 0)

    $ekuList = @($tpl.EKUs)
    $ekuStrings = @($ekuList | ForEach-Object { if ($OID_MAP.ContainsKey($_)) { $OID_MAP[$_] } else { $_ } })

    $hasAuthEKU   = ($ekuList.Count -eq 0) -or ($ekuList | Where-Object { $_ -in $AUTH_EKUS })
    $hasAnyOrNone = ($ekuList.Count -eq 0) -or ($ekuList -contains '2.5.29.37.0')
    $hasAgentEKU  = ($ekuList -contains $AGENT_EKU)

    $findings = [System.Collections.Generic.List[string]]::new()

    if ($suppliesSAN -and $hasAuthEKU -and $noApproval -and $noSignature) {
        $findings.Add('ESC1: ENROLLEE_SUPPLIES_SUBJECT + Auth EKU + No Approval')
    }
    if ($hasAnyOrNone -and $noApproval -and $noSignature) {
        $findings.Add('ESC2: Any Purpose / No EKU restriction')
    }
    if ($hasAgentEKU -and $noApproval -and $noSignature) {
        $findings.Add('ESC3: Certificate Request Agent EKU')
    }
    if ($noSecExt -and $hasAuthEKU) {
        $findings.Add('ESC9: CT_FLAG_NO_SECURITY_EXTENSION + Auth EKU')
    }

    $dangerousAces = @()
    if ($tpl.SDBytes) {
        $dangerousAces = @(Get-DangerousAces -SDBytes $tpl.SDBytes -DomainSID $domainSID)
        if ($dangerousAces.Count -gt 0) {
            foreach ($dAce in $dangerousAces) {
                $findings.Add("ESC4: $($dAce.Principal) has $($dAce.Right)")
            }
        }
    }

    $certPolicyList = @($tpl.CertPolicy)
    if ($certPolicyList.Count -gt 0) {
        $findings.Add("ESC13: Has issuance policy OID ($($certPolicyList -join ', ')) - verify OID group link")
    }

    if ($VulnerableOnly -and $findings.Count -eq 0) { continue }

    $totalFindings += $findings.Count

    $enabledStr = if ($enabled) { "True (CA: $caList)" } else { "False" }
    $enabledColor = if ($enabled) { 'Green' } else { 'DarkGray' }

    Out-Line "    +---------------------------------------------------------+" 'DarkCyan'
    Out-Line "    | Template: $($name.PadRight(46))  |" 'DarkCyan'
    Out-Line "    +---------------------------------------------------------+" 'DarkCyan'
    Out-Line "      Display Name           : $($tpl.DisplayName)" 'White'
    Out-Line "      Enabled                : $enabledStr" $enabledColor
    Out-Line "      Schema Version         : $($tpl.SchemaVersion)" 'White'

    $validStr = if ($tpl.ValidityPeriod) { ConvertTo-DurationString $tpl.ValidityPeriod } else { 'N/A' }
    $renewStr = if ($tpl.RenewalPeriod)  { ConvertTo-DurationString $tpl.RenewalPeriod }  else { 'N/A' }
    Out-Line "      Validity Period        : $validStr" 'White'
    Out-Line "      Renewal Period         : $renewStr" 'White'

    $sanColor = if ($suppliesSAN) { 'Red' } else { 'White' }
    Out-Line "      Enrollee Supplies Subj : $suppliesSAN" $sanColor

    $approvalColor = if ($noApproval) { 'Yellow' } else { 'Green' }
    $approvalStr   = if ($noApproval) { 'False (no approval needed)' } else { 'True' }
    Out-Line "      Requires Approval      : $approvalStr" $approvalColor

    Out-Line "      RA Signatures Required : $($tpl.RASignature)" 'White'

    $secExtColor = if ($noSecExt) { 'Red' } else { 'White' }
    Out-Line "      No Security Extension  : $noSecExt" $secExtColor

    if ($ekuStrings.Count -eq 0) {
        Out-Line "      Extended Key Usage     : (none - any purpose)" 'Yellow'
    } else {
        Out-Line "      Extended Key Usage     :" 'White'
        foreach ($eku in $ekuStrings) { Out-Line "        - $eku" 'White' }
    }

    # Enrollment flags
    $enrollFlagNames = @()
    if ($tpl.EnrollFlag -band 0x00000001) { $enrollFlagNames += 'INCLUDE_SYMMETRIC_ALGORITHMS' }
    if ($tpl.EnrollFlag -band 0x00000002) { $enrollFlagNames += 'PEND_ALL_REQUESTS' }
    if ($tpl.EnrollFlag -band 0x00000008) { $enrollFlagNames += 'PUBLISH_TO_DS' }
    if ($tpl.EnrollFlag -band 0x00000020) { $enrollFlagNames += 'AUTO_ENROLLMENT' }
    if ($tpl.EnrollFlag -band 0x00080000) { $enrollFlagNames += 'NO_SECURITY_EXTENSION' }
    if ($enrollFlagNames.Count -gt 0) {
        Out-Line "      Enrollment Flags       : $($enrollFlagNames -join ', ')" 'Gray'
    }

    # Name flags
    $nameFlagNames = @()
    if ($tpl.NameFlag -band 0x00000001) { $nameFlagNames += 'ENROLLEE_SUPPLIES_SUBJECT' }
    if ($tpl.NameFlag -band 0x00010000) { $nameFlagNames += 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME' }
    if ($tpl.NameFlag -band 0x00400000) { $nameFlagNames += 'SUBJECT_ALT_REQUIRE_UPN' }
    if ($tpl.NameFlag -band 0x04000000) { $nameFlagNames += 'SUBJECT_ALT_REQUIRE_DNS' }
    if ($tpl.NameFlag -band 0x20000000) { $nameFlagNames += 'SUBJECT_REQUIRE_COMMON_NAME' }
    if ($nameFlagNames.Count -gt 0) {
        Out-Line "      Certificate Name Flags : $($nameFlagNames -join ', ')" 'Gray'
    }

    # Enrollment principals
    if ($tpl.SDBytes) {
        $enrollPrincipals = Get-EnrollmentPrincipals -SDBytes $tpl.SDBytes -DomainSID $domainSID
        if ($enrollPrincipals.Count -gt 0) {
            Out-Line "      Enrollment Principals  :" 'White'
            foreach ($ep in $enrollPrincipals) { Out-Line "        - $ep" 'Gray' }
        }
    }

    if ($findings.Count -gt 0) {
        Out-Line "" 'White'
        Out-Line "      VULNERABILITIES:" 'Red'
        foreach ($f in $findings) {
            Out-Line "        [!] $f" 'Red'
            $escTag = ($f -split ':')[0]
            $findingsSummary.Add("$escTag - $name")
        }
    } else {
        Out-Line "      Status: No ESC vulnerabilities detected" 'Green'
    }
    Out-Line "" 'White'
}

# -- SUMMARY ---------------------------------------------------------------
Out-Line "  +==============================================================+" 'DarkCyan'
Out-Line "  |  SUMMARY                                                     |" 'DarkCyan'
Out-Line "  +==============================================================+" 'DarkCyan'
Out-Line ""
Out-Line "    Server         : $Server`:$Port" 'White'
Out-Line "    Domain         : $defaultNC" 'White'
Out-Line "    CAs            : $($caTemplateMap.Count)" 'White'
Out-Line "    Templates      : $($certTemplates.Count) total / $enabledCount enabled" 'White'
Out-Line "    Findings       : $totalFindings" $(if ($totalFindings -gt 0) { 'Red' } else { 'Green' })
Out-Line ""

if ($findingsSummary.Count -gt 0) {
    $grouped = $findingsSummary | Group-Object { ($_ -split ' - ')[0] }
    Out-Line "    Findings by Type:" 'Yellow'
    foreach ($g in $grouped | Sort-Object Name) {
        Out-Line "      $($g.Name): $($g.Count) template(s)" 'Yellow'
    }
    Out-Line ""

    Out-Line "    All Findings:" 'Yellow'
    foreach ($f in $findingsSummary) {
        Out-Line "      [!] $f" 'Red'
    }
    Out-Line ""
}

Out-Line "    Checks performed (live LDAP):" 'Gray'
Out-Line "      ESC1  : Enrollee Supplies Subject + Auth EKU + No Approval" 'Gray'
Out-Line "      ESC2  : Any Purpose / No EKU + No Approval" 'Gray'
Out-Line "      ESC3  : Certificate Request Agent EKU + No Approval" 'Gray'
Out-Line "      ESC4  : Dangerous ACLs on certificate templates" 'Gray'
Out-Line "      ESC9  : CT_FLAG_NO_SECURITY_EXTENSION + Auth EKU" 'Gray'
Out-Line "      ESC13 : Certificate issuance policy OID (manual verification)" 'Gray'
Out-Line ""
Out-Line "    For ESC6/7/8/10/11/12 checks, use Invoke-Enumerate.ps1 from a domain-joined host." 'DarkGray'
Out-Line ""

if ($OutputFile) {
    $script:ReportLines | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "  [+] Report saved to: $OutputFile" -ForegroundColor Green
    Write-Host ""
}
