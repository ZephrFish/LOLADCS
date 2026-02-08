<#
.SYNOPSIS
    AD CS Template Finder - Discover enrollable certificate templates.
.DESCRIPTION
    Enumerates all certificate templates from Active Directory and checks
    which ones the current user (or a specified principal) can enroll in.
    Displays key properties, flags, EKUs, and highlights ESC-relevant misconfigs.
.PARAMETER Identity
    Optional: sAMAccountName or DN to check enrollment rights for.
    Defaults to the current user and their group memberships.
.PARAMETER CAConfig
    Optional: filter templates published on a specific CA.
    If omitted, shows all templates regardless of CA assignment.
.PARAMETER VulnerableOnly
    Only display templates with at least one ESC-relevant misconfiguration.
.PARAMETER Enrollable
    Only display templates the current user can enroll in.
.PARAMETER Raw
    Output template objects to the pipeline instead of formatted display.
.EXAMPLE
    .\Invoke-FindTemplates.ps1
    Lists all certificate templates with properties and enrollment status.
.EXAMPLE
    .\Invoke-FindTemplates.ps1 -Enrollable
    Shows only templates the current user can enroll in.
.EXAMPLE
    .\Invoke-FindTemplates.ps1 -VulnerableOnly
    Shows only templates with ESC-relevant misconfigurations.
.EXAMPLE
    .\Invoke-FindTemplates.ps1 -VulnerableOnly -Enrollable
    Shows vulnerable templates the current user can enroll in (attack surface).
.EXAMPLE
    .\Invoke-FindTemplates.ps1 -CAConfig "polaris.zsec.red\corp-CA" -Enrollable
    Shows enrollable templates published on a specific CA.
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [string]$Identity,
    [string]$CAConfig,
    [switch]$VulnerableOnly,
    [switch]$Enrollable,
    [switch]$Raw
)

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - Template Finder" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

# ============================================================================
#  Resolve current user SIDs for enrollment checks
# ============================================================================

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSIDs = @($currentIdentity.User.Value) + ($currentIdentity.Groups | ForEach-Object { $_.Value })

# Well-known SIDs that grant broad enrollment
$broadSIDs = @{
    'S-1-5-11'  = 'Authenticated Users'
    'S-1-1-0'   = 'Everyone'
}

# If a specific identity was requested, resolve its SIDs
if ($Identity) {
    try {
        $adUser = Get-ADUser -Identity $Identity -Properties memberOf, primaryGroupID -ErrorAction Stop
        $userSID = $adUser.SID.Value
        $groupSIDs = @()
        foreach ($grpDN in $adUser.memberOf) {
            $grp = Get-ADGroup -Identity $grpDN -ErrorAction SilentlyContinue
            if ($grp) { $groupSIDs += $grp.SID.Value }
        }
        $checkSIDs = @($userSID) + $groupSIDs + $broadSIDs.Keys
        Write-Host "  [i] Checking enrollment for: $Identity ($userSID)" -ForegroundColor Cyan
    } catch {
        Write-Host "  [-] Could not resolve identity: $Identity" -ForegroundColor Red
        Write-Host "  [i] Falling back to current user" -ForegroundColor Yellow
        $checkSIDs = $currentSIDs
    }
} else {
    $checkSIDs = $currentSIDs
    Write-Host "  [i] Current user: $($currentIdentity.Name)" -ForegroundColor Cyan
}

# ============================================================================
#  Get published templates from CA (if CAConfig specified)
# ============================================================================

$publishedTemplates = $null
if ($CAConfig) {
    Write-Host "  [i] Filtering by CA: $CAConfig" -ForegroundColor Cyan
    $ctx = Get-ADContext
    $caName = ($CAConfig -split '\\')[-1]
    $caObj = Get-ADObject -SearchBase $ctx.EnrollBase `
        -Filter {cn -eq $caName -and objectClass -eq 'pKIEnrollmentService'} `
        -Properties certificateTemplates -ErrorAction SilentlyContinue
    if ($caObj) {
        $publishedTemplates = $caObj.certificateTemplates
        Write-Host "  [+] CA publishes $($publishedTemplates.Count) templates" -ForegroundColor Green
    } else {
        Write-Host "  [-] CA '$caName' not found in AD" -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
#  EKU lookup table
# ============================================================================

$ekuNames = @{
    '1.3.6.1.5.5.7.3.1'        = 'Server Auth'
    '1.3.6.1.5.5.7.3.2'        = 'Client Auth'
    '1.3.6.1.5.5.7.3.3'        = 'Code Signing'
    '1.3.6.1.5.5.7.3.4'        = 'Email Protection'
    '1.3.6.1.4.1.311.20.2.1'   = 'Certificate Request Agent'
    '1.3.6.1.4.1.311.20.2.2'   = 'Smart Card Logon'
    '1.3.6.1.5.2.3.4'          = 'PKINIT Client Auth'
    '2.5.29.37.0'              = 'Any Purpose'
    '1.3.6.1.4.1.311.10.3.4'   = 'EFS'
    '1.3.6.1.4.1.311.10.3.4.1' = 'EFS Recovery'
}

$authEKUs = @(
    '1.3.6.1.5.5.7.3.2',
    '1.3.6.1.4.1.311.20.2.2',
    '1.3.6.1.5.2.3.4',
    '2.5.29.37.0'
)

# ============================================================================
#  Enumerate templates
# ============================================================================

$ctx = Get-ADContext

Write-Host ""
Write-Stage -Number 1 -Name "TEMPLATE DISCOVERY"

$templates = Get-ADObject -SearchBase $ctx.TemplateBase `
    -Filter {objectClass -eq 'pKICertificateTemplate'} `
    -Properties cn, displayName, name,
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'msPKI-RA-Signature',
        'msPKI-Minimal-Key-Size',
        'msPKI-Template-Schema-Version',
        'pKIExtendedKeyUsage',
        'pKIExpirationPeriod',
        'msPKI-Certificate-Policy',
        'nTSecurityDescriptor' -ErrorAction Stop

# Filter by CA-published templates if specified
if ($publishedTemplates) {
    $templates = $templates | Where-Object { $_.cn -in $publishedTemplates }
}

Write-Host "  [+] Found $($templates.Count) templates" -ForegroundColor Green
Write-Stage -Number 1 -Name "TEMPLATE DISCOVERY" -Status 'COMPLETE'

# ============================================================================
#  Analyse each template
# ============================================================================

Write-Host ""
Write-Stage -Number 2 -Name "TEMPLATE ANALYSIS"
Write-Host ""

$results = @()
$enrollableCount = 0
$vulnerableCount = 0

foreach ($t in $templates | Sort-Object cn) {
    $nameFlag   = $t.'msPKI-Certificate-Name-Flag'
    $enrollFlag = $t.'msPKI-Enrollment-Flag'
    $raSig      = $t.'msPKI-RA-Signature'
    $ekus       = $t.'pKIExtendedKeyUsage'
    $sd         = $t.nTSecurityDescriptor
    $certPolicy = $t.'msPKI-Certificate-Policy'

    # -- Decode flags ------------------------------------------
    $suppliesSAN  = ($nameFlag -band 1) -eq 1
    $noApproval   = ($enrollFlag -band 2) -ne 2
    $noSignature  = ($raSig -eq 0) -or ($null -eq $raSig)
    $noSecExt     = ($enrollFlag -band 0x80000) -ne 0

    # -- Decode EKUs -------------------------------------------
    $ekuDisplay = @()
    $hasAuthEKU = $false
    $hasAnyOrNone = $false
    $hasAgentEKU = $false

    if ($null -eq $ekus -or $ekus.Count -eq 0) {
        $ekuDisplay += 'No EKU (Any)'
        $hasAuthEKU = $true
        $hasAnyOrNone = $true
    } else {
        foreach ($e in $ekus) {
            $name = if ($ekuNames[$e]) { $ekuNames[$e] } else { $e }
            $ekuDisplay += $name
            if ($e -in $authEKUs) { $hasAuthEKU = $true }
            if ($e -eq '2.5.29.37.0') { $hasAnyOrNone = $true }
            if ($e -eq '1.3.6.1.4.1.311.20.2.1') { $hasAgentEKU = $true }
        }
    }

    # -- Check enrollment ACL ----------------------------------
    $canEnroll = $false
    $enrollPrincipals = @()

    if ($sd) {
        foreach ($ace in $sd.Access) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            $objectType = $ace.ObjectType.ToString()

            # Enroll: ExtendedRight with OID 0e10c968-78fb-11d2-90d4-00c04f79dc55
            # AutoEnroll: ExtendedRight with OID a05b8cc2-17bc-4802-a710-e7c15ab866a2
            # GenericAll also grants enrollment
            $isEnroll = ($rights -match 'ExtendedRight' -and $objectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55')
            $isAutoEnroll = ($rights -match 'ExtendedRight' -and $objectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
            $isGenericAll = ($rights -match 'GenericAll')

            if ($isEnroll -or $isAutoEnroll -or $isGenericAll) {
                $enrollPrincipals += $ace.IdentityReference.Value

                # Check if current user matches
                try {
                    $aceSID = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($aceSID -in $checkSIDs) { $canEnroll = $true }
                } catch {
                    # SID translation failed - check by name against well-known groups
                    $id = $ace.IdentityReference.Value
                    if ($id -match 'Authenticated Users|Everyone|Domain Users|Domain Computers') {
                        $canEnroll = $true
                    }
                }
            }
        }
    }

    # -- Check for dangerous ACLs (ESC4) -----------------------
    $writableBy = @()
    if ($sd) {
        foreach ($ace in $sd.Access) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                try {
                    $aceSID = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($aceSID -in $checkSIDs) {
                        $writableBy += $ace.IdentityReference.Value
                    }
                } catch { }
            }
        }
    }

    # -- Check OID group links (ESC13) -------------------------
    $linkedGroups = @()
    if ($certPolicy) {
        foreach ($oid in $certPolicy) {
            $oidObj = Get-ADObject -SearchBase $ctx.OIDBase `
                -Filter {msPKI-Cert-Template-OID -eq $oid} `
                -Properties 'msDS-OIDToGroupLink' -ErrorAction SilentlyContinue
            if ($oidObj.'msDS-OIDToGroupLink') {
                try {
                    $grp = Get-ADGroup -Identity $oidObj.'msDS-OIDToGroupLink' -ErrorAction Stop
                    $linkedGroups += $grp.Name
                } catch {
                    $linkedGroups += $oidObj.'msDS-OIDToGroupLink'
                }
            }
        }
    }

    # -- Identify ESC conditions -------------------------------
    $escFlags = @()

    if ($suppliesSAN -and $hasAuthEKU -and $noApproval -and $noSignature) { $escFlags += 'ESC1' }
    if ($hasAnyOrNone -and $noApproval -and $noSignature)                 { $escFlags += 'ESC2' }
    if ($hasAgentEKU -and $noApproval -and $noSignature)                  { $escFlags += 'ESC3' }
    if ($writableBy.Count -gt 0)                                          { $escFlags += 'ESC4' }
    if ($noSecExt -and $hasAuthEKU)                                       { $escFlags += 'ESC9' }
    if ($linkedGroups.Count -gt 0)                                        { $escFlags += 'ESC13' }

    $isVulnerable = $escFlags.Count -gt 0

    # -- Apply filters -----------------------------------------
    if ($Enrollable -and -not $canEnroll) { continue }
    if ($VulnerableOnly -and -not $isVulnerable) { continue }

    if ($canEnroll) { $enrollableCount++ }
    if ($isVulnerable) { $vulnerableCount++ }

    # -- Build result object -----------------------------------
    $obj = [PSCustomObject]@{
        Name             = $t.cn
        DisplayName      = $t.displayName
        Enrollable       = $canEnroll
        EnrollPrincipals = ($enrollPrincipals | Select-Object -Unique) -join ', '
        EKUs             = $ekuDisplay -join ', '
        HasAuthEKU       = $hasAuthEKU
        SuppliesSAN      = $suppliesSAN
        NoApproval       = $noApproval
        NoSignature      = $noSignature
        NoSecurityExt    = $noSecExt
        Writable         = ($writableBy | Select-Object -Unique) -join ', '
        LinkedGroups     = $linkedGroups -join ', '
        ESCFlags         = $escFlags -join ', '
        SchemaVersion    = $t.'msPKI-Template-Schema-Version'
        KeySize          = $t.'msPKI-Minimal-Key-Size'
    }
    $results += $obj

    # -- Display -----------------------------------------------
    if (-not $Raw) {
        $nameColor = if ($isVulnerable) { 'Red' } elseif ($canEnroll) { 'Yellow' } else { 'Gray' }
        $enrollIcon = if ($canEnroll) { '[E]' } else { '   ' }
        $escTag = if ($escFlags) { " [$($escFlags -join ',')]" } else { '' }

        Write-Host "  $enrollIcon " -NoNewline -ForegroundColor $(if ($canEnroll) {'Green'} else {'DarkGray'})
        Write-Host "$($t.cn)" -NoNewline -ForegroundColor $nameColor
        Write-Host "$escTag" -ForegroundColor Red

        # Detail line
        $details = @()
        $details += "EKU: $($ekuDisplay -join ', ')"
        if ($suppliesSAN) { $details += "SUPPLIES_SAN" }
        if (-not $noApproval) { $details += "APPROVAL_REQ" }
        if (-not $noSignature) { $details += "SIG_REQ" }
        if ($noSecExt) { $details += "NO_SEC_EXT" }
        Write-Host "        $($details -join ' | ')" -ForegroundColor DarkGray

        if ($enrollPrincipals.Count -gt 0) {
            $displayed = ($enrollPrincipals | Select-Object -Unique | Select-Object -First 3) -join ', '
            $more = if (($enrollPrincipals | Select-Object -Unique).Count -gt 3) { ' ...' } else { '' }
            Write-Host "        Enroll: $displayed$more" -ForegroundColor DarkGray
        }
        if ($writableBy.Count -gt 0) {
            Write-Host "        WRITABLE by: $($writableBy -join ', ')" -ForegroundColor Red
        }
        if ($linkedGroups.Count -gt 0) {
            Write-Host "        OID -> Group: $($linkedGroups -join ', ')" -ForegroundColor Magenta
        }
        Write-Host ""
    }
}

Write-Stage -Number 2 -Name "TEMPLATE ANALYSIS" -Status 'COMPLETE'

# ============================================================================
#  Summary
# ============================================================================

Write-Host ""
Write-Host "  ====================================================" -ForegroundColor DarkCyan
Write-Host "  Templates found  : $($results.Count)" -ForegroundColor White
Write-Host "  Enrollable       : $enrollableCount" -ForegroundColor $(if ($enrollableCount -gt 0) {'Green'} else {'Gray'})
Write-Host "  Vulnerable       : $vulnerableCount" -ForegroundColor $(if ($vulnerableCount -gt 0) {'Red'} else {'Green'})
Write-Host "  ====================================================" -ForegroundColor DarkCyan

# Legend
Write-Host ""
Write-Host "  Legend:" -ForegroundColor DarkGray
Write-Host "    [E] = Current user can enroll" -ForegroundColor Green
Write-Host "    Red = ESC-vulnerable template" -ForegroundColor Red
Write-Host "    Yellow = Enrollable (no ESC flag)" -ForegroundColor Yellow
Write-Host "    Gray = Not enrollable" -ForegroundColor Gray
Write-Host ""

# Pipeline output
if ($Raw) {
    return $results
}
