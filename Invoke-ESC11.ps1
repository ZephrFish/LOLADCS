<#
.SYNOPSIS
    AD CS ESC11 - NTLM Relay to RPC Endpoint Discovery (LOLBAS).
.DESCRIPTION
    Checks whether CAs have IF_ENFORCEENCRYPTICERTREQUEST set.
    If not, the CA's RPC interface is vulnerable to NTLM relay.
    Enumeration only - relay requires an external setup.
.EXAMPLE
    .\Invoke-ESC11.ps1
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC11 Standalone" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC11" "NTLM Relay to RPC (Enumeration)"

Write-Stage -Number 1 -Name "CA RPC FLAG ENUMERATION"
foreach ($ca in (Get-CAConfigs)) {
    Write-Host "    [*] CA: $ca" -ForegroundColor Cyan
    $iflags = certutil -config $ca -getreg CA\InterfaceFlags 2>$null
    if ($iflags -match 'IF_ENFORCEENCRYPTICERTREQUEST') {
        Write-Host "    [+] IF_ENFORCEENCRYPTICERTREQUEST SET (protected)" -ForegroundColor Green
    } else {
        Write-Host "    [!] IF_ENFORCEENCRYPTICERTREQUEST NOT SET - RPC relay possible" -ForegroundColor Red
    }
}
Write-Stage -Number 1 -Name "CA RPC FLAG ENUMERATION" -Status 'COMPLETE'

Write-Host ""
Write-Host "    [i] ESC11 = ESC8 but over RPC (TCP 135 + dynamic)" -ForegroundColor Cyan
Write-Host "    [i] Bypasses HTTP-specific mitigations (EPA on certsrv)" -ForegroundColor Cyan
Write-Host ""
