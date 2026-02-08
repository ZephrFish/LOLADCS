<#
.SYNOPSIS
    AD CS ESC8 - NTLM Relay to HTTP Endpoint Discovery (LOLBAS).
.DESCRIPTION
    Discovers HTTP/HTTPS enrollment endpoints on CA servers that are
    vulnerable to NTLM relay attacks. Enumeration only - relay requires
    an external relay setup and authentication coercion.
.EXAMPLE
    .\Invoke-ESC8.ps1
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC8 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC8" "NTLM Relay to HTTP (Enumeration)"

Write-Stage -Number 1 -Name "HTTP ENDPOINT DISCOVERY"
$ctx = Get-ADContext
$services = Get-ADObject -SearchBase $ctx.EnrollBase `
    -Filter {objectClass -eq 'pKIEnrollmentService'} `
    -Properties dNSHostName, cn -ErrorAction SilentlyContinue

foreach ($svc in $services) {
    $h = $svc.dNSHostName
    Write-Host "    [*] CA Server: $h ($($svc.cn))" -ForegroundColor Cyan

    $endpoints = @(
        @{ Name="Web Enrollment (HTTP)";  URL="http://$h/certsrv/" },
        @{ Name="Web Enrollment (HTTPS)"; URL="https://$h/certsrv/" },
        @{ Name="CES (HTTP)";             URL="http://$h/$($svc.cn)_CES_Kerberos/service.svc" },
        @{ Name="NDES (HTTP)";            URL="http://$h/certsrv/mscep/" }
    )

    foreach ($ep in $endpoints) {
        try {
            $resp = Invoke-WebRequest -Uri $ep.URL -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            Write-Host "    [!] $($ep.Name): $($ep.URL) - REACHABLE" -ForegroundColor Red
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 401) {
                Write-Host "    [!] $($ep.Name): $($ep.URL) - 401 (exists)" -ForegroundColor Yellow
            }
        }
    }
}
Write-Stage -Number 1 -Name "HTTP ENDPOINT DISCOVERY" -Status 'COMPLETE'

Write-Host ""
Write-Host "    [i] ESC8 exploitation requires:" -ForegroundColor Cyan
Write-Host "        1. NTLM relay setup targeting discovered HTTP endpoints" -ForegroundColor Gray
Write-Host "        2. Authentication coercion from target (PetitPotam, PrinterBug, DFSCoerce)" -ForegroundColor Gray
Write-Host "        3. Relay captures auth and requests certificate as target" -ForegroundColor Gray
Write-Host "        4. Use certificate for PKINIT/Schannel auth (use Invoke-ESC1.ps1 auth stage)" -ForegroundColor Gray
Write-Host ""
