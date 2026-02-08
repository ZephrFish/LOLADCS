<#
.SYNOPSIS
    AD CS ESC5 - PKI Object ACL Audit (LOLBAS).
.DESCRIPTION
    Enumerates ACLs on PKI AD objects (NTAuthCertificates, Certificate Templates,
    Enrollment Services, OID container). Identifies writable objects for the current user.
.EXAMPLE
    .\Invoke-ESC5.ps1
.NOTES
    For authorised security testing and educational purposes only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$_dir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
. "$_dir\adcs-common.ps1"

Write-Host ""
Write-Host "  AD CS LOLBAS - ESC5 Standalone" -ForegroundColor White
Write-Host "  --------------------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Banner "ESC5" "PKI Object ACL Audit"

Write-Stage -Number 1 -Name "PKI OBJECT ENUMERATION"
$ctx = Get-ADContext
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSIDs = @($currentUser.User.Value) + ($currentUser.Groups | ForEach-Object { $_.Value })

$targets = @(
    @{ Name = "NTAuthCertificates";    DN = $ctx.NTAuthDN },
    @{ Name = "Certificate Templates"; DN = $ctx.TemplateBase },
    @{ Name = "Enrollment Services";   DN = $ctx.EnrollBase },
    @{ Name = "OID Container";         DN = $ctx.OIDBase },
    @{ Name = "Public Key Services";   DN = $ctx.PKIBase }
)

$writable = @()
foreach ($target in $targets) {
    try {
        $obj = Get-ADObject -Identity $target.DN -Properties nTSecurityDescriptor -ErrorAction Stop
        foreach ($ace in $obj.nTSecurityDescriptor.Access) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                $msg = "    [!] $($target.Name): $($ace.IdentityReference) - $rights"
                Write-Host $msg -ForegroundColor Yellow

                try {
                    $aceSID = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($aceSID -in $currentSIDs) {
                        Write-Host "        ^^^ CURRENT USER MATCH ^^^" -ForegroundColor Red
                        $writable += $target
                    }
                } catch { }
            }
        }
    } catch { }
}

Write-Stage -Number 1 -Name "PKI OBJECT ENUMERATION" -Status 'COMPLETE'

Write-Host ""
Write-Host "    [i] Exploitation depends on the writable object:" -ForegroundColor Cyan
Write-Host "        NTAuthCertificates  -> Add rogue CA (certutil -dspublish -f rogue.cer NTAuthCA)" -ForegroundColor Gray
Write-Host "        Enrollment Services -> Modify CA config / template associations" -ForegroundColor Gray
Write-Host "        Template Containers -> Chain to ESC4" -ForegroundColor Gray
Write-Host "        CA Computer Object  -> RBCD / shadow credentials" -ForegroundColor Gray
Write-Host ""
