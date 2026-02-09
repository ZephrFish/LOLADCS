<#
.SYNOPSIS
    AD CS Snapshot Audit - Parse ADExplorer .dat snapshots offline for vulnerable AD CS templates.
.DESCRIPTION
    Parses the binary ADExplorer snapshot format (no external dependencies) and identifies
    certificate templates vulnerable to ESC1, ESC2, ESC3, ESC4, ESC9, and ESC13.
    Based on parsing logic from github.com/c3c/ADExplorerSnapshot.py (certipy/bloodhound).
.PARAMETER SnapshotPath
    Path to the ADExplorer .dat snapshot file.
.PARAMETER VulnerableOnly
    Only display templates with at least one ESC finding.
.PARAMETER List
    Interactive mode: runs the full audit, then presents a numbered list of
    high-value target users (Domain Admins, Enterprise Admins, etc.) to pick from.
    The selected user is used in all generated exploitation commands.
.PARAMETER Target
    Specify the target user for ESC attack commands (e.g. 'administrator').
    If not specified, defaults to the first non-computer Domain Admin found in the snapshot.
.PARAMETER OutputFile
    Optional path to save the report as a text file.
.PARAMETER CsvFile
    Optional path to export structured results as CSV for offline parsing.
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -VulnerableOnly
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -OutputFile report.txt
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -CsvFile results.csv
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -List
.EXAMPLE
    .\Invoke-SnapshotAudit.ps1 -SnapshotPath .\snapshot.dat -Target jsmith
.NOTES
    For authorised security testing and educational purposes only.
    Requires no domain connectivity - works entirely offline against snapshot files.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SnapshotPath,
    [switch]$VulnerableOnly,
    [switch]$List,
    [string]$Target,
    [string]$OutputFile,
    [string]$CsvFile
)

$ErrorActionPreference = 'Stop'

# ============================================================================
#  CONSTANTS
# ============================================================================

$OBJECTS_OFFSET = 0x43E

# ADSTYPE enumeration
$ADSTYPE_DN_STRING          = 1
$ADSTYPE_CASE_EXACT_STRING  = 2
$ADSTYPE_CASE_IGNORE_STRING = 3
$ADSTYPE_PRINTABLE_STRING   = 4
$ADSTYPE_NUMERIC_STRING     = 5
$ADSTYPE_BOOLEAN            = 6
$ADSTYPE_INTEGER            = 7
$ADSTYPE_OCTET_STRING       = 8
$ADSTYPE_UTC_TIME           = 9
$ADSTYPE_LARGE_INTEGER      = 10
$ADSTYPE_OBJECT_CLASS       = 12
$ADSTYPE_NT_SECURITY_DESCRIPTOR = 25
$STRING_TYPES = @($ADSTYPE_DN_STRING, $ADSTYPE_CASE_EXACT_STRING, $ADSTYPE_CASE_IGNORE_STRING,
                  $ADSTYPE_PRINTABLE_STRING, $ADSTYPE_NUMERIC_STRING, $ADSTYPE_OBJECT_CLASS)

# CertificateNameFlag
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

# EnrollmentFlag
$CT_FLAG_PEND_ALL_REQUESTS      = 0x00000002
$CT_FLAG_NO_SECURITY_EXTENSION  = 0x00080000

# EKU OIDs
$OID_MAP = @{
    "1.3.6.1.5.5.7.3.1"        = "Server Authentication"
    "1.3.6.1.5.5.7.3.2"        = "Client Authentication"
    "1.3.6.1.5.5.7.3.3"        = "Code Signing"
    "1.3.6.1.5.5.7.3.4"        = "Secure Email"
    "1.3.6.1.5.5.7.3.8"        = "Time Stamping"
    "1.3.6.1.5.5.7.3.9"        = "OCSP Signing"
    "1.3.6.1.4.1.311.10.3.1"   = "Microsoft Trust List Signing"
    "1.3.6.1.4.1.311.10.3.4"   = "Encrypting File System"
    "1.3.6.1.4.1.311.20.2.1"   = "Certificate Request Agent"
    "1.3.6.1.4.1.311.20.2.2"   = "Smart Card Logon"
    "1.3.6.1.5.2.3.4"          = "PKINIT Client Authentication"
    "2.5.29.37.0"               = "Any Purpose"
    "1.3.6.1.4.1.311.21.5"     = "CA Exchange"
    "1.3.6.1.4.1.311.21.6"     = "Key Recovery Agent"
}
$AUTH_EKUS  = @("1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.311.20.2.2","1.3.6.1.5.2.3.4","2.5.29.37.0")
$AGENT_EKU  = "1.3.6.1.4.1.311.20.2.1"

# ACL constants
$ADS_RIGHT_WRITE_DAC      = 0x00040000
$ADS_RIGHT_WRITE_OWNER    = 0x00080000
$ADS_RIGHT_GENERIC_ALL    = 0x10000000
$ADS_RIGHT_GENERIC_WRITE  = 0x40000000
$ADS_RIGHT_DS_WRITE_PROP  = 0x00000020
$ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
$DANGEROUS_MASK = $ADS_RIGHT_WRITE_DAC -bor $ADS_RIGHT_WRITE_OWNER -bor $ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_GENERIC_WRITE

# Enrollment extended right GUID
$ENROLL_GUID     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
$AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Privileged SIDs to exclude from ESC4 flagging
$PRIVILEGED_SIDS = @(
    'S-1-5-18',       # SYSTEM
    'S-1-5-9',        # Enterprise Domain Controllers
    'S-1-5-32-544'    # BUILTIN\Administrators
)
$PRIVILEGED_RID_SUFFIXES = @('-512','-518','-519') # Domain Admins, Schema Admins, Enterprise Admins

# Well-known SIDs
$WELLKNOWN_SIDS = @{
    'S-1-1-0'    = 'Everyone'
    'S-1-5-7'    = 'Anonymous Logon'
    'S-1-5-11'   = 'Authenticated Users'
    'S-1-5-18'   = 'SYSTEM'
    'S-1-5-9'    = 'Enterprise Domain Controllers'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
}

# Report buffer
$script:ReportLines = [System.Collections.Generic.List[string]]::new()

# ============================================================================
#  UI & REPORT HELPERS
# ============================================================================

function Out-Line {
    param([string]$Text = '', [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
    $script:ReportLines.Add($Text)
}

# ============================================================================
#  BINARY READER HELPERS
# ============================================================================

function Read-NullTermWchar {
    param([System.IO.BinaryReader]$R)
    $chars = [System.Collections.Generic.List[char]]::new(64)
    while ($true) {
        $code = $R.ReadUInt16()
        if ($code -eq 0) { break }
        $chars.Add([char]$code)
    }
    return (-join $chars)
}

function Read-FixedWchar {
    param([System.IO.BinaryReader]$R, [int]$CharCount)
    $bytes = $R.ReadBytes($CharCount * 2)
    return [System.Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
}

function Read-Attribute {
    param(
        [System.IO.BinaryReader]$R,
        [long]$ObjFileOffset,
        [int]$AttrOffset,
        [int]$AdsType,
        [string]$AttrName,
        [switch]$Raw
    )

    $fileAttrOffset = [long]$ObjFileOffset + [long]$AttrOffset
    $R.BaseStream.Seek($fileAttrOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $numValues = $R.ReadUInt32()
    if ($numValues -eq 0) { return ,@() }

    $values = [System.Collections.Generic.List[object]]::new($numValues)

    if ($AdsType -in $STRING_TYPES) {
        # Read offset array then null-terminated wchar strings
        $offsets = [uint32[]]::new($numValues)
        for ($v = 0; $v -lt $numValues; $v++) { $offsets[$v] = $R.ReadUInt32() }
        for ($v = 0; $v -lt $numValues; $v++) {
            $R.BaseStream.Seek($fileAttrOffset + $offsets[$v], [System.IO.SeekOrigin]::Begin) | Out-Null
            $values.Add((Read-NullTermWchar $R))
        }
    }
    elseif ($AdsType -eq $ADSTYPE_OCTET_STRING) {
        $lengths = [uint32[]]::new($numValues)
        for ($v = 0; $v -lt $numValues; $v++) { $lengths[$v] = $R.ReadUInt32() }
        for ($v = 0; $v -lt $numValues; $v++) {
            $octets = $R.ReadBytes($lengths[$v])
            if (-not $Raw) {
                if ($octets.Length -eq 16 -and $AttrName -like '*guid*') {
                    $values.Add(([guid]::new($octets)).ToString())
                    continue
                }
                if ($AttrName -ieq 'objectSid' -or $AttrName -ieq 'securityIdentifier') {
                    try {
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($octets, 0)
                        $values.Add($sid.Value)
                    } catch { $values.Add($octets) }
                    continue
                }
            }
            $values.Add($octets)
        }
    }
    elseif ($AdsType -eq $ADSTYPE_BOOLEAN) {
        for ($v = 0; $v -lt $numValues; $v++) { $values.Add([bool]$R.ReadUInt32()) }
    }
    elseif ($AdsType -eq $ADSTYPE_INTEGER) {
        for ($v = 0; $v -lt $numValues; $v++) { $values.Add($R.ReadUInt32()) }
    }
    elseif ($AdsType -eq $ADSTYPE_LARGE_INTEGER) {
        for ($v = 0; $v -lt $numValues; $v++) { $values.Add($R.ReadInt64()) }
    }
    elseif ($AdsType -eq $ADSTYPE_UTC_TIME) {
        for ($v = 0; $v -lt $numValues; $v++) {
            $yr=$R.ReadUInt16(); $mo=$R.ReadUInt16(); $R.ReadUInt16() | Out-Null # dayOfWeek
            $dy=$R.ReadUInt16(); $hr=$R.ReadUInt16(); $mn=$R.ReadUInt16()
            $sc=$R.ReadUInt16(); $ms=$R.ReadUInt16()
            try { $values.Add([datetime]::new($yr,$mo,$dy,$hr,$mn,$sc,$ms,[System.DateTimeKind]::Utc)) }
            catch { $values.Add($null) }
        }
    }
    elseif ($AdsType -eq $ADSTYPE_NT_SECURITY_DESCRIPTOR) {
        for ($v = 0; $v -lt $numValues; $v++) {
            $len = $R.ReadUInt32()
            $values.Add($R.ReadBytes($len))
        }
    }
    # else: unhandled type, return empty

    return ,$values.ToArray()
}

function Get-ObjectAttribute {
    param(
        [System.IO.BinaryReader]$R,
        [long]$ObjFileOffset,
        [array]$MappingTable,
        [hashtable]$PropertyDict,
        [array]$Properties,
        [string]$AttrName,
        [switch]$Raw
    )

    $idx = $PropertyDict[$AttrName]
    if ($null -eq $idx) { return $null }

    foreach ($entry in $MappingTable) {
        if ($entry.Index -eq $idx) {
            $prop = $Properties[$idx]
            $params = @{
                R = $R
                ObjFileOffset = $ObjFileOffset
                AttrOffset = $entry.Offset
                AdsType = $prop.AdsType
                AttrName = $AttrName
            }
            if ($Raw) { $params['Raw'] = $true }
            return ,(Read-Attribute @params)
        }
    }
    return $null
}

function Read-ObjectMappingTable {
    param([System.IO.BinaryReader]$R, [long]$ObjectOffset)
    $R.BaseStream.Seek($ObjectOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $objSize   = $R.ReadUInt32()
    $tableSize = $R.ReadUInt32()
    $table = [System.Collections.Generic.List[PSCustomObject]]::new($tableSize)
    for ($j = 0; $j -lt $tableSize; $j++) {
        $aIdx = $R.ReadUInt32()
        $aOff = $R.ReadInt32()   # signed - can be negative
        $table.Add([PSCustomObject]@{ Index = $aIdx; Offset = $aOff })
    }
    return ,@($objSize, $table.ToArray())
}

# ============================================================================
#  SECURITY DESCRIPTOR ANALYSIS
# ============================================================================

function Get-DangerousAces {
    param(
        [byte[]]$SDBytes,
        [string]$DomainSID
    )

    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }

    try {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes, 0)
    } catch { return ,@() }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check owner
    if ($sd.Owner) {
        $ownerStr = $sd.Owner.Value
        if (-not (Test-PrivilegedSID $ownerStr $DomainSID)) {
            $ownerName = Resolve-SIDName $ownerStr $DomainSID
            $results.Add([PSCustomObject]@{
                Principal = $ownerName; SID = $ownerStr; Right = 'Owner'; Inherited = $false
            })
        }
    }

    if (-not $sd.DiscretionaryAcl) { return ,$results.ToArray() }

    foreach ($ace in $sd.DiscretionaryAcl) {
        # Only check AccessAllowed ACEs
        if ($ace.AceType -notin @(
            [System.Security.AccessControl.AceType]::AccessAllowed,
            [System.Security.AccessControl.AceType]::AccessAllowedObject
        )) { continue }

        $sid = $ace.SecurityIdentifier.Value
        if (Test-PrivilegedSID $sid $DomainSID) { continue }

        $mask = $ace.AccessMask
        $principalName = Resolve-SIDName $sid $DomainSID
        $inherited = $ace.IsInherited

        # Check for dangerous broad rights
        if ($mask -band $ADS_RIGHT_GENERIC_ALL) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='GenericAll'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_GENERIC_WRITE) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='GenericWrite'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_WRITE_DAC) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteDacl'; Inherited=$inherited })
        }
        if ($mask -band $ADS_RIGHT_WRITE_OWNER) {
            $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteOwner'; Inherited=$inherited })
        }
        if (($mask -band $ADS_RIGHT_DS_WRITE_PROP) -and -not ($mask -band $DANGEROUS_MASK)) {
            # WriteProperty without broader rights - check if it's unrestricted (no objectType)
            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                $objFlags = $ace.ObjectAceFlags
                if (-not ($objFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
                    $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteAllProperties'; Inherited=$inherited })
                }
            } else {
                $results.Add([PSCustomObject]@{ Principal=$principalName; SID=$sid; Right='WriteAllProperties'; Inherited=$inherited })
            }
        }
    }

    return ,$results.ToArray()
}

function Get-EnrollmentPrincipals {
    param([byte[]]$SDBytes, [string]$DomainSID)
    if (-not $SDBytes -or $SDBytes.Length -lt 20) { return ,@() }
    try { $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDBytes, 0) } catch { return ,@() }

    $results = [System.Collections.Generic.List[string]]::new()
    if (-not $sd.DiscretionaryAcl) { return ,$results.ToArray() }

    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowedObject) { continue }
        $mask = $ace.AccessMask
        if (-not ($mask -band $ADS_RIGHT_DS_CONTROL_ACCESS)) { continue }
        if ($ace -is [System.Security.AccessControl.ObjectAce]) {
            $objType = $ace.ObjectAceType.ToString().ToLower()
            if ($objType -eq $ENROLL_GUID -or $objType -eq $AUTOENROLL_GUID) {
                $sid = $ace.SecurityIdentifier.Value
                $results.Add("$(Resolve-SIDName $sid $DomainSID) ($sid)")
            }
        }
    }
    # Also check for GenericAll / ControlAccess without objectType (implies all extended rights)
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { continue }
        $mask = $ace.AccessMask
        if ($mask -band ($ADS_RIGHT_GENERIC_ALL -bor $ADS_RIGHT_DS_CONTROL_ACCESS)) {
            $sid = $ace.SecurityIdentifier.Value
            $entry = "$(Resolve-SIDName $sid $DomainSID) ($sid)"
            if ($entry -notin $results) { $results.Add($entry) }
        }
    }
    return ,$results.ToArray()
}

function Test-PrivilegedSID {
    param([string]$SID, [string]$DomainSID)
    if ($SID -in $PRIVILEGED_SIDS) { return $true }
    if ($DomainSID) {
        foreach ($suffix in $PRIVILEGED_RID_SUFFIXES) {
            if ($SID -eq "$DomainSID$suffix") { return $true }
        }
    }
    return $false
}

function Resolve-SIDName {
    param([string]$SID, [string]$DomainSID)
    if ($WELLKNOWN_SIDS.ContainsKey($SID)) { return $WELLKNOWN_SIDS[$SID] }
    if ($DomainSID) {
        if ($SID -eq "$DomainSID-513") { return 'Domain Users' }
        if ($SID -eq "$DomainSID-515") { return 'Domain Computers' }
        if ($SID -eq "$DomainSID-512") { return 'Domain Admins' }
        if ($SID -eq "$DomainSID-519") { return 'Enterprise Admins' }
        if ($SID -eq "$DomainSID-518") { return 'Schema Admins' }
        if ($SID -eq "$DomainSID-516") { return 'Domain Controllers' }
    }
    return $SID
}

# ============================================================================
#  FILETIME INTERVAL TO STRING
# ============================================================================

function ConvertTo-DurationString {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 8) { return 'Unknown' }
    $ticks = [BitConverter]::ToInt64($Bytes, 0)
    if ($ticks -eq 0) { return 'Unknown' }
    $span = [TimeSpan]::FromTicks([Math]::Abs($ticks))
    if ($span.TotalDays -ge 365) { return "$([Math]::Round($span.TotalDays / 365, 1)) years" }
    if ($span.TotalDays -ge 1)   { return "$([int]$span.TotalDays) days" }
    if ($span.TotalHours -ge 1)  { return "$([int]$span.TotalHours) hours" }
    return "$([int]$span.TotalMinutes) minutes"
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

# -- Validate input --------------------------------------------------------
if (-not (Test-Path $SnapshotPath)) {
    Write-Host "  [-] File not found: $SnapshotPath" -ForegroundColor Red
    return
}
$SnapshotPath = (Resolve-Path $SnapshotPath).Path

Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host "  |  AD CS LOLBAS - Snapshot Audit                               |" -ForegroundColor DarkCyan
Write-Host "  |  Parse ADExplorer snapshots for vulnerable AD CS templates   |" -ForegroundColor DarkCyan
Write-Host "  +==============================================================+" -ForegroundColor DarkCyan
Write-Host ""
$script:ReportLines.Add("AD CS Snapshot Audit Report")
$script:ReportLines.Add("=" * 60)

# -- Open file -------------------------------------------------------------
$stream = [System.IO.FileStream]::new($SnapshotPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
$reader = [System.IO.BinaryReader]::new($stream)

try {

# -- STAGE 1: Parse Header ------------------------------------------------
Out-Line "  >>> STAGE 1 - PARSING SNAPSHOT HEADER" 'Cyan'

$reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
$winAdSig    = $reader.ReadBytes(10)
$marker      = $reader.ReadInt32()
$filetime    = $reader.ReadUInt64()
$description = Read-FixedWchar $reader 260
$server      = Read-FixedWchar $reader 260
$numObjects  = $reader.ReadUInt32()
$numAttribs  = $reader.ReadUInt32()
$metadataOff = $reader.ReadUInt64()
$treeviewOff = $reader.ReadUInt64()

# Convert FILETIME to DateTime
$snapshotTime = [datetime]::FromFileTimeUtc($filetime)

Out-Line "    [i] File    : $(Split-Path $SnapshotPath -Leaf)" 'Gray'
Out-Line "    [i] Server  : $server" 'Gray'
Out-Line "    [i] Captured: $($snapshotTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC" 'Gray'
Out-Line "    [i] Objects : $($numObjects.ToString('N0'))  |  Attributes: $($numAttribs.ToString('N0'))" 'Gray'
if ($description) { Out-Line "    [i] Desc    : $description" 'Gray' }
Out-Line ""

# -- STAGE 2: Parse Property Definitions ----------------------------------
Out-Line "  >>> STAGE 2 - PARSING PROPERTY DEFINITIONS" 'Cyan'

$reader.BaseStream.Seek($metadataOff, [System.IO.SeekOrigin]::Begin) | Out-Null
$numProperties = $reader.ReadUInt32()
$properties    = [object[]]::new($numProperties)
$propertyDict  = @{}   # PowerShell hashtables are case-insensitive by default

for ($i = 0; $i -lt $numProperties; $i++) {
    $lenPN = $reader.ReadUInt32()
    $pName = (Read-FixedWchar $reader ($lenPN / 2)).TrimEnd([char]0)
    $unk1  = $reader.ReadInt32()
    $adsTy = $reader.ReadUInt32()
    $lenDN = $reader.ReadUInt32()
    $pDN   = (Read-FixedWchar $reader ($lenDN / 2)).TrimEnd([char]0)
    $null  = $reader.ReadBytes(16)  # schemaIDGUID
    $null  = $reader.ReadBytes(16)  # attributeSecurityGUID
    $null  = $reader.ReadBytes(4)   # blob

    $properties[$i] = @{ Name = $pName; AdsType = $adsTy; DN = $pDN }
    $propertyDict[$pName] = $i
    if ($pDN) {
        $propertyDict[$pDN] = $i
        if ($pDN -match '^CN=([^,]+)') { $propertyDict[$Matches[1]] = $i }
    }
}
Out-Line "    [i] Parsed $numProperties property definitions" 'Gray'

# Verify required properties exist
$requiredProps = @('objectClass','name','certificateTemplates')
foreach ($rp in $requiredProps) {
    if ($null -eq $propertyDict[$rp]) {
        Out-Line "    [-] Required property '$rp' not found in snapshot schema" 'Red'
        return
    }
}
Out-Line ""

# -- STAGE 3: Index Object Offsets ----------------------------------------
Out-Line "  >>> STAGE 3 - INDEXING OBJECTS" 'Cyan'

$reader.BaseStream.Seek($OBJECTS_OFFSET, [System.IO.SeekOrigin]::Begin) | Out-Null
$objectOffsets = [System.Collections.Generic.List[long]]::new($numObjects)
for ($i = 0; $i -lt $numObjects; $i++) {
    $pos = $reader.BaseStream.Position
    $objSz = $reader.ReadUInt32()
    $objectOffsets.Add($pos)
    $reader.BaseStream.Seek($pos + $objSz, [System.IO.SeekOrigin]::Begin) | Out-Null
}
Out-Line "    [i] Indexed $($objectOffsets.Count.ToString('N0')) objects" 'Gray'
Out-Line ""

# -- STAGE 4: Discover CAs, Templates, Domain SID -------------------------
Out-Line "  >>> STAGE 4 - DISCOVERING AD CS OBJECTS" 'Cyan'

$caTemplateMap    = @{}          # CA name -> [list of template names]
$certTemplateObjs = [System.Collections.Generic.List[hashtable]]::new()
$domainSID        = $null
$dnToSam          = @{}          # distinguishedName -> sAMAccountName
$highValueGroups  = [ordered]@{} # group sAMAccountName -> @{ SID; Members }
$HIGH_VALUE_RIDS  = @('-512','-518','-519','-498') # DA, SA, EA, Enterprise RO DCs
$HIGH_VALUE_BUILTIN = @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-551') # Admins, AcctOps, SvrOps, BackupOps
$progressInterval = [Math]::Max(1, [Math]::Floor($numObjects / 40))

# Common attribute getter params
$gaCommon = @{
    R            = $reader
    PropertyDict = $propertyDict
    Properties   = $properties
}

for ($i = 0; $i -lt $numObjects; $i++) {
    if ($i % $progressInterval -eq 0) {
        $pct = [Math]::Round(($i / $numObjects) * 100)
        Write-Host "`r    [i] Scanning objects... $pct%   " -NoNewline -ForegroundColor Gray
    }

    $objOffset = $objectOffsets[$i]

    try {
        $sizeAndTable = Read-ObjectMappingTable $reader $objOffset
        $objSize = $sizeAndTable[0]
        $mappingTable = $sizeAndTable[1]

        # Get objectClass
        $objClasses = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'objectClass'
        if (-not $objClasses) { continue }
        $classesArr = @($objClasses)
        $classesLower = @($classesArr | ForEach-Object { "$_".ToLower() })

        # --- pKIEnrollmentService (Certificate Authority) ---
        if ('pkienrollmentservice' -in $classesLower) {
            $caName = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'name'
            $caTpls = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'certificateTemplates'
            if ($caName) {
                $caNameStr = @($caName)[0]
                $caTemplateMap[$caNameStr] = @()
                if ($caTpls) { $caTemplateMap[$caNameStr] = @($caTpls) }
            }
        }

        # --- pKICertificateTemplate ---
        if ('pkicertificatetemplate' -in $classesLower) {
            $tplName    = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'name'
            $tplCN      = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'cn'
            $tplDisplay = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'displayName'
            $tplDN      = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'distinguishedName'
            $nameFlag   = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'msPKI-Certificate-Name-Flag'
            $enrollFlag = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'msPKI-Enrollment-Flag'
            $raSig      = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'msPKI-RA-Signature'
            $ekus       = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'pKIExtendedKeyUsage'
            $schemaVer  = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'msPKI-Template-Schema-Version'
            $certPolicy = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'msPKI-Certificate-Policy'
            $sdBytes    = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'nTSecurityDescriptor'
            $validity   = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'pKIExpirationPeriod' -Raw
            $renewal    = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'pKIOverlapPeriod' -Raw

            $certTemplateObjs.Add(@{
                Name          = if ($tplName)    { @($tplName)[0] }    else { '' }
                CN            = if ($tplCN)      { @($tplCN)[0] }      else { '' }
                DisplayName   = if ($tplDisplay) { @($tplDisplay)[0] } else { '' }
                DN            = if ($tplDN)      { @($tplDN)[0] }      else { '' }
                NameFlag      = if ($nameFlag)   { [uint32]@($nameFlag)[0] }   else { 0 }
                EnrollFlag    = if ($enrollFlag) { [uint32]@($enrollFlag)[0] } else { 0 }
                RASignature   = if ($raSig)      { [int]@($raSig)[0] }        else { 0 }
                EKUs          = @(if ($ekus) { $ekus } else { })
                SchemaVersion = if ($schemaVer)  { [int]@($schemaVer)[0] }    else { 0 }
                CertPolicy    = @(if ($certPolicy) { $certPolicy } else { })
                SDBytes       = if ($sdBytes)    { @($sdBytes)[0] } else { $null }
                ValidityPeriod = if ($validity) { @($validity)[0] } else { $null }
                RenewalPeriod  = if ($renewal)  { @($renewal)[0] }  else { $null }
            })
        }

        # --- Domain object (for domain SID) ---
        if ('domain' -in $classesLower -and -not $domainSID) {
            $objSidVals = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'objectSid'
            if ($objSidVals -and @($objSidVals)[0] -is [string]) {
                $domainSID = @($objSidVals)[0]
            }
        }

        # --- High-value target enumeration ---
        # Build DN -> sAMAccountName map for principal resolution
        $sam = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'sAMAccountName'
        if ($sam) {
            $samStr = @($sam)[0]
            $objDN = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'distinguishedName'
            if ($objDN) { $dnToSam[@($objDN)[0]] = $samStr }
        }

        # High-value group detection
        if ('group' -in $classesLower) {
            $grpSid = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'objectSid'
            if ($grpSid -and @($grpSid)[0] -is [string]) {
                $sidStr = @($grpSid)[0]
                $isHV = $sidStr -in $HIGH_VALUE_BUILTIN
                if (-not $isHV) {
                    foreach ($rid in $HIGH_VALUE_RIDS) {
                        if ($sidStr.EndsWith($rid)) { $isHV = $true; break }
                    }
                }
                if ($isHV) {
                    $grpNameStr = if ($sam) { $samStr } else { 'Unknown' }
                    $members = Get-ObjectAttribute @gaCommon -ObjFileOffset $objOffset -MappingTable $mappingTable -AttrName 'member'
                    $highValueGroups[$grpNameStr] = @{
                        SID     = $sidStr
                        Members = if ($members) { @($members) } else { @() }
                    }
                }
            }
        }
    } catch {
        # Skip objects that fail to parse (corrupted data, unusual attribute types, etc.)
        continue
    }
}
Write-Host "`r    [i] Scanning objects... 100%   " -ForegroundColor Gray

# Build reverse map: template name -> list of CAs
$templateToCA = @{}
foreach ($ca in $caTemplateMap.Keys) {
    foreach ($tpl in $caTemplateMap[$ca]) {
        if (-not $templateToCA.ContainsKey($tpl)) { $templateToCA[$tpl] = @() }
        $templateToCA[$tpl] += $ca
    }
}

$enabledCount = @($certTemplateObjs | Where-Object { $templateToCA.ContainsKey($_.Name) }).Count

Out-Line "    [i] Certificate Authorities : $($caTemplateMap.Count)" 'Green'
foreach ($ca in $caTemplateMap.Keys) {
    Out-Line "        - $ca ($($caTemplateMap[$ca].Count) published templates)" 'Gray'
}
Out-Line "    [i] Certificate Templates   : $($certTemplateObjs.Count) total ($enabledCount enabled)" 'Green'
if ($domainSID) { Out-Line "    [i] Domain SID              : $domainSID" 'Gray' }
Out-Line ""

# Resolve high-value target groups
$resolvedGroups = [ordered]@{}
$defaultTarget  = if ($Target) { $Target } else { 'TARGET_USER' }

if ($highValueGroups.Count -gt 0) {
    Out-Line "    [i] High-Value Groups       : $($highValueGroups.Count) found" 'Green'

    # Resolve member DNs to sAMAccountNames
    foreach ($grpName in $highValueGroups.Keys) {
        $grp = $highValueGroups[$grpName]
        $resolved = [System.Collections.Generic.List[string]]::new()
        foreach ($memberDN in $grp.Members) {
            if ($dnToSam.ContainsKey($memberDN)) {
                $resolved.Add($dnToSam[$memberDN])
            } elseif ($memberDN -match '^CN=([^,]+)') {
                $resolved.Add($Matches[1])
            } else {
                $resolved.Add($memberDN)
            }
        }
        $resolvedGroups[$grpName] = @{
            SID     = $grp.SID
            Members = @($resolved | Sort-Object)
        }
    }

    # Display high-value groups
    Out-Line "    High-Value Group Membership:" 'Yellow'
    foreach ($grpName in $resolvedGroups.Keys) {
        $grp = $resolvedGroups[$grpName]
        $memberCount = $grp.Members.Count
        $userMembers = @($grp.Members | Where-Object { $_ -notmatch '\$$' })
        Out-Line "      $grpName ($($grp.SID)) - $memberCount members ($($userMembers.Count) users):" 'Yellow'
        foreach ($m in $grp.Members) {
            $mColor = if ($m -match '\$$') { 'DarkGray' } else { 'Gray' }
            Out-Line "        - $m" $mColor
        }
    }
    Out-Line ""

    # Pick default target: first non-computer Domain Admin (only if -Target not specified)
    if (-not $Target) {
        foreach ($grpName in $resolvedGroups.Keys) {
            $grp = $resolvedGroups[$grpName]
            if ($grp.SID -match '-512$') {
                $userMembers = @($grp.Members | Where-Object { $_ -notmatch '\$$' })
                if ($userMembers.Count -gt 0) { $defaultTarget = $userMembers[0]; break }
                if ($grp.Members.Count -gt 0) { $defaultTarget = $grp.Members[0]; break }
            }
        }
    }
}

# -- STAGE 5: Vulnerability Analysis --------------------------------------
Out-Line "  >>> STAGE 5 - VULNERABILITY ANALYSIS" 'Cyan'
Out-Line ""

$totalFindings = 0
$findingsSummary = [System.Collections.Generic.List[string]]::new()
$csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($tpl in $certTemplateObjs | Sort-Object { $_.Name }) {
    $name        = $tpl.Name
    $enabled     = $templateToCA.ContainsKey($name)
    $caList      = if ($enabled) { $templateToCA[$name] -join ', ' } else { '(none)' }

    # Decode flags
    $suppliesSAN = ($tpl.NameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
    $noApproval  = ($tpl.EnrollFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -eq 0
    $noSecExt    = ($tpl.EnrollFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) -ne 0
    $noSignature = ($tpl.RASignature -eq 0)

    # Resolve EKUs
    $ekuList = @($tpl.EKUs)
    $ekuStrings = @($ekuList | ForEach-Object { if ($OID_MAP.ContainsKey($_)) { $OID_MAP[$_] } else { $_ } })

    $hasAuthEKU   = ($ekuList.Count -eq 0) -or ($ekuList | Where-Object { $_ -in $AUTH_EKUS })
    $hasAnyOrNone = ($ekuList.Count -eq 0) -or ($ekuList -contains '2.5.29.37.0')
    $hasAgentEKU  = ($ekuList -contains $AGENT_EKU)

    # Vulnerability checks
    $findings = [System.Collections.Generic.List[string]]::new()

    # ESC1: Enrollee supplies subject + auth EKU + no approval + no signature
    if ($suppliesSAN -and $hasAuthEKU -and $noApproval -and $noSignature) {
        $findings.Add('ESC1: ENROLLEE_SUPPLIES_SUBJECT + Auth EKU + No Approval')
    }
    # ESC2: Any Purpose or no EKU + no approval + no signature
    if ($hasAnyOrNone -and $noApproval -and $noSignature) {
        $findings.Add('ESC2: Any Purpose / No EKU restriction')
    }
    # ESC3: Certificate Request Agent EKU + no approval + no signature
    if ($hasAgentEKU -and $noApproval -and $noSignature) {
        $findings.Add('ESC3: Certificate Request Agent EKU')
    }
    # ESC9: No security extension + auth EKU
    if ($noSecExt -and $hasAuthEKU) {
        $findings.Add('ESC9: CT_FLAG_NO_SECURITY_EXTENSION + Auth EKU')
    }

    # ESC4: Dangerous ACLs on template
    $dangerousAces = @()
    if ($tpl.SDBytes) {
        try {
            $dangerousAces = Get-DangerousAces -SDBytes $tpl.SDBytes -DomainSID $domainSID
        } catch { $dangerousAces = @() }
        if ($dangerousAces.Count -gt 0) {
            foreach ($dAce in $dangerousAces) {
                $findings.Add("ESC4: $($dAce.Principal) has $($dAce.Right)")
            }
        }
    }

    # ESC13: Certificate policy OID (basic check - flag if OID present)
    $certPolicyList = @($tpl.CertPolicy)
    if ($certPolicyList.Count -gt 0) {
        $findings.Add("ESC13: Has issuance policy OID ($($certPolicyList -join ', ')) - verify OID group link")
    }

    # Collect structured row for CSV (always — before VulnerableOnly filter)
    $escTags = @($findings | ForEach-Object { ($_ -split ':')[0] }) | Select-Object -Unique
    $csvRows.Add([PSCustomObject]@{
        Template            = $name
        DisplayName         = $tpl.DisplayName
        Enabled             = $enabled
        CA                  = $caList
        SuppliesSubject     = $suppliesSAN
        RequiresApproval    = -not $noApproval
        RASignatures        = $tpl.RASignature
        NoSecurityExtension = $noSecExt
        EKUs                = ($ekuStrings -join '; ')
        SchemaVersion       = $tpl.SchemaVersion
        Vulnerable          = ($findings.Count -gt 0)
        ESCs                = ($escTags -join ', ')
        Findings            = ($findings -join '; ')
    })

    if ($VulnerableOnly -and $findings.Count -eq 0) { continue }

    $totalFindings += $findings.Count

    # -- Output template details --
    $enabledStr = if ($enabled) { "True (CA: $caList)" } else { "False" }
    $enabledColor = if ($enabled) { 'Green' } else { 'DarkGray' }

    Out-Line "    +---------------------------------------------------------+"  'DarkCyan'
    Out-Line "    | Template: $($name.PadRight(46))  |" 'DarkCyan'
    Out-Line "    +---------------------------------------------------------+"  'DarkCyan'
    Out-Line "      Display Name           : $($tpl.DisplayName)" 'White'
    Out-Line "      Enabled                : $enabledStr" $enabledColor
    Out-Line "      Schema Version         : $($tpl.SchemaVersion)" 'White'

    # Validity/Renewal periods
    $validStr  = if ($tpl.ValidityPeriod) { ConvertTo-DurationString $tpl.ValidityPeriod } else { 'N/A' }
    $renewStr  = if ($tpl.RenewalPeriod)  { ConvertTo-DurationString $tpl.RenewalPeriod }  else { 'N/A' }
    Out-Line "      Validity Period        : $validStr" 'White'
    Out-Line "      Renewal Period         : $renewStr" 'White'

    # Flags
    $sanColor = if ($suppliesSAN) { 'Red' } else { 'White' }
    Out-Line "      Enrollee Supplies Subj : $suppliesSAN" $sanColor

    $approvalColor = if ($noApproval) { 'Yellow' } else { 'Green' }
    $approvalStr   = if ($noApproval) { 'False (no approval needed)' } else { 'True' }
    Out-Line "      Requires Approval      : $approvalStr" $approvalColor

    Out-Line "      RA Signatures Required : $($tpl.RASignature)" 'White'

    $secExtColor = if ($noSecExt) { 'Red' } else { 'White' }
    Out-Line "      No Security Extension  : $noSecExt" $secExtColor

    # EKU display
    if ($ekuStrings.Count -eq 0) {
        Out-Line "      Extended Key Usage     : (none - any purpose)" 'Yellow'
    } else {
        Out-Line "      Extended Key Usage     :" 'White'
        foreach ($eku in $ekuStrings) { Out-Line "        - $eku" 'White' }
    }

    # Enrollment flags decoded
    $enrollFlagNames = @()
    if ($tpl.EnrollFlag -band 0x00000001) { $enrollFlagNames += 'INCLUDE_SYMMETRIC_ALGORITHMS' }
    if ($tpl.EnrollFlag -band 0x00000002) { $enrollFlagNames += 'PEND_ALL_REQUESTS' }
    if ($tpl.EnrollFlag -band 0x00000004) { $enrollFlagNames += 'PUBLISH_TO_KRA_CONTAINER' }
    if ($tpl.EnrollFlag -band 0x00000008) { $enrollFlagNames += 'PUBLISH_TO_DS' }
    if ($tpl.EnrollFlag -band 0x00000010) { $enrollFlagNames += 'AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE' }
    if ($tpl.EnrollFlag -band 0x00000020) { $enrollFlagNames += 'AUTO_ENROLLMENT' }
    if ($tpl.EnrollFlag -band 0x00000100) { $enrollFlagNames += 'PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT' }
    if ($tpl.EnrollFlag -band 0x00080000) { $enrollFlagNames += 'NO_SECURITY_EXTENSION' }
    if ($enrollFlagNames.Count -gt 0) {
        Out-Line "      Enrollment Flags       : $($enrollFlagNames -join ', ')" 'Gray'
    }

    # Name flags decoded
    $nameFlagNames = @()
    if ($tpl.NameFlag -band 0x00000001) { $nameFlagNames += 'ENROLLEE_SUPPLIES_SUBJECT' }
    if ($tpl.NameFlag -band 0x00010000) { $nameFlagNames += 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME' }
    if ($tpl.NameFlag -band 0x00400000) { $nameFlagNames += 'SUBJECT_ALT_REQUIRE_UPN' }
    if ($tpl.NameFlag -band 0x01000000) { $nameFlagNames += 'SUBJECT_ALT_REQUIRE_EMAIL' }
    if ($tpl.NameFlag -band 0x04000000) { $nameFlagNames += 'SUBJECT_ALT_REQUIRE_DNS' }
    if ($tpl.NameFlag -band 0x08000000) { $nameFlagNames += 'SUBJECT_REQUIRE_DNS_AS_CN' }
    if ($tpl.NameFlag -band 0x10000000) { $nameFlagNames += 'SUBJECT_REQUIRE_EMAIL' }
    if ($tpl.NameFlag -band 0x20000000) { $nameFlagNames += 'SUBJECT_REQUIRE_COMMON_NAME' }
    if ($tpl.NameFlag -band 0x40000000) { $nameFlagNames += 'SUBJECT_REQUIRE_DIRECTORY_PATH' }
    if ($nameFlagNames.Count -gt 0) {
        Out-Line "      Certificate Name Flags : $($nameFlagNames -join ', ')" 'Gray'
    }

    # Enrollment principals
    $enrollPrincipals = @()
    if ($tpl.SDBytes) {
        try {
            $enrollPrincipals = Get-EnrollmentPrincipals -SDBytes $tpl.SDBytes -DomainSID $domainSID
        } catch { $enrollPrincipals = @() }
        if ($enrollPrincipals.Count -gt 0) {
            Out-Line "      Enrollment Principals  :" 'White'
            foreach ($ep in $enrollPrincipals) { Out-Line "        - $ep" 'Gray' }
        }
    }

    # Findings
    if ($findings.Count -gt 0) {
        Out-Line "" 'White'
        Out-Line "      VULNERABILITIES:" 'Red'
        foreach ($f in $findings) {
            $escTag = ($f -split ':')[0]
            Out-Line "        [!] $f" 'Red'
            $findingsSummary.Add("$escTag - $name")
        }
    } else {
        Out-Line "      Status: No ESC vulnerabilities detected" 'Green'
    }
    Out-Line "" 'White'
}

# -- SUMMARY ---------------------------------------------------------------
Out-Line "  +==============================================================+" 'DarkCyan'
Out-Line "  |  SUMMARY                                                     |" 'DarkCyan'
Out-Line "  +==============================================================+" 'DarkCyan'
Out-Line ""
Out-Line "    Snapshot       : $(Split-Path $SnapshotPath -Leaf)" 'White'
Out-Line "    Server         : $server" 'White'
Out-Line "    Captured       : $($snapshotTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC" 'White'
Out-Line "    CAs            : $($caTemplateMap.Count)" 'White'
Out-Line "    Templates      : $($certTemplateObjs.Count) total / $enabledCount enabled" 'White'
Out-Line "    Findings       : $totalFindings" $(if ($totalFindings -gt 0) { 'Red' } else { 'Green' })
Out-Line ""

if ($findingsSummary.Count -gt 0) {
    Out-Line "    Findings Detail:" 'Yellow'
    foreach ($f in $findingsSummary) {
        Out-Line "      [!] $f" 'Red'
    }
    Out-Line ""
}

# Group findings by ESC type
if ($findingsSummary.Count -gt 0) {
    $grouped = $findingsSummary | Group-Object { ($_ -split ' - ')[0] }
    Out-Line "    Findings by Type:" 'Yellow'
    foreach ($g in $grouped | Sort-Object Name) {
        Out-Line "      $($g.Name): $($g.Count) template(s)" 'Yellow'
    }
    Out-Line ""
}

Out-Line "    Checks performed from snapshot (offline):" 'Gray'
Out-Line "      ESC1  : Enrollee Supplies Subject + Auth EKU + No Approval" 'Gray'
Out-Line "      ESC2  : Any Purpose / No EKU + No Approval" 'Gray'
Out-Line "      ESC3  : Certificate Request Agent EKU + No Approval" 'Gray'
Out-Line "      ESC4  : Dangerous ACLs on certificate templates" 'Gray'
Out-Line "      ESC9  : CT_FLAG_NO_SECURITY_EXTENSION + Auth EKU" 'Gray'
Out-Line "      ESC13 : Certificate issuance policy OID (requires manual OID group link verification)" 'Gray'
Out-Line ""
Out-Line "    Not checked (require live access):" 'DarkGray'
Out-Line "      ESC6/7/11 : CA EditFlags/InterfaceFlags (use Invoke-Enumerate.ps1 live)" 'DarkGray'
Out-Line "      ESC8      : HTTP enrollment endpoints" 'DarkGray'
Out-Line "      ESC10     : StrongCertificateBindingEnforcement registry" 'DarkGray'
Out-Line "      ESC12     : YubiHSM key storage" 'DarkGray'
Out-Line ""

# -- Exploitation Commands -------------------------------------------------
if ($findingsSummary.Count -gt 0) {
    # Derive domain from server FQDN (e.g. POLARIS.zsec.red -> zsec.red)
    $domainDNS = if ($server -match '\.(.+)$') { $Matches[1] } else { 'DOMAIN' }
    $caName    = @($caTemplateMap.Keys)[0]
    $caTarget  = "$caName.$domainDNS"

    # --- Interactive target picker (-List) ---
    if ($List -and $resolvedGroups.Count -gt 0) {
        # Build flat numbered list of all HVT user accounts
        $hvtUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($grpName in $resolvedGroups.Keys) {
            $grp = $resolvedGroups[$grpName]
            foreach ($m in $grp.Members) {
                if ($m -notmatch '\$$' -and -not ($hvtUsers | Where-Object { $_.Name -eq $m })) {
                    $groups = @($resolvedGroups.Keys | Where-Object { $m -in $resolvedGroups[$_].Members })
                    $hvtUsers.Add([PSCustomObject]@{ Name = $m; Groups = $groups -join ', ' })
                }
            }
        }

        if ($hvtUsers.Count -gt 0) {
            Out-Line "  +==============================================================+" 'DarkCyan'
            Out-Line "  |  SELECT TARGET                                               |" 'DarkCyan'
            Out-Line "  +==============================================================+" 'DarkCyan'
            Out-Line ""
            for ($i = 0; $i -lt $hvtUsers.Count; $i++) {
                $u = $hvtUsers[$i]
                Out-Line "    [$($i + 1)] $($u.Name)  ($($u.Groups))" 'White'
            }
            Out-Line ""
            $selection = Read-Host "    Select target [1-$($hvtUsers.Count), or username]"
            $selection = $selection.Trim()

            if ($selection -match '^\d+$') {
                $idx = [int]$selection - 1
                if ($idx -ge 0 -and $idx -lt $hvtUsers.Count) {
                    $defaultTarget = $hvtUsers[$idx].Name
                } else {
                    Write-Host "    [!] Invalid selection, using default: $defaultTarget" -ForegroundColor Red
                }
            } elseif ($selection.Length -gt 0) {
                $defaultTarget = $selection
            }
            Out-Line ""
            Out-Line "    Selected target: $defaultTarget" 'Green'
            Out-Line ""
        }
    }

    Out-Line "  +==============================================================+" 'DarkCyan'
    Out-Line "  |  SUGGESTED COMMANDS                                          |" 'DarkCyan'
    Out-Line "  +==============================================================+" 'DarkCyan'
    Out-Line ""
    Out-Line "    Replace USER / PASS with your compromised credentials." 'Gray'
    Out-Line "    CA      : $caName" 'Gray'
    Out-Line "    DC      : $server" 'Gray'
    Out-Line "    Domain  : $domainDNS" 'Gray'
    $targetSrc = if ($Target) { "(user-specified)" } elseif ($defaultTarget -ne 'TARGET_USER') { "(Domain Admin)" } else { "(use -Target to set)" }
    if ($List) { $targetSrc = "(selected)" }
    Out-Line "    Target  : $defaultTarget $targetSrc" 'Yellow'
    Out-Line ""

    # List all high-value targets for reference
    if (-not $List -and $resolvedGroups.Count -gt 0) {
        Out-Line "    High-Value Targets (use -Target <user> or -List to pick interactively):" 'Yellow'
        foreach ($grpName in $resolvedGroups.Keys) {
            $grp = $resolvedGroups[$grpName]
            $userMembers = @($grp.Members | Where-Object { $_ -notmatch '\$$' })
            if ($userMembers.Count -gt 0) {
                Out-Line "      $grpName :" 'Gray'
                foreach ($m in $userMembers) {
                    $marker = if ($m -eq $defaultTarget) { ' <-- current target' } else { '' }
                    Out-Line "        - $m$marker" 'White'
                }
            }
        }
        Out-Line ""
    }

    # Build CAConfig string (hostname\CAName) matching Invoke-ESC* parameter format
    $caConfig = "$server\$caName"
    $targetUPN = "$defaultTarget@$domainDNS"

    # Build per-template commands grouped by ESC type
    $vulnTemplates = @($csvRows | Where-Object { $_.Vulnerable })
    $seen = @{}
    foreach ($row in $vulnTemplates) {
        $tName = $row.Template
        $escs  = @($row.ESCs -split ',\s*')

        Out-Line "    --- $tName ---" 'Yellow'

        foreach ($esc in $escs) {
            $key = "$esc|$tName"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            switch ($esc) {
                'ESC1' {
                    Out-Line "      # $esc - Enrollee Supplies Subject (impersonate $defaultTarget)" 'DarkGray'
                    Out-Line "      .\Invoke-ESC1.ps1 -CAConfig `"$caConfig`" -TemplateName `"$tName`" -TargetUPN `"$targetUPN`"" 'White'
                    Out-Line ""
                }
                'ESC2' {
                    Out-Line "      # $esc - Any Purpose / No EKU" 'DarkGray'
                    Out-Line "      .\Invoke-ESC2.ps1 -CAConfig `"$caConfig`" -TemplateName `"$tName`"" 'White'
                    Out-Line ""
                }
                'ESC3' {
                    Out-Line "      # $esc - Enrollment Agent (enroll on behalf of $defaultTarget)" 'DarkGray'
                    Out-Line "      .\Invoke-ESC3.ps1 -CAConfig `"$caConfig`" -AgentTemplate `"$tName`" -TargetTemplate `"User`" -TargetUPN `"$targetUPN`"" 'White'
                    Out-Line ""
                }
                'ESC4' {
                    Out-Line "      # $esc - Template ACL Abuse -> ESC1 Chain (impersonate $defaultTarget)" 'DarkGray'
                    Out-Line "      .\Invoke-ESC4.ps1 -CAConfig `"$caConfig`" -TemplateName `"$tName`" -TargetUPN `"$targetUPN`"" 'White'
                    Out-Line ""
                }
                'ESC9' {
                    Out-Line "      # $esc - No Security Extension + UPN Manipulation" 'DarkGray'
                    Out-Line "      .\Invoke-ESC9.ps1 -CAConfig `"$caConfig`" -TemplateName `"$tName`" -AccountToModify `"<CONTROLLED_USER>`" -TargetUPN `"$targetUPN`"" 'White'
                    Out-Line ""
                }
                'ESC13' {
                    Out-Line "      # $esc - OID Group Link" 'DarkGray'
                    Out-Line "      .\Invoke-ESC13.ps1 -CAConfig `"$caConfig`" -TemplateName `"$tName`"" 'White'
                    Out-Line ""
                }
            }
        }
    }
}

} finally {
    $reader.Close()
    $stream.Close()
}

# -- Save report if requested ----------------------------------------------
if ($OutputFile) {
    $script:ReportLines | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "  [+] Report saved to: $OutputFile" -ForegroundColor Green
}
if ($CsvFile) {
    $csvRows | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Host "  [+] CSV exported to: $CsvFile ($($csvRows.Count) templates)" -ForegroundColor Green
}
if ($OutputFile -or $CsvFile) { Write-Host "" }
