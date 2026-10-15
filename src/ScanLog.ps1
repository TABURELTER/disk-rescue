# DMDE's text records are input data, never PowerShell expressions.
# A scan log describes the scan; it does not contain recoverable file contents.
function Read-ScanLog([string]$Text) {
    $m = [regex]::Match($Text, '(?m)^scan_dev=([^\r\n]+)')
    if (!$m.Success) { throw 'DMDE scan_dev record is missing.' }
    $fields = $m.Groups[1].Value.Split(':', 8)
    if ($fields.Count -ne 8) { throw 'Unsupported scan_dev record.' }
    $sector = 0L
    $sectors = 0L
    if (![int64]::TryParse($fields[5],[ref]$sector) -or ![int64]::TryParse($fields[6],[ref]$sectors)) {
        throw 'Invalid disk geometry.'
    }
    if ($sector -notin @(512,4096) -or $sectors -le 0 -or $sectors -gt ([int64]::MaxValue / $sector)) {
        throw 'Invalid disk geometry.'
    }
    $bytes = [int64]($sector * $sectors)
    $range = [regex]::Match($Text, '(?m)^scan_range="0x0-0x([0-9a-fA-F]+)"')
    if (!$range.Success -or [Convert]::ToInt64($range.Groups[1].Value,16) -ne $bytes) {
        throw 'The scan range does not match the disk size.'
    }
    # USB serials can be shown when present; an absent serial is valid for analysis.
    # No serial from an untrusted log is ever used to select a disk automatically.
    $serialMatch = [regex]::Match($fields[7], '(?i)#([^#]+)&\d+#\{')
    $serial = if ($serialMatch.Success) { $serialMatch.Groups[1].Value } else { '(not provided)' }
    $types = @([regex]::Matches($Text, '(?m)^ft\[([^\]]+)\]=!?"(\d+);') | ForEach-Object {
        $count = 0L
        if (![int64]::TryParse($_.Groups[2].Value,[ref]$count)) { throw 'Invalid candidate count.' }
        [pscustomobject]@{Type=$_.Groups[1].Value; Candidates=$count}
    })
    [pscustomobject]@{
        Serial=$serial
        SectorSize=$sector
        Bytes=$bytes
        Sections=@([regex]::Matches($Text,'(?m)^\[([^\]]+)\]') | ForEach-Object {$_.Groups[1].Value})
        RawCandidates=$types
    }
}
