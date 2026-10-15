#requires -Version 5.1
<#
Disk Rescue release bootstrap. Execute from a trusted copy or the published GitHub URL.
The app is saved as a real file and run in a child PowerShell process; its exit command
does not close the caller's terminal. Source: https://github.com/TABURELTER/disk-rescue
#>
[CmdletBinding()]
param(
    [string]$Version='v2.1.0',
    [string]$InstallRoot=(Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'DiskRescue'),
    [switch]$NoLaunch
)
function Invoke-DiskRescueInstall {
    param([string]$RequestedVersion,[string]$Root,[bool]$SkipLaunch)
    $ErrorActionPreference='Stop'
    if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess) {throw 'Disk Rescue requires 64-bit PowerShell on Windows.'}
    $repo='TABURELTER/disk-rescue'
    function Assert-InstallPath([string]$Path) {
        $full=[IO.Path]::GetFullPath($Path)
        if($full -notmatch '^[A-Za-z]:\\' -or $full.IndexOf(':',2) -ge 0) {throw 'Use a local drive-letter installation path.'}
        $current=$full
        while($current) {
            if(Test-Path -LiteralPath $current) {
                if(((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw "Reparse points are blocked: $current"}
            }
            $parent=[IO.Directory]::GetParent($current)
            if($null -eq $parent){break}
            $current=$parent.FullName
        }
        return $full
    }
    function Receive-ReleaseFile([string]$Uri,[string]$Destination) {
        $client=[Net.Http.HttpClient]::new()
        $response=$null;$output=$null;$input=$null
        try {
            $client.DefaultRequestHeaders.UserAgent.ParseAdd('DiskRescue-Bootstrap/2.1')
            $client.Timeout=[TimeSpan]::FromMinutes(10)
            $response=$client.GetAsync($Uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $null=$response.EnsureSuccessStatusCode()
            $input=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            $input.CopyTo($output)
            $output.Flush()
        } finally {
            if($input){$input.Dispose()};if($output){$output.Dispose()};if($response){$response.Dispose()};$client.Dispose()
        }
    }
    Add-Type -AssemblyName System.Net.Http
    Add-Type -AssemblyName System.IO.Compression
    [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $root=Assert-InstallPath $Root
    if($RequestedVersion -eq 'latest') {
        $info=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{'User-Agent'='DiskRescue-Bootstrap/2.1'}
        $RequestedVersion=[string]$info.tag_name
    }
    if($RequestedVersion -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {throw 'Invalid release version. Use v2.1.0 or latest.'}
    $release="https://github.com/$repo/releases/download/$RequestedVersion"
    $null=[IO.Directory]::CreateDirectory($root)
    $stage=Join-Path $root ('.staging-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($stage)
    $sumsFile=Join-Path $stage 'SHA256SUMS.json'
    $archive=Join-Path $stage 'DiskRescue-win-x64.zip'
    $unzipped=Join-Path $stage 'app'
    Write-Host "Disk Rescue: downloading $RequestedVersion from github.com/$repo ..." -ForegroundColor Cyan
    Receive-ReleaseFile "$release/SHA256SUMS.json" $sumsFile
    $sums=[IO.File]::ReadAllText($sumsFile) | ConvertFrom-Json
    $zipHash=[string]$sums.'DiskRescue-win-x64.zip'
    $scriptHash=[string]$sums.'Recover-Disk.ps1'
    if($zipHash -notmatch '^[a-fA-F0-9]{64}$' -or $scriptHash -notmatch '^[a-fA-F0-9]{64}$') {throw 'Invalid release checksums.'}
    $versions=Join-Path $root 'versions'
    $null=[IO.Directory]::CreateDirectory($versions)
    $target=Assert-InstallPath (Join-Path $versions ($RequestedVersion+'-'+$zipHash.Substring(0,12).ToLowerInvariant()))
    $app=Join-Path $target 'Recover-Disk.ps1'
    if(Test-Path -LiteralPath $target) {
        if(!(Test-Path -LiteralPath $app -PathType Leaf) -or (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash -ne $scriptHash) {
            throw "Existing installation checksum failed. Choose another -InstallRoot. Nothing overwritten: $target"
        }
    } else {
        Receive-ReleaseFile "$release/DiskRescue-win-x64.zip" $archive
        if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $zipHash) {throw "Release ZIP checksum mismatch. File retained: $archive"}
        $null=[IO.Directory]::CreateDirectory($unzipped)
        $stream=[IO.File]::OpenRead($archive)
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read)
        $allowed=@('Recover-Disk.ps1','START.cmd','README.md','LICENSE','THIRD_PARTY_NOTICES.md','BUILD-INFO.json')
        $seen=@{}
        try {
            foreach($entry in $zip.Entries) {
                if($entry.FullName -cnotin $allowed -or $seen.ContainsKey($entry.FullName)) {throw 'Unexpected or duplicate release archive entry.'}
                if($entry.Length -gt 100MB) {throw 'Unexpectedly large release archive entry.'}
                $seen[$entry.FullName]=$true
                $input=$entry.Open();$output=[IO.File]::Open((Join-Path $unzipped $entry.FullName),[IO.FileMode]::CreateNew)
                try {$input.CopyTo($output)} finally {$input.Dispose();$output.Dispose()}
            }
        } finally {$zip.Dispose();$stream.Dispose()}
        foreach($name in $allowed){if(!$seen.ContainsKey($name)){throw "Release file missing: $name"}}
        if((Get-FileHash -LiteralPath (Join-Path $unzipped 'Recover-Disk.ps1') -Algorithm SHA256).Hash -ne $scriptHash) {throw 'Extracted program checksum mismatch.'}
        [IO.Directory]::Move($unzipped,$target)
    }
    # Only these known files were created in this unique staging directory. No recursive deletion.
    foreach($file in @($sumsFile,$archive)) {if([IO.File]::Exists($file)){[IO.File]::Delete($file)}}
    [IO.Directory]::Delete($stage,$false)
    Write-Host "Installed and checksum verified: $target" -ForegroundColor Green
    Write-Host 'For physical disk imaging, use an administrator PowerShell or run START.cmd as administrator.'
    if($SkipLaunch) {return $app}
    $hostExe=Join-Path $PSHOME 'powershell.exe'
    if(!(Test-Path -LiteralPath $hostExe)) {$hostExe=Join-Path $PSHOME 'pwsh.exe'}
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$hostExe;$start.WorkingDirectory=$target;$start.UseShellExecute=$false
    $start.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$app+'"'
    $child=[Diagnostics.Process]::Start($start)
    try {$child.WaitForExit();if($child.ExitCode -ne 0){throw ('Disk Rescue exited with code '+$child.ExitCode)}} finally {$child.Dispose()}
}
Invoke-DiskRescueInstall -RequestedVersion $Version -Root $InstallRoot -SkipLaunch $NoLaunch.IsPresent
