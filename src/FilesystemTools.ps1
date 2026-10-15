# Image-only filesystem inspection and safe tree export using The Sleuth Kit 4.15.0.
# Dot-source this file, then pass the directory containing the bundled EXEs/DLLs.
# Source metadata is untrusted. No function opens a raw Windows device.

function Initialize-RecoveryNative {
    if ('SafeFsNative.Runner' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
namespace SafeFsNative {
 public sealed class Result {
  public int ExitCode = -1;
  public bool TimedOut, Cancelled, OutputTruncated;
  public string Stdout = "", Stderr = "", IOFailure = "";
  public long FileBytes;
 }
 public static class Runner {
  static string Quote(string value) {
   StringBuilder b = new StringBuilder("\""); int n = 0;
   foreach(char c in value) {
    if(c == '\\') { n++; continue; }
    if(c == '"') { b.Append('\\', n*2+1); b.Append(c); n=0; continue; }
    b.Append('\\', n); n=0; b.Append(c);
   }
   b.Append('\\', n*2); b.Append('"'); return b.ToString();
  }
  public static bool CancelRequested() {
   try {
    if(!Console.IsInputRedirected && Console.KeyAvailable) {
     ConsoleKeyInfo k = Console.ReadKey(true);
     return k.Key == ConsoleKey.Q || k.Key == ConsoleKey.Escape;
    }
   } catch(InvalidOperationException) {} catch(IOException) {}
   return false;
  }
  static string ReadBounded(StreamReader reader, int limit, Result result, bool isStdout) {
   StringBuilder b = new StringBuilder(); char[] buffer = new char[4096]; int count;
   while((count = reader.Read(buffer,0,buffer.Length)) != 0) {
    int keep = Math.Min(count, Math.Max(0,limit-b.Length));
    if(keep>0) b.Append(buffer,0,keep);
    if(keep<count && isStdout) result.OutputTruncated=true;
   }
   return b.ToString();
  }
  public static Result Run(string executable, string[] args, string outputFile, int timeoutSeconds, bool allowCancel) {
   Result r = new Result(); Process p = new Process(); FileStream output = null;
   Task outTask = null; Task errTask = null;
   try {
    ProcessStartInfo si = new ProcessStartInfo(); si.FileName=executable;
    StringBuilder command = new StringBuilder();
    foreach(string arg in args) { if(command.Length>0) command.Append(' '); command.Append(Quote(arg)); }
    si.Arguments=command.ToString(); si.WorkingDirectory=Path.GetDirectoryName(executable);
    si.UseShellExecute=false; si.CreateNoWindow=true;
    si.RedirectStandardOutput=true; si.RedirectStandardError=true;
    si.StandardOutputEncoding=new UTF8Encoding(false); si.StandardErrorEncoding=new UTF8Encoding(false);
    if(!String.IsNullOrEmpty(outputFile)) output=new FileStream(outputFile,FileMode.CreateNew,FileAccess.Write,FileShare.Read);
    p.StartInfo=si; p.Start();
    if(output != null) {
     FileStream destination=output;
     outTask=Task.Factory.StartNew(delegate { p.StandardOutput.BaseStream.CopyTo(destination,1024*1024); });
    } else outTask=Task.Factory.StartNew(delegate { r.Stdout=ReadBounded(p.StandardOutput,4*1024*1024,r,true); });
    errTask=Task.Factory.StartNew(delegate { r.Stderr=ReadBounded(p.StandardError,65536,r,false); });
    Stopwatch clock=Stopwatch.StartNew();
    while(!p.WaitForExit(100)) {
     if(outTask.IsFaulted || errTask.IsFaulted) { try { p.Kill(); } catch {} break; }
     if(timeoutSeconds>0 && clock.Elapsed.TotalSeconds>=timeoutSeconds) { r.TimedOut=true; try {p.Kill();} catch {} break; }
     if(allowCancel && CancelRequested()) {r.Cancelled=true; try {p.Kill();} catch {} break;}
    }
    p.WaitForExit(); r.ExitCode=p.ExitCode;
    try { Task.WaitAll(new Task[]{outTask,errTask}); }
    catch(AggregateException e) { r.IOFailure=e.GetBaseException().Message; }
    if(output != null) { output.Flush(); r.FileBytes=output.Length; }
   } catch(Exception e) {
    r.IOFailure=e.Message; try {if(!p.HasExited) p.Kill();} catch {}
   } finally { if(output != null) output.Dispose(); p.Dispose(); }
   return r;
  }
 }
}
'@
}

function Assert-RecoveryLocalPath {
    param([Parameter(Mandatory=$true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw 'Only absolute local drive paths are accepted; devices and network paths are blocked.'
    }
    if ($Path.Substring(2).Contains(':')) { throw 'Alternate data stream paths are blocked.' }
    $full = [IO.Path]::GetFullPath($Path)
    $current = $full
    while ($current -and $current.Length -gt 3) {
        if ([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse-point path is blocked: $current" }
        }
        $parent = [IO.Path]::GetDirectoryName($current.TrimEnd('\'))
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $full
}

function Assert-RecoveryImage {
    param([Parameter(Mandatory=$true)][string]$ImagePath,[long]$OffsetSectors=0,[int]$SectorSize=512)
    $full = Assert-RecoveryLocalPath $ImagePath
    if (![IO.File]::Exists($full)) { throw "Image file does not exist: $full" }
    if ($SectorSize -notin @(512,1024,2048,4096)) { throw 'Unsupported sector size (use 512, 1024, 2048 or 4096).' }
    $length = ([IO.FileInfo]$full).Length
    if ($OffsetSectors -lt 0 -or $OffsetSectors -gt [long]::MaxValue / $SectorSize) { throw 'Invalid sector offset.' }
    if ([decimal]$OffsetSectors * $SectorSize -ge $length) { throw 'Filesystem offset is outside the image.' }
    return $full
}

function Get-RecoveryTool {
    param([Parameter(Mandatory=$true)][string]$EngineDirectory,[Parameter(Mandatory=$true)][ValidateSet('mmls','fsstat','fls','icat')][string]$Name)
    $directory = Assert-RecoveryLocalPath $EngineDirectory
    $tool = Join-Path $directory ($Name + '.exe')
    if (![IO.File]::Exists($tool)) { throw "Bundled filesystem engine not found: $tool" }
    $null = Assert-RecoveryLocalPath $tool
    Initialize-RecoveryNative
    return $tool
}

function Get-RecoveryPartitions {
    param([Parameter(Mandatory=$true)][string]$EngineDirectory,[Parameter(Mandatory=$true)][string]$ImagePath,[int]$SectorSize=512,[ValidateRange(1,300)][int]$TimeoutSeconds=15)
    $image = Assert-RecoveryImage $ImagePath 0 $SectorSize
    $tool = Get-RecoveryTool $EngineDirectory 'mmls'
    $result = [SafeFsNative.Runner]::Run($tool,[string[]]@('-i','raw','-b',"$SectorSize",'-a',$image),$null,$TimeoutSeconds,$false)
    $partitions = @()
    foreach ($line in ($result.Stdout -split '\r?\n')) {
        if ($line -match '^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$') {
            $start=0L; $end=0L; $length=0L
            if ([long]::TryParse($Matches[1],[ref]$start) -and [long]::TryParse($Matches[2],[ref]$end) -and [long]::TryParse($Matches[3],[ref]$length)) {
                if ($start -ge 0 -and [decimal]$start*$SectorSize -lt ([IO.FileInfo]$image).Length -and $end -ge $start) {
                    $partitions += [pscustomobject]@{StartSector=$start;EndSector=$end;LengthSectors=$length;Description=$Matches[4]}
                }
            }
        }
    }
    [pscustomobject]@{Partitions=@($partitions);Text=$result.Stdout;Error=$result.Stderr;ExitCode=$result.ExitCode;TimedOut=$result.TimedOut;IOFailure=$result.IOFailure}
}

function Get-RecoveryFilesystem {
    param([Parameter(Mandatory=$true)][string]$EngineDirectory,[Parameter(Mandatory=$true)][string]$ImagePath,[long]$OffsetSectors=0,[int]$SectorSize=512,[ValidateRange(1,300)][int]$TimeoutSeconds=15)
    $image = Assert-RecoveryImage $ImagePath $OffsetSectors $SectorSize
    $tool = Get-RecoveryTool $EngineDirectory 'fsstat'
    $result = [SafeFsNative.Runner]::Run($tool,[string[]]@('-i','raw','-b',"$SectorSize",'-o',"$OffsetSectors",$image),$null,$TimeoutSeconds,$false)
    $type = ''
    if ($result.Stdout -match '(?m)^File System Type:\s*(.+)$') { $type=$Matches[1].Trim() }
    [pscustomobject]@{Recognized=($result.ExitCode -eq 0 -and !$result.TimedOut -and !$result.IOFailure -and $type.Length -gt 0);Type=$type;Text=$result.Stdout;Error=$result.Stderr;ExitCode=$result.ExitCode;TimedOut=$result.TimedOut;IOFailure=$result.IOFailure}
}

function Export-RecoveryTreeListing {
    param([Parameter(Mandatory=$true)][string]$EngineDirectory,[Parameter(Mandatory=$true)][string]$ImagePath,[Parameter(Mandatory=$true)][string]$ReportPath,[long]$OffsetSectors=0,[int]$SectorSize=512,[ValidateSet('All','Deleted','Allocated')][string]$Mode='All',[int]$TimeoutSeconds=0)
    $image = Assert-RecoveryImage $ImagePath $OffsetSectors $SectorSize
    $report = Assert-RecoveryLocalPath $ReportPath
    if ($report.Equals($image,[StringComparison]::OrdinalIgnoreCase)) { throw 'Listing cannot overwrite the image.' }
    $errorPath = Assert-RecoveryLocalPath ($report + '.errors.txt')
    if ($errorPath.Equals($image,[StringComparison]::OrdinalIgnoreCase)) { throw 'Listing error log cannot overwrite the image.' }
    if ([IO.File]::Exists($report) -or [IO.File]::Exists($errorPath)) { throw 'Use new listing and error-log paths.' }
    $tool = Get-RecoveryTool $EngineDirectory 'fls'
    $arguments = @('-r','-p','-l','-i','raw','-b',"$SectorSize",'-o',"$OffsetSectors")
    if ($Mode -eq 'Deleted') { $arguments += '-d' }
    if ($Mode -eq 'Allocated') { $arguments += '-u' }
    $arguments += $image
    $result = [SafeFsNative.Runner]::Run($tool,[string[]]$arguments,$report,$TimeoutSeconds,$true)
    $errorStream=[IO.File]::Open($errorPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $errorWriter=[IO.StreamWriter]::new($errorStream,[Text.UTF8Encoding]::new($false))
    try {$errorWriter.Write($result.Stderr + $result.IOFailure)} finally {$errorWriter.Dispose()}
    [pscustomobject]@{ReportPath=$report;ErrorPath=$errorPath;ExitCode=$result.ExitCode;Cancelled=$result.Cancelled;TimedOut=$result.TimedOut;IOFailure=$result.IOFailure}
}

function ConvertTo-RecoveryName {
    param([Parameter(Mandatory=$true)][string]$Name)
    $clean = [regex]::Replace($Name,'[\x00-\x1f\x7f<>:"/\\|?*]','_').TrimEnd(' ','.')
    if (!$clean -or $clean -in @('.','..')) { $clean='_' }
    if ($clean -match '^(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)') { $clean='_' + $clean }
    # Keep a usable file extension while limiting the component to Win32 limits.
    if ($clean.Length -gt 120) { $extension=[IO.Path]::GetExtension($clean); if ($extension.Length -gt 16) {$extension=''}; $clean=$clean.Substring(0,120-$extension.Length)+$extension }
    return $clean
}

function Get-RecoverySafeRelativePath {
    param([string]$SourcePath,[string]$Identity,[hashtable]$SourceMap,[hashtable]$UsedMap)
    if (!$Identity -and $SourceMap.ContainsKey('/'+$SourcePath)) {return $SourceMap['/'+$SourcePath]}
    $parts = $SourcePath -split '/'
    $sourceKey=''; $safe=''
    for ($i=0;$i -lt $parts.Count;$i++) {
        $sourceKey += '/' + $parts[$i]
        $key = $sourceKey
        # Directory identities are shared; a duplicate file uses its metadata identity.
        if ($i -eq $parts.Count-1) { $key += '|'+$Identity }
        if ($SourceMap.ContainsKey($key)) { $safe=$SourceMap[$key]; continue }
        $component = ConvertTo-RecoveryName $parts[$i]
        $candidate = if ($safe) { $safe+'\'+$component } else {$component}
        if ($UsedMap.ContainsKey($candidate)) {
            $extension = if ($i -eq $parts.Count-1) {[IO.Path]::GetExtension($component)} else {''}
            if ($extension.Length -gt 16) {$extension=''}
            $stem=$component.Substring(0,$component.Length-$extension.Length)
            $suffix= if ($i -eq $parts.Count-1) { '__'+($Identity -replace '[^0-9A-Za-z_-]','_') } else {'__dir'}
            $candidate = if ($safe) {$safe+'\'+$stem+$suffix+$extension} else {$stem+$suffix+$extension}
            $n=1; $first=$candidate
            while ($UsedMap.ContainsKey($candidate)) { $candidate=$first+'_'+$n; $n++ }
        }
        $UsedMap[$candidate]=$key; $SourceMap[$key]=$candidate; $safe=$candidate
        if ($i -lt $parts.Count-1) { $SourceMap[$sourceKey]=$candidate }
    }
    return $safe
}

function Write-RecoveryCsvRow {
    param([IO.StreamWriter]$Writer,[object[]]$Fields)
    $values = foreach ($field in $Fields) { '"'+([string]$field).Replace('"','""')+'"' }
    $Writer.WriteLine(($values -join ',')); $Writer.Flush()
}

function Restore-RecoveryFilesystem {
    param(
        [Parameter(Mandatory=$true)][string]$EngineDirectory,
        [Parameter(Mandatory=$true)][string]$ImagePath,
        [Parameter(Mandatory=$true)][string]$Destination,
        [long]$OffsetSectors=0,[int]$SectorSize=512,
        [ValidateSet('All','Deleted','Allocated')][string]$Mode='All',
        [string]$Subtree='', [scriptblock]$Progress,
        [ValidateRange(1,86400)][int]$FileTimeoutSeconds=600
    )
    $image = Assert-RecoveryImage $ImagePath $OffsetSectors $SectorSize
    $root = (Assert-RecoveryLocalPath $Destination).TrimEnd('\')
    if ($root.Length -le 3) {throw 'Recovery destination must be a new subdirectory.'}
    if ($image.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $image.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Recovery destination cannot contain the source image.'}
    if ([IO.File]::Exists($root)) {throw 'Destination is a file.'}
    if ([IO.Directory]::Exists($root) -and @([IO.Directory]::EnumerateFileSystemEntries($root)).Count -gt 0) {throw 'Use a new or empty destination directory to avoid overwriting files.'}
    $null=[IO.Directory]::CreateDirectory($root)
    $dataRoot=Join-Path $root 'files'; $null=[IO.Directory]::CreateDirectory($dataRoot)
    $indexPath=Join-Path $root 'filesystem-index.tsv'
    # List all entries so allocated ancestor directories survive Deleted mode.
    $listing=Export-RecoveryTreeListing -EngineDirectory $EngineDirectory -ImagePath $image -ReportPath $indexPath -OffsetSectors $OffsetSectors -SectorSize $SectorSize -Mode All
    $sub=$Subtree.Replace('\','/').Trim('/')
    if ($sub) { foreach($component in ($sub -split '/')) {if($component -in @('.','..','')) {throw 'Invalid subtree filter.'}} }
    $manifest=Join-Path $root 'recovery-manifest.csv'
    $writer=[IO.StreamWriter]::new($manifest,$false,[Text.UTF8Encoding]::new($true))
    $writer.WriteLine('OriginalPath,OutputPath,MetadataId,Deleted,ExpectedBytes,ActualBytes,Status,Details')
    $tool=Get-RecoveryTool $EngineDirectory 'icat'
    $sourceMap=New-Object 'System.Collections.Hashtable' ([StringComparer]::Ordinal)
    $usedMap=New-Object 'System.Collections.Hashtable' ([StringComparer]::OrdinalIgnoreCase)
    $total=0L; $recovered=0L; $failed=0L; $skipped=0L; $unparsed=0L; $processed=0L; $cancelled=$listing.Cancelled
    try {
        # Count without loading the potentially very large index into memory.
        foreach($line in [IO.File]::ReadLines($indexPath,[Text.Encoding]::UTF8)) {if($line -match '^\S+/\S+\s+(?:\*\s+)?[0-9]+(?:-[0-9]+)*:') {$total++}}
        foreach($line in [IO.File]::ReadLines($indexPath,[Text.Encoding]::UTF8)) {
            if($cancelled -or [SafeFsNative.Runner]::CancelRequested()) {$cancelled=$true;break}
            # fls long format is tab-separated; name itself may contain tabs, so parse from the numeric tail.
            if($line -notmatch '^(?<kind>\S+/\S+)\s+(?<deleted>\*\s+)?(?<id>[0-9]+(?:-[0-9]+)*):\s(?<path>.*?)\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t(?<size>[0-9]+)\t[0-9]+\t[0-9]+\s*$') {
                if($line.Trim()) {$skipped++;$unparsed++;Write-RecoveryCsvRow $writer @($line,'','','','','','Unparsed','Unrecognized metadata listing entry')}
                continue
            }
            $kind=$Matches['kind']; $deleted=!!$Matches['deleted']; $id=$Matches['id']; $original=$Matches['path']; $size=0L
            if(![long]::TryParse($Matches['size'],[ref]$size)) {$failed++;Write-RecoveryCsvRow $writer @($original,'',$id,$deleted,'','','Failed','Invalid size');continue}
            $processed++
            if($sub -and !($original.Equals($sub,[StringComparison]::Ordinal) -or $original.StartsWith($sub+'/',[StringComparison]::Ordinal))) {continue}
            $types=$kind -split '/'
            # Deleted NTFS names often have an unknown name type: -/r and -/d.
            $effectiveType=if($types[0] -eq '-') {$types[1]} else {$types[0]}
            $isDirectory=($effectiveType -in @('d','v'))
            if(!$isDirectory -and (($Mode -eq 'Deleted' -and !$deleted) -or ($Mode -eq 'Allocated' -and $deleted))) {continue}
            $status=''; $details=''; $actual=0L; $relative=''; $out=''
            try {
                if($original.EndsWith('/') -or !$original -or $original -match '(^|/)\.\.?(/|$)') {throw 'Invalid directory path in source metadata.'}
                # TSK virtual orphan directory is an ordinary output directory. Never recreate symlinks/reparse points.
                if($kind -match '^l/' -or $kind -match '/l$') {$status='Skipped';$details='Symbolic link metadata is not followed';$skipped++}
                elseif($types[0] -ne '-' -and $types[1] -ne '-' -and $types[0] -ne $types[1]) {$status='Skipped';$details='Conflicting name and metadata types (possibly reallocated)';$skipped++}
                elseif($original -match '^(?:\$MFT(?:Mirr)?|\$LogFile|\$Volume|\$AttrDef|\$Bitmap|\$Boot|\$BadClus|\$Secure|\$UpCase|\$Extend)(?:/|:|$)' -or $original -match '^\$(?:FAT[0-9]+|MBR|Boot)$') {$status='Skipped';$details='Filesystem service metadata';$skipped++}
                elseif($effectiveType -eq 'r' -and $id -match '^\d+-\d+-\d+$' -and $original -match ':') {$status='Skipped';$details='NTFS alternate data stream; indexed but not exported';$skipped++}
                elseif(!$isDirectory -and $effectiveType -ne 'r') {$status='Skipped';$details='Unsupported special file type';$skipped++}
                else {
                    $identity=if($isDirectory){''}else{$id}
                    $relative=Get-RecoverySafeRelativePath $original $identity $sourceMap $usedMap
                    $out=[IO.Path]::GetFullPath((Join-Path $dataRoot $relative))
                    if(!$out.StartsWith($dataRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Output escaped the recovery directory.'}
                    $null=Assert-RecoveryLocalPath $out
                    if($isDirectory) {
                        $null=[IO.Directory]::CreateDirectory($out);$status='Directory';$details='Created as an ordinary directory'
                        # Directory identity also serves as parent mapping for descendants.
                        $sourceMap['/'+$original]=$relative
                    } else {
                        $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($out))
                        if($size -eq 0) {
                            $empty=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$empty.Dispose()
                            $status='Recovered';$details='Empty file; content not verified';$recovered++
                        } else {
                            $temporary=$out+'.partial-'+[guid]::NewGuid().ToString('N')
                            $arguments=@('-i','raw','-b',"$SectorSize",'-o',"$OffsetSectors")
                            if($deleted) {$arguments+='-r'}
                            $arguments+=@($image,$id)
                            $native=[SafeFsNative.Runner]::Run($tool,[string[]]$arguments,$temporary,$FileTimeoutSeconds,$true)
                            $actual=$native.FileBytes
                            if($native.Cancelled) {$cancelled=$true;$status='Partial';$details='Cancelled; partial file retained';$failed++}
                            elseif($native.ExitCode -ne 0 -or $native.TimedOut -or $native.IOFailure -or $actual -ne $size) {$status='Partial';$details=('Exit='+$native.ExitCode+'; timeout='+$native.TimedOut+'; '+$native.IOFailure+'; '+$native.Stderr).Trim();$failed++}
                            else {[IO.File]::Move($temporary,$out);$status='Recovered';$details='Metadata export; content not verified';$recovered++}
                            if($status -eq 'Partial') {$out=$temporary}
                        }
                    }
                }
            } catch {$status='Failed';$details=$_.Exception.Message;$failed++}
            Write-RecoveryCsvRow $writer @($original,$out,$id,$deleted,$size,$actual,$status,$details)
            if($Progress) {& $Progress ([pscustomobject]@{Index=$processed;Total=$total;Path=$original;Status=$status;Recovered=$recovered;Failed=$failed})}
            if($cancelled) {break}
        }
    } finally {$writer.Dispose()}
    [pscustomobject]@{Total=$total;Recovered=$recovered;Failed=$failed;Skipped=$skipped;Unparsed=$unparsed;Cancelled=$cancelled;ManifestPath=$manifest;Destination=$root;FilesDirectory=$dataRoot;Unverified=$true;ListingExitCode=$listing.ExitCode;ListingTimedOut=$listing.TimedOut;ListingErrorPath=$listing.ErrorPath;Complete=(!$cancelled -and $failed -eq 0 -and $unparsed -eq 0 -and $listing.ExitCode -eq 0 -and !$listing.TimedOut -and !$listing.IOFailure)}
}
