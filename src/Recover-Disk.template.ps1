#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu','Scan','Recover','Carve','Analyze')][string]$Action='Menu',
    [string]$ImagePath,
    [string]$OutputDirectory,
    [ValidateSet(512,4096)][int]$SectorSize=512,
    [int64]$Offset=0,
    [ValidateSet('All','Allocated','Deleted')][string]$RecoveryMode='All',
    [string]$LogPath,
    [switch]$DeepScan
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$EngineHash='__ENGINE_HASH__'
$script:SessionNumber=0

__LOG_PARSER__

function Write-Header([string]$Title) {
    Write-Host ''
    Write-Host ('='*72) -ForegroundColor DarkCyan
    Write-Host ('  DISK RESCUE __VERSION__   |   '+$Title) -ForegroundColor Cyan
    Write-Host ('='*72) -ForegroundColor DarkCyan
}
function Read-Choice([string]$Prompt,[string[]]$Values) {
    while($true) {
        $value=(Read-Host $Prompt).Trim()
        if($value -in $Values) { return $value }
        Write-Host ('Допустимые значения: '+($Values -join ', ')) -ForegroundColor Yellow
    }
}
function Read-Path([string]$Prompt) {
    $value=(Read-Host $Prompt).Trim().Trim('"')
    if([string]::IsNullOrWhiteSpace($value)) {throw 'Путь не задан.'}
    $value
}
function Assert-DataPath([string]$Path,[int]$ForbiddenDisk=-1) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full -notmatch '^[A-Za-z]:\\' -or $full.IndexOf(':',2) -ge 0) {throw 'Нужен локальный путь с буквой диска; сетевые пути и потоки NTFS не поддерживаются.'}
    $root=[IO.Path]::GetPathRoot($full)
    $part=@(Get-Partition -DriveLetter $root.Substring(0,1) -ErrorAction Stop)
    if($part.Count -ne 1) {throw 'Не удалось однозначно определить физический диск для пути.'}
    $disk=Get-Disk -Number $part[0].DiskNumber
    if($ForbiddenDisk -ge 0 -and [string]$disk.BusType -in @('Virtual','File Backed Virtual','Spaces','iSCSI','Unknown')) {throw 'Виртуальные, сетевые и составные тома назначения не поддерживаются: нельзя надёжно исключить исходный диск.'}
    if($disk.Number -eq $ForbiddenDisk) {throw 'Запись на исходный физический диск запрещена, включая другие его разделы.'}
    $current=$full
    while($current) {
        if(Test-Path -LiteralPath $current) {
            $item=Get-Item -LiteralPath $current -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw "Ссылка/junction/точка монтирования в пути запрещена: $current"}
        }
        $parent=[IO.Directory]::GetParent($current)
        if($null -eq $parent) {break}
        $current=$parent.FullName
    }
    $full
}
function Assert-Image([string]$Path) {
    $full=Assert-DataPath $Path
    if(!(Test-Path -LiteralPath $full -PathType Leaf)) {throw 'Файл образа не найден.'}
    if([IO.Path]::GetExtension($full) -notin @('.img','.dd','.raw')) {throw 'Поддерживаются полные сырые образы .img, .dd, .raw. Частичные образы .partial не принимаются.'}
    if((Get-Item -LiteralPath $full).Length -lt 512) {throw 'Образ слишком мал.'}
    $full
}
function Assert-FreeSpace([string]$Path,[int64]$Bytes) {
    $v=Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($Path).Substring(0,1))
    if([string]$v.FileSystem -notin @('NTFS','ReFS')) {throw 'Для результата нужен диск NTFS или ReFS.'}
    if([int64]$v.SizeRemaining -lt $Bytes) {throw ('Недостаточно места: требуется минимум {0:N2} ГиБ.' -f ($Bytes/1GB))}
}
function Expand-Engines([string]$Directory) {
    # Large runtime assets are a data comment, loaded lazily; no enormous PS5 string token.
    $self=[IO.File]::ReadAllText($PSCommandPath)
    $marker='<# DISK_RESCUE_ENGINE_BASE64'
    $at=$self.LastIndexOf($marker,[StringComparison]::Ordinal)
    if($at -lt 0) {throw 'Встроенный архив не найден.'}
    $payload=$self.Substring($at+$marker.Length)
    $payload=$payload.Substring(0,$payload.LastIndexOf('#>',[StringComparison]::Ordinal))
    $bytes=[Convert]::FromBase64String($payload)
    $h=[Security.Cryptography.SHA256]::Create()
    try {$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()} finally {$h.Dispose()}
    if($actual -ne $EngineHash) {throw 'Контрольная сумма встроенных инструментов не совпала.'}
    Add-Type -AssemblyName System.IO.Compression
    $stream=[IO.MemoryStream]::new($bytes,$false)
    $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read)
    try {
        foreach($entry in $zip.Entries) {
            if($entry.FullName -notmatch '^(tsk|photorec)/[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$') {throw 'Недопустимый путь во встроенном архиве.'}
            $target=Join-Path $Directory $entry.FullName
            $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $out=[IO.File]::Open($target,[IO.FileMode]::CreateNew)
            $input=$entry.Open()
            try {$input.CopyTo($out)} finally {$input.Dispose();$out.Dispose()}
        }
    } finally {$zip.Dispose();$stream.Dispose()}
}

__NATIVE_READER__

__FILESYSTEM_TOOLS__

function Initialize-Native {
    if(!('DiskRescueNative' -as [type])) {
        $null=Assert-DataPath ([IO.Path]::GetTempPath())
        Add-Type -TypeDefinition $NativeSource
    }
}
function New-Session([string]$Destination,[int]$ForbiddenDisk=-1,[int64]$Reserve=268435456) {
    $null=Assert-DataPath $PSCommandPath $ForbiddenDisk
    $null=Assert-DataPath ([IO.Path]::GetTempPath()) $ForbiddenDisk
    $Destination=Assert-DataPath $Destination $ForbiddenDisk
    if(Test-Path -LiteralPath $Destination) {throw 'Папка уже существует. Укажите НОВУЮ папку: имеющиеся результаты не перезаписываются.'}
    Assert-FreeSpace $Destination $Reserve
    $null=[IO.Directory]::CreateDirectory($Destination)
    $engineDir=Join-Path $Destination 'engines'
    Expand-Engines $engineDir
    [pscustomobject]@{Root=$Destination; Tsk=(Join-Path $engineDir 'tsk'); PhotoRec=(Join-Path $engineDir 'photorec'); Image=''; SectorSize=512; Volumes=@()}
}
function New-ReportPath($Session,[string]$Prefix,[string]$Extension='txt') {
    $script:SessionNumber++
    Join-Path $Session.Root ('{0}-{1:D4}.{2}' -f $Prefix,$script:SessionNumber,$Extension)
}
function Get-ScanInfo([string]$Path) {
    if([string]::IsNullOrWhiteSpace($Path)) {throw 'Для анализа укажите свой лог: -Action Analyze -LogPath "C:\Logs\scan.log".'}
    $full=[IO.Path]::GetFullPath($Path)
    if(!(Test-Path -LiteralPath $full -PathType Leaf)) {throw 'Файл лога не найден.'}
    if((Get-Item -LiteralPath $full).Length -gt 256MB) {throw 'Лог больше 256 МиБ: сохраните текстовый лог меньшего размера.'}
    $text=[IO.File]::ReadAllText($full)
    Read-ScanLog $text
}
function Show-ScanInfo([string]$Path) {
    Write-Header 'Анализ лога DMDE'
    $scan=Get-ScanInfo $Path
    Write-Host ('Серийный номер из лога: {0} | Размер: {1:N2} ГиБ | Сектор: {2}' -f $scan.Serial,($scan.Bytes/1GB),$scan.SectorSize)
    $scan.RawCandidates | Format-Table -AutoSize | Out-Host
    Write-Host 'Это кандидаты, а не проверенные целые файлы. Внутренние сжатые записи DMDE не декодируются.'
    Write-Host 'Лог не содержит восстанавливаемых данных и не выбирает физический диск автоматически.'
}
function Show-Disks {
    $rows=@(Get-Disk | Sort-Object Number | ForEach-Object {
        [pscustomobject]@{N=$_.Number; 'Модель'=$_.FriendlyName; 'ГиБ'=[math]::Round($_.Size/1GB,2); 'Шина'=[string]$_.BusType; 'Серийный'=([string]$_.SerialNumber).Trim(); 'Состояние'=$(if($_.IsSystem -or $_.IsBoot){'системный: нужен офлайн-образ'}elseif($_.IsOffline){'offline'}else{'доступен'})}
    })
    $rows | Format-Table -AutoSize | Out-Host
    $rows
}
function Acquire-Disk {
    Write-Header 'Выбор физического диска'
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(!(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Для создания образа запустите START.cmd от администратора. Готовые образы доступны без повышения прав.'}
    $null=Show-Disks
    $n=Read-Host 'Номер исходного диска (Enter — отмена)'
    if($n -eq '') {return $null}
    if($n -notmatch '^\d+$') {throw 'Нужен номер из списка.'}
    $disk=Get-Disk -Number ([int]$n)
    if($disk.IsBoot -or $disk.IsSystem) {throw 'Системный диск работающей Windows требует офлайн-образа: текущая ОС меняет его во время чтения.'}
    if($disk.IsOffline -or [int64]$disk.Size -le 0 -or $disk.LogicalSectorSize -notin @(512,4096)) {throw 'Носитель недоступен либо имеет неподдерживаемый размер сектора.'}
    if([string]$disk.BusType -in @('Virtual','File Backed Virtual','Spaces','iSCSI','Unknown')) {throw 'Виртуальные, составные и сетевые диски: используйте сырой образ.'}
    $pnp=Get-CimInstance Win32_DiskDrive -Filter ('Index='+$disk.Number)
    if($null -eq $pnp) {throw 'Не удалось проверить идентификатор физического диска.'}
    $null=Assert-DataPath $PSCommandPath ([int]$disk.Number)
    $null=Assert-DataPath ([IO.Path]::GetTempPath()) ([int]$disk.Number)
    Write-Host ('Источник: #{0} | {1} | {2:N2} ГиБ | SERIAL {3}' -f $disk.Number,$disk.FriendlyName,($disk.Size/1GB),$disk.SerialNumber) -ForegroundColor Yellow
    $dest=Read-Path 'Новая папка на ДРУГОМ физическом диске'
    $dest=Assert-DataPath $dest ([int]$disk.Number)
    if(Test-Path -LiteralPath $dest) {throw 'Папка назначения уже существует.'}
    Assert-FreeSpace $dest ([int64]($disk.Size+512MB))
    Write-Host 'Для восстановления дополнительно потребуется место под выбранные файлы.'
    Write-Host 'Источник открывается только для чтения. При ошибке копирование остановится. Q — остановить.'
    $token='DISK '+$disk.Number
    if((Read-Host ('Для начала введите '+$token)) -cne $token) {throw 'Создание образа отменено.'}
    $again=Get-Disk -Number $disk.Number
    $pnpAgain=Get-CimInstance Win32_DiskDrive -Filter ('Index='+$disk.Number)
    if($null -eq $pnpAgain -or $pnpAgain.PNPDeviceID -ne $pnp.PNPDeviceID -or [int64]$again.Size -ne [int64]$disk.Size -or [string]$again.UniqueId -ne [string]$disk.UniqueId) {throw 'Идентификатор диска изменился; операция отменена.'}
    $session=New-Session $dest ([int]$disk.Number) ([int64]($disk.Size+512MB))
    Initialize-Native
    $manifest=[ordered]@{Complete=$false; Source=('\\.\PhysicalDrive'+$disk.Number); PNP=$pnp.PNPDeviceID; UniqueId=$disk.UniqueId; Bytes=[int64]$disk.Size; SectorSize=[int]$disk.LogicalSectorSize; StartedUtc=[DateTime]::UtcNow.ToString('o')}
    $manifestPath=Join-Path $dest 'image-info.json'
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $partial=Join-Path $dest 'disk.img.partial'
    $sha=[DiskRescueNative]::Copy($manifest.Source,$partial,[int64]$disk.Size,[int]$disk.LogicalSectorSize,([string]$disk.SerialNumber).Trim())
    $session.Image=Join-Path $dest 'disk.img'
    [IO.File]::Move($partial,$session.Image)
    $manifest.Complete=$true;$manifest['Sha256']=$sha
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $session.SectorSize=[int]$disk.LogicalSectorSize
    Write-Host 'Полный образ создан. Дальше программа работает с ним; флешка/диск больше не нужны.' -ForegroundColor Green
    $session
}
function Open-ImageSession([string]$Image,[string]$Destination,[int]$Sector=512) {
    $Image=Assert-Image $Image
    $session=New-Session $Destination
    $session.Image=$Image;$session.SectorSize=$Sector
    [pscustomobject]@{Image=$Image; Bytes=(Get-Item -LiteralPath $Image).Length; SectorSize=$Sector; OpenedUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $session.Root 'session.json') -Encoding UTF8
    $session
}
function Show-Volumes($Session) {
    if(@($Session.Volumes).Count -eq 0) {Write-Host 'Файловые системы пока не найдены. Запустите быстрое или полное сканирование.';return}
    $i=0
    @($Session.Volumes) | ForEach-Object {$i++;[pscustomobject]@{N=$i;'Начало (сектор)'=$_.Offset;'ФС'=$_.Type;'Источник'=$_.Source}} | Format-Table -AutoSize | Out-Host
}
function Select-Volume($Session) {
    Show-Volumes $Session
    if(@($Session.Volumes).Count -eq 0) {return $null}
    $n=Read-Host 'Номер файловой системы (Enter — отмена)'
    if($n -eq '') {return $null}
    if($n -notmatch '^\d+$' -or [int]$n -lt 1 -or [int]$n -gt @($Session.Volumes).Count) {throw 'Неверный номер.'}
    @($Session.Volumes)[[int]$n-1]
}

__SESSION_TOOLS__

function Session-Menu($Session) {
    while($true) {
        Write-Header 'Образ и восстановление'
        Write-Host ('Образ: '+$Session.Image)
        Write-Host ('Результаты: '+$Session.Root)
        Show-Volumes $Session
        Write-Host '  1  Быстрый поиск: таблица разделов + начало образа'
        Write-Host '  2  Полный поиск загрузочных секторов NTFS / exFAT / FAT'
        Write-Host '  3  Открыть список файлов и папок'
        Write-Host '  4  Восстановить выбранную файловую систему с деревом папок'
        Write-Host '  5  Поиск по сигнатурам PhotoRec (без исходных имён)'
        Write-Host '  0  Вернуться в главное меню'
        $choice=Read-Choice 'Выбор' @('0','1','2','3','4','5')
        try {
            switch($choice) {
                '0' {return}
                '1' {Invoke-SessionScan $Session}
                '2' {Invoke-SessionScan $Session -Deep}
                '3' {$v=Select-Volume $Session;if($null -ne $v){Show-FileBrowser $Session $v}}
                '4' {
                    $v=Select-Volume $Session
                    if($null -ne $v) {
                        Write-Host '1 — существующие и удалённые; 2 — только существующие; 3 — только удалённые'
                        $mode=Read-Choice 'Какие файлы' @('1','2','3')
                        $modeName=@{'1'='All';'2'='Allocated';'3'='Deleted'}[$mode]
                        Invoke-TreeRecovery $Session $v $modeName
                    }
                }
                '5' {Invoke-Carving $Session}
            }
        } catch {Write-Host ('Ошибка: '+$_.Exception.Message) -ForegroundColor Red}
    }
}
function Main {
    if(![Environment]::Is64BitProcess) {throw 'Нужна 64-разрядная Windows PowerShell 5.1 или PowerShell 7.'}
    $build=[int][Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion','CurrentBuildNumber',0)
    if($build -lt 18362) {throw 'Для сохранения Unicode-имён нужна Windows 10 версии 1903 или новее, либо Windows 11.'}
    if($Action -eq 'Analyze') {Show-ScanInfo $LogPath;return}
    if($Action -ne 'Menu') {
        if(!$ImagePath -or !$OutputDirectory) {throw 'Нужны -ImagePath и -OutputDirectory (новая папка).'}
        $session=Open-ImageSession $ImagePath $OutputDirectory $SectorSize
        switch($Action) {
            'Scan' {Invoke-SessionScan $session -Deep:$DeepScan}
            'Recover' {
                $v=Probe-SessionVolume $session $Offset 'заданный сектор'
                if($null -eq $v) {throw 'Файловая система по указанному смещению не найдена.'}
                Invoke-TreeRecovery $session $v $RecoveryMode
            }
            'Carve' {Invoke-Carving $session}
        }
        return
    }
    while($true) {
        Write-Header 'Главное меню'
        Write-Host '  1  Физический HDD / SSD / USB → безопасный образ → восстановление'
        Write-Host '  2  Открыть готовый образ .img / .dd / .raw'
        Write-Host '  3  Изучить сохранённый лог DMDE'
        Write-Host '  4  Возможности и ограничения'
        Write-Host '  0  Выход'
        $choice=Read-Choice 'Выбор' @('0','1','2','3','4')
        try {
            switch($choice) {
                '0' {return}
                '1' {$session=Acquire-Disk;if($null -ne $session){Invoke-SessionScan $session;Session-Menu $session}}
                '2' {
                    $image=Read-Path 'Путь к образу'
                    $dest=Read-Path 'Новая папка результатов'
                    $sector=Read-Choice 'Размер сектора исходника: 512 или 4096' @('512','4096')
                    $session=Open-ImageSession $image $dest ([int]$sector)
                    Invoke-SessionScan $session;Session-Menu $session
                }
                '3' {$selectedLog=Read-Path 'Путь к сохранённому текстовому логу DMDE';Show-ScanInfo $selectedLog}
                '4' {
                    Write-Host 'Метаданные: имена и дерево папок NTFS/exFAT/FAT и других ФС, распознаваемых TSK.'
                    Write-Host 'Удалённые файлы: только если сохранились метаданные и данные не перезаписаны.'
                    Write-Host 'Полный поиск: загрузочные сектора NTFS/exFAT/FAT; повреждённая ФС может не открыться.'
                    Write-Host 'PhotoRec: запасной поиск содержимого без исходного дерева.'
                    Write-Host 'Нет ремонта/записи разделов, RAID-реконструкции, расшифровки, редактора секторов.'
                    Write-Host 'Системный диск работающей Windows: нужен офлайн-образ. Гарантий восстановления нет.'
                    Write-Host 'При потере метаданных восстановить исходное дерево невозможно. Это не полная замена DMDE.'
                }
            }
        } catch {Write-Host ('Ошибка: '+$_.Exception.Message) -ForegroundColor Red}
    }
}
try {Main;exit 0} catch {Write-Host ('Ошибка: '+$_.Exception.Message) -ForegroundColor Red;exit 1}
