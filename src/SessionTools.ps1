function Probe-SessionVolume($Session,[int64]$Sector,[string]$Source) {
    $length=[int64](Get-Item -LiteralPath $Session.Image).Length
    if($Sector -lt 0 -or $Sector -gt [math]::Floor(($length-512)/$Session.SectorSize)) {return $null}
    $result=Get-RecoveryFilesystem -EngineDirectory $Session.Tsk -ImagePath $Session.Image -SectorSize $Session.SectorSize -OffsetSectors $Sector -TimeoutSeconds 10
    if(!$result.Recognized) {return $null}
    $report=New-ReportPath $Session ('fsstat-sector-'+$Sector)
    [IO.File]::WriteAllText($report,[string]$result.Text,[Text.UTF8Encoding]::new($false))
    [pscustomobject]@{Offset=$Sector;Type=$result.Type;Source=$Source;Report=$report}
}
function Invoke-SessionScan($Session,[switch]$Deep) {
    Write-Header $(if($Deep){'Полное сканирование образа'}else{'Быстрое сканирование образа'})
    $found=@{};foreach($v in @($Session.Volumes)) {$found[[string]$v.Offset]=$v}
    $offsets=@{ '0'='начало образа' }
    $partitions=Get-RecoveryPartitions -EngineDirectory $Session.Tsk -ImagePath $Session.Image -SectorSize $Session.SectorSize -TimeoutSeconds 15
    [IO.File]::WriteAllText((New-ReportPath $Session 'partition-table'),[string]$partitions.Text,[Text.UTF8Encoding]::new($false))
    foreach($p in @($partitions.Partitions)) {$offsets[[string]$p.StartSector]=$p.Description}
    if($Deep) {
        Initialize-Native
        Write-Host 'Последовательное чтение образа. Q/Esc — остановить; оригинальный диск не используется.'
        $candidates=@([DiskRescueNative]::ScanBootSectors($Session.Image,$Session.SectorSize))
        ConvertTo-Json -InputObject $candidates -Depth 4 | Set-Content -LiteralPath (New-ReportPath $Session 'boot-candidates' 'json') -Encoding UTF8
        foreach($c in $candidates) {$offsets[[string]$c.Offset]=('boot: '+$c.Type)}
    }
    $index=0
    foreach($key in @($offsets.Keys | Sort-Object {[int64]$_})) {
        $index++
        Write-Progress -Activity 'Проверка файловых систем' -Status ("Сектор $key ($index из $($offsets.Count)); Q/Esc — остановить") -PercentComplete ([int]($index*100/$offsets.Count))
        if('DiskRescueNative' -as [type]) {if([DiskRescueNative]::StopRequested()){break}}
        $v=Probe-SessionVolume $Session ([int64]$key) ([string]$offsets[$key])
        if($null -ne $v) {$found[$key]=$v}
    }
    Write-Progress -Activity 'Проверка файловых систем' -Completed
    $Session.Volumes=@($found.Values | Sort-Object Offset)
    ConvertTo-Json -InputObject @($Session.Volumes) -Depth 5 | Set-Content -LiteralPath (Join-Path $Session.Root 'volumes.json') -Encoding UTF8
    Show-Volumes $Session
    Write-Host 'Открытые ФС подтверждены парсером, но целостность каждого файла ещё не проверена.'
    if($Deep) {Write-Host 'Резервные загрузочные секторы могут отображаться отдельными кандидатами.'}
}
function Show-FileBrowser($Session,$Volume) {
    $report=New-ReportPath $Session ('files-sector-'+$Volume.Offset)
    $listed=Export-RecoveryTreeListing -EngineDirectory $Session.Tsk -ImagePath $Session.Image -SectorSize $Session.SectorSize -OffsetSectors $Volume.Offset -ReportPath $report -Mode All
    if($listed.ExitCode -ne 0 -or $listed.Cancelled -or $listed.TimedOut -or $listed.IOFailure) {throw ('Не удалось получить полный список. Отчёт: '+$report)}
    $page=0;$filter=''
    while($true) {
        Write-Header ('Список файлов | страница '+($page+1))
        Write-Host ('Полный список: '+$report)
        Write-Host ('Фильтр: '+$(if($filter){$filter}else{'нет'}))
        $reader=[IO.StreamReader]::new($report,[Text.Encoding]::UTF8,$true)
        try {
            $matched=0;$shown=0;$more=$false
            while($null -ne ($line=$reader.ReadLine())) {
                if($filter -and $line.IndexOf($filter,[StringComparison]::OrdinalIgnoreCase) -lt 0) {continue}
                if($matched++ -lt $page*20){continue}
                if($shown -ge 20){$more=$true;break}
                Write-Host $line;$shown++
            }
        } finally {$reader.Dispose()}
        Write-Host 'n — следующая | p — предыдущая | f — найти по части пути | q — назад'
        $choice=Read-Choice 'Команда' @('n','p','f','q')
        switch($choice) {
            'n' {if($more){$page++}else{Write-Host 'Конец списка.'}}
            'p' {if($page -gt 0){$page--}}
            'f' {$filter=Read-Host 'Часть пути (пусто — все)';$page=0}
            'q' {return}
        }
    }
}
function Invoke-TreeRecovery($Session,$Volume,[string]$Mode) {
    $script:SessionNumber++
    $dest=Join-Path $Session.Root ('recovered-tree-{0:D4}' -f $script:SessionNumber)
    Write-Host ('Восстановление дерева в '+$dest) -ForegroundColor Cyan
    Write-Host 'Удалённые данные могут быть перезаписаны; совпадение имён не доказывает целостность. Q/Esc — остановить.'
    $result=Restore-RecoveryFilesystem -EngineDirectory $Session.Tsk -ImagePath $Session.Image -SectorSize $Session.SectorSize -OffsetSectors $Volume.Offset -Destination $dest -Mode $Mode -Progress {
        param($p)
        $total=[math]::Max(1,[int64]$p.Total)
        Write-Progress -Activity 'Восстановление с именами и папками' -Status ("$($p.Index)/$($p.Total): $($p.Path)") -PercentComplete ([int][math]::Min(100,($p.Index*100/$total)))
    }
    Write-Progress -Activity 'Восстановление с именами и папками' -Completed
    $result | Format-List | Out-Host
    $json=New-ReportPath $Session 'recovery-summary' 'json'
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $json -Encoding UTF8
    if($result.Cancelled) {Write-Host 'Остановлено. Уже извлечённые файлы и отчёт сохранены.' -ForegroundColor Yellow}
    elseif($result.Failed -gt 0) {throw ('Есть ошибки экспорта. Уже извлечённые файлы сохранены, подробности: '+$result.ManifestPath)}
    elseif(!$result.Complete) {throw ('Экспорт неполный: часть списка не прочитана или не распознана. Подробности: '+$result.ManifestPath+'; '+$result.ListingErrorPath)}
    else {Write-Host 'Экспорт завершён. Проверьте важные файлы; отчёт содержит пути и статусы.' -ForegroundColor Green}
}
function Invoke-Carving($Session) {
    $script:SessionNumber++
    $dest=Join-Path $Session.Root ('carving-{0:D4}' -f $script:SessionNumber)
    $null=[IO.Directory]::CreateDirectory($dest)
    Write-Host 'PhotoRec: поиск по сигнатурам. Исходные имена и дерево папок не восстанавливаются.' -ForegroundColor Yellow
    $p=[Diagnostics.ProcessStartInfo]::new()
    $p.FileName=Join-Path $Session.PhotoRec 'photorec_win.exe'
    $p.WorkingDirectory=$dest;$p.UseShellExecute=$false
    $p.EnvironmentVariables['__COMPAT_LAYER']='RunAsInvoker'
    $p.Arguments='/log /d "'+(Join-Path $dest 'recovered')+'" /cmd "'+$Session.Image+'" partition_none,options,paranoid,keep_corrupted_file_no,fileopt,everything,enable,wholespace,search'
    $child=[Diagnostics.Process]::Start($p)
    try {$child.WaitForExit();$code=$child.ExitCode} finally {$child.Dispose()}
    if($code -ne 0) {throw "PhotoRec завершился с кодом $code; образ и результаты сохранены."}
    Write-Host ('PhotoRec завершён: '+$dest)
}
