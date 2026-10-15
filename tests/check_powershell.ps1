#requires -Version 5.1
[CmdletBinding()]
param([string]$Root)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$paths = @(
    (Join-Path $Root 'install.ps1'),
    (Join-Path $Root 'dist/Recover-Disk.ps1')
)
$paths += @(Get-ChildItem -LiteralPath (Join-Path $Root 'src') -Filter '*.ps1' -File -Recurse |
    Where-Object { $_.Name -notlike '*.template.ps1' } | ForEach-Object { $_.FullName })
foreach ($path in $paths) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing PowerShell file: $path" }
    $tokens = $null
    $parseErrors = $null
    # UTF-8 BOMs allow Windows PowerShell 5.1 to read Unicode source correctly.
    $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) {
        throw ('PowerShell syntax errors in {0}: {1}' -f $path, (@($parseErrors | ForEach-Object { $_.Message }) -join '; '))
    }
    Write-Host ('PASS syntax: ' + (Split-Path -Leaf $path))
}
$builtBytes = [IO.File]::ReadAllBytes((Join-Path $Root 'dist/Recover-Disk.ps1'))
if ($builtBytes[0] -ne 0xEF -or $builtBytes[1] -ne 0xBB -or $builtBytes[2] -ne 0xBF) {
    throw 'Standalone script needs a UTF-8 BOM for Windows PowerShell 5.1.'
}
$tokens = $null
$parseErrors = $null
$installer = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'install.ps1'), [ref]$tokens, [ref]$parseErrors)
$commands = @($installer.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() })
if ('Invoke-Expression' -in $commands -or 'iex' -in $commands) {
    throw 'Installer must download the release and launch a verified local script, without nested Invoke-Expression.'
}
$installerText = [IO.File]::ReadAllText((Join-Path $Root 'install.ps1'))
foreach ($required in @('SHA256SUMS.json', 'Get-FileHash', 'SHA256')) {
    if (!$installerText.Contains($required)) { throw "Installer missing verification component: $required" }
}
Write-Host 'PASS installer verification structure'
