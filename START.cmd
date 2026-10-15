@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
title Disk Rescue
echo Disk Rescue - terminal interface
echo Physical disk imaging requires Run as administrator.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Recover-Disk.ps1"
echo.
echo Exit code: %errorlevel%
pause
