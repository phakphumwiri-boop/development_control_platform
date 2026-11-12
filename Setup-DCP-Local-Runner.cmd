@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Setup-DCP-Local-Runner.ps1" %*
exit /b %ERRORLEVEL%
