@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0malvex-wazuh-ar.ps1"
exit /b %ERRORLEVEL%
