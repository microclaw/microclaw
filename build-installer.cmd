@echo off
setlocal

set "REPO_ROOT=%~dp0"
set "POWERSHELL_SCRIPT=%REPO_ROOT%scripts\build_windows_installer.ps1"

if not exist "%POWERSHELL_SCRIPT%" (
  echo Missing script: "%POWERSHELL_SCRIPT%"
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%POWERSHELL_SCRIPT%" %*
exit /b %ERRORLEVEL%
