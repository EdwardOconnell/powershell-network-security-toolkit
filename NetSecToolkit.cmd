@echo off
rem NetSecToolkit menu. Keep this file next to the NetSecToolkit folder.
rem Right-click it and choose Run as administrator for the full check and for hardening.
where pwsh >nul 2>nul
if errorlevel 1 (
  echo PowerShell 7 is not installed. Install it with:  winget install Microsoft.PowerShell
  pause
  exit /b 1
)
if not exist "%~dp0NetSecToolkit\NetSecToolkit.psd1" (
  echo The NetSecToolkit folder must be next to this file.
  pause
  exit /b 1
)
cd /d "%~dp0"
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& { Import-Module .\NetSecToolkit\NetSecToolkit.psd1 -Force; Start-NetSecToolkit }"
