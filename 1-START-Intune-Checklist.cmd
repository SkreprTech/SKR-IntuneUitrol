@echo off
setlocal
rem Windows PowerShell 5.1 met WPF; uitvoering als beheerder wordt door de PS1 gevraagd.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%~dp0SkreprTech-Intune-Checklist.ps1"
endlocal
