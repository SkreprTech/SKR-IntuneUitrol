@echo off
setlocal
rem Handmatige hervatting indien Windows de automatische opstart niet uitvoerde.
set "SCRIPT=%ProgramData%\SkreprTech\IntuneChecklist\SkreprTech-Intune-Checklist.ps1"
if not exist "%SCRIPT%" (
  echo De checklist is op deze computer nog niet voorbereid.
  pause
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "%SCRIPT%" -Resume
endlocal
