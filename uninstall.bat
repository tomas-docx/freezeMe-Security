@echo off
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "DIR=%ProgramFiles%\freezeMe-Security"
if exist "%DIR%\freezeMe-Security.exe" (
  start "" /wait "%DIR%\freezeMe-Security.exe" --stop
  timeout /t 2 /nobreak >nul
)
schtasks /delete /tn freezeMe-Security /f >nul 2>&1
rmdir /s /q "%DIR%" 2>nul
echo Removed
pause
