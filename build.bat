@echo off
setlocal
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo csc.exe not found
  pause
  exit /b 1
)

"%CSC%" /nologo /target:winexe /optimize+ /out:freezeMe-Security.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll freezeMe-Security.cs
if errorlevel 1 (
  echo Build failed
  pause
  exit /b 1
)

echo Done
pause
