@echo off
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
net stop DBDPI 2>nul
bin\dbdpi.exe --remove-service
pause
