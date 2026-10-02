@echo off
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
echo DBDPI: fake + autottl. Ctrl+C to stop.
bin\dbdpi.exe --debug --dpi-desync=fake --fake-gen --repeats=3 ^
    --fooling=ttl --autottl=3:3-64 ^
    --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt
pause
