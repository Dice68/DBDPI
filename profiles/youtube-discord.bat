@echo off
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
echo DBDPI: multisplit (midsld) with hostlist. Ctrl+C to stop.
bin\dbdpi.exe --debug --dpi-desync=multisplit --split-pos=midsld ^
    --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt
pause
