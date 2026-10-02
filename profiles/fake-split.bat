@echo off
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
echo DBDPI: fakedsplit + fake-gen + badsum/badseq with hostlist. Ctrl+C to stop.
bin\dbdpi.exe --debug --preset=4 ^
    --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt
pause
