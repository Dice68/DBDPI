@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

set RESULT=%~dp0blockcheck-result.txt
set LOG=%~dp0blockcheck-dbdpi.log
echo DBDPI blockcheck %date% %time% > "%RESULT%"

set CONTROL=https://www.google.com/generate_204
set TARGET=https://www.youtube.com/generate_204

curl -sS -o nul --max-time 8 %CONTROL%
if errorlevel 1 (
    echo [!] control URL unreachable - check your internet >> "%RESULT%"
    type "%RESULT%"
    pause
    exit /b 1
)
echo [ok] control URL reachable >> "%RESULT%"

for %%P in (1 2 3 4 5 6) do (
    echo --- preset %%P --- >> "%RESULT%"
    start "" /min /b bin\dbdpi.exe --preset=%%P --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt --timeout=20 --log="%LOG%"
    ping -n 3 127.0.0.1 >nul
    curl -sS -o nul -m 12 %TARGET% >> "%RESULT%" 2>&1
    if errorlevel 1 (
        echo     preset %%P: FAIL >> "%RESULT%"
    ) else (
        echo     preset %%P: OK >> "%RESULT%"
    )
    taskkill /f /im dbdpi.exe >nul 2>&1
    ping -n 2 127.0.0.1 >nul
)

echo --- done --- >> "%RESULT%"
echo. 
echo ============ RESULTS ============
type "%RESULT%"
echo.
echo Working preset? Add it to profiles or service.args.
pause
