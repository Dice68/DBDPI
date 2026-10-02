@echo off
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

(
    echo --dpi-desync=multisplit --split-pos=midsld
    echo --hostlist="%~dp0..\lists\hostlist.txt"
    echo --hostlist-exclude="%~dp0..\lists\hostlist-exclude.txt"
    echo --log="%~dp0..\bin\dbdpi-service.log"
) > "%~dp0service.args"

bin\dbdpi.exe --install-service="%~dp0service.args"
if errorlevel 1 (
    echo [!] service install failed
    pause
    exit /b 1
)
net start DBDPI
echo [ok] DBDPI service installed and started. Remove with service_remove.cmd
pause
