@echo off
setlocal
cd /d "%~dp0.."
set OUT=%~dp0elevated-test-result.txt
set LOG=%~dp0elevated-dbdpi.log

echo === DBDPI elevated test %date% %time% === > "%OUT%"
net session >nul 2>&1
if errorlevel 1 (
    echo RESULT: NOT ADMIN >> "%OUT%"
    exit /b 1
)

start "dbdpi" /min bin\dbdpi.exe --debug --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt --log="%LOG%"
ping -n 4 127.0.0.1 >nul
curl -sS -o nul -m 10 https://www.google.com/generate_204
echo passthrough google(204): rc=%errorlevel% >> "%OUT%"
taskkill /f /im dbdpi.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul

start "dbdpi" /min bin\dbdpi.exe --debug --preset=1 --hostlist=lists\hostlist.txt --hostlist-exclude=lists\hostlist-exclude.txt --log="%LOG%"
ping -n 4 127.0.0.1 >nul
curl -sS -o nul -m 12 https://www.youtube.com/generate_204
echo multisplit youtube: rc=%errorlevel% >> "%OUT%"
curl -sS -o nul -m 12 https://www.google.com/generate_204
echo multisplit google(control, not in hostlist): rc=%errorlevel% >> "%OUT%"
curl -sS -o nul -m 12 -x "" https://discord.com >>"%OUT%" 2>&1
taskkill /f /im dbdpi.exe >nul 2>&1
echo === done === >> "%OUT%"
exit /b 0
