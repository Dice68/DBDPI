@echo off
setlocal
cd /d "%~dp0"
curl -L -o windivert.zip https://reqrypt.org/download/WinDivert-2.2.2-A.zip
if errorlevel 1 (
    echo [!] download failed - get it manually from https://reqrypt.org/windivert.html
    exit /b 1
)
if not exist windivert mkdir windivert
tar -xf windivert.zip -C windivert
echo [ok] extracted to tools\windivert\
