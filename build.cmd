@echo off
setlocal
cd /d "%~dp0"

set WD=%~dp0tools\windivert\WinDivert-2.2.2-A

set GCC=%~dp0tools\mingw64\bin\gcc.exe
if not exist "%GCC%" (
    where gcc >nul 2>&1
    if errorlevel 1 (
        echo [!] gcc not found: put mingw-w64 into tools\mingw64, run
        echo     tools\download_mingw.cmd, or install it into PATH
        exit /b 1
    )
    set GCC=gcc
)
if not exist "%WD%\include\windivert.h" (
    echo [!] WinDivert not found in tools\windivert - run tools\download_windivert.cmd
    exit /b 1
)

if not exist bin mkdir bin

"%GCC%" -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter ^
    -DWIN32_LEAN_AND_MEAN ^
    -I"%WD%\include" ^
    -o bin\dbdpi.exe ^
    src\main.c src\divert.c src\desync.c src\fakegen.c src\parse_tls.c ^
    src\parse_http.c src\hostlist.c src\conntrack.c src\log.c src\selftest.c ^
    "%WD%\x64\WinDivert.lib" -lws2_32
if errorlevel 1 (
    echo [!] build failed
    exit /b 1
)

copy /y "%WD%\x64\WinDivert.dll" bin\ >nul 2>nul
copy /y "%WD%\x64\WinDivert64.sys" bin\ >nul 2>nul
if not exist bin\WinDivert.dll echo [!] could not copy WinDivert.dll (file in use?)
if not exist bin\WinDivert64.sys echo [!] could not copy WinDivert64.sys (file in use?)

echo [ok] bin\dbdpi.exe built
bin\dbdpi.exe --version
