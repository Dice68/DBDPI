@echo off
setlocal
cd /d "%~dp0"
set URL=https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-14.0.0-ucrt-r2/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r2.zip
set ZIP=winlibs-mingw64.zip

if exist mingw64\bin\gcc.exe (
    echo [ok] tools\mingw64 already present
    exit /b 0
)

echo Downloading %URL%
curl -L -o "%ZIP%" "%URL%"
if errorlevel 1 (
    echo [!] download failed - get mingw-w64 manually from https://winlibs.com
    exit /b 1
)

echo Extracting...
if exist _mingw_tmp rmdir /s /q _mingw_tmp
mkdir _mingw_tmp
tar -xf "%ZIP%" -C _mingw_tmp
if errorlevel 1 (
    echo [!] extraction failed
    exit /b 1
)

if exist _mingw_tmp\mingw64 (
    move _mingw_tmp\mingw64 mingw64 >nul
) else (
    echo [!] unexpected archive layout - unpack %ZIP% into tools\mingw64 manually
    exit /b 1
)
rmdir /s /q _mingw_tmp
del "%ZIP%"

if not exist mingw64\bin\gcc.exe (
    echo [!] gcc not found after extraction
    exit /b 1
)
echo [ok] mingw-w64 installed into tools\mingw64
