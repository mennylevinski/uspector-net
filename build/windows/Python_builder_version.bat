@echo off
REM === Build Uspector.exe ===
cd /d "%~dp0"
setlocal enabledelayedexpansion

REM --- Clean previous build ---
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist Uspector.spec del /q Uspector.spec


REM --- Ensure version.txt exists ---
if not exist version.txt (
    echo [!] version.txt not found! Cannot embed version info.
    pause
    exit /b 1
)

REM --- Remove old EXE if exists ---
if exist dist\Uspector.exe del /q dist\Uspector.exe

echo [*] Building Uspector.exe with PyInstaller...
REM --- Removed --icon option to use default Python icon ---
call pyinstaller --onefile --windowed --version-file=version.txt Uspector.py

if %ERRORLEVEL% neq 0 (
    echo [!] Build failed. Check output above.
    pause
    exit /b 1
) else (
    echo [*] Build complete! EXE is in dist\Uspector.exe
)

pause
