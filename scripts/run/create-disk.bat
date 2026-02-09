@echo off

echo ============================================
echo   Zamrud OS - Create Virtual Disk
echo ============================================

set SCRIPT_DIR=%~dp0
set DISK_DIR=%SCRIPT_DIR%..\..\disks
set DISK_FILE=%DISK_DIR%\system.qcow2
set DISK_SIZE=100M

REM Create disks folder if not exists
if not exist "%DISK_DIR%" (
    echo Creating disks folder...
    mkdir "%DISK_DIR%"
)

REM Check if disk already exists
if exist "%DISK_FILE%" (
    echo.
    echo Disk already exists: %DISK_FILE%
    echo.
    choice /C YN /M "Delete and recreate"
    if errorlevel 2 goto :end
    del "%DISK_FILE%"
)

echo.
echo Creating %DISK_SIZE% virtual disk...
qemu-img create -f qcow2 "%DISK_FILE%" %DISK_SIZE%

if %errorlevel% equ 0 (
    echo.
    echo ============================================
    echo   SUCCESS!
    echo   Disk: %DISK_FILE%
    echo   Size: %DISK_SIZE%
    echo ============================================
    echo.
    echo Now run: scripts\run\run-qemu.bat
) else (
    echo.
    echo ERROR: Failed to create disk
    echo Make sure qemu-img is in PATH
    exit /b 1
)

:end