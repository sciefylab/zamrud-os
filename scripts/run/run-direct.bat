@echo off

echo ============================================
echo   Zamrud OS - Direct FAT Boot
echo ============================================

if not exist "zig-out\bin\kernel" (
    echo ERROR: Kernel not found!
    echo Run 'zig build' first.
    exit /b 1
)

if not exist "tools\limine" (
    echo ERROR: tools\limine folder not found
    exit /b 1
)

if not exist "boot\limine.cfg" (
    echo ERROR: boot\limine.cfg not found
    exit /b 1
)

REM Setup direktori untuk QEMU FAT drive
if not exist "build\direct" mkdir build\direct
if not exist "build\direct\boot" mkdir build\direct\boot
if not exist "build\direct\boot\limine" mkdir build\direct\boot\limine

REM Copy files
copy /Y zig-out\bin\kernel build\direct\boot\kernel >nul
copy /Y boot\limine.cfg build\direct\limine.cfg >nul
copy /Y boot\limine.cfg build\direct\boot\limine\limine.cfg >nul
copy /Y tools\limine\limine-bios.sys build\direct\boot\limine\ >nul

echo Starting Zamrud OS (FAT mode)...
echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -drive format=raw,file=fat:rw:build\direct ^
    -m 256M ^
    -serial stdio ^
    -cpu qemu64,+rdrand ^
    -no-reboot ^
    -no-shutdown