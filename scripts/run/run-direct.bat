@echo off

echo ============================================
echo   Zamrud OS - Direct FAT Boot (AHCI + Disk)
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

REM Check for persistent disk
set DISK_OPTS=
if exist "disks\system.qcow2" (
    echo Disk: disks\system.qcow2 [AHCI/SATA]
    set DISK_OPTS=-device ahci,id=ahci0 -drive file=disks\system.qcow2,format=qcow2,if=none,id=sata0 -device ide-hd,drive=sata0,bus=ahci0.0
) else (
    echo Disk: None
    echo   Run 'scripts\run\create-disk.bat' to create virtual disk
)

echo Starting Zamrud OS (FAT mode)...
echo Network: E1000
echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -drive format=raw,file=fat:rw:build\direct ^
    %DISK_OPTS% ^
    -m 256M ^
    -serial stdio ^
    -cpu qemu64,+rdrand ^
    -no-reboot ^
    -no-shutdown ^
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 ^
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
    -netdev user,id=net0

REM ============================================
REM Boot:    FAT directory (build\direct)
REM Storage: AHCI/SATA (disks\system.qcow2)
REM Network: E1000
REM
REM Fallback (IDE mode):
REM   Replace DISK_OPTS with:
REM   set DISK_OPTS=-drive file=disks\system.qcow2,format=qcow2,if=ide
REM ============================================