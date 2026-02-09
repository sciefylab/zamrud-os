@echo off

echo ============================================
echo   Zamrud OS - QEMU Runner (Dual NIC + Disk)
echo ============================================

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..\..
set ISO=%ROOT_DIR%\build\zamrud-os.iso
set DISK=%ROOT_DIR%\disks\system.qcow2

if not exist "%ISO%" (
    echo ERROR: ISO not found!
    echo Run 'zig build' first.
    exit /b 1
)

echo Starting Zamrud OS...
echo Network: E1000 (eth0) + VirtIO (eth1)

REM Check if disk exists
set DISK_OPTS=
if exist "%DISK%" (
    echo Disk: system.qcow2 [ATTACHED]
    set DISK_OPTS=-drive file=%DISK%,format=qcow2,if=ide
) else (
    echo Disk: None
    echo   Run 'scripts\run\create-disk.bat' to create virtual disk
)

echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -cdrom "%ISO%" ^
    -boot d ^
    %DISK_OPTS% ^
    -m 256M ^
    -serial stdio ^
    -cpu qemu64,+rdrand ^
    -no-shutdown ^
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 ^
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
    -netdev user,id=net0,hostfwd=tcp::8080-:80 ^
    -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57 ^
    -netdev user,id=net1

REM ============================================
REM Network Interfaces:
REM   eth0 (E1000):   10.0.2.15 (default)
REM   eth1 (VirtIO):  10.0.2.15 (secondary)
REM   Gateway:        10.0.2.2
REM   DNS Server:     10.0.2.3
REM
REM Storage:
REM   IDE Primary:    disks/system.qcow2
REM
REM Port Forwarding:
REM   Host 8080 -> Guest 80
REM
REM Debug:
REM   isa-debug-exit on port 0xF4 for clean shutdown
REM ============================================