@echo off

echo ============================================
echo   Zamrud OS - QEMU Runner (Dual NIC)
echo ============================================

if not exist "build\zamrud-os.iso" (
    echo ERROR: ISO not found!
    echo Run 'zig build iso' first.
    exit /b 1
)

echo Starting Zamrud OS...
echo Network: E1000 (eth0) + VirtIO (eth1)
echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -cdrom build\zamrud-os.iso ^
    -m 256M ^
    -serial stdio ^
    -cpu qemu64,+rdrand ^
    -no-reboot ^
    -no-shutdown ^
    -device e1000,netdev=net0 ^
    -netdev user,id=net0 ^
    -device virtio-net-pci,netdev=net1 ^
    -netdev user,id=net1

REM ============================================
REM Network Interfaces:
REM   eth0 (E1000):   10.0.2.15 (default)
REM   eth1 (VirtIO):  10.0.2.15 (secondary)
REM   Gateway:        10.0.2.2
REM   DNS Server:     10.0.2.3
REM ============================================