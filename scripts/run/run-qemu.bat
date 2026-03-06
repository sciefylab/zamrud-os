@echo off

echo ============================================
echo   Zamrud OS - QEMU Runner (SMP + USB + NIC)
echo   B2.9: Auto-detect CPUs + APIC
echo   B2.11: USB Controllers + Devices
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

REM ============================================
REM Auto-detect CPU cores (max 8 for QEMU)
REM ============================================
set /a CPU_CORES=%NUMBER_OF_PROCESSORS%
if %CPU_CORES% GTR 8 set CPU_CORES=8
if %CPU_CORES% LSS 1 set CPU_CORES=2

REM Calculate memory based on CPU count
set /a MEM_MB=128 + (%CPU_CORES% * 32)
if %MEM_MB% GTR 512 set MEM_MB=512

echo.
echo CPU Configuration (B2.9 SMP - Auto-detected):
echo   Host CPUs:  %NUMBER_OF_PROCESSORS%
echo   Guest CPUs: %CPU_CORES% (max 8)
echo   Memory:     %MEM_MB%MB
echo   APIC:       Enabled (multi-core scheduling)
echo.
echo USB Controllers + Devices (B2.11):
echo   usb-bus0: PIIX3 UHCI  (USB 1.1, 12 Mbps)
echo     +-- USB Storage Test (if available)
echo   usb-bus1: ICH9 EHCI   (USB 2.0, 480 Mbps)
echo     +-- USB Tablet        (absolute mouse)
echo.
echo Input:
echo   Keyboard: PS/2 (default, working)
echo   Mouse:    PS/2 + USB Tablet
echo.
echo Network Interfaces:
echo   eth0: Intel E1000     (Gigabit, MMIO)
echo   eth1: Realtek RTL8139 (Fast Ethernet, I/O Port)
echo   eth2: VirtIO-Net      (Paravirtualized, High Performance)
echo.

REM Check if disk exists
set DISK_OPTS=
if exist "%DISK%" (
    echo Disk: system.qcow2 [AHCI/SATA]
    set DISK_OPTS=-device ahci,id=ahci0 -drive file=%DISK%,format=qcow2,if=none,id=sata0 -device ide-hd,drive=sata0,bus=ahci0.0
) else (
    echo Disk: None
    echo   Run 'scripts\run\create-disk.bat' to create virtual disk
)

echo.
echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -cdrom "%ISO%" ^
    -boot d ^
    %DISK_OPTS% ^
    -m %MEM_MB%M ^
    -smp %CPU_CORES%,cores=%CPU_CORES%,threads=1,sockets=1 ^
    -cpu qemu64,+rdrand ^
    -serial stdio ^
    -no-shutdown ^
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 ^
    -device piix3-usb-uhci,id=usb-bus0 ^
    -device usb-ehci,id=usb-bus1 ^
    -device usb-tablet,bus=usb-bus1.0 ^
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
    -netdev user,id=net0,hostfwd=tcp::8080-:80 ^
    -device rtl8139,netdev=net1,mac=52:54:00:12:34:57 ^
    -netdev user,id=net1,hostfwd=tcp::8081-:81 ^
    -device virtio-net-pci,netdev=net2,mac=52:54:00:12:34:58 ^
    -netdev user,id=net2,hostfwd=tcp::8082-:82


REM ============================================
REM B2.11 USB Configuration:
REM   piix3-usb-uhci: USB 1.1 controller (UHCI)
REM   usb-ehci:       USB 2.0 controller (EHCI)
REM
REM To add virtual USB devices for testing:
REM   -device usb-kbd,bus=usb0.0      (USB Keyboard)
REM   -device usb-mouse,bus=usb0.0    (USB Mouse)
REM   -device usb-tablet,bus=usb1.0   (USB Tablet - absolute positioning)
REM   -device usb-storage,drive=usbdisk (USB Flash Drive)
REM
REM Example with USB keyboard and mouse:
REM   qemu-system-x86_64 ... ^
REM     -device piix3-usb-uhci,id=usb0 ^
REM     -device usb-kbd,bus=usb0.0 ^
REM     -device usb-mouse,bus=usb0.0
REM
REM ============================================
REM B2.9 SMP Auto-Detection:
REM   Uses %NUMBER_OF_PROCESSORS% from Windows
REM   Caps at 8 CPUs (QEMU practical limit)
REM   Memory scales: 128MB + 32MB per CPU
REM ============================================