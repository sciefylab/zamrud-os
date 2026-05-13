@echo off
setlocal enabledelayedexpansion

echo ============================================
echo   Zamrud OS - QEMU Runner (SMP + USB + NIC)
echo   B2.9:  Auto-detect CPUs + APIC
echo   B2.10: AC97 Audio (wav)
echo   B2.10b Intel HDA Audio (SDL Live)
echo   B2.11c: USB HID (Keyboard + Mouse)
echo ============================================

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..\..

REM Convert to short 8.3 path (no spaces, no quote issues)
for %%I in ("%ROOT_DIR%\build\zamrud-os.iso") do set ISO=%%~sI
for %%I in ("%ROOT_DIR%\disks\system.qcow2")  do set DISK=%%~sI
for %%I in ("%ROOT_DIR%\audio_out.wav")       do set WAV=%%~sI

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

set /a MEM_MB=128 + (%CPU_CORES% * 32)
if %MEM_MB% GTR 512 set MEM_MB=512

echo.
echo CPU Configuration (B2.9 SMP - Auto-detected):
echo   Host CPUs:  %NUMBER_OF_PROCESSORS%
echo   Guest CPUs: %CPU_CORES% (max 8)
echo   Memory:     %MEM_MB%MB
echo   APIC:       Enabled (multi-core scheduling)
echo.
echo USB Controllers + Devices (B2.11c):
echo   usb-bus0: PIIX3 UHCI  (USB 1.1, 12 Mbps)
echo     +-- USB Mouse         (boot protocol, relative)
echo   usb-bus1: ICH9 EHCI   (USB 2.0, 480 Mbps)
echo     +-- USB Keyboard      (boot protocol)
echo.
echo Input:
echo   Keyboard: PS/2 + USB (both active)
echo   Mouse:    PS/2 (IRQ12) + USB Mouse (UHCI)
echo.
echo Network Interfaces:
echo   eth0: Intel E1000     (Gigabit, MMIO)
echo   eth1: Realtek RTL8139 (Fast Ethernet, I/O Port)
echo   eth2: VirtIO-Net      (Paravirtualized, High Performance)
echo.
echo Audio (B2.10b):
echo   Device:  Intel HDA (ICH6, MMIO, hda-micro)
echo   Backend: SDL (Live Speaker)
echo.

REM ============================================
REM Disk options — build as separate lines
REM (avoid inline variable with spaces in ^ block)
REM ============================================
set DISK_A=
set DISK_B=
set DISK_C=
if exist "%DISK%" (
    echo Disk: %DISK% [AHCI/SATA]
    set DISK_A=-device ahci,id=ahci0
    set DISK_B=-drive file=%DISK%,format=qcow2,if=none,id=sata0
    set DISK_C=-device ide-hd,drive=sata0,bus=ahci0.0
) else (
    echo Disk: None
    echo   Run 'scripts\run\create-disk.bat' to create virtual disk
)

echo.
echo Press Ctrl+C to exit
echo.

qemu-system-x86_64 ^
    -cdrom %ISO% ^
    -boot d ^
    %DISK_A% %DISK_B% %DISK_C% ^
    -m %MEM_MB%M ^
    -smp %CPU_CORES%,cores=%CPU_CORES%,threads=1,sockets=1 ^
    -cpu qemu64,+rdrand ^
    -serial stdio ^
    -no-shutdown ^
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 ^
    -device piix3-usb-uhci,id=usb-bus0 ^
    -device usb-ehci,id=usb-bus1 ^
    -device usb-kbd,bus=usb-bus1.0 ^
    -device usb-mouse,bus=usb-bus0.0 ^
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
    -netdev user,id=net0,hostfwd=tcp::8080-:80 ^
    -device rtl8139,netdev=net1,mac=52:54:00:12:34:57 ^
    -netdev user,id=net1,hostfwd=tcp::8081-:81 ^
    -device virtio-net-pci,netdev=net2,mac=52:54:00:12:34:58 ^
    -netdev user,id=net2,hostfwd=tcp::8082-:82 ^
    -device intel-hda,id=hda0 ^
    -device hda-micro,bus=hda0.0,audiodev=audio0 ^
    -audiodev sdl,id=audio0

REM ============================================
REM ALTERNATIVE: AC97 (B2.10) — QEMU only
REM Uncomment block below and comment HDA block above
REM
REM qemu-system-x86_64 ^
REM     -cdrom %ISO% ^
REM     -boot d ^
REM     %DISK_A% %DISK_B% %DISK_C% ^
REM     -m %MEM_MB%M ^
REM     -smp %CPU_CORES%,cores=%CPU_CORES%,threads=1,sockets=1 ^
REM     -cpu qemu64,+rdrand ^
REM     -serial stdio ^
REM     -no-shutdown ^
REM     -device isa-debug-exit,iobase=0xf4,iosize=0x04 ^
REM     -device piix3-usb-uhci,id=usb-bus0 ^
REM     -device usb-ehci,id=usb-bus1 ^
REM     -device usb-kbd,bus=usb-bus1.0 ^
REM     -device usb-mouse,bus=usb-bus0.0 ^
REM     -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
REM     -netdev user,id=net0,hostfwd=tcp::8080-:80 ^
REM     -device rtl8139,netdev=net1,mac=52:54:00:12:34:57 ^
REM     -netdev user,id=net1,hostfwd=tcp::8081-:81 ^
REM     -device virtio-net-pci,netdev=net2,mac=52:54:00:12:34:58 ^
REM     -netdev user,id=net2,hostfwd=tcp::8082-:82 ^
REM     -device AC97,audiodev=audio0 ^
REM     -audiodev wav,id=audio0,path=%WAV%