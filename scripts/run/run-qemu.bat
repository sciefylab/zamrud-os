@echo off

echo ============================================
echo   Zamrud OS - QEMU Runner (SMP + USB + NIC)
echo   B2.9: Auto-detect CPUs + APIC
echo   B2.10: AC97 Audio (dsound)
echo   B2.11c: USB HID (Keyboard + Mouse)
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
echo Audio (B2.10):
echo   AC97: Intel ICH (PCI, I/O Port, IRQ10)
echo   Backend: DirectSound (host speaker output)
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
    -device usb-kbd,bus=usb-bus1.0 ^
    -device usb-mouse,bus=usb-bus0.0 ^
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 ^
    -netdev user,id=net0,hostfwd=tcp::8080-:80 ^
    -device rtl8139,netdev=net1,mac=52:54:00:12:34:57 ^
    -netdev user,id=net1,hostfwd=tcp::8081-:81 ^
    -device virtio-net-pci,netdev=net2,mac=52:54:00:12:34:58 ^
    -netdev user,id=net2,hostfwd=tcp::8082-:82 ^
    -device AC97,audiodev=audio0 ^
    -audiodev dsound,id=audio0

REM ============================================
REM AUDIO BACKEND OPTIONS:
REM
REM   DirectSound (Windows, live speaker):
REM     -audiodev dsound,id=audio0
REM
REM   SDL (Windows/Linux, live speaker):
REM     -audiodev sdl,id=audio0
REM
REM   WAV file (record to file, no speaker):
REM     -audiodev wav,id=audio0,path=audio_out.wav
REM
REM   PulseAudio (Linux):
REM     -audiodev pa,id=audio0
REM
REM ============================================
REM B2.11c USB Configuration:
REM
REM   UHCI (usb-bus0): usb-mouse (boot protocol)
REM   EHCI (usb-bus1): usb-kbd   (boot protocol)
REM
REM   Only 1 HID device per controller (QEMU addr=0 limit)
REM
REM ============================================
REM B2.9 SMP Auto-Detection:
REM   Uses %NUMBER_OF_PROCESSORS% from Windows
REM   Caps at 8 CPUs (QEMU practical limit)
REM   Memory scales: 128MB + 32MB per CPU
REM ============================================