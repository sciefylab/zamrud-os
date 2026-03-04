#!/bin/bash

echo "============================================"
echo "  Zamrud OS - QEMU Runner (SMP + Triple NIC)"
echo "  B2.9: Auto-detect CPUs + APIC"
echo "============================================"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/../.."
ISO="$ROOT_DIR/build/zamrud-os.iso"
DISK="$ROOT_DIR/disks/system.qcow2"

if [ ! -f "$ISO" ]; then
    echo "ERROR: ISO not found!"
    echo "Run 'zig build' first."
    exit 1
fi

# ============================================
# Auto-detect CPU cores
# ============================================
if [ -f /proc/cpuinfo ]; then
    # Linux
    HOST_CPUS=$(grep -c ^processor /proc/cpuinfo)
elif [ "$(uname)" == "Darwin" ]; then
    # macOS
    HOST_CPUS=$(sysctl -n hw.ncpu)
else
    HOST_CPUS=2
fi

# Manual override via argument
if [ -n "$1" ]; then
    CPU_CORES=$1
    echo "[INFO] Manual CPU override: $1 cores"
else
    CPU_CORES=$HOST_CPUS
fi

# Clamp to range 1-8
[ $CPU_CORES -gt 8 ] && CPU_CORES=8
[ $CPU_CORES -lt 1 ] && CPU_CORES=1

# Calculate memory
MEM_MB=$((128 + CPU_CORES * 32))
[ $MEM_MB -gt 512 ] && MEM_MB=512

# Build SMP options
SMP_OPTS=""
if [ $CPU_CORES -gt 1 ]; then
    SMP_OPTS="-smp $CPU_CORES,cores=$CPU_CORES,threads=1,sockets=1"
fi

echo ""
echo "CPU Configuration (B2.9 SMP):"
echo "  Host CPUs:  $HOST_CPUS"
echo "  Guest CPUs: $CPU_CORES"
if [ $CPU_CORES -gt 1 ]; then
    echo "  Mode:       SMP (multi-core)"
else
    echo "  Mode:       Single CPU"
fi
echo "  Memory:     ${MEM_MB}MB"
echo "  APIC:       Enabled"
echo ""

# Check disk
DISK_OPTS=""
if [ -f "$DISK" ]; then
    echo "Disk: system.qcow2 [AHCI/SATA]"
    DISK_OPTS="-device ahci,id=ahci0 -drive file=$DISK,format=qcow2,if=none,id=sata0 -device ide-hd,drive=sata0,bus=ahci0.0"
else
    echo "Disk: None"
fi

echo ""
echo "Usage: ./run-qemu.sh [cpu_count]"
echo "Press Ctrl+C to exit"
echo ""

qemu-system-x86_64 \
    -cdrom "$ISO" \
    -boot d \
    $DISK_OPTS \
    -m ${MEM_MB}M \
    $SMP_OPTS \
    -cpu qemu64,+rdrand,+x2apic \
    -serial stdio \
    -no-shutdown \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -netdev user,id=net0,hostfwd=tcp::8080-:80 \
    -device rtl8139,netdev=net1,mac=52:54:00:12:34:57 \
    -netdev user,id=net1,hostfwd=tcp::8081-:81 \
    -device virtio-net-pci,netdev=net2,mac=52:54:00:12:34:58 \
    -netdev user,id=net2,hostfwd=tcp::8082-:82