//! Zamrud OS - Local APIC & I/O APIC Driver
//! B2.9a: APIC initialization for SMP support
//!
//! Local APIC: Per-CPU interrupt controller
//! I/O APIC: Routes external IRQs to CPUs
//! Replaces legacy 8259 PIC for multi-core operation

const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");
const pmm = @import("../../mm/pmm.zig");
const acpi = @import("../../drivers/acpi/acpi.zig");

// ============================================================================
// MSR Addresses
// ============================================================================

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const IA32_APIC_BASE_ENABLE: u64 = 1 << 11;
const IA32_APIC_BASE_BSP: u64 = 1 << 8;
const IA32_APIC_BASE_ADDR_MASK: u64 = 0xFFFFF000;

// ============================================================================
// Local APIC Register Offsets (memory-mapped)
// ============================================================================

const LAPIC_ID: u32 = 0x020;
const LAPIC_VERSION: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080; // Task Priority
const LAPIC_APR: u32 = 0x090; // Arbitration Priority
const LAPIC_PPR: u32 = 0x0A0; // Processor Priority
const LAPIC_EOI: u32 = 0x0B0; // End of Interrupt
const LAPIC_RRD: u32 = 0x0C0; // Remote Read
const LAPIC_LDR: u32 = 0x0D0; // Logical Destination
const LAPIC_DFR: u32 = 0x0E0; // Destination Format
const LAPIC_SVR: u32 = 0x0F0; // Spurious Interrupt Vector
const LAPIC_ISR_BASE: u32 = 0x100; // In-Service (8 registers)
const LAPIC_TMR_BASE: u32 = 0x180; // Trigger Mode (8 registers)
const LAPIC_IRR_BASE: u32 = 0x200; // Interrupt Request (8 registers)
const LAPIC_ESR: u32 = 0x280; // Error Status
const LAPIC_ICR_LO: u32 = 0x300; // Interrupt Command (low)
const LAPIC_ICR_HI: u32 = 0x310; // Interrupt Command (high)
const LAPIC_TIMER_LVT: u32 = 0x320; // Timer LVT
const LAPIC_THERMAL_LVT: u32 = 0x330;
const LAPIC_PERF_LVT: u32 = 0x340;
const LAPIC_LINT0_LVT: u32 = 0x350;
const LAPIC_LINT1_LVT: u32 = 0x360;
const LAPIC_ERROR_LVT: u32 = 0x370;
const LAPIC_TIMER_ICR: u32 = 0x380; // Timer Initial Count
const LAPIC_TIMER_CCR: u32 = 0x390; // Timer Current Count
const LAPIC_TIMER_DCR: u32 = 0x3E0; // Timer Divide Config

// SVR bits
const SVR_ENABLE: u32 = 1 << 8;
const SVR_SPURIOUS_VEC: u32 = 0xFF; // Spurious vector = 255

// ICR delivery modes
const ICR_FIXED: u32 = 0x00000000;
const ICR_INIT: u32 = 0x00000500;
const ICR_STARTUP: u32 = 0x00000600;
const ICR_LEVEL_ASSERT: u32 = 0x00004000;
const ICR_LEVEL_DEASSERT: u32 = 0x00000000;
const ICR_TRIGGER_LEVEL: u32 = 0x00008000;
const ICR_DEST_ALL_EX: u32 = 0x000C0000;
const ICR_DEST_SELF: u32 = 0x00040000;

// Timer modes
const TIMER_PERIODIC: u32 = 1 << 17;
const TIMER_ONE_SHOT: u32 = 0;
const TIMER_MASKED: u32 = 1 << 16;

// Timer divide values
const TIMER_DIV_1: u32 = 0xB;
const TIMER_DIV_2: u32 = 0x0;
const TIMER_DIV_4: u32 = 0x1;
const TIMER_DIV_8: u32 = 0x2;
const TIMER_DIV_16: u32 = 0x3;
const TIMER_DIV_32: u32 = 0x8;
const TIMER_DIV_64: u32 = 0x9;
const TIMER_DIV_128: u32 = 0xA;

// ============================================================================
// I/O APIC Registers
// ============================================================================

const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;
const IOAPIC_REG_ARB: u32 = 0x02;
const IOAPIC_REG_REDTBL_BASE: u32 = 0x10; // Each entry is 2 registers (lo/hi)

// I/O APIC redirection entry flags
const IOAPIC_MASKED: u64 = 1 << 16;
const IOAPIC_LEVEL: u64 = 1 << 15;
const IOAPIC_LOW_ACTIVE: u64 = 1 << 13;
const IOAPIC_LOGICAL: u64 = 1 << 11;

// ============================================================================
// MADT (Multiple APIC Description Table) Structures
// ============================================================================

const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;
const MADT_TYPE_ISO: u8 = 2; // Interrupt Source Override
const MADT_TYPE_NMI: u8 = 3;
const MADT_TYPE_LOCAL_APIC_NMI: u8 = 4;
const MADT_TYPE_LOCAL_APIC_OVERRIDE: u8 = 5;
const MADT_TYPE_LOCAL_X2APIC: u8 = 9;

// ============================================================================
// State
// ============================================================================

pub const MAX_CPUS: usize = 16;
pub const MAX_IOAPICS: usize = 4;
pub const MAX_ISO: usize = 24;

/// Per-CPU Local APIC info from MADT
pub const CpuInfo = struct {
    acpi_id: u8 = 0,
    apic_id: u8 = 0,
    enabled: bool = false,
    is_bsp: bool = false,
    online: bool = false,
};

/// I/O APIC info from MADT
pub const IoApicInfo = struct {
    id: u8 = 0,
    address: u32 = 0,
    gsi_base: u32 = 0,
};

/// Interrupt Source Override from MADT
pub const IsoEntry = struct {
    bus: u8 = 0,
    source: u8 = 0, // ISA IRQ
    gsi: u32 = 0, // Global System Interrupt
    flags: u16 = 0,
};

// State variables
var initialized: bool = false;
var lapic_base_phys: u64 = 0;
var lapic_base_virt: u64 = 0;
var hhdm_offset: u64 = 0;

var cpu_count: usize = 0;
var cpus: [MAX_CPUS]CpuInfo = [_]CpuInfo{.{}} ** MAX_CPUS;
var bsp_apic_id: u8 = 0;

var ioapic_count: usize = 0;
var ioapics: [MAX_IOAPICS]IoApicInfo = [_]IoApicInfo{.{}} ** MAX_IOAPICS;

var iso_count: usize = 0;
var isos: [MAX_ISO]IsoEntry = [_]IsoEntry{.{}} ** MAX_ISO;

// APIC timer calibration
var apic_timer_frequency: u64 = 0;
var apic_timer_ticks_per_ms: u32 = 0;

// ============================================================================
// Local APIC Register Access
// ============================================================================

pub inline fn lapicRead(reg: u32) u32 {
    if (lapic_base_virt == 0) return 0;
    const ptr: *volatile u32 = @ptrFromInt(lapic_base_virt + reg);
    return ptr.*;
}

pub inline fn lapicWrite(reg: u32, value: u32) void {
    if (lapic_base_virt == 0) return;
    const ptr: *volatile u32 = @ptrFromInt(lapic_base_virt + reg);
    ptr.* = value;
}

// ============================================================================
// I/O APIC Register Access
// ============================================================================

fn ioapicRead(ioapic_addr: u64, reg: u32) u32 {
    const sel: *volatile u32 = @ptrFromInt(ioapic_addr);
    const data: *volatile u32 = @ptrFromInt(ioapic_addr + 0x10);
    sel.* = reg;
    return data.*;
}

fn ioapicWrite(ioapic_addr: u64, reg: u32, value: u32) void {
    const sel: *volatile u32 = @ptrFromInt(ioapic_addr);
    const data: *volatile u32 = @ptrFromInt(ioapic_addr + 0x10);
    sel.* = reg;
    data.* = value;
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init() bool {
    serial.writeString("[APIC] Initializing Local APIC & I/O APIC...\n");

    hhdm_offset = pmm.getHhdmOffset();

    // Step 1: Get LAPIC base address from MSR
    const apic_base_msr = cpu.rdmsr(IA32_APIC_BASE_MSR);
    lapic_base_phys = apic_base_msr & IA32_APIC_BASE_ADDR_MASK;
    lapic_base_virt = hhdm_offset + lapic_base_phys;

    const is_bsp = (apic_base_msr & IA32_APIC_BASE_BSP) != 0;

    serial.writeString("[APIC] LAPIC phys: 0x");
    printHex64(lapic_base_phys);
    serial.writeString(if (is_bsp) " (BSP)\n" else " (AP)\n");

    // Step 2: Read BSP APIC ID
    bsp_apic_id = @truncate(lapicRead(LAPIC_ID) >> 24);
    serial.writeString("[APIC] BSP APIC ID: ");
    printDec(bsp_apic_id);
    serial.writeString("\n");

    // Step 3: Parse MADT for CPU topology
    if (!parseMadt()) {
        serial.writeString("[APIC] No MADT found, single-CPU fallback\n");
        // Register BSP as only CPU
        cpus[0] = .{
            .acpi_id = 0,
            .apic_id = bsp_apic_id,
            .enabled = true,
            .is_bsp = true,
            .online = true,
        };
        cpu_count = 1;
    }

    // Step 4: Enable Local APIC
    enableLocalApic();

    // Step 5: Setup I/O APIC (route external IRQs)
    if (ioapic_count > 0) {
        setupIoApic();
    }

    // Step 6: Calibrate APIC timer
    calibrateTimer();

    // Print summary
    serial.writeString("[APIC] ─── CPU Topology ───\n");
    for (0..cpu_count) |i| {
        serial.writeString("[APIC]   CPU ");
        printDec(i);
        serial.writeString(": APIC_ID=");
        printDec(cpus[i].apic_id);
        if (cpus[i].is_bsp) serial.writeString(" (BSP)");
        if (cpus[i].enabled) serial.writeString(" [enabled]") else serial.writeString(" [disabled]");
        if (cpus[i].online) serial.writeString(" [online]");
        serial.writeString("\n");
    }
    serial.writeString("[APIC] ────────────────────\n");
    serial.writeString("[APIC] Total CPUs: ");
    printDec(cpu_count);
    serial.writeString(", I/O APICs: ");
    printDec(ioapic_count);
    serial.writeString(", ISOs: ");
    printDec(iso_count);
    serial.writeString("\n");

    if (apic_timer_ticks_per_ms > 0) {
        serial.writeString("[APIC] Timer: ");
        printDec(apic_timer_ticks_per_ms);
        serial.writeString(" ticks/ms\n");
    }

    initialized = true;
    serial.writeString("[APIC] Initialization complete\n");
    return true;
}

// ============================================================================
// Local APIC Enable
// ============================================================================

fn enableLocalApic() void {
    // Enable APIC in MSR
    var msr_val = cpu.rdmsr(IA32_APIC_BASE_MSR);
    msr_val |= IA32_APIC_BASE_ENABLE;
    cpu.wrmsr(IA32_APIC_BASE_MSR, msr_val);

    // Set spurious interrupt vector and enable APIC
    lapicWrite(LAPIC_SVR, SVR_ENABLE | SVR_SPURIOUS_VEC);

    // Clear task priority to accept all interrupts
    lapicWrite(LAPIC_TPR, 0);

    // Set logical destination (flat model)
    lapicWrite(LAPIC_DFR, 0xFFFFFFFF); // Flat model
    lapicWrite(LAPIC_LDR, (lapicRead(LAPIC_LDR) & 0x00FFFFFF) | (@as(u32, 1) << 24));

    serial.writeString("[APIC] Local APIC enabled, SVR=0x");
    printHex32(lapicRead(LAPIC_SVR));
    serial.writeString("\n");
}

/// Enable Local APIC on an AP (called by each AP during bootstrap)
pub fn enableLocalApicAP() void {
    var msr_val = cpu.rdmsr(IA32_APIC_BASE_MSR);
    msr_val |= IA32_APIC_BASE_ENABLE;
    cpu.wrmsr(IA32_APIC_BASE_MSR, msr_val);

    lapicWrite(LAPIC_SVR, SVR_ENABLE | SVR_SPURIOUS_VEC);
    lapicWrite(LAPIC_TPR, 0);
    lapicWrite(LAPIC_DFR, 0xFFFFFFFF);

    const apic_id = getCurrentApicId();
    lapicWrite(LAPIC_LDR, (lapicRead(LAPIC_LDR) & 0x00FFFFFF) | (@as(u32, @intCast(apic_id)) << 24));
}

// ============================================================================
// MADT Parsing
// ============================================================================

fn parseMadt() bool {
    const madt_phys = acpi.findTable(acpi.SIG_MADT) orelse return false;
    const madt_virt = hhdm_offset + madt_phys;

    // SDT header: 36 bytes
    // MADT specific: offset 36 = Local APIC Address (4 bytes)
    //                offset 40 = Flags (4 bytes)
    //                offset 44 = entries start

    const length = readU32At(madt_virt, 4);
    if (length < 44) {
        serial.writeString("[APIC] MADT too small\n");
        return false;
    }

    // Read Local APIC address override from MADT header
    const madt_lapic_addr = readU32At(madt_virt, 36);
    if (madt_lapic_addr != 0) {
        lapic_base_phys = madt_lapic_addr;
        lapic_base_virt = hhdm_offset + lapic_base_phys;
        serial.writeString("[APIC] MADT LAPIC addr: 0x");
        printHex64(lapic_base_phys);
        serial.writeString("\n");
    }

    const madt_flags = readU32At(madt_virt, 40);
    _ = madt_flags; // PC/AT dual-8259 flag

    // Parse MADT entries
    var offset: u64 = 44;
    while (offset + 2 <= length) {
        const entry_type = readU8At(madt_virt, offset);
        const entry_len = readU8At(madt_virt, offset + 1);

        if (entry_len < 2) break;
        if (offset + entry_len > length) break;

        switch (entry_type) {
            MADT_TYPE_LOCAL_APIC => {
                if (entry_len >= 8 and cpu_count < MAX_CPUS) {
                    const acpi_id = readU8At(madt_virt, offset + 2);
                    const apic_id = readU8At(madt_virt, offset + 3);
                    const flags = readU32At(madt_virt, offset + 4);
                    const enabled = (flags & 1) != 0 or (flags & 2) != 0;

                    cpus[cpu_count] = .{
                        .acpi_id = acpi_id,
                        .apic_id = apic_id,
                        .enabled = enabled,
                        .is_bsp = (apic_id == bsp_apic_id),
                        .online = (apic_id == bsp_apic_id),
                    };
                    cpu_count += 1;
                }
            },
            MADT_TYPE_IO_APIC => {
                if (entry_len >= 12 and ioapic_count < MAX_IOAPICS) {
                    ioapics[ioapic_count] = .{
                        .id = readU8At(madt_virt, offset + 2),
                        .address = readU32At(madt_virt, offset + 4),
                        .gsi_base = readU32At(madt_virt, offset + 8),
                    };
                    serial.writeString("[APIC] I/O APIC #");
                    printDec(ioapic_count);
                    serial.writeString(" addr=0x");
                    printHex32(ioapics[ioapic_count].address);
                    serial.writeString(" GSI_base=");
                    printDec(ioapics[ioapic_count].gsi_base);
                    serial.writeString("\n");
                    ioapic_count += 1;
                }
            },
            MADT_TYPE_ISO => {
                if (entry_len >= 10 and iso_count < MAX_ISO) {
                    isos[iso_count] = .{
                        .bus = readU8At(madt_virt, offset + 2),
                        .source = readU8At(madt_virt, offset + 3),
                        .gsi = readU32At(madt_virt, offset + 4),
                        .flags = readU16At(madt_virt, offset + 8),
                    };
                    serial.writeString("[APIC] ISO: IRQ");
                    printDec(isos[iso_count].source);
                    serial.writeString(" -> GSI ");
                    printDec(isos[iso_count].gsi);
                    serial.writeString("\n");
                    iso_count += 1;
                }
            },
            MADT_TYPE_LOCAL_APIC_OVERRIDE => {
                if (entry_len >= 12) {
                    lapic_base_phys = readU64At(madt_virt, offset + 4);
                    lapic_base_virt = hhdm_offset + lapic_base_phys;
                    serial.writeString("[APIC] LAPIC override: 0x");
                    printHex64(lapic_base_phys);
                    serial.writeString("\n");
                }
            },
            else => {},
        }

        offset += entry_len;
    }

    return cpu_count > 0;
}

// ============================================================================
// I/O APIC Setup
// ============================================================================

fn setupIoApic() void {
    if (ioapic_count == 0) return;

    const ioapic_virt = hhdm_offset + ioapics[0].address;

    const ver = ioapicRead(ioapic_virt, IOAPIC_REG_VER);
    const max_redir = ((ver >> 16) & 0xFF) + 1;

    serial.writeString("[APIC] I/O APIC version: ");
    printDec(ver & 0xFF);
    serial.writeString(", max redirections: ");
    printDec(max_redir);
    serial.writeString("\n");

    // Mask all interrupts first
    for (0..max_redir) |i| {
        const reg_lo: u32 = IOAPIC_REG_REDTBL_BASE + @as(u32, @intCast(i)) * 2;
        const reg_hi: u32 = reg_lo + 1;
        ioapicWrite(ioapic_virt, reg_lo, @as(u32, @truncate(IOAPIC_MASKED)) | @as(u32, @intCast(32 + i)));
        ioapicWrite(ioapic_virt, reg_hi, @as(u32, @intCast(bsp_apic_id)) << 24);
    }

    // Route standard ISA IRQs
    routeIrq(0, 32); // IRQ0  - PIT Timer
    routeIrq(1, 33); // IRQ1  - Keyboard
    routeIrq(2, 34); // IRQ2  - Cascade (masked, tapi di-route supaya tidak spurious)
    routeIrq(5, 37); // IRQ5  - AC97 Audio ← TAMBAH INI
    routeIrq(9, 41); // IRQ9  - AC97 Audio (ACPI) ← TAMBAH INI
    routeIrq(10, 42); // IRQ10 - AC97 Audio (PCI) ← TAMBAH INI
    routeIrq(11, 43); // IRQ11 - AHCI/SATA
    routeIrq(12, 44); // IRQ12 - Mouse

    serial.writeString("[APIC] I/O APIC routing configured\n");
    serial.writeString("[APIC]   IRQ0  -> vector 32 (Timer)\n");
    serial.writeString("[APIC]   IRQ1  -> vector 33 (Keyboard)\n");
    serial.writeString("[APIC]   IRQ5  -> vector 37 (Audio)\n");
    serial.writeString("[APIC]   IRQ9  -> vector 41 (Audio)\n");
    serial.writeString("[APIC]   IRQ10 -> vector 42 (Audio)\n");
    serial.writeString("[APIC]   IRQ11 -> vector 43 (AHCI)\n");
    serial.writeString("[APIC]   IRQ12 -> vector 44 (Mouse)\n");
}

/// Route an ISA IRQ to a vector, checking for ISO overrides
fn routeIrq(irq: u8, vector: u8) void {
    if (ioapic_count == 0) return;

    const ioapic_virt = hhdm_offset + ioapics[0].address;

    // Check for Interrupt Source Override
    var gsi: u32 = irq;
    var flags: u16 = 0;

    for (0..iso_count) |i| {
        if (isos[i].source == irq) {
            gsi = isos[i].gsi;
            flags = isos[i].flags;
            break;
        }
    }

    // Build redirection entry
    var entry: u64 = vector;

    // Polarity
    const polarity = flags & 0x3;
    if (polarity == 3) {
        entry |= IOAPIC_LOW_ACTIVE; // Active low
    }

    // Trigger mode
    const trigger = (flags >> 2) & 0x3;
    if (trigger == 3) {
        entry |= IOAPIC_LEVEL; // Level triggered
    }

    // Destination: BSP APIC ID
    entry |= @as(u64, bsp_apic_id) << 56;

    // Write to I/O APIC redirection table
    const reg_lo: u32 = IOAPIC_REG_REDTBL_BASE + gsi * 2;
    const reg_hi: u32 = reg_lo + 1;

    ioapicWrite(ioapic_virt, reg_hi, @truncate(entry >> 32));
    ioapicWrite(ioapic_virt, reg_lo, @truncate(entry));
}

/// Route IRQ to specific CPU (for SMP load balancing)
pub fn routeIrqToCpu(irq: u8, vector: u8, target_apic_id: u8) void {
    if (ioapic_count == 0) return;

    const ioapic_virt = hhdm_offset + ioapics[0].address;
    var gsi: u32 = irq;
    var flags: u16 = 0;

    for (0..iso_count) |i| {
        if (isos[i].source == irq) {
            gsi = isos[i].gsi;
            flags = isos[i].flags;
            break;
        }
    }

    var entry: u64 = vector;
    const polarity = flags & 0x3;
    if (polarity == 3) entry |= IOAPIC_LOW_ACTIVE;
    const trigger = (flags >> 2) & 0x3;
    if (trigger == 3) entry |= IOAPIC_LEVEL;
    entry |= @as(u64, target_apic_id) << 56;

    const reg_lo: u32 = IOAPIC_REG_REDTBL_BASE + gsi * 2;
    const reg_hi: u32 = reg_lo + 1;
    ioapicWrite(ioapic_virt, reg_hi, @truncate(entry >> 32));
    ioapicWrite(ioapic_virt, reg_lo, @truncate(entry));
}

// ============================================================================
// APIC Timer
// ============================================================================

fn calibrateTimer() void {
    // Use PIT to calibrate APIC timer
    // PIT channel 2 gate + readback method

    // Set APIC timer divide to 16
    lapicWrite(LAPIC_TIMER_DCR, TIMER_DIV_16);

    // Start APIC timer with max count
    lapicWrite(LAPIC_TIMER_ICR, 0xFFFFFFFF);

    // Wait ~10ms using PIT
    pitSleep10ms();

    // Read how many ticks elapsed
    const elapsed = 0xFFFFFFFF - lapicRead(LAPIC_TIMER_CCR);

    // Stop timer
    lapicWrite(LAPIC_TIMER_LVT, TIMER_MASKED);

    // Calculate frequency: elapsed ticks in 10ms, so ticks/ms = elapsed/10
    apic_timer_ticks_per_ms = elapsed / 10;
    apic_timer_frequency = @as(u64, apic_timer_ticks_per_ms) * 1000;

    if (apic_timer_ticks_per_ms == 0) {
        serial.writeString("[APIC] Timer calibration failed, using default\n");
        apic_timer_ticks_per_ms = 100000; // Reasonable default
    }
}

fn pitSleep10ms() void {
    // PIT Channel 2 - one-shot mode for ~10ms
    // PIT frequency = 1193182 Hz, 10ms = 11932 counts
    const count: u16 = 11932;

    // Gate off, speaker off
    var gate = cpu.inb(0x61);
    gate &= 0xFD; // Clear bit 1 (speaker)
    gate |= 0x01; // Set bit 0 (gate)
    cpu.outb(0x61, gate);

    // Channel 2, mode 0 (one-shot), binary
    cpu.outb(0x43, 0xB0);
    cpu.outb(0x42, @truncate(count & 0xFF));
    cpu.outb(0x42, @truncate(count >> 8));

    // Reset gate to start countdown
    gate = cpu.inb(0x61);
    gate &= 0xFE; // Clear gate
    cpu.outb(0x61, gate);
    gate |= 0x01; // Set gate
    cpu.outb(0x61, gate);

    // Wait for output to go high (bit 5 of port 0x61)
    while ((cpu.inb(0x61) & 0x20) == 0) {
        cpu.pause();
    }
}

/// Start periodic APIC timer (called per-CPU)
pub fn startTimer(vector: u8, frequency_hz: u32) void {
    if (apic_timer_ticks_per_ms == 0) return;

    const ticks_per_interval = (apic_timer_ticks_per_ms * 1000) / frequency_hz;

    lapicWrite(LAPIC_TIMER_DCR, TIMER_DIV_16);
    lapicWrite(LAPIC_TIMER_LVT, TIMER_PERIODIC | @as(u32, vector));
    lapicWrite(LAPIC_TIMER_ICR, ticks_per_interval);
}

/// Stop APIC timer
pub fn stopTimer() void {
    lapicWrite(LAPIC_TIMER_LVT, TIMER_MASKED);
}

// ============================================================================
// EOI & IPI
// ============================================================================

/// Send End-of-Interrupt to Local APIC
pub fn sendEoi() void {
    lapicWrite(LAPIC_EOI, 0);
}

/// Send IPI (Inter-Processor Interrupt) to specific CPU
pub fn sendIpi(target_apic_id: u8, vector: u8) void {
    // Wait for previous IPI to complete
    while ((lapicRead(LAPIC_ICR_LO) & (1 << 12)) != 0) {
        cpu.pause();
    }

    // Set destination
    lapicWrite(LAPIC_ICR_HI, @as(u32, target_apic_id) << 24);
    // Send fixed IPI
    lapicWrite(LAPIC_ICR_LO, ICR_FIXED | @as(u32, vector));
}

/// Send IPI to all CPUs except self
pub fn sendIpiAllExSelf(vector: u8) void {
    while ((lapicRead(LAPIC_ICR_LO) & (1 << 12)) != 0) {
        cpu.pause();
    }
    lapicWrite(LAPIC_ICR_LO, ICR_FIXED | ICR_DEST_ALL_EX | @as(u32, vector));
}

/// Send INIT IPI to specific CPU
pub fn sendInitIpi(target_apic_id: u8) void {
    while ((lapicRead(LAPIC_ICR_LO) & (1 << 12)) != 0) {
        cpu.pause();
    }
    lapicWrite(LAPIC_ICR_HI, @as(u32, target_apic_id) << 24);
    lapicWrite(LAPIC_ICR_LO, ICR_INIT | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL);

    // Deassert
    busyWait(10000);
    lapicWrite(LAPIC_ICR_LO, ICR_INIT | ICR_LEVEL_DEASSERT | ICR_TRIGGER_LEVEL);
}

/// Send STARTUP IPI to specific CPU
pub fn sendStartupIpi(target_apic_id: u8, page: u8) void {
    while ((lapicRead(LAPIC_ICR_LO) & (1 << 12)) != 0) {
        cpu.pause();
    }
    lapicWrite(LAPIC_ICR_HI, @as(u32, target_apic_id) << 24);
    lapicWrite(LAPIC_ICR_LO, ICR_STARTUP | @as(u32, page));
}

// ============================================================================
// Disable Legacy PIC (8259)
// ============================================================================

pub fn disableLegacyPic() void {
    serial.writeString("[APIC] Disabling legacy 8259 PIC...\n");

    // Remap PIC to vectors 32-47 first (avoid conflicts with exceptions)
    cpu.outb(0x20, 0x11); // ICW1
    cpu.outb(0xA0, 0x11);
    cpu.outb(0x21, 0x20); // ICW2: master offset 32
    cpu.outb(0xA1, 0x28); // ICW2: slave offset 40
    cpu.outb(0x21, 0x04); // ICW3
    cpu.outb(0xA1, 0x02);
    cpu.outb(0x21, 0x01); // ICW4
    cpu.outb(0xA1, 0x01);

    // Mask all IRQs on both PICs
    cpu.outb(0x21, 0xFF);
    cpu.outb(0xA1, 0xFF);

    serial.writeString("[APIC] Legacy PIC disabled\n");
}

// ============================================================================
// Getters
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getCpuCount() usize {
    return cpu_count;
}

pub fn getEnabledCpuCount() usize {
    var count: usize = 0;
    for (0..cpu_count) |i| {
        if (cpus[i].enabled) count += 1;
    }
    return count;
}

pub fn getOnlineCpuCount() usize {
    var count: usize = 0;
    for (0..cpu_count) |i| {
        if (cpus[i].online) count += 1;
    }
    return count;
}

pub fn getCpuInfo(index: usize) ?CpuInfo {
    if (index >= cpu_count) return null;
    return cpus[index];
}

pub fn getBspApicId() u8 {
    return bsp_apic_id;
}

pub fn getCurrentApicId() u8 {
    return @truncate(lapicRead(LAPIC_ID) >> 24);
}

pub fn getCurrentCpuIndex() usize {
    const apic_id = getCurrentApicId();
    for (0..cpu_count) |i| {
        if (cpus[i].apic_id == apic_id) return i;
    }
    return 0; // Fallback to BSP
}

pub fn markCpuOnline(apic_id: u8) void {
    for (0..cpu_count) |i| {
        if (cpus[i].apic_id == apic_id) {
            cpus[i].online = true;
            return;
        }
    }
}

pub fn getTimerTicksPerMs() u32 {
    return apic_timer_ticks_per_ms;
}

// ============================================================================
// Safe Read Helpers (same pattern as ACPI)
// ============================================================================

inline fn readU8At(base: u64, offset: u64) u8 {
    const ptr: *const u8 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU16At(base: u64, offset: u64) u16 {
    const ptr: *align(1) const u16 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU32At(base: u64, offset: u64) u32 {
    const ptr: *align(1) const u32 = @ptrFromInt(base + offset);
    return ptr.*;
}

inline fn readU64At(base: u64, offset: u64) u64 {
    const ptr: *align(1) const u64 = @ptrFromInt(base + offset);
    return ptr.*;
}

fn busyWait(count: u32) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        cpu.pause();
    }
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@truncate((value >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex32(value: u32) void {
    const hex = "0123456789ABCDEF";
    const v: u64 = value;
    var i: u6 = 28;
    while (true) {
        serial.writeChar(hex[@truncate((v >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printDec(value: anytype) void {
    const v: u64 = @intCast(value);
    if (v == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
