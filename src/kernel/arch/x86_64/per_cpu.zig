//! Zamrud OS - Per-CPU Data Structures
//! B2.9c: CPU-local storage for SMP
//! FIXED: Aligned stack allocation for APs

const serial = @import("../../drivers/serial/serial.zig");
const gdt = @import("gdt.zig");
const apic = @import("apic.zig");
const cpu_mod = @import("../../core/cpu.zig");
const pmm = @import("../../mm/pmm.zig");
const spinlock = @import("spinlock.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_CPUS = apic.MAX_CPUS;
const PER_CPU_STACK_SIZE: u64 = 16 * 1024; // 16KB per CPU
const PER_CPU_IST_SIZE: u64 = 8 * 1024; // 8KB IST per CPU
const STACK_ALIGNMENT: u64 = 16; // x86_64 requires 16-byte aligned stacks

// ============================================================================
// Per-CPU Data Block
// ============================================================================

pub const PerCpuData = struct {
    // Identity
    cpu_index: u32 = 0,
    apic_id: u8 = 0,
    is_bsp: bool = false,
    online: bool = false,

    // TSS for this CPU
    tss: gdt.TSS = .{},

    // Stacks
    kernel_stack_base: u64 = 0,
    kernel_stack_top: u64 = 0,
    ist_stack_base: u64 = 0,
    ist_stack_top: u64 = 0,
    syscall_stack_base: u64 = 0,
    syscall_stack_top: u64 = 0,

    // Scheduler state
    current_pid: u32 = 0,
    current_slot: usize = 0,
    idle_ticks: u64 = 0,
    switch_count: u64 = 0,
    preempt_pending: bool = false,
    in_switch: bool = false,

    // Timer
    timer_ticks: u64 = 0,
    preempt_counter: u64 = 0,

    // Padding to cache line boundary (avoid false sharing)
    _pad: [16]u8 = [_]u8{0} ** 16,
};

// ============================================================================
// Per-CPU Array (statically allocated)
// ============================================================================

var per_cpu_data: [MAX_CPUS]PerCpuData = [_]PerCpuData{.{}} ** MAX_CPUS;
var bsp_index: u32 = 0;
var initialized: bool = false;

// Per-CPU stacks (statically allocated for BSP, dynamically for APs)
var bsp_kernel_stack: [PER_CPU_STACK_SIZE]u8 align(16) = undefined;
var bsp_ist_stack: [PER_CPU_IST_SIZE]u8 align(16) = undefined;
var bsp_syscall_stack: [PER_CPU_STACK_SIZE]u8 align(16) = undefined;

// Static AP stacks (avoid heap alignment issues)
var ap_kernel_stacks: [MAX_CPUS][PER_CPU_STACK_SIZE]u8 align(16) = undefined;
var ap_ist_stacks: [MAX_CPUS][PER_CPU_IST_SIZE]u8 align(16) = undefined;
var ap_syscall_stacks: [MAX_CPUS][PER_CPU_STACK_SIZE]u8 align(16) = undefined;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[PERCPU] Initializing per-CPU data...\n");

    const cpu_count = apic.getCpuCount();
    const bsp_apic_id = apic.getBspApicId();

    // Setup BSP first
    for (0..cpu_count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;

        per_cpu_data[i].cpu_index = @intCast(i);
        per_cpu_data[i].apic_id = info.apic_id;
        per_cpu_data[i].is_bsp = info.is_bsp;

        if (info.apic_id == bsp_apic_id) {
            bsp_index = @intCast(i);

            // BSP uses static stacks
            per_cpu_data[i].kernel_stack_base = @intFromPtr(&bsp_kernel_stack);
            per_cpu_data[i].kernel_stack_top = @intFromPtr(&bsp_kernel_stack) + PER_CPU_STACK_SIZE;
            per_cpu_data[i].ist_stack_base = @intFromPtr(&bsp_ist_stack);
            per_cpu_data[i].ist_stack_top = @intFromPtr(&bsp_ist_stack) + PER_CPU_IST_SIZE;
            per_cpu_data[i].syscall_stack_base = @intFromPtr(&bsp_syscall_stack);
            per_cpu_data[i].syscall_stack_top = @intFromPtr(&bsp_syscall_stack) + PER_CPU_STACK_SIZE;
            per_cpu_data[i].online = true;

            // Setup TSS for BSP
            per_cpu_data[i].tss.rsp0 = per_cpu_data[i].kernel_stack_top;
            per_cpu_data[i].tss.ist1 = per_cpu_data[i].ist_stack_top;
            per_cpu_data[i].tss.iopb = @sizeOf(gdt.TSS);

            serial.writeString("[PERCPU] BSP (CPU ");
            printDec(i);
            serial.writeString("): stack=0x");
            printHex64(per_cpu_data[i].kernel_stack_top);
            serial.writeString("\n");
        }
    }

    initialized = true;
    serial.writeString("[PERCPU] Per-CPU data initialized for ");
    printDec(cpu_count);
    serial.writeString(" CPUs\n");
}

/// Allocate stacks for an AP (called before AP bootstrap)
/// FIXED: Use static arrays instead of heap to ensure alignment
pub fn allocApStacks(cpu_index: usize) bool {
    if (cpu_index >= MAX_CPUS) return false;
    if (cpu_index == 0) return true; // BSP already has stacks

    // Use pre-allocated static stacks (guaranteed 16-byte aligned)
    const kstack_base = @intFromPtr(&ap_kernel_stacks[cpu_index]);
    const kstack_top = kstack_base + PER_CPU_STACK_SIZE;

    const ist_base = @intFromPtr(&ap_ist_stacks[cpu_index]);
    const ist_top = ist_base + PER_CPU_IST_SIZE;

    const sstack_base = @intFromPtr(&ap_syscall_stacks[cpu_index]);
    const sstack_top = sstack_base + PER_CPU_STACK_SIZE;

    // Verify alignment
    if ((kstack_top & 0xF) != 0 or (ist_top & 0xF) != 0 or (sstack_top & 0xF) != 0) {
        serial.writeString("[PERCPU] ERROR: Stack alignment failed for CPU ");
        printDec(cpu_index);
        serial.writeString("\n");
        return false;
    }

    per_cpu_data[cpu_index].kernel_stack_base = kstack_base;
    per_cpu_data[cpu_index].kernel_stack_top = kstack_top;
    per_cpu_data[cpu_index].ist_stack_base = ist_base;
    per_cpu_data[cpu_index].ist_stack_top = ist_top;
    per_cpu_data[cpu_index].syscall_stack_base = sstack_base;
    per_cpu_data[cpu_index].syscall_stack_top = sstack_top;

    // Setup TSS
    per_cpu_data[cpu_index].tss.rsp0 = kstack_top;
    per_cpu_data[cpu_index].tss.ist1 = ist_top;
    per_cpu_data[cpu_index].tss.iopb = @sizeOf(gdt.TSS);

    serial.writeString("[PERCPU] AP ");
    printDec(cpu_index);
    serial.writeString(" stacks: kernel=0x");
    printHex64(kstack_top);
    serial.writeString(" ist=0x");
    printHex64(ist_top);
    serial.writeString("\n");

    return true;
}

// ============================================================================
// Accessors
// ============================================================================

/// Get per-CPU data for current CPU (uses APIC ID)
pub fn current() *PerCpuData {
    if (!initialized) return &per_cpu_data[0]; // Pre-init: assume BSP

    const idx = apic.getCurrentCpuIndex();
    return &per_cpu_data[idx];
}

/// Get per-CPU data by index
pub fn get(index: usize) *PerCpuData {
    if (index >= MAX_CPUS) return &per_cpu_data[0];
    return &per_cpu_data[index];
}

/// Get BSP per-CPU data
pub fn bsp() *PerCpuData {
    return &per_cpu_data[bsp_index];
}

/// Get current CPU index
pub fn currentIndex() usize {
    if (!initialized) return 0;
    return apic.getCurrentCpuIndex();
}

/// Get current CPU's APIC ID
pub fn currentApicId() u8 {
    if (!initialized) return 0;
    return apic.getCurrentApicId();
}

/// Is current CPU the BSP?
pub fn isBsp() bool {
    if (!initialized) return true;
    return current().is_bsp;
}

// ============================================================================
// Scheduler State (per-CPU)
// ============================================================================

pub fn getCurrentPid() u32 {
    return current().current_pid;
}

pub fn setCurrentPid(pid: u32) void {
    current().current_pid = pid;
}

pub fn getCurrentSlot() usize {
    return current().current_slot;
}

pub fn setCurrentSlot(slot: usize) void {
    current().current_slot = slot;
}

pub fn isInSwitch() bool {
    return @atomicLoad(bool, &current().in_switch, .acquire);
}

pub fn setInSwitch(val: bool) void {
    @atomicStore(bool, &current().in_switch, val, .release);
}

pub fn isPreemptPending() bool {
    return @atomicLoad(bool, &current().preempt_pending, .acquire);
}

pub fn setPreemptPending(val: bool) void {
    @atomicStore(bool, &current().preempt_pending, val, .release);
}

pub fn incrementSwitchCount() void {
    current().switch_count += 1;
}

pub fn incrementTimerTicks() void {
    current().timer_ticks += 1;
}

// ============================================================================
// Status
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getOnlineCount() usize {
    var count: usize = 0;
    for (0..MAX_CPUS) |i| {
        if (per_cpu_data[i].online) count += 1;
    }
    return count;
}

pub fn printStatus() void {
    serial.writeString("[PERCPU] ─── CPU Status ───\n");
    for (0..MAX_CPUS) |i| {
        if (per_cpu_data[i].apic_id != 0 or per_cpu_data[i].is_bsp) {
            serial.writeString("[PERCPU]   CPU ");
            printDec(i);
            serial.writeString(": APIC=");
            printDec(per_cpu_data[i].apic_id);
            if (per_cpu_data[i].is_bsp) serial.writeString(" BSP");
            if (per_cpu_data[i].online) serial.writeString(" [ONLINE]") else serial.writeString(" [OFFLINE]");
            serial.writeString(" switches=");
            printDec(per_cpu_data[i].switch_count);
            serial.writeString(" pid=");
            printDec(per_cpu_data[i].current_pid);
            serial.writeString("\n");
        }
    }
    serial.writeString("[PERCPU] ──────────────────\n");
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
