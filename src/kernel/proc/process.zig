//! Zamrud OS - Process Management

const serial = @import("../drivers/serial/serial.zig");
const heap = @import("../mm/heap.zig");
const switch_ctx = @import("../arch/x86_64/switch.zig");
const capability = @import("../security/capability.zig");
const unveil = @import("../security/unveil.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PROCESSES: usize = 64;
pub const MAX_SLOTS_USED: usize = 8;
pub const KERNEL_STACK_SIZE: u64 = 16 * 1024;

// ============================================================================
// Process State
// ============================================================================

pub const ProcessState = enum(u8) {
    Created = 0,
    Ready = 1,
    Running = 2,
    Blocked = 3,
    Terminated = 4,
};

// ============================================================================
// Process Control Block
// ============================================================================

pub const Process = struct {
    pid: u32 = 0,
    state: ProcessState = .Created,
    kernel_stack: u64 = 0,
    kernel_stack_top: u64 = 0,
    rsp: u64 = 0,
    priority: u8 = 0,
    time_slice: u32 = 0,
    total_ticks: u64 = 0,
    caps: u32 = capability.CAP_ALL,
};

// ============================================================================
// Globals
// ============================================================================

pub var process_table: [MAX_PROCESSES]Process = [_]Process{.{}} ** MAX_PROCESSES;
pub var process_used: [MAX_PROCESSES]bool = [_]bool{false} ** MAX_PROCESSES;

var current_pid: u32 = 0;
var next_pid: u32 = 1;
var process_count: u32 = 0;
var initialized: bool = false;

// ============================================================================
// Init
// ============================================================================

pub fn init() void {
    serial.writeString("[PROC] Initializing...\n");

    var i: usize = 0;
    while (i < MAX_PROCESSES) : (i += 1) {
        process_used[i] = false;
        process_table[i] = .{
            .pid = 0,
            .state = .Created,
            .kernel_stack = 0,
            .kernel_stack_top = 0,
            .rsp = 0,
            .priority = 0,
            .time_slice = 0,
            .total_ticks = 0,
            .caps = capability.CAP_NONE,
        };
    }

    current_pid = 0;
    next_pid = 1;
    process_count = 0;
    initialized = true;

    serial.writeString("[PROC] Initialized!\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Slot helpers
// ============================================================================

fn findFreeSlot() ?usize {
    var slot: usize = 1;
    while (slot < MAX_SLOTS_USED) : (slot += 1) {
        if (!process_used[slot]) return slot;
    }
    return null;
}

pub fn getSlotByPid(pid: u32) ?usize {
    var i: usize = 0;
    while (i < MAX_SLOTS_USED) : (i += 1) {
        if (process_used[i] and process_table[i].pid == pid) return i;
    }
    return null;
}

// ============================================================================
// Create Process
// ============================================================================

pub fn create(entry: u64) ?u32 {
    return createWithEntry("unnamed", entry, 0);
}

pub fn createWithEntry(name: []const u8, entry: u64, arg: u64) ?u32 {
    return createWithCaps(name, entry, arg, capability.CAP_ALL);
}

pub fn createWithCaps(name: []const u8, entry: u64, arg: u64, caps: u32) ?u32 {
    _ = name;

    if (!initialized) {
        serial.writeString("[PROC] ERROR: Not initialized!\n");
        return null;
    }

    serial.writeString("[PROC] Create entry=0x");
    printHex64(entry);
    serial.writeString("\n");

    const slot = findFreeSlot() orelse {
        serial.writeString("[PROC] ERROR: No free slot!\n");
        return null;
    };

    const stack_ptr = heap.kmalloc(KERNEL_STACK_SIZE) orelse {
        serial.writeString("[PROC] ERROR: Stack allocation failed!\n");
        return null;
    };
    const stack_addr: u64 = @intFromPtr(stack_ptr);
    const stack_top: u64 = stack_addr + KERNEL_STACK_SIZE;

    const pid = next_pid;
    next_pid += 1;

    process_table[slot] = .{
        .pid = pid,
        .state = .Ready,
        .kernel_stack = stack_addr,
        .kernel_stack_top = stack_top,
        .rsp = 0,
        .priority = 1,
        .time_slice = 10,
        .total_ticks = 0,
        .caps = caps,
    };

    process_table[slot].rsp = switch_ctx.setupProcessStack(stack_top, entry, arg);

    process_used[slot] = true;
    process_count += 1;

    // E3.1: Register in capability system
    if (capability.isInitialized()) {
        _ = capability.registerProcess(pid, caps);
    }

    serial.writeString("[PROC] Created PID=0x");
    printHex32(pid);
    serial.writeString(" slot=");
    serial.writeChar('0' + @as(u8, @intCast(slot)));
    serial.writeString(" caps=0x");
    printHex32(caps);
    serial.writeString("\n");

    return pid;
}

// ============================================================================
// Terminate
// ============================================================================

pub fn terminate(pid: u32) bool {
    if (!initialized) return false;

    const slot = getSlotByPid(pid) orelse return false;

    if (slot == 0) return false;

    // E3.1: Unregister capabilities
    if (capability.isInitialized()) {
        capability.unregisterProcess(pid);
    }

    // E3.2: Destroy unveil table
    if (unveil.isInitialized()) {
        unveil.destroyTable(pid);
    }

    if (process_table[slot].kernel_stack != 0) {
        const stack_ptr: [*]u8 = @ptrFromInt(process_table[slot].kernel_stack);
        heap.kfree(stack_ptr);
    }

    process_used[slot] = false;
    process_table[slot] = .{
        .pid = 0,
        .state = .Terminated,
        .kernel_stack = 0,
        .kernel_stack_top = 0,
        .rsp = 0,
        .priority = 0,
        .time_slice = 0,
        .total_ticks = 0,
        .caps = capability.CAP_NONE,
    };

    if (process_count > 0) process_count -= 1;
    return true;
}

// ============================================================================
// Capability Accessors (E3.1)
// ============================================================================

pub fn getCurrentCaps() u32 {
    return getProcessCaps(current_pid);
}

pub fn getProcessCaps(pid: u32) u32 {
    if (pid == 0) return capability.CAP_ALL;

    const slot = getSlotByPid(pid) orelse return capability.CAP_ALL;
    return process_table[slot].caps;
}

pub fn setProcessCaps(pid: u32, caps: u32) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].caps = caps;

    if (capability.isInitialized()) {
        return capability.setCaps(pid, caps);
    }
    return true;
}

pub fn grantProcessCap(pid: u32, cap: u32) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].caps |= cap;

    if (capability.isInitialized()) {
        return capability.grantCap(pid, cap);
    }
    return true;
}

pub fn revokeProcessCap(pid: u32, cap: u32) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].caps &= ~cap;

    if (capability.isInitialized()) {
        return capability.revokeCap(pid, cap);
    }
    return true;
}

// ============================================================================
// Idle Process
// ============================================================================

pub fn createIdleProcess() void {
    if (!initialized) {
        serial.writeString("[PROC] ERROR: Cannot create idle - not initialized!\n");
        return;
    }

    serial.writeString("[PROC] Creating idle...\n");

    if (process_used[0]) {
        serial.writeString("[PROC] Idle already exists\n");
        return;
    }

    const stack_ptr = heap.kmalloc(KERNEL_STACK_SIZE) orelse {
        serial.writeString("[PROC] ERROR: Idle stack allocation failed!\n");
        return;
    };
    const stack_addr: u64 = @intFromPtr(stack_ptr);
    const stack_top: u64 = stack_addr + KERNEL_STACK_SIZE;

    process_table[0] = .{
        .pid = 0,
        .state = .Ready,
        .kernel_stack = stack_addr,
        .kernel_stack_top = stack_top,
        .rsp = 0,
        .priority = 255,
        .time_slice = 1,
        .total_ticks = 0,
        .caps = capability.CAP_ALL,
    };

    process_table[0].rsp = switch_ctx.setupProcessStack(
        stack_top,
        @intFromPtr(&idleLoop),
        0,
    );

    process_used[0] = true;

    if (capability.isInitialized()) {
        _ = capability.registerProcess(0, capability.CAP_ALL);
    }

    serial.writeString("[PROC] Idle created\n");
}

fn idleLoop() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

// ============================================================================
// Getters
// ============================================================================

pub fn getCount() u32 {
    return process_count;
}

pub fn getCurrentPid() u32 {
    return current_pid;
}

pub fn setCurrentPid(pid: u32) void {
    current_pid = pid;
}

pub fn getMaxSlots() usize {
    return MAX_SLOTS_USED;
}

// ============================================================================
// Safe access for shell
// ============================================================================

pub fn getProcessInfo(slot: usize) ?struct {
    pid: u32,
    state: ProcessState,
    priority: u8,
    caps: u32,
} {
    if (slot >= MAX_SLOTS_USED) return null;
    if (!process_used[slot]) return null;

    return .{
        .pid = process_table[slot].pid,
        .state = process_table[slot].state,
        .priority = process_table[slot].priority,
        .caps = process_table[slot].caps,
    };
}

// ============================================================================
// Print / Debug
// ============================================================================

pub fn printProcessList() void {
    serial.writeString("\n[PROC] List:\n");
    var i: usize = 0;
    while (i < MAX_SLOTS_USED) : (i += 1) {
        if (process_used[i]) {
            serial.writeString("  [");
            serial.writeChar('0' + @as(u8, @intCast(i)));
            serial.writeString("] PID=0x");
            printHex32(process_table[i].pid);
            serial.writeString(" state=0x");
            printHex8(@intFromEnum(process_table[i].state));
            serial.writeString(" caps=0x");
            printHex32(process_table[i].caps);
            serial.writeString(" rsp=0x");
            printHex64(process_table[i].rsp);
            serial.writeString("\n");
        }
    }
}

pub fn dumpQwords(addr: u64, count: usize) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const p: *volatile u64 = @ptrFromInt(addr + i * 8);
        serial.writeString("  +0x");
        printHex64(@as(u64, @intCast(i * 8)));
        serial.writeString(" : 0x");
        printHex64(p.*);
        serial.writeString("\n");
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[@intCast((val >> 28) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 24) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 20) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 16) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 12) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 8) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 4) & 0xF)]);
    serial.writeChar(hex[@intCast(val & 0xF)]);
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}
