//! Zamrud OS - Process Management
//! B2.9b: CPU affinity support added

const serial = @import("../drivers/serial/serial.zig");
const heap = @import("../mm/heap.zig");
const switch_ctx = @import("../arch/x86_64/switch.zig");
const capability = @import("../security/capability.zig");
const unveil = @import("../security/unveil.zig");
const sanitize = @import("../mm/sanitize.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PROCESSES: usize = 64;
pub const MAX_SLOTS_USED: usize = 16; // Increased for SMP
pub const KERNEL_STACK_SIZE: u64 = 16 * 1024;
pub const CPU_AFFINITY_ANY: u8 = 0xFF; // Run on any CPU

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

    // === B2.9b: CPU affinity ===
    cpu_affinity: u8 = CPU_AFFINITY_ANY, // Which CPU to run on (0xFF = any)
    last_cpu: u8 = 0, // Last CPU this process ran on
    migrations: u32 = 0, // Number of times migrated between CPUs

    // === F3: User context ===
    uid: u16 = 0,
    gid: u16 = 0,
    euid: u16 = 0,
    egid: u16 = 0,

    // === F3: Process name ===
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,

    pub fn getName(self: *const Process) []const u8 {
        if (self.name_len == 0) return "unnamed";
        return self.name[0..self.name_len];
    }

    /// B2.9b: Check if process can run on given CPU
    pub fn canRunOnCpu(self: *const Process, cpu_id: u8) bool {
        return self.cpu_affinity == CPU_AFFINITY_ANY or self.cpu_affinity == cpu_id;
    }
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
            .cpu_affinity = CPU_AFFINITY_ANY,
            .last_cpu = 0,
            .migrations = 0,
            .uid = 0,
            .gid = 0,
            .euid = 0,
            .egid = 0,
            .name_len = 0,
        };
    }

    current_pid = 0;
    next_pid = 1;
    process_count = 0;
    initialized = true;

    serial.writeString("[PROC] Initialized (B2.9b SMP-aware)!\n");
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
    return createFull(name, entry, arg, caps, CPU_AFFINITY_ANY);
}

/// B2.9b: Full process creation with CPU affinity
pub fn createFull(name: []const u8, entry: u64, arg: u64, caps: u32, affinity: u8) ?u32 {
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

    // F3: Determine user context and effective caps
    var proc_uid: u16 = 0;
    var proc_gid: u16 = 0;
    var proc_caps: u32 = caps;

    const users_mod = @import("../security/users.zig");
    if (users_mod.isInitialized() and users_mod.isLoggedIn()) {
        proc_uid = users_mod.getCurrentUid();
        proc_gid = users_mod.getCurrentGid();

        if (caps == capability.CAP_ALL) {
            proc_caps = users_mod.getCurrentRole().defaultCaps();
        }
    }

    process_table[slot] = .{
        .pid = pid,
        .state = .Ready,
        .kernel_stack = stack_addr,
        .kernel_stack_top = stack_top,
        .rsp = 0,
        .priority = 1,
        .time_slice = 10,
        .total_ticks = 0,
        .caps = proc_caps,
        .cpu_affinity = affinity,
        .last_cpu = 0,
        .migrations = 0,
        .uid = proc_uid,
        .gid = proc_gid,
        .euid = proc_uid,
        .egid = proc_gid,
    };

    // Copy process name
    const nlen = @min(name.len, 32);
    var ni: usize = 0;
    while (ni < nlen) : (ni += 1) {
        process_table[slot].name[ni] = name[ni];
    }
    process_table[slot].name_len = @intCast(nlen);

    process_table[slot].rsp = switch_ctx.setupProcessStack(stack_top, entry, arg);

    process_used[slot] = true;
    process_count += 1;

    // E3.1: Register in capability system
    if (capability.isInitialized()) {
        _ = capability.registerProcess(pid, proc_caps);
    }

    serial.writeString("[PROC] Created PID=0x");
    printHex32(pid);
    serial.writeString(" slot=");
    printDec8(@intCast(slot));
    serial.writeString(" affinity=");
    if (affinity == CPU_AFFINITY_ANY) {
        serial.writeString("ANY");
    } else {
        printDec8(affinity);
    }
    serial.writeString("\n");

    return pid;
}

// ============================================================================
// B2.9b: CPU Affinity
// ============================================================================

/// Set CPU affinity for a process
pub fn setAffinity(pid: u32, cpu_id: u8) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].cpu_affinity = cpu_id;
    return true;
}

/// Get CPU affinity for a process
pub fn getAffinity(pid: u32) u8 {
    const slot = getSlotByPid(pid) orelse return CPU_AFFINITY_ANY;
    return process_table[slot].cpu_affinity;
}

/// Record that process ran on a CPU
pub fn recordCpuRun(pid: u32, cpu_id: u8) void {
    const slot = getSlotByPid(pid) orelse return;
    if (process_table[slot].last_cpu != cpu_id and process_table[slot].last_cpu != 0) {
        process_table[slot].migrations += 1;
    }
    process_table[slot].last_cpu = cpu_id;
}

/// Get migration count for a process
pub fn getMigrations(pid: u32) u32 {
    const slot = getSlotByPid(pid) orelse return 0;
    return process_table[slot].migrations;
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

    // H.9e: Wipe all mlocked pages for this process
    if (sanitize.isInitialized()) {
        sanitize.munlockAll(pid);
    }

    // H.9d: Secure wipe process memory BEFORE freeing
    if (sanitize.isInitialized()) {
        sanitize.secureWipeProcess(
            process_table[slot].kernel_stack,
            KERNEL_STACK_SIZE,
            pid,
        );
    }

    if (process_table[slot].kernel_stack != 0) {
        const stack_ptr: [*]u8 = @ptrFromInt(process_table[slot].kernel_stack);
        heap.kfree(stack_ptr);
    }

    // H.9d: Secure wipe process struct using volatile writes
    if (sanitize.isInitialized()) {
        sanitize.secureWipeStruct(
            @intFromPtr(&process_table[slot]),
            @sizeOf(Process),
        );
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
        .cpu_affinity = CPU_AFFINITY_ANY,
        .last_cpu = 0,
        .migrations = 0,
        .uid = 0,
        .gid = 0,
        .euid = 0,
        .egid = 0,
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
// F3: User Context Accessors
// ============================================================================

pub fn getProcessUid(pid: u32) u16 {
    if (pid == 0) return 0;
    const slot = getSlotByPid(pid) orelse return 0;
    return process_table[slot].euid;
}

pub fn getProcessGid(pid: u32) u16 {
    if (pid == 0) return 0;
    const slot = getSlotByPid(pid) orelse return 0;
    return process_table[slot].egid;
}

pub fn setProcessUid(pid: u32, uid: u16) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].uid = uid;
    process_table[slot].euid = uid;
    return true;
}

pub fn setProcessGid(pid: u32, gid: u16) bool {
    const slot = getSlotByPid(pid) orelse return false;
    process_table[slot].gid = gid;
    process_table[slot].egid = gid;
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
        .cpu_affinity = CPU_AFFINITY_ANY, // Idle runs on any CPU
        .last_cpu = 0,
        .migrations = 0,
        .uid = 0,
        .gid = 0,
        .euid = 0,
        .egid = 0,
    };

    const idle_name = "idle";
    var ni: usize = 0;
    while (ni < idle_name.len) : (ni += 1) {
        process_table[0].name[ni] = idle_name[ni];
    }
    process_table[0].name_len = @intCast(idle_name.len);

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

/// B2.9b: Count ready processes that can run on a specific CPU
pub fn countReadyForCpu(cpu_id: u8) u32 {
    var count: u32 = 0;
    for (1..MAX_SLOTS_USED) |i| {
        if (process_used[i] and
            process_table[i].state == .Ready and
            process_table[i].canRunOnCpu(cpu_id))
        {
            count += 1;
        }
    }
    return count;
}

/// B2.9b: Find next ready process for a specific CPU
pub fn findReadyForCpu(cpu_id: u8, start_slot: usize) ?usize {
    var slot = start_slot;
    for (0..MAX_SLOTS_USED) |_| {
        slot = (slot + 1) % MAX_SLOTS_USED;
        if (slot == 0) continue; // Skip idle

        if (process_used[slot] and
            process_table[slot].state == .Ready and
            process_table[slot].canRunOnCpu(cpu_id))
        {
            return slot;
        }
    }
    return null;
}

// ============================================================================
// Safe access for shell
// ============================================================================

pub fn getProcessInfo(slot: usize) ?struct {
    pid: u32,
    state: ProcessState,
    priority: u8,
    caps: u32,
    uid: u16,
    gid: u16,
    name: []const u8,
    cpu_affinity: u8,
    last_cpu: u8,
    migrations: u32,
} {
    if (slot >= MAX_SLOTS_USED) return null;
    if (!process_used[slot]) return null;

    return .{
        .pid = process_table[slot].pid,
        .state = process_table[slot].state,
        .priority = process_table[slot].priority,
        .caps = process_table[slot].caps,
        .uid = process_table[slot].euid,
        .gid = process_table[slot].egid,
        .name = process_table[slot].getName(),
        .cpu_affinity = process_table[slot].cpu_affinity,
        .last_cpu = process_table[slot].last_cpu,
        .migrations = process_table[slot].migrations,
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
            printDec8(@intCast(i));
            serial.writeString("] PID=0x");
            printHex32(process_table[i].pid);
            serial.writeString(" state=");
            printDec8(@intFromEnum(process_table[i].state));
            serial.writeString(" cpu=");
            if (process_table[i].cpu_affinity == CPU_AFFINITY_ANY) {
                serial.writeString("ANY");
            } else {
                printDec8(process_table[i].cpu_affinity);
            }
            serial.writeString(" last=");
            printDec8(process_table[i].last_cpu);
            serial.writeString(" ");
            serial.writeString(process_table[i].getName());
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

fn printDec8(val: u8) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [3]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printDec16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [5]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
