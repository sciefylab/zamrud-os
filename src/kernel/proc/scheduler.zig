//! Zamrud OS - Scheduler (B2.9b Multi-CPU)
//! Per-CPU runqueues with load balancing

const serial = @import("../drivers/serial/serial.zig");
const process = @import("process.zig");
const switch_ctx = @import("../arch/x86_64/switch.zig");
const gdt = @import("../arch/x86_64/gdt.zig");
const cpu = @import("../core/cpu.zig");
const sanitize = @import("../mm/sanitize.zig");
const spinlock = @import("../arch/x86_64/spinlock.zig");
const per_cpu = @import("../arch/x86_64/per_cpu.zig");
const apic = @import("../arch/x86_64/apic.zig");

// ============================================================================
// Constants
// ============================================================================

const LOAD_BALANCE_INTERVAL: u64 = 100; // Balance every 100 ticks (1 second)
const MIN_MIGRATION_THRESHOLD: u32 = 2; // Don't migrate if difference < 2

// ============================================================================
// Global State
// ============================================================================

var scheduler_enabled: bool = false;
var scheduler_running: bool = false;
var global_switch_count: u64 = 0;
var global_tick_count: u64 = 0;
var last_balance_tick: u64 = 0;

// Global scheduler lock (for process table operations)
var sched_lock: spinlock.SpinLock = .{};

// Exit stack
var exit_stack: [4096]u8 align(16) = undefined;
var dummy_rsp: u64 = 0;

// ============================================================================
// Per-CPU Runqueue (B2.9b)
// ============================================================================

const MAX_RUNQUEUE_SIZE = 16;

pub const RunQueue = struct {
    slots: [MAX_RUNQUEUE_SIZE]usize = [_]usize{0} ** MAX_RUNQUEUE_SIZE,
    count: u32 = 0,
    head: u32 = 0,
    lock: spinlock.SpinLock = .{},

    pub fn add(self: *RunQueue, slot: usize) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (self.count >= MAX_RUNQUEUE_SIZE) return false;

        const idx = (self.head + self.count) % MAX_RUNQUEUE_SIZE;
        self.slots[idx] = slot;
        self.count += 1;
        return true;
    }

    pub fn remove(self: *RunQueue) ?usize {
        self.lock.acquire();
        defer self.lock.release();

        if (self.count == 0) return null;

        const slot = self.slots[self.head];
        self.head = (self.head + 1) % MAX_RUNQUEUE_SIZE;
        self.count -= 1;
        return slot;
    }

    pub fn peek(self: *RunQueue) ?usize {
        self.lock.acquire();
        defer self.lock.release();

        if (self.count == 0) return null;
        return self.slots[self.head];
    }

    pub fn getCount(self: *RunQueue) u32 {
        return @atomicLoad(u32, &self.count, .acquire);
    }
};

// Per-CPU runqueues
var cpu_runqueues: [apic.MAX_CPUS]RunQueue = [_]RunQueue{.{}} ** apic.MAX_CPUS;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[SCHED] Init (B2.9b Multi-CPU)\n");
    scheduler_enabled = false;
    scheduler_running = false;
    global_switch_count = 0;
    global_tick_count = 0;
    last_balance_tick = 0;

    // Initialize per-CPU runqueues
    for (0..apic.MAX_CPUS) |i| {
        cpu_runqueues[i] = .{};
    }
}

pub fn enable() void {
    serial.writeString("[SCHED] Enable\n");
    scheduler_enabled = true;
}

pub fn disable() void {
    scheduler_enabled = false;
}

pub fn isEnabled() bool {
    return scheduler_enabled;
}

pub fn isRunning() bool {
    return scheduler_running;
}

// ============================================================================
// Tick Handling
// ============================================================================

pub fn tick() void {
    if (!scheduler_enabled) return;

    _ = spinlock.Atomic.fetchAdd64(&global_tick_count, 1);

    if (per_cpu.isInitialized()) {
        per_cpu.incrementTimerTicks();
    }

    // Periodic load balancing
    const ticks = spinlock.Atomic.load64(&global_tick_count);
    if (ticks - last_balance_tick >= LOAD_BALANCE_INTERVAL) {
        last_balance_tick = ticks;
        balanceLoad();
    }
}

pub fn getTicks() u64 {
    return spinlock.Atomic.load64(&global_tick_count);
}

pub fn getSwitchCount() u64 {
    return spinlock.Atomic.load64(&global_switch_count);
}

// ============================================================================
// Current Slot (per-CPU aware)
// ============================================================================

pub fn getCurrentSlot() usize {
    if (per_cpu.isInitialized()) {
        return per_cpu.getCurrentSlot();
    }
    return 0;
}

fn setCurrentSlot(slot: usize) void {
    if (per_cpu.isInitialized()) {
        per_cpu.setCurrentSlot(slot);
    }
}

// ============================================================================
// B2.9b: Load Balancing
// ============================================================================

fn balanceLoad() void {
    if (!per_cpu.isInitialized()) return;

    const cpu_count = apic.getOnlineCpuCount();
    if (cpu_count <= 1) return;

    // Find busiest and idlest CPUs
    var busiest_cpu: usize = 0;
    var busiest_count: u32 = 0;
    var idlest_cpu: usize = 0;
    var idlest_count: u32 = 0xFFFFFFFF;

    for (0..cpu_count) |i| {
        const info = apic.getCpuInfo(i) orelse continue;
        if (!info.online) continue;

        const count = cpu_runqueues[i].getCount();
        if (count > busiest_count) {
            busiest_count = count;
            busiest_cpu = i;
        }
        if (count < idlest_count) {
            idlest_count = count;
            idlest_cpu = i;
        }
    }

    // Migrate if imbalance is significant
    if (busiest_cpu != idlest_cpu and
        busiest_count > idlest_count + MIN_MIGRATION_THRESHOLD)
    {
        // Try to migrate one process
        if (cpu_runqueues[busiest_cpu].remove()) |slot| {
            // Check if process allows migration
            if (process.process_table[slot].cpu_affinity == process.CPU_AFFINITY_ANY) {
                _ = cpu_runqueues[idlest_cpu].add(slot);
                process.process_table[slot].migrations += 1;

                serial.writeString("[SCHED] Migrated slot ");
                printDec64(@as(u64, slot));
                serial.writeString(" from CPU ");
                printDec64(@as(u64, busiest_cpu));
                serial.writeString(" to CPU ");
                printDec64(@as(u64, idlest_cpu));
                serial.writeString("\n");
            } else {
                // Put it back if affinity doesn't allow migration
                _ = cpu_runqueues[busiest_cpu].add(slot);
            }
        }
    }
}

/// B2.9b: Get runqueue for a CPU
pub fn getRunQueue(cpu_id: usize) *RunQueue {
    if (cpu_id >= apic.MAX_CPUS) return &cpu_runqueues[0];
    return &cpu_runqueues[cpu_id];
}

/// B2.9b: Add process to appropriate runqueue
pub fn enqueue(slot: usize) bool {
    if (slot == 0) return false; // Don't enqueue idle

    const affinity = process.process_table[slot].cpu_affinity;

    if (affinity == process.CPU_AFFINITY_ANY) {
        // Find least loaded CPU
        var best_cpu: usize = 0;
        var best_count: u32 = 0xFFFFFFFF;

        const cpu_count = apic.getOnlineCpuCount();
        for (0..cpu_count) |i| {
            const info = apic.getCpuInfo(i) orelse continue;
            if (!info.online) continue;

            const count = cpu_runqueues[i].getCount();
            if (count < best_count) {
                best_count = count;
                best_cpu = i;
            }
        }

        return cpu_runqueues[best_cpu].add(slot);
    } else {
        // Specific CPU affinity
        return cpu_runqueues[affinity].add(slot);
    }
}

// ============================================================================
// Preemption
// ============================================================================

pub fn requestPreempt() void {
    if (!scheduler_running or !scheduler_enabled) return;

    if (per_cpu.isInitialized()) {
        if (!per_cpu.isInSwitch()) {
            per_cpu.setPreemptPending(true);
        }
    }
}

pub fn checkPreempt() void {
    if (!scheduler_enabled or !scheduler_running) return;

    if (per_cpu.isInitialized()) {
        if (per_cpu.isInSwitch()) return;
        if (per_cpu.isPreemptPending()) {
            per_cpu.setPreemptPending(false);
            preemptSwitch();
        }
    }
}

pub fn isPreemptPending() bool {
    if (per_cpu.isInitialized()) {
        return per_cpu.isPreemptPending();
    }
    return false;
}

pub fn clearPreempt() void {
    if (per_cpu.isInitialized()) {
        per_cpu.setPreemptPending(false);
    }
}

// ============================================================================
// Context Switching
// ============================================================================

fn preemptSwitch() void {
    if (!scheduler_enabled or !scheduler_running) return;

    const current_slot = getCurrentSlot();
    const cpu_id: u8 = @intCast(per_cpu.currentIndex());

    // Validate current process
    if (!process.process_used[current_slot] or
        process.process_table[current_slot].state != .Running)
    {
        return;
    }

    // B2.9b: Find next from per-CPU runqueue or global search
    var next: ?usize = cpu_runqueues[cpu_id].peek();

    if (next == null) {
        // Fallback to global search for this CPU
        next = process.findReadyForCpu(cpu_id, current_slot);
    }

    if (next == null or next.? == current_slot) return;

    serial.writeString("[PREEMPT] CPU");
    printDec64(@as(u64, cpu_id));
    serial.writeString(": ");
    printDec64(@as(u64, current_slot));
    serial.writeString("->");
    printDec64(@as(u64, next.?));
    serial.writeString("\n");

    doSwitch(next.?);
}

fn findNextReady() ?usize {
    sched_lock.acquire();
    defer sched_lock.release();

    const current = getCurrentSlot();
    const cpu_id: u8 = @intCast(per_cpu.currentIndex());

    // First check per-CPU runqueue
    if (cpu_runqueues[cpu_id].peek()) |slot| {
        if (slot != current) return slot;
    }

    // Fallback to global search
    return process.findReadyForCpu(cpu_id, current);
}

pub fn yield() void {
    if (!scheduler_enabled or !scheduler_running) return;
    if (per_cpu.isInitialized() and per_cpu.isInSwitch()) return;

    const next = findNextReady() orelse return;
    if (next == getCurrentSlot()) return;
    doSwitch(next);
}

pub fn schedule() void {
    yield();
}

fn doSwitch(next: usize) void {
    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(true);
    }

    const old_slot = getCurrentSlot();
    const cpu_id: u8 = @intCast(per_cpu.currentIndex());

    sched_lock.acquire();

    // Mark old as ready (if still running)
    if (process.process_used[old_slot] and
        process.process_table[old_slot].state == .Running)
    {
        process.process_table[old_slot].state = .Ready;
    }

    // Remove from runqueue if present
    _ = cpu_runqueues[cpu_id].remove();

    // Mark new as running
    process.process_table[next].state = .Running;
    process.setCurrentPid(process.process_table[next].pid);

    // B2.9b: Record CPU run
    process.recordCpuRun(process.process_table[next].pid, cpu_id);

    sched_lock.release();

    setCurrentSlot(next);
    _ = spinlock.Atomic.fetchAdd64(&global_switch_count, 1);

    if (per_cpu.isInitialized()) {
        per_cpu.incrementSwitchCount();
    }

    gdt.setKernelStack(process.process_table[next].kernel_stack_top);

    switch_ctx.contextSwitch(
        &process.process_table[old_slot].rsp,
        process.process_table[next].rsp,
    );

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(false);
    }
}

// ============================================================================
// Process Exit
// ============================================================================

pub fn exitCurrentProcess() void {
    if (!scheduler_running) return;

    cpu.cli();

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(true);
        per_cpu.setPreemptPending(false);
    }

    const slot = getCurrentSlot();
    const pid = process.process_table[slot].pid;
    const cpu_id: u8 = @intCast(per_cpu.currentIndex());

    serial.writeString("\n[EXIT] CPU");
    printDec64(@as(u64, cpu_id));
    serial.writeString(" PID=0x");
    printHex8(@intCast(pid & 0xFF));
    serial.writeString(" slot=");
    printDec64(@as(u64, slot));
    serial.writeString("\n");

    sched_lock.acquire();
    process.process_table[slot].state = .Terminated;
    process.process_used[slot] = false;
    sched_lock.release();

    // Find next process for this CPU
    var has_next = false;
    var next_slot: usize = 0;

    sched_lock.acquire();
    // Check per-CPU runqueue first
    if (cpu_runqueues[cpu_id].remove()) |s| {
        has_next = true;
        next_slot = s;
    } else {
        // Fallback to global search
        for (1..process.MAX_SLOTS_USED) |i| {
            if (process.process_used[i] and
                process.process_table[i].state == .Ready and
                process.process_table[i].canRunOnCpu(cpu_id))
            {
                has_next = true;
                next_slot = i;
                break;
            }
        }
    }
    sched_lock.release();

    if (has_next) {
        serial.writeString("[EXIT] -> slot=");
        printDec64(@as(u64, next_slot));
        serial.writeString("\n");

        sched_lock.acquire();
        process.process_table[next_slot].state = .Running;
        process.setCurrentPid(process.process_table[next_slot].pid);
        process.recordCpuRun(process.process_table[next_slot].pid, cpu_id);
        sched_lock.release();

        gdt.setKernelStack(process.process_table[next_slot].kernel_stack_top);
        setCurrentSlot(next_slot);
        _ = spinlock.Atomic.fetchAdd64(&global_switch_count, 1);

        if (per_cpu.isInitialized()) {
            per_cpu.setInSwitch(false);
        }

        cpu.sti();
        switch_ctx.contextSwitch(&dummy_rsp, process.process_table[next_slot].rsp);
    } else {
        const exit_stack_top = @intFromPtr(&exit_stack) + exit_stack.len;

        asm volatile (
            \\movq %[stack], %%rsp
            \\call schedulerComplete
            :
            : [stack] "r" (exit_stack_top),
        );

        unreachable;
    }
}

export fn schedulerComplete() noreturn {
    scheduler_running = false;
    scheduler_enabled = false;

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(false);
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  ALL PROCESSES COMPLETED!\n");
    serial.writeString("  Switches: ");
    printDec64(global_switch_count);
    serial.writeString("\n");
    serial.writeString("========================================\n");

    cpu.cli();
    while (true) {
        asm volatile ("hlt");
    }
}

// ============================================================================
// Kill Process
// ============================================================================

pub fn killProcess(pid: u32) bool {
    if (pid == 0) return false;

    const slot = process.getSlotByPid(pid) orelse return false;

    if (slot == getCurrentSlot() and scheduler_running) {
        exitCurrentProcess();
        return true;
    }

    if (sanitize.isInitialized()) {
        sanitize.secureWipeProcess(
            process.process_table[slot].kernel_stack,
            process.KERNEL_STACK_SIZE,
            pid,
        );
    }

    sched_lock.acquire();
    process.process_table[slot].state = .Terminated;
    process.process_used[slot] = false;
    sched_lock.release();

    return true;
}

// ============================================================================
// Running Count
// ============================================================================

pub fn getRunningCount() u32 {
    var count: u32 = 0;

    sched_lock.acquire();
    defer sched_lock.release();

    for (1..process.MAX_SLOTS_USED) |i| {
        if (process.process_used[i] and
            (process.process_table[i].state == .Ready or
                process.process_table[i].state == .Running))
        {
            count += 1;
        }
    }
    return count;
}

// ============================================================================
// Start Scheduler
// ============================================================================

pub fn start() void {
    if (!scheduler_enabled) {
        serial.writeString("[S-ERR] Not enabled\n");
        return;
    }
    if (scheduler_running) {
        serial.writeString("[S-ERR] Already running\n");
        return;
    }

    const cpu_id: u8 = @intCast(per_cpu.currentIndex());
    var slot: usize = 0;
    var found: bool = false;

    sched_lock.acquire();
    // Try per-CPU runqueue first
    if (cpu_runqueues[cpu_id].remove()) |s| {
        slot = s;
        found = true;
    } else {
        // Fallback to global search
        for (1..process.MAX_SLOTS_USED) |i| {
            if (process.process_used[i] and
                process.process_table[i].state == .Ready and
                process.process_table[i].canRunOnCpu(cpu_id))
            {
                slot = i;
                found = true;
                break;
            }
        }
    }
    sched_lock.release();

    if (!found) {
        serial.writeString("[S-ERR] No ready process for CPU ");
        printDec64(@as(u64, cpu_id));
        serial.writeString("\n");
        return;
    }

    serial.writeString("[SCHED] Start CPU");
    printDec64(@as(u64, cpu_id));
    serial.writeString(" slot=");
    printDec64(@as(u64, slot));
    serial.writeString("\n");

    setCurrentSlot(slot);
    scheduler_running = true;

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(false);
    }

    sched_lock.acquire();
    process.process_table[slot].state = .Running;
    process.setCurrentPid(process.process_table[slot].pid);
    process.recordCpuRun(process.process_table[slot].pid, cpu_id);
    sched_lock.release();

    gdt.setKernelStack(process.process_table[slot].kernel_stack_top);

    switch_ctx.jumpToFirst(process.process_table[slot].rsp, 0);
}

pub fn stop() void {
    scheduler_running = false;
    scheduler_enabled = false;

    if (per_cpu.isInitialized()) {
        per_cpu.setPreemptPending(false);
        per_cpu.setInSwitch(false);
    }
}

// ============================================================================
// Status
// ============================================================================

pub fn printStatus() void {
    serial.writeString("[SCHED] en=");
    printDec64(if (scheduler_enabled) 1 else 0);
    serial.writeString(" run=");
    printDec64(if (scheduler_running) 1 else 0);
    serial.writeString(" slot=");
    printDec64(@as(u64, getCurrentSlot()));

    if (per_cpu.isInitialized()) {
        serial.writeString(" cpu=");
        printDec64(@as(u64, per_cpu.currentIndex()));
    }

    serial.writeString(" switches=");
    printDec64(global_switch_count);
    serial.writeString("\n");

    // Print per-CPU runqueue stats
    const cpu_count = apic.getOnlineCpuCount();
    for (0..cpu_count) |i| {
        serial.writeString("  CPU");
        printDec64(@as(u64, i));
        serial.writeString(" runqueue: ");
        printDec64(@as(u64, cpu_runqueues[i].getCount()));
        serial.writeString(" tasks\n");
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn printDec64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = val;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}
