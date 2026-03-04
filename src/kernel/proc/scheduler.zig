//! Zamrud OS - Scheduler (SMP-aware)
//! B2.9: Per-CPU scheduling support

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
// Global State (shared across CPUs)
// ============================================================================

var scheduler_enabled: bool = false;
var scheduler_running: bool = false;
var global_switch_count: u64 = 0;
var global_tick_count: u64 = 0;

// Global scheduler lock (for process table operations)
var sched_lock: spinlock.SpinLock = .{};

// Exit stack - dedicated for exit handling
var exit_stack: [4096]u8 align(16) = undefined;

// Dummy RSP for context switch when no old context needed
var dummy_rsp: u64 = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[SCHED] Init\n");
    scheduler_enabled = false;
    scheduler_running = false;
    global_switch_count = 0;
    global_tick_count = 0;
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
// Tick Handling (called from timer interrupt on each CPU)
// ============================================================================

pub fn tick() void {
    if (!scheduler_enabled) return;

    // Atomic increment of global tick
    _ = spinlock.Atomic.fetchAdd64(&global_tick_count, 1);

    // Per-CPU tick tracking
    if (per_cpu.isInitialized()) {
        per_cpu.incrementTimerTicks();
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
    // Fallback for pre-SMP
    return 0;
}

fn setCurrentSlot(slot: usize) void {
    if (per_cpu.isInitialized()) {
        per_cpu.setCurrentSlot(slot);
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

    // Validate current process
    if (!process.process_used[current_slot] or
        process.process_table[current_slot].state != .Running)
    {
        return;
    }

    const next = findNextReady() orelse return;
    if (next == current_slot) return;

    serial.writeString("[PREEMPT] ");
    printHex8(@intCast(current_slot));
    serial.writeString("->");
    printHex8(@intCast(next));
    serial.writeString("\n");

    doSwitch(next);
}

fn findNextReady() ?usize {
    sched_lock.acquire();
    defer sched_lock.release();

    const current = getCurrentSlot();
    var next: usize = current;
    var i: u8 = 0;

    while (i < process.MAX_SLOTS_USED) : (i += 1) {
        next = (next + 1) % process.MAX_SLOTS_USED;
        if (next == 0) continue; // Skip idle

        if (process.process_used[next] and
            process.process_table[next].state == .Ready)
        {
            return next;
        }
    }
    return null;
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

    sched_lock.acquire();

    // Mark old as ready (if still running)
    if (process.process_used[old_slot] and
        process.process_table[old_slot].state == .Running)
    {
        process.process_table[old_slot].state = .Ready;
    }

    // Mark new as running
    process.process_table[next].state = .Running;
    process.setCurrentPid(process.process_table[next].pid);

    sched_lock.release();

    // Update per-CPU state
    setCurrentSlot(next);
    _ = spinlock.Atomic.fetchAdd64(&global_switch_count, 1);

    if (per_cpu.isInitialized()) {
        per_cpu.incrementSwitchCount();
    }

    // Update kernel stack for interrupts
    gdt.setKernelStack(process.process_table[next].kernel_stack_top);

    // Perform context switch
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

    serial.writeString("\n[EXIT] PID=0x");
    printHex8(@intCast(pid & 0xFF));
    serial.writeString(" slot=");
    printHex8(@intCast(slot));
    serial.writeString("\n");

    // Mark as terminated
    sched_lock.acquire();
    process.process_table[slot].state = .Terminated;
    process.process_used[slot] = false;
    sched_lock.release();

    // Find next process
    var has_next = false;
    var next_slot: usize = 0;

    sched_lock.acquire();
    var i: usize = 1;
    while (i < process.MAX_SLOTS_USED) : (i += 1) {
        if (process.process_used[i] and process.process_table[i].state == .Ready) {
            has_next = true;
            next_slot = i;
            break;
        }
    }
    sched_lock.release();

    if (has_next) {
        serial.writeString("[EXIT] -> slot=");
        printHex8(@intCast(next_slot));
        serial.writeString("\n");

        sched_lock.acquire();
        process.process_table[next_slot].state = .Running;
        process.setCurrentPid(process.process_table[next_slot].pid);
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
        // All processes done - switch to exit stack
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

/// Called when all processes complete
export fn schedulerComplete() noreturn {
    scheduler_running = false;
    scheduler_enabled = false;

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(false);
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  ALL PROCESSES COMPLETED!\n");
    serial.writeString("  Switches: 0x");
    printHex8(@intCast(global_switch_count & 0xFF));
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

    // H.9d: Wipe process memory before marking dead
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

    var i: usize = 1;
    while (i < process.MAX_SLOTS_USED) : (i += 1) {
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

    var slot: usize = 0;
    var found: bool = false;

    sched_lock.acquire();
    var i: usize = 1;
    while (i < process.MAX_SLOTS_USED) : (i += 1) {
        if (process.process_used[i] and
            process.process_table[i].state == .Ready)
        {
            slot = i;
            found = true;
            break;
        }
    }
    sched_lock.release();

    if (!found) {
        serial.writeString("[S-ERR] No ready process\n");
        return;
    }

    serial.writeString("[SCHED] Start slot=");
    printHex8(@intCast(slot));
    serial.writeString("\n");

    setCurrentSlot(slot);
    scheduler_running = true;

    if (per_cpu.isInitialized()) {
        per_cpu.setInSwitch(false);
    }

    sched_lock.acquire();
    process.process_table[slot].state = .Running;
    process.setCurrentPid(process.process_table[slot].pid);
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
    printHex8(if (scheduler_enabled) 1 else 0);
    serial.writeString(" run=");
    printHex8(if (scheduler_running) 1 else 0);
    serial.writeString(" slot=");
    printHex8(@intCast(getCurrentSlot()));

    if (per_cpu.isInitialized()) {
        serial.writeString(" cpu=");
        printHex8(@intCast(per_cpu.currentIndex()));
    }

    serial.writeString("\n");
}

// ============================================================================
// Helpers
// ============================================================================

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}
