//! Zamrud OS - Scheduler (FINAL FIX)

const serial = @import("../drivers/serial/serial.zig");
const process = @import("process.zig");
const switch_ctx = @import("../arch/x86_64/switch.zig");
const gdt = @import("../arch/x86_64/gdt.zig");
const cpu = @import("../core/cpu.zig");

var scheduler_enabled: bool = false;
var current_slot: usize = 0;
var switch_count: u64 = 0;
var tick_count: u64 = 0;
var scheduler_running: bool = false;
var preempt_pending: bool = false;
var in_switch: bool = false;
var dummy_rsp: u64 = 0;

// Exit stack - dedicated untuk exit handling
var exit_stack: [4096]u8 align(16) = undefined;

pub fn init() void {
    serial.writeString("[SCHED] Init\n");
    scheduler_enabled = false;
    scheduler_running = false;
    current_slot = 0;
    switch_count = 0;
    tick_count = 0;
    preempt_pending = false;
    in_switch = false;
    dummy_rsp = 0;
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

pub fn tick() void {
    if (scheduler_enabled) tick_count += 1;
}

pub fn getTicks() u64 {
    return tick_count;
}

pub fn getSwitchCount() u64 {
    return switch_count;
}

pub fn getCurrentSlot() usize {
    return current_slot;
}

pub fn requestPreempt() void {
    if (scheduler_running and scheduler_enabled and !in_switch) {
        preempt_pending = true;
    }
}

pub fn checkPreempt() void {
    if (in_switch) return;
    if (preempt_pending) {
        preempt_pending = false;
        preemptSwitch();
    }
}

pub fn isPreemptPending() bool {
    return preempt_pending;
}

pub fn clearPreempt() void {
    preempt_pending = false;
}

fn preemptSwitch() void {
    if (!scheduler_enabled or !scheduler_running or in_switch) return;

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
    var next: usize = current_slot;
    var i: u8 = 0;
    while (i < 8) : (i += 1) {
        next = (next + 1) & 0x7;
        if (next == 0) continue;

        if (process.process_used[next] and
            process.process_table[next].state == .Ready)
        {
            return next;
        }
    }
    return null;
}

pub fn yield() void {
    if (!scheduler_enabled or !scheduler_running or in_switch) return;
    const next = findNextReady() orelse return;
    if (next == current_slot) return;
    doSwitch(next);
}

pub fn schedule() void {
    yield();
}

fn doSwitch(next: usize) void {
    in_switch = true;

    const old_slot = current_slot;

    if (process.process_used[old_slot] and
        process.process_table[old_slot].state == .Running)
    {
        process.process_table[old_slot].state = .Ready;
    }

    process.process_table[next].state = .Running;
    process.setCurrentPid(process.process_table[next].pid);
    current_slot = next;
    switch_count += 1;
    gdt.setKernelStack(process.process_table[next].kernel_stack_top);

    switch_ctx.contextSwitch(
        &process.process_table[old_slot].rsp,
        process.process_table[next].rsp,
    );

    in_switch = false;
}

/// Exit current process - dengan switch ke exit stack
pub fn exitCurrentProcess() void {
    if (!scheduler_running) return;

    cpu.cli();
    in_switch = true;
    preempt_pending = false;

    const slot = current_slot;
    const pid = process.process_table[slot].pid;

    serial.writeString("\n[EXIT] PID=0x");
    printHex8(@intCast(pid & 0xFF));
    serial.writeString(" slot=");
    printHex8(@intCast(slot));
    serial.writeString("\n");

    // Mark as terminated
    process.process_table[slot].state = .Terminated;
    process.process_used[slot] = false;

    // Check if ada process lain
    var has_next = false;
    var next_slot: usize = 0;

    // Simple loop - tidak pakai findNextReady untuk avoid any issues
    var i: usize = 1;
    while (i < 8) : (i += 1) {
        if (process.process_used[i] and process.process_table[i].state == .Ready) {
            has_next = true;
            next_slot = i;
            break;
        }
    }

    if (has_next) {
        serial.writeString("[EXIT] -> slot=");
        printHex8(@intCast(next_slot));
        serial.writeString("\n");

        process.process_table[next_slot].state = .Running;
        process.setCurrentPid(process.process_table[next_slot].pid);
        gdt.setKernelStack(process.process_table[next_slot].kernel_stack_top);
        current_slot = next_slot;
        switch_count += 1;
        in_switch = false;

        cpu.sti();
        switch_ctx.contextSwitch(&dummy_rsp, process.process_table[next_slot].rsp);
    } else {
        // ALL PROCESSES DONE - switch ke exit stack dulu

        // Switch ke exit stack untuk safe execution
        const exit_stack_top = @intFromPtr(&exit_stack) + exit_stack.len;

        // Call completion handler on exit stack
        asm volatile (
            \\movq %[stack], %%rsp
            \\call schedulerComplete
            :
            : [stack] "r" (exit_stack_top),
        );

        unreachable;
    }
}

/// Called when all processes complete - runs on exit stack
export fn schedulerComplete() noreturn {
    scheduler_running = false;
    scheduler_enabled = false;
    in_switch = false;

    serial.writeString("\n========================================\n");
    serial.writeString("  ALL PROCESSES COMPLETED!\n");
    serial.writeString("  Switches: 0x");
    printHex8(@intCast(switch_count & 0xFF));
    serial.writeString("\n");
    serial.writeString("========================================\n");

    // Halt forever
    cpu.cli();
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn killProcess(pid: u32) bool {
    if (pid == 0) return false;
    const slot = process.getSlotByPid(pid) orelse return false;
    if (slot == current_slot and scheduler_running) {
        exitCurrentProcess();
        return true;
    }
    process.process_table[slot].state = .Terminated;
    process.process_used[slot] = false;
    return true;
}

pub fn getRunningCount() u32 {
    var count: u32 = 0;
    var i: usize = 1;
    while (i < 8) : (i += 1) {
        if (process.process_used[i] and
            (process.process_table[i].state == .Ready or
                process.process_table[i].state == .Running))
        {
            count += 1;
        }
    }
    return count;
}

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
    var i: usize = 1;
    while (i < 8) : (i += 1) {
        if (process.process_used[i] and
            process.process_table[i].state == .Ready)
        {
            slot = i;
            found = true;
            break;
        }
    }

    if (!found) {
        serial.writeString("[S-ERR] No ready process\n");
        return;
    }

    serial.writeString("[SCHED] Start slot=");
    printHex8(@intCast(slot));
    serial.writeString("\n");

    current_slot = slot;
    scheduler_running = true;
    in_switch = false;
    process.process_table[slot].state = .Running;
    process.setCurrentPid(process.process_table[slot].pid);
    gdt.setKernelStack(process.process_table[slot].kernel_stack_top);

    switch_ctx.jumpToFirst(process.process_table[slot].rsp, 0);
}

pub fn stop() void {
    scheduler_running = false;
    scheduler_enabled = false;
    preempt_pending = false;
    in_switch = false;
}

pub fn printStatus() void {
    serial.writeString("[SCHED] en=");
    printHex8(if (scheduler_enabled) 1 else 0);
    serial.writeString(" run=");
    printHex8(if (scheduler_running) 1 else 0);
    serial.writeString(" slot=");
    printHex8(@intCast(current_slot));
    serial.writeString("\n");
}

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

// check point 8 scheduller
