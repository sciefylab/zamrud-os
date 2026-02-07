//! Zamrud OS - Timer Driver

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");
const scheduler = @import("../../proc/scheduler.zig");
const terminal = @import("../display/terminal.zig");

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_FREQUENCY: u32 = 1193182;
const TIMER_FREQUENCY: u32 = 100;
const PREEMPT_TICKS: u64 = 10;

var ticks: u64 = 0;
var seconds: u64 = 0;
var preempt_counter: u64 = 0;
var timer_callback: ?*const fn () void = null;

pub fn init() void {
    serial.writeString("  TIMER: Initializing...\n");
    const divisor: u32 = PIT_FREQUENCY / TIMER_FREQUENCY;
    cpu.outb(PIT_COMMAND, 0x36);
    cpu.outb(PIT_CHANNEL0, @truncate(divisor & 0xFF));
    cpu.outb(PIT_CHANNEL0, @truncate((divisor >> 8) & 0xFF));
    ticks = 0;
    seconds = 0;
    preempt_counter = 0;
    serial.writeString("  TIMER: Done\n");
}

pub fn handleInterrupt() void {
    ticks += 1;

    if ((ticks % 100) == 0) {
        seconds += 1;
    }

    // Update cursor blink (setiap tick = 10ms, jadi 50 ticks = 500ms)
    if (terminal.isInitialized()) {
        terminal.tick();
    }

    scheduler.tick();

    if (scheduler.isRunning()) {
        preempt_counter += 1;
        if (preempt_counter >= PREEMPT_TICKS) {
            preempt_counter = 0;
            scheduler.requestPreempt();
        }
    }

    if (timer_callback) |callback| {
        callback();
    }
}

pub fn getTicks() u64 {
    return ticks;
}

pub fn getSeconds() u64 {
    return seconds;
}

pub fn getMillis() u64 {
    return ticks * 10;
}

pub fn sleep(ms: u32) void {
    const target = getMillis() + ms;
    while (getMillis() < target) {
        cpu.hlt();
    }
}

pub fn setCallback(callback: ?*const fn () void) void {
    timer_callback = callback;
}

pub fn test_timer() void {
    serial.writeString("\n[TIMER TEST]\n");
    serial.writeString("Ticks: ");
    var t = ticks;
    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        const hex = "0123456789ABCDEF";
        serial.writeChar(hex[@intCast((t >> 60) & 0xF)]);
        t <<= 4;
    }
    serial.writeString("\n");
}
