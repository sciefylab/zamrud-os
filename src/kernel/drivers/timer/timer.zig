//! Zamrud OS - Timer Driver
//! B2.9a: Hybrid PIT/APIC timer support
//! - PIT used for initial boot and time-keeping (read ticks)
//! - APIC timer takes over scheduling when SMP is active

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");
const scheduler = @import("../../proc/scheduler.zig");
const terminal = @import("../display/terminal.zig");
const smp = @import("../../arch/x86_64/smp.zig");
const pic = @import("../../arch/x86_64/pic.zig");

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
    serial.writeString("  TIMER: Initializing PIT...\n");
    const divisor: u32 = PIT_FREQUENCY / TIMER_FREQUENCY;
    cpu.outb(PIT_COMMAND, 0x36);
    cpu.outb(PIT_CHANNEL0, @truncate(divisor & 0xFF));
    cpu.outb(PIT_CHANNEL0, @truncate((divisor >> 8) & 0xFF));
    ticks = 0;
    seconds = 0;
    preempt_counter = 0;
    serial.writeString("  TIMER: PIT configured at 100Hz\n");
}

/// PIT interrupt handler (IRQ0/vector 32)
/// B2.9a: This is only called when PIC IRQ0 is NOT masked
/// After APIC timer is enabled, this handler won't be called
pub fn handleInterrupt() void {
    ticks += 1;

    if ((ticks % 100) == 0) {
        seconds += 1;
    }

    // B2.9a: Only do scheduling work if APIC timer is NOT active
    // When APIC timer is active, it handles terminal.tick() and scheduler
    if (!smp.isApicTimerEnabled()) {
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
    }

    if (timer_callback) |callback| {
        callback();
    }
}

/// Get total ticks
/// B2.9a: Returns APIC ticks if APIC timer is active, else PIT ticks
pub fn getTicks() u64 {
    if (smp.isApicTimerEnabled()) {
        return smp.getTicks();
    }
    return ticks;
}

/// Get seconds since boot
/// B2.9a: Returns APIC seconds if APIC timer is active, else PIT seconds
pub fn getSeconds() u64 {
    if (smp.isApicTimerEnabled()) {
        return smp.getSeconds();
    }
    return seconds;
}

/// Get milliseconds since boot
/// B2.9a: Returns APIC millis if APIC timer is active, else PIT millis
pub fn getMillis() u64 {
    if (smp.isApicTimerEnabled()) {
        return smp.getMillis();
    }
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

/// B2.9a: Check which timer is active
pub fn isApicTimerActive() bool {
    return smp.isApicTimerEnabled();
}

pub fn test_timer() void {
    serial.writeString("\n[TIMER TEST]\n");
    serial.writeString("Timer source: ");
    serial.writeString(if (isApicTimerActive()) "APIC\n" else "PIT\n");
    serial.writeString("Ticks: ");
    var t = getTicks();
    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        const hex = "0123456789ABCDEF";
        serial.writeChar(hex[@intCast((t >> 60) & 0xF)]);
        t <<= 4;
    }
    serial.writeString("\n");
    serial.writeString("Seconds: ");
    printDec(getSeconds());
    serial.writeString("\n");
    serial.writeString("Millis: ");
    printDec(getMillis());
    serial.writeString("\n");
}

fn printDec(value: u64) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = value;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
