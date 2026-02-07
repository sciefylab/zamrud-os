//! Zamrud OS - Test Processes

const serial = @import("../drivers/serial/serial.zig");
const scheduler = @import("scheduler.zig");
const cpu = @import("../core/cpu.zig");

const MAX_COUNT: u32 = 20;

/// Entry wrapper - naked function
/// r12 berisi argument, move ke rdi sebelum call process
export fn _processEntryWrapper() callconv(.naked) noreturn {
    asm volatile (
        \\movq %%r12, %%rdi
        \\call counterProcessImpl
        \\1:
        \\cli
        \\hlt
        \\jmp 1b
    );
}

/// Get wrapper address
pub fn getCounterProcessEntry() u64 {
    return @intFromPtr(&_processEntryWrapper);
}

/// Actual process implementation
export fn counterProcessImpl(id: u64) void {
    const my_id: u8 = @intCast(id & 0xF);

    serial.writeString("[P");
    serial.writeChar('0' + my_id);
    serial.writeString("] Start\n");

    var counter: u32 = 0;

    while (counter < MAX_COUNT) {
        serial.writeString("[P");
        serial.writeChar('0' + my_id);
        serial.writeString("] ");
        printHex32(counter);
        serial.writeString("\n");

        counter += 1;

        var d: u32 = 0;
        while (d < 2000000) : (d += 1) {
            asm volatile ("nop");
        }
    }

    serial.writeString("[P");
    serial.writeChar('0' + my_id);
    serial.writeString("] EXIT\n");

    scheduler.exitCurrentProcess();

    // Never reached
    while (true) {
        cpu.hlt();
    }
}

/// Legacy - tidak dipakai langsung
pub fn counterProcess(id: u64) noreturn {
    _ = id;
    while (true) {
        cpu.hlt();
    }
}

pub fn idleProcess(id: u64) noreturn {
    _ = id;
    cpu.sti();
    while (true) {
        asm volatile ("hlt");
    }
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

// check point 8 scheduller
