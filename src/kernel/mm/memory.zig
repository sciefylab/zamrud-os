//! Zamrud OS - Memory Management

const serial = @import("../drivers/serial/serial.zig");
const limine = @import("../core/limine.zig");

// Read 1 byte at a time
fn readU8(addr: u64) u8 {
    var result: u8 = undefined;
    asm volatile ("movb (%[addr]), %[result]"
        : [result] "=r" (result),
        : [addr] "r" (addr),
    );
    return result;
}

// Build u64 from bytes
fn readU64(addr: u64) u64 {
    var result: u64 = 0;
    var offset: u64 = 0;
    while (offset < 8) : (offset += 1) {
        const byte = readU8(addr + offset);
        result |= @as(u64, byte) << @intCast(offset * 8);
    }
    return result;
}

// Print small decimal number (0-9999) without division
fn printSmallDec(value: u64) void {
    if (value >= 1000) {
        serial.writeChar(@truncate((value / 1000) % 10 + '0'));
    }
    if (value >= 100) {
        serial.writeChar(@truncate((value / 100) % 10 + '0'));
    }
    if (value >= 10) {
        serial.writeChar(@truncate((value / 10) % 10 + '0'));
    }
    serial.writeChar(@truncate(value % 10 + '0'));
}

pub fn init(
    memmap_request: *limine.MemoryMapRequest,
    hhdm_request: *limine.HhdmRequest,
) void {
    serial.writeString("\n========================================\n");
    serial.writeString("  Memory Management Init\n");
    serial.writeString("========================================\n");

    // Check HHDM
    if (hhdm_request.response) |hhdm| {
        serial.writeString("[MEM] HHDM offset: ");
        printHex64(hhdm.offset);
        serial.writeString("\n");
    }

    // Check memory map response
    const response = memmap_request.response orelse {
        serial.writeString("[ERROR] No memory map response!\n");
        return;
    };

    const response_addr = @intFromPtr(response);
    const entry_count = readU64(response_addr + 8);
    const entries_addr = readU64(response_addr + 16);

    serial.writeString("[MEM] Entries: ");
    printSmallDec(entry_count);
    serial.writeString("\n\n");

    if (entry_count == 0 or entry_count > 256) {
        serial.writeString("[ERROR] Invalid entry count!\n");
        return;
    }

    // Iterate entries
    var total_usable: u64 = 0;
    var i: u64 = 0;

    while (i < entry_count) : (i += 1) {
        const entry_addr = readU64(entries_addr + i * 8);

        const base = readU64(entry_addr);
        const length = readU64(entry_addr + 8);
        const kind = readU64(entry_addr + 16);

        serial.writeString("  [");
        printSmallDec(i);
        serial.writeString("] ");

        printHex64(base);
        serial.writeString("-");
        printHex64(base + length - 1);
        serial.writeString(" ");

        // Size in MB
        const size_mb = length / (1024 * 1024);
        printSmallDec(size_mb);
        serial.writeString("MB ");

        // Type
        switch (kind) {
            0 => {
                serial.writeString("USABLE");
                total_usable += length;
            },
            1 => serial.writeString("RESERVED"),
            2 => serial.writeString("ACPI_RECLAIM"),
            3 => serial.writeString("ACPI_NVS"),
            4 => serial.writeString("BAD"),
            5 => serial.writeString("BOOTLOADER"),
            6 => serial.writeString("KERNEL"),
            7 => serial.writeString("FRAMEBUFFER"),
            else => serial.writeString("UNKNOWN"),
        }

        serial.writeString("\n");
    }

    serial.writeString("\n[MEM] Total usable: ");
    printSmallDec(total_usable / (1024 * 1024));
    serial.writeString(" MB\n");

    serial.writeString("========================================\n\n");
}

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    serial.writeString("0x");

    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nibble: u8 = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

// check point 8 scheduller
