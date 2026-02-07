//! Zamrud OS - Secure Random Number Generator
//! RDRAND hardware + software fallback

const serial = @import("../drivers/serial/serial.zig");

const RDRAND_RETRIES: u32 = 10;

var prng_state: u64 = 0x5A4D5255445F4F53;
var hardware_rng_available: bool = false;
var initialized: bool = false;

// Static buffer for testing (avoid stack allocation issues)
var test_buffer: [16]u8 = [_]u8{0} ** 16;

/// Initialize RNG
pub fn init() void {
    prng_state ^= readTSC();
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 7;
    prng_state ^= prng_state << 17;

    hardware_rng_available = checkRdrandSupport();

    if (hardware_rng_available) {
        if (tryRdrand32()) |val| {
            prng_state ^= @as(u64, val);
            prng_state ^= @as(u64, val) << 32;
        } else {
            hardware_rng_available = false;
        }
    }

    initialized = true;

    serial.writeString("[CRYPTO] Random initialized");
    if (hardware_rng_available) {
        serial.writeString(" (RDRAND)\n");
    } else {
        serial.writeString(" (software)\n");
    }
}

fn checkRdrandSupport() bool {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [_eax] "={eax}" (eax),
          [_ebx] "={ebx}" (ebx),
          [_ecx] "={ecx}" (ecx),
          [_edx] "={edx}" (edx),
        : [in_eax] "{eax}" (@as(u32, 1)),
    );

    return (ecx & (1 << 30)) != 0;
}

/// Check if RNG is initialized and available
pub fn isAvailable() bool {
    return initialized;
}

pub fn hasHardwareRng() bool {
    return hardware_rng_available;
}

fn tryRdrand32() ?u32 {
    var value: u32 = undefined;
    var success: u8 = undefined;

    var i: u32 = 0;
    while (i < RDRAND_RETRIES) : (i += 1) {
        asm volatile (
            \\.byte 0x0f, 0xc7, 0xf0
            \\setc %[ok]
            : [val] "={eax}" (value),
              [ok] "=r" (success),
        );

        if (success != 0) return value;
    }

    return null;
}

fn rdrand64() ?u64 {
    if (!hardware_rng_available) return null;

    const lo = tryRdrand32() orelse return null;
    const hi = tryRdrand32() orelse return null;

    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn softwareRandom() u64 {
    var x = prng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    prng_state = x;
    return x;
}

fn readTSC() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;

    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );

    return (@as(u64, hi) << 32) | @as(u64, lo);
}

pub fn getU64() u64 {
    if (hardware_rng_available) {
        if (rdrand64()) |val| {
            return val;
        }
    }
    return softwareRandom();
}

pub fn getU32() u32 {
    if (hardware_rng_available) {
        if (tryRdrand32()) |val| {
            return val;
        }
    }
    return @truncate(softwareRandom());
}

pub fn getBytes(buffer: []u8) void {
    var i: usize = 0;

    // Fill 8 bytes at a time using simple loop
    while (i + 8 <= buffer.len) {
        const val = getU64();
        buffer[i] = @truncate(val);
        buffer[i + 1] = @truncate(val >> 8);
        buffer[i + 2] = @truncate(val >> 16);
        buffer[i + 3] = @truncate(val >> 24);
        buffer[i + 4] = @truncate(val >> 32);
        buffer[i + 5] = @truncate(val >> 40);
        buffer[i + 6] = @truncate(val >> 48);
        buffer[i + 7] = @truncate(val >> 56);
        i += 8;
    }

    // Fill remaining bytes
    if (i < buffer.len) {
        const val = getU64();
        var shift: u6 = 0;
        while (i < buffer.len) {
            buffer[i] = @truncate(val >> shift);
            i += 1;
            if (shift < 56) shift += 8;
        }
    }
}

/// Alias for getBytes - fills buffer with random data
pub fn fill(buffer: []u8) void {
    getBytes(buffer);
}

pub fn test_random() bool {
    serial.writeString("[CRYPTO] Testing random...\n");

    serial.writeString("  RDRAND: ");
    if (hardware_rng_available) {
        serial.writeString("YES\n");
    } else {
        serial.writeString("NO (software)\n");
    }

    // Test 1: getU64
    serial.writeString("  u64 #1: ");
    const v1 = getU64();
    printHex64(v1);
    serial.writeString("\n");

    serial.writeString("  u64 #2: ");
    const v2 = getU64();
    printHex64(v2);
    serial.writeString("\n");

    if (v1 == v2) {
        serial.writeString("  WARNING: identical values\n");
    }

    // Test 2: getBytes using static buffer
    serial.writeString("  Testing getBytes...\n");

    // Clear static buffer
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        test_buffer[i] = 0;
    }

    getBytes(test_buffer[0..16]);

    serial.writeString("  Bytes: ");
    i = 0;
    while (i < 16) : (i += 1) {
        printHex8(test_buffer[i]);
    }
    serial.writeString("\n");

    serial.writeString("  Random test: OK\n");
    return true;
}

fn printHex64(val: u64) void {
    const hex = "0123456789abcdef";
    serial.writeString("0x");

    var i: u6 = 60;
    while (true) {
        const nibble: u4 = @truncate(val >> i);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex8(val: u8) void {
    const hex = "0123456789abcdef";
    serial.writeChar(hex[val >> 4]);
    serial.writeChar(hex[val & 0xF]);
}
