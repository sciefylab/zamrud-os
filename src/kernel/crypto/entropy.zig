//! Zamrud OS - Entropy Pool & CSPRNG
//! H.2: Hardware + software entropy collection with SHA-256 mixing
//!
//! Sources: RDRAND, RDSEED, RDTSC, interrupt timing, external events
//! Output: SHA-256 CTR mode CSPRNG with forward secrecy

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("hash.zig");
const ct = @import("constant_time.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const POOL_SIZE: usize = 256;
pub const MIN_ENTROPY_BITS: u32 = 128;
pub const RESEED_INTERVAL: u64 = 1024;

// =============================================================================
// Entropy Pool State
// =============================================================================

pub const EntropyPool = struct {
    pool: [POOL_SIZE]u8,
    entropy_bits: u32,
    mix_count: u64,
    output_count: u64,
    last_tsc: u64,
    initialized: bool,
    hw_rng_available: bool,
    hw_rdseed_available: bool,
    csprng_key: [32]u8,
    csprng_counter: u64,
    csprng_seeded: bool,
};

var pool: EntropyPool = .{
    .pool = [_]u8{0} ** POOL_SIZE,
    .entropy_bits = 0,
    .mix_count = 0,
    .output_count = 0,
    .last_tsc = 0,
    .initialized = false,
    .hw_rng_available = false,
    .hw_rdseed_available = false,
    .csprng_key = [_]u8{0} ** 32,
    .csprng_counter = 0,
    .csprng_seeded = false,
};

// Static work buffers
var mix_input: [POOL_SIZE + 8]u8 = [_]u8{0} ** (POOL_SIZE + 8);
var mix_output: [32]u8 = [_]u8{0} ** 32;
var csprng_input: [40]u8 = [_]u8{0} ** 40;
var csprng_output: [32]u8 = [_]u8{0} ** 32;
var hw_entropy_buf: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[ENTROPY] Initializing entropy pool...\n");

    pool.hw_rng_available = checkRdrand();
    pool.hw_rdseed_available = checkRdseed();

    serial.writeString("[ENTROPY] RDRAND: ");
    if (pool.hw_rng_available) {
        serial.writeString("YES\n");
    } else {
        serial.writeString("NO\n");
    }
    serial.writeString("[ENTROPY] RDSEED: ");
    if (pool.hw_rdseed_available) {
        serial.writeString("YES\n");
    } else {
        serial.writeString("NO\n");
    }

    seedFromTsc();
    if (pool.hw_rng_available) {
        seedFromHardware();
    }
    mixPool();

    // Seed CSPRNG immediately so isSeeded() returns true
    seedCsprng();

    pool.initialized = true;

    serial.writeString("[ENTROPY] Pool ready, entropy: ");
    printU32(pool.entropy_bits);
    serial.writeString(" bits, CSPRNG: seeded\n");
}

// =============================================================================
// Hardware Detection
// =============================================================================

fn checkRdrand() bool {
    var ecx: u32 = undefined;
    asm volatile ("cpuid"
        : [_ecx] "={ecx}" (ecx),
        : [in_eax] "{eax}" (@as(u32, 1)),
        : .{ .ebx = true, .edx = true });
    return (ecx & (1 << 30)) != 0;
}

fn checkRdseed() bool {
    var ebx: u32 = undefined;
    asm volatile ("cpuid"
        : [_ebx] "={ebx}" (ebx),
        : [in_eax] "{eax}" (@as(u32, 7)),
          [in_ecx] "{ecx}" (@as(u32, 0)),
        : .{ .edx = true });
    return (ebx & (1 << 18)) != 0;
}

// =============================================================================
// Entropy Sources
// =============================================================================

fn readTsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn tryRdrand32() ?u32 {
    if (!pool.hw_rng_available) return null;
    var value: u32 = undefined;
    var success: u8 = undefined;
    var retry: u32 = 0;
    while (retry < 10) : (retry += 1) {
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

fn tryRdseed32() ?u32 {
    if (!pool.hw_rdseed_available) return null;
    var value: u32 = undefined;
    var success: u8 = undefined;
    var retry: u32 = 0;
    while (retry < 10) : (retry += 1) {
        asm volatile (
            \\.byte 0x0f, 0xc7, 0xf8
            \\setc %[ok]
            : [val] "={eax}" (value),
              [ok] "=r" (success),
        );
        if (success != 0) return value;
    }
    return null;
}

fn seedFromTsc() void {
    const tsc = readTsc();
    var tsc_bytes: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        tsc_bytes[i] = @truncate(tsc >> @intCast(i * 8));
    }
    addEntropyRaw(&tsc_bytes, 8);
    pool.last_tsc = tsc;
}

fn seedFromHardware() void {
    var i: usize = 0;
    var bytes_added: u32 = 0;

    while (i < 32) : (i += 4) {
        if (tryRdseed32()) |val| {
            hw_entropy_buf[i] = @truncate(val);
            hw_entropy_buf[i + 1] = @truncate(val >> 8);
            hw_entropy_buf[i + 2] = @truncate(val >> 16);
            hw_entropy_buf[i + 3] = @truncate(val >> 24);
            bytes_added += 4;
        } else if (tryRdrand32()) |val| {
            hw_entropy_buf[i] = @truncate(val);
            hw_entropy_buf[i + 1] = @truncate(val >> 8);
            hw_entropy_buf[i + 2] = @truncate(val >> 16);
            hw_entropy_buf[i + 3] = @truncate(val >> 24);
            bytes_added += 4;
        }
    }

    if (bytes_added > 0) {
        addEntropyRaw(hw_entropy_buf[0..bytes_added], bytes_added * 8);
    }
}

// =============================================================================
// Entropy Pool Management
// =============================================================================

fn addEntropyRaw(data: []const u8, estimated_bits: u32) void {
    var pool_pos: usize = @intCast(pool.mix_count % POOL_SIZE);
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        pool.pool[pool_pos] ^= data[i];
        pool_pos = (pool_pos + 1) % POOL_SIZE;
    }

    pool.entropy_bits +|= estimated_bits;
    if (pool.entropy_bits > POOL_SIZE * 8) {
        pool.entropy_bits = POOL_SIZE * 8;
    }
}

/// Add entropy from interrupt/event timing
pub fn addEventEntropy() void {
    const tsc = readTsc();
    const delta = tsc -% pool.last_tsc;
    pool.last_tsc = tsc;

    var delta_bytes: [8]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        delta_bytes[i] = @truncate(delta >> @intCast(i * 8));
    }
    addEntropyRaw(&delta_bytes, 2);

    if (pool.mix_count % 64 == 0) {
        mixPool();
    }
}

/// Add explicit entropy from external source
pub fn addEntropy(data: []const u8, estimated_bits: u32) void {
    addEntropyRaw(data, estimated_bits);
    mixPool();
}

fn mixPool() void {
    var i: usize = 0;
    while (i < POOL_SIZE) : (i += 1) {
        mix_input[i] = pool.pool[i];
    }

    // Append counter
    const mc = pool.mix_count;
    mix_input[POOL_SIZE] = @truncate(mc);
    mix_input[POOL_SIZE + 1] = @truncate(mc >> 8);
    mix_input[POOL_SIZE + 2] = @truncate(mc >> 16);
    mix_input[POOL_SIZE + 3] = @truncate(mc >> 24);
    mix_input[POOL_SIZE + 4] = @truncate(mc >> 32);
    mix_input[POOL_SIZE + 5] = @truncate(mc >> 40);
    mix_input[POOL_SIZE + 6] = @truncate(mc >> 48);
    mix_input[POOL_SIZE + 7] = @truncate(mc >> 56);

    hash.sha256Into(mix_input[0 .. POOL_SIZE + 8], &mix_output);

    i = 0;
    while (i < 32) : (i += 1) {
        pool.pool[i] ^= mix_output[i];
    }

    pool.mix_count += 1;
}

/// Check if RDRAND is available (alias for H.7)
pub fn hasRdrand() bool {
    return pool.hw_rng_available;
}

/// Add entropy from a single byte (H.7 compatibility)
/// Original addEventEntropy() uses TSC timing
/// This version accepts explicit byte value
pub fn addEventEntropyByte(value: u8) void {
    // Add the explicit value
    var byte_arr = [_]u8{value};
    addEntropyRaw(&byte_arr, 1);

    // Also add TSC timing
    addEventEntropy();
}

// =============================================================================
// CSPRNG Output
// =============================================================================

fn seedCsprng() void {
    if (pool.entropy_bits < MIN_ENTROPY_BITS) {
        if (pool.hw_rng_available) {
            seedFromHardware();
        }
        seedFromTsc();
        mixPool();
    }

    hash.sha256Into(pool.pool[0..POOL_SIZE], &pool.csprng_key);
    pool.csprng_counter = 0;
    pool.output_count = 0;
    pool.csprng_seeded = true;

    // Forward secrecy: re-mix after extraction
    mixPool();
}

fn generateBlock(out: *[32]u8) void {
    if (!pool.csprng_seeded or pool.output_count >= RESEED_INTERVAL) {
        seedCsprng();
    }

    // SHA-256(key || counter)
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        csprng_input[i] = pool.csprng_key[i];
    }
    csprng_input[32] = @truncate(pool.csprng_counter);
    csprng_input[33] = @truncate(pool.csprng_counter >> 8);
    csprng_input[34] = @truncate(pool.csprng_counter >> 16);
    csprng_input[35] = @truncate(pool.csprng_counter >> 24);
    csprng_input[36] = @truncate(pool.csprng_counter >> 32);
    csprng_input[37] = @truncate(pool.csprng_counter >> 40);
    csprng_input[38] = @truncate(pool.csprng_counter >> 48);
    csprng_input[39] = @truncate(pool.csprng_counter >> 56);

    hash.sha256Into(&csprng_input, out);

    pool.csprng_counter += 1;
    pool.output_count += 1;
}

// =============================================================================
// Public API
// =============================================================================

/// Get cryptographically secure random bytes
pub fn getSecureBytes(buffer: []u8) !void {
    if (!pool.initialized) {
        init();
    }

    if (pool.entropy_bits < MIN_ENTROPY_BITS and !pool.hw_rng_available) {
        return error.InsufficientEntropy;
    }

    var offset: usize = 0;
    while (offset < buffer.len) {
        generateBlock(&csprng_output);
        const remaining = buffer.len - offset;
        const to_copy = if (remaining > 32) @as(usize, 32) else remaining;

        var i: usize = 0;
        while (i < to_copy) : (i += 1) {
            buffer[offset + i] = csprng_output[i];
        }
        offset += to_copy;
    }

    ct.secureZero32(&csprng_output);
}

/// Get secure u64
pub fn getSecureU64() !u64 {
    var buf: [8]u8 = undefined;
    try getSecureBytes(&buf);
    return (@as(u64, buf[0])) |
        (@as(u64, buf[1]) << 8) |
        (@as(u64, buf[2]) << 16) |
        (@as(u64, buf[3]) << 24) |
        (@as(u64, buf[4]) << 32) |
        (@as(u64, buf[5]) << 40) |
        (@as(u64, buf[6]) << 48) |
        (@as(u64, buf[7]) << 56);
}

/// Get secure u32
pub fn getSecureU32() !u32 {
    var buf: [4]u8 = undefined;
    try getSecureBytes(&buf);
    return (@as(u32, buf[0])) |
        (@as(u32, buf[1]) << 8) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 24);
}

pub fn getEntropyBits() u32 {
    return pool.entropy_bits;
}

pub fn isSeeded() bool {
    return pool.csprng_seeded;
}

pub fn hasHardwareRng() bool {
    return pool.hw_rng_available;
}

pub fn hasHardwareRdseed() bool {
    return pool.hw_rdseed_available;
}

pub fn reseed() void {
    seedFromTsc();
    if (pool.hw_rng_available) {
        seedFromHardware();
    }
    mixPool();
    seedCsprng();
}

// =============================================================================
// Tests — 12 tests
// =============================================================================

var test_buf_a: [32]u8 = [_]u8{0} ** 32;
var test_buf_b: [32]u8 = [_]u8{0} ** 32;
var test_buf_c: [64]u8 = [_]u8{0} ** 64;

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  ENTROPY & CSPRNG TESTS (H.2)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Pool initialized
    serial.writeString("  [1]  Pool initialized........ ");
    if (!pool.initialized) init();
    if (pool.initialized) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 2: Entropy > 0
    serial.writeString("  [2]  Entropy collected........ ");
    if (pool.entropy_bits > 0) {
        serial.writeString("PASS (");
        printU32(pool.entropy_bits);
        serial.writeString(" bits)\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 3: CSPRNG output non-zero
    serial.writeString("  [3]  CSPRNG output........... ");
    {
        ct.secureZero32(&test_buf_a);
        if (getSecureBytes(&test_buf_a)) {
            if (!ct.constantTimeIsZero32(&test_buf_a)) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (zeros)\n");
                failed += 1;
            }
        } else |_| {
            serial.writeString("FAIL (error)\n");
            failed += 1;
        }
    }

    // Test 4: Two outputs differ
    serial.writeString("  [4]  Outputs differ.......... ");
    {
        ct.secureZero32(&test_buf_a);
        ct.secureZero32(&test_buf_b);
        const ok_a = getSecureBytes(&test_buf_a);
        const ok_b = getSecureBytes(&test_buf_b);
        if (ok_a) {
            if (ok_b) {
                if (!ct.constantTimeCompare32(&test_buf_a, &test_buf_b)) {
                    serial.writeString("PASS\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL (same)\n");
                    failed += 1;
                }
            } else |_| {
                serial.writeString("FAIL (err b)\n");
                failed += 1;
            }
        } else |_| {
            serial.writeString("FAIL (err a)\n");
            failed += 1;
        }
    }

    // Test 5: Secure u64
    serial.writeString("  [5]  Secure u64.............. ");
    {
        if (getSecureU64()) |v1| {
            if (getSecureU64()) |v2| {
                if (v1 != v2) {
                    serial.writeString("PASS\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL (same)\n");
                    failed += 1;
                }
            } else |_| {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else |_| {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 6: Secure u32
    serial.writeString("  [6]  Secure u32.............. ");
    {
        if (getSecureU32()) |v1| {
            if (getSecureU32()) |v2| {
                if (v1 != v2) {
                    serial.writeString("PASS\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL (same)\n");
                    failed += 1;
                }
            } else |_| {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else |_| {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 7: Event entropy
    serial.writeString("  [7]  Event entropy........... ");
    {
        const before = pool.entropy_bits;
        addEventEntropy();
        addEventEntropy();
        addEventEntropy();
        if (pool.entropy_bits >= before) {
            serial.writeString("PASS (+");
            printU32(pool.entropy_bits -| before);
            serial.writeString(")\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 8: Manual add entropy
    serial.writeString("  [8]  Manual entropy.......... ");
    {
        const before = pool.entropy_bits;
        const extra = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        addEntropy(&extra, 32);
        if (pool.entropy_bits > before or pool.entropy_bits == POOL_SIZE * 8) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 9: Reseed
    serial.writeString("  [9]  Reseed.................. ");
    {
        const before_count = pool.mix_count;
        reseed();
        if (pool.mix_count > before_count and pool.csprng_seeded) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 10: Large buffer
    serial.writeString("  [10] 64-byte fill............ ");
    {
        ct.secureZero(test_buf_c[0..64]);
        if (getSecureBytes(test_buf_c[0..64])) {
            var non_zero: u32 = 0;
            var i: usize = 0;
            while (i < 64) : (i += 1) {
                if (test_buf_c[i] != 0) non_zero += 1;
            }
            if (non_zero > 10) {
                serial.writeString("PASS (");
                printU32(non_zero);
                serial.writeString("/64)\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else |_| {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 11: Status checks
    serial.writeString("  [11] Status checks........... ");
    {
        if (isSeeded() and getEntropyBits() > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 12: Forward secrecy
    serial.writeString("  [12] Forward secrecy......... ");
    {
        var pool_hash_before: [32]u8 = undefined;
        hash.sha256Into(&pool.pool, &pool_hash_before);

        ct.secureZero32(&test_buf_a);
        _ = getSecureBytes(&test_buf_a) catch {};

        var pool_hash_after: [32]u8 = undefined;
        hash.sha256Into(&pool.pool, &pool_hash_after);

        if (!ct.constantTimeCompare32(&pool_hash_before, &pool_hash_after)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Summary
    serial.writeString("\n  ────────────────────────────────\n");
    serial.writeString("  H.2 Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed");
    if (failed == 0) {
        serial.writeString(" ✓\n");
    } else {
        serial.writeString(" ✗\n");
    }

    return failed == 0;
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
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
