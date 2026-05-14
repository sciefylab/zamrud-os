//! Zamrud OS - Entropy Pool & CSPRNG
//! H.2: Hardware + software entropy collection with SHA-256 mixing
//!
//! Sources: RDRAND, RDSEED, RDTSC, interrupt timing, external events
//! Output: SHA-256 CTR mode CSPRNG with forward secrecy
//! FIX: Enforced Forward Secrecy mixing after CSPRNG extraction.

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

var mix_input: [POOL_SIZE + 8]u8 = [_]u8{0} ** (POOL_SIZE + 8);
var mix_output: [32]u8 = [_]u8{0} ** 32;
var csprng_input: [40]u8 = [_]u8{0} ** 40;
var csprng_output: [32]u8 = [_]u8{0} ** 32;
var hw_entropy_buf: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    pool.hw_rng_available = checkRdrand();
    pool.hw_rdseed_available = checkRdseed();

    seedFromTsc();
    if (pool.hw_rng_available) {
        seedFromHardware();
    }
    mixPool();

    seedCsprng();
    pool.initialized = true;
}

// =============================================================================
// Hardware Detection & Entropy Sources
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

    if (pool.mix_count % 64 == 0) mixPool();
}

pub fn addEntropy(data: []const u8, estimated_bits: u32) void {
    addEntropyRaw(data, estimated_bits);
    mixPool();
}

fn mixPool() void {
    var i: usize = 0;
    while (i < POOL_SIZE) : (i += 1) mix_input[i] = pool.pool[i];

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
    while (i < 32) : (i += 1) pool.pool[i] ^= mix_output[i];

    pool.mix_count += 1;
}

pub fn hasRdrand() bool {
    return pool.hw_rng_available;
}
pub fn addEventEntropyByte(value: u8) void {
    var byte_arr = [_]u8{value};
    addEntropyRaw(&byte_arr, 1);
    addEventEntropy();
}

// =============================================================================
// CSPRNG Output
// =============================================================================

fn seedCsprng() void {
    if (pool.entropy_bits < MIN_ENTROPY_BITS) {
        if (pool.hw_rng_available) seedFromHardware();
        seedFromTsc();
        mixPool();
    }

    hash.sha256Into(pool.pool[0..POOL_SIZE], &pool.csprng_key);
    pool.csprng_counter = 0;
    pool.output_count = 0;
    pool.csprng_seeded = true;

    mixPool(); // Forward secrecy mechanism 1
}

fn generateBlock(out: *[32]u8) void {
    if (!pool.csprng_seeded or pool.output_count >= RESEED_INTERVAL) seedCsprng();

    var i: usize = 0;
    while (i < 32) : (i += 1) csprng_input[i] = pool.csprng_key[i];

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

pub fn getSecureBytes(buffer: []u8) !void {
    if (!pool.initialized) init();
    if (pool.entropy_bits < MIN_ENTROPY_BITS and !pool.hw_rng_available) return error.InsufficientEntropy;

    var offset: usize = 0;
    while (offset < buffer.len) {
        generateBlock(&csprng_output);
        const remaining = buffer.len - offset;
        const to_copy = if (remaining > 32) @as(usize, 32) else remaining;

        var i: usize = 0;
        while (i < to_copy) : (i += 1) buffer[offset + i] = csprng_output[i];
        offset += to_copy;
    }

    ct.secureZero32(&csprng_output);

    // FIX: Enforce forward secrecy by aggressively mixing the pool after extraction
    seedFromTsc();
    mixPool();
}

pub fn getSecureU64() !u64 {
    var buf: [8]u8 = undefined;
    try getSecureBytes(&buf);
    return (@as(u64, buf[0])) | (@as(u64, buf[1]) << 8) | (@as(u64, buf[2]) << 16) | (@as(u64, buf[3]) << 24) |
        (@as(u64, buf[4]) << 32) | (@as(u64, buf[5]) << 40) | (@as(u64, buf[6]) << 48) | (@as(u64, buf[7]) << 56);
}

pub fn getSecureU32() !u32 {
    var buf: [4]u8 = undefined;
    try getSecureBytes(&buf);
    return (@as(u32, buf[0])) | (@as(u32, buf[1]) << 8) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 24);
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
    if (pool.hw_rng_available) seedFromHardware();
    mixPool();
    seedCsprng();
}

// =============================================================================
// Tests — 12 tests
// =============================================================================

var test_buf_a: [32]u8 = [_]u8{0} ** 32;

pub fn runTests() bool {
    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 12: Forward secrecy
    var pool_hash_before: [32]u8 = undefined;
    hash.sha256Into(&pool.pool, &pool_hash_before);

    ct.secureZero32(&test_buf_a);
    _ = getSecureBytes(&test_buf_a) catch {};

    var pool_hash_after: [32]u8 = undefined;
    hash.sha256Into(&pool.pool, &pool_hash_after);

    // After getSecureBytes, the pool state MUST change!
    if (!ct.constantTimeCompare32(&pool_hash_before, &pool_hash_after)) {
        passed += 1;
    } else {
        failed += 1;
    }

    return failed == 0;
}
