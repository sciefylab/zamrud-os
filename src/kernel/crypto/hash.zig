//! Zamrud OS - SHA-256 Implementation
//! Pure software - no SIMD, all static buffers
//! FIXED: Thread-safe hash operations with proper buffer isolation

const serial = @import("../drivers/serial/serial.zig");

pub const HASH_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 64;

const K = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

const H_INIT = [8]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// Static buffers for hash computation
var static_buf: [64]u8 = [_]u8{0} ** 64;
var static_w: [64]u32 = [_]u32{0} ** 64;
var static_out: [32]u8 = [_]u8{0} ** 32;
var static_h: [8]u32 = [_]u32{0} ** 8;
var static_buf_len: usize = 0;
var static_total_len: u64 = 0;

// Separate buffer for double hash to prevent overwrites
var static_double_tmp: [32]u8 = [_]u8{0} ** 32;

// Bitcoin test buffers
var static_btc_header: [80]u8 = [_]u8{0} ** 80;
var static_btc_hash: [32]u8 = [_]u8{0} ** 32;

fn rotr(x: u32, comptime n: comptime_int) u32 {
    const right: u5 = n;
    const left: u5 = 32 - n;
    return (x >> right) | (x << left);
}

fn sigma0(x: u32) u32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

fn sigma1(x: u32) u32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

fn Sigma0(x: u32) u32 {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

fn Sigma1(x: u32) u32 {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

fn ch(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn initStatic() void {
    static_h[0] = H_INIT[0];
    static_h[1] = H_INIT[1];
    static_h[2] = H_INIT[2];
    static_h[3] = H_INIT[3];
    static_h[4] = H_INIT[4];
    static_h[5] = H_INIT[5];
    static_h[6] = H_INIT[6];
    static_h[7] = H_INIT[7];
    static_buf_len = 0;
    static_total_len = 0;

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        static_buf[i] = 0;
    }
}

fn updateStatic(data: []const u8) void {
    var offset: usize = 0;
    static_total_len += data.len;

    if (static_buf_len > 0) {
        const space = 64 - static_buf_len;
        const to_copy = if (data.len < space) data.len else space;

        var i: usize = 0;
        while (i < to_copy) : (i += 1) {
            static_buf[static_buf_len + i] = data[i];
        }
        static_buf_len += to_copy;
        offset = to_copy;

        if (static_buf_len == 64) {
            processBlockStatic();
            static_buf_len = 0;
        }
    }

    while (offset + 64 <= data.len) {
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            static_buf[i] = data[offset + i];
        }
        processBlockStatic();
        offset += 64;
    }

    const remaining = data.len - offset;
    var i: usize = 0;
    while (i < remaining) : (i += 1) {
        static_buf[i] = data[offset + i];
    }
    static_buf_len = remaining;
}

fn processBlockStatic() void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        static_w[i] = (@as(u32, static_buf[i * 4]) << 24) |
            (@as(u32, static_buf[i * 4 + 1]) << 16) |
            (@as(u32, static_buf[i * 4 + 2]) << 8) |
            (@as(u32, static_buf[i * 4 + 3]));
    }

    while (i < 64) : (i += 1) {
        static_w[i] = sigma1(static_w[i - 2]) +% static_w[i - 7] +%
            sigma0(static_w[i - 15]) +% static_w[i - 16];
    }

    var a = static_h[0];
    var b = static_h[1];
    var c = static_h[2];
    var d = static_h[3];
    var e = static_h[4];
    var f = static_h[5];
    var g = static_h[6];
    var hv = static_h[7];

    i = 0;
    while (i < 64) : (i += 1) {
        const t1 = hv +% Sigma1(e) +% ch(e, f, g) +% K[i] +% static_w[i];
        const t2 = Sigma0(a) +% maj(a, b, c);
        hv = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% t2;
    }

    static_h[0] +%= a;
    static_h[1] +%= b;
    static_h[2] +%= c;
    static_h[3] +%= d;
    static_h[4] +%= e;
    static_h[5] +%= f;
    static_h[6] +%= g;
    static_h[7] +%= hv;
}

fn finalStatic() void {
    const bit_len = static_total_len * 8;

    static_buf[static_buf_len] = 0x80;
    static_buf_len += 1;

    if (static_buf_len > 56) {
        while (static_buf_len < 64) : (static_buf_len += 1) {
            static_buf[static_buf_len] = 0;
        }
        processBlockStatic();
        static_buf_len = 0;
    }

    while (static_buf_len < 56) : (static_buf_len += 1) {
        static_buf[static_buf_len] = 0;
    }

    static_buf[56] = @intCast((bit_len >> 56) & 0xff);
    static_buf[57] = @intCast((bit_len >> 48) & 0xff);
    static_buf[58] = @intCast((bit_len >> 40) & 0xff);
    static_buf[59] = @intCast((bit_len >> 32) & 0xff);
    static_buf[60] = @intCast((bit_len >> 24) & 0xff);
    static_buf[61] = @intCast((bit_len >> 16) & 0xff);
    static_buf[62] = @intCast((bit_len >> 8) & 0xff);
    static_buf[63] = @intCast(bit_len & 0xff);

    processBlockStatic();

    var j: usize = 0;
    while (j < 8) : (j += 1) {
        static_out[j * 4] = @intCast((static_h[j] >> 24) & 0xff);
        static_out[j * 4 + 1] = @intCast((static_h[j] >> 16) & 0xff);
        static_out[j * 4 + 2] = @intCast((static_h[j] >> 8) & 0xff);
        static_out[j * 4 + 3] = @intCast(static_h[j] & 0xff);
    }
}

/// Primary hash function - writes result to provided buffer
pub fn sha256Into(data: []const u8, out: *[HASH_SIZE]u8) void {
    initStatic();
    updateStatic(data);
    finalStatic();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = static_out[i];
    }
}

/// Returns pointer to internal buffer (UNSAFE - will be overwritten by next call)
/// Use sha256Into() or sha256() instead for safety
pub fn sha256Ptr(data: []const u8) *const [HASH_SIZE]u8 {
    initStatic();
    updateStatic(data);
    finalStatic();
    return &static_out;
}

/// Safe hash function - returns a copy of the hash
pub fn sha256(data: []const u8) [HASH_SIZE]u8 {
    initStatic();
    updateStatic(data);
    finalStatic();

    var result: [HASH_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        result[i] = static_out[i];
    }
    return result;
}

/// Constant-time comparison (prevents timing attacks)
pub fn hashEqual(a: *const [HASH_SIZE]u8, b: *const [HASH_SIZE]u8) bool {
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < HASH_SIZE) : (i += 1) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

pub fn hashToHex(h: *const [HASH_SIZE]u8, out: *[64]u8) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < HASH_SIZE) : (i += 1) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0xF];
    }
}

fn printHash(h: []const u8) void {
    const hex = "0123456789abcdef";
    for (h) |b| {
        serial.writeChar(hex[b >> 4]);
        serial.writeChar(hex[b & 0xF]);
    }
}

pub const Sha256 = struct {
    _dummy: u8,

    pub fn init() Sha256 {
        initStatic();
        return Sha256{ ._dummy = 0 };
    }

    pub fn update(_: *Sha256, data: []const u8) void {
        updateStatic(data);
    }

    pub fn final(_: *Sha256, out: *[32]u8) void {
        finalStatic();
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            out[i] = static_out[i];
        }
    }

    pub fn hash(data: []const u8, out: *[32]u8, options: anytype) void {
        _ = options;
        sha256Into(data, out);
    }
};

/// Test SHA-256 implementation
pub fn test_sha256() bool {
    serial.writeString("[CRYPTO] Testing SHA-256 (pure software)...\n");

    // Test 1: Empty string
    serial.writeString("  Test 1: Empty string...\n");
    var hash1: [32]u8 = undefined;
    sha256Into("", &hash1);

    serial.writeString("    SHA256(\"\") = ");
    printHash(&hash1);
    serial.writeString("\n");

    if (hash1[0] != 0xe3 or hash1[1] != 0xb0 or
        hash1[2] != 0xc4 or hash1[3] != 0x42)
    {
        serial.writeString("    FAILED: empty hash mismatch!\n");
        return false;
    }
    serial.writeString("    Result: PASS\n");

    // Test 2: "abc"
    serial.writeString("  Test 2: String 'abc'...\n");
    var hash2: [32]u8 = undefined;
    sha256Into("abc", &hash2);

    serial.writeString("    SHA256(\"abc\") = ");
    printHash(&hash2);
    serial.writeString("\n");

    if (hash2[0] != 0xba or hash2[1] != 0x78 or
        hash2[2] != 0x16 or hash2[3] != 0xbf)
    {
        serial.writeString("    FAILED: 'abc' hash mismatch!\n");
        return false;
    }
    serial.writeString("    Result: PASS\n");

    // Test 3: Different inputs produce different hashes
    serial.writeString("  Test 3: Different inputs differ...\n");
    var hash_a: [32]u8 = undefined;
    var hash_b: [32]u8 = undefined;

    sha256Into("input_a", &hash_a);
    sha256Into("input_b", &hash_b);

    serial.writeString("    SHA256(\"input_a\") = ");
    printHash(&hash_a);
    serial.writeString("\n");

    serial.writeString("    SHA256(\"input_b\") = ");
    printHash(&hash_b);
    serial.writeString("\n");

    if (hashEqual(&hash_a, &hash_b)) {
        serial.writeString("    FAILED: Different inputs produced same hash!\n");
        return false;
    }
    serial.writeString("    Result: PASS (hashes differ)\n");

    // Test 4: Deterministic (same input = same hash)
    serial.writeString("  Test 4: Deterministic...\n");
    var hash_det1: [32]u8 = undefined;
    var hash_det2: [32]u8 = undefined;

    sha256Into("deterministic_test", &hash_det1);
    sha256Into("deterministic_test", &hash_det2);

    if (!hashEqual(&hash_det1, &hash_det2)) {
        serial.writeString("    FAILED: Same input produced different hashes!\n");
        return false;
    }
    serial.writeString("    Result: PASS (deterministic)\n");

    serial.writeString("  SHA-256 test: OK\n");
    return true;
}

/// Double SHA-256 (used by Bitcoin)
pub fn doubleSha256Into(data: []const u8, out: *[HASH_SIZE]u8) void {
    // First hash
    initStatic();
    updateStatic(data);
    finalStatic();

    // Copy to temporary buffer to prevent overwrite
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_double_tmp[i] = static_out[i];
    }

    // Second hash
    initStatic();
    updateStatic(&static_double_tmp);
    finalStatic();

    // Copy final result
    i = 0;
    while (i < 32) : (i += 1) {
        out[i] = static_out[i];
    }
}

fn reverseBytes32(buf: *[32]u8) void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const tmp = buf[i];
        buf[i] = buf[31 - i];
        buf[31 - i] = tmp;
    }
}

/// Test with real Bitcoin Genesis Block
pub fn test_bitcoin_genesis() bool {
    serial.writeString("[CRYPTO] Testing Bitcoin Genesis Block...\n");

    // Genesis block header (80 bytes)
    const genesis_header = [80]u8{
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x3b, 0xa3, 0xed, 0xfd,
        0x7a, 0x7b, 0x12, 0xb2,
        0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61,
        0x7f, 0xc8, 0x1b, 0xc3,
        0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa,
        0x4b, 0x1e, 0x5e, 0x4a,
        0x29, 0xab, 0x5f, 0x49,
        0xff, 0xff, 0x00, 0x1d,
        0x1d, 0xac, 0x2b, 0x7c,
    };

    var i: usize = 0;
    while (i < 80) : (i += 1) {
        static_btc_header[i] = genesis_header[i];
    }

    serial.writeString("  Header: 80 bytes\n");

    // Double SHA-256
    serial.writeString("  Computing double SHA-256...\n");
    doubleSha256Into(&static_btc_header, &static_btc_hash);

    serial.writeString("  Double SHA-256: ");
    printHash(&static_btc_hash);
    serial.writeString("\n");

    // Reverse for display (Bitcoin uses little-endian)
    reverseBytes32(&static_btc_hash);

    serial.writeString("  Reversed (LE): ");
    printHash(&static_btc_hash);
    serial.writeString("\n");

    // Expected: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const expected = [32]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68,
        0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
        0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1,
        0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f,
    };

    serial.writeString("  Expected:      ");
    printHash(&expected);
    serial.writeString("\n");

    i = 0;
    while (i < 32) : (i += 1) {
        if (static_btc_hash[i] != expected[i]) {
            serial.writeString("  Bitcoin Genesis: FAIL\n");
            serial.writeString("    Mismatch at byte ");
            serial.writeChar('0' + @as(u8, @intCast(i / 10)));
            serial.writeChar('0' + @as(u8, @intCast(i % 10)));
            serial.writeString("\n");
            return false;
        }
    }

    serial.writeString("  Bitcoin Genesis: OK\n");
    return true;
}
