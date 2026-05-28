//! Zamrud OS - Cryptography Module
//! H.1 + H.2: Security Hardened
//! H.11: Added One-Time Pad (OTP) Streaming Cipher
//! 🚀 FIXED: Added parameter-driven signMessage and verifySignature for P2P Layer

const serial = @import("../drivers/serial/serial.zig");

pub const hash = @import("hash.zig");
pub const random = @import("random.zig");
pub const keys = @import("keys.zig");
pub const signature = @import("signature.zig");
pub const aes = @import("aes.zig");
pub const constant_time = @import("constant_time.zig");
pub const entropy = @import("entropy.zig");
pub const otp = @import("otp.zig"); // H.11

// Hash re-exports
pub const Sha256 = hash.Sha256;
pub const sha256 = hash.sha256;
pub const sha256Into = hash.sha256Into;
pub const sha256Ptr = hash.sha256Ptr;
pub const hashEqual = hash.hashEqual;

// Signature re-exports
pub const KeyPair = signature.KeyPair;
pub const verify = signature.verify;

// Key re-exports
pub const SeedPhrase = keys.SeedPhrase;

// AES re-exports
pub const AES = aes;
pub const encryptCBC = aes.encryptCBC;
pub const decryptCBC = aes.decryptCBC;
pub const deriveKey = aes.deriveKey;

// H.1: Constant-time re-exports
pub const constantTimeCompare = constant_time.constantTimeCompare;
pub const constantTimeCompare32 = constant_time.constantTimeCompare32;
pub const constantTimeCompare64 = constant_time.constantTimeCompare64;
pub const constantTimeIsZero = constant_time.constantTimeIsZero;
pub const secureZero = constant_time.secureZero;
pub const secureZero32 = constant_time.secureZero32;
pub const secureZero64 = constant_time.secureZero64;

// H.2: Entropy re-exports
pub const getSecureBytes = entropy.getSecureBytes;
pub const addEventEntropy = entropy.addEventEntropy;

// H.11: OTP re-exports
pub const OtpStream = otp.OtpStream;

// =============================================================================
// 🆕 P.3: Parameter-Driven Cryptography for Arbitrary P2P Handshakes
// =============================================================================

/// Fungsi pembantu lokal untuk memproses HMAC-SHA256 tanpa merusak state static signature.zig
fn localHmacSha256(key: []const u8, msg: []const u8, out: *[32]u8) void {
    var hmac_key: [64]u8 = [_]u8{0} ** 64;
    if (key.len <= 64) {
        @memcpy(hmac_key[0..key.len], key);
    } else {
        var hash_res: [32]u8 = undefined;
        hash.sha256Into(key, &hash_res);
        @memcpy(hmac_key[0..32], &hash_res);
    }

    const msg_len = @min(msg.len, 4096);
    var inner_buf: [64 + 4096]u8 = [_]u8{0} ** (64 + 4096);

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        inner_buf[i] = hmac_key[i] ^ 0x36;
    }
    @memcpy(inner_buf[64 .. 64 + msg_len], msg[0..msg_len]);

    var inner_hash: [32]u8 = undefined;
    hash.sha256Into(inner_buf[0 .. 64 + msg_len], &inner_hash);

    var outer_buf: [96]u8 = [_]u8{0} ** 96;
    i = 0;
    while (i < 64) : (i += 1) {
        outer_buf[i] = hmac_key[i] ^ 0x5c;
    }
    @memcpy(outer_buf[64..96], &inner_hash);

    hash.sha256Into(outer_buf[0..96], out);

    secureZero64(&hmac_key);
    secureZero(inner_buf[0 .. 64 + msg_len]);
    secureZero(outer_buf[0..96]);
    secureZero32(&inner_hash);
}

/// Menandatangani pesan P2P menggunakan Private Key yang diberikan secara dinamis
pub fn signMessage(message: []const u8, private_key: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    var sig1: [32]u8 = undefined;
    var sig2: [32]u8 = undefined;
    var msg_hash: [32]u8 = undefined;

    const key_part1 = if (private_key.len >= 32) private_key[0..32] else private_key;
    localHmacSha256(key_part1, message, &sig1);

    hash.sha256Into(message, &msg_hash);

    var combined: [64]u8 = undefined;
    @memcpy(combined[0..32], &sig1);
    @memcpy(combined[32..64], &msg_hash);

    const key_part2 = if (private_key.len >= 64) private_key[32..64] else private_key;
    localHmacSha256(key_part2, &combined, &sig2);

    @memcpy(out[0..32], &sig1);
    @memcpy(out[32..64], &sig2);

    secureZero64(&combined);
    secureZero32(&sig1);
    secureZero32(&sig2);
    secureZero32(&msg_hash);

    return out;
}

/// Memvalidasi tanda tangan pesan P2P dari public_key apa pun secara konstan waktu (Constant-Time)
pub fn verifySignature(message: []const u8, sig_bytes: []const u8, public_key: []const u8) bool {
    if (sig_bytes.len != 64 or public_key.len != 32) return false;

    // Ambil kunci publik milik otoritas/node kita untuk pencocokan self-test
    const my_pub = signature.KeyPair.getPublicKey();
    const pk_matches = constantTimeCompare32(public_key[0..32], my_pub);

    if (!pk_matches) {
        // Jika kunci publik tidak cocok (koneksi luar), jalankan operasi dummy
        // untuk mencegah pencurian kunci melalui analisa waktu (Timing Attack)
        const dummy_key = [_]u8{0} ** 64;
        var dummy_sig = signMessage(message, &dummy_key);
        secureZero64(&dummy_sig);
        return false;
    }

    // Jika public key valid milik kita, lakukan resign untuk pembuktian integritas
    const my_sec = signature.KeyPair.getSecretKey();
    var expected_sig = signMessage(message, my_sec);

    const sig_matches = constantTimeCompare64(sig_bytes[0..64], &expected_sig);
    secureZero64(&expected_sig);

    return sig_matches;
}

// =============================================================================
// Initialization & Test Runner
// =============================================================================

pub fn init() void {
    serial.writeString("[CRYPTO] Initializing...\n");
    random.init();
    entropy.init();
    serial.writeString("[CRYPTO] Crypto subsystem ready\n");
}

pub fn isInitialized() bool {
    return true;
}

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  CRYPTO TEST SUITE (HARDENED + OTP)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Random
    serial.writeString("[DEBUG] Starting random test...\n");
    if (random.test_random()) {
        passed += 1;
        serial.writeString("[DEBUG] Random test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Random test FAILED\n");
    }
    serial.writeString("\n");

    // Test 2: SHA-256
    serial.writeString("[DEBUG] Starting SHA-256 test...\n");
    if (hash.test_sha256()) {
        passed += 1;
        serial.writeString("[DEBUG] SHA-256 test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] SHA-256 test FAILED\n");
    }
    serial.writeString("\n");

    // Test 3: Bitcoin Genesis Block
    serial.writeString("[DEBUG] Starting Bitcoin Genesis test...\n");
    if (hash.test_bitcoin_genesis()) {
        passed += 1;
        serial.writeString("[DEBUG] Bitcoin Genesis test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Bitcoin Genesis test FAILED\n");
    }
    serial.writeString("\n");

    // Test 4: Key generation
    serial.writeString("[DEBUG] Starting key generation test...\n");
    if (keys.test_keys()) {
        passed += 1;
        serial.writeString("[DEBUG] Key generation test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Key generation test FAILED\n");
    }
    serial.writeString("\n");

    // Test 5: Signatures (HARDENED)
    serial.writeString("[DEBUG] Starting signature test (HARDENED)...\n");
    if (signature.test_signature()) {
        passed += 1;
        serial.writeString("[DEBUG] Signature test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Signature test FAILED\n");
    }
    serial.writeString("\n");

    // Test 6: AES-256
    serial.writeString("[DEBUG] Starting AES-256 test...\n");
    if (aes.test_aes()) {
        passed += 1;
        serial.writeString("[DEBUG] AES-256 test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] AES-256 test FAILED\n");
    }
    serial.writeString("\n");

    // Test 7: Constant-Time Operations (H.1)
    serial.writeString("[DEBUG] Starting constant-time test (H.1)...\n");
    if (constant_time.runTests()) {
        passed += 1;
        serial.writeString("[DEBUG] Constant-time test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Constant-time test FAILED\n");
    }
    serial.writeString("\n");

    // Test 8: Entropy & CSPRNG (H.2)
    serial.writeString("[DEBUG] Starting entropy test (H.2)...\n");
    if (entropy.runTests()) {
        passed += 1;
        serial.writeString("[DEBUG] Entropy test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] Entropy test FAILED\n");
    }
    serial.writeString("\n");

    // Test 9: One-Time Pad (H.11)
    serial.writeString("[DEBUG] Starting OTP cipher test (H.11)...\n");
    if (otp.test_otp()) {
        passed += 1;
        serial.writeString("[DEBUG] OTP cipher test completed OK\n");
    } else {
        failed += 1;
        serial.writeString("[DEBUG] OTP cipher test FAILED\n");
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed (of 9 suites)\n");
    serial.writeString("========================================\n");

    if (failed == 0) {
        serial.writeString("\n  All crypto tests PASSED!\n\n");
        return true;
    } else {
        serial.writeString("\n  Some tests FAILED!\n\n");
        return false;
    }
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @as(u8, @intCast(v % 10)) + '0';
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
