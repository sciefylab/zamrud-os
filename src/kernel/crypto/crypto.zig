//! Zamrud OS - Cryptography Module

const serial = @import("../drivers/serial/serial.zig");

pub const hash = @import("hash.zig");
pub const random = @import("random.zig");
pub const keys = @import("keys.zig");
pub const signature = @import("signature.zig");
pub const aes = @import("aes.zig");

// Re-exports
pub const Sha256 = hash.Sha256;
pub const sha256 = hash.sha256;
pub const sha256Into = hash.sha256Into;
pub const sha256Ptr = hash.sha256Ptr;
pub const hashEqual = hash.hashEqual;

pub const KeyPair = signature.KeyPair;
pub const verify = signature.verify;

pub const SeedPhrase = keys.SeedPhrase;

// AES re-exports
pub const AES = aes;
pub const encryptCBC = aes.encryptCBC;
pub const decryptCBC = aes.decryptCBC;
pub const deriveKey = aes.deriveKey;

pub fn init() void {
    serial.writeString("[CRYPTO] Initializing...\n");
    random.init();
    serial.writeString("[CRYPTO] Crypto subsystem ready\n");
}

pub fn isInitialized() bool {
    return true;
}

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  CRYPTO TEST SUITE\n");
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

    // Test 5: Signatures
    serial.writeString("[DEBUG] Starting signature test...\n");
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

    serial.writeString("\n========================================\n");
    serial.writeString("  RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
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
