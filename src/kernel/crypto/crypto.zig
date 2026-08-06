//! Zamrud OS - Unified Cryptography Module
//!
//! Production signature policy:
//! - gov_sign.zig is the sole production signature facade.
//! - The removed HMAC signature singleton is not exported here.
//! - P2P V2, ZAM V3, identity, and governance use typed ML-DSA-65 APIs.

const serial = @import("../drivers/serial/serial.zig");

pub const hash = @import("hash.zig");
pub const random = @import("random.zig");
pub const keys = @import("keys.zig");
pub const gov_sign = @import("gov_sign.zig");
pub const aes = @import("aes.zig");
pub const constant_time = @import("constant_time.zig");
pub const entropy = @import("entropy.zig");
pub const otp = @import("otp.zig");

// Hash re-exports.
pub const Sha256 = hash.Sha256;
pub const sha256 = hash.sha256;
pub const sha256Into = hash.sha256Into;
pub const sha256Ptr = hash.sha256Ptr;
pub const hashEqual = hash.hashEqual;

// Seed/mnemonic re-exports. Signature keys are intentionally not re-exported.
pub const SeedPhrase = keys.SeedPhrase;
pub const SEED_SIZE = keys.SEED_SIZE;

// AES re-exports.
pub const AES = aes;
pub const encryptCBC = aes.encryptCBC;
pub const decryptCBC = aes.decryptCBC;
pub const deriveKey = aes.deriveKey;

// Constant-time and memory-sanitization re-exports.
pub const constantTimeCompare = constant_time.constantTimeCompare;
pub const constantTimeCompare32 = constant_time.constantTimeCompare32;
pub const constantTimeCompare64 = constant_time.constantTimeCompare64;
pub const constantTimeIsZero = constant_time.constantTimeIsZero;
pub const secureZero = constant_time.secureZero;
pub const secureZero32 = constant_time.secureZero32;
pub const secureZero64 = constant_time.secureZero64;

// Entropy re-exports.
pub const getSecureBytes = entropy.getSecureBytes;
pub const addEventEntropy = entropy.addEventEntropy;

// Historical stream-protection facade. AEAD migration remains separate.
pub const OtpStream = otp.OtpStream;

pub fn init() void {
    serial.writeString("[CRYPTO] Initializing unified crypto subsystem...\n");
    random.init();
    entropy.init();

    if (!gov_sign.initialize()) {
        serial.writeString("[CRYPTO] ML-DSA-65 unavailable; signing remains fail-closed\n");
    }

    serial.writeString("[CRYPTO] Unified crypto subsystem ready\n");
}

pub fn isInitialized() bool {
    return true;
}

/// Core primitive test runner.
///
/// ML-DSA's complete KAT and negative suite remains available through
/// `identity test dsa`; this runner checks its production health gate only.
pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  CRYPTO TEST SUITE (UNIFIED)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    runSuite("Random", random.test_random(), &passed, &failed);
    runSuite("SHA-256", hash.test_sha256(), &passed, &failed);
    runSuite("Bitcoin genesis hash", hash.test_bitcoin_genesis(), &passed, &failed);
    runSuite("Seed phrase management", keys.test_keys(), &passed, &failed);
    runSuite("AES-256", aes.test_aes(), &passed, &failed);
    runSuite("Constant-time operations", constant_time.runTests(), &passed, &failed);
    runSuite("Entropy/CSPRNG", entropy.runTests(), &passed, &failed);
    runSuite("Stream protection", otp.test_otp(), &passed, &failed);
    runSuite(
        "ML-DSA-65 production health",
        gov_sign.isProductionBackendAvailable(),
        &passed,
        &failed,
    );

    serial.writeString("\n========================================\n");
    serial.writeString("  RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed (of 9 suites)\n");
    serial.writeString("========================================\n");

    if (failed == 0) {
        serial.writeString("  All unified crypto tests PASSED\n\n");
        return true;
    }

    serial.writeString("  Some unified crypto tests FAILED\n\n");
    return false;
}

fn runSuite(
    name: []const u8,
    result: bool,
    passed: *u32,
    failed: *u32,
) void {
    serial.writeString("  ");
    serial.writeString(name);
    serial.writeString("... ");

    if (result) {
        passed.* += 1;
        serial.writeString("PASS\n");
    } else {
        failed.* += 1;
        serial.writeString("FAIL\n");
    }
}

fn printU32(value: u32) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }

    var buffer: [10]u8 = [_]u8{0} ** 10;
    var index: usize = 0;
    var remaining = value;

    while (remaining > 0 and index < buffer.len) : (index += 1) {
        const digit: u8 = @intCast(remaining % 10);
        buffer[index] = digit + '0';
        remaining /= 10;
    }

    while (index > 0) {
        index -= 1;
        serial.writeChar(buffer[index]);
    }
}
