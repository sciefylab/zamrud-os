//! Zamrud OS - Constant-Time Cryptographic Operations
//! H.1: Prevents timing side-channel attacks
//!
//! RULE: Every comparison of secrets MUST use these functions.
//! Using == or early-return loops on secrets leaks information via timing.

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("hash.zig");

// =============================================================================
// Core Constant-Time Primitives
// =============================================================================

/// Constant-time byte comparison — always examines ALL bytes
pub fn constantTimeCompare(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/// Constant-time 32-byte comparison (hashes, keys)
pub fn constantTimeCompare32(a: *const [32]u8, b: *const [32]u8) bool {
    var result: u8 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/// Constant-time 64-byte comparison (signatures)
pub fn constantTimeCompare64(a: *const [64]u8, b: *const [64]u8) bool {
    var result: u8 = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/// Constant-time select: returns a if true, b if false (no branch)
pub fn constantTimeSelect(condition: bool, a: u8, b: u8) u8 {
    const mask: u8 = @as(u8, 0) -% @intFromBool(condition);
    return (a & mask) | (b & ~mask);
}

/// Constant-time select for u32
pub fn constantTimeSelectU32(condition: bool, a: u32, b: u32) u32 {
    const mask: u32 = @as(u32, 0) -% @intFromBool(condition);
    return (a & mask) | (b & ~mask);
}

/// Constant-time select for u64
pub fn constantTimeSelectU64(condition: bool, a: u64, b: u64) u64 {
    const mask: u64 = @as(u64, 0) -% @intFromBool(condition);
    return (a & mask) | (b & ~mask);
}

/// Constant-time all-zero check
pub fn constantTimeIsZero(data: []const u8) bool {
    var acc: u8 = 0;
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        acc |= data[i];
    }
    return acc == 0;
}

/// Constant-time all-zero check for 32-byte
pub fn constantTimeIsZero32(data: *const [32]u8) bool {
    var acc: u8 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        acc |= data[i];
    }
    return acc == 0;
}

/// Constant-time all-zero check for 64-byte
pub fn constantTimeIsZero64(data: *const [64]u8) bool {
    var acc: u8 = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        acc |= data[i];
    }
    return acc == 0;
}

// =============================================================================
// Secure Memory Operations
// =============================================================================

/// Secure zero — compiler CANNOT optimize away (volatile writes)
pub fn secureZero(buffer: []u8) void {
    for (buffer) |*b| {
        @as(*volatile u8, @ptrCast(b)).* = 0;
    }
}

/// Secure zero 32-byte buffer
pub fn secureZero32(buffer: *[32]u8) void {
    for (buffer) |*b| {
        @as(*volatile u8, @ptrCast(b)).* = 0;
    }
}

/// Secure zero 64-byte buffer
pub fn secureZero64(buffer: *[64]u8) void {
    for (buffer) |*b| {
        @as(*volatile u8, @ptrCast(b)).* = 0;
    }
}

/// Constant-time conditional copy (no branching)
pub fn constantTimeCopy(condition: bool, dst: []u8, src: []const u8) void {
    if (dst.len != src.len) return;
    const mask: u8 = @as(u8, 0) -% @intFromBool(condition);
    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        dst[i] = (src[i] & mask) | (dst[i] & ~mask);
    }
}

// =============================================================================
// PKCS7 Padding Verification (constant-time, prevents padding oracle)
// =============================================================================

/// Constant-time PKCS7 padding validation
pub fn verifyPkcs7Padding(block: []const u8, block_size: usize) ?usize {
    if (block.len == 0 or block.len < block_size) return null;

    const last_byte = block[block.len - 1];
    const pad_len = @as(usize, last_byte);

    if (pad_len == 0 or pad_len > block_size or pad_len > block.len) return null;

    // Verify ALL padding bytes in constant time
    var pad_check: u8 = 0;
    var i: usize = 0;
    while (i < block_size) : (i += 1) {
        if (i < pad_len) {
            const idx = block.len - 1 - i;
            pad_check |= block[idx] ^ last_byte;
        }
    }

    if (pad_check != 0) return null;
    return block.len - pad_len;
}

// =============================================================================
// Tests — 25 tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  CONSTANT-TIME CRYPTO TESTS (H.1)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Equal arrays
    serial.writeString("  [1]  Equal arrays............. ");
    {
        const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
        const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
        if (constantTimeCompare(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 2: Different arrays
    serial.writeString("  [2]  Different arrays......... ");
    {
        const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDE };
        if (!constantTimeCompare(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 3: First byte different
    serial.writeString("  [3]  First byte diff.......... ");
    {
        const a = [_]u8{ 0x00, 0xBB, 0xCC, 0xDD };
        const b = [_]u8{ 0xFF, 0xBB, 0xCC, 0xDD };
        if (!constantTimeCompare(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 4: Last byte different
    serial.writeString("  [4]  Last byte diff........... ");
    {
        const a = [_]u8{ 0xAA, 0xBB, 0xCC, 0x00 };
        const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xFF };
        if (!constantTimeCompare(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 5: Different lengths
    serial.writeString("  [5]  Different lengths........ ");
    {
        const a = [_]u8{ 0xAA, 0xBB, 0xCC };
        const b = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        if (!constantTimeCompare(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 6: 32-byte comparison
    serial.writeString("  [6]  32-byte compare.......... ");
    {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            a[i] = @intCast(i);
            b[i] = @intCast(i);
        }
        if (constantTimeCompare32(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 7: 64-byte comparison equal
    serial.writeString("  [7]  64-byte compare.......... ");
    {
        var a: [64]u8 = undefined;
        var b: [64]u8 = undefined;
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            a[i] = @intCast(i *% 3 +% 7);
            b[i] = @intCast(i *% 3 +% 7);
        }
        if (constantTimeCompare64(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 8: 64-byte one bit different
    serial.writeString("  [8]  64-byte 1-bit diff....... ");
    {
        var a: [64]u8 = [_]u8{0x42} ** 64;
        var b: [64]u8 = [_]u8{0x42} ** 64;
        b[63] ^= 0x01;
        if (!constantTimeCompare64(&a, &b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 9: CT select true
    serial.writeString("  [9]  CT select true........... ");
    if (constantTimeSelect(true, 0xAA, 0xBB) == 0xAA) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 10: CT select false
    serial.writeString("  [10] CT select false.......... ");
    if (constantTimeSelect(false, 0xAA, 0xBB) == 0xBB) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 11: CT select u32
    serial.writeString("  [11] CT select u32........... ");
    {
        const r1 = constantTimeSelectU32(true, 0xDEADBEEF, 0xCAFEBABE);
        const r2 = constantTimeSelectU32(false, 0xDEADBEEF, 0xCAFEBABE);
        if (r1 == 0xDEADBEEF and r2 == 0xCAFEBABE) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 12: CT select u64
    serial.writeString("  [12] CT select u64........... ");
    {
        const r1 = constantTimeSelectU64(true, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
        const r2 = constantTimeSelectU64(false, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
        if (r1 == 0xDEADBEEFCAFEBABE and r2 == 0x1234567890ABCDEF) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 13: isZero on zeros
    serial.writeString("  [13] isZero (zeros).......... ");
    {
        const zeros = [_]u8{0} ** 16;
        if (constantTimeIsZero(&zeros)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 14: isZero on non-zero
    serial.writeString("  [14] isZero (non-zero)....... ");
    {
        var data = [_]u8{0} ** 16;
        data[15] = 0x01;
        if (!constantTimeIsZero(&data)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 15: isZero32 on zeros
    serial.writeString("  [15] isZero32 (zeros)........ ");
    {
        const zeros: [32]u8 = [_]u8{0} ** 32;
        if (constantTimeIsZero32(&zeros)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 16: isZero64
    serial.writeString("  [16] isZero64 (non-zero)..... ");
    {
        var data: [64]u8 = [_]u8{0} ** 64;
        data[0] = 0xFF;
        if (!constantTimeIsZero64(&data)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 17: secureZero
    serial.writeString("  [17] secureZero.............. ");
    {
        var secret = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
        secureZero(&secret);
        if (constantTimeIsZero(&secret)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 18: secureZero32
    serial.writeString("  [18] secureZero32............ ");
    {
        var key: [32]u8 = [_]u8{0xFF} ** 32;
        secureZero32(&key);
        if (constantTimeIsZero32(&key)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 19: secureZero64
    serial.writeString("  [19] secureZero64............ ");
    {
        var sig: [64]u8 = [_]u8{0xAB} ** 64;
        secureZero64(&sig);
        if (constantTimeIsZero64(&sig)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 20: CT copy true
    serial.writeString("  [20] CT copy (true).......... ");
    {
        var dst = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
        const src = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        constantTimeCopy(true, &dst, &src);
        if (dst[0] == 0xAA and dst[3] == 0xDD) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 21: CT copy false (no change)
    serial.writeString("  [21] CT copy (false)......... ");
    {
        var dst = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
        const src = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        constantTimeCopy(false, &dst, &src);
        if (dst[0] == 0x11 and dst[3] == 0x44) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 22: PKCS7 valid padding
    serial.writeString("  [22] PKCS7 valid padding..... ");
    {
        const padded = [_]u8{ 'H', 'e', 'l', 'l', 'o', 0x03, 0x03, 0x03 };
        if (verifyPkcs7Padding(&padded, 8)) |len| {
            if (len == 5) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (wrong len)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (null)\n");
            failed += 1;
        }
    }

    // Test 23: PKCS7 invalid padding
    serial.writeString("  [23] PKCS7 invalid padding... ");
    {
        const bad = [_]u8{ 'H', 'e', 'l', 'l', 'o', 0x02, 0x03, 0x03 };
        if (verifyPkcs7Padding(&bad, 8)) |_| {
            serial.writeString("FAIL (accepted bad)\n");
            failed += 1;
        } else {
            serial.writeString("PASS\n");
            passed += 1;
        }
    }

    // Test 24: PKCS7 zero padding rejected
    serial.writeString("  [24] PKCS7 zero pad rejected. ");
    {
        const zero_pad = [_]u8{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 0x00 };
        if (verifyPkcs7Padding(&zero_pad, 8)) |_| {
            serial.writeString("FAIL\n");
            failed += 1;
        } else {
            serial.writeString("PASS\n");
            passed += 1;
        }
    }

    // Test 25: PKCS7 full block padding
    serial.writeString("  [25] PKCS7 full block pad.... ");
    {
        const full_pad = [_]u8{0x10} ** 16;
        if (verifyPkcs7Padding(&full_pad, 16)) |len| {
            if (len == 0) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (len)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (null)\n");
            failed += 1;
        }
    }

    // Summary
    serial.writeString("\n  ────────────────────────────────\n");
    serial.writeString("  H.1 Results: ");
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
