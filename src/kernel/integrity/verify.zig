//! Zamrud OS - File Verification
//! Verifies file integrity against registry

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const registry = @import("registry.zig");

// =============================================================================
// Static storage for tests
// =============================================================================

var static_test_hash: [32]u8 = [_]u8{0} ** 32;
var static_bad_hash: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Verification Functions
// =============================================================================

/// Verify file by providing pre-computed hash
pub fn verifyByHash(name: []const u8, actual_hash: *const [32]u8) registry.FileStatus {
    const entry = registry.findEntry(name);
    if (entry == null) return .missing;

    return compareHash(entry.?, actual_hash);
}

/// Compare hash with expected
fn compareHash(entry: *registry.FileEntry, actual_hash: *const [32]u8) registry.FileStatus {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (actual_hash[i] != entry.expected_hash[i]) {
            entry.status = .modified;
            return .modified;
        }
    }

    entry.status = .valid;
    return .valid;
}

/// Verify all registered files (placeholder)
pub fn verifyAll() *const VerifyResult {
    static_result.total = 0;
    static_result.valid = 0;
    static_result.modified = 0;
    static_result.missing = 0;

    const stats = registry.getStats();
    static_result.total = stats.total;
    static_result.valid = stats.valid;
    static_result.modified = stats.modified;

    return &static_result;
}

// Add static result
var static_result: VerifyResult = undefined;

pub const VerifyResult = struct {
    total: usize,
    valid: usize,
    modified: usize,
    missing: usize,
};

// =============================================================================
// Test
// =============================================================================

pub fn test_verify() bool {
    serial.writeString("[VERIFY] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup: init registry
    serial.writeString("  Setup: init registry\n");
    registry.init();

    // Setup: init test hash (static)
    serial.writeString("  Setup: init test_hash\n");
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_test_hash[i] = 0;
    }
    static_test_hash[0] = 0xAB;
    static_test_hash[1] = 0xCD;

    // Setup: register file
    serial.writeString("  Setup: registerFile\n");
    _ = registry.registerFile("test.bin", &static_test_hash, .kernel, 1);

    // Test 1: Verify valid hash
    serial.writeString("  Test 1: Valid hash\n");
    const status1 = verifyByHash("test.bin", &static_test_hash);
    if (status1 == .valid) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Detect modification
    serial.writeString("  Test 2: Detect modification\n");

    // Init bad hash (static)
    i = 0;
    while (i < 32) : (i += 1) {
        static_bad_hash[i] = 0;
    }
    static_bad_hash[0] = 0xFF;

    const status2 = verifyByHash("test.bin", &static_bad_hash);
    if (status2 == .modified) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Missing file
    serial.writeString("  Test 3: Missing file\n");
    const status3 = verifyByHash("notexist.bin", &static_test_hash);
    if (status3 == .missing) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  VERIFY: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = [_]u8{0} ** 10;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
