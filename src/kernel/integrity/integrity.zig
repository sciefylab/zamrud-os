//! Zamrud OS - Integrity Module
//! Main interface for file integrity system

const serial = @import("../drivers/serial/serial.zig");

pub const registry = @import("registry.zig");
pub const verify = @import("verify.zig");
pub const quarantine = @import("quarantine.zig");
pub const monitor = @import("monitor.zig");

// Re-exports
pub const FileEntry = registry.FileEntry;
pub const FileType = registry.FileType;
pub const FileStatus = registry.FileStatus;

// =============================================================================
// Module State
// =============================================================================

var initialized: bool = false;

/// Initialize integrity subsystem
pub fn init() void {
    serial.writeString("[INTEGRITY] Initializing...\n");

    registry.init();
    quarantine.init();
    monitor.init();

    initialized = true;
    serial.writeString("[INTEGRITY] Ready\n");
}

/// Check if initialized
pub fn isInitialized() bool {
    return initialized;
}

/// Register a file
pub fn registerFile(name: []const u8, hash_val: *const [32]u8, file_type: FileType) bool {
    return registry.registerFile(name, hash_val, file_type, 1);
}

/// Verify a file
pub fn verifyFile(name: []const u8, actual_hash: *const [32]u8) FileStatus {
    return verify.verifyByHash(name, actual_hash);
}

/// Check system integrity
pub fn isSystemValid() bool {
    return registry.isSystemValid();
}

/// Get system hash
pub fn getSystemHash() *const [32]u8 {
    return registry.getSystemHash();
}

/// Get statistics - returns pointer
pub fn getStats() *const registry.IntegrityStats {
    return registry.getStats();
}

// =============================================================================
// Test Runner
// =============================================================================

pub fn runAllTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  INTEGRITY MODULE TESTS\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("[1/4] Registry...\n\n");
    serial.writeString("=== Registry Test ===\n");
    if (registry.test_registry()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[2/4] Verify...\n\n");
    serial.writeString("=== Verify Test ===\n");
    if (verify.test_verify()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[3/4] Quarantine...\n\n");
    serial.writeString("=== Quarantine Test ===\n");
    if (quarantine.test_quarantine()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[4/4] Monitor...\n\n");
    serial.writeString("=== Monitor Test ===\n");
    if (monitor.test_monitor()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  INTEGRITY RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
    serial.writeString("========================================\n");

    if (failed == 0) {
        serial.writeString("\n  All integrity tests PASSED!\n\n");
        return true;
    } else {
        serial.writeString("\n  Some integrity tests FAILED!\n\n");
        return false;
    }
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
