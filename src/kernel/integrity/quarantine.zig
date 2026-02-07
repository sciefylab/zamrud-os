//! Zamrud OS - Quarantine System
//! Manages suspicious/compromised files

const serial = @import("../drivers/serial/serial.zig");
const registry = @import("registry.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_QUARANTINE: usize = 8;

pub const QuarantineReason = enum(u8) {
    hash_mismatch = 0,
    signature_invalid = 1,
    malware_detected = 2,
    unauthorized_change = 3,
    manual = 4,
};

pub const QuarantineEntry = struct {
    name: [32]u8,
    name_len: u8,
    original_hash: [32]u8,
    detected_hash: [32]u8,
    reason: QuarantineReason,
    timestamp: u32,
    active: bool,

    pub fn getName(self: *const QuarantineEntry) []const u8 {
        return self.name[0..self.name_len];
    }
};

// =============================================================================
// State - all static
// =============================================================================

var quarantine_list: [MAX_QUARANTINE]QuarantineEntry = undefined;
var quarantine_count: usize = 0;
var initialized: bool = false;

// Static test variables
var static_orig_hash: [32]u8 = [_]u8{0} ** 32;
var static_det_hash: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[QUARANTINE] Initializing...\n");

    quarantine_count = 0;

    var i: usize = 0;
    while (i < MAX_QUARANTINE) : (i += 1) {
        quarantine_list[i].name_len = 0;
        quarantine_list[i].reason = .hash_mismatch;
        quarantine_list[i].timestamp = 0;
        quarantine_list[i].active = false;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            quarantine_list[i].name[j] = 0;
            quarantine_list[i].original_hash[j] = 0;
            quarantine_list[i].detected_hash[j] = 0;
        }
    }

    initialized = true;
    serial.writeString("[QUARANTINE] Initialized\n");
}

/// Add file to quarantine
pub fn add(name: []const u8, original: *const [32]u8, detected: *const [32]u8, reason: QuarantineReason) bool {
    if (!initialized) init();
    if (quarantine_count >= MAX_QUARANTINE) return false;

    var entry = &quarantine_list[quarantine_count];

    const len = if (name.len > 32) 32 else name.len;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        entry.name[i] = name[i];
    }
    entry.name_len = @intCast(len);

    i = 0;
    while (i < 32) : (i += 1) {
        entry.original_hash[i] = original[i];
        entry.detected_hash[i] = detected[i];
    }

    entry.reason = reason;
    entry.active = true;

    quarantine_count += 1;

    // Update registry status
    _ = registry.updateStatus(name, .quarantined);

    return true;
}

/// Check if file is quarantined
pub fn isQuarantined(name: []const u8) bool {
    var i: usize = 0;
    while (i < quarantine_count) : (i += 1) {
        if (!quarantine_list[i].active) continue;

        const entry_name = quarantine_list[i].getName();
        if (entry_name.len != name.len) continue;

        var match = true;
        var j: usize = 0;
        while (j < name.len) : (j += 1) {
            if (entry_name[j] != name[j]) {
                match = false;
                break;
            }
        }

        if (match) return true;
    }
    return false;
}

/// Get quarantine count
pub fn getCount() usize {
    return quarantine_count;
}

/// Clear quarantine (for recovery)
pub fn clear() void {
    quarantine_count = 0;
    var i: usize = 0;
    while (i < MAX_QUARANTINE) : (i += 1) {
        quarantine_list[i].active = false;
    }
}

// =============================================================================
// Test
// =============================================================================

pub fn test_quarantine() bool {
    serial.writeString("[QUARANTINE] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and quarantine_count == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Add to quarantine - use static hashes
    serial.writeString("  Test 2: Add file\n");

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_orig_hash[i] = 0;
        static_det_hash[i] = 0;
    }
    static_orig_hash[0] = 0xAA;
    static_det_hash[0] = 0xBB;

    if (add("malware.bin", &static_orig_hash, &static_det_hash, .malware_detected)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Check quarantined
    serial.writeString("  Test 3: Is quarantined\n");
    if (isQuarantined("malware.bin") and !isQuarantined("clean.bin")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  QUARANTINE: ");
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
