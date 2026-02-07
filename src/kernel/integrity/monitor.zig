//! Zamrud OS - Integrity Monitor
//! Runtime monitoring of file integrity

const serial = @import("../drivers/serial/serial.zig");
const registry = @import("registry.zig");
const quarantine = @import("quarantine.zig");

// =============================================================================
// Monitor State
// =============================================================================

pub const MonitorState = struct {
    enabled: bool,
    check_interval: u32,
    last_check: u32,
    checks_performed: u64,
    violations_found: u64,
};

var state: MonitorState = undefined;
var initialized: bool = false;

// Static storage for tests
var static_expected: [32]u8 = [_]u8{0} ** 32;
var static_actual: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[MONITOR] Initializing...\n");

    state.enabled = false;
    state.check_interval = 60;
    state.last_check = 0;
    state.checks_performed = 0;
    state.violations_found = 0;

    initialized = true;
    serial.writeString("[MONITOR] Initialized\n");
}

/// Enable monitoring
pub fn enable() void {
    state.enabled = true;
}

/// Disable monitoring
pub fn disable() void {
    state.enabled = false;
}

/// Check if monitoring is enabled
pub fn isEnabled() bool {
    return state.enabled;
}

/// Set check interval
pub fn setInterval(seconds: u32) void {
    state.check_interval = seconds;
}

/// Perform integrity check (called periodically)
pub fn performCheck(current_time: u32) void {
    if (!state.enabled) return;
    if (!initialized) return;

    if (current_time < state.last_check + state.check_interval) return;

    state.last_check = current_time;
    state.checks_performed += 1;

    if (!registry.isSystemValid()) {
        state.violations_found += 1;
        serial.writeString("[MONITOR] ALERT: System integrity violation!\n");
    }
}

/// Get monitor statistics
pub fn getStats() MonitorState {
    return state;
}

/// Report violation
pub fn reportViolation(name: []const u8, expected: *const [32]u8, actual: *const [32]u8) void {
    state.violations_found += 1;

    serial.writeString("[MONITOR] Violation: ");
    serial.writeString(name);
    serial.writeString("\n");

    _ = quarantine.add(name, expected, actual, .hash_mismatch);
}

// =============================================================================
// Test
// =============================================================================

pub fn test_monitor() bool {
    serial.writeString("[MONITOR] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and !state.enabled) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Enable/Disable
    serial.writeString("  Test 2: Enable/Disable\n");
    enable();
    const was_enabled = isEnabled();
    disable();
    const now_disabled = !isEnabled();

    if (was_enabled and now_disabled) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Set interval
    serial.writeString("  Test 3: Set interval\n");
    setInterval(120);
    if (state.check_interval == 120) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  MONITOR: ");
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
