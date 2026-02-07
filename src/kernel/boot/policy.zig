//! Zamrud OS - Boot Security Policy
//! Defines and enforces security requirements at boot

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Policy Configuration
// =============================================================================

pub const SecurityLevel = enum {
    permissive,
    standard,
    strict,
    paranoid,
};

pub const PolicyFlags = struct {
    require_kernel_hash: bool,
    require_module_hashes: bool,
    require_secure_boot: bool,
    require_memory_isolation: bool,
    require_stack_protection: bool,
    require_nx: bool,
    allow_debug: bool,
    allow_serial_output: bool,
    allow_unsigned: bool,
    log_violations: bool,
};

// =============================================================================
// State
// =============================================================================

var current_level: SecurityLevel = .standard;
var current_flags: PolicyFlags = .{
    .require_kernel_hash = true,
    .require_module_hashes = false,
    .require_secure_boot = false,
    .require_memory_isolation = true,
    .require_stack_protection = true,
    .require_nx = true,
    .allow_debug = true,
    .allow_serial_output = true,
    .allow_unsigned = true,
    .log_violations = true,
};

var violation_count: u32 = 0;
var initialized: bool = false;

// =============================================================================
// Public API
// =============================================================================

pub fn init() void {
    serial.writeString("[POLICY] Initializing...\n");

    violation_count = 0;
    current_level = .standard;

    applyLevel(.standard);

    initialized = true;
    serial.writeString("[POLICY] Initialized (");
    serial.writeString(getLevelName(current_level));
    serial.writeString(" mode)\n");
}

pub fn check() bool {
    if (!initialized) {
        init();
    }

    var passed = true;

    if (!current_flags.allow_debug) {
        if (isDebugEnabled()) {
            logViolation("Debug mode enabled in non-debug policy");
            if (current_level == .strict or current_level == .paranoid) {
                passed = false;
            }
        }
    }

    if (current_flags.require_memory_isolation) {
        if (!isMemoryIsolated()) {
            logViolation("Memory isolation not enabled");
            if (current_level == .strict or current_level == .paranoid) {
                passed = false;
            }
        }
    }

    if (current_level == .permissive) {
        return true;
    }

    return passed;
}

pub fn setLevel(level: SecurityLevel) void {
    current_level = level;
    applyLevel(level);

    serial.writeString("[POLICY] Level set to ");
    serial.writeString(getLevelName(level));
    serial.writeString("\n");
}

pub fn getLevel() SecurityLevel {
    return current_level;
}

pub fn getFlags() PolicyFlags {
    return current_flags;
}

pub fn getViolationCount() u32 {
    return violation_count;
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Internal Functions
// =============================================================================

fn applyLevel(level: SecurityLevel) void {
    switch (level) {
        .permissive => {
            current_flags = .{
                .require_kernel_hash = false,
                .require_module_hashes = false,
                .require_secure_boot = false,
                .require_memory_isolation = false,
                .require_stack_protection = false,
                .require_nx = false,
                .allow_debug = true,
                .allow_serial_output = true,
                .allow_unsigned = true,
                .log_violations = true,
            };
        },
        .standard => {
            current_flags = .{
                .require_kernel_hash = true,
                .require_module_hashes = false,
                .require_secure_boot = false,
                .require_memory_isolation = true,
                .require_stack_protection = true,
                .require_nx = true,
                .allow_debug = true,
                .allow_serial_output = true,
                .allow_unsigned = true,
                .log_violations = true,
            };
        },
        .strict => {
            current_flags = .{
                .require_kernel_hash = true,
                .require_module_hashes = true,
                .require_secure_boot = false,
                .require_memory_isolation = true,
                .require_stack_protection = true,
                .require_nx = true,
                .allow_debug = false,
                .allow_serial_output = true,
                .allow_unsigned = false,
                .log_violations = true,
            };
        },
        .paranoid => {
            current_flags = .{
                .require_kernel_hash = true,
                .require_module_hashes = true,
                .require_secure_boot = true,
                .require_memory_isolation = true,
                .require_stack_protection = true,
                .require_nx = true,
                .allow_debug = false,
                .allow_serial_output = false,
                .allow_unsigned = false,
                .log_violations = true,
            };
        },
    }
}

fn getLevelName(level: SecurityLevel) []const u8 {
    return switch (level) {
        .permissive => "permissive",
        .standard => "standard",
        .strict => "strict",
        .paranoid => "paranoid",
    };
}

fn logViolation(msg: []const u8) void {
    if (current_flags.log_violations) {
        serial.writeString("[POLICY] VIOLATION: ");
        serial.writeString(msg);
        serial.writeString("\n");
    }
    violation_count += 1;
}

fn isDebugEnabled() bool {
    return true;
}

fn isMemoryIsolated() bool {
    return true;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_policy() bool {
    serial.writeString("\n=== Policy Test ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 2: Default level\n");
    if (current_level == .standard) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 3: Check passes\n");
    if (check()) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 4: Permissive mode\n");
    setLevel(.permissive);
    if (check()) {
        passed += 1;
    } else {
        failed += 1;
    }

    setLevel(.standard);

    return failed == 0;
}
