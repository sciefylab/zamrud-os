//! Zamrud OS - Privacy Modes
//! Controls what identity information is shared on the network

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Types
// =============================================================================

pub const PrivacyMode = enum(u8) {
    stealth = 0, // Maximum privacy - only NodeID visible
    pseudonymous = 1, // Default - Address visible, name hidden
    public = 2, // Full visibility - Name & address visible
};

pub const PrivacySettings = struct {
    mode: PrivacyMode,
    hide_ip: bool,
    rotate_node_id: bool,
    use_onion_routing: bool,
    encrypt_p2p: bool,
};

// =============================================================================
// State
// =============================================================================

var settings: PrivacySettings = undefined;
var initialized: bool = false;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[PRIVACY] Initializing...\n");

    // Default: Pseudonymous with reasonable privacy
    settings.mode = .pseudonymous;
    settings.hide_ip = true;
    settings.rotate_node_id = true;
    settings.use_onion_routing = false; // Disabled by default (slower)
    settings.encrypt_p2p = true;

    initialized = true;
    serial.writeString("[PRIVACY] Initialized (Pseudonymous mode)\n");
}

/// Set privacy mode
pub fn setMode(mode: PrivacyMode) void {
    settings.mode = mode;

    // Adjust settings based on mode
    switch (mode) {
        .stealth => {
            settings.hide_ip = true;
            settings.rotate_node_id = true;
            settings.use_onion_routing = true;
            settings.encrypt_p2p = true;
        },
        .pseudonymous => {
            settings.hide_ip = true;
            settings.rotate_node_id = true;
            settings.use_onion_routing = false;
            settings.encrypt_p2p = true;
        },
        .public => {
            settings.hide_ip = false;
            settings.rotate_node_id = false;
            settings.use_onion_routing = false;
            settings.encrypt_p2p = true;
        },
    }
}

/// Get current privacy mode
pub fn getMode() PrivacyMode {
    return settings.mode;
}

/// Get full settings
pub fn getSettings() *const PrivacySettings {
    return &settings;
}

/// Individual setting controls
pub fn setHideIp(hide: bool) void {
    settings.hide_ip = hide;
}

pub fn setRotateNodeId(rotate: bool) void {
    settings.rotate_node_id = rotate;
}

pub fn setOnionRouting(enable: bool) void {
    settings.use_onion_routing = enable;
}

pub fn setEncryptP2P(encrypt: bool) void {
    settings.encrypt_p2p = encrypt;
}

/// Check what's visible to peers based on current mode
pub fn isAddressVisible() bool {
    return settings.mode != .stealth;
}

pub fn isNameVisible() bool {
    return settings.mode == .public;
}

pub fn isIpHidden() bool {
    return settings.hide_ip;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_privacy() bool {
    serial.writeString("[PRIVACY] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and settings.mode == .pseudonymous) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Set stealth mode
    serial.writeString("  Test 2: Stealth mode\n");
    setMode(.stealth);
    if (getMode() == .stealth and !isAddressVisible() and !isNameVisible()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Set public mode
    serial.writeString("  Test 3: Public mode\n");
    setMode(.public);
    if (getMode() == .public and isAddressVisible() and isNameVisible()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Back to pseudonymous
    serial.writeString("  Test 4: Pseudonymous mode\n");
    setMode(.pseudonymous);
    if (getMode() == .pseudonymous and isAddressVisible() and !isNameVisible()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  PRIVACY: ");
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
