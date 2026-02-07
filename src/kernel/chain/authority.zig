//! Zamrud OS - Proof of Authority
//! Simple validator management for PoA consensus

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_AUTHORITIES: usize = 4;

// =============================================================================
// Authority Entry
// =============================================================================

pub const Authority = struct {
    pubkey: [32]u8,
    name: [16]u8,
    name_len: u8,
    active: bool,
    blocks_signed: u32,

    pub fn getName(self: *const Authority) []const u8 {
        return self.name[0..self.name_len];
    }
};

// =============================================================================
// State - all static
// =============================================================================

var authorities: [MAX_AUTHORITIES]Authority = undefined;
var authority_count: usize = 0;
var initialized: bool = false;

// Static test variables
var static_pubkey: [32]u8 = [_]u8{0} ** 32;
var static_fake_key: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[AUTHORITY] Initializing...\n");

    authority_count = 0;

    var i: usize = 0;
    while (i < MAX_AUTHORITIES) : (i += 1) {
        authorities[i].name_len = 0;
        authorities[i].active = false;
        authorities[i].blocks_signed = 0;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            authorities[i].pubkey[j] = 0;
        }
        j = 0;
        while (j < 16) : (j += 1) {
            authorities[i].name[j] = 0;
        }
    }

    initialized = true;
    serial.writeString("[AUTHORITY] Initialized\n");
}

/// Add a new authority
pub fn addAuthority(pubkey: *const [32]u8, name: []const u8) bool {
    if (!initialized) init();
    if (authority_count >= MAX_AUTHORITIES) return false;
    if (isAuthority(pubkey)) return false;

    var auth = &authorities[authority_count];

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        auth.pubkey[i] = pubkey[i];
    }

    const name_len = if (name.len > 16) 16 else name.len;
    i = 0;
    while (i < name_len) : (i += 1) {
        auth.name[i] = name[i];
    }
    auth.name_len = @intCast(name_len);

    auth.active = true;
    auth.blocks_signed = 0;
    authority_count += 1;

    return true;
}

/// Remove an authority
pub fn removeAuthority(pubkey: *const [32]u8) bool {
    if (authority_count <= 1) return false;

    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        var match = true;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (authorities[i].pubkey[j] != pubkey[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            authorities[i].active = false;
            return true;
        }
    }

    return false;
}

/// Check if pubkey is an authority
pub fn isAuthority(pubkey: *const [32]u8) bool {
    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        var match = true;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (authorities[i].pubkey[j] != pubkey[j]) {
                match = false;
                break;
            }
        }

        if (match) return true;
    }
    return false;
}

/// Get authority by index
pub fn getAuthority(index: usize) ?*Authority {
    if (index >= authority_count) return null;
    if (!authorities[index].active) return null;
    return &authorities[index];
}

/// Get authority count
pub fn getAuthorityCount() usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (authorities[i].active) count += 1;
    }
    return count;
}

/// Record block signed by authority
pub fn recordBlockSigned(pubkey: *const [32]u8) void {
    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        var match = true;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (authorities[i].pubkey[j] != pubkey[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            authorities[i].blocks_signed += 1;
            return;
        }
    }
}

// =============================================================================
// Test
// =============================================================================

pub fn test_authority() bool {
    serial.writeString("[AUTHORITY] Testing PoA...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Initialize
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and authority_count == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Add authority - use static pubkey
    serial.writeString("  Test 2: Add authority\n");
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_pubkey[i] = 0;
    }
    static_pubkey[0] = 0x01;

    if (addAuthority(&static_pubkey, "genesis") and getAuthorityCount() == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Check authority
    serial.writeString("  Test 3: Is authority\n");
    if (isAuthority(&static_pubkey)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Non-authority
    serial.writeString("  Test 4: Non-authority check\n");
    i = 0;
    while (i < 32) : (i += 1) {
        static_fake_key[i] = 0;
    }
    static_fake_key[0] = 0xFF;

    if (!isAuthority(&static_fake_key)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Record block signed
    serial.writeString("  Test 5: Record block\n");
    recordBlockSigned(&static_pubkey);
    const auth = getAuthority(0);
    if (auth != null and auth.?.blocks_signed == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  AUTHORITY: ");
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
