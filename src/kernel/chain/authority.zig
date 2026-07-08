//! Zamrud OS - Chain Authority Adapter
//! Proof-of-Authority consensus authority bridge
//!
//! IMPORTANT ARCHITECTURE:
//! - security/authority.zig is the ONLY global authority source-of-truth.
//! - chain/authority.zig is only a PoA consensus adapter/cache.
//! - This file keeps legacy chain API compatibility:
//!     addAuthority()
//!     removeAuthority()
//!     isAuthority()
//!     getAuthority()
//!     getAuthorityCount()
//!     recordBlockSigned()
//!     test_authority()
//!
//! No double authority system:
//! - Runtime authority decision is delegated to security/authority.zig.
//! - Local cache only stores chain display metadata and blocks_signed count.

const serial = @import("../drivers/serial/serial.zig");
const sec_authority = @import("../security/authority.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_AUTHORITIES: usize = 4;

// =============================================================================
// Authority Entry - chain-side display/cache only
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
// State - local cache only
// =============================================================================
var authorities: [MAX_AUTHORITIES]Authority = undefined;
var authority_count: usize = 0;
var initialized: bool = false;

// Bootstrapped root authority used when registering validators through
// legacy chain API. The first authority added becomes chain root.
var consensus_root: [32]u8 = [_]u8{0} ** 32;
var has_consensus_root: bool = false;

// Static test variables
var static_pubkey: [32]u8 = [_]u8{0} ** 32;
var static_fake_key: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[CHAIN_AUTHORITY] Initializing PoA adapter...\n");

    authority_count = 0;
    has_consensus_root = false;
    consensus_root = [_]u8{0} ** 32;

    var i: usize = 0;
    while (i < MAX_AUTHORITIES) : (i += 1) {
        authorities[i] = emptyAuthority();
    }

    if (!sec_authority.isInitialized()) {
        sec_authority.init();
    }

    initialized = true;
    serial.writeString("[CHAIN_AUTHORITY] Initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyAuthority() Authority {
    return .{
        .pubkey = [_]u8{0} ** 32,
        .name = [_]u8{0} ** 16,
        .name_len = 0,
        .active = false,
        .blocks_signed = 0,
    };
}

// =============================================================================
// Legacy Chain Authority API
// =============================================================================

/// Add a new chain consensus authority.
///
/// Compatibility behavior:
/// - First authority becomes root authority in security/authority.zig.
/// - Subsequent authorities become validators signed by first root.
/// - This function updates local chain display cache only after
///   security/authority.zig accepts registration.
pub fn addAuthority(pubkey: *const [32]u8, name: []const u8) bool {
    if (!initialized) init();
    if (!sec_authority.isInitialized()) sec_authority.init();

    if (authority_count >= MAX_AUTHORITIES) return false;
    if (isAuthority(pubkey)) return false;

    var registered = false;

    if (!has_consensus_root) {
        registered = sec_authority.registerRootAuthority(pubkey, name);
        if (registered) {
            consensus_root = pubkey.*;
            has_consensus_root = true;
        }
    } else {
        var hw: [32]u8 = [_]u8{0} ** 32;

        registered = sec_authority.registerValidator(
            pubkey,
            &consensus_root,
            &hw,
            true,
            true,
            name,
        );
    }

    if (!registered) {
        return false;
    }

    return addCacheEntry(pubkey, name);
}

/// Remove/revoke an authority.
///
/// Compatibility behavior:
/// - Does not allow removing the last active consensus authority.
/// - Delegates authority removal to security/authority.zig revocation.
/// - Marks local chain cache entry inactive.
pub fn removeAuthority(pubkey: *const [32]u8) bool {
    if (!initialized) init();

    if (getAuthorityCount() <= 1) return false;

    var found = false;

    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        if (eqlId(&authorities[i].pubkey, pubkey)) {
            authorities[i].active = false;
            found = true;
            break;
        }
    }

    if (!found and !isAuthority(pubkey)) {
        return false;
    }

    _ = sec_authority.revokeAuthority(pubkey);

    return true;
}

/// Check if pubkey is an active chain signing authority.
/// Source-of-truth is security/authority.zig.
pub fn isAuthority(pubkey: *const [32]u8) bool {
    if (!sec_authority.isInitialized()) return false;

    if (sec_authority.isRevoked(pubkey)) return false;

    return sec_authority.isRootAuthority(pubkey) or
        sec_authority.isValidator(pubkey);
}

/// Get local chain authority cache by active index.
pub fn getAuthority(index: usize) ?*Authority {
    if (!initialized) init();

    var active_idx: usize = 0;

    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        if (active_idx == index) {
            return &authorities[i];
        }

        active_idx += 1;
    }

    return null;
}

/// Get active chain consensus authority count from local cache.
pub fn getAuthorityCount() usize {
    if (!initialized) init();

    var count: usize = 0;

    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (authorities[i].active and isAuthority(&authorities[i].pubkey)) {
            count += 1;
        }
    }

    return count;
}

/// Record block signed by authority.
/// This only updates chain display/cache stats.
/// It does not modify global authority permission.
pub fn recordBlockSigned(pubkey: *const [32]u8) void {
    if (!initialized) init();

    if (!isAuthority(pubkey)) return;

    var i: usize = 0;
    while (i < authority_count) : (i += 1) {
        if (!authorities[i].active) continue;

        if (eqlId(&authorities[i].pubkey, pubkey)) {
            authorities[i].blocks_signed += 1;

            if (sec_authority.isInitialized()) {
                sec_authority.markSeen(pubkey);
            }

            return;
        }
    }
}

// =============================================================================
// Cache Helpers
// =============================================================================

fn addCacheEntry(pubkey: *const [32]u8, name: []const u8) bool {
    if (authority_count >= MAX_AUTHORITIES) return false;

    var slot = &authorities[authority_count];

    slot.* = emptyAuthority();
    slot.pubkey = pubkey.*;
    slot.active = true;
    slot.blocks_signed = 0;

    const name_len = if (name.len > 16) 16 else name.len;

    var i: usize = 0;
    while (i < name_len) : (i += 1) {
        slot.name[i] = name[i];
    }

    slot.name_len = @intCast(name_len);

    authority_count += 1;

    return true;
}

fn eqlId(a: *const [32]u8, b: *const [32]u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a.*[i] != b.*[i]) return false;
    }
    return true;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_authority() bool {
    serial.writeString("[CHAIN_AUTHORITY] Testing PoA adapter...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    if (@hasDecl(sec_authority, "resetForTest")) {
        sec_authority.resetForTest();
    }

    // Test 1: Initialize
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and authority_count == 0 and getAuthorityCount() == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Add root authority
    serial.writeString("  Test 2: Add root authority\n");
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

    // Test 3: Check authority through security source-of-truth
    serial.writeString("  Test 3: Is authority\n");
    if (isAuthority(&static_pubkey) and sec_authority.isRootAuthority(&static_pubkey)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Non-authority check
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

    // Test 6: Add validator
    serial.writeString("  Test 6: Add validator\n");
    var validator: [32]u8 = [_]u8{0} ** 32;
    validator[0] = 0x02;

    if (addAuthority(&validator, "validator") and
        isAuthority(&validator) and
        sec_authority.isValidator(&validator))
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Remove validator revokes global authority
    serial.writeString("  Test 7: Remove validator\n");
    if (removeAuthority(&validator) and
        sec_authority.isRevoked(&validator) and
        !isAuthority(&validator))
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  CHAIN AUTHORITY: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

// =============================================================================
// Print Helper
// =============================================================================

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
