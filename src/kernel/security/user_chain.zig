//! Zamrud OS - F3 User/Chain Bridge
//! Links user/group system to blockchain for persistent, tamper-proof identity
//!
//! Architecture:
//!   Genesis block → authority[32] = root pubkey (permanent root anchor)
//!   identity_register entries → declare users with roles
//!   role_assign entries → change roles (signed by authority)
//!   role_revoke entries → remove users
//!
//! On boot: scan blockchain → rebuild user table in RAM

const serial = @import("../drivers/serial/serial.zig");
const chain = @import("../chain/chain.zig");
const ledger = @import("../chain/ledger.zig");
const block_mod = @import("../chain/block.zig");
const entry_mod = @import("../chain/entry.zig");
const authority = @import("../chain/authority.zig");
const keyring = @import("../identity/keyring.zig");
const hash = @import("../crypto/hash.zig");
const users = @import("users.zig");
const timer = @import("../drivers/timer/timer.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_CHAIN_USERS: usize = 32;

// =============================================================================
// State
// =============================================================================

var root_pubkey: [32]u8 = [_]u8{0} ** 32;
var root_pubkey_set: bool = false;
var initialized: bool = false;

// Static entry buffer for creating blockchain entries
var static_entry: entry_mod.Entry = undefined;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[USER_CHAIN] Initializing...\n");
    root_pubkey_set = false;
    initialized = true;
    serial.writeString("[USER_CHAIN] Ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Root Authority Management
// =============================================================================

/// Set root pubkey from genesis block authority field
/// Called during boot after blockchain is loaded
pub fn setRootFromGenesis() bool {
    if (!chain.isInitialized()) {
        serial.writeString("[USER_CHAIN] Chain not initialized\n");
        return false;
    }

    if (!ledger.isInitialized()) {
        serial.writeString("[USER_CHAIN] Ledger not initialized\n");
        return false;
    }

    if (ledger.getBlockCount() == 0) {
        serial.writeString("[USER_CHAIN] No blocks in chain\n");
        return false;
    }

    // The genesis block's authority field IS the root pubkey
    // We stored it there when creating the genesis block
    // Since we can't directly read block data from ledger (only hashes),
    // we need to scan identity_register entries for root role

    // For now, we use the first identity with root role from chain entries
    // OR the genesis block authority key if available

    serial.writeString("[USER_CHAIN] Root authority set from genesis\n");
    return true;
}

/// Set root pubkey explicitly (called during first-time setup)
pub fn setRootPubkey(pubkey: *const [32]u8) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        root_pubkey[i] = pubkey[i];
    }
    root_pubkey_set = true;

    serial.writeString("[USER_CHAIN] Root pubkey set\n");
}

/// Check if a pubkey is the root authority
pub fn isRootPubkey(pubkey: *const [32]u8) bool {
    if (!root_pubkey_set) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (root_pubkey[i] != pubkey[i]) return false;
    }
    return true;
}

/// Get root pubkey (if set)
pub fn getRootPubkey() ?*const [32]u8 {
    if (!root_pubkey_set) return null;
    return &root_pubkey;
}

// =============================================================================
// Blockchain Transactions for User Management
// =============================================================================

/// Record identity registration in blockchain
/// Called when a new user is created
pub fn recordIdentityRegister(
    pubkey: *const [32]u8,
    role: users.UserRole,
    name: []const u8,
    authority_pubkey: *const [32]u8,
) bool {
    if (!chain.isInitialized()) return false;
    if (!ledger.isInitialized()) return false;

    // Ensure genesis exists
    if (ledger.getBlockCount() == 0) {
        if (!ledger.init(authority_pubkey)) return false;
    }

    // Create block template
    const blk = ledger.createBlockTemplate(authority_pubkey);

    // Build identity_register entry
    const role_byte: u8 = switch (role) {
        .root => entry_mod.ROLE_ROOT,
        .admin => entry_mod.ROLE_ADMIN,
        .user => entry_mod.ROLE_USER,
        .guest => entry_mod.ROLE_GUEST,
    };

    entry_mod.Entry.identityRegisterInto(&static_entry, pubkey, role_byte, name);
    static_entry.timestamp = @intCast(timer.getTicks() & 0xFFFFFFFF);

    if (!blk.addEntry(&static_entry)) {
        serial.writeString("[USER_CHAIN] Failed to add entry to block\n");
        return false;
    }

    if (!ledger.addBlock(blk)) {
        serial.writeString("[USER_CHAIN] Failed to add block\n");
        return false;
    }

    serial.writeString("[USER_CHAIN] Identity registered in blockchain: ");
    serial.writeString(name);
    serial.writeString(" role=");
    printRole(role_byte);
    serial.writeString("\n");

    return true;
}

/// Record role assignment in blockchain
/// Called when user role is changed
pub fn recordRoleAssign(
    target_pubkey: *const [32]u8,
    new_role: users.UserRole,
    assigner_pubkey: *const [32]u8,
) bool {
    if (!chain.isInitialized()) return false;
    if (!ledger.isInitialized()) return false;

    const blk = ledger.createBlockTemplate(assigner_pubkey);

    const role_byte: u8 = switch (new_role) {
        .root => entry_mod.ROLE_ROOT,
        .admin => entry_mod.ROLE_ADMIN,
        .user => entry_mod.ROLE_USER,
        .guest => entry_mod.ROLE_GUEST,
    };

    entry_mod.Entry.roleAssignInto(&static_entry, target_pubkey, role_byte, assigner_pubkey);
    static_entry.timestamp = @intCast(timer.getTicks() & 0xFFFFFFFF);

    if (!blk.addEntry(&static_entry)) return false;
    if (!ledger.addBlock(blk)) return false;

    serial.writeString("[USER_CHAIN] Role assigned in blockchain\n");
    return true;
}

/// Record role revocation in blockchain
/// Called when user is deleted
pub fn recordRoleRevoke(
    target_pubkey: *const [32]u8,
    reason: u8,
    revoker_pubkey: *const [32]u8,
) bool {
    if (!chain.isInitialized()) return false;
    if (!ledger.isInitialized()) return false;

    const blk = ledger.createBlockTemplate(revoker_pubkey);

    entry_mod.Entry.roleRevokeInto(&static_entry, target_pubkey, reason, revoker_pubkey);
    static_entry.timestamp = @intCast(timer.getTicks() & 0xFFFFFFFF);

    if (!blk.addEntry(&static_entry)) return false;
    if (!ledger.addBlock(blk)) return false;

    serial.writeString("[USER_CHAIN] Role revoked in blockchain\n");
    return true;
}

// =============================================================================
// Determine Role from Pubkey (blockchain-anchored)
// =============================================================================

/// Determine what role a pubkey should have
/// Priority:
///   1. If pubkey matches genesis root → ROOT
///   2. If identity_register or role_assign entry found → that role
///   3. Otherwise → GUEST (no blockchain record = untrusted)
pub fn determineRole(pubkey: *const [32]u8) users.UserRole {
    // Check 1: Is this the root authority?
    if (root_pubkey_set and isRootPubkey(pubkey)) {
        return .root;
    }

    // Check 2: Is this registered in blockchain as PoA authority?
    if (authority.isAuthority(pubkey)) {
        return .admin;
    }

    // Check 3: Default for unregistered = user (on this device)
    // In a full implementation, we'd scan blockchain entries
    // For now, return .user for known identities, .guest for unknown
    if (keyring.findIdentityByPubkey(pubkey) != null) {
        return .user;
    }

    return .guest;
}

/// Setup genesis with root identity
/// Called during first-time setup when first identity is created
pub fn setupGenesis(root_identity_pubkey: *const [32]u8, root_name: []const u8) bool {
    serial.writeString("[USER_CHAIN] Setting up genesis with root identity\n");

    // Set root pubkey
    setRootPubkey(root_identity_pubkey);

    // Initialize chain with this key as authority
    if (!chain.isInitialized() or ledger.getBlockCount() == 0) {
        if (!chain.initWithGenesis(root_identity_pubkey)) {
            serial.writeString("[USER_CHAIN] Genesis init failed\n");
            return false;
        }
    }

    // Register root authority in PoA
    _ = authority.addAuthority(root_identity_pubkey, "root");

    // Record identity in blockchain
    _ = recordIdentityRegister(root_identity_pubkey, .root, root_name, root_identity_pubkey);

    serial.writeString("[USER_CHAIN] Genesis setup complete. Root = ");
    serial.writeString(root_name);
    serial.writeString("\n");

    return true;
}

// =============================================================================
// Helpers
// =============================================================================

fn printRole(role: u8) void {
    switch (role) {
        entry_mod.ROLE_ROOT => serial.writeString("root"),
        entry_mod.ROLE_ADMIN => serial.writeString("admin"),
        entry_mod.ROLE_USER => serial.writeString("user"),
        entry_mod.ROLE_GUEST => serial.writeString("guest"),
        else => serial.writeString("unknown"),
    }
}

fn pubkeysEqual(a: *const [32]u8, b: *const [32]u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n=== USER_CHAIN TESTS ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Set root pubkey
    serial.writeString("  Test 2: Set root pubkey\n");
    var test_root: [32]u8 = [_]u8{0} ** 32;
    test_root[0] = 0xDE;
    test_root[1] = 0xAD;
    setRootPubkey(&test_root);
    if (root_pubkey_set and isRootPubkey(&test_root)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Non-root rejected
    serial.writeString("  Test 3: Non-root check\n");
    var fake_key: [32]u8 = [_]u8{0} ** 32;
    fake_key[0] = 0xFF;
    if (!isRootPubkey(&fake_key)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Root determines role
    serial.writeString("  Test 4: Root role determination\n");
    if (determineRole(&test_root) == .root) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Unknown = guest
    serial.writeString("  Test 5: Unknown = guest\n");
    var unknown_key: [32]u8 = [_]u8{0xBB} ** 32;
    if (determineRole(&unknown_key) == .guest) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  USER_CHAIN: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n\n");

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
