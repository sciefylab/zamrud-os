//! Zamrud OS - Blockchain Module
//! Lightweight integrity ledger with PoA consensus

const serial = @import("../drivers/serial/serial.zig");

// Sub-modules
pub const block = @import("block.zig");
pub const ledger = @import("ledger.zig");
pub const authority = @import("authority.zig");
pub const entry = @import("entry.zig");

// Re-exports
pub const Block = block.Block;
pub const BlockHeader = block.BlockHeader;
pub const Entry = entry.Entry;
pub const EntryType = entry.EntryType;

// =============================================================================
// Chain State
// =============================================================================

var chain_initialized: bool = false;

// Static auth key for initialization
var static_chain_auth_key: [32]u8 = [_]u8{0} ** 32;

/// Initialize the blockchain subsystem
pub fn init() bool {
    serial.writeString("[CHAIN] Initializing integrity ledger...\n");

    serial.writeString("[CHAIN] Step 1: authority.init()...\n");
    authority.init();
    serial.writeString("[CHAIN] Step 1: Done\n");

    serial.writeString("[CHAIN] Setting chain_initialized=true\n");
    chain_initialized = true;

    serial.writeString("[CHAIN] Integrity ledger ready\n");

    return true;
}

/// Initialize with genesis (PoA)
pub fn initWithGenesis(authority_pubkey: *const [32]u8) bool {
    if (!chain_initialized) {
        if (!init()) return false;
    }

    // Add genesis authority
    _ = authority.addAuthority(authority_pubkey, "genesis");

    // Initialize ledger
    return ledger.init(authority_pubkey);
}

/// Check if initialized
pub fn isInitialized() bool {
    return chain_initialized;
}

/// Get chain height
pub fn getHeight() u32 {
    return ledger.getHeight();
}

/// Get block count
pub fn getBlockCount() u32 {
    return ledger.getBlockCount();
}

/// Get tip hash
pub fn getTipHash() *const [32]u8 {
    return ledger.getTipHash();
}

/// Add a new block
pub fn addBlock(blk: *const Block) bool {
    return ledger.addBlock(blk);
}

/// Create block template
pub fn createBlockTemplate(authority_pubkey: *const [32]u8) *Block {
    return ledger.createBlockTemplate(authority_pubkey);
}

// =============================================================================
// Test Runner
// =============================================================================

pub fn runAllTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  INTEGRITY LEDGER TEST SUITE\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Block
    serial.writeString("[1/4] Block Structure...\n\n");
    serial.writeString("=== Block Test ===\n");
    if (block.test_blockchain()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    // Test 2: Entry
    serial.writeString("[2/4] Block Entries...\n\n");
    serial.writeString("=== Entry Test ===\n");
    if (entry.test_entry()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    // Test 3: Authority
    serial.writeString("[3/4] PoA Authority...\n\n");
    serial.writeString("=== Authority Test ===\n");
    if (authority.test_authority()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    // Test 4: Ledger
    serial.writeString("[4/4] Lightweight Ledger...\n\n");
    serial.writeString("=== Ledger Test ===\n");
    if (ledger.test_ledger()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  CHAIN RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
    serial.writeString("========================================\n");

    if (failed == 0) {
        serial.writeString("\n  All chain tests PASSED!\n\n");
        return true;
    } else {
        serial.writeString("\n  Some chain tests FAILED!\n\n");
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
