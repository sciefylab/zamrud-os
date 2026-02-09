//! Zamrud OS - Blockchain Module
//! Lightweight integrity ledger with PoA consensus and persistence

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");

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

var static_chain_auth_key: [32]u8 = [_]u8{0} ** 32;
var static_config_entry: entry.Entry = undefined;

/// Initialize the blockchain subsystem
/// Tries to load from disk first, falls back to fresh init
pub fn init() bool {
    serial.writeString("[CHAIN] Initializing integrity ledger...\n");

    serial.writeString("[CHAIN] Step 1: authority.init()...\n");
    authority.init();
    serial.writeString("[CHAIN] Step 1: Done\n");

    // Step 2: Try to load persisted chain from disk
    if (fat32.isMounted()) {
        serial.writeString("[CHAIN] Step 2: Checking for saved chain...\n");
        if (ledger.loadFromDisk()) {
            serial.writeString("[CHAIN] Step 2: Chain restored from disk!\n");
            chain_initialized = true;
            serial.writeString("[CHAIN] Integrity ledger ready (restored)\n");
            return true;
        } else {
            serial.writeString("[CHAIN] Step 2: No saved chain, starting fresh\n");
        }
    } else {
        serial.writeString("[CHAIN] Step 2: Disk not available, skip persistence\n");
    }

    serial.writeString("[CHAIN] Setting chain_initialized=true\n");
    chain_initialized = true;

    serial.writeString("[CHAIN] Integrity ledger ready\n");

    return true;
}

/// Initialize with genesis (PoA)
pub fn initWithGenesis(authority_pubkey: *const [32]u8) bool {
    if (!chain_initialized) {
        // Don't call full init() here to avoid double-load
        authority.init();
        chain_initialized = true;
    }

    // Add genesis authority
    _ = authority.addAuthority(authority_pubkey, "genesis");

    // Initialize ledger
    if (!ledger.init(authority_pubkey)) return false;

    // Auto-save genesis to disk
    if (fat32.isMounted()) {
        _ = ledger.saveToDisk();
    }

    return true;
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

/// Add a new block (auto-saves to disk)
pub fn addBlock(blk: *const Block) bool {
    return ledger.addBlock(blk);
}

/// Create block template
pub fn createBlockTemplate(authority_pubkey: *const [32]u8) *Block {
    return ledger.createBlockTemplate(authority_pubkey);
}

// =============================================================================
// Config Change Recording (D3)
// =============================================================================

/// Add a config change entry to the blockchain
/// Creates a new block with the config_change entry
pub fn addConfigEntry(config_entry: *const entry.Entry) bool {
    if (!chain_initialized) return false;
    if (!ledger.isInitialized()) return false;

    // Use a default authority key for config changes
    var auth_key: [32]u8 = [_]u8{0} ** 32;
    auth_key[0] = 0xCF; // 'CF' for ConFig

    // Ensure ledger has genesis
    if (ledger.getBlockCount() == 0) {
        if (!ledger.init(&auth_key)) return false;
    }

    // Create a new block with this entry
    const blk = ledger.createBlockTemplate(&auth_key);

    // Copy entry to static storage and add to block
    var i: usize = 0;
    static_config_entry.entry_type = config_entry.entry_type;
    static_config_entry.timestamp = config_entry.timestamp;
    while (i < 32) : (i += 1) {
        static_config_entry.target_hash[i] = config_entry.target_hash[i];
        static_config_entry.data[i] = config_entry.data[i];
    }

    _ = blk.addEntry(&static_config_entry);

    return ledger.addBlock(blk);
}

// =============================================================================
// Persistence API
// =============================================================================

/// Manually save chain to disk
pub fn saveChain() bool {
    return ledger.saveToDisk();
}

/// Manually load chain from disk
pub fn loadChain() bool {
    return ledger.loadFromDisk();
}

/// Check if a saved chain exists on disk
pub fn hasSavedChain() bool {
    return ledger.hasSavedChain();
}

/// Enable/disable auto-save
pub fn setAutoSave(enabled: bool) void {
    ledger.setAutoSave(enabled);
}

/// Get last saved height
pub fn getLastSaveHeight() u32 {
    return ledger.getLastSaveHeight();
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
