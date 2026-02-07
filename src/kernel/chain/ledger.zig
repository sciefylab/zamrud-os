//! Zamrud OS - Lightweight Ledger
//! Minimal storage for integrity blockchain

const serial = @import("../drivers/serial/serial.zig");
const block_mod = @import("block.zig");
const entry_mod = @import("entry.zig");

pub const Block = block_mod.Block;
pub const Entry = entry_mod.Entry;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_BLOCKS: usize = 16;

// =============================================================================
// Ledger State
// =============================================================================

pub const LedgerState = struct {
    height: u32,
    tip_hash: [32]u8,
    genesis_hash: [32]u8,
    block_count: u32,
    initialized: bool,
};

// =============================================================================
// Global State
// =============================================================================

var ledger: LedgerState = undefined;
var ledger_inited: bool = false;
var block_hashes: [MAX_BLOCKS][32]u8 = undefined;

var static_ledger_entry: entry_mod.Entry = undefined;
var static_auth_key: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Functions
// =============================================================================

fn resetLedger() void {
    ledger.height = 0;
    ledger.block_count = 0;
    ledger.initialized = false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = 0;
        ledger.genesis_hash[i] = 0;
    }
}

pub fn init(authority_pubkey: *const [32]u8) bool {
    resetLedger();

    const genesis = Block.createGenesis(authority_pubkey);
    const genesis_hash = genesis.getHash();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        block_hashes[0][i] = genesis_hash[i];
        ledger.tip_hash[i] = genesis_hash[i];
        ledger.genesis_hash[i] = genesis_hash[i];
    }

    ledger.height = 0;
    ledger.block_count = 1;
    ledger.initialized = true;
    ledger_inited = true;

    serial.writeString("[LEDGER] Initialized\n");
    return true;
}

pub fn addBlock(blk: *const Block) bool {
    if (!ledger.initialized) return false;
    if (ledger.block_count >= MAX_BLOCKS) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (blk.header.prev_hash[i] != ledger.tip_hash[i]) {
            return false;
        }
    }

    if (blk.header.height != ledger.height + 1) {
        return false;
    }

    const blk_hash = blk.getHash();
    i = 0;
    while (i < 32) : (i += 1) {
        block_hashes[ledger.block_count][i] = blk_hash[i];
        ledger.tip_hash[i] = blk_hash[i];
    }

    ledger.height = blk.header.height;
    ledger.block_count += 1;

    return true;
}

pub fn getHeight() u32 {
    return ledger.height;
}

pub fn getBlockCount() u32 {
    return ledger.block_count;
}

pub fn isInitialized() bool {
    return ledger.initialized;
}

pub fn getTipHash() *const [32]u8 {
    return &ledger.tip_hash;
}

pub fn getGenesisHash() *const [32]u8 {
    return &ledger.genesis_hash;
}

pub fn createBlockTemplate(authority_pubkey: *const [32]u8) *Block {
    const blk = Block.initStatic();

    blk.header.height = ledger.height + 1;
    blk.header.timestamp = 1700000000 + (ledger.block_count * 10);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        blk.header.prev_hash[i] = ledger.tip_hash[i];
        blk.header.authority[i] = authority_pubkey[i];
    }

    return blk;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_ledger() bool {
    serial.writeString("[LEDGER] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Initialize
    serial.writeString("  Test 1: Initialize\n");
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_auth_key[i] = 0;
    }
    static_auth_key[0] = 0x01;

    if (init(&static_auth_key) and ledger.initialized) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Genesis height
    serial.writeString("  Test 2: Genesis height\n");
    if (getHeight() == 0 and getBlockCount() == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Add block
    serial.writeString("  Test 3: Add block\n");
    const blk = createBlockTemplate(&static_auth_key);

    static_ledger_entry.entry_type = .file_register;
    static_ledger_entry.timestamp = 0;
    var j: usize = 0;
    while (j < 32) : (j += 1) {
        static_ledger_entry.target_hash[j] = 0;
        static_ledger_entry.data[j] = 0;
    }

    _ = blk.addEntry(&static_ledger_entry);

    if (addBlock(blk) and getHeight() == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  LEDGER: ");
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
