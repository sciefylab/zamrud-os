//! Zamrud OS - Lightweight Ledger
//! Minimal storage for integrity blockchain with persistence

const serial = @import("../drivers/serial/serial.zig");
const block_mod = @import("block.zig");
const entry_mod = @import("entry.zig");
const fat32 = @import("../fs/fat32.zig");

pub const Block = block_mod.Block;
pub const Entry = entry_mod.Entry;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_BLOCKS: usize = 16;

// Persistence format
const CHAIN_MAGIC = [4]u8{ 'Z', 'M', 'R', 'D' };
const CHAIN_VERSION: u32 = 1;
const CHAIN_FILENAME = "CHAIN.DAT";

// Header: magic(4) + version(4) + block_count(4) + height(4) = 16
// Hashes: genesis(32) + tip(32) = 64
// Block hashes: 32 * MAX_BLOCKS = 512
// Total max: 16 + 64 + 512 = 592 bytes
const HEADER_SIZE: usize = 16;
const HASHES_OFFSET: usize = HEADER_SIZE;
const BLOCK_HASHES_OFFSET: usize = HEADER_SIZE + 64;
const MAX_CHAIN_FILE_SIZE: usize = HEADER_SIZE + 64 + (32 * MAX_BLOCKS);

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
pub var block_hashes: [MAX_BLOCKS][32]u8 = undefined;

var static_ledger_entry: entry_mod.Entry = undefined;
var static_auth_key: [32]u8 = [_]u8{0} ** 32;

// Persistence state
var auto_save_enabled: bool = true;
var last_save_height: u32 = 0;

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

    // Auto-save to disk after each new block
    if (auto_save_enabled) {
        _ = saveToDisk();
    }

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
// Persistence: Save to Disk
// =============================================================================

/// Serialize ledger state to /disk/CHAIN.DAT
pub fn saveToDisk() bool {
    if (!ledger.initialized) {
        serial.writeString("[LEDGER] Cannot save - not initialized\n");
        return false;
    }

    if (!fat32.isMounted()) {
        serial.writeString("[LEDGER] Cannot save - disk not mounted\n");
        return false;
    }

    var buf: [MAX_CHAIN_FILE_SIZE]u8 = [_]u8{0} ** MAX_CHAIN_FILE_SIZE;
    const size = serialize(&buf);

    if (size == 0) {
        serial.writeString("[LEDGER] Serialize failed\n");
        return false;
    }

    // Delete old file first
    if (fat32.findInRoot(CHAIN_FILENAME) != null) {
        _ = fat32.deleteFile(CHAIN_FILENAME);
    }

    // Write new file
    if (fat32.createFile(CHAIN_FILENAME, buf[0..size])) {
        last_save_height = ledger.height;
        serial.writeString("[LEDGER] Saved to disk (height=");
        printU32(ledger.height);
        serial.writeString(", blocks=");
        printU32(ledger.block_count);
        serial.writeString(")\n");
        return true;
    } else {
        serial.writeString("[LEDGER] Save to disk FAILED\n");
        return false;
    }
}

/// Serialize ledger to byte buffer
fn serialize(buf: []u8) usize {
    if (buf.len < MAX_CHAIN_FILE_SIZE) return 0;

    var pos: usize = 0;

    // Magic: "ZMRD"
    buf[pos] = CHAIN_MAGIC[0];
    buf[pos + 1] = CHAIN_MAGIC[1];
    buf[pos + 2] = CHAIN_MAGIC[2];
    buf[pos + 3] = CHAIN_MAGIC[3];
    pos += 4;

    // Version
    writeU32LE(buf, pos, CHAIN_VERSION);
    pos += 4;

    // Block count
    writeU32LE(buf, pos, ledger.block_count);
    pos += 4;

    // Height
    writeU32LE(buf, pos, ledger.height);
    pos += 4;

    // Genesis hash
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[pos + i] = ledger.genesis_hash[i];
    }
    pos += 32;

    // Tip hash
    i = 0;
    while (i < 32) : (i += 1) {
        buf[pos + i] = ledger.tip_hash[i];
    }
    pos += 32;

    // Block hashes
    var b: usize = 0;
    while (b < ledger.block_count and b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            buf[pos + i] = block_hashes[b][i];
        }
        pos += 32;
    }

    return pos;
}

// =============================================================================
// Persistence: Load from Disk
// =============================================================================

/// Load ledger state from /disk/CHAIN.DAT
pub fn loadFromDisk() bool {
    if (!fat32.isMounted()) {
        serial.writeString("[LEDGER] Cannot load - disk not mounted\n");
        return false;
    }

    const file_info = fat32.findInRoot(CHAIN_FILENAME) orelse {
        serial.writeString("[LEDGER] No saved chain found\n");
        return false;
    };

    if (file_info.size < HEADER_SIZE + 64) {
        serial.writeString("[LEDGER] Chain file too small\n");
        return false;
    }

    var buf: [MAX_CHAIN_FILE_SIZE]u8 = [_]u8{0} ** MAX_CHAIN_FILE_SIZE;
    const read_size: usize = @min(@as(usize, file_info.size), MAX_CHAIN_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes < HEADER_SIZE + 64) {
        serial.writeString("[LEDGER] Chain file read error\n");
        return false;
    }

    return deserialize(buf[0..bytes]);
}

/// Deserialize ledger from byte buffer
fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_SIZE + 64) return false;

    var pos: usize = 0;

    // Verify magic
    if (buf[0] != CHAIN_MAGIC[0] or
        buf[1] != CHAIN_MAGIC[1] or
        buf[2] != CHAIN_MAGIC[2] or
        buf[3] != CHAIN_MAGIC[3])
    {
        serial.writeString("[LEDGER] Invalid chain file magic\n");
        return false;
    }
    pos += 4;

    // Verify version
    const version = readU32LE(buf, pos);
    if (version != CHAIN_VERSION) {
        serial.writeString("[LEDGER] Unsupported chain version: ");
        printU32(version);
        serial.writeString("\n");
        return false;
    }
    pos += 4;

    // Read block count
    const saved_block_count = readU32LE(buf, pos);
    if (saved_block_count == 0 or saved_block_count > MAX_BLOCKS) {
        serial.writeString("[LEDGER] Invalid block count\n");
        return false;
    }
    pos += 4;

    // Read height
    const saved_height = readU32LE(buf, pos);
    pos += 4;

    // Verify we have enough data for all hashes
    const needed = HEADER_SIZE + 64 + (saved_block_count * 32);
    if (buf.len < needed) {
        serial.writeString("[LEDGER] Chain file truncated\n");
        return false;
    }

    // Read genesis hash
    resetLedger();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        ledger.genesis_hash[i] = buf[pos + i];
    }
    pos += 32;

    // Read tip hash
    i = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = buf[pos + i];
    }
    pos += 32;

    // Read block hashes
    var b: usize = 0;
    while (b < saved_block_count and b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            block_hashes[b][i] = buf[pos + i];
        }
        pos += 32;
    }

    // Verify tip hash matches last block hash
    var tip_match = true;
    i = 0;
    while (i < 32) : (i += 1) {
        if (ledger.tip_hash[i] != block_hashes[saved_block_count - 1][i]) {
            tip_match = false;
            break;
        }
    }

    if (!tip_match) {
        serial.writeString("[LEDGER] Chain integrity check FAILED\n");
        resetLedger();
        return false;
    }

    // Restore state
    ledger.block_count = saved_block_count;
    ledger.height = saved_height;
    ledger.initialized = true;
    ledger_inited = true;
    last_save_height = saved_height;

    serial.writeString("[LEDGER] Loaded from disk (height=");
    printU32(saved_height);
    serial.writeString(", blocks=");
    printU32(saved_block_count);
    serial.writeString(")\n");

    return true;
}

// =============================================================================
// Persistence Configuration
// =============================================================================

pub fn setAutoSave(enabled: bool) void {
    auto_save_enabled = enabled;
}

pub fn isAutoSaveEnabled() bool {
    return auto_save_enabled;
}

pub fn getLastSaveHeight() u32 {
    return last_save_height;
}

pub fn hasSavedChain() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot(CHAIN_FILENAME) != null;
}

// =============================================================================
// Utility
// =============================================================================

fn writeU32LE(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value & 0xFF);
    buf[offset + 1] = @intCast((value >> 8) & 0xFF);
    buf[offset + 2] = @intCast((value >> 16) & 0xFF);
    buf[offset + 3] = @intCast((value >> 24) & 0xFF);
}

fn readU32LE(buf: []const u8, offset: usize) u32 {
    return @as(u32, buf[offset]) |
        (@as(u32, buf[offset + 1]) << 8) |
        (@as(u32, buf[offset + 2]) << 16) |
        (@as(u32, buf[offset + 3]) << 24);
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

    // Disable auto-save during tests
    const prev_auto_save = auto_save_enabled;
    auto_save_enabled = false;

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

    // Restore auto-save
    auto_save_enabled = prev_auto_save;

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
