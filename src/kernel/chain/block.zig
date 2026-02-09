//! Zamrud OS - Block Structure
//! Lightweight block for integrity ledger (NO MINING)

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const entry_mod = @import("entry.zig");

// =============================================================================
// Constants
// =============================================================================

pub const BLOCK_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 8;

// =============================================================================
// Block Header
// =============================================================================

pub const BlockHeader = struct {
    version: u32,
    height: u32,
    prev_hash: [32]u8,
    entries_hash: [32]u8,
    timestamp: u32,
    authority: [32]u8,
    signature: [64]u8,
};

// =============================================================================
// Static storage
// =============================================================================

var static_block_data: [256]u8 = [_]u8{0} ** 256;
var static_block_hash: [32]u8 = [_]u8{0} ** 32;
var static_entries_data: [128]u8 = [_]u8{0} ** 128;

pub var static_block: Block = undefined;
var static_block_initialized: bool = false;

var static_test_entry: entry_mod.Entry = undefined;
var test_auth_key: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Block
// =============================================================================

pub const Block = struct {
    header: BlockHeader,
    entries: [MAX_ENTRIES]entry_mod.Entry,
    entry_count: u8,

    pub fn initStatic() *Block {
        static_block.header.version = BLOCK_VERSION;
        static_block.header.height = 0;
        static_block.header.timestamp = 0;
        static_block.entry_count = 0;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            static_block.header.prev_hash[i] = 0;
            static_block.header.entries_hash[i] = 0;
            static_block.header.authority[i] = 0;
        }
        i = 0;
        while (i < 64) : (i += 1) {
            static_block.header.signature[i] = 0;
        }

        static_block_initialized = true;
        return &static_block;
    }

    pub fn addEntry(self: *Block, ent: *const entry_mod.Entry) bool {
        if (self.entry_count >= MAX_ENTRIES) return false;

        self.entries[self.entry_count].entry_type = ent.entry_type;
        self.entries[self.entry_count].timestamp = ent.timestamp;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            self.entries[self.entry_count].target_hash[i] = ent.target_hash[i];
            self.entries[self.entry_count].data[i] = ent.data[i];
        }

        self.entry_count += 1;
        self.calculateEntriesHash();
        return true;
    }

    pub fn calculateEntriesHash(self: *Block) void {
        var pos: usize = 0;

        var i: usize = 0;
        while (i < self.entry_count and pos + 33 < 128) : (i += 1) {
            static_entries_data[pos] = @intFromEnum(self.entries[i].entry_type);
            pos += 1;

            var j: usize = 0;
            while (j < 32 and pos < 128) : (j += 1) {
                static_entries_data[pos] = self.entries[i].target_hash[j];
                pos += 1;
            }
        }

        hash.sha256Into(static_entries_data[0..pos], &self.header.entries_hash);
    }

    pub fn getHash(self: *const Block) *const [32]u8 {
        var pos: usize = 0;

        static_block_data[pos] = @intCast(self.header.version & 0xFF);
        static_block_data[pos + 1] = @intCast((self.header.version >> 8) & 0xFF);
        static_block_data[pos + 2] = @intCast((self.header.version >> 16) & 0xFF);
        static_block_data[pos + 3] = @intCast((self.header.version >> 24) & 0xFF);
        pos += 4;

        static_block_data[pos] = @intCast(self.header.height & 0xFF);
        static_block_data[pos + 1] = @intCast((self.header.height >> 8) & 0xFF);
        static_block_data[pos + 2] = @intCast((self.header.height >> 16) & 0xFF);
        static_block_data[pos + 3] = @intCast((self.header.height >> 24) & 0xFF);
        pos += 4;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            static_block_data[pos + i] = self.header.prev_hash[i];
        }
        pos += 32;

        i = 0;
        while (i < 32) : (i += 1) {
            static_block_data[pos + i] = self.header.entries_hash[i];
        }
        pos += 32;

        static_block_data[pos] = @intCast(self.header.timestamp & 0xFF);
        static_block_data[pos + 1] = @intCast((self.header.timestamp >> 8) & 0xFF);
        static_block_data[pos + 2] = @intCast((self.header.timestamp >> 16) & 0xFF);
        static_block_data[pos + 3] = @intCast((self.header.timestamp >> 24) & 0xFF);
        pos += 4;

        hash.sha256Into(static_block_data[0..pos], &static_block_hash);
        return &static_block_hash;
    }

    pub fn createGenesis(authority_pubkey: *const [32]u8) *Block {
        _ = initStatic();

        static_block.header.height = 0;
        static_block.header.timestamp = 1700000000;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            static_block.header.authority[i] = authority_pubkey[i];
        }

        static_test_entry.entry_type = .system_update;
        static_test_entry.timestamp = static_block.header.timestamp;

        i = 0;
        while (i < 32) : (i += 1) {
            static_test_entry.target_hash[i] = 0;
            static_test_entry.data[i] = 0;
        }

        static_test_entry.data[0] = 'Z';
        static_test_entry.data[1] = 'A';
        static_test_entry.data[2] = 'M';
        static_test_entry.data[3] = 'R';
        static_test_entry.data[4] = 'U';
        static_test_entry.data[5] = 'D';

        _ = static_block.addEntry(&static_test_entry);

        return &static_block;
    }

    pub fn validate(self: *const Block) bool {
        if (self.header.version == 0 or self.header.version > 10) return false;
        if (self.entry_count == 0) return false;
        return true;
    }
};

// =============================================================================
// Test Suite
// =============================================================================

pub fn test_blockchain() bool {
    serial.writeString("[BLOCK] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Block creation
    serial.writeString("  Test 1: Block creation\n");
    const blk_ptr = Block.initStatic();

    if (blk_ptr.entry_count == 0 and blk_ptr.header.version == BLOCK_VERSION) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Add entry
    serial.writeString("  Test 2: Add entry\n");
    _ = Block.initStatic();

    static_test_entry.entry_type = .file_register;
    static_test_entry.timestamp = 0;
    var j: usize = 0;
    while (j < 32) : (j += 1) {
        static_test_entry.target_hash[j] = 0;
        static_test_entry.data[j] = 0;
    }
    static_test_entry.target_hash[0] = 0xAB;

    if (static_block.addEntry(&static_test_entry) and static_block.entry_count == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Genesis block
    serial.writeString("  Test 3: Genesis block\n");
    j = 0;
    while (j < 32) : (j += 1) {
        test_auth_key[j] = 0;
    }
    test_auth_key[0] = 0x01;

    const genesis = Block.createGenesis(&test_auth_key);
    if (genesis.header.height == 0 and genesis.entry_count == 1 and genesis.validate()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Block hash
    serial.writeString("  Test 4: Block hash\n");
    const block_hash = genesis.getHash();
    var has_data = false;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (block_hash[i] != 0) has_data = true;
    }
    if (has_data) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  BLOCK: ");
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
