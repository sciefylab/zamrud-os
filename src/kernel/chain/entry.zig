//! Zamrud OS - Block Entry Types
//! Entries that can be recorded in a block

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Entry Types
// =============================================================================

pub const EntryType = enum(u8) {
    file_register = 0,
    file_update = 1,
    file_revoke = 2,
    authority_add = 10,
    authority_remove = 11,
    system_update = 20,
    config_change = 21,
    quarantine = 30,
    incident = 31,
};

// =============================================================================
// Static storage for entries
// =============================================================================

var static_entry: Entry = undefined;
var static_entry2: Entry = undefined;
var test_hash: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Block Entry
// =============================================================================

pub const Entry = struct {
    entry_type: EntryType,
    target_hash: [32]u8,
    data: [32]u8,
    timestamp: u32,

    /// Initialize into provided pointer (safe - no return by value)
    pub fn initInto(dest: *Entry) void {
        dest.entry_type = .file_register;
        dest.timestamp = 0;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = 0;
            dest.data[i] = 0;
        }
    }

    /// Initialize static entry and return pointer
    pub fn initPtr() *Entry {
        initInto(&static_entry);
        return &static_entry;
    }

    /// Legacy init - uses static, returns copy (may cause issues)
    pub fn init() Entry {
        initInto(&static_entry);

        // Manual copy to avoid memcpy
        var result: Entry = undefined;
        result.entry_type = static_entry.entry_type;
        result.timestamp = static_entry.timestamp;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            result.target_hash[i] = static_entry.target_hash[i];
            result.data[i] = static_entry.data[i];
        }

        return result;
    }

    /// Create file registration entry into destination
    pub fn fileRegisterInto(dest: *Entry, file_hash: *const [32]u8, version: u16) void {
        initInto(dest);
        dest.entry_type = .file_register;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = file_hash[i];
        }

        dest.data[0] = @intCast(version & 0xFF);
        dest.data[1] = @intCast((version >> 8) & 0xFF);
    }

    /// Create quarantine entry into destination
    pub fn quarantineFileInto(dest: *Entry, file_hash: *const [32]u8, reason: u8) void {
        initInto(dest);
        dest.entry_type = .quarantine;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = file_hash[i];
        }

        dest.data[0] = reason;
    }

    /// Serialize entry to bytes
    pub fn serialize(self: *const Entry, out: []u8) usize {
        if (out.len < 66) return 0;

        out[0] = @intFromEnum(self.entry_type);

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            out[1 + i] = self.target_hash[i];
            out[33 + i] = self.data[i];
        }

        out[65] = @intCast(self.timestamp & 0xFF);

        return 66;
    }
};

// =============================================================================
// Test
// =============================================================================

pub fn test_entry() bool {
    serial.writeString("[ENTRY] Testing block entries...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Create entry using static
    serial.writeString("  Test 1: Create entry\n");

    // Init test hash
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        test_hash[i] = 0;
    }
    test_hash[0] = 0xAB;

    // Use Into version - no return by value
    Entry.fileRegisterInto(&static_entry, &test_hash, 1);

    if (static_entry.entry_type == .file_register and static_entry.target_hash[0] == 0xAB) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Quarantine entry
    serial.writeString("  Test 2: Quarantine entry\n");

    Entry.quarantineFileInto(&static_entry2, &test_hash, 1);

    if (static_entry2.entry_type == .quarantine and static_entry2.data[0] == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  ENTRY: ");
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
