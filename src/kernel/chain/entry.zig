//! Zamrud OS - Block Entry Types
//! Entries that can be recorded in a block
//! Updated: F3 identity/role entries

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

    // F3: Identity & Role Management
    identity_register = 40,
    role_assign = 41,
    role_revoke = 42,
};

// =============================================================================
// F3: Role encoding in data[0]
// =============================================================================

pub const ROLE_ROOT: u8 = 0;
pub const ROLE_ADMIN: u8 = 1;
pub const ROLE_USER: u8 = 2;
pub const ROLE_GUEST: u8 = 3;

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

    /// Legacy init - uses static, returns copy
    pub fn init() Entry {
        initInto(&static_entry);

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

    // =========================================================================
    // F3: Identity/Role Entry Builders
    // =========================================================================

    /// Create identity_register entry
    /// target_hash = user's pubkey
    /// data[0] = role, data[1..16] = name
    pub fn identityRegisterInto(
        dest: *Entry,
        pubkey: *const [32]u8,
        role: u8,
        name: []const u8,
    ) void {
        initInto(dest);
        dest.entry_type = .identity_register;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = pubkey[i];
        }

        dest.data[0] = role;

        // Copy name to data[1..16] (max 15 chars)
        const nlen = if (name.len > 15) @as(usize, 15) else name.len;
        i = 0;
        while (i < nlen) : (i += 1) {
            dest.data[1 + i] = name[i];
        }
    }

    /// Create role_assign entry
    /// target_hash = target user's pubkey
    /// data[0] = new role, data[1..16] = assigner's pubkey prefix
    pub fn roleAssignInto(
        dest: *Entry,
        target_pubkey: *const [32]u8,
        new_role: u8,
        assigner_pubkey: *const [32]u8,
    ) void {
        initInto(dest);
        dest.entry_type = .role_assign;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = target_pubkey[i];
        }

        dest.data[0] = new_role;

        // Copy first 15 bytes of assigner's pubkey as identifier
        i = 0;
        while (i < 15) : (i += 1) {
            dest.data[1 + i] = assigner_pubkey[i];
        }
    }

    /// Create role_revoke entry
    /// target_hash = target user's pubkey
    /// data[0] = reason code, data[1..16] = revoker's pubkey prefix
    pub fn roleRevokeInto(
        dest: *Entry,
        target_pubkey: *const [32]u8,
        reason: u8,
        revoker_pubkey: *const [32]u8,
    ) void {
        initInto(dest);
        dest.entry_type = .role_revoke;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            dest.target_hash[i] = target_pubkey[i];
        }

        dest.data[0] = reason;

        i = 0;
        while (i < 15) : (i += 1) {
            dest.data[1 + i] = revoker_pubkey[i];
        }
    }

    /// Get role from identity_register or role_assign entry
    pub fn getRole(self: *const Entry) u8 {
        return self.data[0];
    }

    /// Get name from identity_register entry (data[1..16])
    pub fn getEntryName(self: *const Entry) []const u8 {
        var len: usize = 0;
        while (len < 15) : (len += 1) {
            if (self.data[1 + len] == 0) break;
        }
        if (len == 0) return "";
        return self.data[1 .. 1 + len];
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

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        test_hash[i] = 0;
    }
    test_hash[0] = 0xAB;

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

    // Test 3: F3 - Identity register entry
    serial.writeString("  Test 3: Identity register\n");

    var test_pubkey: [32]u8 = [_]u8{0} ** 32;
    test_pubkey[0] = 0x42;

    Entry.identityRegisterInto(&static_entry, &test_pubkey, ROLE_ROOT, "testroot");

    if (static_entry.entry_type == .identity_register and
        static_entry.target_hash[0] == 0x42 and
        static_entry.data[0] == ROLE_ROOT and
        static_entry.data[1] == 't')
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: F3 - Role assign entry
    serial.writeString("  Test 4: Role assign\n");

    var assigner_key: [32]u8 = [_]u8{0} ** 32;
    assigner_key[0] = 0xAA;

    Entry.roleAssignInto(&static_entry2, &test_pubkey, ROLE_ADMIN, &assigner_key);

    if (static_entry2.entry_type == .role_assign and
        static_entry2.data[0] == ROLE_ADMIN and
        static_entry2.data[1] == 0xAA)
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: F3 - Get role/name from entry
    serial.writeString("  Test 5: Get role/name\n");

    if (static_entry.getRole() == ROLE_ROOT) {
        const name = static_entry.getEntryName();
        if (name.len >= 4 and name[0] == 't' and name[1] == 'e') {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL (name)\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL (role)\n");
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
