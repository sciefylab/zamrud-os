//! Zamrud OS - File Integrity Registry (Persistent Signed Ledger)
//! Tracks SHA-256 hashes of system files and Hardware Ledger approvals
//! 🆕 F4.3: Cryptographically Signed Persistent Storage (REGISTRY.DAT)

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");
const hash_mod = @import("../crypto/hash.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_ENTRIES: usize = 32;
const REGISTRY_FILE = "REGISTRY.DAT";
const REGISTRY_MAGIC = "ZREGv100"; // 8-byte magic header

// =============================================================================
// Types
// =============================================================================

pub const FileType = enum(u8) {
    kernel = 0,
    driver = 1,
    system_lib = 2,
    config = 3,
    user_app = 4,
    physical_drive = 5, // F4.3: Hardware Authentication
    unknown = 255,
};

pub const FileStatus = enum(u8) {
    unknown = 0,
    valid = 1,
    modified = 2,
    missing = 3,
    quarantined = 4,
};

pub const FileEntry = struct {
    name: [32]u8,
    name_len: u8,
    expected_hash: [32]u8,
    file_type: FileType,
    status: FileStatus,
    version: u16,
    last_check: u32,
    active: bool,

    pub fn getName(self: *const FileEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *FileEntry, name: []const u8) void {
        const len = if (name.len > 32) 32 else name.len;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = name[i];
        }
        self.name_len = @intCast(len);
    }
};

pub const IntegrityStats = struct {
    total: usize,
    valid: usize,
    modified: usize,
    quarantined: usize,
    unknown: usize,
};

// =============================================================================
// State
// =============================================================================

var entries: [MAX_ENTRIES]FileEntry = undefined;
var entry_count: usize = 0;
var system_hash: [32]u8 = [_]u8{0} ** 32;
var system_hash_valid: bool = false;
var initialized: bool = false;

var static_test_hash: [32]u8 = [_]u8{0} ** 32;
var static_stats: IntegrityStats = undefined;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[REGISTRY] Initializing...\n");

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        entries[i].name_len = 0;
        entries[i].file_type = .unknown;
        entries[i].status = .unknown;
        entries[i].version = 0;
        entries[i].last_check = 0;
        entries[i].active = false;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            entries[i].name[j] = 0;
            entries[i].expected_hash[j] = 0;
        }
    }

    entry_count = 0;
    system_hash_valid = false;
    initialized = true;
    serial.writeString("[REGISTRY] Initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// 🆕 PRODUCTION SECURITY: Persistent Cryptographic Ledger (Save/Load)
// =============================================================================

/// Menyimpan data Registry ke Disk dengan segel Tanda Tangan Kriptografi (Hash)
pub fn saveToDisk() bool {
    if (!fat32.isMounted()) return false;

    var buf: [4096]u8 = [_]u8{0} ** 4096;
    var pos: usize = 0;

    // 1. Tulis Magic Header
    for (REGISTRY_MAGIC) |c| {
        buf[pos] = c;
        pos += 1;
    }

    // 2. Tulis Jumlah Entry Aktif
    const active_count = getTotalCount();
    buf[pos] = @intCast(active_count & 0xFF);
    pos += 1;
    buf[pos] = @intCast((active_count >> 8) & 0xFF);
    pos += 1;
    buf[pos] = @intCast((active_count >> 16) & 0xFF);
    pos += 1;
    buf[pos] = @intCast((active_count >> 24) & 0xFF);
    pos += 1;

    // 3. Serialize Entries
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (!entries[i].active) continue;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            buf[pos] = entries[i].name[j];
            pos += 1;
        }
        buf[pos] = entries[i].name_len;
        pos += 1;

        j = 0;
        while (j < 32) : (j += 1) {
            buf[pos] = entries[i].expected_hash[j];
            pos += 1;
        }

        buf[pos] = @intFromEnum(entries[i].file_type);
        pos += 1;
        buf[pos] = @intFromEnum(entries[i].status);
        pos += 1;

        buf[pos] = @intCast(entries[i].version & 0xFF);
        pos += 1;
        buf[pos] = @intCast((entries[i].version >> 8) & 0xFF);
        pos += 1;

        buf[pos] = @intCast(entries[i].last_check & 0xFF);
        pos += 1;
        buf[pos] = @intCast((entries[i].last_check >> 8) & 0xFF);
        pos += 1;
        buf[pos] = @intCast((entries[i].last_check >> 16) & 0xFF);
        pos += 1;
        buf[pos] = @intCast((entries[i].last_check >> 24) & 0xFF);
        pos += 1;
    }

    // 4. Buat Segel Digital (SHA-256) dari Payload
    var hash_result: [32]u8 = undefined;
    hash_mod.sha256Into(buf[0..pos], &hash_result);

    // 5. Tempelkan Segel di Ekor File
    var h: usize = 0;
    while (h < 32) : (h += 1) {
        buf[pos] = hash_result[h];
        pos += 1;
    }

    _ = fat32.deleteFile(REGISTRY_FILE);
    const success = fat32.createFile(REGISTRY_FILE, buf[0..pos]);

    if (success) {
        serial.writeString("[REGISTRY] Signed Ledger persistently saved to disk.\n");
    }
    return success;
}

/// Membaca dan Memverifikasi Segel Kriptografi Registry dari Disk
pub fn loadFromDisk() bool {
    if (!fat32.isMounted()) return false;
    const file = fat32.findInRoot(REGISTRY_FILE) orelse return false;

    var buf: [4096]u8 = [_]u8{0} ** 4096;
    const read_size = @min(@as(usize, @intCast(file.size)), 4096);
    const bytes_read = fat32.readFile(file.cluster, buf[0..read_size]);

    if (bytes_read < 8 + 4 + 32) {
        serial.writeString("[REGISTRY] CORRUPTION: File too small.\n");
        return false;
    }

    const payload_len = bytes_read - 32;

    // 1. Verifikasi Integritas Data (Tamper Check)
    var computed_hash: [32]u8 = undefined;
    hash_mod.sha256Into(buf[0..payload_len], &computed_hash);

    var hash_match = true;
    var h: usize = 0;
    while (h < 32) : (h += 1) {
        if (computed_hash[h] != buf[payload_len + h]) {
            hash_match = false;
            break;
        }
    }
    if (!hash_match) {
        serial.writeString("[REGISTRY] CRITICAL: HASH MISMATCH! Ledger tampering detected!\n");
        return false;
    }

    // 2. Verifikasi Magic Header
    var m: usize = 0;
    while (m < 8) : (m += 1) {
        if (buf[m] != REGISTRY_MAGIC[m]) {
            serial.writeString("[REGISTRY] ERROR: Invalid magic header.\n");
            return false;
        }
    }

    // 3. Deserialize Data
    var pos: usize = 8;
    const count = @as(u32, buf[pos]) | (@as(u32, buf[pos + 1]) << 8) |
        (@as(u32, buf[pos + 2]) << 16) | (@as(u32, buf[pos + 3]) << 24);
    pos += 4;

    init(); // Reset state memori

    var i: usize = 0;
    while (i < count and i < MAX_ENTRIES) : (i += 1) {
        entries[i].active = true;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            entries[i].name[j] = buf[pos];
            pos += 1;
        }
        entries[i].name_len = buf[pos];
        pos += 1;

        j = 0;
        while (j < 32) : (j += 1) {
            entries[i].expected_hash[j] = buf[pos];
            pos += 1;
        }

        entries[i].file_type = @enumFromInt(buf[pos]);
        pos += 1;
        entries[i].status = @enumFromInt(buf[pos]);
        pos += 1;

        entries[i].version = @as(u16, buf[pos]) | (@as(u16, buf[pos + 1]) << 8);
        pos += 2;

        entries[i].last_check = @as(u32, buf[pos]) | (@as(u32, buf[pos + 1]) << 8) |
            (@as(u32, buf[pos + 2]) << 16) | (@as(u32, buf[pos + 3]) << 24);
        pos += 4;

        entry_count += 1;
    }

    serial.writeString("[REGISTRY] Secure Ledger loaded and verified.\n");
    return true;
}

// =============================================================================
// Core API
// =============================================================================

pub fn registerFile(name: []const u8, hash_val: *const [32]u8, file_type: FileType, version: u16) bool {
    if (!initialized) init();
    if (entry_count >= MAX_ENTRIES) return false;
    if (findEntry(name) != null) return false;

    var entry = &entries[entry_count];
    entry.setName(name);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        entry.expected_hash[i] = hash_val[i];
    }

    entry.file_type = file_type;
    entry.version = version;
    entry.status = .unknown;
    entry.active = true;

    entry_count += 1;
    system_hash_valid = false;

    return true;
}

pub fn findEntry(name: []const u8) ?*FileEntry {
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        if (!entries[i].active) continue;

        const entry_name = entries[i].getName();
        if (entry_name.len != name.len) continue;

        var match = true;
        var j: usize = 0;
        while (j < name.len) : (j += 1) {
            if (entry_name[j] != name[j]) {
                match = false;
                break;
            }
        }

        if (match) return &entries[i];
    }
    return null;
}

pub fn findEntryByHash(target_hash: *const [32]u8) ?*FileEntry {
    if (!initialized) return null;
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        if (!entries[i].active) continue;

        var match = true;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (entries[i].expected_hash[j] != target_hash[j]) {
                match = false;
                break;
            }
        }
        if (match) return &entries[i];
    }
    return null;
}

pub fn isRegistered(target_hash: *const [32]u8) bool {
    return findEntryByHash(target_hash) != null;
}

pub fn updateStatus(name: []const u8, status: FileStatus) bool {
    const entry = findEntry(name);
    if (entry == null) return false;
    entry.?.status = status;
    return true;
}

pub fn getSystemHash() *const [32]u8 {
    return &system_hash;
}

pub fn isSystemValid() bool {
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        if (!entries[i].active) continue;
        if (entries[i].file_type == .kernel or entries[i].file_type == .driver or entries[i].file_type == .system_lib) {
            if (entries[i].status == .modified or entries[i].status == .quarantined) {
                return false;
            }
        }
    }
    return true;
}

pub fn getStats() *const IntegrityStats {
    static_stats.total = 0;
    static_stats.valid = 0;
    static_stats.modified = 0;
    static_stats.quarantined = 0;
    static_stats.unknown = 0;

    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        if (!entries[i].active) continue;
        static_stats.total += 1;
        switch (entries[i].status) {
            .valid => static_stats.valid += 1,
            .modified => static_stats.modified += 1,
            .quarantined => static_stats.quarantined += 1,
            else => static_stats.unknown += 1,
        }
    }
    return &static_stats;
}

pub fn getTotalCount() usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        if (entries[i].active) count += 1;
    }
    return count;
}

pub fn getEntryCount() usize {
    return entry_count;
}

// =============================================================================
// Test
// =============================================================================
pub fn test_registry() bool {
    serial.writeString("[REGISTRY] Testing...\n");
    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and entry_count == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 2: Register file\n");
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_test_hash[i] = 0;
    }
    static_test_hash[0] = 0xAB;
    if (registerFile("kernel.bin", &static_test_hash, .kernel, 1)) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 3: Find entry\n");
    if (findEntry("kernel.bin") != null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 4: Get stats\n");
    const total = getTotalCount();
    if (total == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  REGISTRY: ");
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
