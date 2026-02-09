//! Zamrud OS - Runtime Config Store with Disk Persistence
//! Saves/loads runtime configuration to /disk/CONFIG.DAT
//!
//! Format: Binary key-value store
//!   Header: magic(4) + version(4) + entry_count(4) + checksum(4) = 16 bytes
//!   Entry:  key_len(1) + key(32) + val_len(1) + value(64) = 98 bytes each
//!
//! Config is separate from compile-time config.zig:
//!   config.zig    = build-time constants (profile, limits)
//!   config_store  = runtime settings (hostname, user prefs)

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");
const hash = @import("../crypto/hash.zig");
const chain_mod = @import("../chain/chain.zig");
const entry_mod = @import("../chain/entry.zig");

// =============================================================================
// Constants
// =============================================================================

const CONFIG_MAGIC = [4]u8{ 'Z', 'C', 'F', 'G' };
const CONFIG_VERSION: u32 = 1;
const CONFIG_FILENAME = "CONFIG.DAT";

const MAX_KEY_LEN: usize = 32;
const MAX_VAL_LEN: usize = 64;
const MAX_ENTRIES: usize = 32;

const ENTRY_SIZE: usize = 1 + MAX_KEY_LEN + 1 + MAX_VAL_LEN; // 98 bytes
const HEADER_SIZE: usize = 16;
const MAX_FILE_SIZE: usize = HEADER_SIZE + (ENTRY_SIZE * MAX_ENTRIES); // 3152 bytes

// =============================================================================
// Config Entry
// =============================================================================

const ConfigEntry = struct {
    key: [MAX_KEY_LEN]u8,
    key_len: u8,
    value: [MAX_VAL_LEN]u8,
    value_len: u8,
    active: bool,

    fn clear(self: *ConfigEntry) void {
        var i: usize = 0;
        while (i < MAX_KEY_LEN) : (i += 1) self.key[i] = 0;
        i = 0;
        while (i < MAX_VAL_LEN) : (i += 1) self.value[i] = 0;
        self.key_len = 0;
        self.value_len = 0;
        self.active = false;
    }

    fn getKey(self: *const ConfigEntry) []const u8 {
        return self.key[0..self.key_len];
    }

    fn getValue(self: *const ConfigEntry) []const u8 {
        return self.value[0..self.value_len];
    }

    fn setKey(self: *ConfigEntry, k: []const u8) void {
        const len = @min(k.len, MAX_KEY_LEN);
        var i: usize = 0;
        while (i < len) : (i += 1) self.key[i] = k[i];
        while (i < MAX_KEY_LEN) : (i += 1) self.key[i] = 0;
        self.key_len = @intCast(len);
    }

    fn setValue(self: *ConfigEntry, v: []const u8) void {
        const len = @min(v.len, MAX_VAL_LEN);
        var i: usize = 0;
        while (i < len) : (i += 1) self.value[i] = v[i];
        while (i < MAX_VAL_LEN) : (i += 1) self.value[i] = 0;
        self.value_len = @intCast(len);
    }

    fn keyEquals(self: *const ConfigEntry, k: []const u8) bool {
        if (self.key_len != k.len) return false;
        var i: usize = 0;
        while (i < self.key_len) : (i += 1) {
            if (self.key[i] != k[i]) return false;
        }
        return true;
    }
};

// =============================================================================
// State
// =============================================================================

var entries: [MAX_ENTRIES]ConfigEntry = undefined;
var entry_count: usize = 0;
var initialized: bool = false;
var dirty: bool = false; // Has unsaved changes
var loaded_from_disk: bool = false;
var auto_save: bool = true;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[CONFIG_STORE] Initializing...\n");

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        entries[i].clear();
    }
    entry_count = 0;
    dirty = false;
    loaded_from_disk = false;

    // Set defaults
    setDefaults();

    initialized = true;
    serial.writeString("[CONFIG_STORE] Initialized with defaults\n");
}

fn setDefaults() void {
    // System defaults
    setInternal("system.hostname", "zamrud-node");
    setInternal("system.version", "0.1.0");
    setInternal("system.profile", "development");

    // Network defaults
    setInternal("network.p2p_port", "9333");
    setInternal("network.max_peers", "256");
    setInternal("network.discovery", "on");

    // Security defaults
    setInternal("security.firewall", "enforcing");
    setInternal("security.stealth", "off");
    setInternal("security.auto_blacklist", "off");

    // Identity defaults
    setInternal("identity.auto_lock", "300");
    setInternal("identity.privacy", "pseudonymous");

    // Chain defaults
    setInternal("chain.auto_save", "on");
    setInternal("chain.max_blocks", "10000");

    dirty = false; // Defaults don't count as dirty
}

/// Internal set that doesn't mark dirty or trigger blockchain
fn setInternal(key: []const u8, value: []const u8) void {
    // Find existing
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active and entries[i].keyEquals(key)) {
            entries[i].setValue(value);
            return;
        }
    }

    // Find free slot
    i = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (!entries[i].active) {
            entries[i].setKey(key);
            entries[i].setValue(value);
            entries[i].active = true;
            entry_count += 1;
            return;
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Get config value by key
pub fn get(key: []const u8) ?[]const u8 {
    if (!initialized) return null;

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active and entries[i].keyEquals(key)) {
            return entries[i].getValue();
        }
    }
    return null;
}

/// Set config value (marks dirty, optional blockchain record)
pub fn set(key: []const u8, value: []const u8) bool {
    if (!initialized) return false;
    if (key.len == 0 or key.len > MAX_KEY_LEN) return false;
    if (value.len > MAX_VAL_LEN) return false;

    // Check if value actually changed
    const old_value = get(key);
    if (old_value) |old| {
        if (strEqual(old, value)) return true; // No change
    }

    // Find existing or free slot
    var target: ?usize = null;
    var free_slot: ?usize = null;

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active and entries[i].keyEquals(key)) {
            target = i;
            break;
        }
        if (!entries[i].active and free_slot == null) {
            free_slot = i;
        }
    }

    if (target == null) {
        target = free_slot;
        if (target == null) return false; // No space
        entry_count += 1;
    }

    const idx = target.?;
    entries[idx].setKey(key);
    entries[idx].setValue(value);
    entries[idx].active = true;
    dirty = true;

    // Record config change in blockchain
    recordConfigChange(key, value);

    // Auto-save
    if (auto_save) {
        _ = saveToDisk();
    }

    return true;
}

/// Delete a config entry
pub fn delete(key: []const u8) bool {
    if (!initialized) return false;

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active and entries[i].keyEquals(key)) {
            entries[i].clear();
            if (entry_count > 0) entry_count -= 1;
            dirty = true;

            if (auto_save) {
                _ = saveToDisk();
            }
            return true;
        }
    }
    return false;
}

/// Get entry count
pub fn getEntryCount() usize {
    return entry_count;
}

/// Check if initialized
pub fn isInitialized() bool {
    return initialized;
}

/// Check if has unsaved changes
pub fn isDirty() bool {
    return dirty;
}

/// Check if was loaded from disk
pub fn wasLoadedFromDisk() bool {
    return loaded_from_disk;
}

/// Iterate over entries (for display)
pub fn getEntryByIndex(index: usize) ?struct { key: []const u8, value: []const u8 } {
    if (index >= MAX_ENTRIES) return null;

    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active) {
            if (count == index) {
                return .{
                    .key = entries[i].getKey(),
                    .value = entries[i].getValue(),
                };
            }
            count += 1;
        }
    }
    return null;
}

// =============================================================================
// Blockchain Integration
// =============================================================================

fn recordConfigChange(key: []const u8, value: []const u8) void {
    if (!chain_mod.isInitialized()) return;

    // Hash the key+value as the entry target
    var combined: [MAX_KEY_LEN + MAX_VAL_LEN]u8 = [_]u8{0} ** (MAX_KEY_LEN + MAX_VAL_LEN);
    var pos: usize = 0;

    var i: usize = 0;
    while (i < key.len and pos < combined.len) : (i += 1) {
        combined[pos] = key[i];
        pos += 1;
    }
    // Separator
    if (pos < combined.len) {
        combined[pos] = '=';
        pos += 1;
    }
    i = 0;
    while (i < value.len and pos < combined.len) : (i += 1) {
        combined[pos] = value[i];
        pos += 1;
    }

    var config_hash: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(combined[0..pos], &config_hash);

    // Create config_change entry
    var entry: entry_mod.Entry = undefined;
    entry_mod.Entry.initInto(&entry);
    entry.entry_type = .config_change;
    i = 0;
    while (i < 32) : (i += 1) {
        entry.target_hash[i] = config_hash[i];
    }

    // Store key prefix in data field for identification
    i = 0;
    while (i < key.len and i < 32) : (i += 1) {
        entry.data[i] = key[i];
    }

    // Add to blockchain
    _ = chain_mod.addConfigEntry(&entry);
}

// =============================================================================
// Persistence: Save to Disk
// =============================================================================

pub fn saveToDisk() bool {
    if (!initialized) {
        serial.writeString("[CONFIG_STORE] Cannot save - not initialized\n");
        return false;
    }

    if (!fat32.isMounted()) {
        serial.writeString("[CONFIG_STORE] Cannot save - disk not mounted\n");
        return false;
    }

    var buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const size = serialize(&buf);

    if (size == 0) {
        serial.writeString("[CONFIG_STORE] Serialize failed\n");
        return false;
    }

    // Delete old file
    if (fat32.findInRoot(CONFIG_FILENAME) != null) {
        _ = fat32.deleteFile(CONFIG_FILENAME);
    }

    // Write new file
    if (fat32.createFile(CONFIG_FILENAME, buf[0..size])) {
        dirty = false;
        serial.writeString("[CONFIG_STORE] Saved to disk (");
        printU32(@intCast(entry_count));
        serial.writeString(" entries)\n");
        return true;
    } else {
        serial.writeString("[CONFIG_STORE] Save FAILED\n");
        return false;
    }
}

fn serialize(buf: []u8) usize {
    if (buf.len < HEADER_SIZE) return 0;

    var pos: usize = 0;

    // Magic
    buf[pos] = CONFIG_MAGIC[0];
    buf[pos + 1] = CONFIG_MAGIC[1];
    buf[pos + 2] = CONFIG_MAGIC[2];
    buf[pos + 3] = CONFIG_MAGIC[3];
    pos += 4;

    // Version
    writeU32LE(buf, pos, CONFIG_VERSION);
    pos += 4;

    // Entry count
    var active_count: u32 = 0;
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entries[i].active) active_count += 1;
    }
    writeU32LE(buf, pos, active_count);
    pos += 4;

    // Checksum placeholder (will fill later)
    const checksum_offset = pos;
    pos += 4;

    // Entries
    i = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (!entries[i].active) continue;
        if (pos + ENTRY_SIZE > buf.len) break;

        // key_len
        buf[pos] = entries[i].key_len;
        pos += 1;

        // key
        var j: usize = 0;
        while (j < MAX_KEY_LEN) : (j += 1) {
            buf[pos + j] = entries[i].key[j];
        }
        pos += MAX_KEY_LEN;

        // val_len
        buf[pos] = entries[i].value_len;
        pos += 1;

        // value
        j = 0;
        while (j < MAX_VAL_LEN) : (j += 1) {
            buf[pos + j] = entries[i].value[j];
        }
        pos += MAX_VAL_LEN;
    }

    // Calculate checksum over data (after header)
    var checksum: u32 = 0;
    i = HEADER_SIZE;
    while (i < pos) : (i += 1) {
        checksum = checksum +% buf[i];
    }
    writeU32LE(buf, checksum_offset, checksum);

    return pos;
}

// =============================================================================
// Persistence: Load from Disk
// =============================================================================

pub fn loadFromDisk() bool {
    if (!fat32.isMounted()) {
        serial.writeString("[CONFIG_STORE] Cannot load - disk not mounted\n");
        return false;
    }

    const file_info = fat32.findInRoot(CONFIG_FILENAME) orelse {
        serial.writeString("[CONFIG_STORE] No saved config found\n");
        return false;
    };

    if (file_info.size < HEADER_SIZE) {
        serial.writeString("[CONFIG_STORE] Config file too small\n");
        return false;
    }

    var buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const read_size = @min(@as(usize, file_info.size), MAX_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes < HEADER_SIZE) {
        serial.writeString("[CONFIG_STORE] Config file read error\n");
        return false;
    }

    return deserialize(buf[0..bytes]);
}

fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_SIZE) return false;

    var pos: usize = 0;

    // Verify magic
    if (buf[0] != CONFIG_MAGIC[0] or
        buf[1] != CONFIG_MAGIC[1] or
        buf[2] != CONFIG_MAGIC[2] or
        buf[3] != CONFIG_MAGIC[3])
    {
        serial.writeString("[CONFIG_STORE] Invalid config magic\n");
        return false;
    }
    pos += 4;

    // Verify version
    const version = readU32LE(buf, pos);
    if (version != CONFIG_VERSION) {
        serial.writeString("[CONFIG_STORE] Unsupported config version\n");
        return false;
    }
    pos += 4;

    // Read entry count
    const saved_count = readU32LE(buf, pos);
    if (saved_count > MAX_ENTRIES) {
        serial.writeString("[CONFIG_STORE] Too many entries\n");
        return false;
    }
    pos += 4;

    // Read checksum
    const saved_checksum = readU32LE(buf, pos);
    pos += 4;

    // Verify checksum
    var calc_checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;
    while (ci < buf.len) : (ci += 1) {
        calc_checksum = calc_checksum +% buf[ci];
    }

    if (calc_checksum != saved_checksum) {
        serial.writeString("[CONFIG_STORE] Checksum mismatch!\n");
        return false;
    }

    // Clear current entries
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        entries[i].clear();
    }
    entry_count = 0;

    // Read entries
    var loaded: usize = 0;
    while (loaded < saved_count and pos + ENTRY_SIZE <= buf.len) : (loaded += 1) {
        if (loaded >= MAX_ENTRIES) break;

        // key_len
        const key_len = buf[pos];
        pos += 1;

        if (key_len > MAX_KEY_LEN) {
            serial.writeString("[CONFIG_STORE] Invalid key length\n");
            break;
        }

        // key
        var j: usize = 0;
        while (j < MAX_KEY_LEN) : (j += 1) {
            entries[loaded].key[j] = buf[pos + j];
        }
        entries[loaded].key_len = key_len;
        pos += MAX_KEY_LEN;

        // val_len
        const val_len = buf[pos];
        pos += 1;

        if (val_len > MAX_VAL_LEN) {
            serial.writeString("[CONFIG_STORE] Invalid value length\n");
            break;
        }

        // value
        j = 0;
        while (j < MAX_VAL_LEN) : (j += 1) {
            entries[loaded].value[j] = buf[pos + j];
        }
        entries[loaded].value_len = val_len;
        pos += MAX_VAL_LEN;

        entries[loaded].active = true;
        entry_count += 1;
    }

    dirty = false;
    loaded_from_disk = true;

    serial.writeString("[CONFIG_STORE] Loaded from disk (");
    printU32(@intCast(entry_count));
    serial.writeString(" entries)\n");

    return true;
}

// =============================================================================
// Config Queries (convenience)
// =============================================================================

pub fn getHostname() []const u8 {
    return get("system.hostname") orelse "zamrud-node";
}

pub fn getP2PPort() []const u8 {
    return get("network.p2p_port") orelse "9333";
}

pub fn getPrivacyMode() []const u8 {
    return get("identity.privacy") orelse "pseudonymous";
}

pub fn getAutoLockSeconds() []const u8 {
    return get("identity.auto_lock") orelse "300";
}

pub fn isFirewallEnforcing() bool {
    const val = get("security.firewall") orelse "enforcing";
    return strEqual(val, "enforcing");
}

pub fn isStealthMode() bool {
    const val = get("security.stealth") orelse "off";
    return strEqual(val, "on");
}

pub fn isDiscoveryEnabled() bool {
    const val = get("network.discovery") orelse "on";
    return strEqual(val, "on");
}

pub fn hasSavedConfig() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot(CONFIG_FILENAME) != null;
}

// =============================================================================
// Utility
// =============================================================================

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

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

// =============================================================================
// Test
// =============================================================================

pub fn test_config_store() bool {
    serial.writeString("[CONFIG_STORE] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and entry_count > 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Get default
    serial.writeString("  Test 2: Get default value\n");
    if (get("system.hostname")) |hostname| {
        if (strEqual(hostname, "zamrud-node")) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL (wrong value)\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL (null)\n");
        failed += 1;
    }

    // Test 3: Set new value
    serial.writeString("  Test 3: Set value\n");
    // Disable auto-save during test
    const prev_auto = auto_save;
    auto_save = false;

    if (set("test.key", "test_value")) {
        if (get("test.key")) |val| {
            if (strEqual(val, "test_value")) {
                serial.writeString("    OK\n");
                passed += 1;
            } else {
                serial.writeString("    FAIL (wrong value)\n");
                failed += 1;
            }
        } else {
            serial.writeString("    FAIL (get returned null)\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL (set returned false)\n");
        failed += 1;
    }

    // Test 4: Update existing
    serial.writeString("  Test 4: Update value\n");
    if (set("system.hostname", "my-node")) {
        if (get("system.hostname")) |val| {
            if (strEqual(val, "my-node")) {
                serial.writeString("    OK\n");
                passed += 1;
            } else {
                serial.writeString("    FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Delete
    serial.writeString("  Test 5: Delete entry\n");
    if (delete("test.key")) {
        if (get("test.key") == null) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Nonexistent key
    serial.writeString("  Test 6: Nonexistent key\n");
    if (get("nonexistent.key") == null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Serialize/Deserialize round-trip
    serial.writeString("  Test 7: Serialize round-trip\n");
    _ = set("round.trip", "hello123");
    var test_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const ser_size = serialize(&test_buf);

    // Save current state
    const saved_count = entry_count;

    // Clear and deserialize
    var k: usize = 0;
    while (k < MAX_ENTRIES) : (k += 1) entries[k].clear();
    entry_count = 0;

    if (ser_size > 0 and deserialize(test_buf[0..ser_size])) {
        if (entry_count == saved_count) {
            if (get("round.trip")) |val| {
                if (strEqual(val, "hello123")) {
                    serial.writeString("    OK\n");
                    passed += 1;
                } else {
                    serial.writeString("    FAIL (value mismatch)\n");
                    failed += 1;
                }
            } else {
                serial.writeString("    FAIL (key lost)\n");
                failed += 1;
            }
        } else {
            serial.writeString("    FAIL (count mismatch)\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL (deser failed)\n");
        failed += 1;
    }

    // Test 8: Convenience getters
    serial.writeString("  Test 8: Convenience getters\n");
    _ = set("system.hostname", "zamrud-node");
    if (getHostname().len > 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Restore auto-save
    auto_save = prev_auto;

    // Re-init to clean state
    init();

    serial.writeString("  CONFIG_STORE: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
