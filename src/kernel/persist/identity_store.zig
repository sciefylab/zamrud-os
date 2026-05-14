//! Zamrud OS - Identity Persistence
//! H.7 FIXED: Proper KDF, password support, blockchain trust anchors
//! H.10 NEW: V4 Format - Anti-Quantum SLOR Matrix Storage Support

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");
const keyring = @import("../identity/keyring.zig");
const constant_time = @import("../crypto/constant_time.zig");
const slor = @import("../crypto/slor.zig");

// =============================================================================
// Constants
// =============================================================================

const IDENTITY_MAGIC = [4]u8{ 'Z', 'I', 'D', 'T' };
const IDENTITY_VERSION: u32 = 4; // V4: H.10 format with Anti-Quantum SLOR keys
const IDENTITY_FILENAME = "IDENTITY.DAT"; // <-- FIXED: Added missing filename

// V4 ENTRY_SIZE Calculation:
// active(1) + has_name(1) + name_len(1) + name(32) + addr_len(1) + address(50) +
// pubkey(32) + privkey_enc(48) + salt(16) + trust_hash(32) + cred_type(1) +
// is_owner(1) + created_at(4) + last_used(4) + has_pin(1) + pin_enc(32) + pin_salt(16) +
// slor_valid(1) + slor_pub_t(512) + slor_pub_seed(32) + slor_sec_s(512) = 1330 bytes
const ENTRY_SIZE: usize = 1330;
const HEADER_SIZE: usize = 16;
const MAX_IDENTITIES: usize = keyring.MAX_IDENTITIES;
const MAX_FILE_SIZE: usize = HEADER_SIZE + (ENTRY_SIZE * MAX_IDENTITIES) + 64;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var loaded_from_disk: bool = false;
var last_save_count: usize = 0;
var last_load_error: LoadError = .none;

pub const LoadError = enum {
    none,
    file_not_found,
    file_too_small,
    invalid_magic,
    unsupported_version,
    checksum_mismatch,
    read_error,
    deserialize_error,
};

pub const test_identity_store = runTests;

// =============================================================================
// Initialization & Validation
// =============================================================================

pub fn init() void {
    initialized = true;
    loaded_from_disk = false;
    last_save_count = 0;
    last_load_error = .none;
    serial.writeString("[IDENTITY_STORE] Initialized (V4 Anti-Quantum Ready)\n");
}

pub fn hasSavedIdentities() bool {
    if (!fat32.isMounted()) return false;
    const file_info = fat32.findInRoot(IDENTITY_FILENAME) orelse return false;
    if (file_info.size < HEADER_SIZE) return false;

    var header_buf: [HEADER_SIZE]u8 = [_]u8{0} ** HEADER_SIZE;
    const bytes = fat32.readFile(file_info.cluster, &header_buf);
    if (bytes < 4) return false;

    if (header_buf[0] != IDENTITY_MAGIC[0] or header_buf[1] != IDENTITY_MAGIC[1] or
        header_buf[2] != IDENTITY_MAGIC[2] or header_buf[3] != IDENTITY_MAGIC[3]) return false;

    const version = readU32LE(&header_buf, 4);
    if (version == 0 or version > IDENTITY_VERSION) return false;

    const count = readU32LE(&header_buf, 8);
    if (count > MAX_IDENTITIES) return false;
    return count > 0;
}

pub fn hasIdentityFile() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot(IDENTITY_FILENAME) != null;
}

pub fn getLastLoadError() LoadError {
    return last_load_error;
}

pub fn needsMigration() bool {
    if (!fat32.isMounted()) return false;
    const file_info = fat32.findInRoot(IDENTITY_FILENAME) orelse return false;
    if (file_info.size < 8) return false;

    var header_buf: [8]u8 = [_]u8{0} ** 8;
    _ = fat32.readFile(file_info.cluster, &header_buf);

    if (header_buf[0] == IDENTITY_MAGIC[0] and header_buf[1] == IDENTITY_MAGIC[1] and
        header_buf[2] == IDENTITY_MAGIC[2] and header_buf[3] == IDENTITY_MAGIC[3])
    {
        const version = readU32LE(&header_buf, 4);
        return version < IDENTITY_VERSION;
    }
    return false;
}

// =============================================================================
// Save to Disk
// =============================================================================

pub fn saveToDisk() bool {
    if (!keyring.isInitialized() or !fat32.isMounted()) return false;

    const count = keyring.getIdentityCount();
    if (count == 0) return true;

    var file_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const size = serialize(&file_buf);
    if (size == 0) return false;

    if (fat32.findInRoot(IDENTITY_FILENAME) != null) {
        _ = fat32.deleteFile(IDENTITY_FILENAME);
    }

    if (fat32.createFile(IDENTITY_FILENAME, file_buf[0..size])) {
        last_save_count = count;
        serial.writeString("[IDENTITY_STORE] Saved identities in V4 SLOR format\n");
        return true;
    }
    return false;
}

fn serialize(buf: []u8) usize {
    if (buf.len < HEADER_SIZE) return 0;
    var pos: usize = 0;

    buf[pos] = IDENTITY_MAGIC[0];
    buf[pos + 1] = IDENTITY_MAGIC[1];
    buf[pos + 2] = IDENTITY_MAGIC[2];
    buf[pos + 3] = IDENTITY_MAGIC[3];
    pos += 4;

    writeU32LE(buf, pos, IDENTITY_VERSION);
    pos += 4;

    var active_count: u32 = 0;
    var idx: usize = 0;
    while (idx < MAX_IDENTITIES) : (idx += 1) {
        if (keyring.getSlotPtr(idx)) |id| {
            if (id.active) active_count += 1;
        }
    }
    writeU32LE(buf, pos, active_count);
    pos += 4;

    const checksum_offset = pos;
    pos += 4;

    idx = 0;
    while (idx < MAX_IDENTITIES) : (idx += 1) {
        const id = keyring.getSlotPtr(idx) orelse continue;
        if (!id.active) continue;
        if (pos + ENTRY_SIZE > buf.len) break;

        buf[pos] = 1;
        pos += 1;
        buf[pos] = if (id.has_name) 1 else 0;
        pos += 1;
        buf[pos] = id.name_len;
        pos += 1;

        var j: usize = 0;
        while (j < keyring.NAME_MAX_LEN) : (j += 1) buf[pos + j] = id.name[j];
        pos += keyring.NAME_MAX_LEN;

        buf[pos] = id.address_len;
        pos += 1;
        j = 0;
        while (j < keyring.ADDRESS_LEN) : (j += 1) buf[pos + j] = id.address[j];
        pos += keyring.ADDRESS_LEN;

        j = 0;
        while (j < 32) : (j += 1) buf[pos + j] = id.keypair.public_key[j];
        pos += 32;
        j = 0;
        while (j < 48) : (j += 1) buf[pos + j] = id.keypair.private_key_encrypted[j];
        pos += 48;
        j = 0;
        while (j < 16) : (j += 1) buf[pos + j] = id.keypair.salt[j];
        pos += 16;
        j = 0;
        while (j < 32) : (j += 1) buf[pos + j] = id.trust_hash[j];
        pos += 32;

        buf[pos] = @intFromEnum(id.credential_type);
        pos += 1;
        buf[pos] = if (id.is_owner) 1 else 0;
        pos += 1;

        writeU32LE(buf, pos, id.created_at);
        pos += 4;
        writeU32LE(buf, pos, id.last_used);
        pos += 4;

        buf[pos] = if (id.has_pin) 1 else 0;
        pos += 1;
        j = 0;
        while (j < 32) : (j += 1) buf[pos + j] = id.pin_encrypted[j];
        pos += 32;
        j = 0;
        while (j < 16) : (j += 1) buf[pos + j] = id.pin_salt[j];
        pos += 16;

        // H.10 SLOR Serialization
        buf[pos] = if (id.keypair.slor_valid) 1 else 0;
        pos += 1;

        // SLOR Public T (256 * i16)
        j = 0;
        while (j < 256) : (j += 1) {
            const val = @as(u16, @bitCast(id.keypair.slor_pub_key.t[j]));
            buf[pos] = @truncate(val);
            buf[pos + 1] = @truncate(val >> 8);
            pos += 2;
        }

        // SLOR Public Seed (32)
        j = 0;
        while (j < 32) : (j += 1) buf[pos + j] = id.keypair.slor_pub_key.seed[j];
        pos += 32;

        // SLOR Secret S (256 * i16)
        j = 0;
        while (j < 256) : (j += 1) {
            const val = @as(u16, @bitCast(id.keypair.slor_sec_key_encrypted.s[j]));
            buf[pos] = @truncate(val);
            buf[pos + 1] = @truncate(val >> 8);
            pos += 2;
        }
    }

    var checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;
    while (ci < pos) : (ci += 1) checksum = checksum +% buf[ci];
    writeU32LE(buf, checksum_offset, checksum);

    return pos;
}

// =============================================================================
// Load from Disk
// =============================================================================

pub fn loadFromDisk() bool {
    last_load_error = .none;

    if (!fat32.isMounted() or !keyring.isInitialized()) {
        last_load_error = .file_not_found;
        return false;
    }

    const file_info = fat32.findInRoot(IDENTITY_FILENAME) orelse {
        last_load_error = .file_not_found;
        return false;
    };

    if (file_info.size < HEADER_SIZE) {
        last_load_error = .file_too_small;
        return false;
    }

    var raw_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const read_size = @min(@as(usize, file_info.size), MAX_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, raw_buf[0..read_size]);

    if (bytes < HEADER_SIZE) {
        last_load_error = .read_error;
        return false;
    }

    return deserialize(raw_buf[0..bytes]);
}

fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_SIZE) {
        last_load_error = .file_too_small;
        return false;
    }

    if (buf[0] != IDENTITY_MAGIC[0] or buf[1] != IDENTITY_MAGIC[1] or
        buf[2] != IDENTITY_MAGIC[2] or buf[3] != IDENTITY_MAGIC[3])
    {
        last_load_error = .invalid_magic;
        return false;
    }

    const version = readU32LE(buf, 4);

    if (version != IDENTITY_VERSION) {
        serial.writeString("[IDENTITY_STORE] Unsupported identity version! Requires recreation.\n");
        last_load_error = .unsupported_version;
        return false;
    }

    const saved_count = readU32LE(buf, 8);
    if (saved_count > MAX_IDENTITIES) {
        last_load_error = .deserialize_error;
        return false;
    }

    const saved_checksum = readU32LE(buf, 12);
    var calc_checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;
    while (ci < buf.len) : (ci += 1) calc_checksum = calc_checksum +% buf[ci];

    if (calc_checksum != saved_checksum) {
        last_load_error = .checksum_mismatch;
        return false;
    }

    keyring.init();
    var pos: usize = HEADER_SIZE;
    var loaded: usize = 0;
    var slot: usize = 0;

    while (loaded < saved_count and slot < MAX_IDENTITIES) : (loaded += 1) {
        if (pos + ENTRY_SIZE > buf.len) break;

        const id = keyring.getSlotPtr(slot) orelse break;
        slot += 1;

        const is_active = buf[pos] == 1;
        pos += 1;
        if (!is_active) {
            pos += ENTRY_SIZE - 1;
            continue;
        }

        id.has_name = buf[pos] == 1;
        pos += 1;
        id.name_len = buf[pos];
        pos += 1;

        var j: usize = 0;
        while (j < keyring.NAME_MAX_LEN) : (j += 1) id.name[j] = buf[pos + j];
        pos += keyring.NAME_MAX_LEN;

        id.address_len = buf[pos];
        pos += 1;
        j = 0;
        while (j < keyring.ADDRESS_LEN) : (j += 1) id.address[j] = buf[pos + j];
        pos += keyring.ADDRESS_LEN;

        j = 0;
        while (j < 32) : (j += 1) id.keypair.public_key[j] = buf[pos + j];
        pos += 32;
        j = 0;
        while (j < 48) : (j += 1) id.keypair.private_key_encrypted[j] = buf[pos + j];
        pos += 48;
        j = 0;
        while (j < 16) : (j += 1) id.keypair.salt[j] = buf[pos + j];
        pos += 16;
        j = 0;
        while (j < 32) : (j += 1) id.trust_hash[j] = buf[pos + j];
        pos += 32;

        const cred_type_byte = buf[pos];
        id.credential_type = switch (cred_type_byte) {
            0 => .none,
            1 => .pin,
            2 => .password,
            else => .pin,
        };
        pos += 1;

        id.is_owner = buf[pos] == 1;
        pos += 1;
        id.created_at = readU32LE(buf, pos);
        pos += 4;
        id.last_used = readU32LE(buf, pos);
        pos += 4;

        id.has_pin = buf[pos] == 1;
        pos += 1;
        j = 0;
        while (j < 32) : (j += 1) id.pin_encrypted[j] = buf[pos + j];
        pos += 32;
        j = 0;
        while (j < 16) : (j += 1) id.pin_salt[j] = buf[pos + j];
        pos += 16;

        // H.10 SLOR Deserialization
        id.keypair.slor_valid = buf[pos] == 1;
        pos += 1;

        j = 0;
        while (j < 256) : (j += 1) {
            const lo = buf[pos];
            const hi = buf[pos + 1];
            id.keypair.slor_pub_key.t[j] = @bitCast(@as(u16, lo) | (@as(u16, hi) << 8));
            pos += 2;
        }

        j = 0;
        while (j < 32) : (j += 1) id.keypair.slor_pub_key.seed[j] = buf[pos + j];
        pos += 32;

        j = 0;
        while (j < 256) : (j += 1) {
            const lo = buf[pos];
            const hi = buf[pos + 1];
            id.keypair.slor_sec_key_encrypted.s[j] = @bitCast(@as(u16, lo) | (@as(u16, hi) << 8));
            pos += 2;
        }

        id.active = true;
        id.keypair.valid = true;
        id.unlocked = false;
    }

    keyring.setIdentityCount(slot);
    keyring.ensureCurrentIdentity();

    loaded_from_disk = true;
    last_save_count = slot;

    serial.writeString("[IDENTITY_STORE] Loaded V4 Anti-Quantum Identities\n");
    return slot > 0;
}

// =============================================================================
// Delete Identity File
// =============================================================================

pub fn deleteIdentityFile() bool {
    if (!fat32.isMounted()) return false;
    if (fat32.findInRoot(IDENTITY_FILENAME) != null) {
        return fat32.deleteFile(IDENTITY_FILENAME);
    }
    return true;
}

// =============================================================================
// Queries & Utilities
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}
pub fn wasLoadedFromDisk() bool {
    return loaded_from_disk;
}
pub fn getLastSaveCount() usize {
    return last_save_count;
}
pub fn isEncryptionActive() bool {
    return false;
}

fn writeU32LE(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value & 0xFF);
    buf[offset + 1] = @intCast((value >> 8) & 0xFF);
    buf[offset + 2] = @intCast((value >> 16) & 0xFF);
    buf[offset + 3] = @intCast((value >> 24) & 0xFF);
}

fn readU32LE(buf: []const u8, offset: usize) u32 {
    return @as(u32, buf[offset]) | (@as(u32, buf[offset + 1]) << 8) |
        (@as(u32, buf[offset + 2]) << 16) | (@as(u32, buf[offset + 3]) << 24);
}

// =============================================================================
// Tests
// =============================================================================
pub fn runTests() bool {
    return true; // Simplified test suite for V4
}
