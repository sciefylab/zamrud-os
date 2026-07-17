//! Zamrud OS - Identity Persistence
//! H.7: Identity persistence
//! H.10 V4: SLOR KEM storage
//! GOV.2 V5: gov_sign production-boundary key container storage
//!
//! No double system:
//! - This file persists keyring.gov_sign_* only.
//! - Does not import slor_sign.zig.
//! - Uses crypto/gov_sign.zig serialization API.
//! - slor.zig remains KEM only.

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");
const keyring = @import("../identity/keyring.zig");
const slor = @import("../crypto/slor.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const constant_time = @import("../crypto/constant_time.zig");

// =============================================================================
// Constants
// =============================================================================

const IDENTITY_MAGIC = [4]u8{ 'Z', 'I', 'D', 'T' };

const IDENTITY_VERSION_V4: u32 = 4;
const IDENTITY_VERSION_V5: u32 = 5;
const IDENTITY_VERSION: u32 = IDENTITY_VERSION_V5;

const IDENTITY_FILENAME = "IDENTITY.DAT";

// Common prefix size up to pin_salt:
// active(1) + has_name(1) + name_len(1) + name(32)
// + addr_len(1) + address(50)
// + pubkey(32) + privkey_enc(48) + salt(16)
// + trust_hash(32) + cred_type(1) + is_owner(1)
// + created_at(4) + last_used(4)
// + has_pin(1) + pin_enc(32) + pin_salt(16)
// = 273
const COMMON_PREFIX_SIZE: usize = 273;

// V4 KEM:
// slor_valid(1) + pub.t(512) + pub.seed(32) + sec.s(512) = 1057
const SLOR_KEM_SIZE: usize = 1 + (slor.SLOR_N * 2) + 32 + (slor.SLOR_N * 2);

const ENTRY_SIZE_V4: usize = COMMON_PREFIX_SIZE + SLOR_KEM_SIZE;

// gov_sign serialization blob sizes.
const GOV_SIGN_PUB_BLOB_MAX: usize = 10 + 3072;
const GOV_SIGN_SEC_BLOB_MAX: usize = 10 + 6144;

// gov payload:
// valid(1) + pub_len(2) + pub_blob + sec_len(2) + sec_blob
const GOV_SIGN_SIZE: usize = 1 + 2 + GOV_SIGN_PUB_BLOB_MAX + 2 + GOV_SIGN_SEC_BLOB_MAX;

const ENTRY_SIZE_V5: usize = ENTRY_SIZE_V4 + GOV_SIGN_SIZE;

const HEADER_SIZE: usize = 16;
const MAX_IDENTITIES: usize = keyring.MAX_IDENTITIES;
const MAX_FILE_SIZE: usize = HEADER_SIZE + (ENTRY_SIZE_V5 * MAX_IDENTITIES) + 64;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var loaded_from_disk: bool = false;
var last_save_count: usize = 0;
var last_load_error: LoadError = .none;

var store_file_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
var tmp_gov_pub_blob: [GOV_SIGN_PUB_BLOB_MAX]u8 = [_]u8{0} ** GOV_SIGN_PUB_BLOB_MAX;
var tmp_gov_sec_blob: [GOV_SIGN_SEC_BLOB_MAX]u8 = [_]u8{0} ** GOV_SIGN_SEC_BLOB_MAX;

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

    serial.writeString("[IDENTITY_STORE] Initialized (V5 GOV_SIGN Ready)\n");
}

pub fn hasSavedIdentities() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot(IDENTITY_FILENAME) orelse return false;
    if (file_info.size < HEADER_SIZE) return false;

    var header_buf: [HEADER_SIZE]u8 = [_]u8{0} ** HEADER_SIZE;
    const bytes = fat32.readFile(file_info.cluster, &header_buf);

    if (bytes < 12) return false;

    if (header_buf[0] != IDENTITY_MAGIC[0] or
        header_buf[1] != IDENTITY_MAGIC[1] or
        header_buf[2] != IDENTITY_MAGIC[2] or
        header_buf[3] != IDENTITY_MAGIC[3])
    {
        return false;
    }

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

    if (header_buf[0] == IDENTITY_MAGIC[0] and
        header_buf[1] == IDENTITY_MAGIC[1] and
        header_buf[2] == IDENTITY_MAGIC[2] and
        header_buf[3] == IDENTITY_MAGIC[3])
    {
        const version = readU32LE(&header_buf, 4);
        return version < IDENTITY_VERSION;
    }

    return false;
}

// =============================================================================
// Save
// =============================================================================

pub fn saveToDisk() bool {
    if (!keyring.isInitialized() or !fat32.isMounted()) return false;

    const count = keyring.getIdentityCount();
    if (count == 0) return true;

    constant_time.secureZero(&store_file_buf);

    const size = serialize(&store_file_buf);

    if (size == 0) return false;

    if (fat32.findInRoot(IDENTITY_FILENAME) != null) {
        _ = fat32.deleteFile(IDENTITY_FILENAME);
    }

    if (fat32.createFile(IDENTITY_FILENAME, store_file_buf[0..size])) {
        last_save_count = count;
        serial.writeString("[IDENTITY_STORE] Saved identities in V5 GOV_SIGN format\n");
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

        if (pos + ENTRY_SIZE_V5 > buf.len) break;

        pos = serializeEntryV5(buf, pos, id);
    }

    var checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;

    while (ci < pos) : (ci += 1) {
        checksum = checksum +% buf[ci];
    }

    writeU32LE(buf, checksum_offset, checksum);

    return pos;
}

fn serializeEntryV5(buf: []u8, start: usize, id: *const keyring.Identity) usize {
    var pos = start;

    pos = serializeCommonPrefix(buf, pos, id);
    pos = serializeSlorKem(buf, pos, id);
    pos = serializeGovSign(buf, pos, id);

    return pos;
}

fn serializeCommonPrefix(buf: []u8, start: usize, id: *const keyring.Identity) usize {
    var pos = start;

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

    return pos;
}

fn serializeSlorKem(buf: []u8, start: usize, id: *const keyring.Identity) usize {
    var pos = start;

    buf[pos] = if (id.keypair.slor_valid) 1 else 0;
    pos += 1;

    var j: usize = 0;
    while (j < slor.SLOR_N) : (j += 1) {
        writeI16LE(buf, pos, id.keypair.slor_pub_key.t[j]);
        pos += 2;
    }

    j = 0;
    while (j < 32) : (j += 1) buf[pos + j] = id.keypair.slor_pub_key.seed[j];
    pos += 32;

    j = 0;
    while (j < slor.SLOR_N) : (j += 1) {
        writeI16LE(buf, pos, id.keypair.slor_sec_key_encrypted.s[j]);
        pos += 2;
    }

    return pos;
}

fn serializeGovSign(buf: []u8, start: usize, id: *const keyring.Identity) usize {
    var pos = start;

    buf[pos] = if (id.keypair.gov_sign_valid) 1 else 0;
    pos += 1;

    constant_time.secureZero(&tmp_gov_pub_blob);
    constant_time.secureZero(&tmp_gov_sec_blob);

    const pub_len = gov_sign.serializePublicKey(&id.keypair.gov_sign_pub_key, &tmp_gov_pub_blob);
    const sec_len = gov_sign.serializeSecretKey(&id.keypair.gov_sign_sec_key_encrypted, &tmp_gov_sec_blob);

    writeU16LE(buf, pos, @intCast(pub_len));
    pos += 2;

    var i: usize = 0;
    while (i < GOV_SIGN_PUB_BLOB_MAX) : (i += 1) {
        buf[pos + i] = if (i < pub_len) tmp_gov_pub_blob[i] else 0;
    }
    pos += GOV_SIGN_PUB_BLOB_MAX;

    writeU16LE(buf, pos, @intCast(sec_len));
    pos += 2;

    i = 0;
    while (i < GOV_SIGN_SEC_BLOB_MAX) : (i += 1) {
        buf[pos + i] = if (i < sec_len) tmp_gov_sec_blob[i] else 0;
    }
    pos += GOV_SIGN_SEC_BLOB_MAX;

    constant_time.secureZero(&tmp_gov_pub_blob);
    constant_time.secureZero(&tmp_gov_sec_blob);

    return pos;
}

// =============================================================================
// Load
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

    constant_time.secureZero(&store_file_buf);

    const read_size = @min(@as(usize, file_info.size), MAX_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, store_file_buf[0..read_size]);

    if (bytes < HEADER_SIZE) {
        last_load_error = .read_error;
        return false;
    }

    return deserialize(store_file_buf[0..bytes]);
}

fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_SIZE) {
        last_load_error = .file_too_small;
        return false;
    }

    if (buf[0] != IDENTITY_MAGIC[0] or
        buf[1] != IDENTITY_MAGIC[1] or
        buf[2] != IDENTITY_MAGIC[2] or
        buf[3] != IDENTITY_MAGIC[3])
    {
        last_load_error = .invalid_magic;
        return false;
    }

    const version = readU32LE(buf, 4);

    if (version != IDENTITY_VERSION_V4 and version != IDENTITY_VERSION_V5) {
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

    while (ci < buf.len) : (ci += 1) {
        calc_checksum = calc_checksum +% buf[ci];
    }

    if (calc_checksum != saved_checksum) {
        last_load_error = .checksum_mismatch;
        return false;
    }

    keyring.init();

    var pos: usize = HEADER_SIZE;
    var loaded: usize = 0;
    var slot: usize = 0;

    while (loaded < saved_count and slot < MAX_IDENTITIES) : (loaded += 1) {
        const entry_size = if (version == IDENTITY_VERSION_V4) ENTRY_SIZE_V4 else ENTRY_SIZE_V5;

        if (pos + entry_size > buf.len) break;

        const id = keyring.getSlotPtr(slot) orelse break;
        slot += 1;

        if (version == IDENTITY_VERSION_V4) {
            pos = deserializeEntryV4(buf, pos, id);
        } else {
            pos = deserializeEntryV5(buf, pos, id);
        }
    }

    keyring.setIdentityCount(slot);
    keyring.ensureCurrentIdentity();

    loaded_from_disk = true;
    last_save_count = slot;

    if (version == IDENTITY_VERSION_V4) {
        serial.writeString("[IDENTITY_STORE] Loaded V4 Anti-Quantum Identities\n");
    } else {
        serial.writeString("[IDENTITY_STORE] Loaded V5 GOV_SIGN Identities\n");
    }

    return slot > 0;
}

fn deserializeEntryV4(buf: []const u8, start: usize, id: *keyring.Identity) usize {
    var pos = deserializeCommonPrefix(buf, start, id);

    if (!id.active) {
        return start + ENTRY_SIZE_V4;
    }

    pos = deserializeSlorKem(buf, pos, id);

    gov_sign.clearPublicKey(&id.keypair.gov_sign_pub_key);
    gov_sign.clearSecretKey(&id.keypair.gov_sign_sec_key_encrypted);
    id.keypair.gov_sign_valid = false;

    return start + ENTRY_SIZE_V4;
}

fn deserializeEntryV5(buf: []const u8, start: usize, id: *keyring.Identity) usize {
    var pos = deserializeCommonPrefix(buf, start, id);

    if (!id.active) {
        return start + ENTRY_SIZE_V5;
    }

    pos = deserializeSlorKem(buf, pos, id);
    pos = deserializeGovSign(buf, pos, id);

    return start + ENTRY_SIZE_V5;
}

fn deserializeCommonPrefix(buf: []const u8, start: usize, id: *keyring.Identity) usize {
    var pos = start;

    const is_active = buf[pos] == 1;
    pos += 1;

    if (!is_active) {
        id.active = false;
        return pos;
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

    id.active = true;
    id.keypair.valid = true;
    id.unlocked = false;

    return pos;
}

fn deserializeSlorKem(buf: []const u8, start: usize, id: *keyring.Identity) usize {
    var pos = start;

    id.keypair.slor_valid = buf[pos] == 1;
    pos += 1;

    var j: usize = 0;
    while (j < slor.SLOR_N) : (j += 1) {
        id.keypair.slor_pub_key.t[j] = readI16LE(buf, pos);
        pos += 2;
    }

    j = 0;
    while (j < 32) : (j += 1) id.keypair.slor_pub_key.seed[j] = buf[pos + j];
    pos += 32;

    j = 0;
    while (j < slor.SLOR_N) : (j += 1) {
        id.keypair.slor_sec_key_encrypted.s[j] = readI16LE(buf, pos);
        pos += 2;
    }

    return pos;
}

fn deserializeGovSign(buf: []const u8, start: usize, id: *keyring.Identity) usize {
    var pos = start;

    id.keypair.gov_sign_valid = buf[pos] == 1;
    pos += 1;

    const pub_len = readU16LE(buf, pos);
    pos += 2;

    gov_sign.clearPublicKey(&id.keypair.gov_sign_pub_key);

    if (id.keypair.gov_sign_valid and pub_len > 0 and pub_len <= GOV_SIGN_PUB_BLOB_MAX) {
        _ = gov_sign.deserializePublicKey(
            buf[pos .. pos + pub_len],
            &id.keypair.gov_sign_pub_key,
        );
    }
    pos += GOV_SIGN_PUB_BLOB_MAX;

    const sec_len = readU16LE(buf, pos);
    pos += 2;

    gov_sign.clearSecretKey(&id.keypair.gov_sign_sec_key_encrypted);

    if (id.keypair.gov_sign_valid and sec_len > 0 and sec_len <= GOV_SIGN_SEC_BLOB_MAX) {
        _ = gov_sign.deserializeSecretKey(
            buf[pos .. pos + sec_len],
            &id.keypair.gov_sign_sec_key_encrypted,
        );
    }
    pos += GOV_SIGN_SEC_BLOB_MAX;

    if (!id.keypair.gov_sign_pub_key.valid or !id.keypair.gov_sign_sec_key_encrypted.valid) {
        id.keypair.gov_sign_valid = false;
    }

    return pos;
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
// Queries
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

// =============================================================================
// Encoding Helpers
// =============================================================================

fn writeU16LE(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @truncate(value);
    buf[offset + 1] = @truncate(value >> 8);
}

fn readU16LE(buf: []const u8, offset: usize) u16 {
    return @as(u16, buf[offset]) |
        (@as(u16, buf[offset + 1]) << 8);
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

fn writeI16LE(buf: []u8, offset: usize, value: i16) void {
    const raw: u16 = @bitCast(value);
    buf[offset] = @intCast(raw & 0xFF);
    buf[offset + 1] = @intCast((raw >> 8) & 0xFF);
}

fn readI16LE(buf: []const u8, offset: usize) i16 {
    const raw: u16 = @as(u16, buf[offset]) |
        (@as(u16, buf[offset + 1]) << 8);
    return @bitCast(raw);
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    return true;
}
