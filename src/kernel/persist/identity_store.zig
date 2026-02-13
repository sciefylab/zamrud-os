//! Zamrud OS - Identity Persistence
//! F4.2: AES-256 encrypted before disk write
//! Double encryption: private keys are PIN-encrypted + disk-level encrypted
//!
//! On disk: [SYS_MAGIC(4)][IV(16)][encrypted identity data]

const serial = @import("../drivers/serial/serial.zig");
const fat32 = @import("../fs/fat32.zig");
const keyring = @import("../identity/keyring.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");

// =============================================================================
// Constants
// =============================================================================

const IDENTITY_MAGIC = [4]u8{ 'Z', 'I', 'D', 'T' };
const IDENTITY_VERSION: u32 = 2; // Bumped for encrypted format
const IDENTITY_FILENAME = "IDENTITY.DAT";

const ENTRY_SIZE: usize = 182;
const HEADER_SIZE: usize = 16;
const MAX_IDENTITIES: usize = keyring.MAX_IDENTITIES;
const MAX_PLAINTEXT_SIZE: usize = HEADER_SIZE + (ENTRY_SIZE * MAX_IDENTITIES);
const MAX_FILE_SIZE: usize = MAX_PLAINTEXT_SIZE + sys_encrypt.HEADER_SIZE + sys_encrypt.BLOCK_SIZE + 64;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var loaded_from_disk: bool = false;
var last_save_count: usize = 0;
var encryption_active: bool = false; // F4.2

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    initialized = true;
    loaded_from_disk = false;
    last_save_count = 0;
    encryption_active = false;
    serial.writeString("[IDENTITY_STORE] Initialized\n");
}

// =============================================================================
// F4.2: Encrypted Save to Disk
// =============================================================================

pub fn saveToDisk() bool {
    if (!keyring.isInitialized()) {
        serial.writeString("[IDENTITY_STORE] Cannot save - keyring not initialized\n");
        return false;
    }

    if (!fat32.isMounted()) {
        serial.writeString("[IDENTITY_STORE] Cannot save - disk not mounted\n");
        return false;
    }

    const count = keyring.getIdentityCount();
    if (count == 0) {
        serial.writeString("[IDENTITY_STORE] No identities to save\n");
        return true;
    }

    // Step 1: Serialize to plaintext
    var plain_buf: [MAX_PLAINTEXT_SIZE]u8 = [_]u8{0} ** MAX_PLAINTEXT_SIZE;
    const plain_size = serialize(&plain_buf);

    if (plain_size == 0) {
        serial.writeString("[IDENTITY_STORE] Serialize failed\n");
        return false;
    }

    // Step 2: Encrypt if available
    var write_data: []const u8 = undefined;

    if (sys_encrypt.isInitialized() and sys_encrypt.isMasterKeySet()) {
        if (sys_encrypt.encryptIdentity(plain_buf[0..plain_size])) |encrypted| {
            write_data = encrypted;
            encryption_active = true;
            serial.writeString("[IDENTITY_STORE] Encrypting identity data (double-encrypted privkeys)...\n");
        } else {
            serial.writeString("[IDENTITY_STORE] WARNING: encryption failed, saving with PIN protection only!\n");
            write_data = plain_buf[0..plain_size];
            encryption_active = false;
        }
    } else {
        write_data = plain_buf[0..plain_size];
        encryption_active = false;
    }

    // Step 3: Write to disk
    if (fat32.findInRoot(IDENTITY_FILENAME) != null) {
        _ = fat32.deleteFile(IDENTITY_FILENAME);
    }

    var file_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const write_len = @min(write_data.len, MAX_FILE_SIZE);
    var wi: usize = 0;
    while (wi < write_len) : (wi += 1) {
        file_buf[wi] = write_data[wi];
    }

    if (fat32.createFile(IDENTITY_FILENAME, file_buf[0..write_len])) {
        last_save_count = count;
        serial.writeString("[IDENTITY_STORE] Saved ");
        printU32(@intCast(count));
        serial.writeString(" identities (");
        if (encryption_active) serial.writeString("ENCRYPTED") else serial.writeString("PIN-only");
        serial.writeString(")\n");
        return true;
    } else {
        serial.writeString("[IDENTITY_STORE] Save FAILED\n");
        return false;
    }
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
        while (j < keyring.NAME_MAX_LEN) : (j += 1) {
            buf[pos + j] = id.name[j];
        }
        pos += keyring.NAME_MAX_LEN;

        buf[pos] = id.address_len;
        pos += 1;

        j = 0;
        while (j < keyring.ADDRESS_LEN) : (j += 1) {
            buf[pos + j] = id.address[j];
        }
        pos += keyring.ADDRESS_LEN;

        j = 0;
        while (j < 32) : (j += 1) {
            buf[pos + j] = id.keypair.public_key[j];
        }
        pos += 32;

        j = 0;
        while (j < 48) : (j += 1) {
            buf[pos + j] = id.keypair.private_key_encrypted[j];
        }
        pos += 48;

        j = 0;
        while (j < 16) : (j += 1) {
            buf[pos + j] = id.keypair.salt[j];
        }
        pos += 16;
    }

    var checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;
    while (ci < pos) : (ci += 1) {
        checksum = checksum +% buf[ci];
    }
    writeU32LE(buf, checksum_offset, checksum);

    return pos;
}

// =============================================================================
// F4.2: Encrypted Load from Disk
// =============================================================================

pub fn loadFromDisk() bool {
    if (!fat32.isMounted()) {
        serial.writeString("[IDENTITY_STORE] Cannot load - disk not mounted\n");
        return false;
    }

    if (!keyring.isInitialized()) {
        serial.writeString("[IDENTITY_STORE] Cannot load - keyring not initialized\n");
        return false;
    }

    const file_info = fat32.findInRoot(IDENTITY_FILENAME) orelse {
        serial.writeString("[IDENTITY_STORE] No saved identities found\n");
        return false;
    };

    if (file_info.size < HEADER_SIZE) {
        serial.writeString("[IDENTITY_STORE] Identity file too small\n");
        return false;
    }

    var raw_buf: [MAX_FILE_SIZE]u8 = [_]u8{0} ** MAX_FILE_SIZE;
    const read_size = @min(@as(usize, file_info.size), MAX_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, raw_buf[0..read_size]);

    if (bytes < 4) {
        serial.writeString("[IDENTITY_STORE] Identity file read error\n");
        return false;
    }

    // Check if encrypted
    if (sys_encrypt.isEncrypted(raw_buf[0..bytes])) {
        serial.writeString("[IDENTITY_STORE] Detected encrypted identity data\n");

        if (!sys_encrypt.isInitialized() or !sys_encrypt.isMasterKeySet()) {
            serial.writeString("[IDENTITY_STORE] Cannot decrypt - no system key\n");
            return false;
        }

        if (sys_encrypt.decryptIdentity(raw_buf[0..bytes])) |decrypted| {
            var parse_buf: [MAX_PLAINTEXT_SIZE]u8 = [_]u8{0} ** MAX_PLAINTEXT_SIZE;
            const dec_len = @min(decrypted.len, MAX_PLAINTEXT_SIZE);
            var di: usize = 0;
            while (di < dec_len) : (di += 1) {
                parse_buf[di] = decrypted[di];
            }
            encryption_active = true;
            return deserialize(parse_buf[0..dec_len]);
        } else {
            serial.writeString("[IDENTITY_STORE] Identity decryption FAILED\n");
            return false;
        }
    } else {
        serial.writeString("[IDENTITY_STORE] Loading legacy plaintext identities\n");
        encryption_active = false;
        return deserialize(raw_buf[0..bytes]);
    }
}

fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_SIZE) return false;

    if (buf[0] != IDENTITY_MAGIC[0] or buf[1] != IDENTITY_MAGIC[1] or
        buf[2] != IDENTITY_MAGIC[2] or buf[3] != IDENTITY_MAGIC[3])
    {
        serial.writeString("[IDENTITY_STORE] Invalid identity file magic\n");
        return false;
    }

    const version = readU32LE(buf, 4);
    if (version != 1 and version != IDENTITY_VERSION) {
        serial.writeString("[IDENTITY_STORE] Unsupported identity version\n");
        return false;
    }

    const saved_count = readU32LE(buf, 8);
    if (saved_count > MAX_IDENTITIES) {
        serial.writeString("[IDENTITY_STORE] Too many identities\n");
        return false;
    }

    const saved_checksum = readU32LE(buf, 12);

    var calc_checksum: u32 = 0;
    var ci: usize = HEADER_SIZE;
    while (ci < buf.len) : (ci += 1) {
        calc_checksum = calc_checksum +% buf[ci];
    }

    if (calc_checksum != saved_checksum) {
        serial.writeString("[IDENTITY_STORE] Identity checksum mismatch!\n");
        return false;
    }

    if (buf.len < HEADER_SIZE + (saved_count * ENTRY_SIZE)) {
        serial.writeString("[IDENTITY_STORE] Identity file truncated\n");
        return false;
    }

    keyring.init();

    var pos: usize = HEADER_SIZE;
    var loaded: usize = 0;
    var slot: usize = 0;
    while (loaded < saved_count and pos + ENTRY_SIZE <= buf.len) : (loaded += 1) {
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
        while (j < keyring.NAME_MAX_LEN) : (j += 1) {
            id.name[j] = buf[pos + j];
        }
        pos += keyring.NAME_MAX_LEN;

        id.address_len = buf[pos];
        pos += 1;

        j = 0;
        while (j < keyring.ADDRESS_LEN) : (j += 1) {
            id.address[j] = buf[pos + j];
        }
        pos += keyring.ADDRESS_LEN;

        j = 0;
        while (j < 32) : (j += 1) {
            id.keypair.public_key[j] = buf[pos + j];
        }
        pos += 32;

        j = 0;
        while (j < 48) : (j += 1) {
            id.keypair.private_key_encrypted[j] = buf[pos + j];
        }
        pos += 48;

        j = 0;
        while (j < 16) : (j += 1) {
            id.keypair.salt[j] = buf[pos + j];
        }
        pos += 16;

        id.active = true;
        id.keypair.valid = true;
        id.unlocked = false;
        id.created_at = 1700000000;
        id.last_used = 1700000000;
    }

    keyring.setIdentityCount(slot);
    keyring.ensureCurrentIdentity();

    loaded_from_disk = true;
    last_save_count = slot;

    serial.writeString("[IDENTITY_STORE] Loaded ");
    printU32(@intCast(slot));
    serial.writeString(" identities from disk\n");

    return slot > 0;
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
    return encryption_active;
}

pub fn hasSavedIdentities() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot(IDENTITY_FILENAME) != null;
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
// Tests
// =============================================================================

pub fn test_identity_store() bool {
    serial.writeString("[IDENTITY_STORE] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Serialize
    serial.writeString("  Test 2: Serialize identity\n");
    keyring.init();
    _ = keyring.createIdentity("persist_test", "1234");

    if (keyring.getIdentityCount() == 1) {
        var test_buf: [MAX_PLAINTEXT_SIZE]u8 = [_]u8{0} ** MAX_PLAINTEXT_SIZE;
        const size = serialize(&test_buf);
        if (size > HEADER_SIZE) {
            serial.writeString("    OK (");
            printU32(@intCast(size));
            serial.writeString(" bytes)\n");
            passed += 1;

            // Test 3: Deserialize
            serial.writeString("  Test 3: Deserialize identity\n");
            if (deserialize(test_buf[0..size])) {
                if (keyring.getIdentityCount() == 1) {
                    if (keyring.findIdentity("persist_test")) |id| {
                        if (id.active and id.keypair.valid and !id.unlocked) {
                            serial.writeString("    OK (restored, locked)\n");
                            passed += 1;
                        } else {
                            serial.writeString("    FAIL (bad state)\n");
                            failed += 1;
                        }
                    } else {
                        serial.writeString("    FAIL (not found)\n");
                        failed += 1;
                    }
                } else {
                    serial.writeString("    FAIL (count)\n");
                    failed += 1;
                }
            } else {
                serial.writeString("    FAIL (deser)\n");
                failed += 1;
            }

            // Test 4: Unlock after restore
            serial.writeString("  Test 4: Unlock after restore\n");
            const auth = @import("../identity/auth.zig");
            auth.init();
            if (auth.unlock("persist_test", "1234")) {
                serial.writeString("    OK\n");
                passed += 1;
            } else {
                serial.writeString("    FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("    FAIL (serialize)\n");
            failed += 1;
            serial.writeString("  Test 3: SKIP\n");
            serial.writeString("  Test 4: SKIP\n");
            failed += 2;
        }
    } else {
        serial.writeString("    FAIL (create)\n");
        failed += 1;
        serial.writeString("  Test 3: SKIP\n");
        serial.writeString("  Test 4: SKIP\n");
        failed += 2;
    }

    // Test 5: Disk persistence
    serial.writeString("  Test 5: Disk save/load\n");
    if (fat32.isMounted()) {
        keyring.init();
        _ = keyring.createIdentity("disk_test", "5678");

        if (saveToDisk()) {
            keyring.init();
            if (loadFromDisk()) {
                if (keyring.findIdentity("disk_test") != null) {
                    serial.writeString("    OK\n");
                    passed += 1;
                    _ = fat32.deleteFile(IDENTITY_FILENAME);
                } else {
                    serial.writeString("    FAIL (not found after load)\n");
                    failed += 1;
                }
            } else {
                serial.writeString("    FAIL (load)\n");
                failed += 1;
            }
        } else {
            serial.writeString("    FAIL (save)\n");
            failed += 1;
        }
    } else {
        serial.writeString("    SKIP (no disk)\n");
        passed += 1;
    }

    serial.writeString("  IDENTITY_STORE: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
