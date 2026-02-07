//! Zamrud OS - Identity Keyring
//! Stores and manages user identities with keypairs

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");

// Debug flag - set to false for production
const DEBUG = false;

fn debug(msg: []const u8) void {
    if (DEBUG) {
        serial.writeString(msg);
    }
}

// =============================================================================
// Constants
// =============================================================================

pub const MAX_IDENTITIES: usize = 8;
pub const NAME_MAX_LEN: usize = 32;
pub const ADDRESS_LEN: usize = 50;

// =============================================================================
// Types
// =============================================================================

pub const KeyPair = struct {
    public_key: [32]u8,
    private_key_encrypted: [48]u8,
    salt: [16]u8,
    valid: bool,
};

pub const Identity = struct {
    address: [ADDRESS_LEN]u8,
    address_len: u8,
    name: [NAME_MAX_LEN]u8,
    name_len: u8,
    has_name: bool,
    keypair: KeyPair,
    created_at: u32,
    last_used: u32,
    active: bool,
    unlocked: bool,

    pub fn getName(self: *const Identity) []const u8 {
        if (!self.has_name) return "";
        return self.name[0..self.name_len];
    }

    pub fn getAddress(self: *const Identity) []const u8 {
        return self.address[0..self.address_len];
    }

    pub fn getPublicKey(self: *const Identity) *const [32]u8 {
        return &self.keypair.public_key;
    }
};

// =============================================================================
// State
// =============================================================================

var identities: [MAX_IDENTITIES]Identity = undefined;
var identity_count: usize = 0;
var current_identity_idx: usize = 0;
var has_current_identity: bool = false;
var initialized: bool = false;

var temp_key_buffer: [32]u8 = [_]u8{0} ** 32;
var temp_hash_buffer: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Functions
// =============================================================================

fn clearIdentityAt(idx: usize) void {
    identities[idx].address_len = 0;
    identities[idx].name_len = 0;
    identities[idx].has_name = false;
    identities[idx].created_at = 0;
    identities[idx].last_used = 0;
    identities[idx].active = false;
    identities[idx].unlocked = false;
    identities[idx].keypair.valid = false;

    var j: usize = 0;
    while (j < ADDRESS_LEN) : (j += 1) {
        identities[idx].address[j] = 0;
    }
    j = 0;
    while (j < NAME_MAX_LEN) : (j += 1) {
        identities[idx].name[j] = 0;
    }
    j = 0;
    while (j < 32) : (j += 1) {
        identities[idx].keypair.public_key[j] = 0;
    }
    j = 0;
    while (j < 48) : (j += 1) {
        identities[idx].keypair.private_key_encrypted[j] = 0;
    }
    j = 0;
    while (j < 16) : (j += 1) {
        identities[idx].keypair.salt[j] = 0;
    }
}

pub fn init() void {
    debug("[KEYRING] Initializing...\n");

    identity_count = 0;
    current_identity_idx = 0;
    has_current_identity = false;
    initialized = false;

    var i: usize = 0;
    while (i < MAX_IDENTITIES) : (i += 1) {
        clearIdentityAt(i);
    }

    initialized = true;
    debug("[KEYRING] Initialized\n");
}

pub fn createIdentity(name: []const u8, pin: []const u8) ?*Identity {
    debug("[KEYRING] createIdentity\n");

    if (!initialized) init();
    if (identity_count >= MAX_IDENTITIES) return null;
    if (!validateName(name)) return null;
    if (!validatePin(pin)) return null;
    if (findIdentity(name) != null) return null;

    const idx = identity_count;
    clearIdentityAt(idx);

    var id = &identities[idx];
    setIdentityName(id, name);
    id.has_name = true;

    generateAndEncryptKeyPair(id, pin);
    generateAddress(id);

    id.created_at = 1700000000;
    id.last_used = id.created_at;
    id.active = true;
    id.unlocked = false;

    identity_count += 1;

    if (!has_current_identity) {
        current_identity_idx = idx;
        has_current_identity = true;
    }

    return id;
}

pub fn createAnonymousIdentity(pin: []const u8) ?*Identity {
    if (!initialized) init();
    if (identity_count >= MAX_IDENTITIES) return null;
    if (!validatePin(pin)) return null;

    const idx = identity_count;
    clearIdentityAt(idx);

    var id = &identities[idx];
    id.has_name = false;
    id.name_len = 0;

    generateAndEncryptKeyPair(id, pin);
    generateAddress(id);

    id.created_at = 1700000000;
    id.last_used = id.created_at;
    id.active = true;
    id.unlocked = false;

    identity_count += 1;

    if (!has_current_identity) {
        current_identity_idx = idx;
        has_current_identity = true;
    }

    return id;
}

fn validateName(name: []const u8) bool {
    if (name.len < 3 or name.len > NAME_MAX_LEN) return false;

    var start: usize = 0;
    if (name[0] == '@') start = 1;
    if (name.len - start < 3) return false;

    var i: usize = start;
    while (i < name.len) : (i += 1) {
        const c = name[i];
        if ((c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '_')
        {
            continue;
        }
        return false;
    }

    return true;
}

fn validatePin(pin: []const u8) bool {
    if (pin.len < 4) return false;
    if (pin.len > 64) return false;
    return true;
}

fn setIdentityName(id: *Identity, name: []const u8) void {
    var dest: usize = 0;

    id.name[0] = '@';
    dest = 1;

    var start: usize = 0;
    if (name.len > 0 and name[0] == '@') start = 1;

    var i: usize = start;
    while (i < name.len and dest < NAME_MAX_LEN) : (i += 1) {
        id.name[dest] = name[i];
        dest += 1;
    }
    id.name_len = @intCast(dest);
}

fn generateAndEncryptKeyPair(id: *Identity, pin: []const u8) void {
    debug("[KEYRING] generateKeyPair\n");

    crypto.random.getBytes(&id.keypair.salt);
    crypto.random.getBytes(&temp_key_buffer);
    hash.sha256Into(&temp_key_buffer, &id.keypair.public_key);

    deriveKeyFromPin(pin, &id.keypair.salt, &temp_hash_buffer);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] = temp_key_buffer[i] ^ temp_hash_buffer[i];
    }
    while (i < 48) : (i += 1) {
        id.keypair.private_key_encrypted[i] = 0;
    }

    id.keypair.valid = true;

    i = 0;
    while (i < 32) : (i += 1) {
        temp_key_buffer[i] = 0;
    }
}

fn deriveKeyFromPin(pin: []const u8, salt: *const [16]u8, out: *[32]u8) void {
    var input: [48]u8 = [_]u8{0} ** 48;

    var i: usize = 0;
    while (i < pin.len and i < 32) : (i += 1) {
        input[i] = pin[i];
    }
    i = 0;
    while (i < 16) : (i += 1) {
        input[32 + i] = salt[i];
    }

    hash.sha256Into(&input, out);

    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        hash.sha256Into(out, out);
    }
}

fn generateAddress(id: *Identity) void {
    const prefix = "zamrud1";
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        id.address[i] = prefix[i];
    }

    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    var j: usize = 0;
    while (j < 32 and i < ADDRESS_LEN) : (j += 1) {
        const idx = id.keypair.public_key[j] % 58;
        id.address[i] = alphabet[idx];
        i += 1;
    }

    id.address_len = @intCast(i);
}

pub fn findIdentity(name: []const u8) ?*Identity {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active) continue;
        if (!identities[i].has_name) continue;

        const id_name = identities[i].getName();
        if (namesMatch(id_name, name)) return &identities[i];
    }
    return null;
}

pub fn findIdentityByAddress(address: *const [50]u8) ?*Identity {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active) continue;

        var match = true;
        var j: usize = 0;
        while (j < identities[i].address_len) : (j += 1) {
            if (identities[i].address[j] != address[j]) {
                match = false;
                break;
            }
        }

        if (match) return &identities[i];
    }
    return null;
}

fn namesMatch(a: []const u8, b: []const u8) bool {
    var a_start: usize = 0;
    var b_start: usize = 0;

    if (a.len > 0 and a[0] == '@') a_start = 1;
    if (b.len > 0 and b[0] == '@') b_start = 1;

    const a_name = a[a_start..];
    const b_name = b[b_start..];

    if (a_name.len != b_name.len) return false;

    var i: usize = 0;
    while (i < a_name.len) : (i += 1) {
        if (a_name[i] != b_name[i]) return false;
    }
    return true;
}

pub fn getIdentityByIndex(index: usize) ?*Identity {
    if (index >= identity_count) return null;
    if (!identities[index].active) return null;
    return &identities[index];
}

pub fn getCurrentIdentity() ?*Identity {
    if (!has_current_identity) return null;
    if (current_identity_idx >= identity_count) return null;
    return &identities[current_identity_idx];
}

pub fn setCurrentIdentity(name: []const u8) bool {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active) continue;

        if (identities[i].has_name) {
            if (namesMatch(identities[i].getName(), name)) {
                current_identity_idx = i;
                has_current_identity = true;
                return true;
            }
        }
    }
    return false;
}

pub fn getIdentityCount() usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (identities[i].active) count += 1;
    }
    return count;
}

pub fn deleteIdentity(name: []const u8) bool {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active) continue;
        if (!identities[i].has_name) continue;

        if (namesMatch(identities[i].getName(), name)) {
            clearIdentityAt(i);
            return true;
        }
    }
    return false;
}

pub fn decryptPrivateKey(id: *Identity, pin: []const u8, out: *[32]u8) bool {
    if (!id.keypair.valid) return false;

    deriveKeyFromPin(pin, &id.keypair.salt, &temp_hash_buffer);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = id.keypair.private_key_encrypted[i] ^ temp_hash_buffer[i];
    }

    var verify_pubkey: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(out, &verify_pubkey);

    i = 0;
    while (i < 32) : (i += 1) {
        if (verify_pubkey[i] != id.keypair.public_key[i]) {
            var j: usize = 0;
            while (j < 32) : (j += 1) {
                out[j] = 0;
            }
            return false;
        }
    }

    return true;
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_keyring() bool {
    serial.writeString("\n=== Keyring Test ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and identity_count == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Create identity
    serial.writeString("  Test 2: Create identity\n");
    const id = createIdentity("alice", "123456");
    if (id != null and identity_count == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Name format
    serial.writeString("  Test 3: Name format\n");
    if (id != null) {
        const name = id.?.getName();
        if (name.len > 0 and name[0] == '@') {
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

    // Test 4: Find identity
    serial.writeString("  Test 4: Find identity\n");
    const found = findIdentity("alice");
    if (found != null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Address generated
    serial.writeString("  Test 5: Address generated\n");
    if (id != null and id.?.address_len > 7) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Keypair valid
    serial.writeString("  Test 6: Keypair valid\n");
    if (id != null and id.?.keypair.valid) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  KEYRING: ");
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
