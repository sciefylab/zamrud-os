//! Zamrud OS - Identity Keyring
//! Stores and manages user identities with keypairs
//! H.7 FIXED: Proper KDF, password support, blockchain trust anchors
//! H.7.1: Dual credential support (Password + optional PIN)

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");
const constant_time = @import("../crypto/constant_time.zig");

const DEBUG = false;

fn debug(msg: []const u8) void {
    if (DEBUG) {
        serial.writeString(msg);
    }
}

// =============================================================================
// Constants
// =============================================================================

// =============================================================================
// Constants - H.7.3 HARDENED KDF
// =============================================================================

pub const MAX_IDENTITIES: usize = 8;
pub const NAME_MAX_LEN: usize = 32;
pub const ADDRESS_LEN: usize = 50;

// H.7.3 FIX: Production-grade KDF parameters
// Reference: OWASP Password Storage Cheat Sheet
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

/// Primary password KDF iterations (100,000 - matches LUKS/1Password/Bitwarden)
pub const KDF_ROUNDS: u32 = 100_000;

/// Secondary PIN KDF iterations (fewer for UX, but still secure)
/// PIN has limited keyspace (10^4 to 10^8), so we use more iterations
/// to compensate, but less than password for responsiveness
pub const KDF_ROUNDS_PIN: u32 = 50_000;

/// Export/backup password KDF (highest security - offline attack resistant)
pub const KDF_ROUNDS_EXPORT: u32 = 200_000;

/// Credential length constraints
pub const CREDENTIAL_MIN_LEN: usize = 4; // PIN minimum
pub const CREDENTIAL_MAX_LEN: usize = 64; // Password maximum
pub const PASSWORD_MIN_LEN: usize = 8; // Password minimum
pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 8;

// =============================================================================
// Types
// =============================================================================

pub const CredentialType = enum(u8) {
    none = 0,
    pin = 1, // 4-8 digit PIN
    password = 2, // 8-64 char password
};

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
    credential_type: CredentialType, // H.7: Primary credential type (always password for ceremony)
    is_owner: bool, // H.7: System owner flag
    trust_hash: [32]u8, // H.7: Trust anchor hash (blockchain binding)

    // H.7.1: Secondary PIN support (optional quick unlock)
    has_pin: bool,
    pin_encrypted: [32]u8, // Private key encrypted with PIN
    pin_salt: [16]u8,

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

    pub fn getTrustHash(self: *const Identity) *const [32]u8 {
        return &self.trust_hash;
    }

    pub fn hasSecondaryPin(self: *const Identity) bool {
        return self.has_pin;
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

// H.7: System owner tracking
var system_owner_idx: usize = 0;
var has_system_owner: bool = false;

// Work buffers
var temp_key_buffer: [32]u8 = [_]u8{0} ** 32;
var temp_hash_buffer: [32]u8 = [_]u8{0} ** 32;
var kdf_work_buffer: [64]u8 = [_]u8{0} ** 64; // H.7: For proper KDF

// =============================================================================
// Initialization
// =============================================================================

fn clearIdentityAt(idx: usize) void {
    identities[idx].address_len = 0;
    identities[idx].name_len = 0;
    identities[idx].has_name = false;
    identities[idx].created_at = 0;
    identities[idx].last_used = 0;
    identities[idx].active = false;
    identities[idx].unlocked = false;
    identities[idx].credential_type = .none;
    identities[idx].is_owner = false;
    identities[idx].keypair.valid = false;
    identities[idx].has_pin = false;

    var j: usize = 0;
    while (j < ADDRESS_LEN) : (j += 1) identities[idx].address[j] = 0;
    j = 0;
    while (j < NAME_MAX_LEN) : (j += 1) identities[idx].name[j] = 0;
    j = 0;
    while (j < 32) : (j += 1) identities[idx].keypair.public_key[j] = 0;
    j = 0;
    while (j < 48) : (j += 1) identities[idx].keypair.private_key_encrypted[j] = 0;
    j = 0;
    while (j < 16) : (j += 1) identities[idx].keypair.salt[j] = 0;
    j = 0;
    while (j < 32) : (j += 1) identities[idx].trust_hash[j] = 0;
    j = 0;
    while (j < 32) : (j += 1) identities[idx].pin_encrypted[j] = 0;
    j = 0;
    while (j < 16) : (j += 1) identities[idx].pin_salt[j] = 0;
}

pub fn init() void {
    debug("[KEYRING] Initializing...\n");

    identity_count = 0;
    current_identity_idx = 0;
    has_current_identity = false;
    has_system_owner = false;
    initialized = false;

    var i: usize = 0;
    while (i < MAX_IDENTITIES) : (i += 1) {
        clearIdentityAt(i);
    }

    initialized = true;
    debug("[KEYRING] Initialized\n");
}

// =============================================================================
// Identity Creation — H.7 FIXED
// =============================================================================

/// Create identity with credential (PIN or password)
/// H.7: Automatically detects credential type and applies proper KDF
pub fn createIdentity(name: []const u8, credential: []const u8) ?*Identity {
    debug("[KEYRING] createIdentity\n");

    if (!initialized) init();
    if (identity_count >= MAX_IDENTITIES) return null;
    if (!validateName(name)) return null;
    if (!validateCredential(credential)) return null;
    if (findIdentity(name) != null) return null;

    const idx = identity_count;
    clearIdentityAt(idx);

    var id = &identities[idx];
    setIdentityName(id, name);
    id.has_name = true;

    // H.7: Detect credential type
    id.credential_type = detectCredentialType(credential);

    // H.7: Use proper KDF with appropriate rounds
    generateAndEncryptKeyPair(id, credential);
    generateAddress(id);

    // H.7: Generate trust anchor hash (blockchain binding)
    generateTrustHash(id);

    // H.7.1: No PIN by default
    id.has_pin = false;

    id.created_at = 1700000000; // TODO: real timestamp
    id.last_used = id.created_at;
    id.active = true;
    id.unlocked = false;

    // H.7: First identity is system owner
    if (!has_system_owner) {
        id.is_owner = true;
        system_owner_idx = idx;
        has_system_owner = true;
    }

    identity_count += 1;

    if (!has_current_identity) {
        current_identity_idx = idx;
        has_current_identity = true;
    }

    return id;
}

/// Create identity with password (explicit password type)
/// H.7: For trust ceremony — enforces password strength
pub fn createIdentityWithPassword(name: []const u8, password: []const u8) ?*Identity {
    if (password.len < PASSWORD_MIN_LEN) return null;
    if (!isStrongPassword(password)) return null;

    const id = createIdentity(name, password);
    if (id != null) {
        id.?.credential_type = .password; // Force password type
    }
    return id;
}

pub fn createAnonymousIdentity(credential: []const u8) ?*Identity {
    if (!initialized) init();
    if (identity_count >= MAX_IDENTITIES) return null;
    if (!validateCredential(credential)) return null;

    const idx = identity_count;
    clearIdentityAt(idx);

    var id = &identities[idx];
    id.has_name = false;
    id.name_len = 0;
    id.credential_type = detectCredentialType(credential);

    generateAndEncryptKeyPair(id, credential);
    generateAddress(id);
    generateTrustHash(id);

    id.has_pin = false;
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

// =============================================================================
// Credential Handling — H.7 UNIFIED
// =============================================================================

/// Detect if credential is a PIN or password
pub fn detectCredentialType(credential: []const u8) CredentialType {
    if (credential.len >= PIN_MIN_LEN and credential.len <= PIN_MAX_LEN) {
        // Check if all digits — it's a PIN
        var all_digits = true;
        for (credential) |c| {
            if (c < '0' or c > '9') {
                all_digits = false;
                break;
            }
        }
        if (all_digits) return .pin;
    }
    return .password;
}

/// Validate credential (accepts both PIN and password)
fn validateCredential(credential: []const u8) bool {
    if (credential.len < CREDENTIAL_MIN_LEN) return false;
    if (credential.len > CREDENTIAL_MAX_LEN) return false;
    return true;
}

/// Check if credential looks like a PIN (4-8 digits)
pub fn looksLikePin(credential: []const u8) bool {
    if (credential.len < PIN_MIN_LEN or credential.len > PIN_MAX_LEN) return false;
    for (credential) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Check if credential is a valid PIN format
pub fn isValidPin(pin: []const u8) bool {
    return looksLikePin(pin);
}

/// Check password strength (at least 2 of 3 character types)
pub fn isStrongPassword(password: []const u8) bool {
    if (password.len < PASSWORD_MIN_LEN) return false;

    var has_lower = false;
    var has_upper = false;
    var has_digit = false;

    for (password) |c| {
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
        if (c >= '0' and c <= '9') has_digit = true;
    }

    var types: u8 = 0;
    if (has_lower) types += 1;
    if (has_upper) types += 1;
    if (has_digit) types += 1;

    return types >= 2;
}

// =============================================================================
// Name & Address Helpers
// =============================================================================

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

// =============================================================================
// Key Derivation — H.7.3 HARDENED
// =============================================================================

/// Key derivation from credential + salt (configurable rounds)
/// Uses iterated SHA-256 (PBKDF2-like construction)
fn deriveKeyFromCredentialWithRounds(credential: []const u8, salt: *const [16]u8, rounds: u32, out: *[32]u8) void {
    // Phase 1: Combine credential + salt
    var i: usize = 0;
    while (i < 64) : (i += 1) kdf_work_buffer[i] = 0;

    i = 0;
    while (i < credential.len and i < 48) : (i += 1) {
        kdf_work_buffer[i] = credential[i];
    }
    i = 0;
    while (i < 16) : (i += 1) {
        kdf_work_buffer[48 + i] = salt[i];
    }

    // Phase 2: Initial hash
    hash.sha256Into(&kdf_work_buffer, out);

    // Phase 3: Iterated hashing (PBKDF2-style)
    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        i = 0;
        while (i < 32) : (i += 1) kdf_work_buffer[i] = out[i];
        i = 0;
        while (i < 16) : (i += 1) kdf_work_buffer[32 + i] = salt[i];

        // Include round counter for domain separation
        kdf_work_buffer[48] = @truncate(round);
        kdf_work_buffer[49] = @truncate(round >> 8);
        kdf_work_buffer[50] = @truncate(round >> 16);
        kdf_work_buffer[51] = @truncate(round >> 24);

        hash.sha256Into(kdf_work_buffer[0..52], out);
    }

    // Phase 4: Wipe work buffer
    constant_time.secureZero(&kdf_work_buffer);
}

/// Key derivation from password (100,000 rounds)
fn deriveKeyFromCredential(credential: []const u8, salt: *const [16]u8, out: *[32]u8) void {
    deriveKeyFromCredentialWithRounds(credential, salt, KDF_ROUNDS, out);
}

/// Key derivation for PIN (50,000 rounds - fewer for UX)
fn deriveKeyFromPin(pin: []const u8, salt: *const [16]u8, out: *[32]u8) void {
    deriveKeyFromCredentialWithRounds(pin, salt, KDF_ROUNDS_PIN, out);
}

fn generateAndEncryptKeyPair(id: *Identity, credential: []const u8) void {
    debug("[KEYRING] generateKeyPair\n");

    // Generate random salt
    crypto.random.getBytes(&id.keypair.salt);

    // Generate random private key
    crypto.random.getBytes(&temp_key_buffer);

    // Derive public key = SHA-256(private_key)
    hash.sha256Into(&temp_key_buffer, &id.keypair.public_key);

    // Derive encryption key from credential
    deriveKeyFromCredential(credential, &id.keypair.salt, &temp_hash_buffer);

    // Encrypt private key with XOR (simple stream cipher)
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] = temp_key_buffer[i] ^ temp_hash_buffer[i];
    }
    // Padding bytes
    while (i < 48) : (i += 1) {
        id.keypair.private_key_encrypted[i] = 0;
    }

    id.keypair.valid = true;

    // Wipe private key from temp buffer
    constant_time.secureZero32(&temp_key_buffer);
    constant_time.secureZero32(&temp_hash_buffer);
}

// =============================================================================
// H.7.1: Secondary PIN Support
// =============================================================================

/// Setup secondary PIN for quick unlock
/// Requires password verification first
pub fn setupSecondaryPin(id: *Identity, password: []const u8, pin: []const u8) bool {
    if (!id.active or !id.keypair.valid) return false;
    if (!isValidPin(pin)) return false;

    // Verify password first by decrypting private key
    var privkey: [32]u8 = [_]u8{0} ** 32;
    if (!decryptPrivateKey(id, password, &privkey)) {
        return false;
    }

    // Generate new salt for PIN
    crypto.random.getBytes(&id.pin_salt);

    // Derive PIN encryption key (fewer rounds for convenience)
    var pin_key: [32]u8 = [_]u8{0} ** 32;
    deriveKeyFromPin(pin, &id.pin_salt, &pin_key);

    // Encrypt private key with PIN
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.pin_encrypted[i] = privkey[i] ^ pin_key[i];
    }

    id.has_pin = true;

    // Wipe sensitive data
    constant_time.secureZero32(&privkey);
    constant_time.secureZero32(&pin_key);

    serial.writeString("[KEYRING] Secondary PIN setup complete\n");
    return true;
}

/// Remove secondary PIN (requires password verification)
pub fn removeSecondaryPin(id: *Identity, password: []const u8) bool {
    if (!id.has_pin) return true; // Already no PIN

    // Verify password first
    var privkey: [32]u8 = [_]u8{0} ** 32;
    if (!decryptPrivateKey(id, password, &privkey)) {
        return false;
    }
    constant_time.secureZero32(&privkey);

    // Clear PIN data
    id.has_pin = false;
    constant_time.secureZero32(&id.pin_encrypted);
    constant_time.secureZero(&id.pin_salt);

    serial.writeString("[KEYRING] Secondary PIN removed\n");
    return true;
}

/// Change secondary PIN (requires password verification)
pub fn changeSecondaryPin(id: *Identity, password: []const u8, new_pin: []const u8) bool {
    // This is essentially remove + setup
    if (!removeSecondaryPin(id, password)) return false;
    return setupSecondaryPin(id, password, new_pin);
}

/// Decrypt private key using PIN
pub fn decryptPrivateKeyWithPin(id: *Identity, pin: []const u8, out: *[32]u8) bool {
    if (!id.has_pin) return false;
    if (!id.keypair.valid) return false;
    if (!isValidPin(pin)) return false;

    // Derive PIN decryption key
    var pin_key: [32]u8 = [_]u8{0} ** 32;
    deriveKeyFromPin(pin, &id.pin_salt, &pin_key);

    // Decrypt
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = id.pin_encrypted[i] ^ pin_key[i];
    }

    // Verify: SHA-256(decrypted_privkey) should match pubkey
    var verify_pubkey: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(out, &verify_pubkey);

    const valid = constant_time.constantTimeCompare32(&verify_pubkey, &id.keypair.public_key);

    if (!valid) {
        constant_time.secureZero32(out);
    }

    constant_time.secureZero32(&pin_key);
    constant_time.secureZero32(&verify_pubkey);

    return valid;
}

// =============================================================================
// Trust Anchor — H.7 (Blockchain Binding)
// =============================================================================

fn generateTrustHash(id: *Identity) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) kdf_work_buffer[i] = id.keypair.public_key[i];
    i = 0;
    while (i < 32 and i < id.address_len) : (i += 1) {
        kdf_work_buffer[32 + i] = id.address[i];
    }

    var intermediate: [32]u8 = undefined;
    hash.sha256Into(kdf_work_buffer[0..64], &intermediate);

    i = 0;
    while (i < 32) : (i += 1) kdf_work_buffer[i] = intermediate[i];

    kdf_work_buffer[32] = @truncate(id.created_at);
    kdf_work_buffer[33] = @truncate(id.created_at >> 8);
    kdf_work_buffer[34] = @truncate(id.created_at >> 16);
    kdf_work_buffer[35] = @truncate(id.created_at >> 24);

    const domain = "zamrud-trust-v1";
    var d: usize = 0;
    while (d < domain.len) : (d += 1) {
        kdf_work_buffer[36 + d] = domain[d];
    }

    hash.sha256Into(kdf_work_buffer[0 .. 36 + domain.len], &id.trust_hash);

    constant_time.secureZero(&kdf_work_buffer);
    constant_time.secureZero32(&intermediate);
}

pub fn verifyTrustHash(id: *const Identity) bool {
    var expected: [32]u8 = undefined;
    var work: [64]u8 = [_]u8{0} ** 64;

    var i: usize = 0;
    while (i < 32) : (i += 1) work[i] = id.keypair.public_key[i];
    i = 0;
    while (i < 32 and i < id.address_len) : (i += 1) {
        work[32 + i] = id.address[i];
    }

    var intermediate: [32]u8 = undefined;
    hash.sha256Into(work[0..64], &intermediate);

    i = 0;
    while (i < 32) : (i += 1) work[i] = intermediate[i];
    work[32] = @truncate(id.created_at);
    work[33] = @truncate(id.created_at >> 8);
    work[34] = @truncate(id.created_at >> 16);
    work[35] = @truncate(id.created_at >> 24);

    const domain = "zamrud-trust-v1";
    var d: usize = 0;
    while (d < domain.len) : (d += 1) {
        work[36 + d] = domain[d];
    }

    hash.sha256Into(work[0 .. 36 + domain.len], &expected);

    const result = constant_time.constantTimeCompare32(&expected, &id.trust_hash);

    constant_time.secureZero(&work);
    constant_time.secureZero32(&intermediate);
    constant_time.secureZero32(&expected);

    return result;
}

// =============================================================================
// Lookup Functions
// =============================================================================

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

pub fn findIdentityByPubkey(pubkey: *const [32]u8) ?*Identity {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active) continue;

        if (constant_time.constantTimeCompare32(&identities[i].keypair.public_key, pubkey)) {
            return &identities[i];
        }
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

// =============================================================================
// Access & State
// =============================================================================

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

pub fn getSystemOwner() ?*Identity {
    if (!has_system_owner) return null;
    if (system_owner_idx >= identity_count) return null;
    if (!identities[system_owner_idx].active) return null;
    return &identities[system_owner_idx];
}

pub fn isSystemOwner(id: *const Identity) bool {
    return id.is_owner;
}

// =============================================================================
// Decryption & Verification (Primary credential - password)
// =============================================================================

pub fn decryptPrivateKey(id: *Identity, credential: []const u8, out: *[32]u8) bool {
    if (!id.keypair.valid) return false;

    deriveKeyFromCredential(credential, &id.keypair.salt, &temp_hash_buffer);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = id.keypair.private_key_encrypted[i] ^ temp_hash_buffer[i];
    }

    var verify_pubkey: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(out, &verify_pubkey);

    const valid = constant_time.constantTimeCompare32(&verify_pubkey, &id.keypair.public_key);

    if (!valid) {
        constant_time.secureZero32(out);
    }

    constant_time.secureZero32(&temp_hash_buffer);
    constant_time.secureZero32(&verify_pubkey);

    return valid;
}

/// Re-encrypt private key with new credential (password change)
pub fn reEncryptPrivateKey(id: *Identity, old_credential: []const u8, new_credential: []const u8) bool {
    var privkey: [32]u8 = [_]u8{0} ** 32;

    if (!decryptPrivateKey(id, old_credential, &privkey)) {
        return false;
    }

    // Generate new salt
    crypto.random.getBytes(&id.keypair.salt);

    // Derive new encryption key
    deriveKeyFromCredential(new_credential, &id.keypair.salt, &temp_hash_buffer);

    // Re-encrypt
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] = privkey[i] ^ temp_hash_buffer[i];
    }

    // Update credential type
    id.credential_type = detectCredentialType(new_credential);

    // If had PIN, invalidate it (need to re-setup with new password)
    if (id.has_pin) {
        id.has_pin = false;
        constant_time.secureZero32(&id.pin_encrypted);
        constant_time.secureZero(&id.pin_salt);
        serial.writeString("[KEYRING] PIN invalidated after password change\n");
    }

    // Wipe
    constant_time.secureZero32(&privkey);
    constant_time.secureZero32(&temp_hash_buffer);

    return true;
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Persistence Support (D3)
// =============================================================================

pub fn getSlotPtr(index: usize) ?*Identity {
    if (index >= MAX_IDENTITIES) return null;
    return &identities[index];
}

pub fn setIdentityCount(count: usize) void {
    if (count <= MAX_IDENTITIES) {
        identity_count = count;
    }
}

pub fn ensureCurrentIdentity() void {
    if (has_current_identity) return;

    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (identities[i].active) {
            current_identity_idx = i;
            has_current_identity = true;

            if (identities[i].is_owner) {
                system_owner_idx = i;
                has_system_owner = true;
            }
            return;
        }
    }
}

// =============================================================================
// Test — Updated for H.7.1
// =============================================================================

pub fn test_keyring() bool {
    serial.writeString("\n=== Keyring Test (H.7.1 Dual Credential) ===\n");

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

    // Test 2: Create identity with password
    serial.writeString("  Test 2: Create identity (password)\n");
    const id = createIdentityWithPassword("alice", "SecurePass1");
    if (id != null and identity_count == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Credential type is password
    serial.writeString("  Test 3: Credential type (password)\n");
    if (id != null and id.?.credential_type == .password) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: No PIN initially
    serial.writeString("  Test 4: No PIN initially\n");
    if (id != null and !id.?.has_pin) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: System owner
    serial.writeString("  Test 5: System owner\n");
    if (id != null and id.?.is_owner) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Decrypt with password
    serial.writeString("  Test 6: Decrypt with password\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (decryptPrivateKey(id.?, "SecurePass1", &privkey)) {
            serial.writeString("    OK\n");
            passed += 1;
            constant_time.secureZero32(&privkey);
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Wrong password rejected
    serial.writeString("  Test 7: Wrong password rejected\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (!decryptPrivateKey(id.?, "WrongPass1", &privkey)) {
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

    // Test 8: Setup secondary PIN
    serial.writeString("  Test 8: Setup secondary PIN\n");
    if (id != null) {
        if (setupSecondaryPin(id.?, "SecurePass1", "1234")) {
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

    // Test 9: has_pin = true
    serial.writeString("  Test 9: has_pin flag\n");
    if (id != null and id.?.has_pin) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 10: Decrypt with PIN
    serial.writeString("  Test 10: Decrypt with PIN\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (decryptPrivateKeyWithPin(id.?, "1234", &privkey)) {
            serial.writeString("    OK\n");
            passed += 1;
            constant_time.secureZero32(&privkey);
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 11: Wrong PIN rejected
    serial.writeString("  Test 11: Wrong PIN rejected\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (!decryptPrivateKeyWithPin(id.?, "9999", &privkey)) {
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

    // Test 12: Password still works after PIN setup
    serial.writeString("  Test 12: Password still works\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (decryptPrivateKey(id.?, "SecurePass1", &privkey)) {
            serial.writeString("    OK\n");
            passed += 1;
            constant_time.secureZero32(&privkey);
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 13: Remove PIN
    serial.writeString("  Test 13: Remove PIN\n");
    if (id != null) {
        if (removeSecondaryPin(id.?, "SecurePass1") and !id.?.has_pin) {
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

    // Test 14: PIN no longer works after removal
    serial.writeString("  Test 14: PIN disabled after removal\n");
    if (id != null) {
        var privkey: [32]u8 = undefined;
        if (!decryptPrivateKeyWithPin(id.?, "1234", &privkey)) {
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

    // Test 15: looksLikePin detection
    serial.writeString("  Test 15: looksLikePin\n");
    if (looksLikePin("1234") and looksLikePin("12345678") and !looksLikePin("123") and !looksLikePin("123456789") and !looksLikePin("abcd")) {
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
