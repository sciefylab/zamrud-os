//! Zamrud OS - Identity Keyring
//! Stores and manages user identities with keypairs
//! H.7 FIXED: Proper KDF, password support, blockchain trust anchors
//! H.7.1: Dual credential support (Password + optional PIN)
//! H.10: SLOR KEM keypair support
//! GOV.2: Production governance signature key container via crypto/gov_sign.zig
//!
//! Production crypto policy:
//! - slor.zig       = KEM / key exchange only.
//! - gov_sign.zig   = only official governance signature API.
//! - slor_sign.zig  = not used here.
//! - If gov_sign backend is unavailable, governance signing is fail-closed.

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");
const constant_time = @import("../crypto/constant_time.zig");
const slor = @import("../crypto/slor.zig");
const gov_sign = @import("../crypto/gov_sign.zig");

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

// H.7.3: KDF parameters
pub const KDF_ROUNDS: u32 = 100_000;
pub const KDF_ROUNDS_PIN: u32 = 50_000;
pub const KDF_ROUNDS_EXPORT: u32 = 200_000;

pub const CREDENTIAL_MIN_LEN: usize = 4;
pub const CREDENTIAL_MAX_LEN: usize = 64;
pub const PASSWORD_MIN_LEN: usize = 8;
pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 8;

// =============================================================================
// Types
// =============================================================================

pub const CredentialType = enum(u8) {
    none = 0,
    pin = 1,
    password = 2,
};

pub const KeyPair = struct {
    public_key: [32]u8,
    private_key_encrypted: [48]u8,
    salt: [16]u8,
    valid: bool,

    // H.10: SLOR KEM keypair.
    // This is NOT a digital signature key.
    slor_pub_key: slor.SlorPublicKey,
    slor_sec_key_encrypted: slor.SlorSecretKey,
    slor_valid: bool,

    // GOV.2: Official governance signature key container.
    //
    // Important:
    // - Uses crypto/gov_sign.zig only.
    // - No slor_sign.zig dependency.
    // - If gov_sign backend is unavailable, this remains invalid.
    gov_sign_pub_key: gov_sign.PublicKey,
    gov_sign_sec_key_encrypted: gov_sign.SecretKey,
    gov_sign_valid: bool,
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
    credential_type: CredentialType,
    is_owner: bool,
    trust_hash: [32]u8,
    has_pin: bool,
    pin_encrypted: [32]u8,
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

    pub fn hasGovernanceSigningKey(self: *const Identity) bool {
        return self.keypair.gov_sign_valid;
    }

    pub fn getGovernancePublicKey(self: *const Identity) ?*const gov_sign.PublicKey {
        if (!self.keypair.gov_sign_valid) return null;
        return &self.keypair.gov_sign_pub_key;
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

var system_owner_idx: usize = 0;
var has_system_owner: bool = false;

var temp_key_buffer: [32]u8 = [_]u8{0} ** 32;
var temp_hash_buffer: [32]u8 = [_]u8{0} ** 32;
var kdf_work_buffer: [64]u8 = [_]u8{0} ** 64;

// GOV.2 secret-key encryption stream buffers.
var gov_stream_input: [40]u8 = [_]u8{0} ** 40;
var gov_stream_hash: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Initialization Helpers
// =============================================================================

fn clearSlorKemAt(id: *Identity) void {
    var i: usize = 0;

    while (i < slor.SLOR_N) : (i += 1) {
        id.keypair.slor_pub_key.t[i] = 0;
        id.keypair.slor_sec_key_encrypted.s[i] = 0;
    }

    i = 0;
    while (i < 32) : (i += 1) {
        id.keypair.slor_pub_key.seed[i] = 0;
    }

    id.keypair.slor_valid = false;
}

fn clearGovSignAt(id: *Identity) void {
    gov_sign.clearPublicKey(&id.keypair.gov_sign_pub_key);
    gov_sign.clearSecretKey(&id.keypair.gov_sign_sec_key_encrypted);
    id.keypair.gov_sign_valid = false;
}

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

    clearSlorKemAt(&identities[idx]);
    clearGovSignAt(&identities[idx]);
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

    constant_time.secureZero32(&temp_key_buffer);
    constant_time.secureZero32(&temp_hash_buffer);
    constant_time.secureZero(&kdf_work_buffer);
    constant_time.secureZero(&gov_stream_input);
    constant_time.secureZero32(&gov_stream_hash);

    initialized = true;
    debug("[KEYRING] Initialized\n");
}

// =============================================================================
// Identity Creation
// =============================================================================

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

    id.credential_type = detectCredentialType(credential);

    generateAndEncryptKeyPair(id, credential);
    generateAddress(id);
    generateTrustHash(id);

    id.has_pin = false;
    id.created_at = 1700000000;
    id.last_used = id.created_at;
    id.active = true;
    id.unlocked = false;

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

pub fn createIdentityWithPassword(name: []const u8, password: []const u8) ?*Identity {
    if (password.len < PASSWORD_MIN_LEN) return null;
    if (!isStrongPassword(password)) return null;

    const id = createIdentity(name, password);
    if (id != null) {
        id.?.credential_type = .password;
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
// Credential Validation
// =============================================================================

pub fn detectCredentialType(credential: []const u8) CredentialType {
    if (credential.len >= PIN_MIN_LEN and credential.len <= PIN_MAX_LEN) {
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

fn validateCredential(credential: []const u8) bool {
    if (credential.len < CREDENTIAL_MIN_LEN) return false;
    if (credential.len > CREDENTIAL_MAX_LEN) return false;
    return true;
}

pub fn looksLikePin(credential: []const u8) bool {
    if (credential.len < PIN_MIN_LEN or credential.len > PIN_MAX_LEN) return false;
    for (credential) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

pub fn isValidPin(pin: []const u8) bool {
    return looksLikePin(pin);
}

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

// =============================================================================
// Identity Field Generation
// =============================================================================

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
// KDF
// =============================================================================

fn deriveKeyFromCredentialWithRounds(
    credential: []const u8,
    salt: *const [16]u8,
    rounds: u32,
    out: *[32]u8,
) void {
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

    hash.sha256Into(&kdf_work_buffer, out);

    var round: u32 = 0;
    while (round < rounds) : (round += 1) {
        i = 0;
        while (i < 32) : (i += 1) kdf_work_buffer[i] = out[i];

        i = 0;
        while (i < 16) : (i += 1) kdf_work_buffer[32 + i] = salt[i];

        kdf_work_buffer[48] = @truncate(round);
        kdf_work_buffer[49] = @truncate(round >> 8);
        kdf_work_buffer[50] = @truncate(round >> 16);
        kdf_work_buffer[51] = @truncate(round >> 24);

        hash.sha256Into(kdf_work_buffer[0..52], out);
    }

    constant_time.secureZero(&kdf_work_buffer);
}

fn deriveKeyFromCredential(credential: []const u8, salt: *const [16]u8, out: *[32]u8) void {
    deriveKeyFromCredentialWithRounds(credential, salt, KDF_ROUNDS, out);
}

fn deriveKeyFromPin(pin: []const u8, salt: *const [16]u8, out: *[32]u8) void {
    deriveKeyFromCredentialWithRounds(pin, salt, KDF_ROUNDS_PIN, out);
}

// =============================================================================
// GOV.2 Governance Secret Encryption
// =============================================================================

fn streamMaskFromKey(key: *const [32]u8, block: u32, out: *[32]u8) void {
    var i: usize = 0;

    while (i < 32) : (i += 1) {
        gov_stream_input[i] = key[i];
    }

    gov_stream_input[32] = 'G';
    gov_stream_input[33] = 'O';
    gov_stream_input[34] = 'V';
    gov_stream_input[35] = 'S';

    gov_stream_input[36] = @truncate(block);
    gov_stream_input[37] = @truncate(block >> 8);
    gov_stream_input[38] = @truncate(block >> 16);
    gov_stream_input[39] = @truncate(block >> 24);

    hash.sha256Into(&gov_stream_input, out);
}

fn cryptGovSecret(
    input: *const gov_sign.SecretKey,
    key: *const [32]u8,
    output: *gov_sign.SecretKey,
) void {
    gov_sign.clearSecretKey(output);

    // Preserve every non-secret compatibility field. The raw secret-key bytes
    // alone are stream-XOR encrypted; sign() still requires exact backend and
    // parameter-set metadata after the key is restored into an auth session.
    output.len = input.len;
    output.valid = input.valid;
    output.backend = input.backend;
    output.parameter_set = input.parameter_set;

    // A malformed container must never become a valid session key.
    if (input.len > input.bytes.len or input.len > output.bytes.len) {
        gov_sign.clearSecretKey(output);
        constant_time.secureZero(&gov_stream_input);
        constant_time.secureZero32(&gov_stream_hash);
        return;
    }

    var block: u32 = 0;
    var pos: usize = 0;

    while (pos < input.len) {
        streamMaskFromKey(key, block, &gov_stream_hash);

        const remaining = input.len - pos;
        const block_len = @min(
            remaining,
            @as(usize, gov_stream_hash.len),
        );

        var j: usize = 0;
        while (j < block_len) : (j += 1) {
            output.bytes[pos + j] =
                input.bytes[pos + j] ^ gov_stream_hash[j];
        }

        pos += block_len;
        block +%= 1;
    }

    constant_time.secureZero(&gov_stream_input);
    constant_time.secureZero32(&gov_stream_hash);
}

fn generateGovernanceSigningKey(id: *Identity, identity_private_key: *const [32]u8) void {
    gov_sign.clearPublicKey(&id.keypair.gov_sign_pub_key);
    gov_sign.clearSecretKey(&id.keypair.gov_sign_sec_key_encrypted);
    id.keypair.gov_sign_valid = false;

    var pk = gov_sign.PublicKey{};
    var sk_plain = gov_sign.SecretKey{};

    const ok = gov_sign.generateKeyPair(
        gov_sign.DEFAULT_PARAMETER_SET,
        &pk,
        &sk_plain,
    );

    if (!ok) {
        // Production-safe behavior:
        // If ML-DSA/FIPS204 backend is unavailable, no governance signing key
        // is generated. GOV.2 signing remains fail-closed.
        gov_sign.clearPublicKey(&pk);
        gov_sign.clearSecretKey(&sk_plain);
        return;
    }

    id.keypair.gov_sign_pub_key = pk;

    cryptGovSecret(
        &sk_plain,
        identity_private_key,
        &id.keypair.gov_sign_sec_key_encrypted,
    );

    id.keypair.gov_sign_valid = true;

    gov_sign.clearSecretKey(&sk_plain);
}

pub fn decryptGovernanceSigningKeyWithPrivateKey(
    id: *const Identity,
    identity_private_key: *const [32]u8,
    out: *gov_sign.SecretKey,
) bool {
    gov_sign.clearSecretKey(out);

    if (!id.active) return false;
    if (!id.keypair.gov_sign_valid) return false;

    const encrypted = &id.keypair.gov_sign_sec_key_encrypted;

    if (!encrypted.valid) return false;
    if (encrypted.len != gov_sign.SECRET_KEY_BYTES) return false;
    if (encrypted.backend != gov_sign.DEFAULT_BACKEND) return false;
    if (encrypted.parameter_set != gov_sign.DEFAULT_PARAMETER_SET) {
        return false;
    }

    cryptGovSecret(
        encrypted,
        identity_private_key,
        out,
    );

    const valid =
        out.valid and
        out.len == gov_sign.SECRET_KEY_BYTES and
        out.backend == gov_sign.DEFAULT_BACKEND and
        out.parameter_set == gov_sign.DEFAULT_PARAMETER_SET;

    if (!valid) {
        gov_sign.clearSecretKey(out);
        return false;
    }

    return true;
}

pub fn hasGovernanceSigningKey(id: *const Identity) bool {
    return id.keypair.gov_sign_valid;
}

pub fn getGovernancePublicKey(id: *const Identity) ?*const gov_sign.PublicKey {
    if (!id.keypair.gov_sign_valid) return null;
    return &id.keypair.gov_sign_pub_key;
}

// =============================================================================
// Key Generation
// =============================================================================

fn generateAndEncryptKeyPair(id: *Identity, credential: []const u8) void {
    debug("[KEYRING] generateKeyPair\n");

    crypto.random.getBytes(&id.keypair.salt);
    crypto.random.getBytes(&temp_key_buffer);

    hash.sha256Into(&temp_key_buffer, &id.keypair.public_key);
    deriveKeyFromCredential(credential, &id.keypair.salt, &temp_hash_buffer);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] = temp_key_buffer[i] ^ temp_hash_buffer[i];
    }

    while (i < 48) : (i += 1) {
        id.keypair.private_key_encrypted[i] = 0;
    }

    id.keypair.valid = true;

    // H.10: SLOR KEM keypair.
    slor.generateKeyPair(&id.keypair.slor_pub_key, &id.keypair.slor_sec_key_encrypted);
    id.keypair.slor_valid = true;

    // GOV.2: Production governance signature key.
    // This will only generate if gov_sign backend is available.
    generateGovernanceSigningKey(id, &temp_key_buffer);

    constant_time.secureZero32(&temp_key_buffer);
    constant_time.secureZero32(&temp_hash_buffer);
}

// =============================================================================
// PIN Management
// =============================================================================

pub fn setupSecondaryPin(id: *Identity, password: []const u8, pin: []const u8) bool {
    if (!id.active or !id.keypair.valid) return false;
    if (!isValidPin(pin)) return false;

    var privkey: [32]u8 = [_]u8{0} ** 32;
    if (!decryptPrivateKey(id, password, &privkey)) return false;

    crypto.random.getBytes(&id.pin_salt);

    var pin_key: [32]u8 = [_]u8{0} ** 32;
    deriveKeyFromPin(pin, &id.pin_salt, &pin_key);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.pin_encrypted[i] = privkey[i] ^ pin_key[i];
    }

    id.has_pin = true;

    constant_time.secureZero32(&privkey);
    constant_time.secureZero32(&pin_key);
    return true;
}

pub fn removeSecondaryPin(id: *Identity, password: []const u8) bool {
    if (!id.has_pin) return true;

    var privkey: [32]u8 = [_]u8{0} ** 32;
    if (!decryptPrivateKey(id, password, &privkey)) return false;
    constant_time.secureZero32(&privkey);

    id.has_pin = false;
    constant_time.secureZero32(&id.pin_encrypted);
    constant_time.secureZero(&id.pin_salt);
    return true;
}

pub fn changeSecondaryPin(id: *Identity, password: []const u8, new_pin: []const u8) bool {
    if (!removeSecondaryPin(id, password)) return false;
    return setupSecondaryPin(id, password, new_pin);
}

pub fn decryptPrivateKeyWithPin(id: *Identity, pin: []const u8, out: *[32]u8) bool {
    if (!id.has_pin or !id.keypair.valid or !isValidPin(pin)) return false;

    var pin_key: [32]u8 = [_]u8{0} ** 32;
    deriveKeyFromPin(pin, &id.pin_salt, &pin_key);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = id.pin_encrypted[i] ^ pin_key[i];
    }

    var verify_pubkey: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(out, &verify_pubkey);

    const valid = constant_time.constantTimeCompare32(&verify_pubkey, &id.keypair.public_key);
    if (!valid) constant_time.secureZero32(out);

    constant_time.secureZero32(&pin_key);
    constant_time.secureZero32(&verify_pubkey);
    return valid;
}

// =============================================================================
// Trust Hash
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
    while (d < domain.len) : (d += 1) kdf_work_buffer[36 + d] = domain[d];

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
    while (d < domain.len) : (d += 1) work[36 + d] = domain[d];

    hash.sha256Into(work[0 .. 36 + domain.len], &expected);

    const result = constant_time.constantTimeCompare32(&expected, &id.trust_hash);

    constant_time.secureZero(&work);
    constant_time.secureZero32(&intermediate);
    constant_time.secureZero32(&expected);

    return result;
}

// =============================================================================
// Lookup
// =============================================================================

pub fn findIdentity(name: []const u8) ?*Identity {
    var i: usize = 0;
    while (i < identity_count) : (i += 1) {
        if (!identities[i].active or !identities[i].has_name) continue;
        if (namesMatch(identities[i].getName(), name)) return &identities[i];
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

pub fn getIdentityByIndex(index: usize) ?*Identity {
    if (index >= identity_count or !identities[index].active) return null;
    return &identities[index];
}

pub fn getCurrentIdentity() ?*Identity {
    if (!has_current_identity or current_identity_idx >= identity_count) return null;
    return &identities[current_identity_idx];
}

pub fn setCurrentIdentity(name: []const u8) bool {
    var i: usize = 0;

    while (i < identity_count) : (i += 1) {
        if (identities[i].active and identities[i].has_name and namesMatch(identities[i].getName(), name)) {
            current_identity_idx = i;
            has_current_identity = true;
            return true;
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
        if (identities[i].active and identities[i].has_name and namesMatch(identities[i].getName(), name)) {
            clearIdentityAt(i);
            return true;
        }
    }

    return false;
}

pub fn getSystemOwner() ?*Identity {
    if (!has_system_owner or system_owner_idx >= identity_count or !identities[system_owner_idx].active) return null;
    return &identities[system_owner_idx];
}

pub fn isSystemOwner(id: *const Identity) bool {
    return id.is_owner;
}

// =============================================================================
// Private Key Handling
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
    if (!valid) constant_time.secureZero32(out);

    constant_time.secureZero32(&temp_hash_buffer);
    constant_time.secureZero32(&verify_pubkey);

    return valid;
}

pub fn reEncryptPrivateKey(id: *Identity, old_credential: []const u8, new_credential: []const u8) bool {
    var privkey: [32]u8 = [_]u8{0} ** 32;
    if (!decryptPrivateKey(id, old_credential, &privkey)) return false;

    crypto.random.getBytes(&id.keypair.salt);
    deriveKeyFromCredential(new_credential, &id.keypair.salt, &temp_hash_buffer);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        id.keypair.private_key_encrypted[i] = privkey[i] ^ temp_hash_buffer[i];
    }

    id.credential_type = detectCredentialType(new_credential);

    if (id.has_pin) {
        id.has_pin = false;
        constant_time.secureZero32(&id.pin_encrypted);
        constant_time.secureZero(&id.pin_salt);
    }

    // GOV signing secret is encrypted under identity private key, not password.
    // Password change does not require GOV key re-encryption.

    constant_time.secureZero32(&privkey);
    constant_time.secureZero32(&temp_hash_buffer);
    return true;
}

// =============================================================================
// Store Helpers
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getSlotPtr(index: usize) ?*Identity {
    if (index >= MAX_IDENTITIES) return null;
    return &identities[index];
}

pub fn setIdentityCount(count: usize) void {
    if (count <= MAX_IDENTITIES) identity_count = count;
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
// Test
// =============================================================================

pub fn test_keyring() bool {
    serial.writeString("\n=== Keyring Test (H.7.1, H.10, GOV.2 production boundary) ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    init();
    passed += 1;

    const id = createIdentityWithPassword("alice", "SecurePass1");

    if (id != null and identity_count == 1) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 16: SLOR KEM KeyPair generated\n");
    if (id != null and id.?.keypair.slor_valid) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 17: GOV signing backend policy\n");
    if (gov_sign.isProductionBackendAvailable()) {
        if (id != null and id.?.keypair.gov_sign_valid) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        if (id != null and !id.?.keypair.gov_sign_valid) {
            serial.writeString("    OK (fail-closed)\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
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
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
