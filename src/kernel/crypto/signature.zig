//! Zamrud OS - Digital Signatures (HARDENED)
//! HMAC-SHA256 based (pure software, no SIMD)
//!
//! H.1 FIXES:
//! ✅ FIX #1: HMAC handles messages up to 4096 bytes (was truncated at 64)
//! ✅ FIX #2: verify() uses constant-time comparisons throughout
//! ✅ FIX #3: All secret comparisons use constant_time module
//! ✅ FIX #4: Secure zeroing of intermediate buffers

const serial = @import("../drivers/serial/serial.zig");
const random = @import("random.zig");
const hash = @import("hash.zig");
const ct = @import("constant_time.zig");

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 64;
pub const SEED_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

// Static buffers for key generation
var static_seed: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_hmac_key: [64]u8 = [_]u8{0} ** 64;
var static_hash_result: [32]u8 = [_]u8{0} ** 32;
var static_inner_hash: [32]u8 = [_]u8{0} ** 32;
var static_sig1: [32]u8 = [_]u8{0} ** 32;
var static_sig2: [32]u8 = [_]u8{0} ** 32;
var static_msg_hash: [32]u8 = [_]u8{0} ** 32;
var static_secret_hash: [32]u8 = [_]u8{0} ** 32;
var static_public_hash: [32]u8 = [_]u8{0} ** 32;
var static_sig_result: [SIGNATURE_SIZE]u8 = [_]u8{0} ** SIGNATURE_SIZE;
var static_kp_secret: [SECRET_KEY_SIZE]u8 = [_]u8{0} ** SECRET_KEY_SIZE;
var static_kp_public: [PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** PUBLIC_KEY_SIZE;

// Separate buffer for verification
var static_verify_sig: [SIGNATURE_SIZE]u8 = [_]u8{0} ** SIGNATURE_SIZE;

// Test buffers
var static_test_seed: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_test_pub1: [PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** PUBLIC_KEY_SIZE;

// FIX #1: HMAC buffers large enough for any message
const HMAC_BUF_SIZE: usize = 64 + 4096;
var static_hmac_inner_buf: [HMAC_BUF_SIZE]u8 = [_]u8{0} ** HMAC_BUF_SIZE;
var static_hmac_outer_buf: [96]u8 = [_]u8{0} ** 96; // key_pad(64) + hash(32)

// =============================================================================
// KeyPair Generation
// =============================================================================

pub const KeyPair = struct {
    pub fn getSecretKey() *[SECRET_KEY_SIZE]u8 {
        return &static_kp_secret;
    }

    pub fn getPublicKey() *[PUBLIC_KEY_SIZE]u8 {
        return &static_kp_public;
    }

    pub fn generate() void {
        var i: usize = 0;
        while (i < SEED_SIZE) : (i += 1) {
            static_seed[i] = 0;
        }
        random.getBytes(&static_seed);
        fromSeedSlice(&static_seed);
    }

    pub fn fromSeed(seed: [SEED_SIZE]u8) void {
        var i: usize = 0;
        while (i < SEED_SIZE) : (i += 1) {
            static_seed[i] = seed[i];
        }
        fromSeedSlice(&static_seed);
    }

    pub fn fromSeedSlice(seed_ptr: *const [SEED_SIZE]u8) void {
        // FIX #4: Secure zero before use
        ct.secureZero64(&static_kp_secret);
        ct.secureZero32(&static_kp_public);

        // Derive secret key: SHA256(seed || "secret")
        var derive_buf: [38]u8 = [_]u8{0} ** 38;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            derive_buf[i] = seed_ptr[i];
        }
        derive_buf[32] = 's';
        derive_buf[33] = 'e';
        derive_buf[34] = 'c';
        derive_buf[35] = 'r';
        derive_buf[36] = 'e';
        derive_buf[37] = 't';

        hash.sha256Into(&derive_buf, &static_secret_hash);

        // Derive public key: SHA256(secret_hash || "public")
        i = 0;
        while (i < 32) : (i += 1) {
            derive_buf[i] = static_secret_hash[i];
        }
        derive_buf[32] = 'p';
        derive_buf[33] = 'u';
        derive_buf[34] = 'b';
        derive_buf[35] = 'l';
        derive_buf[36] = 'i';
        derive_buf[37] = 'c';

        hash.sha256Into(&derive_buf, &static_public_hash);

        // Build keypair
        i = 0;
        while (i < 32) : (i += 1) {
            static_kp_secret[i] = static_secret_hash[i];
            static_kp_secret[i + 32] = seed_ptr[i];
            static_kp_public[i] = static_public_hash[i];
        }

        // FIX #4: Clean up intermediates
        ct.secureZero(&derive_buf);
        ct.secureZero32(&static_secret_hash);
        ct.secureZero32(&static_public_hash);
    }

    pub fn sign(message: []const u8) *const [SIGNATURE_SIZE]u8 {
        signInto(message, &static_sig_result);
        return &static_sig_result;
    }

    pub fn isValid() bool {
        // FIX #3: Constant-time zero check
        return !ct.constantTimeIsZero32(&static_kp_public);
    }
};

// =============================================================================
// HMAC-SHA256 — FIXED for arbitrary message length
// =============================================================================

/// FIX #1: Properly handles messages of ANY length (up to 4096 bytes)
fn hmacSha256(key: []const u8, message: []const u8, out: *[32]u8) void {
    var i: usize = 0;

    // Prepare key (pad or hash to 64 bytes)
    ct.secureZero64(&static_hmac_key);

    if (key.len <= 64) {
        i = 0;
        while (i < key.len) : (i += 1) {
            static_hmac_key[i] = key[i];
        }
    } else {
        hash.sha256Into(key, &static_hash_result);
        i = 0;
        while (i < 32) : (i += 1) {
            static_hmac_key[i] = static_hash_result[i];
        }
    }

    // Clamp message to buffer capacity
    const msg_len = if (message.len > 4096) @as(usize, 4096) else message.len;

    // INNER: SHA256((key XOR ipad) || message)
    i = 0;
    while (i < 64) : (i += 1) {
        static_hmac_inner_buf[i] = static_hmac_key[i] ^ 0x36;
    }
    i = 0;
    while (i < msg_len) : (i += 1) {
        static_hmac_inner_buf[64 + i] = message[i];
    }

    hash.sha256Into(static_hmac_inner_buf[0 .. 64 + msg_len], &static_inner_hash);

    // OUTER: SHA256((key XOR opad) || inner_hash)
    i = 0;
    while (i < 64) : (i += 1) {
        static_hmac_outer_buf[i] = static_hmac_key[i] ^ 0x5c;
    }
    i = 0;
    while (i < 32) : (i += 1) {
        static_hmac_outer_buf[64 + i] = static_inner_hash[i];
    }

    hash.sha256Into(static_hmac_outer_buf[0..96], out);

    // FIX #4: Clean up
    ct.secureZero(static_hmac_inner_buf[0 .. 64 + msg_len]);
    ct.secureZero(static_hmac_outer_buf[0..96]);
    ct.secureZero32(&static_inner_hash);
}

// =============================================================================
// Internal Sign Function
// =============================================================================

fn signInto(message: []const u8, out: *[SIGNATURE_SIZE]u8) void {
    // sig1 = HMAC(secret[0..32], message)
    hmacSha256(static_kp_secret[0..32], message, &static_sig1);

    // msg_hash = SHA256(message)
    hash.sha256Into(message, &static_msg_hash);

    // sig2 = HMAC(secret[32..64], sig1 || msg_hash)
    var combined: [64]u8 = [_]u8{0} ** 64;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        combined[i] = static_sig1[i];
        combined[i + 32] = static_msg_hash[i];
    }

    hmacSha256(static_kp_secret[32..64], &combined, &static_sig2);

    // Final signature = sig1 || sig2
    i = 0;
    while (i < 32) : (i += 1) {
        out[i] = static_sig1[i];
        out[i + 32] = static_sig2[i];
    }

    // FIX #4: Clean up
    ct.secureZero(&combined);
    ct.secureZero32(&static_sig1);
    ct.secureZero32(&static_sig2);
    ct.secureZero32(&static_msg_hash);
}

// =============================================================================
// Signature Verification — FULLY CONSTANT TIME
// =============================================================================

/// FIX #2: Constant-time verification throughout
pub fn verify(
    public_key: *const [PUBLIC_KEY_SIZE]u8,
    message: []const u8,
    sig_bytes: *const [SIGNATURE_SIZE]u8,
) bool {
    // FIX #2: All checks are constant-time (no early returns on secrets)
    const sig_is_zero = ct.constantTimeIsZero64(sig_bytes);
    const pk_is_zero = ct.constantTimeIsZero32(public_key);
    const pk_matches = ct.constantTimeCompare32(public_key, &static_kp_public);

    if (!pk_matches) {
        // Unknown signer — do dummy work to keep timing constant
        signInto(message, &static_verify_sig);
        ct.secureZero64(&static_verify_sig);
        return false;
    }

    // Re-sign to get expected signature
    signInto(message, &static_verify_sig);

    // FIX #2: Constant-time signature comparison
    const sig_matches = ct.constantTimeCompare64(sig_bytes, &static_verify_sig);

    // Clean up
    ct.secureZero64(&static_verify_sig);

    // All conditions must pass
    return (!sig_is_zero) and (!pk_is_zero) and pk_matches and sig_matches;
}

// =============================================================================
// Tests — 8 tests
// =============================================================================

pub fn test_signature() bool {
    serial.writeString("[CRYPTO] Testing signatures (HARDENED)...\n");

    serial.writeString("  Generating key pair...\n");
    KeyPair.generate();

    if (!KeyPair.isValid()) {
        serial.writeString("  ERROR: Invalid key!\n");
        return false;
    }

    serial.writeString("  Public key: ");
    printBytes(KeyPair.getPublicKey(), 8);
    serial.writeString("...\n");

    // Test 1: Basic sign & verify
    const message = "Hello, Zamrud OS!";
    serial.writeString("  Signing message...\n");
    const sig = KeyPair.sign(message);

    if (ct.constantTimeIsZero(sig)) {
        serial.writeString("  ERROR: Signature is zeros!\n");
        return false;
    }

    serial.writeString("  Signature: ");
    printBytes(sig, 16);
    serial.writeString("...\n");

    serial.writeString("  [1] Verify correct: ");
    if (verify(KeyPair.getPublicKey(), message, sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 2: Wrong message
    serial.writeString("  [2] Reject wrong message: ");
    if (!verify(KeyPair.getPublicKey(), "Wrong message!", sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 3: Bad signature
    serial.writeString("  [3] Reject bad signature: ");
    var bad_sig: [SIGNATURE_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < SIGNATURE_SIZE) : (i += 1) {
        bad_sig[i] = sig[i];
    }
    bad_sig[0] ^= 0xFF;
    if (!verify(KeyPair.getPublicKey(), message, &bad_sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 4: Zero signature
    serial.writeString("  [4] Reject zero sig: ");
    var zero_sig: [SIGNATURE_SIZE]u8 = [_]u8{0} ** SIGNATURE_SIZE;
    if (!verify(KeyPair.getPublicKey(), message, &zero_sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 5: Zero public key
    serial.writeString("  [5] Reject zero pubkey: ");
    var zero_pk: [PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** PUBLIC_KEY_SIZE;
    if (!verify(&zero_pk, message, sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 6: *** CRITICAL — Long message (>64 bytes) ***
    serial.writeString("  [6] Long message (>64B): ");
    const long_msg = "This is a message that is definitely longer than sixty-four bytes to test the HMAC fix for truncation!";
    const long_sig = KeyPair.sign(long_msg);

    if (verify(KeyPair.getPublicKey(), long_msg, long_sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    // Test 7: *** Different suffixes must produce different signatures ***
    serial.writeString("  [7] Long msg diff suffix: ");
    const long_a = "This is a long message where only the end differs: version_AAAAAA";
    const long_b = "This is a long message where only the end differs: version_BBBBBB";
    const sig_a = KeyPair.sign(long_a);

    var sig_a_copy: [SIGNATURE_SIZE]u8 = undefined;
    i = 0;
    while (i < SIGNATURE_SIZE) : (i += 1) {
        sig_a_copy[i] = sig_a[i];
    }

    const sig_b = KeyPair.sign(long_b);
    if (!ct.constantTimeCompare64(&sig_a_copy, sig_b)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL (truncation bug!)\n");
        return false;
    }

    // Test 8: Deterministic keygen
    serial.writeString("  [8] Deterministic keygen: ");
    i = 0;
    while (i < SEED_SIZE) : (i += 1) {
        static_test_seed[i] = 0;
    }
    random.getBytes(&static_test_seed);

    KeyPair.fromSeedSlice(&static_test_seed);
    i = 0;
    while (i < PUBLIC_KEY_SIZE) : (i += 1) {
        static_test_pub1[i] = KeyPair.getPublicKey()[i];
    }

    KeyPair.fromSeedSlice(&static_test_seed);
    if (ct.constantTimeCompare32(&static_test_pub1, KeyPair.getPublicKey())) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    serial.writeString("  Signature test: OK (8/8 passed)\n");
    return true;
}

fn printBytes(data: []const u8, max: usize) void {
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        serial.writeChar(hex_chars[data[i] >> 4]);
        serial.writeChar(hex_chars[data[i] & 0xF]);
    }
}
