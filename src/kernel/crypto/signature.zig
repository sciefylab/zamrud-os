//! Zamrud OS - Digital Signatures
//! HMAC-SHA256 based (pure software, no SIMD)

const serial = @import("../drivers/serial/serial.zig");
const random = @import("random.zig");
const hash = @import("hash.zig");

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 64;
pub const SEED_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

// Static buffers for key generation
var static_seed: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_hmac_key: [64]u8 = [_]u8{0} ** 64;
var static_hmac_buf: [128]u8 = [_]u8{0} ** 128;
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

// Separate buffer for verification (prevents overwrite)
var static_verify_sig: [SIGNATURE_SIZE]u8 = [_]u8{0} ** SIGNATURE_SIZE;

// Static buffers for test
var static_test_seed: [SEED_SIZE]u8 = [_]u8{0} ** SEED_SIZE;
var static_test_pub1: [PUBLIC_KEY_SIZE]u8 = [_]u8{0} ** PUBLIC_KEY_SIZE;

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
        var i: usize = 0;

        // Clear keypair buffers
        while (i < SECRET_KEY_SIZE) : (i += 1) {
            static_kp_secret[i] = 0;
        }
        i = 0;
        while (i < PUBLIC_KEY_SIZE) : (i += 1) {
            static_kp_public[i] = 0;
        }

        // Derive secret key: SHA256(seed || "secret")
        i = 0;
        while (i < 32) : (i += 1) {
            static_hmac_buf[i] = seed_ptr[i];
        }
        static_hmac_buf[32] = 's';
        static_hmac_buf[33] = 'e';
        static_hmac_buf[34] = 'c';
        static_hmac_buf[35] = 'r';
        static_hmac_buf[36] = 'e';
        static_hmac_buf[37] = 't';

        hash.sha256Into(static_hmac_buf[0..38], &static_secret_hash);

        // Derive public key: SHA256(secret_hash || "public")
        i = 0;
        while (i < 32) : (i += 1) {
            static_hmac_buf[i] = static_secret_hash[i];
        }
        static_hmac_buf[32] = 'p';
        static_hmac_buf[33] = 'u';
        static_hmac_buf[34] = 'b';
        static_hmac_buf[35] = 'l';
        static_hmac_buf[36] = 'i';
        static_hmac_buf[37] = 'c';

        hash.sha256Into(static_hmac_buf[0..38], &static_public_hash);

        // Build keypair
        i = 0;
        while (i < 32) : (i += 1) {
            static_kp_secret[i] = static_secret_hash[i];
            static_kp_secret[i + 32] = seed_ptr[i];
            static_kp_public[i] = static_public_hash[i];
        }
    }

    pub fn sign(message: []const u8) *const [SIGNATURE_SIZE]u8 {
        signInto(message, &static_sig_result);
        return &static_sig_result;
    }

    pub fn isValid() bool {
        var i: usize = 0;
        while (i < PUBLIC_KEY_SIZE) : (i += 1) {
            if (static_kp_public[i] != 0) return true;
        }
        return false;
    }
};

// =============================================================================
// Internal Sign Function (writes to provided buffer)
// =============================================================================

fn signInto(message: []const u8, out: *[SIGNATURE_SIZE]u8) void {
    var i: usize = 0;

    // Clear output
    while (i < SIGNATURE_SIZE) : (i += 1) {
        out[i] = 0;
    }

    // sig1 = HMAC(secret_key[0..32], message)
    hmacSha256(static_kp_secret[0..32], message, &static_sig1);

    // msg_hash = SHA256(message)
    hash.sha256Into(message, &static_msg_hash);

    // Combine sig1 || msg_hash
    i = 0;
    while (i < 32) : (i += 1) {
        static_hmac_buf[i] = static_sig1[i];
        static_hmac_buf[i + 32] = static_msg_hash[i];
    }

    // sig2 = HMAC(secret_key[32..64], sig1 || msg_hash)
    hmacSha256(static_kp_secret[32..64], static_hmac_buf[0..64], &static_sig2);

    // Final signature = sig1 || sig2
    i = 0;
    while (i < 32) : (i += 1) {
        out[i] = static_sig1[i];
        out[i + 32] = static_sig2[i];
    }
}

// =============================================================================
// HMAC-SHA256 Implementation
// =============================================================================

fn hmacSha256(key: []const u8, message: []const u8, out: *[32]u8) void {
    var i: usize = 0;

    // Prepare key
    while (i < 64) : (i += 1) {
        static_hmac_key[i] = 0;
    }

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

    // Inner: SHA256((key XOR ipad) || message)
    i = 0;
    while (i < 64) : (i += 1) {
        static_hmac_buf[i] = static_hmac_key[i] ^ 0x36;
    }

    const msg_len = if (message.len > 64) 64 else message.len;
    i = 0;
    while (i < msg_len) : (i += 1) {
        static_hmac_buf[64 + i] = message[i];
    }

    hash.sha256Into(static_hmac_buf[0 .. 64 + msg_len], &static_inner_hash);

    // Outer: SHA256((key XOR opad) || inner_hash)
    i = 0;
    while (i < 64) : (i += 1) {
        static_hmac_buf[i] = static_hmac_key[i] ^ 0x5c;
    }

    i = 0;
    while (i < 32) : (i += 1) {
        static_hmac_buf[64 + i] = static_inner_hash[i];
    }

    hash.sha256Into(static_hmac_buf[0..96], out);
}

// =============================================================================
// Signature Verification
// =============================================================================

/// Verify signature
/// Returns true only if signature matches the message AND was created by the keypair
pub fn verify(
    public_key: *const [PUBLIC_KEY_SIZE]u8,
    message: []const u8,
    sig_bytes: *const [SIGNATURE_SIZE]u8,
) bool {
    var i: usize = 0;

    // Check for null/zero signature
    var sig_all_zero = true;
    i = 0;
    while (i < SIGNATURE_SIZE) : (i += 1) {
        if (sig_bytes[i] != 0) {
            sig_all_zero = false;
            break;
        }
    }
    if (sig_all_zero) return false;

    // Check for null/zero public key
    var pk_all_zero = true;
    i = 0;
    while (i < PUBLIC_KEY_SIZE) : (i += 1) {
        if (public_key[i] != 0) {
            pk_all_zero = false;
            break;
        }
    }
    if (pk_all_zero) return false;

    // Check if public key matches current keypair
    var pk_matches = true;
    i = 0;
    while (i < PUBLIC_KEY_SIZE) : (i += 1) {
        if (public_key[i] != static_kp_public[i]) {
            pk_matches = false;
            break;
        }
    }

    if (!pk_matches) {
        // Unknown signer - cannot verify without secret key
        return false;
    }

    // We have the matching keypair - re-sign into SEPARATE buffer
    signInto(message, &static_verify_sig);

    // Compare byte-by-byte
    i = 0;
    while (i < SIGNATURE_SIZE) : (i += 1) {
        if (sig_bytes[i] != static_verify_sig[i]) {
            return false; // Signature mismatch - wrong message or tampered
        }
    }

    return true; // Valid signature for this message
}

// =============================================================================
// Testing
// =============================================================================

pub fn test_signature() bool {
    serial.writeString("[CRYPTO] Testing signatures...\n");

    serial.writeString("  Generating key pair...\n");
    KeyPair.generate();

    if (!KeyPair.isValid()) {
        serial.writeString("  ERROR: Invalid key!\n");
        return false;
    }

    serial.writeString("  Public key: ");
    printBytes(KeyPair.getPublicKey(), 8);
    serial.writeString("...\n");

    const message = "Hello, Zamrud OS!";
    serial.writeString("  Signing message...\n");
    const sig = KeyPair.sign(message);

    var all_zero = true;
    var i: usize = 0;
    while (i < SIGNATURE_SIZE) : (i += 1) {
        if (sig[i] != 0) {
            all_zero = false;
            break;
        }
    }

    if (all_zero) {
        serial.writeString("  ERROR: Signature is zeros!\n");
        return false;
    }

    serial.writeString("  Signature: ");
    printBytes(sig, 16);
    serial.writeString("...\n");

    serial.writeString("  Verify correct: ");
    if (verify(KeyPair.getPublicKey(), message, sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    serial.writeString("  Reject wrong message: ");
    if (!verify(KeyPair.getPublicKey(), "Wrong message!", sig)) {
        serial.writeString("PASS\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    serial.writeString("  Reject bad signature: ");
    var bad_sig: [SIGNATURE_SIZE]u8 = undefined;
    i = 0;
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

    serial.writeString("  Deterministic keygen: ");

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

    if (bytesEqual(&static_test_pub1, KeyPair.getPublicKey())) {
        serial.writeString("OK\n");
    } else {
        serial.writeString("FAIL\n");
        return false;
    }

    serial.writeString("  Signature test: OK\n");
    return true;
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn printBytes(data: []const u8, max: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        serial.writeChar(hex[data[i] >> 4]);
        serial.writeChar(hex[data[i] & 0xF]);
    }
}
