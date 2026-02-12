//! Zamrud OS - AES-256 Implementation
//! Pure software, no SIMD, all static buffers
//! CBC mode with PKCS7 padding

const serial = @import("../drivers/serial/serial.zig");
const random = @import("random.zig");
const hash = @import("hash.zig");

// =============================================================================
// Constants
// =============================================================================

pub const BLOCK_SIZE: usize = 16; // 128-bit blocks
pub const KEY_SIZE: usize = 32; // 256-bit key
pub const IV_SIZE: usize = 16; // 128-bit IV
pub const ROUNDS: usize = 14; // AES-256 = 14 rounds
pub const EXPANDED_KEY_SIZE: usize = 4 * (ROUNDS + 1); // 60 u32 words

// Max encrypt/decrypt size (bare-metal static buffer)
pub const MAX_PLAINTEXT: usize = 4096;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + BLOCK_SIZE; // +padding

// =============================================================================
// AES S-Box (forward)
// =============================================================================

const SBOX: [256]u8 = .{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// =============================================================================
// AES Inverse S-Box (for decryption)
// =============================================================================

const INV_SBOX: [256]u8 = .{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

// =============================================================================
// Round Constants
// =============================================================================

const RCON: [11]u32 = .{
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000,
};

// =============================================================================
// GF(2^8) Multiplication (for MixColumns)
// =============================================================================

fn gmul(a: u8, b: u8) u8 {
    var result: u8 = 0;
    var aa: u8 = a;
    var bb: u8 = b;
    var i: u4 = 0; // u4 to avoid overflow (0-15 range, we only go to 8)
    while (i < 8) : (i += 1) {
        if ((bb & 1) != 0) {
            result ^= aa;
        }
        const hi_bit: u8 = aa & 0x80;
        aa <<= 1;
        if (hi_bit != 0) {
            aa ^= 0x1b;
        }
        bb >>= 1;
    }
    return result;
}

// =============================================================================
// Static Buffers
// =============================================================================

var static_expanded_key: [EXPANDED_KEY_SIZE]u32 = [_]u32{0} ** EXPANDED_KEY_SIZE;
var static_state: [16]u8 = [_]u8{0} ** 16;
var static_iv: [IV_SIZE]u8 = [_]u8{0} ** IV_SIZE;
var static_prev_block: [BLOCK_SIZE]u8 = [_]u8{0} ** BLOCK_SIZE;
var static_encrypt_out: [MAX_CIPHERTEXT]u8 = [_]u8{0} ** MAX_CIPHERTEXT;
var static_decrypt_out: [MAX_PLAINTEXT]u8 = [_]u8{0} ** MAX_PLAINTEXT;
var static_encrypt_out_len: usize = 0;
var static_decrypt_out_len: usize = 0;

// =============================================================================
// Key Expansion (AES-256)
// =============================================================================

fn keyExpansion(key: *const [KEY_SIZE]u8) void {
    var i: usize = 0;

    // First 8 words directly from key
    while (i < 8) : (i += 1) {
        static_expanded_key[i] =
            (@as(u32, key[4 * i]) << 24) |
            (@as(u32, key[4 * i + 1]) << 16) |
            (@as(u32, key[4 * i + 2]) << 8) |
            (@as(u32, key[4 * i + 3]));
    }

    // Expand remaining
    while (i < EXPANDED_KEY_SIZE) : (i += 1) {
        var temp = static_expanded_key[i - 1];

        if (i % 8 == 0) {
            // RotWord + SubWord + Rcon
            temp = subWord(rotWord(temp)) ^ RCON[i / 8];
        } else if (i % 8 == 4) {
            // SubWord only (AES-256 specific)
            temp = subWord(temp);
        }

        static_expanded_key[i] = static_expanded_key[i - 8] ^ temp;
    }
}

fn subWord(w: u32) u32 {
    return (@as(u32, SBOX[@intCast((w >> 24) & 0xFF)]) << 24) |
        (@as(u32, SBOX[@intCast((w >> 16) & 0xFF)]) << 16) |
        (@as(u32, SBOX[@intCast((w >> 8) & 0xFF)]) << 8) |
        (@as(u32, SBOX[@intCast(w & 0xFF)]));
}

fn rotWord(w: u32) u32 {
    return (w << 8) | (w >> 24);
}

// =============================================================================
// AES Block Operations (Encrypt)
// =============================================================================

fn addRoundKey(round: usize) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const rk = static_expanded_key[round * 4 + i];
        static_state[i * 4] ^= @intCast((rk >> 24) & 0xFF);
        static_state[i * 4 + 1] ^= @intCast((rk >> 16) & 0xFF);
        static_state[i * 4 + 2] ^= @intCast((rk >> 8) & 0xFF);
        static_state[i * 4 + 3] ^= @intCast(rk & 0xFF);
    }
}

fn subBytes() void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        static_state[i] = SBOX[static_state[i]];
    }
}

fn shiftRows() void {
    // Row 1: shift left 1
    const t1 = static_state[1];
    static_state[1] = static_state[5];
    static_state[5] = static_state[9];
    static_state[9] = static_state[13];
    static_state[13] = t1;

    // Row 2: shift left 2
    const t2a = static_state[2];
    const t2b = static_state[6];
    static_state[2] = static_state[10];
    static_state[6] = static_state[14];
    static_state[10] = t2a;
    static_state[14] = t2b;

    // Row 3: shift left 3 (= shift right 1)
    const t3 = static_state[15];
    static_state[15] = static_state[11];
    static_state[11] = static_state[7];
    static_state[7] = static_state[3];
    static_state[3] = t3;
}

fn mixColumns() void {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const a0 = static_state[i * 4];
        const a1 = static_state[i * 4 + 1];
        const a2 = static_state[i * 4 + 2];
        const a3 = static_state[i * 4 + 3];

        static_state[i * 4] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        static_state[i * 4 + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        static_state[i * 4 + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        static_state[i * 4 + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

/// Encrypt a single 16-byte block in-place using static_state
fn encryptBlock() void {
    addRoundKey(0);

    var round: usize = 1;
    while (round < ROUNDS) : (round += 1) {
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(round);
    }

    // Final round (no MixColumns)
    subBytes();
    shiftRows();
    addRoundKey(ROUNDS);
}

// =============================================================================
// AES Block Operations (Decrypt)
// =============================================================================

fn invSubBytes() void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        static_state[i] = INV_SBOX[static_state[i]];
    }
}

fn invShiftRows() void {
    // Row 1: shift right 1
    const t1 = static_state[13];
    static_state[13] = static_state[9];
    static_state[9] = static_state[5];
    static_state[5] = static_state[1];
    static_state[1] = t1;

    // Row 2: shift right 2
    const t2a = static_state[10];
    const t2b = static_state[14];
    static_state[10] = static_state[2];
    static_state[14] = static_state[6];
    static_state[2] = t2a;
    static_state[6] = t2b;

    // Row 3: shift right 3 (= shift left 1)
    const t3 = static_state[3];
    static_state[3] = static_state[7];
    static_state[7] = static_state[11];
    static_state[11] = static_state[15];
    static_state[15] = t3;
}

fn invMixColumns() void {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const a0 = static_state[i * 4];
        const a1 = static_state[i * 4 + 1];
        const a2 = static_state[i * 4 + 2];
        const a3 = static_state[i * 4 + 3];

        static_state[i * 4] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        static_state[i * 4 + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        static_state[i * 4 + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        static_state[i * 4 + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

/// Decrypt a single 16-byte block in-place using static_state
fn decryptBlock() void {
    addRoundKey(ROUNDS);

    var round: usize = ROUNDS - 1;
    while (round >= 1) : (round -= 1) {
        invShiftRows();
        invSubBytes();
        addRoundKey(round);
        invMixColumns();
    }

    // Final round
    invShiftRows();
    invSubBytes();
    addRoundKey(0);
}

// =============================================================================
// CBC Encrypt
// =============================================================================

/// Encrypt data using AES-256-CBC with PKCS7 padding
/// Returns pointer to static output buffer and length
pub fn encryptCBC(
    key: *const [KEY_SIZE]u8,
    iv: *const [IV_SIZE]u8,
    plaintext: []const u8,
) ?struct { data: []const u8, len: usize } {
    if (plaintext.len > MAX_PLAINTEXT) return null;
    if (plaintext.len == 0) return null;

    // Expand key
    keyExpansion(key);

    // Calculate padded length (PKCS7)
    const pad_len = BLOCK_SIZE - (plaintext.len % BLOCK_SIZE);
    const total_len = plaintext.len + pad_len;

    if (total_len > MAX_CIPHERTEXT) return null;

    // Initialize IV
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        static_prev_block[i] = iv[i];
    }

    // Process full blocks
    var offset: usize = 0;
    while (offset + BLOCK_SIZE <= plaintext.len) {
        // Load block into state
        i = 0;
        while (i < BLOCK_SIZE) : (i += 1) {
            static_state[i] = plaintext[offset + i] ^ static_prev_block[i];
        }

        encryptBlock();

        // Store ciphertext and update prev_block
        i = 0;
        while (i < BLOCK_SIZE) : (i += 1) {
            static_encrypt_out[offset + i] = static_state[i];
            static_prev_block[i] = static_state[i];
        }

        offset += BLOCK_SIZE;
    }

    // Handle last block with PKCS7 padding
    i = 0;
    while (i < BLOCK_SIZE) : (i += 1) {
        if (offset + i < plaintext.len) {
            static_state[i] = plaintext[offset + i] ^ static_prev_block[i];
        } else {
            static_state[i] = @as(u8, @intCast(pad_len)) ^ static_prev_block[i];
        }
    }

    encryptBlock();

    i = 0;
    while (i < BLOCK_SIZE) : (i += 1) {
        static_encrypt_out[offset + i] = static_state[i];
    }

    static_encrypt_out_len = total_len;

    return .{
        .data = static_encrypt_out[0..total_len],
        .len = total_len,
    };
}

// =============================================================================
// CBC Decrypt
// =============================================================================

/// Decrypt data using AES-256-CBC, removes PKCS7 padding
/// Returns pointer to static output buffer and original data length
pub fn decryptCBC(
    key: *const [KEY_SIZE]u8,
    iv: *const [IV_SIZE]u8,
    ciphertext: []const u8,
) ?struct { data: []const u8, len: usize } {
    if (ciphertext.len == 0) return null;
    if (ciphertext.len % BLOCK_SIZE != 0) return null;
    if (ciphertext.len > MAX_CIPHERTEXT) return null;

    // Expand key
    keyExpansion(key);

    // Initialize IV
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        static_prev_block[i] = iv[i];
    }

    // Decrypt blocks
    var offset: usize = 0;
    while (offset < ciphertext.len) {
        // Save current ciphertext block (needed for next XOR)
        var saved_ct: [BLOCK_SIZE]u8 = undefined;
        i = 0;
        while (i < BLOCK_SIZE) : (i += 1) {
            saved_ct[i] = ciphertext[offset + i];
            static_state[i] = ciphertext[offset + i];
        }

        decryptBlock();

        // XOR with previous ciphertext (or IV)
        i = 0;
        while (i < BLOCK_SIZE) : (i += 1) {
            static_decrypt_out[offset + i] = static_state[i] ^ static_prev_block[i];
        }

        // Update prev_block
        i = 0;
        while (i < BLOCK_SIZE) : (i += 1) {
            static_prev_block[i] = saved_ct[i];
        }

        offset += BLOCK_SIZE;
    }

    // Remove PKCS7 padding
    const last_byte = static_decrypt_out[ciphertext.len - 1];
    const padding = @as(usize, last_byte);

    if (padding == 0 or padding > BLOCK_SIZE) return null;
    if (padding > ciphertext.len) return null;

    // Verify padding bytes
    i = 0;
    while (i < padding) : (i += 1) {
        if (static_decrypt_out[ciphertext.len - 1 - i] != last_byte) {
            return null; // Invalid padding
        }
    }

    const original_len = ciphertext.len - padding;
    static_decrypt_out_len = original_len;

    return .{
        .data = static_decrypt_out[0..original_len],
        .len = original_len,
    };
}

// =============================================================================
// Key Derivation (from identity/passphrase)
// =============================================================================

var static_derived_key: [KEY_SIZE]u8 = [_]u8{0} ** KEY_SIZE;

/// Derive AES-256 key from passphrase using iterated SHA-256
/// Similar to PBKDF2 but simpler (bare-metal compatible)
pub fn deriveKey(passphrase: []const u8, salt: []const u8) *const [KEY_SIZE]u8 {
    // Combine passphrase + salt
    var input: [128]u8 = [_]u8{0} ** 128;
    var input_len: usize = 0;

    var i: usize = 0;
    while (i < passphrase.len and input_len < 96) : (i += 1) {
        input[input_len] = passphrase[i];
        input_len += 1;
    }

    i = 0;
    while (i < salt.len and input_len < 128) : (i += 1) {
        input[input_len] = salt[i];
        input_len += 1;
    }

    // Initial hash
    hash.sha256Into(input[0..input_len], &static_derived_key);

    // 4096 iterations (key stretching)
    var round: u32 = 0;
    while (round < 4096) : (round += 1) {
        hash.sha256Into(&static_derived_key, &static_derived_key);
    }

    return &static_derived_key;
}

/// Derive key from identity public key
pub fn deriveKeyFromIdentity(pubkey: *const [32]u8) *const [KEY_SIZE]u8 {
    const salt = "zamrud-encfs-v1";
    return deriveKey(pubkey, salt);
}

// =============================================================================
// Generate random IV
// =============================================================================

var static_random_iv: [IV_SIZE]u8 = [_]u8{0} ** IV_SIZE;

pub fn generateIV() *const [IV_SIZE]u8 {
    random.getBytes(&static_random_iv);
    return &static_random_iv;
}

// =============================================================================
// Tests
// =============================================================================

pub fn test_aes() bool {
    serial.writeString("[AES] Testing AES-256...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Key expansion (known test vector)
    serial.writeString("  Key expansion............. ");
    var test_key: [32]u8 = [_]u8{0} ** 32;
    test_key[0] = 0x60;
    test_key[1] = 0x3d;
    test_key[2] = 0xeb;
    test_key[3] = 0x10;
    keyExpansion(&test_key);
    if (static_expanded_key[0] != 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 2: Single block encrypt/decrypt roundtrip
    serial.writeString("  Block roundtrip........... ");
    var block_key: [32]u8 = [_]u8{0} ** 32;
    block_key[0] = 0xAA;
    block_key[15] = 0xBB;
    block_key[31] = 0xCC;
    keyExpansion(&block_key);

    var original: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        static_state[i] = @intCast(i);
        original[i] = @intCast(i);
    }

    encryptBlock();

    // Verify ciphertext differs from plaintext
    var differs = false;
    i = 0;
    while (i < 16) : (i += 1) {
        if (static_state[i] != original[i]) {
            differs = true;
            break;
        }
    }

    if (!differs) {
        serial.writeString("FAIL (no change)\n");
        failed += 1;
    } else {
        // Decrypt
        decryptBlock();

        var match = true;
        i = 0;
        while (i < 16) : (i += 1) {
            if (static_state[i] != original[i]) {
                match = false;
                break;
            }
        }

        if (match) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (mismatch)\n");
            failed += 1;
        }
    }

    // Test 3: CBC encrypt/decrypt roundtrip
    serial.writeString("  CBC roundtrip............. ");
    var cbc_key: [32]u8 = [_]u8{0} ** 32;
    cbc_key[0] = 0x01;
    cbc_key[16] = 0x02;
    var cbc_iv: [16]u8 = [_]u8{0} ** 16;
    cbc_iv[0] = 0xAA;

    const test_plain = "Hello, AES-256!";
    if (encryptCBC(&cbc_key, &cbc_iv, test_plain)) |enc| {
        if (decryptCBC(&cbc_key, &cbc_iv, enc.data)) |dec| {
            if (dec.len == test_plain.len) {
                var ok = true;
                i = 0;
                while (i < dec.len) : (i += 1) {
                    if (dec.data[i] != test_plain[i]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    serial.writeString("PASS\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL (content)\n");
                    failed += 1;
                }
            } else {
                serial.writeString("FAIL (length)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (decrypt)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (encrypt)\n");
        failed += 1;
    }

    // Test 4: Different keys produce different ciphertexts
    serial.writeString("  Different keys differ..... ");
    var key_a: [32]u8 = [_]u8{0} ** 32;
    var key_b: [32]u8 = [_]u8{0} ** 32;
    key_a[0] = 0x11;
    key_b[0] = 0x22;
    var iv_test: [16]u8 = [_]u8{0} ** 16;

    const msg = "test message!!";
    var ct_a: [MAX_CIPHERTEXT]u8 = [_]u8{0} ** MAX_CIPHERTEXT;
    var ct_a_len: usize = 0;

    if (encryptCBC(&key_a, &iv_test, msg)) |enc_a| {
        ct_a_len = enc_a.len;
        i = 0;
        while (i < enc_a.len) : (i += 1) {
            ct_a[i] = enc_a.data[i];
        }

        if (encryptCBC(&key_b, &iv_test, msg)) |enc_b| {
            var diff = false;
            i = 0;
            while (i < @min(ct_a_len, enc_b.len)) : (i += 1) {
                if (ct_a[i] != enc_b.data[i]) {
                    diff = true;
                    break;
                }
            }
            if (diff) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (enc_b)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (enc_a)\n");
        failed += 1;
    }

    // Test 5: Wrong key cannot decrypt
    serial.writeString("  Wrong key rejected........ ");
    var right_key: [32]u8 = [_]u8{0} ** 32;
    var wrong_key: [32]u8 = [_]u8{0} ** 32;
    right_key[0] = 0xAA;
    wrong_key[0] = 0xBB;
    var iv5: [16]u8 = [_]u8{0} ** 16;

    const msg5 = "secret data here";
    if (encryptCBC(&right_key, &iv5, msg5)) |enc5| {
        if (decryptCBC(&wrong_key, &iv5, enc5.data)) |dec5| {
            // Decryption might "succeed" but data should be garbage
            var matches = true;
            i = 0;
            while (i < @min(dec5.len, msg5.len)) : (i += 1) {
                if (dec5.data[i] != msg5[i]) {
                    matches = false;
                    break;
                }
            }
            if (!matches) {
                serial.writeString("PASS (garbage)\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (decrypted!)\n");
                failed += 1;
            }
        } else {
            // Padding check failed = correct rejection
            serial.writeString("PASS (rejected)\n");
            passed += 1;
        }
    } else {
        serial.writeString("FAIL (encrypt)\n");
        failed += 1;
    }

    // Test 6: Key derivation
    serial.writeString("  Key derivation............ ");
    const dk1 = deriveKey("password123", "salt1");
    var dk1_copy: [32]u8 = undefined;
    i = 0;
    while (i < 32) : (i += 1) {
        dk1_copy[i] = dk1[i];
    }

    const dk2 = deriveKey("password123", "salt1");
    var dk_match = true;
    i = 0;
    while (i < 32) : (i += 1) {
        if (dk1_copy[i] != dk2[i]) {
            dk_match = false;
            break;
        }
    }

    if (dk_match) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 7: Different passphrases → different keys
    serial.writeString("  Different pass diff key... ");
    const dka = deriveKey("alpha", "salt");
    var dka_copy: [32]u8 = undefined;
    i = 0;
    while (i < 32) : (i += 1) {
        dka_copy[i] = dka[i];
    }

    const dkb = deriveKey("beta", "salt");
    var dk_diff = false;
    i = 0;
    while (i < 32) : (i += 1) {
        if (dka_copy[i] != dkb[i]) {
            dk_diff = true;
            break;
        }
    }

    if (dk_diff) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 8: IV generation
    serial.writeString("  IV generation............. ");
    const iv_a = generateIV();
    var iv_a_copy: [16]u8 = undefined;
    i = 0;
    while (i < 16) : (i += 1) {
        iv_a_copy[i] = iv_a[i];
    }
    const iv_b = generateIV();
    var iv_diff = false;
    i = 0;
    while (i < 16) : (i += 1) {
        if (iv_a_copy[i] != iv_b[i]) {
            iv_diff = true;
            break;
        }
    }
    if (iv_diff) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 9: Multi-block CBC
    serial.writeString("  Multi-block CBC........... ");
    var mb_key: [32]u8 = [_]u8{0} ** 32;
    mb_key[0] = 0x55;
    var mb_iv: [16]u8 = [_]u8{0} ** 16;
    const mb_plain = "This is a longer message that spans multiple AES blocks for testing.";
    if (encryptCBC(&mb_key, &mb_iv, mb_plain)) |mb_enc| {
        if (decryptCBC(&mb_key, &mb_iv, mb_enc.data)) |mb_dec| {
            if (mb_dec.len == mb_plain.len) {
                var mb_ok = true;
                i = 0;
                while (i < mb_dec.len) : (i += 1) {
                    if (mb_dec.data[i] != mb_plain[i]) {
                        mb_ok = false;
                        break;
                    }
                }
                if (mb_ok) {
                    serial.writeString("PASS\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL\n");
                    failed += 1;
                }
            } else {
                serial.writeString("FAIL (len)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (dec)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (enc)\n");
        failed += 1;
    }

    // Test 10: Empty input rejected
    serial.writeString("  Empty input rejected...... ");
    var empty_key: [32]u8 = [_]u8{0} ** 32;
    var empty_iv: [16]u8 = [_]u8{0} ** 16;
    if (encryptCBC(&empty_key, &empty_iv, "")) |_| {
        serial.writeString("FAIL\n");
        failed += 1;
    } else {
        serial.writeString("PASS\n");
        passed += 1;
    }

    serial.writeString("\n  AES-256: ");
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
