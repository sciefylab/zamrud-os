//! Zamrud OS - F4.2: System Data Encryption Manager
//! Centralized encryption for all system data at rest and in transit.
//!
//! Key Hierarchy:
//!   SYSTEM_MASTER_KEY (derived from root identity at boot)
//!   ├── CONFIG_KEY  = KDF(master, "zamrud-sys:config")
//!   ├── IDENTITY_KEY = KDF(master, "zamrud-sys:identity")
//!   ├── IPC_KEY     = KDF(master, "zamrud-sys:ipc")
//!   └── CHAIN_KEY   = KDF(master, "zamrud-sys:chain")
//!
//! All persist writes go through encrypt-before-write.
//! All persist reads go through read-then-decrypt.
//! IPC encrypted channels use per-message IV.

const serial = @import("../drivers/serial/serial.zig");
const aes = @import("aes.zig");
const hash = @import("hash.zig");
const random = @import("random.zig");

// =============================================================================
// Constants
// =============================================================================

pub const KEY_SIZE = aes.KEY_SIZE; // 32
pub const IV_SIZE = aes.IV_SIZE; // 16
pub const BLOCK_SIZE = aes.BLOCK_SIZE; // 16
pub const HEADER_SIZE = 4 + IV_SIZE; // magic(4) + IV(16) = 20

/// Magic bytes for encrypted system data
pub const SYS_MAGIC = [4]u8{ 'Z', 'S', 'E', 'D' }; // Zamrud System Encrypted Data

/// Maximum sizes
pub const MAX_ENCRYPT_SIZE = 4096;
pub const MAX_DECRYPT_SIZE = MAX_ENCRYPT_SIZE;
pub const MAX_OUTPUT_SIZE = MAX_ENCRYPT_SIZE + HEADER_SIZE + BLOCK_SIZE;

// =============================================================================
// Key Domain — each subsystem gets its own derived key
// =============================================================================

pub const KeyDomain = enum(u8) {
    config = 0,
    identity = 1,
    ipc = 2,
    chain = 3,

    pub fn salt(self: KeyDomain) []const u8 {
        return switch (self) {
            .config => "zamrud-sys:config",
            .identity => "zamrud-sys:identity",
            .ipc => "zamrud-sys:ipc",
            .chain => "zamrud-sys:chain",
        };
    }

    pub fn name(self: KeyDomain) []const u8 {
        return switch (self) {
            .config => "CONFIG",
            .identity => "IDENTITY",
            .ipc => "IPC",
            .chain => "CHAIN",
        };
    }
};

// =============================================================================
// State
// =============================================================================

var master_key: [KEY_SIZE]u8 = [_]u8{0} ** KEY_SIZE;
var master_key_set: bool = false;

/// Per-domain derived keys (cached after first derivation)
var domain_keys: [4][KEY_SIZE]u8 = [_][KEY_SIZE]u8{[_]u8{0} ** KEY_SIZE} ** 4;
var domain_keys_derived: [4]bool = [_]bool{false} ** 4;

/// Static output buffers (bare-metal, no heap)
var encrypt_buf: [MAX_OUTPUT_SIZE]u8 = [_]u8{0} ** MAX_OUTPUT_SIZE;
var decrypt_buf: [MAX_DECRYPT_SIZE]u8 = [_]u8{0} ** MAX_DECRYPT_SIZE;

var initialized: bool = false;

/// Stats
var stats_encrypts: u64 = 0;
var stats_decrypts: u64 = 0;
var stats_failures: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[SYS_ENCRYPT] Initializing system encryption...\n");

    var i: usize = 0;
    while (i < KEY_SIZE) : (i += 1) {
        master_key[i] = 0;
    }
    master_key_set = false;

    i = 0;
    while (i < 4) : (i += 1) {
        domain_keys_derived[i] = false;
        var j: usize = 0;
        while (j < KEY_SIZE) : (j += 1) {
            domain_keys[i][j] = 0;
        }
    }

    stats_encrypts = 0;
    stats_decrypts = 0;
    stats_failures = 0;

    initialized = true;
    serial.writeString("[SYS_ENCRYPT] System encryption ready (awaiting master key)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isMasterKeySet() bool {
    return master_key_set;
}

// =============================================================================
// Master Key Management
// =============================================================================

/// Set master key from root identity's public key
pub fn setMasterKeyFromIdentity(pubkey: *const [32]u8) void {
    const derived = aes.deriveKey(pubkey, "zamrud-system-master-v1");
    var i: usize = 0;
    while (i < KEY_SIZE) : (i += 1) {
        master_key[i] = derived[i];
    }
    master_key_set = true;

    // Invalidate cached domain keys
    i = 0;
    while (i < 4) : (i += 1) {
        domain_keys_derived[i] = false;
    }

    serial.writeString("[SYS_ENCRYPT] Master key set from identity\n");
}

/// Set master key from passphrase (fallback for testing)
pub fn setMasterKeyFromPassphrase(passphrase: []const u8) void {
    const derived = aes.deriveKey(passphrase, "zamrud-system-master-v1");
    var i: usize = 0;
    while (i < KEY_SIZE) : (i += 1) {
        master_key[i] = derived[i];
    }
    master_key_set = true;

    // Invalidate cached domain keys
    i = 0;
    while (i < 4) : (i += 1) {
        domain_keys_derived[i] = false;
    }

    serial.writeString("[SYS_ENCRYPT] Master key set from passphrase\n");
}

/// Set master key directly (for testing)
pub fn setMasterKeyDirect(key: *const [KEY_SIZE]u8) void {
    var i: usize = 0;
    while (i < KEY_SIZE) : (i += 1) {
        master_key[i] = key[i];
    }
    master_key_set = true;

    i = 0;
    while (i < 4) : (i += 1) {
        domain_keys_derived[i] = false;
    }
}

/// Clear master key (on shutdown/lock)
pub fn clearMasterKey() void {
    var i: usize = 0;
    while (i < KEY_SIZE) : (i += 1) {
        master_key[i] = 0;
    }
    master_key_set = false;

    // Clear domain keys
    i = 0;
    while (i < 4) : (i += 1) {
        domain_keys_derived[i] = false;
        var j: usize = 0;
        while (j < KEY_SIZE) : (j += 1) {
            domain_keys[i][j] = 0;
        }
    }

    serial.writeString("[SYS_ENCRYPT] Master key cleared\n");
}

// =============================================================================
// Domain Key Derivation
// =============================================================================

/// Get or derive the key for a specific domain
pub fn getDomainKey(domain: KeyDomain) ?*const [KEY_SIZE]u8 {
    if (!master_key_set) return null;

    const idx = @intFromEnum(domain);

    if (!domain_keys_derived[idx]) {
        // Derive: domain_key = KDF(master_key, domain_salt)
        const derived = aes.deriveKey(&master_key, domain.salt());
        var i: usize = 0;
        while (i < KEY_SIZE) : (i += 1) {
            domain_keys[idx][i] = derived[i];
        }
        domain_keys_derived[idx] = true;
    }

    return &domain_keys[idx];
}

// =============================================================================
// Encrypt System Data — [MAGIC(4)][IV(16)][ciphertext...]
// =============================================================================

/// Encrypt data for a specific domain
/// Returns slice into static buffer, or null on failure
pub fn encryptForDomain(domain: KeyDomain, plaintext: []const u8) ?[]const u8 {
    if (!initialized or !master_key_set) return null;
    if (plaintext.len == 0 or plaintext.len > MAX_ENCRYPT_SIZE) return null;

    const key = getDomainKey(domain) orelse return null;

    // Generate random IV
    var iv: [IV_SIZE]u8 = undefined;
    random.getBytes(&iv);

    // Encrypt
    const enc_result = aes.encryptCBC(key, &iv, plaintext) orelse {
        stats_failures += 1;
        return null;
    };

    // Build output: [MAGIC][IV][ciphertext]
    var pos: usize = 0;

    // Magic
    encrypt_buf[pos] = SYS_MAGIC[0];
    encrypt_buf[pos + 1] = SYS_MAGIC[1];
    encrypt_buf[pos + 2] = SYS_MAGIC[2];
    encrypt_buf[pos + 3] = SYS_MAGIC[3];
    pos += 4;

    // IV
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        encrypt_buf[pos + i] = iv[i];
    }
    pos += IV_SIZE;

    // Ciphertext
    i = 0;
    while (i < enc_result.len) : (i += 1) {
        encrypt_buf[pos + i] = enc_result.data[i];
    }
    pos += enc_result.len;

    stats_encrypts += 1;

    return encrypt_buf[0..pos];
}

// =============================================================================
// Decrypt System Data
// =============================================================================

/// Decrypt data for a specific domain
/// Returns slice into static buffer, or null on failure
pub fn decryptForDomain(domain: KeyDomain, encrypted: []const u8) ?[]const u8 {
    if (!initialized or !master_key_set) return null;
    if (encrypted.len < HEADER_SIZE + BLOCK_SIZE) return null;

    // Verify magic
    if (encrypted[0] != SYS_MAGIC[0] or encrypted[1] != SYS_MAGIC[1] or
        encrypted[2] != SYS_MAGIC[2] or encrypted[3] != SYS_MAGIC[3])
    {
        stats_failures += 1;
        return null;
    }

    const key = getDomainKey(domain) orelse return null;

    // Extract IV
    var iv: [IV_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        iv[i] = encrypted[4 + i];
    }

    // Extract ciphertext
    const ct_start = HEADER_SIZE;
    const ct_len = encrypted.len - HEADER_SIZE;

    const dec_result = aes.decryptCBC(key, &iv, encrypted[ct_start .. ct_start + ct_len]) orelse {
        stats_failures += 1;
        return null;
    };

    // Copy to our static buffer (aes uses its own static buffer)
    if (dec_result.len > MAX_DECRYPT_SIZE) return null;
    i = 0;
    while (i < dec_result.len) : (i += 1) {
        decrypt_buf[i] = dec_result.data[i];
    }

    stats_decrypts += 1;

    return decrypt_buf[0..dec_result.len];
}

// =============================================================================
// Convenience: Encrypt/Decrypt for each subsystem
// =============================================================================

pub fn encryptConfig(plaintext: []const u8) ?[]const u8 {
    return encryptForDomain(.config, plaintext);
}

pub fn decryptConfig(encrypted: []const u8) ?[]const u8 {
    return decryptForDomain(.config, encrypted);
}

pub fn encryptIdentity(plaintext: []const u8) ?[]const u8 {
    return encryptForDomain(.identity, plaintext);
}

pub fn decryptIdentity(encrypted: []const u8) ?[]const u8 {
    return decryptForDomain(.identity, encrypted);
}

pub fn encryptIpc(plaintext: []const u8) ?[]const u8 {
    return encryptForDomain(.ipc, plaintext);
}

pub fn decryptIpc(encrypted: []const u8) ?[]const u8 {
    return decryptForDomain(.ipc, encrypted);
}

pub fn encryptChain(plaintext: []const u8) ?[]const u8 {
    return encryptForDomain(.chain, plaintext);
}

pub fn decryptChain(encrypted: []const u8) ?[]const u8 {
    return decryptForDomain(.chain, encrypted);
}

// =============================================================================
// IPC Message Encryption (small data, per-message IV)
// =============================================================================

/// Encrypt a small IPC message payload (max 64 bytes)
/// Output: [IV(16)][ciphertext] (no magic for compactness)
/// Returns total encrypted length, or 0 on failure
pub fn encryptIpcMsg(plaintext: []const u8, out: []u8) usize {
    if (!master_key_set) return 0;
    if (plaintext.len == 0 or plaintext.len > 64) return 0;

    const key = getDomainKey(.ipc) orelse return 0;

    // Generate IV
    var iv: [IV_SIZE]u8 = undefined;
    random.getBytes(&iv);

    const enc_result = aes.encryptCBC(key, &iv, plaintext) orelse return 0;

    const total = IV_SIZE + enc_result.len;
    if (total > out.len) return 0;

    // [IV][ciphertext]
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        out[i] = iv[i];
    }
    i = 0;
    while (i < enc_result.len) : (i += 1) {
        out[IV_SIZE + i] = enc_result.data[i];
    }

    stats_encrypts += 1;
    return total;
}

/// Decrypt a small IPC message payload
/// Input format: [IV(16)][ciphertext]
/// Returns decrypted length, or 0 on failure
pub fn decryptIpcMsg(encrypted: []const u8, out: []u8) usize {
    if (!master_key_set) return 0;
    if (encrypted.len < IV_SIZE + BLOCK_SIZE) return 0;

    const key = getDomainKey(.ipc) orelse return 0;

    // Extract IV
    var iv: [IV_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < IV_SIZE) : (i += 1) {
        iv[i] = encrypted[i];
    }

    // Decrypt
    const ct = encrypted[IV_SIZE..];
    const dec_result = aes.decryptCBC(key, &iv, ct) orelse return 0;

    if (dec_result.len > out.len) return 0;

    i = 0;
    while (i < dec_result.len) : (i += 1) {
        out[i] = dec_result.data[i];
    }

    stats_decrypts += 1;
    return dec_result.len;
}

// =============================================================================
// Utility: Check if data is encrypted (has our magic header)
// =============================================================================

pub fn isEncrypted(data: []const u8) bool {
    if (data.len < 4) return false;
    return data[0] == SYS_MAGIC[0] and data[1] == SYS_MAGIC[1] and
        data[2] == SYS_MAGIC[2] and data[3] == SYS_MAGIC[3];
}

// =============================================================================
// Stats
// =============================================================================

pub fn getStats() struct { encrypts: u64, decrypts: u64, failures: u64 } {
    return .{
        .encrypts = stats_encrypts,
        .decrypts = stats_decrypts,
        .failures = stats_failures,
    };
}

pub fn resetStats() void {
    stats_encrypts = 0;
    stats_decrypts = 0;
    stats_failures = 0;
}

// =============================================================================
// Convenience: IPC Key Access (used by shared_mem.zig, pipe.zig)
// =============================================================================

/// Check if IPC domain key is available
pub fn isIpcKeySet() bool {
    if (!initialized or !master_key_set) return false;
    // Ensure IPC key is derived
    return getDomainKey(.ipc) != null;
}

/// Get IPC domain key pointer (used by shared_mem/pipe XOR encryption)
pub fn getIpcKey() ?*const [KEY_SIZE]u8 {
    return getDomainKey(.ipc);
}

// =============================================================================
// Debug
// =============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== SYSTEM ENCRYPTION STATUS ===\n");
    serial.writeString("  Initialized:  ");
    serial.writeString(if (initialized) "YES" else "NO");
    serial.writeString("\n  Master key:   ");
    serial.writeString(if (master_key_set) "SET" else "NOT SET");
    serial.writeString("\n  Domain keys:\n");

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const d: KeyDomain = @enumFromInt(i);
        serial.writeString("    ");
        serial.writeString(d.name());
        serial.writeString(": ");
        serial.writeString(if (domain_keys_derived[i]) "derived" else "pending");
        serial.writeString("\n");
    }

    serial.writeString("  Encrypts:     ");
    printU64(stats_encrypts);
    serial.writeString("\n  Decrypts:     ");
    printU64(stats_decrypts);
    serial.writeString("\n  Failures:     ");
    printU64(stats_failures);
    serial.writeString("\n");
}

fn printU64(val: u64) void {
    if (val <= 0xFFFFFFFF) {
        printU32(@intCast(val));
    } else {
        serial.writeString(">4G");
    }
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
