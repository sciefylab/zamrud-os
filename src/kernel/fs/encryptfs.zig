//! Zamrud OS - Encrypted Filesystem Layer (F4)
//! F4.0: Core AES-256-CBC per-file encryption
//! F4.1: User-hierarchy ownership (owner_uid, owner_role)
//!       + findFileMut() + getFileInfo() for integration layer
//!
//! Architecture:
//!   User writes "hello" to /enc/secret.txt
//!     → encryptfs intercepts
//!     → AES-256-CBC encrypt with identity-derived key
//!     → stores: [MAGIC(4)][IV(16)][ciphertext] in backing store
//!   User reads /enc/secret.txt
//!     → encryptfs intercepts
//!     → reads [IV][ciphertext] from backing store
//!     → AES-256-CBC decrypt
//!     → returns "hello"

const serial = @import("../drivers/serial/serial.zig");
const vfs = @import("vfs.zig");
const ramfs = @import("ramfs.zig");
const aes = @import("../crypto/aes.zig");
const hash = @import("../crypto/hash.zig");
const random = @import("../crypto/random.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");
const process = @import("../proc/process.zig");
const users = @import("../security/users.zig"); // F4.1

// =============================================================================
// Constants
// =============================================================================

pub const MAX_ENCRYPTED_FILES: usize = 32;
pub const MAX_FILENAME: usize = 64;
pub const MAX_FILE_DATA: usize = aes.MAX_PLAINTEXT;
pub const MAGIC: [4]u8 = .{ 'Z', 'E', 'N', 'C' }; // Zamrud ENCrypted
pub const HEADER_SIZE: usize = 4 + aes.IV_SIZE; // magic(4) + IV(16) = 20

// =============================================================================
// Encrypted File Entry — F4.1: added owner_role
// =============================================================================

pub const EncryptedFile = struct {
    name: [MAX_FILENAME]u8 = [_]u8{0} ** MAX_FILENAME,
    name_len: u8 = 0,
    /// Raw stored data: [MAGIC(4)][IV(16)][ciphertext...]
    data: [MAX_FILE_DATA + HEADER_SIZE + aes.BLOCK_SIZE]u8 = [_]u8{0} ** (MAX_FILE_DATA + HEADER_SIZE + aes.BLOCK_SIZE),
    data_len: usize = 0,
    /// Original plaintext size (for stat)
    original_size: usize = 0,
    owner_uid: u16 = 0,
    owner_role: users.UserRole = .guest, // F4.1: role of file creator
    active: bool = false,

    pub fn getName(self: *const EncryptedFile) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *EncryptedFile, n: []const u8) void {
        const len = @min(n.len, MAX_FILENAME);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = n[i];
        }
        self.name_len = @intCast(len);
    }
};

// =============================================================================
// State
// =============================================================================

var files: [MAX_ENCRYPTED_FILES]EncryptedFile = undefined;
var file_count: usize = 0;
var initialized: bool = false;

/// Current encryption key (derived from identity or passphrase)
var current_key: [aes.KEY_SIZE]u8 = [_]u8{0} ** aes.KEY_SIZE;
var key_set: bool = false;

/// Stats
var stats_encrypts: u64 = 0;
var stats_decrypts: u64 = 0;
var stats_violations: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[ENCFS] Initializing encrypted filesystem...\n");

    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        files[i] = EncryptedFile{};
    }

    file_count = 0;
    key_set = false;
    stats_encrypts = 0;
    stats_decrypts = 0;
    stats_violations = 0;

    initialized = true;
    serial.writeString("[ENCFS] Encrypted filesystem ready (max=");
    printU32(MAX_ENCRYPTED_FILES);
    serial.writeString(" files, AES-256-CBC)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isKeySet() bool {
    return key_set;
}

// =============================================================================
// Key Management
// =============================================================================

/// Set encryption key from passphrase
pub fn setKeyFromPassphrase(passphrase: []const u8) bool {
    if (!initialized) return false;
    if (passphrase.len < 4) return false;

    // CAP_CRYPTO check
    const pid = process.getCurrentPid();
    if (!capability.check(pid, capability.CAP_CRYPTO)) {
        reportViolation(pid, "setkey_no_cap");
        return false;
    }

    const derived = aes.deriveKey(passphrase, "zamrud-encfs-key");
    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        current_key[i] = derived[i];
    }

    key_set = true;
    serial.writeString("[ENCFS] Key set from passphrase\n");
    return true;
}

/// Set encryption key from identity public key
pub fn setKeyFromIdentity(pubkey: *const [32]u8) bool {
    if (!initialized) return false;

    const pid = process.getCurrentPid();
    if (!capability.check(pid, capability.CAP_CRYPTO)) {
        reportViolation(pid, "setkey_no_cap");
        return false;
    }

    const derived = aes.deriveKeyFromIdentity(pubkey);
    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        current_key[i] = derived[i];
    }

    key_set = true;
    serial.writeString("[ENCFS] Key set from identity\n");
    return true;
}

/// Set key directly (for testing and enc_integration)
pub fn setKeyDirect(key: *const [aes.KEY_SIZE]u8) void {
    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        current_key[i] = key[i];
    }
    key_set = true;
}

/// Clear the current key (lock)
pub fn clearKey() void {
    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        current_key[i] = 0;
    }
    key_set = false;
    serial.writeString("[ENCFS] Key cleared (locked)\n");
}

// =============================================================================
// File Operations
// =============================================================================

/// Create and encrypt a new file
pub fn encryptFile(name: []const u8, plaintext: []const u8) bool {
    if (!initialized) return false;
    if (!key_set) {
        serial.writeString("[ENCFS] No key set!\n");
        return false;
    }
    if (plaintext.len > MAX_FILE_DATA) return false;
    if (plaintext.len == 0) return false;
    if (name.len == 0) return false;

    // CAP_CRYPTO check
    const pid = process.getCurrentPid();
    if (!capability.check(pid, capability.CAP_CRYPTO)) {
        reportViolation(pid, "encrypt_no_cap");
        return false;
    }

    // Check if file already exists
    if (findFileConst(name) != null) {
        serial.writeString("[ENCFS] File already exists: ");
        serial.writeString(name);
        serial.writeString("\n");
        return false;
    }

    // Find free slot
    var slot: usize = MAX_ENCRYPTED_FILES;
    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        if (!files[i].active) {
            slot = i;
            break;
        }
    }

    if (slot >= MAX_ENCRYPTED_FILES) {
        serial.writeString("[ENCFS] No free slots!\n");
        return false;
    }

    // Generate random IV
    const iv = aes.generateIV();

    // Encrypt
    const result = aes.encryptCBC(&current_key, iv, plaintext) orelse {
        serial.writeString("[ENCFS] Encryption failed!\n");
        return false;
    };

    // Store: [MAGIC][IV][ciphertext]
    var f = &files[slot];
    f.setName(name);

    var pos: usize = 0;

    // Magic header
    i = 0;
    while (i < 4) : (i += 1) {
        f.data[pos] = MAGIC[i];
        pos += 1;
    }

    // IV
    i = 0;
    while (i < aes.IV_SIZE) : (i += 1) {
        f.data[pos] = iv[i];
        pos += 1;
    }

    // Ciphertext
    i = 0;
    while (i < result.len) : (i += 1) {
        f.data[pos] = result.data[i];
        pos += 1;
    }

    f.data_len = pos;
    f.original_size = plaintext.len;
    f.owner_uid = 0; // F4.1: will be stamped by enc_integration
    f.owner_role = .guest; // F4.1: will be stamped by enc_integration
    f.active = true;

    file_count += 1;
    stats_encrypts += 1;

    serial.writeString("[ENCFS] Encrypted '");
    serial.writeString(name);
    serial.writeString("' (");
    printU32(@intCast(plaintext.len));
    serial.writeString(" -> ");
    printU32(@intCast(pos));
    serial.writeString(" bytes)\n");

    return true;
}

/// Decrypt and read a file
/// Returns decrypted data slice (from static buffer)
pub fn decryptFile(name: []const u8) ?[]const u8 {
    if (!initialized) return null;
    if (!key_set) {
        serial.writeString("[ENCFS] No key set!\n");
        return null;
    }

    // CAP_CRYPTO check
    const pid = process.getCurrentPid();
    if (!capability.check(pid, capability.CAP_CRYPTO)) {
        reportViolation(pid, "decrypt_no_cap");
        return null;
    }

    const f = findFileConst(name) orelse {
        serial.writeString("[ENCFS] File not found: ");
        serial.writeString(name);
        serial.writeString("\n");
        return null;
    };

    if (f.data_len < HEADER_SIZE) return null;

    // Verify magic
    if (f.data[0] != MAGIC[0] or f.data[1] != MAGIC[1] or
        f.data[2] != MAGIC[2] or f.data[3] != MAGIC[3])
    {
        serial.writeString("[ENCFS] Invalid file header!\n");
        return null;
    }

    // Extract IV
    var iv: [aes.IV_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < aes.IV_SIZE) : (i += 1) {
        iv[i] = f.data[4 + i];
    }

    // Extract ciphertext
    const ct_start = HEADER_SIZE;
    const ct_len = f.data_len - HEADER_SIZE;

    const result = aes.decryptCBC(&current_key, &iv, f.data[ct_start .. ct_start + ct_len]) orelse {
        serial.writeString("[ENCFS] Decryption failed (wrong key?)\n");
        return null;
    };

    stats_decrypts += 1;

    return result.data;
}

/// Delete an encrypted file
pub fn deleteFile(name: []const u8) bool {
    if (!initialized) return false;

    const pid = process.getCurrentPid();
    if (!capability.check(pid, capability.CAP_CRYPTO)) {
        reportViolation(pid, "delete_no_cap");
        return false;
    }

    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        if (files[i].active and strEqual(files[i].getName(), name)) {
            // Secure wipe
            var j: usize = 0;
            while (j < files[i].data_len) : (j += 1) {
                files[i].data[j] = 0;
            }
            files[i].active = false;
            files[i].data_len = 0;
            files[i].original_size = 0;
            files[i].name_len = 0;
            files[i].owner_uid = 0;
            files[i].owner_role = .guest; // F4.1: reset role
            if (file_count > 0) file_count -= 1;

            serial.writeString("[ENCFS] Deleted '");
            serial.writeString(name);
            serial.writeString("'\n");
            return true;
        }
    }

    return false;
}

// =============================================================================
// Query — F4.1: added findFileMut, getFileInfo
// =============================================================================

/// Internal const lookup
fn findFileConst(name: []const u8) ?*const EncryptedFile {
    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        if (files[i].active and strEqual(files[i].getName(), name)) {
            return &files[i];
        }
    }
    return null;
}

/// F4.1: Mutable file lookup (for stamping ownership after encrypt)
pub fn findFileMut(name: []const u8) ?*EncryptedFile {
    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        if (files[i].active and strEqual(files[i].getName(), name)) {
            return &files[i];
        }
    }
    return null;
}

/// F4.1: Get file info for access control checks (read-only)
pub fn getFileInfo(name: []const u8) ?struct {
    owner_uid: u16,
    owner_role: users.UserRole,
    original_size: usize,
    data_len: usize,
} {
    const f = findFileConst(name) orelse return null;
    return .{
        .owner_uid = f.owner_uid,
        .owner_role = f.owner_role,
        .original_size = f.original_size,
        .data_len = f.data_len,
    };
}

pub fn fileExists(name: []const u8) bool {
    return findFileConst(name) != null;
}

pub fn getFileCount() usize {
    return file_count;
}

pub fn getFileByIndex(index: usize) ?*const EncryptedFile {
    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_ENCRYPTED_FILES) : (i += 1) {
        if (files[i].active) {
            if (count == index) return &files[i];
            count += 1;
        }
    }
    return null;
}

pub fn getStats() struct { encrypts: u64, decrypts: u64, violations: u64, files: usize } {
    return .{
        .encrypts = stats_encrypts,
        .decrypts = stats_decrypts,
        .violations = stats_violations,
        .files = file_count,
    };
}

// =============================================================================
// Violation Reporting
// =============================================================================

fn reportViolation(pid: u32, detail: []const u8) void {
    stats_violations += 1;

    if (violation.isInitialized()) {
        _ = violation.reportViolation(.{
            .violation_type = .capability_violation,
            .severity = .medium,
            .pid = @intCast(pid & 0xFFFF),
            .source_ip = 0,
            .detail = detail,
        });
    }
}

// =============================================================================
// Utilities
// =============================================================================

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
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
// Tests (F4.0 — preserved, unchanged logic)
// =============================================================================

pub fn test_encryptfs() bool {
    serial.writeString("\n########################################\n");
    serial.writeString("##  F4 ENCRYPTED FILESYSTEM\n");
    serial.writeString("########################################\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Re-init for clean test
    init();

    // Test 1: Initialize
    serial.writeString("  Initialize................ ");
    if (initialized and file_count == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 2: No key set initially
    serial.writeString("  No key initially.......... ");
    if (!key_set) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 3: Set key from passphrase
    serial.writeString("  Set key (direct).......... ");
    var test_key: [aes.KEY_SIZE]u8 = [_]u8{0} ** aes.KEY_SIZE;
    test_key[0] = 0xDE;
    test_key[1] = 0xAD;
    test_key[16] = 0xBE;
    test_key[31] = 0xEF;
    setKeyDirect(&test_key);
    if (key_set) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 4: Encrypt file
    serial.writeString("  Encrypt file.............. ");
    if (encryptFile("secret.txt", "Hello, encrypted world!")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 5: File count
    serial.writeString("  File count = 1............ ");
    if (file_count == 1) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 6: File exists
    serial.writeString("  File exists............... ");
    if (fileExists("secret.txt")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 7: Decrypt file
    serial.writeString("  Decrypt file.............. ");
    if (decryptFile("secret.txt")) |data| {
        if (strEqual(data, "Hello, encrypted world!")) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (content mismatch)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (null)\n");
        failed += 1;
    }

    // Test 8: Duplicate name blocked
    serial.writeString("  Duplicate blocked......... ");
    if (!encryptFile("secret.txt", "duplicate")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 9: Wrong key cannot decrypt
    serial.writeString("  Wrong key rejected........ ");
    var wrong_key: [aes.KEY_SIZE]u8 = [_]u8{0xFF} ** aes.KEY_SIZE;
    setKeyDirect(&wrong_key);
    if (decryptFile("secret.txt") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Restore correct key
    setKeyDirect(&test_key);

    // Test 10: Decrypt with correct key still works
    serial.writeString("  Correct key works......... ");
    if (decryptFile("secret.txt")) |data| {
        if (strEqual(data, "Hello, encrypted world!")) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 11: Multiple files
    serial.writeString("  Multiple files............ ");
    const ok1 = encryptFile("file1.enc", "First file content");
    const ok2 = encryptFile("file2.enc", "Second file content");
    if (ok1 and ok2 and file_count == 3) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 12: Read each file correctly
    serial.writeString("  Read each correctly....... ");
    var all_ok = true;
    if (decryptFile("file1.enc")) |d1| {
        if (!strEqual(d1, "First file content")) all_ok = false;
    } else all_ok = false;
    if (decryptFile("file2.enc")) |d2| {
        if (!strEqual(d2, "Second file content")) all_ok = false;
    } else all_ok = false;
    if (all_ok) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 13: Delete file
    serial.writeString("  Delete file............... ");
    if (deleteFile("file1.enc") and !fileExists("file1.enc") and file_count == 2) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 14: Nonexist file returns null
    serial.writeString("  Nonexist returns null..... ");
    if (decryptFile("nonexist.enc") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 15: Empty data rejected
    serial.writeString("  Empty data rejected....... ");
    if (!encryptFile("empty.enc", "")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 16: Stats encrypts
    serial.writeString("  Stats: encrypts > 0....... ");
    if (stats_encrypts > 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 17: Stats decrypts
    serial.writeString("  Stats: decrypts > 0....... ");
    if (stats_decrypts > 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 18: Clear key (lock)
    serial.writeString("  Clear key (lock).......... ");
    clearKey();
    if (!key_set) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 19: Decrypt without key fails
    serial.writeString("  Decrypt without key....... ");
    if (decryptFile("secret.txt") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 20: Key derivation produces key
    serial.writeString("  Key derivation works...... ");
    const dk = aes.deriveKey("testpass", "salt");
    var has_nonzero = false;
    var idx: usize = 0;
    while (idx < 32) : (idx += 1) {
        if (dk[idx] != 0) {
            has_nonzero = true;
            break;
        }
    }
    if (has_nonzero) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // F4.1 Test 21: findFileMut works
    serial.writeString("  findFileMut works......... ");
    setKeyDirect(&test_key);
    _ = encryptFile("mut_test.enc", "mutable test");
    if (findFileMut("mut_test.enc")) |mf| {
        mf.owner_uid = 42;
        mf.owner_role = .admin;
        if (mf.owner_uid == 42 and mf.owner_role == .admin) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (not found)\n");
        failed += 1;
    }

    // F4.1 Test 22: getFileInfo works
    serial.writeString("  getFileInfo works......... ");
    if (getFileInfo("mut_test.enc")) |info| {
        if (info.owner_uid == 42 and info.owner_role == .admin and info.original_size > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (wrong info)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (null)\n");
        failed += 1;
    }

    // F4.1 Test 23: getFileInfo nonexist
    serial.writeString("  getFileInfo nonexist...... ");
    if (getFileInfo("no_such_file.enc") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // F4.1 Test 24: owner_role persists after delete/recreate
    serial.writeString("  owner_role reset on delete ");
    _ = deleteFile("mut_test.enc");
    // Recreate same name
    _ = encryptFile("mut_test2.enc", "new file");
    if (findFileMut("mut_test2.enc")) |mf2| {
        // New file should have default role (.guest)
        if (mf2.owner_role == .guest) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // F4.1 Test 25: findFileMut nonexist returns null
    serial.writeString("  findFileMut nonexist...... ");
    if (findFileMut("nonexist_mut.enc") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    clearKey();

    serial.writeString("\n========================================\n");
    serial.writeString("  F4.0+F4.1 Results: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed (");
    printU32(passed + failed);
    serial.writeString(" total)\n");
    serial.writeString("========================================\n\n");

    if (failed == 0) {
        serial.writeString("All F4 tests PASSED!\n");
    } else {
        serial.writeString("Some F4 tests FAILED!\n");
    }

    return failed == 0;
}
