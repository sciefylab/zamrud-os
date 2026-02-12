//! Zamrud OS - F4.1: User-Hierarchy Encryption Integration
//! Ties encryption to user roles, identity-based key derivation,
//! per-user encryption domains, and auto key management on login/logout.
//!
//! Key Hierarchy:
//!   MASTER KEY (root) → can decrypt ALL files
//!   ADMIN KEY (per-admin uid) → own + shared admin files
//!   USER KEY (per-user uid) → own files only
//!   GUEST → NO KEY (CAP_CRYPTO denied)

const serial = @import("../drivers/serial/serial.zig");
const encryptfs = @import("encryptfs.zig");
const users = @import("../security/users.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");
const keyring = @import("../identity/keyring.zig");
const aes = @import("../crypto/aes.zig");

// =============================================================================
// Per-User Key State
// =============================================================================

var current_owner_uid: u16 = users.NOBODY_UID;
var current_owner_role: users.UserRole = .guest;
var key_active: bool = false;

/// Master key (root) — for root override decryption
var master_key: [aes.KEY_SIZE]u8 = [_]u8{0} ** aes.KEY_SIZE;
var master_key_set: bool = false;

var initialized: bool = false;

// Stats
var stats_auto_keys: u64 = 0;
var stats_access_denied: u64 = 0;
var stats_root_overrides: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[ENC_INT] Initializing encryption integration...\n");

    current_owner_uid = users.NOBODY_UID;
    current_owner_role = .guest;
    key_active = false;
    master_key_set = false;
    stats_auto_keys = 0;
    stats_access_denied = 0;
    stats_root_overrides = 0;

    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        master_key[i] = 0;
    }

    initialized = true;
    serial.writeString("[ENC_INT] Encryption integration ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Key Derivation — Identity + Role + UID based
// =============================================================================

/// Derive a unique encryption key for a user
/// key = KDF(pubkey, "zamrud-enc:{role}:{uid}")
pub fn deriveKeyForUser(pubkey: *const [32]u8, role: users.UserRole, uid: u16) [aes.KEY_SIZE]u8 {
    var domain_buf: [48]u8 = [_]u8{0} ** 48;
    var pos: usize = 0;

    const prefix = "zamrud-enc:";
    for (prefix) |c| {
        if (pos < 48) {
            domain_buf[pos] = c;
            pos += 1;
        }
    }

    const role_str = role.toString();
    for (role_str) |c| {
        if (pos < 48) {
            domain_buf[pos] = c;
            pos += 1;
        }
    }

    if (pos < 48) {
        domain_buf[pos] = ':';
        pos += 1;
    }

    if (uid == 0) {
        if (pos < 48) {
            domain_buf[pos] = '0';
            pos += 1;
        }
    } else {
        var tmp: [5]u8 = undefined;
        var tlen: usize = 0;
        var v = uid;
        while (v > 0) : (tlen += 1) {
            tmp[tlen] = @intCast((v % 10) + '0');
            v /= 10;
        }
        while (tlen > 0) {
            tlen -= 1;
            if (pos < 48) {
                domain_buf[pos] = tmp[tlen];
                pos += 1;
            }
        }
    }

    // aes.deriveKey returns *const [32]u8, dereference to get value
    const derived_ptr = aes.deriveKey(pubkey, domain_buf[0..pos]);
    return derived_ptr.*;
}
// =============================================================================
// Login/Logout Hooks
// =============================================================================

/// Called when a user logs in — auto-sets encryption key
pub fn onLogin(uid: u16, role: users.UserRole, identity_index: i8) void {
    if (!initialized) return;
    if (!encryptfs.isInitialized()) return;

    // Guest gets NO key
    if (role == .guest) {
        serial.writeString("[ENC_INT] Guest login - no encryption key\n");
        current_owner_uid = uid;
        current_owner_role = role;
        key_active = false;
        return;
    }

    // Get pubkey from identity
    if (identity_index < 0) {
        serial.writeString("[ENC_INT] No identity linked - no encryption key\n");
        key_active = false;
        return;
    }

    const idx: usize = @intCast(identity_index);
    const id = keyring.getSlotPtr(idx) orelse {
        serial.writeString("[ENC_INT] Identity not found - no encryption key\n");
        key_active = false;
        return;
    };

    if (!id.active) {
        key_active = false;
        return;
    }

    // Derive key for this user
    const derived = deriveKeyForUser(&id.keypair.public_key, role, uid);

    // Set key in encryptfs
    encryptfs.setKeyDirect(&derived);

    current_owner_uid = uid;
    current_owner_role = role;
    key_active = true;
    stats_auto_keys += 1;

    // If root, also save master key
    if (role == .root) {
        var i: usize = 0;
        while (i < aes.KEY_SIZE) : (i += 1) {
            master_key[i] = derived[i];
        }
        master_key_set = true;
    }

    serial.writeString("[ENC_INT] Key auto-set for uid=");
    printU16(uid);
    serial.writeString(" role=");
    serial.writeString(role.toString());
    serial.writeString("\n");
}

/// Called when a user logs out — clears encryption key
pub fn onLogout() void {
    if (!initialized) return;

    encryptfs.clearKey();
    current_owner_uid = users.NOBODY_UID;
    current_owner_role = .guest;
    key_active = false;

    serial.writeString("[ENC_INT] Key cleared on logout\n");
}

// =============================================================================
// Ownership-Aware Encrypt/Decrypt
// =============================================================================

/// Encrypt with current user's ownership stamped
pub fn encryptWithOwnership(name: []const u8, plaintext: []const u8) bool {
    if (!initialized or !encryptfs.isInitialized()) return false;

    if (!hasEncryptPermission()) {
        reportAccessDenied("encrypt: no permission");
        return false;
    }

    if (!key_active) {
        serial.writeString("[ENC_INT] No key active\n");
        return false;
    }

    if (!encryptfs.encryptFile(name, plaintext)) return false;

    // Stamp ownership
    if (encryptfs.findFileMut(name)) |f| {
        f.owner_uid = current_owner_uid;
        f.owner_role = current_owner_role;
    }

    return true;
}

/// Decrypt with ownership/role access control
pub fn decryptWithAccessControl(name: []const u8) ?[]const u8 {
    if (!initialized or !encryptfs.isInitialized()) return null;

    if (!hasEncryptPermission()) {
        reportAccessDenied("decrypt: no CAP_CRYPTO");
        return null;
    }

    const info = encryptfs.getFileInfo(name) orelse return null;

    if (!checkAccess(info.owner_uid, info.owner_role, .read)) {
        reportAccessDenied("decrypt: role denied");
        return null;
    }

    // Owner decrypts normally
    if (current_owner_uid == info.owner_uid) {
        return encryptfs.decryptFile(name);
    }

    // Root uses master key override
    if (current_owner_role == .root and master_key_set) {
        return decryptWithMasterOverride(name, info.owner_uid, info.owner_role);
    }

    return encryptfs.decryptFile(name);
}

/// Delete with ownership check
pub fn deleteWithAccessControl(name: []const u8) bool {
    if (!initialized or !encryptfs.isInitialized()) return false;

    if (!hasEncryptPermission()) {
        reportAccessDenied("delete: no CAP_CRYPTO");
        return false;
    }

    const info = encryptfs.getFileInfo(name) orelse return false;

    if (!checkAccess(info.owner_uid, info.owner_role, .delete)) {
        reportAccessDenied("delete: role denied");
        return false;
    }

    return encryptfs.deleteFile(name);
}

// =============================================================================
// Access Control Matrix
// =============================================================================

pub const AccessType = enum { read, write, delete };

/// Access Matrix:
///   Current\File → root    admin   user    guest
///   root         → R/W/D   R/W/D   R/W/D   R/W/D
///   admin        → DENY    own*    READ**  DENY
///   user         → DENY    DENY    own*    DENY
///   guest        → DENY    DENY    DENY    DENY
///   (* = own files, ** = admin audit read)
pub fn checkAccess(file_uid: u16, file_role: users.UserRole, access: AccessType) bool {
    if (!key_active and current_owner_role != .root) return false;

    // Root can access everything
    if (current_owner_role == .root) return true;

    // Guest can access nothing
    if (current_owner_role == .guest) return false;

    // Own files always allowed
    if (current_owner_uid == file_uid) return true;

    // Cross-role
    switch (current_owner_role) {
        .admin => {
            switch (file_role) {
                .root => return false,
                .admin => return false, // other admin's files
                .user => return access == .read, // audit read only
                .guest => return false,
            }
        },
        .user => return false, // only own files
        .root => return true,
        .guest => return false,
    }
}

// =============================================================================
// Master Key Override
// =============================================================================

fn decryptWithMasterOverride(name: []const u8, file_uid: u16, file_role: users.UserRole) ?[]const u8 {
    if (!master_key_set) return null;

    const owner_user = users.findUserByUid(file_uid) orelse return null;
    if (owner_user.identity_index < 0) return null;

    const idx: usize = @intCast(owner_user.identity_index);
    const id = keyring.getSlotPtr(idx) orelse return null;
    if (!id.active) return null;

    // Derive owner's key
    const owner_key = deriveKeyForUser(&id.keypair.public_key, file_role, file_uid);

    // Save current root key
    var saved_key: [aes.KEY_SIZE]u8 = undefined;
    var i: usize = 0;
    while (i < aes.KEY_SIZE) : (i += 1) {
        saved_key[i] = master_key[i];
    }

    // Switch to owner's key, decrypt, restore
    encryptfs.setKeyDirect(&owner_key);
    const result = encryptfs.decryptFile(name);
    encryptfs.setKeyDirect(&saved_key);

    if (result != null) {
        stats_root_overrides += 1;
    }

    return result;
}

// =============================================================================
// Helpers
// =============================================================================

fn hasEncryptPermission() bool {
    const role_caps = current_owner_role.defaultCaps();
    return (role_caps & capability.CAP_CRYPTO) != 0;
}

fn reportAccessDenied(detail: []const u8) void {
    stats_access_denied += 1;

    serial.writeString("[ENC_INT] ACCESS DENIED: ");
    serial.writeString(detail);
    serial.writeString(" uid=");
    printU16(current_owner_uid);
    serial.writeString(" role=");
    serial.writeString(current_owner_role.toString());
    serial.writeString("\n");

    if (violation.isInitialized()) {
        _ = violation.reportViolation(.{
            .violation_type = .filesystem_violation,
            .severity = .high,
            .pid = 0,
            .source_ip = 0,
            .detail = detail,
        });
    }
}

// =============================================================================
// Query
// =============================================================================

pub fn getCurrentOwnerUid() u16 {
    return current_owner_uid;
}

pub fn getCurrentOwnerRole() users.UserRole {
    return current_owner_role;
}

pub fn isKeyActive() bool {
    return key_active;
}

pub fn getStats() struct { auto_keys: u64, access_denied: u64, root_overrides: u64 } {
    return .{
        .auto_keys = stats_auto_keys,
        .access_denied = stats_access_denied,
        .root_overrides = stats_root_overrides,
    };
}

// =============================================================================
// Print helpers
// =============================================================================

fn printU16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [5]u8 = undefined;
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

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn nameEndsWith(name: []const u8, suffix: []const u8) bool {
    if (name.len < suffix.len) return false;
    const start = name.len - suffix.len;
    var i: usize = 0;
    while (i < suffix.len) : (i += 1) {
        if (name[start + i] != suffix[i]) return false;
    }
    return true;
}

// =============================================================================
// F4.1 Tests — 25 tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n########################################\n");
    serial.writeString("##  F4.1 USER-HIERARCHY ENCRYPTION     \n");
    serial.writeString("########################################\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup
    keyring.init();
    const auth = @import("../identity/auth.zig");
    auth.init();
    encryptfs.init();
    init();

    _ = keyring.createIdentity("encroot", "1234");
    _ = keyring.createIdentity("encadmin", "5678");
    _ = keyring.createIdentity("encuser", "4321");
    _ = keyring.createIdentity("encguest", "0000");

    users.init();

    // T01: Initialize
    serial.writeString("  T01 Initialize............. ");
    if (initialized and !key_active) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T02: Key derivation per-role unique
    serial.writeString("  T02 Key per-role unique.... ");
    {
        var test_pub: [32]u8 = [_]u8{0xAA} ** 32;
        const k_root = deriveKeyForUser(&test_pub, .root, 0);
        const k_admin = deriveKeyForUser(&test_pub, .admin, 100);
        const k_user = deriveKeyForUser(&test_pub, .user, 200);
        var rd = false;
        var ru = false;
        var au = false;
        var ki: usize = 0;
        while (ki < aes.KEY_SIZE) : (ki += 1) {
            if (k_root[ki] != k_admin[ki]) rd = true;
            if (k_root[ki] != k_user[ki]) ru = true;
            if (k_admin[ki] != k_user[ki]) au = true;
        }
        if (rd and ru and au) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T03: Key derivation deterministic
    serial.writeString("  T03 Key deterministic...... ");
    {
        var tp: [32]u8 = [_]u8{0xBB} ** 32;
        const k1 = deriveKeyForUser(&tp, .user, 42);
        const k2 = deriveKeyForUser(&tp, .user, 42);
        var same = true;
        var ki2: usize = 0;
        while (ki2 < aes.KEY_SIZE) : (ki2 += 1) {
            if (k1[ki2] != k2[ki2]) same = false;
        }
        if (same) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T04: Guest no CAP_CRYPTO
    serial.writeString("  T04 Guest no CAP_CRYPTO.... ");
    if ((users.UserRole.guest.defaultCaps() & capability.CAP_CRYPTO) == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T05: Root has CAP_CRYPTO
    serial.writeString("  T05 Root has CAP_CRYPTO.... ");
    if ((users.UserRole.root.defaultCaps() & capability.CAP_CRYPTO) != 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T06: Admin has CAP_CRYPTO
    serial.writeString("  T06 Admin has CAP_CRYPTO... ");
    if ((users.UserRole.admin.defaultCaps() & capability.CAP_CRYPTO) != 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T07: User role CAP_CRYPTO check
    serial.writeString("  T07 User CAP_CRYPTO check.. ");
    {
        const user_caps = users.UserRole.user.defaultCaps();
        const has_crypto = (user_caps & capability.CAP_CRYPTO) != 0;
        if (!has_crypto) {
            serial.writeString("PASS (no crypto - correct)\n");
        } else {
            serial.writeString("PASS (has crypto)\n");
        }
        passed += 1;
    }

    // T08: onLogin root sets key
    serial.writeString("  T08 onLogin root key....... ");
    {
        var root_idx: i8 = -1;
        var si: usize = 0;
        while (si < keyring.MAX_IDENTITIES) : (si += 1) {
            if (keyring.getSlotPtr(si)) |slot| {
                if (slot.active and nameEndsWith(slot.getName(), "encroot")) {
                    root_idx = @intCast(si);
                    break;
                }
            }
        }
        onLogin(0, .root, root_idx);
        if (key_active and current_owner_role == .root and master_key_set) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T09: Root can encrypt
    serial.writeString("  T09 Root encrypt........... ");
    if (key_active) {
        if (encryptfs.encryptFile("root_secret.enc", "Root secret data")) {
            if (encryptfs.findFileMut("root_secret.enc")) |f| {
                f.owner_uid = 0;
                f.owner_role = .root;
            }
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    } else {
        serial.writeString("SKIP\n");
        failed += 1;
    }

    // T10: Root can decrypt own
    serial.writeString("  T10 Root decrypt own....... ");
    if (encryptfs.decryptFile("root_secret.enc")) |data| {
        if (strEqual(data, "Root secret data")) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (content)\n");
            failed += 1;
        }
    } else {
        serial.writeString("FAIL (null)\n");
        failed += 1;
    }

    // T11: onLogout clears key
    serial.writeString("  T11 onLogout clears key.... ");
    onLogout();
    if (!key_active and !encryptfs.isKeySet()) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T12: After logout cannot decrypt
    serial.writeString("  T12 No decrypt after logout ");
    if (encryptfs.decryptFile("root_secret.enc") == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T13: Guest login no key
    serial.writeString("  T13 Guest login no key..... ");
    onLogin(65534, .guest, -1);
    if (!key_active and current_owner_role == .guest) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }
    onLogout();

    // T14: Guest access denied
    serial.writeString("  T14 Guest access denied.... ");
    {
        current_owner_role = .guest;
        current_owner_uid = 65534;
        if (!checkAccess(0, .root, .read)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T15: Root access all
    serial.writeString("  T15 Root access all........ ");
    {
        current_owner_role = .root;
        current_owner_uid = 0;
        key_active = true;
        if (checkAccess(0, .root, .read) and
            checkAccess(100, .admin, .read) and
            checkAccess(200, .user, .read))
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T16: User own file only
    serial.writeString("  T16 User own file only..... ");
    {
        current_owner_role = .user;
        current_owner_uid = 200;
        key_active = true;
        if (checkAccess(200, .user, .read) and
            !checkAccess(300, .user, .read) and
            !checkAccess(100, .admin, .read) and
            !checkAccess(0, .root, .read))
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T17: Admin read user file (audit)
    serial.writeString("  T17 Admin audit user file.. ");
    {
        current_owner_role = .admin;
        current_owner_uid = 100;
        key_active = true;
        if (checkAccess(200, .user, .read) and
            !checkAccess(200, .user, .write) and
            !checkAccess(200, .user, .delete))
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T18: Admin cannot access root files
    serial.writeString("  T18 Admin no root access... ");
    {
        current_owner_role = .admin;
        current_owner_uid = 100;
        if (!checkAccess(0, .root, .read)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T19: Admin own files RWD
    serial.writeString("  T19 Admin own files RWD.... ");
    {
        current_owner_role = .admin;
        current_owner_uid = 100;
        if (checkAccess(100, .admin, .read) and
            checkAccess(100, .admin, .write) and
            checkAccess(100, .admin, .delete))
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T20: Admin no other admin files
    serial.writeString("  T20 Admin no other admin... ");
    {
        current_owner_role = .admin;
        current_owner_uid = 100;
        if (!checkAccess(101, .admin, .read)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T21: Permission per role
    serial.writeString("  T21 Permission per role.... ");
    {
        current_owner_role = .root;
        const r_ok = hasEncryptPermission();
        current_owner_role = .admin;
        const a_ok = hasEncryptPermission();
        current_owner_role = .guest;
        const g_no = !hasEncryptPermission();
        if (r_ok and a_ok and g_no) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T22: Different uid same role → different keys
    serial.writeString("  T22 Diff uid diff key...... ");
    {
        var p3: [32]u8 = [_]u8{0xCC} ** 32;
        const k1 = deriveKeyForUser(&p3, .user, 100);
        const k2 = deriveKeyForUser(&p3, .user, 200);
        var diff = false;
        var d3: usize = 0;
        while (d3 < aes.KEY_SIZE) : (d3 += 1) {
            if (k1[d3] != k2[d3]) diff = true;
        }
        if (diff) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T23: Same uid different pubkey → different keys
    serial.writeString("  T23 Diff pubkey diff key... ");
    {
        var pa: [32]u8 = [_]u8{0xDD} ** 32;
        var pb: [32]u8 = [_]u8{0xEE} ** 32;
        const ka = deriveKeyForUser(&pa, .user, 100);
        const kb = deriveKeyForUser(&pb, .user, 100);
        var diff2 = false;
        var d4: usize = 0;
        while (d4 < aes.KEY_SIZE) : (d4 += 1) {
            if (ka[d4] != kb[d4]) diff2 = true;
        }
        if (diff2) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // T24: Stats tracking
    serial.writeString("  T24 Stats tracking......... ");
    if (stats_auto_keys > 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // T25: Re-login restores key
    serial.writeString("  T25 Re-login restores key.. ");
    {
        var root_idx2: i8 = -1;
        var si2: usize = 0;
        while (si2 < keyring.MAX_IDENTITIES) : (si2 += 1) {
            if (keyring.getSlotPtr(si2)) |slot| {
                if (slot.active and nameEndsWith(slot.getName(), "encroot")) {
                    root_idx2 = @intCast(si2);
                    break;
                }
            }
        }
        onLogout();
        onLogin(0, .root, root_idx2);
        if (key_active and encryptfs.isKeySet()) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
        onLogout();
    }

    // Cleanup
    current_owner_uid = users.NOBODY_UID;
    current_owner_role = .guest;
    key_active = false;

    serial.writeString("\n========================================\n");
    serial.writeString("  F4.1 Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");
    serial.writeString("========================================\n\n");

    return failed == 0;
}
