//! Zamrud OS - Identity Authentication
//! H.7.1 UPDATED: Dual credential support (Password + optional PIN)
//! H.8 UPDATED: Threat scoring integration for auth failures

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const crypto = @import("../crypto/crypto.zig");
const constant_time = @import("../crypto/constant_time.zig");
const keyring = @import("keyring.zig");

// ============================================================================
// H.8 Integration
// ============================================================================
const threat_score = @import("../security/threat_score.zig");
const threat_log = @import("../security/threat_log.zig"); // ⭐ TAMBAHKAN INI

// =============================================================================
// Security Constants
// =============================================================================

pub const PIN_MIN_LEN: usize = keyring.PIN_MIN_LEN;
pub const PIN_MAX_LEN: usize = keyring.PIN_MAX_LEN;
pub const PASSWORD_MIN_LEN: usize = keyring.PASSWORD_MIN_LEN;
pub const PASSWORD_MAX_LEN: usize = keyring.CREDENTIAL_MAX_LEN;

pub const MAX_ATTEMPTS: u32 = 5;
pub const LOCKOUT_ATTEMPTS: u32 = 10;

pub const DELAY_BASE: u32 = 1;
pub const DELAY_MULTIPLIER: u32 = 2;

// =============================================================================
// Types
// =============================================================================

pub const AuthType = enum(u8) {
    none = 0,
    pin = 1,
    password = 2,
    hardware_key = 3,
};

pub const LockoutState = enum(u8) {
    normal = 0,
    soft_lock = 1,
    hard_lock = 2,
};

pub const UnlockMethod = enum(u8) {
    password = 0,
    pin = 1,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var current_unlocked: bool = false;
var auth_attempts: u32 = 0;
var auth_failures: u32 = 0;
var consecutive_failures: u32 = 0;
var last_attempt_time: u32 = 0;
var lockout_state: LockoutState = .normal;
var lockout_until: u32 = 0;

var unlocked_privkey: [32]u8 = [_]u8{0} ** 32;
var has_unlocked_key: bool = false;

var lock_timeout: u32 = 300;

// H.7.1: Track how user unlocked (for UI feedback)
var last_unlock_method: UnlockMethod = .password;

// H.8: Track source IP for threat scoring (set by caller)
var current_source_ip: u32 = 0;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[AUTH] Initializing...\n");

    current_unlocked = false;
    auth_attempts = 0;
    auth_failures = 0;
    consecutive_failures = 0;
    has_unlocked_key = false;
    lockout_state = .normal;
    lockout_until = 0;
    last_unlock_method = .password;
    current_source_ip = 0;

    clearPrivateKey();

    initialized = true;
    serial.writeString("[AUTH] Initialized (H.7.1 dual-credential, H.8 threat-scoring)\n");
}

fn clearPrivateKey() void {
    constant_time.secureZero32(&unlocked_privkey);
    has_unlocked_key = false;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isLockedOut() bool {
    return lockout_state != .normal;
}

pub fn getLockoutState() LockoutState {
    return lockout_state;
}

/// H.8: Set source IP for threat scoring (call before unlock attempts)
pub fn setSourceIP(ip: u32) void {
    current_source_ip = ip;
}

pub fn getRemainingLockout(current_time: u32) u32 {
    if (lockout_state == .normal) return 0;
    if (lockout_state == .hard_lock) return 0xFFFFFFFF;
    if (current_time >= lockout_until) {
        lockout_state = .normal;
        return 0;
    }
    return lockout_until - current_time;
}

fn getAttemptDelay() u32 {
    if (consecutive_failures == 0) return 0;
    var delay: u32 = DELAY_BASE;
    var i: u32 = 0;
    while (i < consecutive_failures and i < 10) : (i += 1) {
        delay *= DELAY_MULTIPLIER;
    }
    return delay;
}

fn recordFailure(current_time: u32) void {
    auth_failures += 1;
    consecutive_failures += 1;
    last_attempt_time = current_time;

    // ⭐ H.8 INTEGRATION: Record auth failure to threat scoring
    if (current_source_ip != 0) {
        // Determine severity based on consecutive failures
        const severity: threat_log.ThreatSeverity = if (consecutive_failures >= LOCKOUT_ATTEMPTS)
            .critical
        else if (consecutive_failures >= MAX_ATTEMPTS)
            .high
        else if (consecutive_failures >= 3)
            .medium
        else
            .low;

        // Determine event type
        const event_type: threat_score.EventType = if (consecutive_failures >= 5)
            .brute_force
        else
            .auth_failure;

        _ = threat_score.recordEvent(current_source_ip, event_type, severity);
    }

    if (consecutive_failures >= LOCKOUT_ATTEMPTS) {
        lockout_state = .hard_lock;
        serial.writeString("[AUTH] LOCKED - Too many failures. Use seed phrase to recover.\n");
    } else if (consecutive_failures >= MAX_ATTEMPTS) {
        lockout_state = .soft_lock;
        lockout_until = current_time + getAttemptDelay();
        serial.writeString("[AUTH] Temporarily locked. Please wait.\n");
    }
}

fn recordSuccess() void {
    consecutive_failures = 0;
    lockout_state = .normal;
    lockout_until = 0;
    // Note: Don't reset source_ip here - might be needed for session tracking
}

/// Unlock identity with credential (auto-detects PIN or password)
/// H.7.1: Tries PIN first if looks like PIN and identity has PIN setup
pub fn unlock(name: []const u8, credential: []const u8) bool {
    const current_time: u32 = 1700000000; // TODO: real timestamp

    auth_attempts += 1;

    if (lockout_state == .hard_lock) {
        serial.writeString("[AUTH] Account locked. Use seed phrase to recover.\n");

        // ⭐ H.8: Record attempt while locked (likely attack)
        if (current_source_ip != 0) {
            _ = threat_score.recordEvent(current_source_ip, .brute_force, .high);
        }

        return false;
    }

    if (lockout_state == .soft_lock) {
        if (current_time < lockout_until) {
            serial.writeString("[AUTH] Please wait before retrying.\n");
            return false;
        }
        lockout_state = .normal;
    }

    const id = keyring.findIdentity(name);
    if (id == null) {
        recordFailure(current_time);
        return false;
    }

    // H.7.1: Try PIN first if it looks like a PIN and identity has PIN
    if (id.?.has_pin and keyring.looksLikePin(credential)) {
        if (keyring.decryptPrivateKeyWithPin(id.?, credential, &unlocked_privkey)) {
            // Success via PIN!
            recordSuccess();
            id.?.unlocked = true;
            id.?.last_used = current_time;
            current_unlocked = true;
            has_unlocked_key = true;
            last_unlock_method = .pin;

            _ = keyring.setCurrentIdentity(name);

            serial.writeString("[AUTH] Unlocked via PIN\n");
            return true;
        }
        // PIN failed — continue to try as password (user might have mistyped)
    }

    // Try as password
    if (keyring.decryptPrivateKey(id.?, credential, &unlocked_privkey)) {
        // Success via password!
        recordSuccess();
        id.?.unlocked = true;
        id.?.last_used = current_time;
        current_unlocked = true;
        has_unlocked_key = true;
        last_unlock_method = .password;

        _ = keyring.setCurrentIdentity(name);

        serial.writeString("[AUTH] Unlocked via password\n");
        return true;
    }

    // Both failed
    recordFailure(current_time);
    return false;
}

/// Unlock explicitly with PIN (skips password fallback)
pub fn unlockWithPin(name: []const u8, pin: []const u8) bool {
    const current_time: u32 = 1700000000;

    auth_attempts += 1;

    if (lockout_state != .normal) {
        // ⭐ H.8: Record attempt while locked
        if (current_source_ip != 0) {
            _ = threat_score.recordEvent(current_source_ip, .brute_force, .high);
        }
        return false;
    }

    const id = keyring.findIdentity(name);
    if (id == null) {
        recordFailure(current_time);
        return false;
    }

    if (!id.?.has_pin) {
        serial.writeString("[AUTH] No PIN configured for this identity\n");
        return false;
    }

    if (keyring.decryptPrivateKeyWithPin(id.?, pin, &unlocked_privkey)) {
        recordSuccess();
        id.?.unlocked = true;
        id.?.last_used = current_time;
        current_unlocked = true;
        has_unlocked_key = true;
        last_unlock_method = .pin;

        _ = keyring.setCurrentIdentity(name);
        return true;
    }

    recordFailure(current_time);
    return false;
}

/// Unlock explicitly with password
pub fn unlockWithPassword(name: []const u8, password: []const u8) bool {
    const current_time: u32 = 1700000000;

    auth_attempts += 1;

    if (lockout_state != .normal) {
        // ⭐ H.8: Record attempt while locked
        if (current_source_ip != 0) {
            _ = threat_score.recordEvent(current_source_ip, .brute_force, .high);
        }
        return false;
    }

    const id = keyring.findIdentity(name);
    if (id == null) {
        recordFailure(current_time);
        return false;
    }

    if (keyring.decryptPrivateKey(id.?, password, &unlocked_privkey)) {
        recordSuccess();
        id.?.unlocked = true;
        id.?.last_used = current_time;
        current_unlocked = true;
        has_unlocked_key = true;
        last_unlock_method = .password;

        _ = keyring.setCurrentIdentity(name);
        return true;
    }

    recordFailure(current_time);
    return false;
}

/// H.7: Unlock with seed phrase (recovery from hard lock)
pub fn unlockWithSeedPhrase(name: []const u8, seed_phrase: []const u8, new_credential: []const u8) bool {
    _ = name;
    _ = seed_phrase;
    _ = new_credential;

    // Reset lockout regardless — seed phrase is ultimate authority
    lockout_state = .normal;
    consecutive_failures = 0;
    lockout_until = 0;

    serial.writeString("[AUTH] Seed phrase recovery: lockout reset\n");
    return false; // Full recovery not yet implemented
}

pub fn lock() void {
    clearPrivateKey();
    current_unlocked = false;

    const current = keyring.getCurrentIdentity();
    if (current != null) {
        current.?.unlocked = false;
    }
}

pub fn isUnlocked() bool {
    return current_unlocked and has_unlocked_key;
}

pub fn getPrivateKey() ?*const [32]u8 {
    if (!has_unlocked_key) return null;
    return &unlocked_privkey;
}

/// Get how user unlocked (PIN or password)
pub fn getLastUnlockMethod() UnlockMethod {
    return last_unlock_method;
}

/// Check if current identity has PIN configured
pub fn hasPinConfigured() bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    return current.?.has_pin;
}

// =============================================================================
// PIN Management (convenience wrappers)
// =============================================================================

/// Setup PIN for current identity (requires password verification)
pub fn setupPin(password: []const u8, new_pin: []const u8) bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.setupSecondaryPin(current.?, password, new_pin);
}

/// Remove PIN from current identity (requires password verification)
pub fn removePin(password: []const u8) bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.removeSecondaryPin(current.?, password);
}

/// Change PIN for current identity (requires password verification)
pub fn changePin(password: []const u8, new_pin: []const u8) bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.changeSecondaryPin(current.?, password, new_pin);
}

// =============================================================================
// Password Management
// =============================================================================

/// Change password for current identity
pub fn changePassword(old_password: []const u8, new_password: []const u8) bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.reEncryptPrivateKey(current.?, old_password, new_password);
}

/// Legacy alias
pub fn changeCredential(old_credential: []const u8, new_credential: []const u8) bool {
    return changePassword(old_credential, new_credential);
}

/// Legacy alias
pub fn changePin_legacy(old_pin: []const u8, new_pin: []const u8) bool {
    return changeCredential(old_pin, new_pin);
}

pub fn updateActivity() void {
    // TODO: real timestamp
}

pub fn shouldAutoLock(current_time: u32) bool {
    _ = current_time;
    if (lock_timeout == 0) return false;
    if (!current_unlocked) return false;
    return false;
}

pub fn setLockTimeout(seconds: u32) void {
    lock_timeout = seconds;
}

pub fn getAttempts() u32 {
    return auth_attempts;
}

pub fn getFailures() u32 {
    return auth_failures;
}

pub fn getConsecutiveFailures() u32 {
    return consecutive_failures;
}

// =============================================================================
// Credential Validation
// =============================================================================

pub fn isValidPin(credential: []const u8) bool {
    return keyring.isValidPin(credential);
}

pub fn isValidPassword(credential: []const u8) bool {
    if (credential.len < PASSWORD_MIN_LEN or credential.len > PASSWORD_MAX_LEN) return false;
    return keyring.isStrongPassword(credential);
}

pub fn getCredentialStrength(credential: []const u8) u8 {
    if (credential.len == 0) return 0;

    var score: u32 = 0;

    if (credential.len >= 4) score += 10;
    if (credential.len >= 6) score += 10;
    if (credential.len >= 8) score += 20;
    if (credential.len >= 12) score += 20;
    if (credential.len >= 16) score += 10;

    var has_lower = false;
    var has_upper = false;
    var has_digit = false;
    var has_special = false;

    for (credential) |c| {
        if (c >= 'a' and c <= 'z') has_lower = true else if (c >= 'A' and c <= 'Z') has_upper = true else if (c >= '0' and c <= '9') has_digit = true else has_special = true;
    }

    if (has_lower) score += 10;
    if (has_upper) score += 10;
    if (has_digit) score += 5;
    if (has_special) score += 15;

    if (score > 100) score = 100;
    return @intCast(score);
}

// =============================================================================
// Test
// =============================================================================

pub fn test_auth() bool {
    serial.writeString("\n=== Auth Test (H.7.1 Dual Credential + H.8) ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    keyring.init();
    _ = keyring.createIdentityWithPassword("testuser", "SecurePass1");

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and !current_unlocked) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Set source IP for H.8
    serial.writeString("  Test 2: Set source IP (H.8)\n");
    setSourceIP(0xC0A80101); // 192.168.1.1
    if (current_source_ip == 0xC0A80101) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Unlock with password
    serial.writeString("  Test 3: Unlock with password\n");
    if (unlock("testuser", "SecurePass1")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Last unlock method is password
    serial.writeString("  Test 4: Unlock method = password\n");
    if (getLastUnlockMethod() == .password) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Setup PIN
    serial.writeString("  Test 5: Setup PIN\n");
    if (setupPin("SecurePass1", "1234")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: hasPinConfigured
    serial.writeString("  Test 6: hasPinConfigured\n");
    if (hasPinConfigured()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Lock
    serial.writeString("  Test 7: Lock\n");
    lock();
    if (!isUnlocked()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 8: Unlock with PIN
    serial.writeString("  Test 8: Unlock with PIN\n");
    if (unlock("testuser", "1234")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 9: Last unlock method is PIN
    serial.writeString("  Test 9: Unlock method = PIN\n");
    if (getLastUnlockMethod() == .pin) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 10: Lock again
    lock();

    // Test 11: Password still works
    serial.writeString("  Test 10: Password still works\n");
    if (unlock("testuser", "SecurePass1")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 12: Remove PIN
    serial.writeString("  Test 11: Remove PIN\n");
    if (removePin("SecurePass1") and !hasPinConfigured()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 13: H.8 auth failure recording
    serial.writeString("  Test 12: H.8 auth failure (bad password)\n");
    lock();
    setSourceIP(0xC0A80102); // Different IP
    const before_failures = auth_failures;
    _ = unlock("testuser", "WrongPassword");
    if (auth_failures == before_failures + 1) {
        serial.writeString("    OK (failure recorded)\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  AUTH (H.7.1+H.8): ");
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
