//! Zamrud OS - Identity Authentication
//! PIN/Password-based authentication with brute-force protection

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const crypto = @import("../crypto/crypto.zig");
const keyring = @import("keyring.zig");

// =============================================================================
// Security Constants
// =============================================================================

pub const PIN_MIN_LEN: usize = 4;
pub const PIN_MAX_LEN: usize = 8;
pub const PASSWORD_MIN_LEN: usize = 8;
pub const PASSWORD_MAX_LEN: usize = 64;

pub const MAX_ATTEMPTS: u32 = 5; // Before lockout
pub const LOCKOUT_ATTEMPTS: u32 = 10; // Require seed phrase
pub const PBKDF2_ITERATIONS: u32 = 100000; // Key stretching iterations

// Delay between attempts (in "ticks" - simplified)
pub const DELAY_BASE: u32 = 1; // Base delay
pub const DELAY_MULTIPLIER: u32 = 2; // Exponential backoff

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
    soft_lock = 1, // Temporary, wait and retry
    hard_lock = 2, // Need seed phrase to unlock
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

// Decrypted private key (only in memory when unlocked)
var unlocked_privkey: [32]u8 = [_]u8{0} ** 32;
var has_unlocked_key: bool = false;

// Auto-lock timeout (seconds, 0 = disabled)
var lock_timeout: u32 = 300; // 5 minutes default

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

    // Clear any leftover key material
    clearPrivateKey();

    initialized = true;
    serial.writeString("[AUTH] Initialized\n");
}

fn clearPrivateKey() void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        unlocked_privkey[i] = 0;
    }
    has_unlocked_key = false;
}

/// Check if currently locked out
pub fn isLockedOut() bool {
    return lockout_state != .normal;
}

/// Get lockout state
pub fn getLockoutState() LockoutState {
    return lockout_state;
}

/// Get remaining lockout time (simplified)
pub fn getRemainingLockout(current_time: u32) u32 {
    if (lockout_state == .normal) return 0;
    if (lockout_state == .hard_lock) return 0xFFFFFFFF; // Infinite until seed phrase
    if (current_time >= lockout_until) {
        lockout_state = .normal;
        return 0;
    }
    return lockout_until - current_time;
}

/// Calculate delay before next attempt allowed
fn getAttemptDelay() u32 {
    if (consecutive_failures == 0) return 0;

    // Exponential backoff: 1, 2, 4, 8, 16, 32...
    var delay: u32 = DELAY_BASE;
    var i: u32 = 0;
    while (i < consecutive_failures and i < 10) : (i += 1) {
        delay *= DELAY_MULTIPLIER;
    }
    return delay;
}

/// Record failed attempt and update lockout
fn recordFailure(current_time: u32) void {
    auth_failures += 1;
    consecutive_failures += 1;
    last_attempt_time = current_time;

    if (consecutive_failures >= LOCKOUT_ATTEMPTS) {
        // Hard lock - need seed phrase
        lockout_state = .hard_lock;
        serial.writeString("[AUTH] LOCKED - Too many failures. Use seed phrase to recover.\n");
    } else if (consecutive_failures >= MAX_ATTEMPTS) {
        // Soft lock with delay
        lockout_state = .soft_lock;
        lockout_until = current_time + getAttemptDelay();
        serial.writeString("[AUTH] Temporarily locked. Please wait.\n");
    }
}

/// Reset after successful auth
fn recordSuccess() void {
    consecutive_failures = 0;
    lockout_state = .normal;
    lockout_until = 0;
}

/// Unlock identity with PIN or password
pub fn unlock(name: []const u8, credential: []const u8) bool {
    const current_time: u32 = 1700000000; // TODO: real timestamp

    auth_attempts += 1;

    // Check lockout
    if (lockout_state == .hard_lock) {
        serial.writeString("[AUTH] Account locked. Use seed phrase to recover.\n");
        return false;
    }

    if (lockout_state == .soft_lock) {
        if (current_time < lockout_until) {
            serial.writeString("[AUTH] Please wait before retrying.\n");
            return false;
        }
        // Lockout expired
        lockout_state = .normal;
    }

    const id = keyring.findIdentity(name);
    if (id == null) {
        recordFailure(current_time);
        return false;
    }

    // Try to decrypt private key with credential
    if (!keyring.decryptPrivateKey(id.?, credential, &unlocked_privkey)) {
        recordFailure(current_time);
        return false;
    }

    // Success!
    recordSuccess();
    id.?.unlocked = true;
    id.?.last_used = current_time;
    current_unlocked = true;
    has_unlocked_key = true;

    // Set as current identity
    _ = keyring.setCurrentIdentity(name);

    return true;
}

/// Unlock with seed phrase (recovery from hard lock)
pub fn unlockWithSeedPhrase(name: []const u8, seed_phrase: []const u8, new_credential: []const u8) bool {
    _ = name;
    _ = seed_phrase;
    _ = new_credential;

    // TODO: Implement seed phrase recovery
    // 1. Derive private key from seed phrase
    // 2. Verify it matches the public key
    // 3. Re-encrypt with new credential
    // 4. Reset lockout state

    lockout_state = .normal;
    consecutive_failures = 0;

    serial.writeString("[AUTH] Seed phrase recovery not yet implemented\n");
    return false;
}

/// Lock current session
pub fn lock() void {
    clearPrivateKey();
    current_unlocked = false;

    // Mark current identity as locked
    const current = keyring.getCurrentIdentity();
    if (current != null) {
        current.?.unlocked = false;
    }
}

/// Check if currently unlocked
pub fn isUnlocked() bool {
    return current_unlocked and has_unlocked_key;
}

/// Get unlocked private key (only if unlocked!)
pub fn getPrivateKey() ?*const [32]u8 {
    if (!has_unlocked_key) return null;
    return &unlocked_privkey;
}

/// Change PIN/password for current identity
pub fn changePin(old_credential: []const u8, new_credential: []const u8) bool {
    _ = new_credential; // TODO: implement re-encryption

    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false;

    // Verify old credential first
    var temp_key: [32]u8 = [_]u8{0} ** 32;
    if (!keyring.decryptPrivateKey(current.?, old_credential, &temp_key)) {
        return false;
    }

    // TODO: Re-encrypt with new credential
    // For now, just verify old credential works

    // Clear temp
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        temp_key[i] = 0;
    }

    return true;
}

/// Update activity timestamp (for auto-lock)
pub fn updateActivity() void {
    // TODO: real timestamp
}

/// Check if should auto-lock
pub fn shouldAutoLock(current_time: u32) bool {
    _ = current_time;
    if (lock_timeout == 0) return false;
    if (!current_unlocked) return false;

    // TODO: implement with real timestamps
    return false;
}

/// Set auto-lock timeout (0 to disable)
pub fn setLockTimeout(seconds: u32) void {
    lock_timeout = seconds;
}

/// Get auth statistics
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

/// Check if credential is a valid PIN (4-8 digits)
pub fn isValidPin(credential: []const u8) bool {
    if (credential.len < PIN_MIN_LEN or credential.len > PIN_MAX_LEN) return false;

    var i: usize = 0;
    while (i < credential.len) : (i += 1) {
        if (credential[i] < '0' or credential[i] > '9') return false;
    }

    return true;
}

/// Check if credential is a valid password (8+ chars, mixed)
pub fn isValidPassword(credential: []const u8) bool {
    if (credential.len < PASSWORD_MIN_LEN or credential.len > PASSWORD_MAX_LEN) return false;

    var has_lower = false;
    var has_upper = false;
    var has_digit = false;

    var i: usize = 0;
    while (i < credential.len) : (i += 1) {
        const c = credential[i];
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
        if (c >= '0' and c <= '9') has_digit = true;
    }

    // Require at least 2 of 3 character types
    var types: u8 = 0;
    if (has_lower) types += 1;
    if (has_upper) types += 1;
    if (has_digit) types += 1;

    return types >= 2;
}

/// Get credential strength (0-100)
pub fn getCredentialStrength(credential: []const u8) u8 {
    if (credential.len == 0) return 0;

    var score: u32 = 0;

    // Length score
    if (credential.len >= 4) score += 10;
    if (credential.len >= 6) score += 10;
    if (credential.len >= 8) score += 20;
    if (credential.len >= 12) score += 20;
    if (credential.len >= 16) score += 10;

    // Character variety
    var has_lower = false;
    var has_upper = false;
    var has_digit = false;
    var has_special = false;

    var i: usize = 0;
    while (i < credential.len) : (i += 1) {
        const c = credential[i];
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
    serial.writeString("[AUTH] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup: create test identity
    keyring.init();
    _ = keyring.createIdentity("testuser", "123456");

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

    // Test 2: Unlock with correct PIN
    serial.writeString("  Test 2: Unlock correct PIN\n");
    if (unlock("testuser", "123456")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Check unlocked state
    serial.writeString("  Test 3: Check unlocked\n");
    if (isUnlocked()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Lock
    serial.writeString("  Test 4: Lock\n");
    lock();
    if (!isUnlocked()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Wrong PIN rejected
    serial.writeString("  Test 5: Wrong PIN rejected\n");
    if (!unlock("testuser", "999999")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Credential validation
    serial.writeString("  Test 6: PIN validation\n");
    if (isValidPin("1234") and isValidPin("123456") and !isValidPin("12") and !isValidPin("abcd")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Password validation
    serial.writeString("  Test 7: Password validation\n");
    if (isValidPassword("Password1") and !isValidPassword("short") and !isValidPassword("alllowercase")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 8: Credential strength
    serial.writeString("  Test 8: Credential strength\n");
    const weak = getCredentialStrength("1234");
    const strong = getCredentialStrength("MyP@ssw0rd123!");
    if (weak < 50 and strong > 70) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  AUTH: ");
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
