//! Zamrud OS - Identity Authentication
//! H.7.1: Dual credential support (Password + optional PIN)
//! H.8: Threat scoring integration for auth failures
//! GOV.2: Production governance signing session via crypto/gov_sign.zig
//!
//! Production crypto policy:
//! - This file does not import slor_sign.zig.
//! - Governance signing is only via crypto/gov_sign.zig.
//! - If gov_sign backend is unavailable, signing fails closed.

const serial = @import("../drivers/serial/serial.zig");
const constant_time = @import("../crypto/constant_time.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const keyring = @import("keyring.zig");

// H.8 integration
const threat_score = @import("../security/threat_score.zig");
const threat_log = @import("../security/threat_log.zig");

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

// GOV.2 session-only secret key.
var unlocked_gov_sign_key: gov_sign.SecretKey = .{};
var has_unlocked_gov_sign_key: bool = false;

var lock_timeout: u32 = 300;
var last_unlock_method: UnlockMethod = .password;
var current_source_ip: u32 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[AUTH] Initializing...\n");

    current_unlocked = false;
    auth_attempts = 0;
    auth_failures = 0;
    consecutive_failures = 0;
    last_attempt_time = 0;

    lockout_state = .normal;
    lockout_until = 0;

    has_unlocked_key = false;
    has_unlocked_gov_sign_key = false;

    last_unlock_method = .password;
    current_source_ip = 0;

    clearPrivateKey();
    clearGovernanceSigningKey();

    initialized = true;

    serial.writeString("[AUTH] Initialized (H.7.1 dual-credential, H.8 threat-scoring, GOV.2 production boundary)\n");
}

fn clearPrivateKey() void {
    constant_time.secureZero32(&unlocked_privkey);
    has_unlocked_key = false;
}

fn clearGovernanceSigningKey() void {
    gov_sign.clearSecretKey(&unlocked_gov_sign_key);
    has_unlocked_gov_sign_key = false;
}

fn loadGovernanceSigningKey(id: *keyring.Identity) bool {
    clearGovernanceSigningKey();

    if (!has_unlocked_key) return false;
    if (!id.keypair.gov_sign_valid) return false;

    const ok = keyring.decryptGovernanceSigningKeyWithPrivateKey(
        id,
        &unlocked_privkey,
        &unlocked_gov_sign_key,
    );

    has_unlocked_gov_sign_key = ok;
    return ok;
}

// =============================================================================
// Status
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isLockedOut() bool {
    return lockout_state != .normal;
}

pub fn getLockoutState() LockoutState {
    return lockout_state;
}

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

    if (current_source_ip != 0) {
        const severity: threat_log.ThreatSeverity = if (consecutive_failures >= LOCKOUT_ATTEMPTS)
            .critical
        else if (consecutive_failures >= MAX_ATTEMPTS)
            .high
        else if (consecutive_failures >= 3)
            .medium
        else
            .low;

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
}

fn finishSuccessfulUnlock(
    id: *keyring.Identity,
    name: []const u8,
    method: UnlockMethod,
    current_time: u32,
) bool {
    recordSuccess();

    id.unlocked = true;
    id.last_used = current_time;

    current_unlocked = true;
    has_unlocked_key = true;
    last_unlock_method = method;

    _ = keyring.setCurrentIdentity(name);

    _ = loadGovernanceSigningKey(id);

    switch (method) {
        .pin => serial.writeString("[AUTH] Unlocked via PIN\n"),
        .password => serial.writeString("[AUTH] Unlocked via password\n"),
    }

    if (has_unlocked_gov_sign_key) {
        serial.writeString("[AUTH] GOV.2 production governance signing key unlocked\n");
    } else {
        if (gov_sign.isProductionBackendAvailable()) {
            serial.writeString("[AUTH] GOV.2 governance signing key unavailable\n");
        } else {
            serial.writeString("[AUTH] GOV.2 signing fail-closed: production backend unavailable\n");
        }
    }

    return true;
}

// =============================================================================
// Unlock
// =============================================================================

pub fn unlock(name: []const u8, credential: []const u8) bool {
    const current_time: u32 = 1700000000;

    auth_attempts += 1;

    if (lockout_state == .hard_lock) {
        serial.writeString("[AUTH] Account locked. Use seed phrase to recover.\n");

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

    clearPrivateKey();
    clearGovernanceSigningKey();

    if (id.?.has_pin and keyring.looksLikePin(credential)) {
        if (keyring.decryptPrivateKeyWithPin(id.?, credential, &unlocked_privkey)) {
            return finishSuccessfulUnlock(id.?, name, .pin, current_time);
        }
    }

    if (keyring.decryptPrivateKey(id.?, credential, &unlocked_privkey)) {
        return finishSuccessfulUnlock(id.?, name, .password, current_time);
    }

    clearPrivateKey();
    clearGovernanceSigningKey();
    recordFailure(current_time);
    return false;
}

pub fn unlockWithPin(name: []const u8, pin: []const u8) bool {
    const current_time: u32 = 1700000000;

    auth_attempts += 1;

    if (lockout_state != .normal) {
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

    clearPrivateKey();
    clearGovernanceSigningKey();

    if (keyring.decryptPrivateKeyWithPin(id.?, pin, &unlocked_privkey)) {
        return finishSuccessfulUnlock(id.?, name, .pin, current_time);
    }

    clearPrivateKey();
    clearGovernanceSigningKey();
    recordFailure(current_time);
    return false;
}

pub fn unlockWithPassword(name: []const u8, password: []const u8) bool {
    const current_time: u32 = 1700000000;

    auth_attempts += 1;

    if (lockout_state != .normal) {
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

    clearPrivateKey();
    clearGovernanceSigningKey();

    if (keyring.decryptPrivateKey(id.?, password, &unlocked_privkey)) {
        return finishSuccessfulUnlock(id.?, name, .password, current_time);
    }

    clearPrivateKey();
    clearGovernanceSigningKey();
    recordFailure(current_time);
    return false;
}

pub fn unlockWithSeedPhrase(name: []const u8, seed_phrase: []const u8, new_credential: []const u8) bool {
    _ = name;
    _ = seed_phrase;
    _ = new_credential;

    lockout_state = .normal;
    consecutive_failures = 0;
    lockout_until = 0;

    serial.writeString("[AUTH] Seed phrase recovery: lockout reset\n");
    return false;
}

pub fn lock() void {
    clearPrivateKey();
    clearGovernanceSigningKey();
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

// =============================================================================
// GOV.2 Governance Signing API
// =============================================================================

pub fn hasGovernanceSigningKey() bool {
    return current_unlocked and has_unlocked_gov_sign_key;
}

pub fn isGovernanceSigningAvailable() bool {
    return gov_sign.isProductionBackendAvailable() and hasGovernanceSigningKey();
}

pub fn getGovernancePublicKey() ?*const gov_sign.PublicKey {
    const current = keyring.getCurrentIdentity() orelse return null;
    return keyring.getGovernancePublicKey(current);
}

pub fn signGovernancePayload(
    domain: []const u8,
    payload: []const u8,
    sig: *gov_sign.Signature,
) bool {
    gov_sign.clearSignature(sig);

    if (!current_unlocked) return false;
    if (!has_unlocked_gov_sign_key) return false;

    return gov_sign.sign(
        &unlocked_gov_sign_key,
        domain,
        payload,
        sig,
    );
}

pub fn verifyGovernancePayload(
    pub_key: *const gov_sign.PublicKey,
    domain: []const u8,
    payload: []const u8,
    sig: *const gov_sign.Signature,
) gov_sign.VerifyResult {
    return gov_sign.verify(pub_key, domain, payload, sig);
}

pub fn verifyGovernancePayloadBool(
    pub_key: *const gov_sign.PublicKey,
    domain: []const u8,
    payload: []const u8,
    sig: *const gov_sign.Signature,
) bool {
    return gov_sign.verifyBool(pub_key, domain, payload, sig);
}

// =============================================================================
// Session Info
// =============================================================================

pub fn getLastUnlockMethod() UnlockMethod {
    return last_unlock_method;
}

pub fn hasPinConfigured() bool {
    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    return current.?.has_pin;
}

// =============================================================================
// PIN Management
// =============================================================================

pub fn setupPin(password: []const u8, new_pin: []const u8) bool {
    const current = keyring.getCurrentIdentity();

    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.setupSecondaryPin(current.?, password, new_pin);
}

pub fn removePin(password: []const u8) bool {
    const current = keyring.getCurrentIdentity();

    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.removeSecondaryPin(current.?, password);
}

pub fn changePin(password: []const u8, new_pin: []const u8) bool {
    const current = keyring.getCurrentIdentity();

    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.changeSecondaryPin(current.?, password, new_pin);
}

// =============================================================================
// Password Management
// =============================================================================

pub fn changePassword(old_password: []const u8, new_password: []const u8) bool {
    const current = keyring.getCurrentIdentity();

    if (current == null) return false;
    if (!current.?.unlocked) return false;

    return keyring.reEncryptPrivateKey(current.?, old_password, new_password);
}

pub fn changeCredential(old_credential: []const u8, new_credential: []const u8) bool {
    return changePassword(old_credential, new_credential);
}

pub fn changePin_legacy(old_pin: []const u8, new_pin: []const u8) bool {
    return changeCredential(old_pin, new_pin);
}

// =============================================================================
// Activity / Timeout
// =============================================================================

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

// =============================================================================
// Stats
// =============================================================================

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
        if (c >= 'a' and c <= 'z') {
            has_lower = true;
        } else if (c >= 'A' and c <= 'Z') {
            has_upper = true;
        } else if (c >= '0' and c <= '9') {
            has_digit = true;
        } else {
            has_special = true;
        }
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
    serial.writeString("\n=== Auth Test (H.7.1 Dual Credential + H.8 + GOV.2 production boundary) ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    keyring.init();
    _ = keyring.createIdentityWithPassword("testuser", "SecurePass1");

    serial.writeString("  Test 1: Initialize\n");
    init();

    if (initialized and !current_unlocked) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 2: Set source IP (H.8)\n");
    setSourceIP(0xC0A80101);

    if (current_source_ip == 0xC0A80101) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 3: Unlock with password\n");
    if (unlock("testuser", "SecurePass1")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 4: Unlock method = password\n");
    if (getLastUnlockMethod() == .password) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 5: GOV.2 production signing policy\n");
    if (gov_sign.isProductionBackendAvailable()) {
        if (hasGovernanceSigningKey()) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        if (!hasGovernanceSigningKey()) {
            serial.writeString("    OK (fail-closed)\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    serial.writeString(
        "  Test 6: GOV.2 production sign / verify policy\n",
    );
    {
        var sig = gov_sign.Signature{};
        const public_key = getGovernancePublicKey();
        const signed = signGovernancePayload(
            gov_sign.DOMAIN_TEST,
            "ZAMRUD-GOV-TEST-PAYLOAD",
            &sig,
        );

        if (gov_sign.isProductionBackendAvailable()) {
            const verified =
                public_key != null and
                signed and
                verifyGovernancePayloadBool(
                    public_key.?,
                    gov_sign.DOMAIN_TEST,
                    "ZAMRUD-GOV-TEST-PAYLOAD",
                    &sig,
                );
            const modified_message_rejected =
                public_key != null and
                signed and
                !verifyGovernancePayloadBool(
                    public_key.?,
                    gov_sign.DOMAIN_TEST,
                    "ZAMRUD-GOV-TEST-PAYLOAD-MODIFIED",
                    &sig,
                );
            const wrong_domain_rejected =
                public_key != null and
                signed and
                !verifyGovernancePayloadBool(
                    public_key.?,
                    gov_sign.DOMAIN_CHAIN,
                    "ZAMRUD-GOV-TEST-PAYLOAD",
                    &sig,
                );

            if (verified and
                modified_message_rejected and
                wrong_domain_rejected)
            {
                serial.writeString(
                    "    OK (sign/verify + domain separation)\n",
                );
                passed += 1;
            } else {
                serial.writeString("    FAIL\n");
                failed += 1;
            }
        } else {
            if (!signed and !sig.valid) {
                serial.writeString("    OK (fail-closed)\n");
                passed += 1;
            } else {
                serial.writeString("    FAIL\n");
                failed += 1;
            }
        }
        gov_sign.clearSignature(&sig);
    }

    serial.writeString("  Test 7: Setup PIN\n");
    if (setupPin("SecurePass1", "1234")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 8: hasPinConfigured\n");
    if (hasPinConfigured()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString(
        "  Test 9: Lock wipes session keys and denies signing\n",
    );
    lock();
    var locked_sig = gov_sign.Signature{};
    const locked_sign_result = signGovernancePayload(
        gov_sign.DOMAIN_TEST,
        "ZAMRUD-GOV-LOCKED-TEST",
        &locked_sig,
    );
    if (!isUnlocked() and
        !hasGovernanceSigningKey() and
        !locked_sign_result and
        !locked_sig.valid)
    {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }
    gov_sign.clearSignature(&locked_sig);

    serial.writeString("  Test 10: Unlock with PIN\n");
    if (unlock("testuser", "1234")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 11: Unlock method = PIN\n");
    if (getLastUnlockMethod() == .pin) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 12: GOV.2 policy after PIN unlock\n");
    if (gov_sign.isProductionBackendAvailable()) {
        if (hasGovernanceSigningKey()) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    } else {
        if (!hasGovernanceSigningKey()) {
            serial.writeString("    OK (fail-closed)\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    lock();

    serial.writeString("  Test 13: Password still works\n");
    if (unlock("testuser", "SecurePass1")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 14: Remove PIN\n");
    if (removePin("SecurePass1") and !hasPinConfigured()) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 15: H.8 auth failure (bad password)\n");
    lock();
    setSourceIP(0xC0A80102);

    const before_failures = auth_failures;
    _ = unlock("testuser", "WrongPassword");

    if (auth_failures == before_failures + 1) {
        serial.writeString("    OK (failure recorded)\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  AUTH (H.7.1+H.8+GOV.2): ");
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
