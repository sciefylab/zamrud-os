//! Zamrud OS - Identity Module
//! H.7: Unified credential handling, trust anchor support
//! GOV.2: Production governance signature boundary via auth/keyring/gov_sign

const serial = @import("../drivers/serial/serial.zig");

pub const keyring = @import("keyring.zig");
pub const auth = @import("auth.zig");
pub const privacy = @import("privacy.zig");
pub const names = @import("names.zig");

// Re-exports
pub const Identity = keyring.Identity;
pub const KeyPair = keyring.KeyPair;
pub const AuthType = auth.AuthType;
pub const PrivacyMode = privacy.PrivacyMode;
pub const CredentialType = keyring.CredentialType;

// =============================================================================
// Module State
// =============================================================================

var initialized: bool = false;

pub fn init() void {
    if (initialized) return;

    serial.writeString("[IDENTITY] Initializing...\n");

    serial.writeString("[IDENTITY] Step 1: keyring.init()\n");
    keyring.init();
    serial.writeString("[IDENTITY] Step 1: Done\n");

    serial.writeString("[IDENTITY] Step 2: auth.init()\n");
    auth.init();
    serial.writeString("[IDENTITY] Step 2: Done\n");

    serial.writeString("[IDENTITY] Step 3: privacy.init()\n");
    privacy.init();
    serial.writeString("[IDENTITY] Step 3: Done\n");

    serial.writeString("[IDENTITY] Step 4: names.init()\n");
    names.init();
    serial.writeString("[IDENTITY] Step 4: Done\n");

    initialized = true;
    serial.writeString("[IDENTITY] Ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Identity Management
// =============================================================================

pub fn createIdentity(name: []const u8, credential: []const u8) ?*Identity {
    return keyring.createIdentity(name, credential);
}

pub fn createIdentityWithPassword(name: []const u8, password: []const u8) ?*Identity {
    return keyring.createIdentityWithPassword(name, password);
}

pub fn createAnonymousIdentity(credential: []const u8) ?*Identity {
    return keyring.createAnonymousIdentity(credential);
}

pub fn getIdentity(name: []const u8) ?*Identity {
    return keyring.findIdentity(name);
}

pub fn getIdentityByAddress(address: *const [50]u8) ?*Identity {
    return keyring.findIdentityByAddress(address);
}

pub fn getIdentityByIndex(index: usize) ?*Identity {
    return keyring.getIdentityByIndex(index);
}

pub fn getCurrentIdentity() ?*Identity {
    return keyring.getCurrentIdentity();
}

pub fn setCurrentIdentity(name: []const u8) bool {
    return keyring.setCurrentIdentity(name);
}

pub fn getIdentityCount() usize {
    return keyring.getIdentityCount();
}

pub fn deleteIdentity(name: []const u8) bool {
    return keyring.deleteIdentity(name);
}

// =============================================================================
// H.7: Trust Anchor Support
// =============================================================================

pub fn getSystemOwner() ?*Identity {
    return keyring.getSystemOwner();
}

pub fn verifyTrust(id: *const Identity) bool {
    return keyring.verifyTrustHash(id);
}

pub fn isOwner(id: *const Identity) bool {
    return keyring.isSystemOwner(id);
}

// =============================================================================
// Authentication
// =============================================================================

pub fn unlock(name: []const u8, credential: []const u8) bool {
    return auth.unlock(name, credential);
}

pub fn unlockWithPin(name: []const u8, pin: []const u8) bool {
    return auth.unlockWithPin(name, pin);
}

pub fn unlockWithPassword(name: []const u8, password: []const u8) bool {
    return auth.unlockWithPassword(name, password);
}

pub fn lock() void {
    auth.lock();
}

pub fn isUnlocked() bool {
    return auth.isUnlocked();
}

pub fn changeCredential(old_credential: []const u8, new_credential: []const u8) bool {
    return auth.changeCredential(old_credential, new_credential);
}

pub fn changePin(old_pin: []const u8, new_pin: []const u8) bool {
    return auth.changePin_legacy(old_pin, new_pin);
}

// =============================================================================
// GOV.2 Governance Signing Boundary
// =============================================================================

pub fn hasGovernanceSigningKey() bool {
    return auth.hasGovernanceSigningKey();
}

pub fn isGovernanceSigningAvailable() bool {
    return auth.isGovernanceSigningAvailable();
}

// =============================================================================
// Privacy
// =============================================================================

pub fn setPrivacyMode(mode: PrivacyMode) void {
    privacy.setMode(mode);
}

pub fn getPrivacyMode() PrivacyMode {
    return privacy.getMode();
}

// =============================================================================
// Name Service
// =============================================================================

pub fn isNameAvailable(name: []const u8) bool {
    return names.isAvailable(name);
}

pub fn registerName(name: []const u8) bool {
    return names.registerName(name);
}

pub fn lookupName(name: []const u8) ?*const [50]u8 {
    return names.lookup(name);
}

// =============================================================================
// Test Runner
// =============================================================================

pub fn runAllTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  IDENTITY MODULE TESTS (H.7/GOV.2)\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("[1/4] Keyring...\n\n");
    if (keyring.test_keyring()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[2/4] Auth...\n\n");
    if (auth.test_auth()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[3/4] Privacy...\n\n");
    if (privacy.test_privacy()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("[4/4] Names...\n\n");
    if (names.test_names()) {
        serial.writeString("      PASSED\n");
        passed += 1;
    } else {
        serial.writeString("      FAILED\n");
        failed += 1;
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  IDENTITY RESULTS: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
    serial.writeString("========================================\n");

    if (failed == 0) {
        serial.writeString("\n  All identity tests PASSED!\n\n");
        return true;
    }

    serial.writeString("\n  Some identity tests FAILED!\n\n");
    return false;
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
