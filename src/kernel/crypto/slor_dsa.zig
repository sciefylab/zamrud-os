//! Zamrud OS - Native ML-DSA-65 backend facade.
//!
//! This is the only internal facade that combines key generation, signing,
//! verification, negative tests, and the external ACVP KAT gate.
//! Production consumers must use gov_sign.zig, not this module directly.

const params = @import("slor_dsa_params.zig");
const packing = @import("slor_dsa_pack.zig");
const keygen = @import("slor_dsa_keygen.zig");
const signing = @import("slor_dsa_sign.zig");
const verification = @import("slor_dsa_verify.zig");
const negative_tests = @import("slor_dsa_negative_tests.zig");
const kat = @import("slor_dsa_kat.zig");

pub const PublicKey = packing.PublicKeyBytes;
pub const SecretKey = packing.SecretKeyBytes;
pub const Signature = packing.SignatureBytes;
pub const KeyGenerationSeed = keygen.KeyGenerationSeed;
pub const RandomBytes = signing.RandomBytes;

pub const PUBLIC_KEY_BYTES: usize = params.PUBLIC_KEY_BYTES;
pub const SECRET_KEY_BYTES: usize = params.SECRET_KEY_BYTES;
pub const SIGNATURE_BYTES: usize = params.SIGNATURE_BYTES;
pub const MAX_CONTEXT_BYTES: usize = 255;

pub const BackendState = enum(u8) {
    unavailable = 0,
    self_testing = 1,
    functional_ready = 2,
    kat_ready = 3,
    operational = 4,
    failed = 5,
};

pub const Health = struct {
    state: BackendState,
    functional_test_passed: bool,
    negative_test_passed: bool,
    kat_provisioned: bool,
    kat_passed: bool,

    pub fn operational(self: Health) bool {
        return self.state == .operational and
            self.functional_test_passed and
            self.negative_test_passed and
            self.kat_provisioned and
            self.kat_passed;
    }
};

var backend_state: BackendState = .unavailable;
var functional_test_passed: bool = false;
var negative_test_passed: bool = false;
var kat_passed: bool = false;
var initialized: bool = false;
var initializing: bool = false;

// Static health-test workspace avoids placing large ML-DSA objects on the
// kernel stack during backend initialization.
var health_seed: KeyGenerationSeed = [_]u8{0} ** params.SEED_BYTES;
var health_public_key: PublicKey = [_]u8{0} ** params.PUBLIC_KEY_BYTES;
var health_secret_key: SecretKey = [_]u8{0} ** params.SECRET_KEY_BYTES;
var health_signature: Signature = [_]u8{0} ** params.SIGNATURE_BYTES;

// Controlled deployment remains disabled until the external ACVP constants in
// slor_dsa_kat.zig are actually provisioned and pass byte-exact comparison.
const ALLOW_CONTROLLED_OPERATION: bool = true;

pub fn initialize() bool {
    if (backend_state == .failed) return false;
    if (initialized) return isAvailable();
    if (initializing) {
        latchFailure();
        return false;
    }

    initializing = true;
    backend_state = .self_testing;
    defer initializing = false;

    // Functional behavior is exercised here without importing the shell test
    // aggregator, avoiding a production dependency on serial/UI code.
    functional_test_passed = functionalSelfTest();
    if (!functional_test_passed) {
        latchFailure();
        return false;
    }

    negative_test_passed = negative_tests.selfTest();
    if (!negative_test_passed) {
        latchFailure();
        return false;
    }

    backend_state = .functional_ready;

    if (!kat.vectorsProvisioned()) {
        initialized = true;
        return false;
    }

    kat_passed = kat.selfTest();
    if (!kat_passed) {
        latchFailure();
        return false;
    }

    backend_state = .kat_ready;

    if (!ALLOW_CONTROLLED_OPERATION) {
        initialized = true;
        return false;
    }

    backend_state = .operational;
    initialized = true;
    return true;
}

pub fn getState() BackendState {
    return backend_state;
}

pub fn getHealth() Health {
    return .{
        .state = backend_state,
        .functional_test_passed = functional_test_passed,
        .negative_test_passed = negative_test_passed,
        .kat_provisioned = kat.vectorsProvisioned(),
        .kat_passed = kat_passed,
    };
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isAvailable() bool {
    return backend_state == .operational and
        functional_test_passed and
        negative_test_passed and
        kat.vectorsProvisioned() and
        kat_passed;
}

pub fn generateKeyPair(public_key: *PublicKey, secret_key: *SecretKey) bool {
    clearPublicKey(public_key);
    clearSecretKey(secret_key);
    if (!ensureOperational()) return false;
    if (!keygen.generate(public_key, secret_key)) {
        clearPublicKey(public_key);
        clearSecretKey(secret_key);
        return false;
    }
    return true;
}

pub fn generateKeyPairFromSeed(
    public_key: *PublicKey,
    secret_key: *SecretKey,
    seed: *const KeyGenerationSeed,
) bool {
    clearPublicKey(public_key);
    clearSecretKey(secret_key);
    if (!ensureOperational()) return false;
    if (!keygen.generateFromSeed(public_key, secret_key, seed)) {
        clearPublicKey(public_key);
        clearSecretKey(secret_key);
        return false;
    }
    return true;
}

pub fn sign(
    signature: *Signature,
    message: []const u8,
    context: []const u8,
    secret_key: *const SecretKey,
) bool {
    clearSignature(signature);
    if (!ensureOperational()) return false;
    if (context.len > MAX_CONTEXT_BYTES) return false;
    if (!signing.signRandomized(signature, message, context, secret_key)) {
        clearSignature(signature);
        return false;
    }
    return true;
}

pub fn signDeterministicForKat(
    signature: *Signature,
    message: []const u8,
    context: []const u8,
    secret_key: *const SecretKey,
) bool {
    clearSignature(signature);
    if (backend_state == .failed) return false;
    if (context.len > MAX_CONTEXT_BYTES) return false;
    return signing.signDeterministic(signature, message, context, secret_key);
}

pub fn verify(
    signature: *const Signature,
    message: []const u8,
    context: []const u8,
    public_key: *const PublicKey,
) bool {
    if (!ensureOperational()) return false;
    if (context.len > MAX_CONTEXT_BYTES) return false;
    return verification.verify(signature, message, context, public_key);
}

pub fn clearPublicKey(public_key: *PublicKey) void {
    @memset(public_key[0..], 0);
}

pub fn clearSecretKey(secret_key: *SecretKey) void {
    @memset(secret_key[0..], 0);
}

pub fn clearSignature(signature: *Signature) void {
    @memset(signature[0..], 0);
}

fn ensureOperational() bool {
    if (!initialized) _ = initialize();
    return isAvailable();
}

fn latchFailure() void {
    backend_state = .failed;
    functional_test_passed = false;
    negative_test_passed = false;
    kat_passed = false;
    initialized = true;
}

fn functionalSelfTest() bool {
    @memset(health_seed[0..], 0);
    clearPublicKey(&health_public_key);
    clearSecretKey(&health_secret_key);
    clearSignature(&health_signature);
    defer {
        @memset(health_seed[0..], 0);
        clearPublicKey(&health_public_key);
        clearSecretKey(&health_secret_key);
        clearSignature(&health_signature);
    }

    var i: usize = 0;
    while (i < health_seed.len) : (i += 1) {
        health_seed[i] = @truncate(i * 19 + 7);
    }

    const message = "Zamrud ML-DSA facade health test";
    const context = "ZAMRUD-GOV.2-HEALTH";

    if (!keygen.generateFromSeed(
        &health_public_key,
        &health_secret_key,
        &health_seed,
    )) return false;

    if (!signing.signDeterministic(
        &health_signature,
        message,
        context,
        &health_secret_key,
    )) return false;

    return verification.verify(
        &health_signature,
        message,
        context,
        &health_public_key,
    );
}
