//! Zamrud OS - Deprecated SLOR Signature Module
//!
//! DEPRECATED:
//! This module is NOT production-grade and MUST NOT be used for governance,
//! authority, P2P eviction, app signing, or any security boundary.
//!
//! Production governance signatures must go through:
//!   crypto/gov_sign.zig
//!
//! Rationale:
//! - This file previously contained a custom lattice-like signature prototype.
//! - Custom cryptography must not be treated as production-grade.
//! - GOV.2 requires a public-verifiable, reviewed, standard-compatible
//!   signature backend such as ML-DSA / FIPS 204.
//!
//! Behavior:
//! - All signing and verification fail closed.
//! - Types remain for temporary source compatibility only.

const serial = @import("../drivers/serial/serial.zig");
const ct = @import("constant_time.zig");

// =============================================================================
// Compatibility Parameters
// =============================================================================

pub const SLOR_N: usize = 256;
pub const SLOR_Q: i32 = 8380417;
pub const REJECT_BOUND: i32 = 65536;

pub const PUBKEY_SIZE: usize = (SLOR_N * 4) + 32;
pub const SIGNATURE_SIZE: usize = (SLOR_N * 4) + 32;

pub const SlorSignPubKey = struct {
    t: [SLOR_N]i32,
    seed: [32]u8,
};

pub const SlorSignSecretKey = struct {
    s: [SLOR_N]i32,
};

pub const SlorSignature = struct {
    z: [SLOR_N]i32,
    c: [32]u8,
};

// =============================================================================
// Secure Wipe
// =============================================================================

fn secureZeroI32(arr: []i32) void {
    const byte_len = arr.len * @sizeOf(i32);
    const byte_ptr: [*]u8 = @ptrCast(arr.ptr);
    ct.secureZero(byte_ptr[0..byte_len]);
}

pub fn wipePublicKey(pk: *SlorSignPubKey) void {
    secureZeroI32(pk.t[0..]);
    ct.secureZero32(&pk.seed);
}

pub fn wipeSecretKey(sk: *SlorSignSecretKey) void {
    secureZeroI32(sk.s[0..]);
}

pub fn wipeSignature(sig: *SlorSignature) void {
    secureZeroI32(sig.z[0..]);
    ct.secureZero32(&sig.c);
}

// =============================================================================
// Deprecated API - Fail Closed
// =============================================================================

pub fn generateKeyPair(pk: *SlorSignPubKey, sk: *SlorSignSecretKey) void {
    wipePublicKey(pk);
    wipeSecretKey(sk);

    serial.writeString("[SLOR_SIGN] Deprecated backend disabled. Use crypto/gov_sign.zig\n");
}

pub fn sign(
    sk: *const SlorSignSecretKey,
    pk: *const SlorSignPubKey,
    msg: []const u8,
    sig: *SlorSignature,
) void {
    _ = sk;
    _ = pk;
    _ = msg;

    wipeSignature(sig);

    serial.writeString("[SLOR_SIGN] Signing denied: deprecated backend disabled\n");
}

pub fn verify(
    pk: *const SlorSignPubKey,
    msg: []const u8,
    sig: *const SlorSignature,
) bool {
    _ = pk;
    _ = msg;
    _ = sig;

    return false;
}

// =============================================================================
// Tests
// =============================================================================

pub fn test_slor_sign() bool {
    serial.writeString("[SLOR_SIGN] Deprecated backend fail-closed test...\n");

    var pk: SlorSignPubKey = undefined;
    var sk: SlorSignSecretKey = undefined;
    var sig: SlorSignature = undefined;

    generateKeyPair(&pk, &sk);
    sign(&sk, &pk, "test", &sig);

    if (!verify(&pk, "test", &sig)) {
        serial.writeString("  SLOR_SIGN deprecated fail-closed: PASS\n");
        return true;
    }

    serial.writeString("  SLOR_SIGN deprecated fail-closed: FAIL\n");
    return false;
}
