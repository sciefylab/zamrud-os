//! Zamrud OS - SLOR-DSA / ML-DSA-65 Parameters
//!
//! Single parameter set:
//! - ML-DSA-65
//! - NIST security category 3
//!
//! No runtime parameter selection is provided.
//! This avoids multiple cryptographic paths and prevents a double system.
//!
//! Standard:
//! - FIPS 204 ML-DSA.
//!
//! All constants in this module are compile-time constants.
//! No cryptographic operation is implemented here.

pub const NAME = "SLOR-DSA/ML-DSA-65";
pub const STANDARD = "FIPS-204";
pub const PARAMETER_SET = "ML-DSA-65";

// =============================================================================
// Core Ring Parameters
// =============================================================================

pub const N: usize = 256;
pub const Q: i32 = 8_380_417;
pub const D: u5 = 13;

pub const ROOT_OF_UNITY: i32 = 1753;

// Module dimensions.
pub const K: usize = 6;
pub const L: usize = 5;

// =============================================================================
// Distribution and Rejection Parameters
// =============================================================================

pub const ETA: i32 = 4;
pub const TAU: usize = 49;
pub const BETA: i32 = 196;

pub const GAMMA1: i32 = 1 << 19;
pub const GAMMA2: i32 = (Q - 1) / 32;

pub const OMEGA: usize = 55;

// =============================================================================
// Seed and Digest Sizes
// =============================================================================

pub const SEED_BYTES: usize = 32;
pub const RNDBYTES: usize = 32;

// H(ρ || t1), μ, and related SHAKE256 outputs.
pub const TR_BYTES: usize = 64;
pub const MU_BYTES: usize = 64;

// ML-DSA-65 security strength λ = 192.
// The challenge digest has λ / 4 bytes.
pub const LAMBDA_BITS: usize = 192;
pub const CTILDE_BYTES: usize = 48;

// =============================================================================
// Packed Polynomial Sizes
// =============================================================================

pub const POLY_T1_PACKED_BYTES: usize = 320;
pub const POLY_T0_PACKED_BYTES: usize = 416;
pub const POLY_ETA_PACKED_BYTES: usize = 128;
pub const POLY_Z_PACKED_BYTES: usize = 640;
pub const POLY_W1_PACKED_BYTES: usize = 128;

// =============================================================================
// Standard Key and Signature Sizes
// =============================================================================

// ρ || t1
pub const PUBLIC_KEY_BYTES: usize =
    SEED_BYTES +
    (K * POLY_T1_PACKED_BYTES);

// ρ || K || tr || s1 || s2 || t0
pub const SECRET_KEY_BYTES: usize =
    SEED_BYTES +
    SEED_BYTES +
    TR_BYTES +
    (L * POLY_ETA_PACKED_BYTES) +
    (K * POLY_ETA_PACKED_BYTES) +
    (K * POLY_T0_PACKED_BYTES);

// c_tilde || z || h
pub const SIGNATURE_BYTES: usize =
    CTILDE_BYTES +
    (L * POLY_Z_PACKED_BYTES) +
    OMEGA +
    K;

// =============================================================================
// SHAKE Rates
// =============================================================================

pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;

// =============================================================================
// Arithmetic Constants
// =============================================================================

// q^(-1) mod 2^32, represented according to Montgomery-reduction usage.
pub const QINV: u32 = 58_728_449;

// 2^32 mod q.
pub const MONT: i32 = 4_193_792;

// 2^64 mod q.
pub const MONT_SQUARED: i32 = 2_365_951;

// Number of bits used by Montgomery reduction.
pub const MONTGOMERY_BITS: usize = 32;

// Centered coefficient range.
pub const Q_HALF: i32 = Q / 2;

// =============================================================================
// Derived Bounds
// =============================================================================

pub const Z_BOUND: i32 =
    GAMMA1 - BETA;

pub const R0_BOUND: i32 =
    GAMMA2 - BETA;

pub const MAX_HINT_WEIGHT: usize =
    OMEGA;

// Number of coefficients in vectors.
pub const VECTOR_K_COEFFICIENTS: usize =
    K * N;

pub const VECTOR_L_COEFFICIENTS: usize =
    L * N;

pub const MATRIX_COEFFICIENTS: usize =
    K * L * N;

// =============================================================================
// Compile-Time Validation
// =============================================================================

comptime {
    if (N != 256) {
        @compileError(
            "ML-DSA requires polynomial degree N=256",
        );
    }

    if (Q != 8_380_417) {
        @compileError(
            "Unexpected ML-DSA modulus",
        );
    }

    if (K != 6 or L != 5) {
        @compileError(
            "SLOR-DSA uses only ML-DSA-65 (K=6, L=5)",
        );
    }

    if (ETA != 4) {
        @compileError(
            "ML-DSA-65 requires ETA=4",
        );
    }

    if (TAU != 49) {
        @compileError(
            "ML-DSA-65 requires TAU=49",
        );
    }

    if (BETA != 196) {
        @compileError(
            "ML-DSA-65 requires BETA=196",
        );
    }

    if (GAMMA1 != 524_288) {
        @compileError(
            "ML-DSA-65 requires GAMMA1=2^19",
        );
    }

    if (GAMMA2 != 261_888) {
        @compileError(
            "ML-DSA-65 GAMMA2 mismatch",
        );
    }

    if (OMEGA != 55) {
        @compileError(
            "ML-DSA-65 requires OMEGA=55",
        );
    }

    if (CTILDE_BYTES != 48) {
        @compileError(
            "ML-DSA-65 challenge digest must be 48 bytes",
        );
    }

    if (PUBLIC_KEY_BYTES != 1952) {
        @compileError(
            "ML-DSA-65 public-key size must be 1952 bytes",
        );
    }

    if (SECRET_KEY_BYTES != 4032) {
        @compileError(
            "ML-DSA-65 secret-key size must be 4032 bytes",
        );
    }

    if (SIGNATURE_BYTES != 3309) {
        @compileError(
            "ML-DSA-65 signature size must be 3309 bytes",
        );
    }

    if (SHAKE128_RATE != 168) {
        @compileError(
            "SHAKE128 rate mismatch",
        );
    }

    if (SHAKE256_RATE != 136) {
        @compileError(
            "SHAKE256 rate mismatch",
        );
    }

    if (Z_BOUND <= 0 or R0_BOUND <= 0) {
        @compileError(
            "Invalid ML-DSA rejection bounds",
        );
    }
}

// =============================================================================
// Runtime Self-Test
// =============================================================================

pub fn selfTest() bool {
    if (N != 256) return false;
    if (Q != 8_380_417) return false;

    if (K != 6 or L != 5) return false;

    if (ETA != 4) return false;
    if (TAU != 49) return false;
    if (BETA != 196) return false;
    if (OMEGA != 55) return false;

    if (GAMMA1 != 524_288) return false;
    if (GAMMA2 != 261_888) return false;

    if (PUBLIC_KEY_BYTES != 1952) {
        return false;
    }

    if (SECRET_KEY_BYTES != 4032) {
        return false;
    }

    if (SIGNATURE_BYTES != 3309) {
        return false;
    }

    if (CTILDE_BYTES != 48) {
        return false;
    }

    return true;
}
