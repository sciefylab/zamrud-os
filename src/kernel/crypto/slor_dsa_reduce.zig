//! Zamrud OS - SLOR-DSA / ML-DSA-65 Modular Reduction
//!
//! Internal arithmetic primitive for the single native ML-DSA-65 backend.
//!
//! Dependency direction:
//!
//!   gov_sign.zig
//!       -> slor_dsa.zig
//!           -> slor_dsa_reduce.zig
//!
//! This file must not be imported directly by identity, P2P, authority,
//! governance, or application modules.
//!
//! Properties:
//! - Pure Zig.
//! - Freestanding.
//! - No allocator.
//! - No libc.
//! - No vendor dependency.
//! - No second signature implementation.
//!
//! Arithmetic modulus:
//!   q = 8,380,417
//!
//! Montgomery radix:
//!   R = 2^32
//!
//! QINV satisfies:
//!   q * QINV == 1 mod 2^32
//!
//! The Montgomery reduction follows the arithmetic convention used by
//! ML-DSA polynomial NTT operations.

const params = @import("slor_dsa_params.zig");

// =============================================================================
// Public Constants
// =============================================================================

pub const Q: i32 = params.Q;
pub const QINV: u32 = params.QINV;
pub const MONT: i32 = params.MONT;
pub const MONT_SQUARED: i32 = params.MONT_SQUARED;

// =============================================================================
// Montgomery Reduction
// =============================================================================

/// Compute:
///
///   a * 2^(-32) mod q
///
/// Input bound:
///
///   -2^31 * q <= a <= 2^31 * q
///
/// The result is represented as a centered residue suitable for subsequent
/// ML-DSA arithmetic.
pub inline fn montgomeryReduce(a: i64) i32 {
    // Only the low 32 bits participate in multiplication by QINV.
    const low: u32 = @truncate(@as(u64, @bitCast(a)));

    const product: u32 = low *% QINV;
    const signed_product: i32 = @bitCast(product);

    const correction =
        @as(i64, signed_product) * @as(i64, Q);

    return @intCast((a - correction) >> 32);
}

// =============================================================================
// Standard Reduction
// =============================================================================

/// Reduce an i32 coefficient to a centered representative close to:
///
///   (-q, q)
///
/// This is the ML-DSA Reduce32 operation.
pub inline fn reduce32(a: i32) i32 {
    const t: i32 =
        (a + (@as(i32, 1) << 22)) >> 23;

    return a - t * Q;
}

/// Conditionally add q when the coefficient is negative.
///
/// Input is expected to be in a range where one conditional addition is
/// sufficient.
pub inline fn conditionalAddQ(a: i32) i32 {
    return a + ((a >> 31) & Q);
}

/// Alias matching common ML-DSA notation.
pub inline fn caddq(a: i32) i32 {
    return conditionalAddQ(a);
}

/// Convert a coefficient into the canonical interval:
///
///   [0, q)
pub inline fn freeze(a: i32) i32 {
    return conditionalAddQ(reduce32(a));
}

/// Reduce an i64 value modulo q and return a centered representation.
///
/// This helper is not used in the hot NTT path. It is useful for validation,
/// tests, and bounded arithmetic outside Montgomery representation.
pub fn reduceI64Centered(a: i64) i32 {
    var value = @rem(a, @as(i64, Q));

    if (value > @as(i64, Q / 2)) {
        value -= Q;
    } else if (value < -@as(i64, Q / 2)) {
        value += Q;
    }

    return @intCast(value);
}

/// Reduce an i64 value into the canonical interval:
///
///   [0, q)
pub fn reduceI64Canonical(a: i64) i32 {
    var value = @rem(a, @as(i64, Q));

    if (value < 0) {
        value += Q;
    }

    return @intCast(value);
}

// =============================================================================
// Montgomery Representation
// =============================================================================

/// Convert a normal coefficient to Montgomery representation.
///
/// Computes:
///
///   a * R mod q
///
/// by applying Montgomery reduction to:
///
///   a * R^2 mod q
pub inline fn toMontgomery(a: i32) i32 {
    return montgomeryReduce(
        @as(i64, a) * @as(i64, MONT_SQUARED),
    );
}

/// Convert a Montgomery coefficient back to normal representation.
pub inline fn fromMontgomery(a: i32) i32 {
    return montgomeryReduce(@as(i64, a));
}

/// Multiply two coefficients where at least one operand is represented in
/// Montgomery form.
pub inline fn montgomeryMultiply(
    left: i32,
    right: i32,
) i32 {
    return montgomeryReduce(
        @as(i64, left) * @as(i64, right),
    );
}

// =============================================================================
// Polynomial Helpers
// =============================================================================

/// Apply Reduce32 to every coefficient.
pub fn reducePolynomial(coefficients: []i32) void {
    for (coefficients) |*coefficient| {
        coefficient.* = reduce32(coefficient.*);
    }
}

/// Apply conditional addition of q to every coefficient.
pub fn conditionalAddQPolynomial(coefficients: []i32) void {
    for (coefficients) |*coefficient| {
        coefficient.* =
            conditionalAddQ(coefficient.*);
    }
}

/// Convert every coefficient to canonical representation [0, q).
pub fn freezePolynomial(coefficients: []i32) void {
    for (coefficients) |*coefficient| {
        coefficient.* = freeze(coefficient.*);
    }
}

/// Convert a polynomial to Montgomery representation.
pub fn toMontgomeryPolynomial(coefficients: []i32) void {
    for (coefficients) |*coefficient| {
        coefficient.* =
            toMontgomery(coefficient.*);
    }
}

/// Convert a polynomial from Montgomery representation.
pub fn fromMontgomeryPolynomial(coefficients: []i32) void {
    for (coefficients) |*coefficient| {
        coefficient.* =
            fromMontgomery(coefficient.*);
    }
}

// =============================================================================
// Validation Helpers
// =============================================================================

fn equivalentModQ(left: i32, right: i32) bool {
    return reduceI64Canonical(left) ==
        reduceI64Canonical(right);
}

// =============================================================================
// Self-Test
// =============================================================================

/// Arithmetic self-test.
///
/// This is an internal consistency test, not a replacement for official
/// ML-DSA Known Answer Tests.
pub fn selfTest() bool {
    if (!testConstants()) return false;
    if (!testReduce32()) return false;
    if (!testConditionalAddQ()) return false;
    if (!testCanonicalReduction()) return false;
    if (!testMontgomeryRoundTrip()) return false;
    if (!testMontgomeryMultiplication()) return false;

    return true;
}

fn testConstants() bool {
    if (Q != 8_380_417) return false;
    if (QINV != 58_728_449) return false;
    if (MONT != 4_193_792) return false;
    if (MONT_SQUARED != 2_365_951) return false;

    // Verify q * QINV == 1 modulo 2^32.
    const product: u32 =
        @truncate(
            @as(u64, @intCast(Q)) *
                @as(u64, QINV),
        );

    return product == 1;
}

fn testReduce32() bool {
    const vectors = [_]i32{
        0,
        1,
        -1,
        Q,
        -Q,
        Q - 1,
        -Q + 1,
        2 * Q,
        -2 * Q,
        4_000_000,
        -4_000_000,
    };

    for (vectors) |value| {
        const reduced = reduce32(value);

        if (!equivalentModQ(value, reduced)) {
            return false;
        }

        if (reduced <= -Q or reduced >= Q) {
            return false;
        }
    }

    return true;
}

fn testConditionalAddQ() bool {
    if (conditionalAddQ(0) != 0) return false;
    if (conditionalAddQ(1) != 1) return false;
    if (conditionalAddQ(Q - 1) != Q - 1) {
        return false;
    }

    if (conditionalAddQ(-1) != Q - 1) {
        return false;
    }

    if (conditionalAddQ(-Q) != 0) {
        return false;
    }

    return true;
}

fn testCanonicalReduction() bool {
    const vectors = [_]i64{
        0,
        1,
        -1,
        Q,
        -Q,
        2 * @as(i64, Q),
        -2 * @as(i64, Q),
        123_456_789,
        -123_456_789,
    };

    for (vectors) |value| {
        const canonical =
            reduceI64Canonical(value);

        if (canonical < 0 or canonical >= Q) {
            return false;
        }

        const difference =
            value - @as(i64, canonical);

        if (@rem(difference, @as(i64, Q)) != 0) {
            return false;
        }
    }

    return true;
}

fn testMontgomeryRoundTrip() bool {
    const vectors = [_]i32{
        0,
        1,
        2,
        3,
        17,
        256,
        65_535,
        Q - 1,
        Q / 2,
        -1,
        -17,
    };

    for (vectors) |value| {
        const montgomery =
            toMontgomery(value);

        const restored =
            fromMontgomery(montgomery);

        if (!equivalentModQ(value, restored)) {
            return false;
        }
    }

    return true;
}

fn testMontgomeryMultiplication() bool {
    const left_values = [_]i32{
        0,
        1,
        2,
        17,
        1234,
        Q - 1,
        -1,
    };

    const right_values = [_]i32{
        0,
        1,
        3,
        19,
        4321,
        Q - 2,
        -7,
    };

    var index: usize = 0;

    while (index < left_values.len) : (index += 1) {
        const left = left_values[index];
        const right = right_values[index];

        const left_montgomery =
            toMontgomery(left);

        const product =
            montgomeryMultiply(
                left_montgomery,
                right,
            );

        const expected =
            reduceI64Centered(
                @as(i64, left) *
                    @as(i64, right),
            );

        if (!equivalentModQ(product, expected)) {
            return false;
        }
    }

    return true;
}
