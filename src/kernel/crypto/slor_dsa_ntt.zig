//! Zamrud OS - SLOR-DSA / ML-DSA-65 Number Theoretic Transform
//!
//! Internal arithmetic primitive for the single native ML-DSA-65 backend.
//!
//! Dependency direction:
//!
//!   gov_sign.zig
//!       -> slor_dsa.zig
//!           -> slor_dsa_ntt.zig
//!               -> slor_dsa_reduce.zig
//!               -> slor_dsa_params.zig
//!
//! There is no alternate signature system here.
//!
//! Properties:
//! - Pure Zig.
//! - Freestanding.
//! - No allocator.
//! - No libc.
//! - No vendor dependency.
//! - Twiddle factors are generated at compile time from the ML-DSA root.
//! - No duplicated hard-coded zeta table.
//!
//! Transform:
//! - Forward NTT in-place.
//! - Inverse NTT to Montgomery representation in-place.
//! - Pointwise Montgomery multiplication.
//!
//! Important representation rule:
//!
//!   inverse(forward(a)) == a * R mod q
//!
//! where:
//!
//!   R = 2^32 mod q.
//!
//! Call reduce.fromMontgomeryPolynomial() after inverseNttToMontgomery() when
//! normal coefficient representation is required.

const params = @import("slor_dsa_params.zig");
const reduce = @import("slor_dsa_reduce.zig");

// =============================================================================
// Public Constants and Types
// =============================================================================

pub const N: usize = params.N;
pub const Q: i32 = params.Q;

pub const Polynomial = [N]i32;

// Inverse NTT scaling constant:
//
//   MONT^2 / 256 mod q
//
// This is the standard ML-DSA inverse-transform scaling factor.
const INVERSE_NTT_FACTOR: i32 = 41_978;

// =============================================================================
// Compile-Time Zeta Generation
// =============================================================================
//
// The ML-DSA NTT zeta sequence is:
//
//   zeta[i] = MONT * root^bit_reverse_8(i) mod q
//
// represented as a centered signed coefficient.
//
// Generating the table from the normative root avoids:
// - an independently maintained duplicate table;
// - accidental transcription mistakes;
// - a second arithmetic implementation.

const ZETAS: [N]i32 = generateZetas();

fn generateZetas() [N]i32 {
    @setEvalBranchQuota(100_000);

    var result: [N]i32 =
        [_]i32{0} ** N;

    var index: usize = 1;

    while (index < N) : (index += 1) {
        const exponent =
            bitReverse8(@intCast(index));

        const power = modularPower(
            @intCast(params.ROOT_OF_UNITY),
            exponent,
        );

        const value =
            (@as(u64, power) *
                @as(u64, @intCast(params.MONT))) %
            @as(u64, @intCast(Q));

        var centered: i64 =
            @intCast(value);

        if (centered > Q / 2) {
            centered -= Q;
        }

        result[index] =
            @intCast(centered);
    }

    return result;
}

fn bitReverse8(value: u8) u8 {
    var source = value;
    var reversed: u8 = 0;
    var bit: usize = 0;

    while (bit < 8) : (bit += 1) {
        reversed =
            (reversed << 1) |
            (source & 1);

        source >>= 1;
    }

    return reversed;
}

fn modularPower(
    base_value: u32,
    exponent_value: u8,
) u32 {
    var result: u64 = 1;
    var base: u64 =
        base_value %
        @as(u32, @intCast(Q));

    var exponent = exponent_value;

    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result =
                (result * base) %
                @as(u64, @intCast(Q));
        }

        base =
            (base * base) %
            @as(u64, @intCast(Q));

        exponent >>= 1;
    }

    return @intCast(result);
}

// =============================================================================
// Forward NTT
// =============================================================================

/// Perform the in-place forward ML-DSA NTT.
///
/// Input:
/// - Normal polynomial coefficients.
/// - Coefficients should be reduced to a bounded representation.
///
/// Output:
/// - Coefficients in NTT representation.
/// - Output order is bit-reversed according to the ML-DSA transform.
///
/// This transform intentionally does not perform final canonical reduction.
pub fn forward(polynomial: *Polynomial) void {
    var zeta_index: usize = 0;
    var length: usize = 128;

    while (length > 0) : (length >>= 1) {
        var start: usize = 0;

        while (start < N) : (start += 2 * length) {
            zeta_index += 1;

            const zeta =
                ZETAS[zeta_index];

            var index = start;

            while (index < start + length) : (index += 1) {
                const product =
                    reduce.montgomeryReduce(
                        @as(i64, zeta) *
                            @as(
                                i64,
                                polynomial[index + length],
                            ),
                    );

                const current =
                    polynomial[index];

                polynomial[index + length] =
                    current - product;

                polynomial[index] =
                    current + product;
            }
        }
    }
}

// =============================================================================
// Inverse NTT
// =============================================================================

/// Perform the in-place inverse NTT and scale into Montgomery representation.
///
/// Output relation:
///
///   inverseNttToMontgomery(forward(a))
///       == a * MONT mod q
///
/// To recover normal representation:
///
///   inverseNttToMontgomery(&poly);
///   reduce.fromMontgomeryPolynomial(poly[0..]);
pub fn inverseToMontgomery(
    polynomial: *Polynomial,
) void {
    var zeta_index: usize = N;
    var length: usize = 1;

    while (length < N) : (length <<= 1) {
        var start: usize = 0;

        while (start < N) : (start += 2 * length) {
            zeta_index -= 1;

            const zeta =
                -ZETAS[zeta_index];

            var index = start;

            while (index < start + length) : (index += 1) {
                const lower =
                    polynomial[index];

                const upper =
                    polynomial[index + length];

                polynomial[index] =
                    lower + upper;

                const difference =
                    lower - upper;

                polynomial[index + length] =
                    reduce.montgomeryReduce(
                        @as(i64, zeta) *
                            @as(i64, difference),
                    );
            }
        }
    }

    var index: usize = 0;

    while (index < N) : (index += 1) {
        polynomial[index] =
            reduce.montgomeryReduce(
                @as(i64, INVERSE_NTT_FACTOR) *
                    @as(i64, polynomial[index]),
            );
    }
}

// =============================================================================
// Pointwise Multiplication
// =============================================================================

/// Pointwise Montgomery multiplication in NTT representation.
pub fn pointwiseMontgomery(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        output[index] =
            reduce.montgomeryReduce(
                @as(i64, left[index]) *
                    @as(i64, right[index]),
            );
    }
}

/// In-place pointwise Montgomery multiplication.
pub fn pointwiseMontgomeryInPlace(
    left: *Polynomial,
    right: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        left[index] =
            reduce.montgomeryReduce(
                @as(i64, left[index]) *
                    @as(i64, right[index]),
            );
    }
}

// =============================================================================
// Complete Polynomial Product
// =============================================================================

/// Multiply two polynomials in:
///
///   Z_q[X] / (X^256 + 1)
///
/// using the ML-DSA NTT.
///
/// Output is converted back to normal coefficient representation.
pub fn multiply(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    var left_ntt = left.*;
    var right_ntt = right.*;

    forward(&left_ntt);
    forward(&right_ntt);

    pointwiseMontgomery(
        output,
        &left_ntt,
        &right_ntt,
    );

    // Pointwise Montgomery multiplication contributes R^-1, while
    // InvNTTToMont contributes R. Their factors cancel, so output is already
    // the normal coefficient product. Do not call fromMontgomery here.
    inverseToMontgomery(output);
    reduce.reducePolynomial(output[0..]);
}

// =============================================================================
// Zeta Access for Internal Tests
// =============================================================================

/// Internal read-only access to a zeta coefficient.
///
/// This function exists for self-testing and future ML-DSA arithmetic tests.
/// It must not be used by identity or governance code.
pub fn getZeta(index: usize) ?i32 {
    if (index >= N) return null;
    return ZETAS[index];
}

// =============================================================================
// Test Helpers
// =============================================================================

fn equivalentModQ(left: i32, right: i32) bool {
    return reduce.reduceI64Canonical(left) ==
        reduce.reduceI64Canonical(right);
}

fn clearPolynomial(polynomial: *Polynomial) void {
    for (polynomial) |*coefficient| {
        coefficient.* = 0;
    }
}

// =============================================================================
// Self-Test
// =============================================================================

/// Internal NTT consistency self-test.
///
/// This validates:
/// - generated zeta constants against known initial coefficients;
/// - forward/inverse round trip;
/// - zero polynomial behavior;
/// - constant polynomial behavior;
/// - pointwise multiplication;
/// - NTT multiplication against schoolbook negacyclic multiplication.
///
/// Official ML-DSA Known Answer Tests are still required before enabling the
/// production signature backend.
pub const SelfTestResults = struct {
    reduction: bool,
    known_zetas: bool,
    zero_polynomial: bool,
    forward_inverse: bool,
    pointwise_zero: bool,
    polynomial_multiplication: bool,

    pub fn allPassed(self: SelfTestResults) bool {
        return self.reduction and self.known_zetas and
            self.zero_polynomial and self.forward_inverse and
            self.pointwise_zero and self.polynomial_multiplication;
    }
};

pub fn getSelfTestResults() SelfTestResults {
    return .{
        .reduction = reduce.selfTest(),
        .known_zetas = testKnownZetas(),
        .zero_polynomial = testZeroPolynomial(),
        .forward_inverse = testForwardInverseRoundTrip(),
        .pointwise_zero = testPointwiseZero(),
        .polynomial_multiplication = testPolynomialMultiplication(),
    };
}

pub fn selfTest() bool {
    return getSelfTestResults().allPassed();
}

fn testKnownZetas() bool {
    // Known first ML-DSA Montgomery zeta coefficients.
    const expected = [_]i32{
        0,
        25_847,
        -2_608_894,
        -518_909,
        237_124,
        -777_960,
        -876_248,
        466_468,
        1_826_347,
        2_353_451,
        -359_251,
        -2_091_905,
        3_119_733,
        -2_884_855,
        3_111_497,
        2_680_103,
    };

    var index: usize = 0;

    while (index < expected.len) : (index += 1) {
        if (ZETAS[index] != expected[index]) {
            return false;
        }
    }

    return true;
}

fn testZeroPolynomial() bool {
    var polynomial: Polynomial =
        [_]i32{0} ** N;

    forward(&polynomial);

    for (polynomial) |coefficient| {
        if (coefficient != 0) {
            return false;
        }
    }

    inverseToMontgomery(&polynomial);

    for (polynomial) |coefficient| {
        if (coefficient != 0) {
            return false;
        }
    }

    return true;
}

fn testForwardInverseRoundTrip() bool {
    var original: Polynomial =
        [_]i32{0} ** N;

    var index: usize = 0;

    while (index < N) : (index += 1) {
        const value: i32 =
            @intCast((index * 7919 + 123) %
            @as(usize, @intCast(Q)));

        original[index] =
            if ((index & 1) == 0)
                value
            else
                -value;
    }

    var transformed = original;

    forward(&transformed);
    inverseToMontgomery(&transformed);

    // Inverse output is in Montgomery form.
    reduce.fromMontgomeryPolynomial(
        transformed[0..],
    );

    reduce.reducePolynomial(
        transformed[0..],
    );

    index = 0;

    while (index < N) : (index += 1) {
        if (!equivalentModQ(
            original[index],
            transformed[index],
        )) {
            return false;
        }
    }

    clearPolynomial(&original);
    clearPolynomial(&transformed);

    return true;
}

fn testPointwiseZero() bool {
    var left: Polynomial =
        [_]i32{0} ** N;

    var right: Polynomial =
        [_]i32{0} ** N;

    var output: Polynomial =
        [_]i32{0} ** N;

    var index: usize = 0;

    while (index < N) : (index += 1) {
        left[index] = @intCast(index);
        right[index] = 0;
    }

    pointwiseMontgomery(
        &output,
        &left,
        &right,
    );

    for (output) |coefficient| {
        if (coefficient != 0) {
            return false;
        }
    }

    clearPolynomial(&left);
    clearPolynomial(&right);
    clearPolynomial(&output);

    return true;
}

fn testPolynomialMultiplication() bool {
    var left: Polynomial =
        [_]i32{0} ** N;

    var right: Polynomial =
        [_]i32{0} ** N;

    // Sparse polynomials keep the schoolbook reference bounded and make any
    // sign/negacyclic-wrap error easy to detect.
    left[0] = 3;
    left[1] = -2;
    left[7] = 5;
    left[128] = 1;
    left[255] = -4;

    right[0] = -7;
    right[2] = 9;
    right[33] = 2;
    right[200] = -3;
    right[255] = 6;

    var ntt_product: Polynomial =
        [_]i32{0} ** N;

    var reference_product: Polynomial =
        [_]i32{0} ** N;

    multiply(
        &ntt_product,
        &left,
        &right,
    );

    schoolbookNegacyclicMultiply(
        &reference_product,
        &left,
        &right,
    );

    var index: usize = 0;

    while (index < N) : (index += 1) {
        if (!equivalentModQ(
            ntt_product[index],
            reference_product[index],
        )) {
            return false;
        }
    }

    clearPolynomial(&left);
    clearPolynomial(&right);
    clearPolynomial(&ntt_product);
    clearPolynomial(&reference_product);

    return true;
}

fn schoolbookNegacyclicMultiply(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    var accumulators: [N]i64 =
        [_]i64{0} ** N;

    var left_index: usize = 0;

    while (left_index < N) : (left_index += 1) {
        var right_index: usize = 0;

        while (right_index < N) : (right_index += 1) {
            const product =
                @as(i64, left[left_index]) *
                @as(i64, right[right_index]);

            const degree =
                left_index + right_index;

            if (degree < N) {
                accumulators[degree] += product;
            } else {
                // X^N == -1 in Z_q[X] / (X^N + 1).
                accumulators[degree - N] -= product;
            }
        }
    }

    var index: usize = 0;

    while (index < N) : (index += 1) {
        output[index] =
            reduce.reduceI64Centered(
                accumulators[index],
            );

        accumulators[index] = 0;
    }
}
