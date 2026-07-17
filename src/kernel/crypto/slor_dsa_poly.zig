//! Zamrud OS - SLOR-DSA / ML-DSA-65 Polynomial Operations
//!
//! Internal polynomial and vector primitive for the single native
//! ML-DSA-65 governance-signature backend.
//!
//! Dependency direction:
//!
//!   gov_sign.zig
//!       -> slor_dsa.zig
//!           -> slor_dsa_poly.zig
//!               -> slor_dsa_ntt.zig
//!               -> slor_dsa_reduce.zig
//!               -> slor_dsa_params.zig
//!
//! This module must not be imported directly by identity, P2P, authority,
//! governance, shell, or application modules.
//!
//! Properties:
//! - Pure Zig.
//! - Freestanding.
//! - No allocator.
//! - No libc.
//! - No vendor dependency.
//! - No alternate signature implementation.
//! - Fixed ML-DSA-65 dimensions only.
//!
//! Important:
//! Matrix is a large type:
//!
//!   K * L * N * sizeof(i32)
//!   = 6 * 5 * 256 * 4
//!   = 30,720 bytes
//!
//! Never instantiate Matrix as a local variable on a small kernel stack.
//! Use static storage or stream matrix polynomials during expansion.

const params = @import("slor_dsa_params.zig");
const reduce = @import("slor_dsa_reduce.zig");
const ntt = @import("slor_dsa_ntt.zig");

// =============================================================================
// Public Constants
// =============================================================================

pub const N: usize = params.N;
pub const K: usize = params.K;
pub const L: usize = params.L;
pub const Q: i32 = params.Q;

// =============================================================================
// Public Types
// =============================================================================

pub const Polynomial = [N]i32;

pub const PolyVecL = [L]Polynomial;
pub const PolyVecK = [K]Polynomial;

// Matrix[row][column][coefficient]
//
// WARNING:
// This type is approximately 30 KiB. Do not allocate it on the kernel stack.
pub const Matrix = [K][L]Polynomial;

// =============================================================================
// Polynomial Initialization and Clear
// =============================================================================

pub fn zero(polynomial: *Polynomial) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        polynomial[index] = 0;
    }
}

pub fn set(
    destination: *Polynomial,
    source: *const Polynomial,
) void {
    destination.* = source.*;
}

pub fn clear(polynomial: *Polynomial) void {
    // Explicit volatile-style overwrite is not available through a generic
    // optimizer barrier here. This function performs deterministic overwrite;
    // secret-key lifecycle code must additionally use constant_time.secureZero
    // on serialized secret buffers.
    zero(polynomial);
}

pub fn zeroVecL(vector: *PolyVecL) void {
    var index: usize = 0;

    while (index < L) : (index += 1) {
        zero(&vector[index]);
    }
}

pub fn zeroVecK(vector: *PolyVecK) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        zero(&vector[index]);
    }
}

pub fn clearVecL(vector: *PolyVecL) void {
    zeroVecL(vector);
}

pub fn clearVecK(vector: *PolyVecK) void {
    zeroVecK(vector);
}

// =============================================================================
// Coefficient-Wise Arithmetic
// =============================================================================

pub fn add(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        output[index] =
            left[index] + right[index];
    }
}

pub fn subtract(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        output[index] =
            left[index] - right[index];
    }
}

pub fn negate(
    output: *Polynomial,
    input: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        output[index] = -input[index];
    }
}

pub fn addInPlace(
    destination: *Polynomial,
    source: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        destination[index] += source[index];
    }
}

pub fn subtractInPlace(
    destination: *Polynomial,
    source: *const Polynomial,
) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        destination[index] -= source[index];
    }
}

/// Shift every coefficient left by D bits.
///
/// This is used when reconstructing t from t1:
///
///   t1 * 2^D
pub fn shiftLeftD(polynomial: *Polynomial) void {
    var index: usize = 0;

    while (index < N) : (index += 1) {
        polynomial[index] <<= params.D;
    }
}

// =============================================================================
// Modular Reduction
// =============================================================================

pub fn reduceCoefficients(polynomial: *Polynomial) void {
    reduce.reducePolynomial(polynomial[0..]);
}

pub fn conditionalAddQ(polynomial: *Polynomial) void {
    reduce.conditionalAddQPolynomial(
        polynomial[0..],
    );
}

pub fn freezeCoefficients(polynomial: *Polynomial) void {
    reduce.freezePolynomial(polynomial[0..]);
}

pub fn toMontgomery(polynomial: *Polynomial) void {
    reduce.toMontgomeryPolynomial(polynomial[0..]);
}

pub fn fromMontgomery(polynomial: *Polynomial) void {
    reduce.fromMontgomeryPolynomial(
        polynomial[0..],
    );
}

// =============================================================================
// Number Theoretic Transform Wrappers
// =============================================================================

pub fn forwardNtt(polynomial: *Polynomial) void {
    ntt.forward(polynomial);
}

pub fn inverseNttToMontgomery(
    polynomial: *Polynomial,
) void {
    ntt.inverseToMontgomery(polynomial);
}

/// Pointwise multiplication of two NTT-domain polynomials.
pub fn pointwiseMontgomery(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    ntt.pointwiseMontgomery(
        output,
        left,
        right,
    );
}

/// Full negacyclic polynomial multiplication in normal representation.
pub fn multiply(
    output: *Polynomial,
    left: *const Polynomial,
    right: *const Polynomial,
) void {
    ntt.multiply(
        output,
        left,
        right,
    );
}

// =============================================================================
// Norm Checks
// =============================================================================

/// Return the absolute value of a bounded coefficient without invoking
/// undefined behavior for the minimum i32 value.
///
/// ML-DSA coefficients passed here must already be substantially smaller than
/// minInt(i32). The explicit minInt check keeps malformed input fail-closed.
fn absoluteCoefficient(value: i32) ?i32 {
    if (value == @as(i32, -2_147_483_648)) {
        return null;
    }

    return if (value < 0) -value else value;
}

/// Check whether any centered coefficient has absolute value >= bound.
///
/// Returns true when the bound is violated.
///
/// This follows the common ML-DSA "chknorm" behavior:
///
///   true  -> reject
///   false -> accept
///
/// The caller must pass:
///
///   0 < bound <= (q - 1) / 8
///
/// for standard ML-DSA rejection checks.
pub fn checkNorm(
    polynomial: *const Polynomial,
    bound: i32,
) bool {
    if (bound <= 0) return true;
    if (bound > (Q - 1) / 8) return true;

    var violated: u32 = 0;
    var index: usize = 0;

    while (index < N) : (index += 1) {
        const absolute =
            absoluteCoefficient(polynomial[index]) orelse return true;

        const difference =
            @as(i64, absolute) -
            @as(i64, bound);

        // difference >= 0 means violation.
        const sign: u64 =
            @bitCast(difference);

        const is_negative: u32 =
            @truncate(sign >> 63);

        violated |= is_negative ^ 1;
    }

    return violated != 0;
}

// =============================================================================
// PolyVecL Operations
// =============================================================================

pub fn copyVecL(
    destination: *PolyVecL,
    source: *const PolyVecL,
) void {
    destination.* = source.*;
}

pub fn addVecL(
    output: *PolyVecL,
    left: *const PolyVecL,
    right: *const PolyVecL,
) void {
    var index: usize = 0;

    while (index < L) : (index += 1) {
        add(
            &output[index],
            &left[index],
            &right[index],
        );
    }
}

pub fn reduceVecL(vector: *PolyVecL) void {
    var index: usize = 0;

    while (index < L) : (index += 1) {
        reduceCoefficients(&vector[index]);
    }
}

pub fn forwardNttVecL(vector: *PolyVecL) void {
    var index: usize = 0;

    while (index < L) : (index += 1) {
        forwardNtt(&vector[index]);
    }
}

pub fn inverseNttToMontgomeryVecL(
    vector: *PolyVecL,
) void {
    var index: usize = 0;

    while (index < L) : (index += 1) {
        inverseNttToMontgomery(
            &vector[index],
        );
    }
}

pub fn checkNormVecL(
    vector: *const PolyVecL,
    bound: i32,
) bool {
    var violated: u32 = 0;
    var index: usize = 0;

    while (index < L) : (index += 1) {
        if (checkNorm(&vector[index], bound)) {
            violated = 1;
        }
    }

    return violated != 0;
}

// =============================================================================
// PolyVecK Operations
// =============================================================================

pub fn copyVecK(
    destination: *PolyVecK,
    source: *const PolyVecK,
) void {
    destination.* = source.*;
}

pub fn addVecK(
    output: *PolyVecK,
    left: *const PolyVecK,
    right: *const PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        add(
            &output[index],
            &left[index],
            &right[index],
        );
    }
}

pub fn subtractVecK(
    output: *PolyVecK,
    left: *const PolyVecK,
    right: *const PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        subtract(
            &output[index],
            &left[index],
            &right[index],
        );
    }
}

pub fn addVecKInPlace(
    destination: *PolyVecK,
    source: *const PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        addInPlace(
            &destination[index],
            &source[index],
        );
    }
}

pub fn subtractVecKInPlace(
    destination: *PolyVecK,
    source: *const PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        subtractInPlace(
            &destination[index],
            &source[index],
        );
    }
}

pub fn reduceVecK(vector: *PolyVecK) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        reduceCoefficients(&vector[index]);
    }
}

pub fn conditionalAddQVecK(
    vector: *PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        conditionalAddQ(&vector[index]);
    }
}

pub fn freezeVecK(vector: *PolyVecK) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        freezeCoefficients(&vector[index]);
    }
}

pub fn shiftLeftDVecK(vector: *PolyVecK) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        shiftLeftD(&vector[index]);
    }
}

pub fn forwardNttVecK(vector: *PolyVecK) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        forwardNtt(&vector[index]);
    }
}

pub fn inverseNttToMontgomeryVecK(
    vector: *PolyVecK,
) void {
    var index: usize = 0;

    while (index < K) : (index += 1) {
        inverseNttToMontgomery(
            &vector[index],
        );
    }
}

pub fn checkNormVecK(
    vector: *const PolyVecK,
    bound: i32,
) bool {
    var violated: u32 = 0;
    var index: usize = 0;

    while (index < K) : (index += 1) {
        if (checkNorm(&vector[index], bound)) {
            violated = 1;
        }
    }

    return violated != 0;
}

// =============================================================================
// NTT Dot Product
// =============================================================================

/// Compute the NTT-domain dot product of two L-dimensional vectors:
///
///   output = sum_i left[i] * right[i]
///
/// Inputs must already be in NTT representation.
///
/// Output remains in NTT representation.
pub fn pointwiseAccumulateVecL(
    output: *Polynomial,
    left: *const PolyVecL,
    right: *const PolyVecL,
) void {
    var temporary: Polynomial =
        [_]i32{0} ** N;

    pointwiseMontgomery(
        output,
        &left[0],
        &right[0],
    );

    var vector_index: usize = 1;

    while (vector_index < L) : (vector_index += 1) {
        pointwiseMontgomery(
            &temporary,
            &left[vector_index],
            &right[vector_index],
        );

        addInPlace(
            output,
            &temporary,
        );
    }

    reduceCoefficients(output);
    clear(&temporary);
}

// =============================================================================
// Matrix-Vector Multiplication
// =============================================================================

/// Multiply a complete expanded K x L matrix by an NTT-domain L-vector.
///
/// Inputs:
/// - matrix entries are in NTT representation;
/// - vector entries are in NTT representation.
///
/// Output:
/// - K polynomials in NTT representation.
///
/// WARNING:
/// Matrix is approximately 30 KiB. It should be stored statically or avoided
/// by streaming one matrix row at a time.
pub fn matrixPointwiseMultiply(
    output: *PolyVecK,
    matrix: *const Matrix,
    vector: *const PolyVecL,
) void {
    var row: usize = 0;

    while (row < K) : (row += 1) {
        pointwiseAccumulateVecL(
            &output[row],
            &matrix[row],
            vector,
        );
    }
}

/// Multiply a single matrix row by an NTT-domain L-vector.
///
/// This function is preferred in the kernel because matrix rows can be
/// generated and consumed one at a time without allocating a complete matrix.
pub fn matrixRowPointwiseMultiply(
    output: *Polynomial,
    row: *const PolyVecL,
    vector: *const PolyVecL,
) void {
    pointwiseAccumulateVecL(
        output,
        row,
        vector,
    );
}

// =============================================================================
// Equality Helpers
// =============================================================================

pub fn equivalentModuloQ(
    left: *const Polynomial,
    right: *const Polynomial,
) bool {
    var difference: u32 = 0;
    var index: usize = 0;

    while (index < N) : (index += 1) {
        const left_canonical =
            reduce.reduceI64Canonical(left[index]);

        const right_canonical =
            reduce.reduceI64Canonical(right[index]);

        difference |= @as(
            u32,
            @bitCast(left_canonical ^ right_canonical),
        );
    }

    return difference == 0;
}

// =============================================================================
// Self-Test
// =============================================================================

pub fn selfTest() bool {
    if (!testZeroAndCopy()) return false;
    if (!testAddSubtract()) return false;
    if (!testShiftLeftD()) return false;
    if (!testNormCheck()) return false;
    if (!testNttRoundTrip()) return false;
    if (!testMultiplication()) return false;
    if (!testVectorOperations()) return false;
    if (!testPointwiseAccumulate()) return false;

    return true;
}

fn testZeroAndCopy() bool {
    var source: Polynomial =
        [_]i32{0} ** N;

    var destination: Polynomial =
        [_]i32{0} ** N;

    var index: usize = 0;

    while (index < N) : (index += 1) {
        source[index] =
            @intCast(index * 17);
    }

    set(&destination, &source);

    index = 0;

    while (index < N) : (index += 1) {
        if (destination[index] != source[index]) {
            return false;
        }
    }

    zero(&destination);

    for (destination) |coefficient| {
        if (coefficient != 0) return false;
    }

    clear(&source);
    clear(&destination);

    return true;
}

fn testAddSubtract() bool {
    var left: Polynomial =
        [_]i32{0} ** N;

    var right: Polynomial =
        [_]i32{0} ** N;

    var sum: Polynomial =
        [_]i32{0} ** N;

    var restored: Polynomial =
        [_]i32{0} ** N;

    var index: usize = 0;

    while (index < N) : (index += 1) {
        left[index] = @intCast(index * 7);
        right[index] = @intCast(index * 11);
    }

    add(&sum, &left, &right);
    subtract(&restored, &sum, &right);

    if (!equivalentModuloQ(
        &left,
        &restored,
    )) {
        return false;
    }

    clear(&left);
    clear(&right);
    clear(&sum);
    clear(&restored);

    return true;
}

fn testShiftLeftD() bool {
    var polynomial: Polynomial =
        [_]i32{0} ** N;

    polynomial[0] = 1;
    polynomial[1] = -1;
    polynomial[2] = 17;

    shiftLeftD(&polynomial);

    if (polynomial[0] !=
        (@as(i32, 1) << params.D))
    {
        return false;
    }

    if (polynomial[1] !=
        -(@as(i32, 1) << params.D))
    {
        return false;
    }

    if (polynomial[2] !=
        (@as(i32, 17) << params.D))
    {
        return false;
    }

    clear(&polynomial);

    return true;
}

fn testNormCheck() bool {
    var polynomial: Polynomial =
        [_]i32{0} ** N;

    polynomial[0] = 5;
    polynomial[1] = -7;
    polynomial[2] = 99;

    if (checkNorm(&polynomial, 100)) {
        return false;
    }

    polynomial[7] = 100;

    if (!checkNorm(&polynomial, 100)) {
        return false;
    }

    polynomial[7] = -100;

    if (!checkNorm(&polynomial, 100)) {
        return false;
    }

    if (!checkNorm(&polynomial, 0)) {
        return false;
    }

    clear(&polynomial);

    return true;
}

fn testNttRoundTrip() bool {
    var original: Polynomial =
        [_]i32{0} ** N;

    var transformed: Polynomial =
        [_]i32{0} ** N;

    var index: usize = 0;

    while (index < N) : (index += 1) {
        original[index] =
            @intCast(
                (index * 97 + 13) %
                    @as(usize, @intCast(Q)),
            );
    }

    transformed = original;

    forwardNtt(&transformed);
    inverseNttToMontgomery(&transformed);
    fromMontgomery(&transformed);
    reduceCoefficients(&transformed);

    const valid = equivalentModuloQ(
        &original,
        &transformed,
    );

    clear(&original);
    clear(&transformed);

    return valid;
}

fn testMultiplication() bool {
    var left: Polynomial =
        [_]i32{0} ** N;

    var right: Polynomial =
        [_]i32{0} ** N;

    var product: Polynomial =
        [_]i32{0} ** N;

    left[0] = 2;
    left[1] = 3;

    right[0] = 5;
    right[1] = 7;

    multiply(
        &product,
        &left,
        &right,
    );

    if (!coefficientsEquivalent(
        product[0],
        10,
    )) {
        return false;
    }

    if (!coefficientsEquivalent(
        product[1],
        29,
    )) {
        return false;
    }

    if (!coefficientsEquivalent(
        product[2],
        21,
    )) {
        return false;
    }

    var index: usize = 3;

    while (index < N) : (index += 1) {
        if (!coefficientsEquivalent(
            product[index],
            0,
        )) {
            return false;
        }
    }

    clear(&left);
    clear(&right);
    clear(&product);

    return true;
}

fn testVectorOperations() bool {
    var left: PolyVecK = undefined;
    var right: PolyVecK = undefined;
    var sum: PolyVecK = undefined;
    var restored: PolyVecK = undefined;

    zeroVecK(&left);
    zeroVecK(&right);
    zeroVecK(&sum);
    zeroVecK(&restored);

    var vector_index: usize = 0;

    while (vector_index < K) : (vector_index += 1) {
        left[vector_index][0] =
            @intCast(vector_index + 1);

        right[vector_index][0] =
            @intCast((vector_index + 1) * 3);
    }

    addVecK(&sum, &left, &right);
    subtractVecK(&restored, &sum, &right);

    vector_index = 0;

    while (vector_index < K) : (vector_index += 1) {
        if (!equivalentModuloQ(
            &left[vector_index],
            &restored[vector_index],
        )) {
            return false;
        }
    }

    clearVecK(&left);
    clearVecK(&right);
    clearVecK(&sum);
    clearVecK(&restored);

    return true;
}

fn testPointwiseAccumulate() bool {
    var left: PolyVecL = undefined;
    var right: PolyVecL = undefined;

    zeroVecL(&left);
    zeroVecL(&right);

    var vector_index: usize = 0;

    while (vector_index < L) : (vector_index += 1) {
        left[vector_index][0] =
            @intCast(vector_index + 1);

        right[vector_index][0] =
            @intCast(vector_index + 2);

        forwardNtt(&left[vector_index]);
        forwardNtt(&right[vector_index]);
    }

    var output: Polynomial =
        [_]i32{0} ** N;

    pointwiseAccumulateVecL(
        &output,
        &left,
        &right,
    );

    // Pointwise Montgomery multiplication and InvNTTToMont cancel their
    // respective R^-1 and R factors. The result is already normal-domain.
    inverseNttToMontgomery(&output);
    reduceCoefficients(&output);

    var expected: i32 = 0;

    vector_index = 0;

    while (vector_index < L) : (vector_index += 1) {
        expected +=
            @as(i32, @intCast(vector_index + 1)) *
            @as(i32, @intCast(vector_index + 2));
    }

    if (!coefficientsEquivalent(
        output[0],
        expected,
    )) {
        return false;
    }

    var coefficient_index: usize = 1;

    while (coefficient_index < N) : (coefficient_index += 1) {
        if (!coefficientsEquivalent(
            output[coefficient_index],
            0,
        )) {
            return false;
        }
    }

    clearVecL(&left);
    clearVecL(&right);
    clear(&output);

    return true;
}

fn coefficientsEquivalent(
    left: i32,
    right: i32,
) bool {
    return reduce.reduceI64Canonical(left) ==
        reduce.reduceI64Canonical(right);
}
