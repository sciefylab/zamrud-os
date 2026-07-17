//! Zamrud OS - SLOR-DSA / ML-DSA-65 Rounding and Hint Operations
//!
//! Internal rounding primitive for the single native ML-DSA-65 backend.
//!
//! Implements:
//! - Power2Round
//! - Decompose
//! - HighBits
//! - LowBits
//! - MakeHint
//! - UseHint
//! - Polynomial/vector wrappers
//!
//! Dependency direction:
//!
//!   gov_sign.zig
//!       -> slor_dsa.zig
//!           -> slor_dsa_rounding.zig
//!               -> slor_dsa_poly.zig
//!               -> slor_dsa_reduce.zig
//!               -> slor_dsa_params.zig
//!
//! This module does not implement a second signature scheme.
//!
//! Fixed parameter set:
//! - ML-DSA-65
//! - GAMMA2 = (q - 1) / 32
//! - high-bit range = 0..15

const params = @import("slor_dsa_params.zig");
const poly = @import("slor_dsa_poly.zig");
const reduce = @import("slor_dsa_reduce.zig");

// =============================================================================
// Public Types
// =============================================================================

pub const Power2RoundResult = struct {
    high: i32,
    low: i32,
};

pub const DecomposeResult = struct {
    high: i32,
    low: i32,
};

// Hint coefficients are encoded as 0 or 1.
pub const HintPolynomial = [params.N]u8;
pub const HintVecK = [params.K]HintPolynomial;

// =============================================================================
// Power2Round
// =============================================================================

/// Split a canonical coefficient into:
///
///   coefficient = high * 2^D + low
///
/// with a small centered low part.
pub inline fn power2Round(
    coefficient: i32,
) Power2RoundResult {
    const high =
        (coefficient +
            ((@as(i32, 1) <<
                (params.D - 1)) - 1)) >>
        params.D;

    const low =
        coefficient -
        (high << params.D);

    return .{
        .high = high,
        .low = low,
    };
}

// =============================================================================
// Decompose
// =============================================================================

/// Decompose a coefficient into high and low parts relative to 2*GAMMA2.
///
/// For ML-DSA-65:
///
///   GAMMA2 = (q - 1) / 32
///
/// so the high part lies in:
///
///   0..15
pub inline fn decompose(
    coefficient: i32,
) DecomposeResult {
    const canonical =
        reduce.freeze(coefficient);

    var high =
        (canonical + 127) >> 7;

    high =
        (high * 1025 +
            (@as(i32, 1) << 21)) >>
        22;

    high &= 15;

    var low =
        canonical -
        high * (2 * params.GAMMA2);

    // If low exceeds (q - 1) / 2, subtract q to center it.
    low -=
        ((((params.Q - 1) / 2) - low) >> 31) &
        params.Q;

    return .{
        .high = high,
        .low = low,
    };
}

pub inline fn highBits(
    coefficient: i32,
) i32 {
    return decompose(coefficient).high;
}

pub inline fn lowBits(
    coefficient: i32,
) i32 {
    return decompose(coefficient).low;
}

// =============================================================================
// Hint Operations
// =============================================================================

/// Return 1 when the high bits would change after adding the low component.
///
/// Inputs match the ML-DSA MakeHint operation:
///
///   low_part  -> r0
///   high_part -> r1
pub inline fn makeHint(
    low_part: i32,
    high_part: i32,
) u8 {
    if (low_part > params.GAMMA2) {
        return 1;
    }

    if (low_part < -params.GAMMA2) {
        return 1;
    }

    if (low_part == -params.GAMMA2 and
        high_part != 0)
    {
        return 1;
    }

    return 0;
}

/// Reconstruct adjusted high bits using a one-bit hint.
///
/// Invalid hint values fail closed by returning null.
pub inline fn useHint(
    coefficient: i32,
    hint: u8,
) ?i32 {
    if (hint > 1) return null;

    const parts = decompose(coefficient);

    if (hint == 0) {
        return parts.high;
    }

    if (parts.low > 0) {
        return (parts.high + 1) & 15;
    }

    return (parts.high - 1) & 15;
}

// =============================================================================
// Polynomial Power2Round
// =============================================================================

pub fn power2RoundPolynomial(
    high_output: *poly.Polynomial,
    low_output: *poly.Polynomial,
    input: *const poly.Polynomial,
) void {
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        const result =
            power2Round(input[index]);

        high_output[index] = result.high;
        low_output[index] = result.low;
    }
}

pub fn power2RoundVecK(
    high_output: *poly.PolyVecK,
    low_output: *poly.PolyVecK,
    input: *const poly.PolyVecK,
) void {
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        power2RoundPolynomial(
            &high_output[vector_index],
            &low_output[vector_index],
            &input[vector_index],
        );
    }
}

// =============================================================================
// Polynomial Decompose
// =============================================================================

pub fn decomposePolynomial(
    high_output: *poly.Polynomial,
    low_output: *poly.Polynomial,
    input: *const poly.Polynomial,
) void {
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        const result =
            decompose(input[index]);

        high_output[index] = result.high;
        low_output[index] = result.low;
    }
}

pub fn decomposeVecK(
    high_output: *poly.PolyVecK,
    low_output: *poly.PolyVecK,
    input: *const poly.PolyVecK,
) void {
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        decomposePolynomial(
            &high_output[vector_index],
            &low_output[vector_index],
            &input[vector_index],
        );
    }
}

// =============================================================================
// Polynomial Hint Generation
// =============================================================================

pub fn zeroHintPolynomial(
    hints: *HintPolynomial,
) void {
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        hints[index] = 0;
    }
}

pub fn zeroHintVecK(
    hints: *HintVecK,
) void {
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        zeroHintPolynomial(
            &hints[vector_index],
        );
    }
}

/// Generate hints for one polynomial.
///
/// Returns the number of set hint bits.
pub fn makeHintPolynomial(
    hints: *HintPolynomial,
    low: *const poly.Polynomial,
    high: *const poly.Polynomial,
) usize {
    var count: usize = 0;
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        const hint =
            makeHint(
                low[index],
                high[index],
            );

        hints[index] = hint;
        count += hint;
    }

    return count;
}

/// Generate hints for a K-vector.
///
/// Returns the total hint weight.
///
/// The caller must reject when:
///
///   returned_weight > OMEGA
pub fn makeHintVecK(
    hints: *HintVecK,
    low: *const poly.PolyVecK,
    high: *const poly.PolyVecK,
) usize {
    var count: usize = 0;
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        count += makeHintPolynomial(
            &hints[vector_index],
            &low[vector_index],
            &high[vector_index],
        );
    }

    return count;
}

// =============================================================================
// Polynomial Hint Application
// =============================================================================

/// Apply hints to one polynomial.
///
/// Returns false if a malformed hint coefficient is encountered.
pub fn useHintPolynomial(
    output: *poly.Polynomial,
    input: *const poly.Polynomial,
    hints: *const HintPolynomial,
) bool {
    var valid: u8 = 1;
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        const adjusted =
            useHint(
                input[index],
                hints[index],
            );

        if (adjusted) |value| {
            output[index] = value;
        } else {
            output[index] = 0;
            valid = 0;
        }
    }

    return valid == 1;
}

/// Apply hints to a K-vector.
///
/// Returns false if any hint coefficient is malformed.
pub fn useHintVecK(
    output: *poly.PolyVecK,
    input: *const poly.PolyVecK,
    hints: *const HintVecK,
) bool {
    var valid: u8 = 1;
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        if (!useHintPolynomial(
            &output[vector_index],
            &input[vector_index],
            &hints[vector_index],
        )) {
            valid = 0;
        }
    }

    return valid == 1;
}

// =============================================================================
// Hint Validation
// =============================================================================

pub fn hintWeightPolynomial(
    hints: *const HintPolynomial,
) ?usize {
    var count: usize = 0;
    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        if (hints[index] > 1) {
            return null;
        }

        count += hints[index];
    }

    return count;
}

pub fn hintWeightVecK(
    hints: *const HintVecK,
) ?usize {
    var count: usize = 0;
    var vector_index: usize = 0;

    while (vector_index < params.K) : (vector_index += 1) {
        count += hintWeightPolynomial(
            &hints[vector_index],
        ) orelse return null;
    }

    return count;
}

pub fn hintsWithinOmega(
    hints: *const HintVecK,
) bool {
    const weight =
        hintWeightVecK(hints) orelse return false;

    return weight <= params.OMEGA;
}

// =============================================================================
// Self-Test
// =============================================================================

pub fn selfTest() bool {
    if (!testPower2Round()) return false;
    if (!testDecomposeReconstruction()) return false;
    if (!testDecomposeRange()) return false;
    if (!testMakeHintBoundaries()) return false;
    if (!testUseHint()) return false;
    if (!testPolynomialOperations()) return false;
    if (!testHintWeightValidation()) return false;

    return true;
}

fn testPower2Round() bool {
    const inputs = [_]i32{
        0,
        1,
        -1,
        params.Q - 1,
        params.Q / 2,
        8191,
        8192,
        8193,
        123_456,
        -123_456,
    };

    for (inputs) |input| {
        const result =
            power2Round(input);

        const reconstructed =
            (result.high << params.D) +
            result.low;

        if (reconstructed != input) {
            return false;
        }

        const half =
            @as(i32, 1) <<
            (params.D - 1);

        if (result.low <= -half or
            result.low > half)
        {
            return false;
        }
    }

    return true;
}

fn testDecomposeReconstruction() bool {
    const inputs = [_]i32{
        0,
        1,
        -1,
        params.Q - 1,
        params.Q,
        params.Q + 1,
        params.Q / 2,
        params.GAMMA2,
        -params.GAMMA2,
        2 * params.GAMMA2,
        123_456,
        -123_456,
    };

    for (inputs) |input| {
        const result =
            decompose(input);

        const reconstructed =
            @as(i64, result.high) *
            @as(i64, 2 * params.GAMMA2) +
            @as(i64, result.low);

        const input_canonical =
            reduce.reduceI64Canonical(input);

        const reconstructed_canonical =
            reduce.reduceI64Canonical(
                reconstructed,
            );

        if (input_canonical !=
            reconstructed_canonical)
        {
            return false;
        }
    }

    return true;
}

fn testDecomposeRange() bool {
    var value: i32 = 0;

    while (value < params.Q) : (value += 13_337) {
        const result =
            decompose(value);

        if (result.high < 0 or
            result.high > 15)
        {
            return false;
        }

        if (result.low < -params.GAMMA2 or
            result.low > params.GAMMA2)
        {
            return false;
        }
    }

    return true;
}

fn testMakeHintBoundaries() bool {
    if (makeHint(0, 0) != 0) {
        return false;
    }

    if (makeHint(params.GAMMA2, 7) != 0) {
        return false;
    }

    if (makeHint(params.GAMMA2 + 1, 0) != 1) {
        return false;
    }

    if (makeHint(-params.GAMMA2, 0) != 0) {
        return false;
    }

    if (makeHint(-params.GAMMA2, 1) != 1) {
        return false;
    }

    if (makeHint(-params.GAMMA2 - 1, 0) != 1) {
        return false;
    }

    return true;
}

fn testUseHint() bool {
    const values = [_]i32{
        0,
        1,
        params.GAMMA2,
        params.GAMMA2 + 1,
        2 * params.GAMMA2,
        params.Q - 1,
        params.Q / 2,
    };

    for (values) |value| {
        const parts =
            decompose(value);

        const unchanged =
            useHint(value, 0) orelse return false;

        if (unchanged != parts.high) {
            return false;
        }

        const adjusted =
            useHint(value, 1) orelse return false;

        const expected =
            if (parts.low > 0)
                (parts.high + 1) & 15
            else
                (parts.high - 1) & 15;

        if (adjusted != expected) {
            return false;
        }
    }

    if (useHint(0, 2) != null) {
        return false;
    }

    return true;
}

fn testPolynomialOperations() bool {
    var input: poly.Polynomial =
        [_]i32{0} ** params.N;

    var high: poly.Polynomial =
        [_]i32{0} ** params.N;

    var low: poly.Polynomial =
        [_]i32{0} ** params.N;

    var index: usize = 0;

    while (index < params.N) : (index += 1) {
        input[index] =
            @intCast(
                (index * 18_271 + 9) %
                    @as(
                        usize,
                        @intCast(params.Q),
                    ),
            );
    }

    decomposePolynomial(
        &high,
        &low,
        &input,
    );

    index = 0;

    while (index < params.N) : (index += 1) {
        const reconstructed =
            @as(i64, high[index]) *
            @as(
                i64,
                2 * params.GAMMA2,
            ) +
            @as(i64, low[index]);

        if (reduce.reduceI64Canonical(
            reconstructed,
        ) != reduce.reduceI64Canonical(
            input[index],
        )) {
            return false;
        }
    }

    poly.clear(&input);
    poly.clear(&high);
    poly.clear(&low);

    return true;
}

fn testHintWeightValidation() bool {
    var hints: HintVecK = undefined;

    zeroHintVecK(&hints);

    var index: usize = 0;

    while (index < params.OMEGA) : (index += 1) {
        const vector_index =
            index / params.N;

        const coefficient_index =
            index % params.N;

        hints[vector_index][coefficient_index] = 1;
    }

    const weight =
        hintWeightVecK(&hints) orelse return false;

    if (weight != params.OMEGA) {
        return false;
    }

    if (!hintsWithinOmega(&hints)) {
        return false;
    }

    hints[0][params.OMEGA] = 1;

    if (hintsWithinOmega(&hints)) {
        return false;
    }

    hints[0][params.OMEGA] = 2;

    if (hintWeightVecK(&hints) != null) {
        return false;
    }

    zeroHintVecK(&hints);

    return true;
}
