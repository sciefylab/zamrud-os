//! Zamrud OS - Native ML-DSA-65 Sampling
//! Internal module of the single SLOR-DSA backend.
//!
//! Implements:
//! - ExpandA / RejNTTPoly using SHAKE128
//! - ExpandS / RejBoundedPoly using SHAKE256
//! - ExpandMask using SHAKE256
//! - SampleInBall using SHAKE256
//!
//! Security:
//! - Pure Zig, freestanding.
//! - No allocator or libc.
//! - No modulo-biased uniform sampling.
//! - rho_prime correctly uses 64 bytes.
//! - Fixed ML-DSA-65 parameter set.
//! - No dependency on slor_sign.zig or slor.zig.

const params = @import("slor_dsa_params.zig");
const keccak = @import("keccak.zig");
const poly = @import("slor_dsa_poly.zig");

// ===============================================================================
// Seed Sizes
// ===============================================================================

pub const RHO_BYTES: usize = params.SEED_BYTES;
pub const RHO_PRIME_BYTES: usize = 64;
pub const MASK_SEED_BYTES: usize = params.MU_BYTES;
pub const CHALLENGE_BYTES: usize = params.CTILDE_BYTES;

// ===============================================================================
// Static Work Buffers
// ===============================================================================

var seed_nonce_32: [RHO_BYTES + 2]u8 =
    [_]u8{0} ** (RHO_BYTES + 2);

var seed_nonce_64: [RHO_PRIME_BYTES + 2]u8 =
    [_]u8{0} ** (RHO_PRIME_BYTES + 2);

var mask_nonce_input: [MASK_SEED_BYTES + 2]u8 =
    [_]u8{0} ** (MASK_SEED_BYTES + 2);

var shake128_block: [params.SHAKE128_RATE]u8 =
    [_]u8{0} ** params.SHAKE128_RATE;

var shake256_block: [params.SHAKE256_RATE]u8 =
    [_]u8{0} ** params.SHAKE256_RATE;

var gamma1_bytes: [params.POLY_Z_PACKED_BYTES]u8 =
    [_]u8{0} ** params.POLY_Z_PACKED_BYTES;

// ===============================================================================
// Internal XOF Reader
// ===============================================================================

const Shake256Reader = struct {
    context: keccak.Shake,
    block: [params.SHAKE256_RATE]u8,
    position: usize,

    fn init(input: []const u8) ?Shake256Reader {
        var reader = Shake256Reader{
            .context = keccak.Shake.init256(),
            .block = [_]u8{0} ** params.SHAKE256_RATE,
            .position = params.SHAKE256_RATE,
        };

        if (!reader.context.update(input)) {
            reader.clear();
            return null;
        }

        return reader;
    }

    fn next(self: *Shake256Reader) ?u8 {
        if (self.position == self.block.len) {
            if (!self.context.squeeze(&self.block)) {
                return null;
            }

            self.position = 0;
        }

        const result = self.block[self.position];
        self.position += 1;
        return result;
    }

    fn clear(self: *Shake256Reader) void {
        self.context.clear();
        @memset(self.block[0..], 0);
        self.position = 0;
    }
};

// ===============================================================================
// Seed + Nonce Encoding
// ===============================================================================

fn appendNonce(
    output: []u8,
    seed: []const u8,
    nonce: u16,
) bool {
    if (output.len != seed.len + 2) return false;

    @memcpy(output[0..seed.len], seed);

    output[seed.len] = @truncate(nonce);
    output[seed.len + 1] = @truncate(nonce >> 8);

    return true;
}

// ===============================================================================
// ExpandA / RejNTTPoly
// ===============================================================================

/// Sample a polynomial uniformly from [0, q).
///
/// Every candidate uses 23 bits. Values >= q are rejected, avoiding modulo
/// bias.
pub fn sampleUniform(
    output: *poly.Polynomial,
    rho: *const [RHO_BYTES]u8,
    nonce: u16,
) bool {
    poly.zero(output);

    if (!appendNonce(&seed_nonce_32, rho, nonce)) {
        return false;
    }

    var context = keccak.Shake.init128();
    defer context.clear();

    if (!context.update(&seed_nonce_32)) {
        clearWork();
        return false;
    }

    var output_index: usize = 0;

    while (output_index < params.N) {
        if (!context.squeeze(&shake128_block)) {
            poly.zero(output);
            clearWork();
            return false;
        }

        var position: usize = 0;

        while (position + 3 <= shake128_block.len and
            output_index < params.N)
        {
            const candidate =
                (@as(u32, shake128_block[position])) |
                (@as(u32, shake128_block[position + 1]) << 8) |
                (@as(u32, shake128_block[position + 2]) << 16);

            const value = candidate & 0x7F_FFFF;

            if (value < @as(u32, @intCast(params.Q))) {
                output[output_index] = @intCast(value);
                output_index += 1;
            }

            position += 3;
        }
    }

    clearWork();
    return true;
}

/// Expand one matrix element.
///
/// FIPS ML-DSA nonce ordering:
///
///   nonce = (row << 8) | column
pub fn expandMatrixElement(
    output: *poly.Polynomial,
    rho: *const [RHO_BYTES]u8,
    row: usize,
    column: usize,
) bool {
    if (row >= params.K or column >= params.L) {
        poly.zero(output);
        return false;
    }

    const nonce =
        (@as(u16, @intCast(row)) << 8) |
        @as(u16, @intCast(column));

    return sampleUniform(output, rho, nonce);
}

/// Expand one matrix row to avoid allocating the complete 30 KiB matrix.
pub fn expandMatrixRow(
    output: *poly.PolyVecL,
    rho: *const [RHO_BYTES]u8,
    row: usize,
) bool {
    if (row >= params.K) {
        poly.zeroVecL(output);
        return false;
    }

    var column: usize = 0;

    while (column < params.L) : (column += 1) {
        if (!expandMatrixElement(
            &output[column],
            rho,
            row,
            column,
        )) {
            poly.zeroVecL(output);
            return false;
        }
    }

    return true;
}

// ===============================================================================
// ExpandS / RejBoundedPoly
// ===============================================================================

/// Sample one secret polynomial from [-ETA, ETA].
///
/// rho_prime must be 64 bytes.
pub fn sampleEta(
    output: *poly.Polynomial,
    rho_prime: *const [RHO_PRIME_BYTES]u8,
    nonce: u16,
) bool {
    poly.zero(output);

    if (!appendNonce(
        &seed_nonce_64,
        rho_prime,
        nonce,
    )) {
        return false;
    }

    var context = keccak.Shake.init256();
    defer context.clear();

    if (!context.update(&seed_nonce_64)) {
        clearWork();
        return false;
    }

    var output_index: usize = 0;

    while (output_index < params.N) {
        if (!context.squeeze(&shake256_block)) {
            poly.zero(output);
            clearWork();
            return false;
        }

        var position: usize = 0;

        while (position < shake256_block.len and
            output_index < params.N)
        {
            const value = shake256_block[position];
            position += 1;

            const low = value & 0x0F;
            const high = value >> 4;

            if (low <= 8) {
                output[output_index] =
                    params.ETA - @as(i32, low);

                output_index += 1;

                if (output_index == params.N) break;
            }

            if (high <= 8) {
                output[output_index] =
                    params.ETA - @as(i32, high);

                output_index += 1;
            }
        }
    }

    clearWork();
    return true;
}

/// Expand s1 using nonces 0..L-1.
pub fn sampleEtaVecL(
    output: *poly.PolyVecL,
    rho_prime: *const [RHO_PRIME_BYTES]u8,
    starting_nonce: u16,
) bool {
    var index: usize = 0;

    while (index < params.L) : (index += 1) {
        const nonce =
            starting_nonce +%
            @as(u16, @intCast(index));

        if (!sampleEta(
            &output[index],
            rho_prime,
            nonce,
        )) {
            poly.zeroVecL(output);
            return false;
        }
    }

    return true;
}

/// Expand s2, normally using nonces L..L+K-1.
pub fn sampleEtaVecK(
    output: *poly.PolyVecK,
    rho_prime: *const [RHO_PRIME_BYTES]u8,
    starting_nonce: u16,
) bool {
    var index: usize = 0;

    while (index < params.K) : (index += 1) {
        const nonce =
            starting_nonce +%
            @as(u16, @intCast(index));

        if (!sampleEta(
            &output[index],
            rho_prime,
            nonce,
        )) {
            poly.zeroVecK(output);
            return false;
        }
    }

    return true;
}

// ===============================================================================
// ExpandMask
// ===============================================================================

/// Sample one y polynomial in (-GAMMA1, GAMMA1].
pub fn sampleGamma1(
    output: *poly.Polynomial,
    seed: *const [MASK_SEED_BYTES]u8,
    nonce: u16,
) bool {
    poly.zero(output);

    if (!appendNonce(
        &mask_nonce_input,
        seed,
        nonce,
    )) {
        return false;
    }

    var context = keccak.Shake.init256();
    defer context.clear();

    if (!context.update(&mask_nonce_input)) {
        clearWork();
        return false;
    }

    if (!context.squeeze(&gamma1_bytes)) {
        clearWork();
        return false;
    }

    var coefficient_index: usize = 0;
    var byte_index: usize = 0;

    while (coefficient_index < params.N) {
        const first =
            @as(u32, gamma1_bytes[byte_index]) |
            (@as(u32, gamma1_bytes[byte_index + 1]) << 8) |
            ((@as(u32, gamma1_bytes[byte_index + 2]) & 0x0F) << 16);

        const second =
            (@as(u32, gamma1_bytes[byte_index + 2]) >> 4) |
            (@as(u32, gamma1_bytes[byte_index + 3]) << 4) |
            (@as(u32, gamma1_bytes[byte_index + 4]) << 12);

        output[coefficient_index] =
            params.GAMMA1 - @as(i32, @intCast(first));

        output[coefficient_index + 1] =
            params.GAMMA1 - @as(i32, @intCast(second));

        coefficient_index += 2;
        byte_index += 5;
    }

    clearWork();
    return true;
}

pub fn sampleGamma1VecL(
    output: *poly.PolyVecL,
    seed: *const [MASK_SEED_BYTES]u8,
    attempt_nonce: u16,
) bool {
    var index: usize = 0;

    while (index < params.L) : (index += 1) {
        const nonce =
            @as(u16, @intCast(params.L)) *%
            attempt_nonce +%
            @as(u16, @intCast(index));

        if (!sampleGamma1(
            &output[index],
            seed,
            nonce,
        )) {
            poly.zeroVecL(output);
            return false;
        }
    }

    return true;
}

// ===============================================================================
// SampleInBall
// ===============================================================================

/// Map a 48-byte challenge digest to a polynomial with exactly TAU nonzero
/// coefficients in {-1,+1}.
pub fn sampleInBall(
    output: *poly.Polynomial,
    challenge: *const [CHALLENGE_BYTES]u8,
) bool {
    poly.zero(output);

    var reader =
        Shake256Reader.init(challenge) orelse return false;

    defer reader.clear();

    var signs: u64 = 0;
    var index: usize = 0;

    while (index < 8) : (index += 1) {
        const value =
            reader.next() orelse {
                poly.zero(output);
                return false;
            };

        signs |= @as(u64, value) <<
            @intCast(index * 8);
    }

    index = params.N - params.TAU;

    while (index < params.N) : (index += 1) {
        var selected: u8 = 0;

        while (true) {
            selected =
                reader.next() orelse {
                    poly.zero(output);
                    return false;
                };

            if (@as(usize, selected) <= index) {
                break;
            }
        }

        output[index] =
            output[@as(usize, selected)];

        output[@as(usize, selected)] =
            if ((signs & 1) == 0) 1 else -1;

        signs >>= 1;
    }

    return true;
}

// ===============================================================================
// Clear
// ===============================================================================

fn clearWork() void {
    @memset(seed_nonce_32[0..], 0);
    @memset(seed_nonce_64[0..], 0);
    @memset(mask_nonce_input[0..], 0);
    @memset(shake128_block[0..], 0);
    @memset(shake256_block[0..], 0);
    @memset(gamma1_bytes[0..], 0);
}

// ===============================================================================
// Self-Test
// ===============================================================================

pub fn selfTest() bool {
    if (!testUniform()) return false;
    if (!testEta()) return false;
    if (!testGamma1()) return false;
    if (!testChallenge()) return false;

    clearWork();
    return true;
}

fn testUniform() bool {
    var rho =
        [_]u8{0xA5} ** RHO_BYTES;

    var first =
        [_]i32{0} ** params.N;

    var second =
        [_]i32{0} ** params.N;

    if (!sampleUniform(&first, &rho, 0x0102)) {
        return false;
    }

    if (!sampleUniform(&second, &rho, 0x0102)) {
        return false;
    }

    var difference: u32 = 0;

    var index: usize = 0;
    while (index < params.N) : (index += 1) {
        if (first[index] < 0 or
            first[index] >= params.Q)
        {
            return false;
        }

        difference |= @bitCast(
            first[index] ^ second[index],
        );
    }

    poly.clear(&first);
    poly.clear(&second);
    @memset(rho[0..], 0);

    return difference == 0;
}

fn testEta() bool {
    var rho_prime =
        [_]u8{0x52} ** RHO_PRIME_BYTES;

    var output =
        [_]i32{0} ** params.N;

    if (!sampleEta(&output, &rho_prime, 7)) {
        return false;
    }

    for (output) |value| {
        if (value < -params.ETA or
            value > params.ETA)
        {
            return false;
        }
    }

    poly.clear(&output);
    @memset(rho_prime[0..], 0);

    return true;
}

fn testGamma1() bool {
    var seed =
        [_]u8{0x37} ** MASK_SEED_BYTES;

    var output =
        [_]i32{0} ** params.N;

    if (!sampleGamma1(&output, &seed, 3)) {
        return false;
    }

    for (output) |value| {
        if (value <= -params.GAMMA1 or
            value > params.GAMMA1)
        {
            return false;
        }
    }

    poly.clear(&output);
    @memset(seed[0..], 0);

    return true;
}

fn testChallenge() bool {
    var seed =
        [_]u8{0x91} ** CHALLENGE_BYTES;

    var output =
        [_]i32{0} ** params.N;

    if (!sampleInBall(&output, &seed)) {
        return false;
    }

    var weight: usize = 0;

    for (output) |value| {
        if (value == 1 or value == -1) {
            weight += 1;
        } else if (value != 0) {
            return false;
        }
    }

    poly.clear(&output);
    @memset(seed[0..], 0);

    return weight == params.TAU;
}
