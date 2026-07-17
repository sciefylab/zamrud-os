//! Zamrud OS - Native Keccak-f[1600] / SHAKE
//!
//! Implements:
//! - Keccak-f[1600]
//! - SHAKE128
//! - SHAKE256
//!
//! Design:
//! - Pure Zig.
//! - Freestanding.
//! - No allocator.
//! - No libc.
//! - No vendor dependency.
//! - Explicit little-endian encoding.
//! - Streaming absorb and squeeze.
//! - State can be securely cleared.
//!
//! Standard:
//! - FIPS 202 SHA-3 Standard.
//!
//! SHAKE domain suffix:
//! - 0x1F
//!
//! Rates:
//! - SHAKE128: 168 bytes
//! - SHAKE256: 136 bytes

const constant_time = @import("constant_time.zig");

// =============================================================================
// Constants
// =============================================================================

pub const STATE_LANES: usize = 25;
pub const STATE_BYTES: usize = 200;

pub const SHAKE128_RATE: usize = 168;
pub const SHAKE256_RATE: usize = 136;

const SHAKE_DOMAIN_SUFFIX: u8 = 0x1F;

const ROUND_CONSTANTS: [24]u64 = .{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

// Indexed as x + 5*y.
const ROTATION_OFFSETS: [25]u6 = .{
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14,
};

// =============================================================================
// Types
// =============================================================================

pub const Mode = enum(u8) {
    shake128 = 1,
    shake256 = 2,
};

pub const Phase = enum(u8) {
    absorbing = 0,
    squeezing = 1,
};

pub const Shake = struct {
    state: [STATE_LANES]u64,
    rate: usize,
    position: usize,
    phase: Phase,

    // =========================================================================
    // Construction
    // =========================================================================

    pub fn init128() Shake {
        return .{
            .state = [_]u64{0} ** STATE_LANES,
            .rate = SHAKE128_RATE,
            .position = 0,
            .phase = .absorbing,
        };
    }

    pub fn init256() Shake {
        return .{
            .state = [_]u64{0} ** STATE_LANES,
            .rate = SHAKE256_RATE,
            .position = 0,
            .phase = .absorbing,
        };
    }

    pub fn init(mode: Mode) Shake {
        return switch (mode) {
            .shake128 => init128(),
            .shake256 => init256(),
        };
    }

    // =========================================================================
    // Absorb
    // =========================================================================

    pub fn update(self: *Shake, input: []const u8) bool {
        if (self.phase != .absorbing) {
            return false;
        }

        var input_pos: usize = 0;

        while (input_pos < input.len) {
            const available = self.rate - self.position;
            const remaining = input.len - input_pos;
            const take = @min(available, remaining);

            xorBytesIntoState(
                &self.state,
                self.position,
                input[input_pos .. input_pos + take],
            );

            self.position += take;
            input_pos += take;

            if (self.position == self.rate) {
                keccakF1600(&self.state);
                self.position = 0;
            }
        }

        return true;
    }

    // =========================================================================
    // Finalize
    // =========================================================================

    pub fn finalize(self: *Shake) bool {
        if (self.phase != .absorbing) {
            return false;
        }

        xorByteIntoState(
            &self.state,
            self.position,
            SHAKE_DOMAIN_SUFFIX,
        );

        xorByteIntoState(
            &self.state,
            self.rate - 1,
            0x80,
        );

        keccakF1600(&self.state);

        self.position = 0;
        self.phase = .squeezing;

        return true;
    }

    // =========================================================================
    // Squeeze
    // =========================================================================

    pub fn squeeze(self: *Shake, output: []u8) bool {
        if (self.phase == .absorbing) {
            if (!self.finalize()) return false;
        }

        if (self.phase != .squeezing) {
            return false;
        }

        var output_pos: usize = 0;

        while (output_pos < output.len) {
            if (self.position == self.rate) {
                keccakF1600(&self.state);
                self.position = 0;
            }

            const available = self.rate - self.position;
            const remaining = output.len - output_pos;
            const take = @min(available, remaining);

            extractBytesFromState(
                &self.state,
                self.position,
                output[output_pos .. output_pos + take],
            );

            self.position += take;
            output_pos += take;
        }

        return true;
    }

    // =========================================================================
    // Clear
    // =========================================================================

    pub fn clear(self: *Shake) void {
        secureZeroU64(self.state[0..]);

        self.rate = 0;
        self.position = 0;
        self.phase = .absorbing;
    }
};

// =============================================================================
// One-Shot API
// =============================================================================

pub fn shake128(
    output: []u8,
    input: []const u8,
) bool {
    var ctx = Shake.init128();
    defer ctx.clear();

    if (!ctx.update(input)) return false;
    return ctx.squeeze(output);
}

pub fn shake256(
    output: []u8,
    input: []const u8,
) bool {
    var ctx = Shake.init256();
    defer ctx.clear();

    if (!ctx.update(input)) return false;
    return ctx.squeeze(output);
}

// =============================================================================
// Keccak-f[1600]
// =============================================================================

pub fn keccakF1600(state: *[STATE_LANES]u64) void {
    var round: usize = 0;

    while (round < ROUND_CONSTANTS.len) : (round += 1) {
        var c: [5]u64 = undefined;
        var d: [5]u64 = undefined;
        var b: [25]u64 = undefined;

        // Theta
        var x: usize = 0;

        while (x < 5) : (x += 1) {
            c[x] =
                state[x] ^
                state[x + 5] ^
                state[x + 10] ^
                state[x + 15] ^
                state[x + 20];
        }

        x = 0;
        while (x < 5) : (x += 1) {
            d[x] =
                c[(x + 4) % 5] ^
                rotateLeft64(c[(x + 1) % 5], 1);
        }

        var y: usize = 0;

        while (y < 5) : (y += 1) {
            x = 0;

            while (x < 5) : (x += 1) {
                state[x + 5 * y] ^= d[x];
            }
        }

        // Rho + Pi
        y = 0;

        while (y < 5) : (y += 1) {
            x = 0;

            while (x < 5) : (x += 1) {
                const source_index = x + 5 * y;
                const destination_x = y;
                const destination_y = (2 * x + 3 * y) % 5;
                const destination_index =
                    destination_x + 5 * destination_y;

                b[destination_index] = rotateLeft64(
                    state[source_index],
                    ROTATION_OFFSETS[source_index],
                );
            }
        }

        // Chi
        y = 0;

        while (y < 5) : (y += 1) {
            x = 0;

            while (x < 5) : (x += 1) {
                const current = x + 5 * y;
                const next = ((x + 1) % 5) + 5 * y;
                const next_next = ((x + 2) % 5) + 5 * y;

                state[current] =
                    b[current] ^
                    ((~b[next]) & b[next_next]);
            }
        }

        // Iota
        state[0] ^= ROUND_CONSTANTS[round];

        secureZeroU64(c[0..]);
        secureZeroU64(d[0..]);
        secureZeroU64(b[0..]);
    }
}

// =============================================================================
// State Byte Access
// =============================================================================

fn xorBytesIntoState(
    state: *[STATE_LANES]u64,
    offset: usize,
    input: []const u8,
) void {
    var i: usize = 0;

    while (i < input.len) : (i += 1) {
        xorByteIntoState(
            state,
            offset + i,
            input[i],
        );
    }
}

fn xorByteIntoState(
    state: *[STATE_LANES]u64,
    byte_index: usize,
    value: u8,
) void {
    const lane_index = byte_index / 8;
    const lane_offset = byte_index % 8;
    const shift: u6 = @intCast(lane_offset * 8);

    state[lane_index] ^=
        @as(u64, value) << shift;
}

fn extractBytesFromState(
    state: *const [STATE_LANES]u64,
    offset: usize,
    output: []u8,
) void {
    var i: usize = 0;

    while (i < output.len) : (i += 1) {
        const byte_index = offset + i;
        const lane_index = byte_index / 8;
        const lane_offset = byte_index % 8;
        const shift: u6 = @intCast(lane_offset * 8);

        output[i] =
            @truncate(state[lane_index] >> shift);
    }
}

// =============================================================================
// Helpers
// =============================================================================

inline fn rotateLeft64(
    value: u64,
    amount: u6,
) u64 {
    if (amount == 0) return value;

    return (value << amount) |
        (value >> @intCast(64 - @as(u7, amount)));
}

fn secureZeroU64(values: []u64) void {
    const byte_len =
        values.len * @sizeOf(u64);

    const byte_ptr: [*]u8 =
        @ptrCast(values.ptr);

    constant_time.secureZero(
        byte_ptr[0..byte_len],
    );
}

fn constantTimeEqual(
    left: []const u8,
    right: []const u8,
) bool {
    if (left.len != right.len) return false;

    var difference: u8 = 0;

    var i: usize = 0;

    while (i < left.len) : (i += 1) {
        difference |= left[i] ^ right[i];
    }

    return difference == 0;
}

// =============================================================================
// FIPS 202 Self-Tests
// =============================================================================

pub fn selfTest() bool {
    return testShake128Empty() and
        testShake256Empty() and
        testStreamingConsistency() and
        testMultiBlockSqueeze();
}

fn testShake128Empty() bool {
    const expected = [32]u8{
        0x7F, 0x9C, 0x2B, 0xA4,
        0xE8, 0x8F, 0x82, 0x7D,
        0x61, 0x60, 0x45, 0x50,
        0x76, 0x05, 0x85, 0x3E,
        0xD7, 0x3B, 0x80, 0x93,
        0xF6, 0xEF, 0xBC, 0x88,
        0xEB, 0x1A, 0x6E, 0xAC,
        0xFA, 0x66, 0xEF, 0x26,
    };

    var output: [32]u8 = undefined;

    if (!shake128(&output, "")) {
        return false;
    }

    const valid =
        constantTimeEqual(&output, &expected);

    constant_time.secureZero(&output);

    return valid;
}

fn testShake256Empty() bool {
    const expected = [64]u8{
        0x46, 0xB9, 0xDD, 0x2B,
        0x0B, 0xA8, 0x8D, 0x13,
        0x23, 0x3B, 0x3F, 0xEB,
        0x74, 0x3E, 0xEB, 0x24,
        0x3F, 0xCD, 0x52, 0xEA,
        0x62, 0xB8, 0x1B, 0x82,
        0xB5, 0x0C, 0x27, 0x64,
        0x6E, 0xD5, 0x76, 0x2F,
        0xD7, 0x5D, 0xC4, 0xDD,
        0xD8, 0xC0, 0xF2, 0x00,
        0xCB, 0x05, 0x01, 0x9D,
        0x67, 0xB5, 0x92, 0xF6,
        0xFC, 0x82, 0x1C, 0x49,
        0x47, 0x9A, 0xB4, 0x86,
        0x40, 0x29, 0x2E, 0xAC,
        0xB3, 0xB7, 0xC4, 0xBE,
    };

    var output: [64]u8 = undefined;

    if (!shake256(&output, "")) {
        return false;
    }

    const valid =
        constantTimeEqual(&output, &expected);

    constant_time.secureZero(&output);

    return valid;
}

fn testStreamingConsistency() bool {
    const message =
        "Zamrud OS native SHAKE streaming test";

    var one_shot: [96]u8 = undefined;
    var streaming: [96]u8 = undefined;

    if (!shake256(&one_shot, message)) {
        return false;
    }

    var ctx = Shake.init256();
    defer ctx.clear();

    if (!ctx.update(message[0..7])) {
        return false;
    }

    if (!ctx.update(message[7..19])) {
        return false;
    }

    if (!ctx.update(message[19..])) {
        return false;
    }

    if (!ctx.squeeze(&streaming)) {
        return false;
    }

    const valid =
        constantTimeEqual(&one_shot, &streaming);

    constant_time.secureZero(&one_shot);
    constant_time.secureZero(&streaming);

    return valid;
}

fn testMultiBlockSqueeze() bool {
    var one_shot: [400]u8 = undefined;
    var split: [400]u8 = undefined;

    if (!shake128(
        &one_shot,
        "ZAMRUD-KECCAK-MULTIBLOCK",
    )) {
        return false;
    }

    var ctx = Shake.init128();
    defer ctx.clear();

    if (!ctx.update(
        "ZAMRUD-KECCAK-MULTIBLOCK",
    )) {
        return false;
    }

    if (!ctx.squeeze(split[0..113])) {
        return false;
    }

    if (!ctx.squeeze(split[113..251])) {
        return false;
    }

    if (!ctx.squeeze(split[251..])) {
        return false;
    }

    const valid =
        constantTimeEqual(&one_shot, &split);

    constant_time.secureZero(&one_shot);
    constant_time.secureZero(&split);

    return valid;
}
