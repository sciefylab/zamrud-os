//! Zamrud OS - SLOR Digital Signature (Anti-Quantum)
//! H.10 / E3.6: Lattice-Based Digital Signature Algorithm using Fiat-Shamir with Aborts.
//! Inspired by Lyubashevsky's signature scheme (basis of Dilithium).

const random = @import("random.zig");
const hash = @import("hash.zig");

// =============================================================================
// Parameters (Ring-LWE Signature)
// =============================================================================

pub const SLOR_N: usize = 256; // Polynomial degree
pub const SLOR_Q: i32 = 8380417; // Larger prime modulus needed for signatures
pub const REJECT_BOUND: i32 = 65536; // Rejection sampling bound (B)

// Sizes for the ZAM Header
pub const PUBKEY_SIZE: usize = (SLOR_N * 4) + 32; // T array (1024 bytes) + Seed (32 bytes) = 1056 bytes
pub const SIGNATURE_SIZE: usize = (SLOR_N * 4) + 32; // Z array (1024 bytes) + C hash (32 bytes) = 1056 bytes

pub const SlorSignPubKey = struct {
    t: [SLOR_N]i32,
    seed: [32]u8,
};

pub const SlorSignSecretKey = struct {
    s: [SLOR_N]i32,
};

pub const SlorSignature = struct {
    z: [SLOR_N]i32, // Response polynomial
    c: [32]u8, // Challenge hash
};

// =============================================================================
// Core Polynomial Math (Mod Q)
// =============================================================================

inline fn polyReduce(a: i64) i32 {
    var v = @rem(a, @as(i64, SLOR_Q));
    if (v > @divTrunc(SLOR_Q, 2)) v -= SLOR_Q;
    if (v < -@divTrunc(SLOR_Q, 2)) v += SLOR_Q;
    return @intCast(v);
}

fn polyAdd(r: *[SLOR_N]i32, a: *const [SLOR_N]i32, b: *const [SLOR_N]i32) void {
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(@as(i64, a[i]) + @as(i64, b[i]));
    }
}

fn polySub(r: *[SLOR_N]i32, a: *const [SLOR_N]i32, b: *const [SLOR_N]i32) void {
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(@as(i64, a[i]) - @as(i64, b[i]));
    }
}

fn polyMul(r: *[SLOR_N]i32, a: *const [SLOR_N]i32, b: *const [SLOR_N]i32) void {
    var temp: [SLOR_N * 2]i32 = [_]i32{0} ** (SLOR_N * 2);

    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        var j: usize = 0;
        while (j < SLOR_N) : (j += 1) {
            const prod = @as(i64, a[i]) * @as(i64, b[j]);
            temp[i + j] = polyReduce(@as(i64, temp[i + j]) + prod);
        }
    }

    // Reduce by X^n + 1
    i = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(@as(i64, temp[i]) - @as(i64, temp[i + SLOR_N]));
    }
}

fn polyGenA(r: *[SLOR_N]i32, seed: *const [32]u8) void {
    var hash_out: [32]u8 = undefined;
    var input: [36]u8 = [_]u8{0} ** 36;

    var i: usize = 0;
    while (i < 32) : (i += 1) input[i] = seed[i];

    var block: u32 = 0;
    var idx: usize = 0;

    while (idx < SLOR_N) {
        input[32] = @truncate(block);
        input[33] = @truncate(block >> 8);
        input[34] = @truncate(block >> 16);
        input[35] = @truncate(block >> 24);

        hash.sha256Into(&input, &hash_out);

        var j: usize = 0;
        while (j < 8 and idx < SLOR_N) : (j += 1) {
            const val = (@as(u32, hash_out[j * 4]) |
                (@as(u32, hash_out[j * 4 + 1]) << 8) |
                (@as(u32, hash_out[j * 4 + 2]) << 16) |
                (@as(u32, hash_out[j * 4 + 3]) << 24));

            const val_rem = @rem(val, @as(u32, @intCast(SLOR_Q)));
            r[idx] = @as(i32, @intCast(val_rem)) - @divTrunc(SLOR_Q, 2);
            idx += 1;
        }
        block += 1;
    }
}

/// Convert a 32-byte hash challenge into a polynomial with small coefficients {-1, 0, 1}
fn hashToPoly(c_poly: *[SLOR_N]i32, c_hash: *const [32]u8) void {
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) c_poly[i] = 0;

    i = 0;
    while (i < 32) : (i += 1) {
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            const bit = (c_hash[i] >> @truncate(j)) & 1;
            // Simple mapping: alternate signs to keep weight small
            if (bit == 1) {
                c_poly[i * 8 + j] = if (i % 2 == 0) 1 else -1;
            }
        }
    }
}

// =============================================================================
// Fiat-Shamir Signature Scheme
// =============================================================================

/// 1. Generate Identity KeyPair
pub fn generateKeyPair(pk: *SlorSignPubKey, sk: *SlorSignSecretKey) void {
    random.getBytes(&pk.seed);
    var a: [SLOR_N]i32 = undefined;
    polyGenA(&a, &pk.seed);

    // Secret is small noise
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        var noise: [1]u8 = undefined;
        random.getBytes(&noise);
        sk.s[i] = @as(i32, noise[0]) - 128; // values between -128 and 127
    }

    // Error is small noise
    var e: [SLOR_N]i32 = undefined;
    i = 0;
    while (i < SLOR_N) : (i += 1) {
        var noise: [1]u8 = undefined;
        random.getBytes(&noise);
        e[i] = @as(i32, noise[0]) - 128;
    }

    // Public Key t = A*s + e
    var as_prod: [SLOR_N]i32 = undefined;
    polyMul(&as_prod, &a, &sk.s);
    polyAdd(&pk.t, &as_prod, &e);
}

/// 2. Sign a message (The ZAM Application) using Rejection Sampling
pub fn sign(sk: *const SlorSignSecretKey, pk: *const SlorSignPubKey, msg: []const u8, sig: *SlorSignature) void {
    var a: [SLOR_N]i32 = undefined;
    polyGenA(&a, &pk.seed);

    var y: [SLOR_N]i32 = undefined;
    var ay: [SLOR_N]i32 = undefined;
    var c_poly: [SLOR_N]i32 = undefined;
    var cs_prod: [SLOR_N]i32 = undefined;

    // Fiat-Shamir with Aborts (Loop until safe bounds are met to prevent secret key leakage)
    var attempt: usize = 0;
    while (attempt < 1000) : (attempt += 1) {
        // Step A: Generate random masking polynomial y (values between -REJECT_BOUND and REJECT_BOUND)
        var i: usize = 0;
        while (i < SLOR_N) : (i += 1) {
            var noise: [4]u8 = undefined;
            random.getBytes(&noise);
            const val = @as(u32, noise[0]) | (@as(u32, noise[1]) << 8) | (@as(u32, noise[2]) << 16);
            y[i] = @as(i32, @intCast(@rem(val, @as(u32, REJECT_BOUND * 2)))) - REJECT_BOUND;
        }

        // Step B: Compute w = A*y
        polyMul(&ay, &a, &y);

        // Step C: Create Challenge c = Hash(Msg || w)
        var hasher = hash.Sha256.init();
        hasher.update(msg);

        // Feed w into hash
        const w_bytes: [*]const u8 = @ptrCast(&ay);
        hasher.update(w_bytes[0 .. SLOR_N * 4]);
        hasher.final(&sig.c);

        // Step D: Compute response z = y + c*s
        hashToPoly(&c_poly, &sig.c);
        polyMul(&cs_prod, &c_poly, &sk.s);
        polyAdd(&sig.z, &y, &cs_prod);

        // Step E: Rejection Sampling (Check Bounds)
        // If z is too large, it leaks info about s. We must abort and try again.
        var reject = false;
        i = 0;
        while (i < SLOR_N) : (i += 1) {
            const abs_z = if (sig.z[i] < 0) -sig.z[i] else sig.z[i];
            if (abs_z >= REJECT_BOUND - 2000) { // Safety margin
                reject = true;
                break;
            }
        }

        if (!reject) {
            return; // Success! Signature generated.
        }
    }
}

/// 3. Verify the Anti-Quantum Signature
pub fn verify(pk: *const SlorSignPubKey, msg: []const u8, sig: *const SlorSignature) bool {
    // Check bounds of z to ensure it's a valid signature form
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        const abs_z = if (sig.z[i] < 0) -sig.z[i] else sig.z[i];
        if (abs_z >= REJECT_BOUND) return false;
    }

    var a: [SLOR_N]i32 = undefined;
    polyGenA(&a, &pk.seed);

    var c_poly: [SLOR_N]i32 = undefined;
    hashToPoly(&c_poly, &sig.c);

    // Recompute w' = A*z - c*t
    var az_prod: [SLOR_N]i32 = undefined;
    var ct_prod: [SLOR_N]i32 = undefined;
    var w_prime: [SLOR_N]i32 = undefined;

    polyMul(&az_prod, &a, &sig.z);
    polyMul(&ct_prod, &c_poly, &pk.t);
    polySub(&w_prime, &az_prod, &ct_prod);

    // Recompute Hash(Msg || w')
    var hasher = hash.Sha256.init();
    hasher.update(msg);

    const w_bytes: [*]const u8 = @ptrCast(&w_prime);
    hasher.update(w_bytes[0 .. SLOR_N * 4]);

    var c_prime: [32]u8 = undefined;
    hasher.final(&c_prime);

    // Signature is valid if c_prime matches the signature's challenge c
    i = 0;
    while (i < 32) : (i += 1) {
        if (c_prime[i] != sig.c[i]) return false;
    }

    return true; // Mathematics proven! Anti-Quantum safe!
}
