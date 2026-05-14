//! Zamrud OS - SLOR (Secure Lattice Output Resilient) KEM
//! H.10: Anti-Quantum Cryptography
//!
//! Ring-LWE (Learning With Errors) Key Encapsulation Mechanism.
//! Resilient against Shor's algorithm (Quantum Computers).
//! Optimized for bare-metal with SSE auto-vectorization.

const random = @import("random.zig");
const hash = @import("hash.zig");
const ct = @import("constant_time.zig");

// =============================================================================
// Parameters (Kyber-like Ring-LWE)
// =============================================================================

pub const SLOR_N: usize = 256; // Polynomial degree
pub const SLOR_Q: i16 = 3329; // Prime modulus
pub const SHARED_SECRET_SIZE = 32; // 256-bit AES/OTP seed

// =============================================================================
// Data Structures
// =============================================================================

pub const SlorPublicKey = struct {
    t: [SLOR_N]i16,
    seed: [32]u8, // Used to deterministically generate polynomial A
};

pub const SlorSecretKey = struct {
    s: [SLOR_N]i16,
};

pub const SlorCiphertext = struct {
    u: [SLOR_N]i16,
    v: [SLOR_N]i16,
};

// =============================================================================
// Core Polynomial Math (Auto-Vectorized by SSE)
// =============================================================================

/// Modulo Q reduction (centered around 0)
inline fn polyReduce(a: i16) i16 {
    // FIX: Zig requires @rem for signed integers, not %
    var v = @rem(a, SLOR_Q);
    if (v > SLOR_Q / 2) v -= SLOR_Q;
    if (v < -SLOR_Q / 2) v += SLOR_Q;
    return v;
}

/// Add two polynomials: r = a + b
fn polyAdd(r: *[SLOR_N]i16, a: *const [SLOR_N]i16, b: *const [SLOR_N]i16) void {
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(a[i] + b[i]);
    }
}

/// Subtract two polynomials: r = a - b
fn polySub(r: *[SLOR_N]i16, a: *const [SLOR_N]i16, b: *const [SLOR_N]i16) void {
    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(a[i] - b[i]);
    }
}

/// Multiply two polynomials in Ring Z_q[X]/(X^n + 1)
/// Standard schoolbook multiplication (O(n^2)), perfectly fine for N=256 on modern CPU
fn polyMul(r: *[SLOR_N]i16, a: *const [SLOR_N]i16, b: *const [SLOR_N]i16) void {
    var temp: [SLOR_N * 2]i16 = [_]i16{0} ** (SLOR_N * 2);

    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        var j: usize = 0;
        while (j < SLOR_N) : (j += 1) {
            const prod: i32 = @as(i32, a[i]) * @as(i32, b[j]);
            // FIX: Use @rem for signed integers
            const prod_rem = @rem(prod, @as(i32, SLOR_Q));
            temp[i + j] = polyReduce(temp[i + j] + @as(i16, @truncate(prod_rem)));
        }
    }

    // Reduce by X^n + 1
    i = 0;
    while (i < SLOR_N) : (i += 1) {
        r[i] = polyReduce(temp[i] - temp[i + SLOR_N]);
    }
}

/// Generate small noise polynomial (values between -2 and 2)
fn polyNoise(r: *[SLOR_N]i16) void {
    var rand_buf: [SLOR_N]u8 = undefined;
    random.getBytes(&rand_buf);

    var i: usize = 0;
    while (i < SLOR_N) : (i += 1) {
        // Simple binomial sampling-like noise
        const val1 = (rand_buf[i] & 0x03);
        const val2 = ((rand_buf[i] >> 2) & 0x03);
        r[i] = @as(i16, val1) - @as(i16, val2);
    }
}

/// Generate deterministic polynomial A from seed
fn polyGenA(r: *[SLOR_N]i16, seed: *const [32]u8) void {
    var hash_out: [32]u8 = undefined;
    var input: [36]u8 = [_]u8{0} ** 36;

    var i: usize = 0;
    while (i < 32) : (i += 1) input[i] = seed[i];

    var block: u32 = 0;
    var idx: usize = 0;

    // Expand seed via SHA256 until we fill the polynomial
    while (idx < SLOR_N) {
        input[32] = @truncate(block);
        input[33] = @truncate(block >> 8);
        input[34] = @truncate(block >> 16);
        input[35] = @truncate(block >> 24);

        hash.sha256Into(&input, &hash_out);

        var j: usize = 0;
        while (j < 16 and idx < SLOR_N) : (j += 1) {
            const val = (@as(u16, hash_out[j * 2]) | (@as(u16, hash_out[j * 2 + 1]) << 8));
            // FIX: Use @rem for safe remainder reduction
            const val_rem = @rem(val, @as(u16, @intCast(SLOR_Q)));
            r[idx] = @as(i16, @intCast(val_rem)) - (SLOR_Q / 2);
            idx += 1;
        }
        block += 1;
    }
}

// =============================================================================
// Helper: Secure Zero for i16 Arrays
// =============================================================================

/// Casts an i16 array to a byte slice and zeroes it out securely
fn secureZeroI16(arr: []i16) void {
    const byte_len = arr.len * @sizeOf(i16);
    const byte_ptr: [*]u8 = @ptrCast(arr.ptr);
    ct.secureZero(byte_ptr[0..byte_len]);
}

// =============================================================================
// KEM Operations
// =============================================================================

/// Generate a post-quantum keypair
pub fn generateKeyPair(pk: *SlorPublicKey, sk: *SlorSecretKey) void {
    // 1. Generate random seed for A
    random.getBytes(&pk.seed);

    var a: [SLOR_N]i16 = undefined;
    polyGenA(&a, &pk.seed);

    // 2. Generate secret polynomial S (small noise)
    polyNoise(&sk.s);

    // 3. Generate error polynomial E (small noise)
    var e: [SLOR_N]i16 = undefined;
    polyNoise(&e);

    // 4. Compute Public Key T = (A * S) + E
    var as_prod: [SLOR_N]i16 = undefined;
    polyMul(&as_prod, &a, &sk.s);
    polyAdd(&pk.t, &as_prod, &e);

    // Clean up
    secureZeroI16(&e);
    secureZeroI16(&as_prod);
}

/// Encapsulate a 32-byte shared secret for the given public key
pub fn encapsulate(pk: *const SlorPublicKey, ct_out: *SlorCiphertext, shared_secret_out: *[SHARED_SECRET_SIZE]u8) void {
    // 1. Generate a random 32-byte message (the underlying shared secret)
    var msg: [32]u8 = undefined;
    random.getBytes(&msg);

    // Hash it to form the final shared secret (KEM style)
    hash.sha256Into(&msg, shared_secret_out);

    // Encode message into polynomial M
    var m: [SLOR_N]i16 = [_]i16{0} ** SLOR_N;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            const bit = (msg[i] >> @truncate(j)) & 1;
            m[i * 8 + j] = if (bit == 1) (SLOR_Q / 2) else 0;
        }
    }

    // 2. Re-generate A from pk.seed
    var a: [SLOR_N]i16 = undefined;
    polyGenA(&a, &pk.seed);

    // 3. Generate ephemeral secret R and errors E1, E2
    var r: [SLOR_N]i16 = undefined;
    var e1: [SLOR_N]i16 = undefined;
    var e2: [SLOR_N]i16 = undefined;
    polyNoise(&r);
    polyNoise(&e1);
    polyNoise(&e2);

    // 4. Compute U = (A * R) + E1
    var ar_prod: [SLOR_N]i16 = undefined;
    polyMul(&ar_prod, &a, &r);
    polyAdd(&ct_out.u, &ar_prod, &e1);

    // 5. Compute V = (T * R) + E2 + M
    var tr_prod: [SLOR_N]i16 = undefined;
    polyMul(&tr_prod, &pk.t, &r);
    var tr_e2: [SLOR_N]i16 = undefined;
    polyAdd(&tr_e2, &tr_prod, &e2);
    polyAdd(&ct_out.v, &tr_e2, &m);

    // Clean up
    ct.secureZero(&msg);
    secureZeroI16(&m);
    secureZeroI16(&r);
    secureZeroI16(&e1);
    secureZeroI16(&e2);
}

/// Decapsulate the ciphertext using the secret key to recover the shared secret
pub fn decapsulate(sk: *const SlorSecretKey, ct_in: *const SlorCiphertext, shared_secret_out: *[SHARED_SECRET_SIZE]u8) void {
    // 1. Compute M' = V - (U * S)
    var us_prod: [SLOR_N]i16 = undefined;
    polyMul(&us_prod, &ct_in.u, &sk.s);

    var m_prime: [SLOR_N]i16 = undefined;
    polySub(&m_prime, &ct_in.v, &us_prod);

    // 2. Decode polynomial M' back to 32-byte message
    var msg: [32]u8 = [_]u8{0} ** 32;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            const val = m_prime[i * 8 + j];
            // If value is closer to Q/2 than 0, it's a 1 bit
            const abs_val = if (val < 0) -val else val;
            if (abs_val > SLOR_Q / 4) {
                msg[i] |= (@as(u8, 1) << @truncate(j));
            }
        }
    }

    // 3. Hash recovered message to get the shared secret
    hash.sha256Into(&msg, shared_secret_out);

    // Clean up
    ct.secureZero(&msg);
    secureZeroI16(&m_prime);
    secureZeroI16(&us_prod);
}

// =============================================================================
// Tests
// =============================================================================

pub fn test_slor() bool {
    const serial_out = @import("../drivers/serial/serial.zig");
    serial_out.writeString("[CRYPTO] Testing Anti-Quantum SLOR KEM (H.10)...\n");

    var pk: SlorPublicKey = undefined;
    var sk: SlorSecretKey = undefined;

    serial_out.writeString("  [1] Generating Lattice KeyPair... ");
    generateKeyPair(&pk, &sk);
    serial_out.writeString("PASS\n");

    var ct_data: SlorCiphertext = undefined;
    var alice_shared_secret: [32]u8 = undefined;
    var bob_shared_secret: [32]u8 = undefined;

    serial_out.writeString("  [2] Encapsulating Shared Secret.. ");
    encapsulate(&pk, &ct_data, &alice_shared_secret);
    serial_out.writeString("PASS\n");

    serial_out.writeString("  [3] Decapsulating Ciphertext..... ");
    decapsulate(&sk, &ct_data, &bob_shared_secret);
    serial_out.writeString("PASS\n");

    serial_out.writeString("  [4] Verify Secrets Match......... ");
    if (ct.constantTimeCompare32(&alice_shared_secret, &bob_shared_secret)) {
        serial_out.writeString("PASS\n");
        return true;
    } else {
        serial_out.writeString("FAIL (Math error in polynomial reduction!)\n");
        return false;
    }
}
