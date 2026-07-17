//! Zamrud OS - Native ML-DSA-65 signing engine.
//!
//! Single-backend internal module. This file does not import slor_sign.zig.
//! The operational API should be exposed only through slor_dsa.zig/gov_sign.zig.

const params = @import("slor_dsa_params.zig");
const keccak = @import("keccak.zig");
const random = @import("random.zig");
const poly = @import("slor_dsa_poly.zig");
const rounding = @import("slor_dsa_rounding.zig");
const sampling = @import("slor_dsa_sampling.zig");
const packing = @import("slor_dsa_pack.zig");

pub const SecretKeyBytes = packing.SecretKeyBytes;
pub const SignatureBytes = packing.SignatureBytes;
pub const RandomBytes = [params.RNDBYTES]u8;

pub const MAX_CONTEXT_BYTES: usize = 255;
pub const MAX_SIGN_ATTEMPTS: u16 = 1024;
const W1_BYTES: usize = params.K * params.POLY_W1_PACKED_BYTES;
const DOMAIN_PURE: u8 = 0;

var busy: bool = false;
var sk_parts: packing.SecretKeyParts = undefined;
var mu: [params.MU_BYTES]u8 = [_]u8{0} ** params.MU_BYTES;
var rho_double_prime: [params.MU_BYTES]u8 = [_]u8{0} ** params.MU_BYTES;
var challenge_digest: [params.CTILDE_BYTES]u8 = [_]u8{0} ** params.CTILDE_BYTES;
var challenge: poly.Polynomial = undefined;
var y: poly.PolyVecL = undefined;
var y_ntt: poly.PolyVecL = undefined;
var z: poly.PolyVecL = undefined;
var matrix_row: poly.PolyVecL = undefined;
var w: poly.PolyVecK = undefined;
var w1: poly.PolyVecK = undefined;
var w0: poly.PolyVecK = undefined;
var cs1: poly.PolyVecL = undefined;
var cs2: poly.PolyVecK = undefined;
var ct0: poly.PolyVecK = undefined;
var hints: rounding.HintVecK = undefined;
var packed_w1: [W1_BYTES]u8 = [_]u8{0} ** W1_BYTES;

fn acquire() bool {
    if (busy) return false;
    busy = true;
    clearWorkspace();
    return true;
}

fn release() void {
    clearWorkspace();
    busy = false;
}

fn clearWorkspace() void {
    packing.clearSecretParts(&sk_parts);
    @memset(mu[0..], 0);
    @memset(rho_double_prime[0..], 0);
    @memset(challenge_digest[0..], 0);
    @memset(packed_w1[0..], 0);
    poly.zero(&challenge);
    poly.zeroVecL(&y);
    poly.zeroVecL(&y_ntt);
    poly.zeroVecL(&z);
    poly.zeroVecL(&matrix_row);
    poly.zeroVecK(&w);
    poly.zeroVecK(&w1);
    poly.zeroVecK(&w0);
    poly.zeroVecL(&cs1);
    poly.zeroVecK(&cs2);
    poly.zeroVecK(&ct0);
    rounding.zeroHintVecK(&hints);
}

fn computeMu(
    output: *[params.MU_BYTES]u8,
    tr: *const [params.TR_BYTES]u8,
    context: []const u8,
    message: []const u8,
) bool {
    if (context.len > MAX_CONTEXT_BYTES) return false;
    var xof = keccak.Shake.init256();
    defer xof.clear();
    if (!xof.update(tr)) return false;
    const prefix = [2]u8{ DOMAIN_PURE, @intCast(context.len) };
    if (!xof.update(&prefix)) return false;
    if (!xof.update(context)) return false;
    if (!xof.update(message)) return false;
    return xof.squeeze(output);
}

fn computeRhoDoublePrime(
    output: *[params.MU_BYTES]u8,
    key: *const [params.SEED_BYTES]u8,
    rnd: *const RandomBytes,
    message_digest: *const [params.MU_BYTES]u8,
) bool {
    var xof = keccak.Shake.init256();
    defer xof.clear();
    if (!xof.update(key)) return false;
    if (!xof.update(rnd)) return false;
    if (!xof.update(message_digest)) return false;
    return xof.squeeze(output);
}

fn computeChallengeDigest(
    output: *[params.CTILDE_BYTES]u8,
    message_digest: *const [params.MU_BYTES]u8,
    encoded_w1: *const [W1_BYTES]u8,
) bool {
    var xof = keccak.Shake.init256();
    defer xof.clear();
    if (!xof.update(message_digest)) return false;
    if (!xof.update(encoded_w1)) return false;
    return xof.squeeze(output);
}

fn encodeW1(vector: *const poly.PolyVecK) bool {
    var row: usize = 0;
    while (row < params.K) : (row += 1) {
        var encoded: [params.POLY_W1_PACKED_BYTES]u8 = undefined;
        if (!packing.packW1(&encoded, &vector[row])) return false;
        const start = row * params.POLY_W1_PACKED_BYTES;
        @memcpy(packed_w1[start .. start + encoded.len], &encoded);
        @memset(encoded[0..], 0);
    }
    return true;
}

fn matrixTimesMask() bool {
    y_ntt = y;
    poly.forwardNttVecL(&y_ntt);
    var row: usize = 0;
    while (row < params.K) : (row += 1) {
        if (!sampling.expandMatrixRow(&matrix_row, &sk_parts.rho, row)) return false;
        poly.matrixRowPointwiseMultiply(&w[row], &matrix_row, &y_ntt);
        poly.inverseNttToMontgomery(&w[row]);
        poly.reduceCoefficients(&w[row]);
        poly.conditionalAddQ(&w[row]);
        poly.zeroVecL(&matrix_row);
    }
    return true;
}

fn multiplyChallengeVecL(output: *poly.PolyVecL, input: *const poly.PolyVecL) void {
    var i: usize = 0;
    while (i < params.L) : (i += 1) poly.multiply(&output[i], &challenge, &input[i]);
}

fn multiplyChallengeVecK(output: *poly.PolyVecK, input: *const poly.PolyVecK) void {
    var i: usize = 0;
    while (i < params.K) : (i += 1) poly.multiply(&output[i], &challenge, &input[i]);
}

pub fn signDeterministic(
    signature: *SignatureBytes,
    message: []const u8,
    context: []const u8,
    secret_key: *const SecretKeyBytes,
) bool {
    const zero_random = [_]u8{0} ** params.RNDBYTES;
    return signWithRandomness(signature, message, context, secret_key, &zero_random);
}

pub fn signRandomized(
    signature: *SignatureBytes,
    message: []const u8,
    context: []const u8,
    secret_key: *const SecretKeyBytes,
) bool {
    var rnd: RandomBytes = [_]u8{0} ** params.RNDBYTES;
    random.getBytes(&rnd);
    defer @memset(rnd[0..], 0);
    return signWithRandomness(signature, message, context, secret_key, &rnd);
}

pub fn signWithRandomness(
    signature: *SignatureBytes,
    message: []const u8,
    context: []const u8,
    secret_key: *const SecretKeyBytes,
    rnd: *const RandomBytes,
) bool {
    @memset(signature[0..], 0);
    if (context.len > MAX_CONTEXT_BYTES) return false;
    if (!acquire()) return false;
    defer release();

    if (!packing.unpackSecretKey(&sk_parts, secret_key)) return false;
    if (!computeMu(&mu, &sk_parts.tr, context, message)) return false;
    if (!computeRhoDoublePrime(&rho_double_prime, &sk_parts.key, rnd, &mu)) return false;

    var attempt: u16 = 0;
    while (attempt < MAX_SIGN_ATTEMPTS) : (attempt += 1) {
        if (!sampling.sampleGamma1VecL(&y, &rho_double_prime, attempt)) return false;
        if (!matrixTimesMask()) return false;

        rounding.decomposeVecK(&w1, &w0, &w);
        if (!encodeW1(&w1)) return false;
        if (!computeChallengeDigest(&challenge_digest, &mu, &packed_w1)) return false;
        if (!sampling.sampleInBall(&challenge, &challenge_digest)) return false;

        multiplyChallengeVecL(&cs1, &sk_parts.s1);
        poly.addVecL(&z, &y, &cs1);
        poly.reduceVecL(&z);
        if (poly.checkNormVecL(&z, params.Z_BOUND)) continue;

        multiplyChallengeVecK(&cs2, &sk_parts.s2);
        poly.subtractVecKInPlace(&w0, &cs2);
        poly.reduceVecK(&w0);
        if (poly.checkNormVecK(&w0, params.R0_BOUND)) continue;

        multiplyChallengeVecK(&ct0, &sk_parts.t0);
        poly.reduceVecK(&ct0);
        if (poly.checkNormVecK(&ct0, params.GAMMA2)) continue;

        poly.addVecKInPlace(&w0, &ct0);
        poly.reduceVecK(&w0);
        rounding.zeroHintVecK(&hints);
        const weight = rounding.makeHintVecK(&hints, &w0, &w1);
        if (weight > params.OMEGA) continue;

        if (!packing.packSignature(signature, &challenge_digest, &z, &hints)) {
            @memset(signature[0..], 0);
            return false;
        }
        return true;
    }

    @memset(signature[0..], 0);
    return false;
}
