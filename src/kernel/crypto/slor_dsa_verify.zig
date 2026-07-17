//! Zamrud OS - Native ML-DSA-65 verification engine.
//!
//! Strict, fail-closed verifier for the single SLOR-DSA backend.

const params = @import("slor_dsa_params.zig");
const keccak = @import("keccak.zig");
const poly = @import("slor_dsa_poly.zig");
const rounding = @import("slor_dsa_rounding.zig");
const sampling = @import("slor_dsa_sampling.zig");
const packing = @import("slor_dsa_pack.zig");

pub const PublicKeyBytes = packing.PublicKeyBytes;
pub const SignatureBytes = packing.SignatureBytes;
pub const MAX_CONTEXT_BYTES: usize = 255;
const W1_BYTES: usize = params.K * params.POLY_W1_PACKED_BYTES;
const DOMAIN_PURE: u8 = 0;

var busy: bool = false;
var pk_rho: [params.SEED_BYTES]u8 = [_]u8{0} ** params.SEED_BYTES;
var t1: poly.PolyVecK = undefined;
var sig_parts: packing.SignatureParts = undefined;
var tr: [params.TR_BYTES]u8 = [_]u8{0} ** params.TR_BYTES;
var mu: [params.MU_BYTES]u8 = [_]u8{0} ** params.MU_BYTES;
var challenge: poly.Polynomial = undefined;
var z_ntt: poly.PolyVecL = undefined;
var matrix_row: poly.PolyVecL = undefined;
var az: poly.PolyVecK = undefined;
var ct1: poly.PolyVecK = undefined;
var reconstructed: poly.PolyVecK = undefined;
var w1: poly.PolyVecK = undefined;
var packed_w1: [W1_BYTES]u8 = [_]u8{0} ** W1_BYTES;
var expected_challenge: [params.CTILDE_BYTES]u8 = [_]u8{0} ** params.CTILDE_BYTES;

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
    @memset(pk_rho[0..], 0);
    @memset(tr[0..], 0);
    @memset(mu[0..], 0);
    @memset(packed_w1[0..], 0);
    @memset(expected_challenge[0..], 0);
    poly.zeroVecK(&t1);
    packing.clearSignatureParts(&sig_parts);
    poly.zero(&challenge);
    poly.zeroVecL(&z_ntt);
    poly.zeroVecL(&matrix_row);
    poly.zeroVecK(&az);
    poly.zeroVecK(&ct1);
    poly.zeroVecK(&reconstructed);
    poly.zeroVecK(&w1);
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    var i: usize = 0;
    while (i < left.len) : (i += 1) difference |= left[i] ^ right[i];
    return difference == 0;
}

fn computeMu(
    output: *[params.MU_BYTES]u8,
    public_key_hash: *const [params.TR_BYTES]u8,
    context: []const u8,
    message: []const u8,
) bool {
    if (context.len > MAX_CONTEXT_BYTES) return false;
    var xof = keccak.Shake.init256();
    defer xof.clear();
    if (!xof.update(public_key_hash)) return false;
    const prefix = [2]u8{ DOMAIN_PURE, @intCast(context.len) };
    if (!xof.update(&prefix)) return false;
    if (!xof.update(context)) return false;
    if (!xof.update(message)) return false;
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

fn computeExpectedChallenge() bool {
    var xof = keccak.Shake.init256();
    defer xof.clear();
    if (!xof.update(&mu)) return false;
    if (!xof.update(&packed_w1)) return false;
    return xof.squeeze(&expected_challenge);
}

fn matrixTimesZ() bool {
    z_ntt = sig_parts.z;
    poly.forwardNttVecL(&z_ntt);
    var row: usize = 0;
    while (row < params.K) : (row += 1) {
        if (!sampling.expandMatrixRow(&matrix_row, &pk_rho, row)) return false;
        poly.matrixRowPointwiseMultiply(&az[row], &matrix_row, &z_ntt);
        poly.inverseNttToMontgomery(&az[row]);
        poly.reduceCoefficients(&az[row]);
        poly.zeroVecL(&matrix_row);
    }
    return true;
}

fn computeChallengeTimesT1() void {
    var row: usize = 0;
    while (row < params.K) : (row += 1) {
        var shifted = t1[row];
        poly.shiftLeftD(&shifted);
        poly.multiply(&ct1[row], &challenge, &shifted);
        poly.clear(&shifted);
    }
}

pub fn verify(
    signature: *const SignatureBytes,
    message: []const u8,
    context: []const u8,
    public_key: *const PublicKeyBytes,
) bool {
    if (context.len > MAX_CONTEXT_BYTES) return false;
    if (!acquire()) return false;
    defer release();

    if (!packing.unpackPublicKey(&pk_rho, &t1, public_key)) return false;
    if (!packing.unpackSignature(&sig_parts, signature)) return false;
    if (!rounding.hintsWithinOmega(&sig_parts.hints)) return false;
    if (poly.checkNormVecL(&sig_parts.z, params.Z_BOUND)) return false;

    if (!keccak.shake256(&tr, public_key)) return false;
    if (!computeMu(&mu, &tr, context, message)) return false;
    if (!sampling.sampleInBall(&challenge, &sig_parts.challenge)) return false;
    if (!matrixTimesZ()) return false;

    computeChallengeTimesT1();
    poly.subtractVecK(&reconstructed, &az, &ct1);
    poly.reduceVecK(&reconstructed);
    poly.conditionalAddQVecK(&reconstructed);

    if (!rounding.useHintVecK(&w1, &reconstructed, &sig_parts.hints)) return false;
    if (!encodeW1(&w1)) return false;
    if (!computeExpectedChallenge()) return false;

    return constantTimeEqual(&expected_challenge, &sig_parts.challenge);
}
