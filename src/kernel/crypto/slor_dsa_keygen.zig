//! Zamrud OS - ML-DSA-65 key generation (single SLOR-DSA backend)
const p = @import("slor_dsa_params.zig");
const keccak = @import("keccak.zig");
const random = @import("random.zig");
const poly = @import("slor_dsa_poly.zig");
const rounding = @import("slor_dsa_rounding.zig");
const sampling = @import("slor_dsa_sampling.zig");
const packing = @import("slor_dsa_pack.zig");

pub const KeyGenerationSeed = [p.SEED_BYTES]u8;
pub const PublicKeyBytes = packing.PublicKeyBytes;
pub const SecretKeyBytes = packing.SecretKeyBytes;

const IN = p.SEED_BYTES + 2;
const OUT = p.SEED_BYTES + sampling.RHO_PRIME_BYTES + p.SEED_BYTES;

var busy = false;
var ein: [IN]u8 = [_]u8{0} ** IN;
var eout: [OUT]u8 = [_]u8{0} ** OUT;

var rho: [p.SEED_BYTES]u8 = [_]u8{0} ** p.SEED_BYTES;
var rhop: [sampling.RHO_PRIME_BYTES]u8 = [_]u8{0} ** sampling.RHO_PRIME_BYTES;
var key: [p.SEED_BYTES]u8 = [_]u8{0} ** p.SEED_BYTES;
var tr: [p.TR_BYTES]u8 = [_]u8{0} ** p.TR_BYTES;

var s1: poly.PolyVecL = undefined;
var s1n: poly.PolyVecL = undefined;
var s2: poly.PolyVecK = undefined;
var t: poly.PolyVecK = undefined;
var t1: poly.PolyVecK = undefined;
var t0: poly.PolyVecK = undefined;
var row: poly.PolyVecL = undefined;

// =============================================================================
// Workspace Lifecycle
// =============================================================================

fn clear() void {
    @memset(ein[0..], 0);
    @memset(eout[0..], 0);
    @memset(rho[0..], 0);
    @memset(rhop[0..], 0);
    @memset(key[0..], 0);
    @memset(tr[0..], 0);

    poly.zeroVecL(&s1);
    poly.zeroVecL(&s1n);
    poly.zeroVecK(&s2);
    poly.zeroVecK(&t);
    poly.zeroVecK(&t1);
    poly.zeroVecK(&t0);
    poly.zeroVecL(&row);
}

fn acquire() bool {
    if (busy) return false;
    busy = true;
    clear();
    return true;
}

fn release() void {
    clear();
    busy = false;
}

// =============================================================================
// Seed Expansion
// =============================================================================

fn expand(seed: *const KeyGenerationSeed) bool {
    @memcpy(ein[0..p.SEED_BYTES], seed);
    ein[p.SEED_BYTES] = @intCast(p.K);
    ein[p.SEED_BYTES + 1] = @intCast(p.L);

    if (!keccak.shake256(&eout, &ein)) return false;

    var q: usize = 0;
    @memcpy(&rho, eout[q .. q + p.SEED_BYTES]);
    q += p.SEED_BYTES;

    @memcpy(&rhop, eout[q .. q + sampling.RHO_PRIME_BYTES]);
    q += sampling.RHO_PRIME_BYTES;

    @memcpy(&key, eout[q .. q + p.SEED_BYTES]);
    return true;
}

// =============================================================================
// Key Generation Methods
// =============================================================================

pub fn generateFromSeed(pk: *PublicKeyBytes, sk: *SecretKeyBytes, seed: *const KeyGenerationSeed) bool {
    @memset(pk[0..], 0);
    @memset(sk[0..], 0);

    if (!acquire()) return false;
    defer release();

    if (!expand(seed)) return false;
    if (!sampling.sampleEtaVecL(&s1, &rhop, 0)) return false;
    if (!sampling.sampleEtaVecK(&s2, &rhop, @intCast(p.L))) return false;

    s1n = s1;
    poly.forwardNttVecL(&s1n);

    var r: usize = 0;
    while (r < p.K) : (r += 1) {
        if (!sampling.expandMatrixRow(&row, &rho, r)) return false;
        poly.matrixRowPointwiseMultiply(&t[r], &row, &s1n);
        poly.inverseNttToMontgomery(&t[r]);
        poly.reduceCoefficients(&t[r]);
        poly.addInPlace(&t[r], &s2[r]);
        poly.reduceCoefficients(&t[r]);
        poly.conditionalAddQ(&t[r]);
        poly.zeroVecL(&row);
    }

    rounding.power2RoundVecK(&t1, &t0, &t);

    if (!packing.packPublicKey(pk, &rho, &t1)) return false;
    if (!keccak.shake256(&tr, pk)) return false;

    if (!packing.packSecretKey(sk, &rho, &key, &tr, &s1, &s2, &t0)) {
        @memset(pk[0..], 0);
        return false;
    }

    return true;
}

pub fn generate(pk: *PublicKeyBytes, sk: *SecretKeyBytes) bool {
    var seed: KeyGenerationSeed = [_]u8{0} ** p.SEED_BYTES;
    random.getBytes(&seed);
    defer @memset(seed[0..], 0);

    return generateFromSeed(pk, sk, &seed);
}

// =============================================================================
// Validation & Testing
// =============================================================================

fn equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var d: u8 = 0;
    for (a, b) |x, y| {
        d |= x ^ y;
    }
    return d == 0;
}

pub fn validateSerializedPair(pk: *const PublicKeyBytes, sk: *const SecretKeyBytes) bool {
    var pp: packing.PublicKeyParts = undefined;
    var sp: packing.SecretKeyParts = undefined;

    defer packing.clearPublicParts(&pp);
    defer packing.clearSecretParts(&sp);

    if (!packing.unpackPublicKey(&pp.rho, &pp.t1, pk) or !packing.unpackSecretKey(&sp, sk)) {
        return false;
    }

    if (!equal(&pp.rho, &sp.rho)) return false;

    var expected: [p.TR_BYTES]u8 = [_]u8{0} ** p.TR_BYTES;
    defer @memset(expected[0..], 0);

    return keccak.shake256(&expected, pk) and equal(&expected, &sp.tr);
}

pub fn selfTest() bool {
    var seed: KeyGenerationSeed = [_]u8{0x42} ** p.SEED_BYTES;
    var pk1: PublicKeyBytes = [_]u8{0} ** p.PUBLIC_KEY_BYTES;
    var sk1: SecretKeyBytes = [_]u8{0} ** p.SECRET_KEY_BYTES;
    var pk2: PublicKeyBytes = [_]u8{0} ** p.PUBLIC_KEY_BYTES;
    var sk2: SecretKeyBytes = [_]u8{0} ** p.SECRET_KEY_BYTES;

    if (!generateFromSeed(&pk1, &sk1, &seed) or !generateFromSeed(&pk2, &sk2, &seed)) {
        return false;
    }

    const ok = equal(&pk1, &pk2) and equal(&sk1, &sk2) and validateSerializedPair(&pk1, &sk1);

    @memset(seed[0..], 0);
    @memset(pk1[0..], 0);
    @memset(sk1[0..], 0);
    @memset(pk2[0..], 0);
    @memset(sk2[0..], 0);

    return ok;
}
