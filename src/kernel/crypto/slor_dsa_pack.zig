//! Zamrud OS - ML-DSA-65 canonical packing (single SLOR-DSA backend)
const p = @import("slor_dsa_params.zig");
const poly = @import("slor_dsa_poly.zig");
const rounding = @import("slor_dsa_rounding.zig");

pub const PublicKeyBytes = [p.PUBLIC_KEY_BYTES]u8;
pub const SecretKeyBytes = [p.SECRET_KEY_BYTES]u8;
pub const SignatureBytes = [p.SIGNATURE_BYTES]u8;

pub const PublicKeyParts = struct {
    rho: [p.SEED_BYTES]u8,
    t1: poly.PolyVecK,
};

pub const SecretKeyParts = struct {
    rho: [p.SEED_BYTES]u8,
    key: [p.SEED_BYTES]u8,
    tr: [p.TR_BYTES]u8,
    s1: poly.PolyVecL,
    s2: poly.PolyVecK,
    t0: poly.PolyVecK,
};

pub const SignatureParts = struct {
    challenge: [p.CTILDE_BYTES]u8,
    z: poly.PolyVecL,
    hints: rounding.HintVecK,
};

// =============================================================================
// Bit Manipulation Helpers
// =============================================================================

fn putBits(out: []u8, bit0: usize, value: u32, bits: usize) void {
    var i: usize = 0;
    while (i < bits) : (i += 1) {
        const d = bit0 + i;
        const m: u8 = @as(u8, 1) << @intCast(d & 7);
        if (((value >> @intCast(i)) & 1) != 0) {
            out[d >> 3] |= m;
        }
    }
}

fn getBits(inp: []const u8, bit0: usize, bits: usize) u32 {
    var v: u32 = 0;
    var i: usize = 0;
    while (i < bits) : (i += 1) {
        v |= @as(u32, (inp[(bit0 + i) >> 3] >> @intCast((bit0 + i) & 7)) & 1) << @intCast(i);
    }
    return v;
}

// =============================================================================
// Generic Packing/Unpacking
// =============================================================================

fn packFixed(out: []u8, a: *const poly.Polynomial, bits: usize, kind: enum { eta, t0, t1, z, w1 }) bool {
    @memset(out, 0);
    var i: usize = 0;

    while (i < p.N) : (i += 1) {
        var x: i32 = undefined;
        switch (kind) {
            .eta => x = p.ETA - a[i],
            .t0 => x = (@as(i32, 1) << (p.D - 1)) - a[i],
            .t1 => x = a[i],
            .z => x = p.GAMMA1 - a[i],
            .w1 => x = a[i],
        }

        if (x < 0 or @as(u64, @intCast(x)) >= (@as(u64, 1) << @intCast(bits))) {
            return false;
        }

        putBits(out, i * bits, @intCast(x), bits);
    }

    return true;
}

fn unpackFixed(a: *poly.Polynomial, inp: []const u8, bits: usize, kind: enum { eta, t0, t1, z }) bool {
    var i: usize = 0;

    while (i < p.N) : (i += 1) {
        const x: u32 = getBits(inp, i * bits, bits);
        switch (kind) {
            .eta => {
                if (x > 8) {
                    poly.zero(a);
                    return false;
                }
                a[i] = p.ETA - @as(i32, @intCast(x));
            },
            .t0 => a[i] = (@as(i32, 1) << (p.D - 1)) - @as(i32, @intCast(x)),
            .t1 => a[i] = @intCast(x),
            .z => a[i] = p.GAMMA1 - @as(i32, @intCast(x)),
        }
    }

    return true;
}

// =============================================================================
// Specific Polynomial Packing/Unpacking Wrappers
// =============================================================================

pub fn packEta(o: *[p.POLY_ETA_PACKED_BYTES]u8, a: *const poly.Polynomial) bool {
    return packFixed(o, a, 4, .eta);
}

pub fn unpackEta(a: *poly.Polynomial, i: *const [p.POLY_ETA_PACKED_BYTES]u8) bool {
    return unpackFixed(a, i, 4, .eta);
}

pub fn packT1(o: *[p.POLY_T1_PACKED_BYTES]u8, a: *const poly.Polynomial) bool {
    return packFixed(o, a, 10, .t1);
}

pub fn unpackT1(a: *poly.Polynomial, i: *const [p.POLY_T1_PACKED_BYTES]u8) void {
    _ = unpackFixed(a, i, 10, .t1);
}

pub fn packT0(o: *[p.POLY_T0_PACKED_BYTES]u8, a: *const poly.Polynomial) bool {
    return packFixed(o, a, 13, .t0);
}

pub fn unpackT0(a: *poly.Polynomial, i: *const [p.POLY_T0_PACKED_BYTES]u8) bool {
    return unpackFixed(a, i, 13, .t0);
}

pub fn packZ(o: *[p.POLY_Z_PACKED_BYTES]u8, a: *const poly.Polynomial) bool {
    return packFixed(o, a, 20, .z);
}

pub fn unpackZ(a: *poly.Polynomial, i: *const [p.POLY_Z_PACKED_BYTES]u8) bool {
    return unpackFixed(a, i, 20, .z);
}

pub fn packW1(o: *[p.POLY_W1_PACKED_BYTES]u8, a: *const poly.Polynomial) bool {
    return packFixed(o, a, 4, .w1);
}

// =============================================================================
// Public Key
// =============================================================================

pub fn packPublicKey(out: *PublicKeyBytes, rho: *const [p.SEED_BYTES]u8, t1: *const poly.PolyVecK) bool {
    @memcpy(out[0..p.SEED_BYTES], rho);
    var pos: usize = p.SEED_BYTES;
    var j: usize = 0;

    while (j < p.K) : (j += 1) {
        var b: [p.POLY_T1_PACKED_BYTES]u8 = undefined;
        if (!packT1(&b, &t1[j])) {
            @memset(out, 0);
            return false;
        }
        @memcpy(out[pos .. pos + b.len], &b);
        pos += b.len;
    }

    return pos == out.len;
}

pub fn unpackPublicKey(rho: *[p.SEED_BYTES]u8, t1: *poly.PolyVecK, inp: *const PublicKeyBytes) bool {
    @memcpy(rho, inp[0..p.SEED_BYTES]);
    var pos: usize = p.SEED_BYTES;
    var j: usize = 0;

    while (j < p.K) : (j += 1) {
        var b: [p.POLY_T1_PACKED_BYTES]u8 = undefined;
        @memcpy(&b, inp[pos .. pos + b.len]);
        unpackT1(&t1[j], &b);
        pos += b.len;
    }

    return pos == inp.len;
}

// =============================================================================
// Secret Key
// =============================================================================

pub fn packSecretKey(out: *SecretKeyBytes, rho: *const [p.SEED_BYTES]u8, key: *const [p.SEED_BYTES]u8, tr: *const [p.TR_BYTES]u8, s1: *const poly.PolyVecL, s2: *const poly.PolyVecK, t0: *const poly.PolyVecK) bool {
    var pos: usize = 0;

    @memcpy(out[pos .. pos + rho.len], rho);
    pos += rho.len;

    @memcpy(out[pos .. pos + key.len], key);
    pos += key.len;

    @memcpy(out[pos .. pos + tr.len], tr);
    pos += tr.len;

    var j: usize = 0;
    while (j < p.L) : (j += 1) {
        var b: [p.POLY_ETA_PACKED_BYTES]u8 = undefined;
        if (!packEta(&b, &s1[j])) return false;
        @memcpy(out[pos .. pos + b.len], &b);
        pos += b.len;
    }

    j = 0;
    while (j < p.K) : (j += 1) {
        var b: [p.POLY_ETA_PACKED_BYTES]u8 = undefined;
        if (!packEta(&b, &s2[j])) return false;
        @memcpy(out[pos .. pos + b.len], &b);
        pos += b.len;
    }

    j = 0;
    while (j < p.K) : (j += 1) {
        var b: [p.POLY_T0_PACKED_BYTES]u8 = undefined;
        if (!packT0(&b, &t0[j])) return false;
        @memcpy(out[pos .. pos + b.len], &b);
        pos += b.len;
    }

    return pos == out.len;
}

pub fn unpackSecretKey(x: *SecretKeyParts, inp: *const SecretKeyBytes) bool {
    var pos: usize = 0;

    @memcpy(&x.rho, inp[pos .. pos + p.SEED_BYTES]);
    pos += p.SEED_BYTES;

    @memcpy(&x.key, inp[pos .. pos + p.SEED_BYTES]);
    pos += p.SEED_BYTES;

    @memcpy(&x.tr, inp[pos .. pos + p.TR_BYTES]);
    pos += p.TR_BYTES;

    var j: usize = 0;
    while (j < p.L) : (j += 1) {
        var b: [p.POLY_ETA_PACKED_BYTES]u8 = undefined;
        @memcpy(&b, inp[pos .. pos + b.len]);
        if (!unpackEta(&x.s1[j], &b)) return false;
        pos += b.len;
    }

    j = 0;
    while (j < p.K) : (j += 1) {
        var b: [p.POLY_ETA_PACKED_BYTES]u8 = undefined;
        @memcpy(&b, inp[pos .. pos + b.len]);
        if (!unpackEta(&x.s2[j], &b)) return false;
        pos += b.len;
    }

    j = 0;
    while (j < p.K) : (j += 1) {
        var b: [p.POLY_T0_PACKED_BYTES]u8 = undefined;
        @memcpy(&b, inp[pos .. pos + b.len]);
        if (!unpackT0(&x.t0[j], &b)) return false;
        pos += b.len;
    }

    return pos == inp.len;
}

// =============================================================================
// Signature
// =============================================================================

pub fn packSignature(out: *SignatureBytes, c: *const [p.CTILDE_BYTES]u8, z: *const poly.PolyVecL, h: *const rounding.HintVecK) bool {
    if (!rounding.hintsWithinOmega(h)) return false;

    var pos: usize = 0;
    @memcpy(out[0..c.len], c);
    pos += c.len;

    var j: usize = 0;
    while (j < p.L) : (j += 1) {
        var b: [p.POLY_Z_PACKED_BYTES]u8 = undefined;
        if (!packZ(&b, &z[j])) return false;
        @memcpy(out[pos .. pos + b.len], &b);
        pos += b.len;
    }

    const hs = pos;
    @memset(out[hs..], 0);

    var n: usize = 0;
    j = 0;

    while (j < p.K) : (j += 1) {
        var i: usize = 0;
        while (i < p.N) : (i += 1) {
            if (h[j][i] == 1) {
                if (n >= p.OMEGA) return false;
                out[hs + n] = @intCast(i);
                n += 1;
            } else if (h[j][i] != 0) {
                return false;
            }
        }
        out[hs + p.OMEGA + j] = @intCast(n);
    }

    return true;
}

pub fn unpackSignature(x: *SignatureParts, inp: *const SignatureBytes) bool {
    var pos: usize = 0;
    @memcpy(&x.challenge, inp[0..p.CTILDE_BYTES]);
    pos += p.CTILDE_BYTES;

    var j: usize = 0;
    while (j < p.L) : (j += 1) {
        var b: [p.POLY_Z_PACKED_BYTES]u8 = undefined;
        @memcpy(&b, inp[pos .. pos + b.len]);
        if (!unpackZ(&x.z[j], &b)) return false;
        pos += b.len;
    }

    rounding.zeroHintVecK(&x.hints);
    const hs = pos;
    var prev: usize = 0;
    j = 0;

    while (j < p.K) : (j += 1) {
        const end: usize = inp[hs + p.OMEGA + j];
        if (end < prev or end > p.OMEGA) return false;

        var q = prev;
        while (q < end) : (q += 1) {
            const idx: usize = inp[hs + q];
            if (q > prev and idx <= inp[hs + q - 1]) return false;
            x.hints[j][idx] = 1;
        }
        prev = end;
    }

    var q = prev;
    while (q < p.OMEGA) : (q += 1) {
        if (inp[hs + q] != 0) return false;
    }

    return true;
}

// =============================================================================
// Clear & Test
// =============================================================================

pub fn clearPublicParts(x: *PublicKeyParts) void {
    @memset(x.rho[0..], 0);
    poly.clearVecK(&x.t1);
}

pub fn clearSecretParts(x: *SecretKeyParts) void {
    @memset(x.rho[0..], 0);
    @memset(x.key[0..], 0);
    @memset(x.tr[0..], 0);
    poly.clearVecL(&x.s1);
    poly.clearVecK(&x.s2);
    poly.clearVecK(&x.t0);
}

pub fn clearSignatureParts(x: *SignatureParts) void {
    @memset(x.challenge[0..], 0);
    poly.clearVecL(&x.z);
    rounding.zeroHintVecK(&x.hints);
}

pub fn selfTest() bool {
    var a: poly.Polynomial = [_]i32{0} ** p.N;
    var b = a;
    var enc: [p.POLY_ETA_PACKED_BYTES]u8 = undefined;

    var i: usize = 0;
    while (i < p.N) : (i += 1) {
        a[i] = @as(i32, @intCast(i % 9)) - p.ETA;
    }

    if (!packEta(&enc, &a) or !unpackEta(&b, &enc)) {
        return false;
    }

    i = 0;
    while (i < p.N) : (i += 1) {
        if (a[i] != b[i]) return false;
    }

    return true;
}
