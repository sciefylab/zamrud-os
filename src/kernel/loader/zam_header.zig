//! Zamrud OS - ZAM Binary Header Parser
//! ZAM Header V3: ML-DSA-65 application signatures through gov_sign.zig only.
//!
//! Layout V3 (8192 bytes):
//!   [0..4]       magic: "ZAMR"
//!   [4..6]       version: u16 (3)
//!   [6..8]       header_size: u16 (8192)
//!   [8..12]      flags: u32
//!   [12..44]     elf_hash: SHA-256 of ELF payload
//!   [44..3353]   ML-DSA-65 signature bytes (3309)
//!   [3353..5305] signer public-key bytes (1952)
//!   [5305..5309] required_caps: u32
//!   [5309]       trust_level: u8
//!   [5310..5312] max_mem_pages: u16
//!   [5312]       unveil_count: u8
//!   [5313..5317] trust_block_ref: u32
//!   [5317..5321] elf_offset: u32
//!   [5321..5325] elf_size: u32
//!   [5325..8192] reserved/padding
//!
//! Security policy:
//! - Production verification uses crypto/gov_sign.zig only.
//! - ZAM V2 / SLOR prototype signatures are rejected fail-closed.
//! - There is no legacy-signature fallback or downgrade path.

const hash_mod = @import("../crypto/hash.zig");
const gov_sign = @import("../crypto/gov_sign.zig");

// ============================================================================
// Constants
// ============================================================================

pub const ZAM_MAGIC: [4]u8 = .{ 'Z', 'A', 'M', 'R' };
pub const ZAM_VERSION: u16 = 3;
pub const ZAM_HEADER_SIZE: usize = 8192;

pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = gov_sign.SIGNATURE_BYTES;
pub const PUBKEY_SIZE: usize = gov_sign.PUBLIC_KEY_BYTES;

pub const OFFSET_MAGIC: usize = 0;
pub const OFFSET_VERSION: usize = 4;
pub const OFFSET_HEADER_SIZE: usize = 6;
pub const OFFSET_FLAGS: usize = 8;
pub const OFFSET_ELF_HASH: usize = 12;
pub const OFFSET_SIGNATURE: usize = OFFSET_ELF_HASH + HASH_SIZE;
pub const OFFSET_SIGNER_PUBKEY: usize = OFFSET_SIGNATURE + SIGNATURE_SIZE;
pub const OFFSET_REQUIRED_CAPS: usize = OFFSET_SIGNER_PUBKEY + PUBKEY_SIZE;
pub const OFFSET_TRUST_LEVEL: usize = OFFSET_REQUIRED_CAPS + 4;
pub const OFFSET_MAX_MEM_PAGES: usize = OFFSET_TRUST_LEVEL + 1;
pub const OFFSET_UNVEIL_COUNT: usize = OFFSET_MAX_MEM_PAGES + 2;
pub const OFFSET_TRUST_BLOCK_REF: usize = OFFSET_UNVEIL_COUNT + 1;
pub const OFFSET_ELF_OFFSET: usize = OFFSET_TRUST_BLOCK_REF + 4;
pub const OFFSET_ELF_SIZE: usize = OFFSET_ELF_OFFSET + 4;
pub const OFFSET_RESERVED: usize = OFFSET_ELF_SIZE + 4;

comptime {
    if (OFFSET_RESERVED > ZAM_HEADER_SIZE) {
        @compileError("ZAM V3 fields exceed ZAM_HEADER_SIZE");
    }
}

// Domain separation for application/binary signing.
pub const SIGNING_DOMAIN = "ZAMRUD:APP-BINARY:V3";

// Flags
pub const FLAG_SIGNED: u32 = 1 << 0;
pub const FLAG_TRUSTED: u32 = 1 << 1;
pub const FLAG_SANDBOX: u32 = 1 << 2;
pub const FLAG_DEBUG: u32 = 1 << 3;
pub const FLAG_DEV_KEY: u32 = 1 << 4;

// Trust levels
pub const TRUST_UNTRUSTED: u8 = 0;
pub const TRUST_USER: u8 = 1;
pub const TRUST_SYSTEM: u8 = 2;
pub const TRUST_KERNEL: u8 = 3;

pub const ZamError = enum(u8) {
    None = 0,
    TooSmall = 1,
    BadMagic = 2,
    BadVersion = 3,
    BadHeaderSize = 4,
    BadElfOffset = 5,
    BadElfSize = 6,
    HashMismatch = 7,
    SignatureInvalid = 8,
    InvalidCaps = 9,
    InvalidTrust = 10,
    LegacyVersionRejected = 11,
};

// ============================================================================
// Header Structure
// ============================================================================

pub const ZamHeader = struct {
    magic: [4]u8,
    version: u16,
    header_size: u16,
    flags: u32,
    elf_hash: [HASH_SIZE]u8,
    sig: [SIGNATURE_SIZE]u8,
    signer_pubkey: [PUBKEY_SIZE]u8,
    required_caps: u32,
    trust_level: u8,
    max_mem_pages: u16,
    unveil_count: u8,
    trust_block_ref: u32,
    elf_offset: u32,
    elf_size: u32,

    pub fn hasValidMagic(self: *const ZamHeader) bool {
        return self.magic[0] == 'Z' and self.magic[1] == 'A' and
            self.magic[2] == 'M' and self.magic[3] == 'R';
    }

    pub fn hasValidVersion(self: *const ZamHeader) bool {
        return self.version == ZAM_VERSION;
    }

    pub fn hasValidHeaderSize(self: *const ZamHeader) bool {
        return self.header_size == ZAM_HEADER_SIZE;
    }

    pub fn hasValidTrustLevel(self: *const ZamHeader) bool {
        return self.trust_level <= TRUST_KERNEL;
    }

    pub fn hasValidElfLocation(self: *const ZamHeader) bool {
        if (self.elf_offset != ZAM_HEADER_SIZE) return false;
        if (self.elf_size == 0) return false;
        return true;
    }

    pub fn isSigned(self: *const ZamHeader) bool {
        return (self.flags & FLAG_SIGNED) != 0;
    }

    pub fn isTrusted(self: *const ZamHeader) bool {
        return (self.flags & FLAG_TRUSTED) != 0;
    }

    pub fn isSandboxed(self: *const ZamHeader) bool {
        return (self.flags & FLAG_SANDBOX) != 0;
    }

    pub fn isDevKey(self: *const ZamHeader) bool {
        return (self.flags & FLAG_DEV_KEY) != 0;
    }

    pub fn validate(self: *const ZamHeader) ZamError {
        if (!self.hasValidMagic()) return .BadMagic;
        if (self.version == 2) return .LegacyVersionRejected;
        if (!self.hasValidVersion()) return .BadVersion;
        if (!self.hasValidHeaderSize()) return .BadHeaderSize;
        if (!self.hasValidElfLocation()) return .BadElfOffset;
        if (!self.hasValidTrustLevel()) return .InvalidTrust;
        return .None;
    }

    pub fn verifyHash(self: *const ZamHeader, elf_data: []const u8) bool {
        if (elf_data.len == 0) return false;
        if (elf_data.len != @as(usize, self.elf_size)) return false;

        var computed: [HASH_SIZE]u8 = [_]u8{0} ** HASH_SIZE;
        defer @memset(computed[0..], 0);
        hash_mod.sha256Into(elf_data, &computed);
        return constantTimeEqual(&self.elf_hash, &computed);
    }

    pub fn verifyQuantumSignature(
        self: *const ZamHeader,
        elf_data: []const u8,
    ) bool {
        if (!self.isSigned()) return false;
        if (!self.verifyHash(elf_data)) return false;
        if (!gov_sign.isProductionBackendAvailable()) return false;

        var public_key = gov_sign.PublicKey{};
        var signature = gov_sign.Signature{};
        defer gov_sign.clearPublicKey(&public_key);
        defer gov_sign.clearSignature(&signature);

        if (!gov_sign.deserializePublicKey(&self.signer_pubkey, &public_key)) {
            return false;
        }
        if (!gov_sign.deserializeSignature(&self.sig, &signature)) {
            return false;
        }

        return gov_sign.verifyBool(
            &public_key,
            SIGNING_DOMAIN,
            elf_data,
            &signature,
        );
    }

    // Compatibility alias for existing loader/test callers.
    pub fn verifySignature(
        self: *const ZamHeader,
        elf_data: []const u8,
    ) bool {
        return self.verifyQuantumSignature(elf_data);
    }
};

// ============================================================================
// Parser
// ============================================================================

pub fn parse(data: []const u8) ?ZamHeader {
    if (data.len < ZAM_HEADER_SIZE) return null;

    const version = readU16(data, OFFSET_VERSION);
    if (version != ZAM_VERSION) return null;

    var hdr: ZamHeader = undefined;
    copyBytes(&hdr.magic, data, OFFSET_MAGIC, ZAM_MAGIC.len);
    hdr.version = version;
    hdr.header_size = readU16(data, OFFSET_HEADER_SIZE);
    hdr.flags = readU32(data, OFFSET_FLAGS);
    copyBytes(&hdr.elf_hash, data, OFFSET_ELF_HASH, HASH_SIZE);
    copyBytes(&hdr.sig, data, OFFSET_SIGNATURE, SIGNATURE_SIZE);
    copyBytes(&hdr.signer_pubkey, data, OFFSET_SIGNER_PUBKEY, PUBKEY_SIZE);
    hdr.required_caps = readU32(data, OFFSET_REQUIRED_CAPS);
    hdr.trust_level = data[OFFSET_TRUST_LEVEL];
    hdr.max_mem_pages = readU16(data, OFFSET_MAX_MEM_PAGES);
    hdr.unveil_count = data[OFFSET_UNVEIL_COUNT];
    hdr.trust_block_ref = readU32(data, OFFSET_TRUST_BLOCK_REF);
    hdr.elf_offset = readU32(data, OFFSET_ELF_OFFSET);
    hdr.elf_size = readU32(data, OFFSET_ELF_SIZE);
    return hdr;
}

pub fn parseAndValidate(data: []const u8) ?ZamHeader {
    const hdr = parse(data) orelse return null;
    if (hdr.validate() != .None) return null;
    return hdr;
}

pub fn getElfPayload(data: []const u8) ?[]const u8 {
    const hdr = parseAndValidate(data) orelse return null;
    const start: usize = @intCast(hdr.elf_offset);
    const size: usize = @intCast(hdr.elf_size);
    if (start > data.len) return null;
    if (size > data.len - start) return null;
    return data[start .. start + size];
}

// ============================================================================
// Builder
// ============================================================================

pub fn buildHeader(
    out: []u8,
    elf_data: []const u8,
    caps: u32,
    trust: u8,
    max_pages: u16,
    flags: u32,
) usize {
    if (out.len < ZAM_HEADER_SIZE) return 0;
    if (elf_data.len == 0) return 0;
    if (elf_data.len > @as(usize, std.math.maxInt(u32))) return 0;
    if (trust > TRUST_KERNEL) return 0;

    @memset(out[0..ZAM_HEADER_SIZE], 0);
    copyInto(out, OFFSET_MAGIC, &ZAM_MAGIC);
    writeU16(out, OFFSET_VERSION, ZAM_VERSION);
    writeU16(out, OFFSET_HEADER_SIZE, @intCast(ZAM_HEADER_SIZE));

    // A header is not signed until attachSignature() succeeds.
    writeU32(out, OFFSET_FLAGS, flags & ~FLAG_SIGNED);

    var elf_hash: [HASH_SIZE]u8 = [_]u8{0} ** HASH_SIZE;
    defer @memset(elf_hash[0..], 0);
    hash_mod.sha256Into(elf_data, &elf_hash);
    copyInto(out, OFFSET_ELF_HASH, &elf_hash);

    writeU32(out, OFFSET_REQUIRED_CAPS, caps);
    out[OFFSET_TRUST_LEVEL] = trust;
    writeU16(out, OFFSET_MAX_MEM_PAGES, max_pages);
    out[OFFSET_UNVEIL_COUNT] = 0;
    writeU32(out, OFFSET_TRUST_BLOCK_REF, 0);
    writeU32(out, OFFSET_ELF_OFFSET, @intCast(ZAM_HEADER_SIZE));
    writeU32(out, OFFSET_ELF_SIZE, @intCast(elf_data.len));
    return ZAM_HEADER_SIZE;
}

pub fn attachSignature(
    header: []u8,
    public_key: *const gov_sign.PublicKey,
    signature: *const gov_sign.Signature,
) bool {
    if (header.len < ZAM_HEADER_SIZE) return false;
    if (readU16(header, OFFSET_VERSION) != ZAM_VERSION) return false;
    if (readU16(header, OFFSET_HEADER_SIZE) != ZAM_HEADER_SIZE) return false;

    var public_bytes: [PUBKEY_SIZE]u8 = [_]u8{0} ** PUBKEY_SIZE;
    var signature_bytes: [SIGNATURE_SIZE]u8 = [_]u8{0} ** SIGNATURE_SIZE;
    defer @memset(public_bytes[0..], 0);
    defer @memset(signature_bytes[0..], 0);

    if (!gov_sign.serializePublicKey(public_key, &public_bytes)) return false;
    if (!gov_sign.serializeSignature(signature, &signature_bytes)) return false;

    copyInto(header, OFFSET_SIGNER_PUBKEY, &public_bytes);
    copyInto(header, OFFSET_SIGNATURE, &signature_bytes);

    const flags = readU32(header, OFFSET_FLAGS);
    writeU32(header, OFFSET_FLAGS, flags | FLAG_SIGNED);
    return true;
}

// ============================================================================
// Helpers
// ============================================================================

const std = @import("std");

pub fn errorName(err: ZamError) []const u8 {
    return switch (err) {
        .None => "None",
        .TooSmall => "TooSmall",
        .BadMagic => "BadMagic",
        .BadVersion => "BadVersion",
        .BadHeaderSize => "BadHeaderSize",
        .BadElfOffset => "BadElfOffset",
        .BadElfSize => "BadElfSize",
        .HashMismatch => "HashMismatch",
        .SignatureInvalid => "SignatureInvalid",
        .InvalidCaps => "InvalidCaps",
        .InvalidTrust => "InvalidTrust",
        .LegacyVersionRejected => "LegacyVersionRejected",
    };
}

fn readU16(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) |
        (@as(u16, data[offset + 1]) << 8);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) |
        (@as(u32, data[offset + 1]) << 8) |
        (@as(u32, data[offset + 2]) << 16) |
        (@as(u32, data[offset + 3]) << 24);
}

fn writeU16(data: []u8, offset: usize, value: u16) void {
    data[offset] = @intCast(value & 0xff);
    data[offset + 1] = @intCast((value >> 8) & 0xff);
}

fn writeU32(data: []u8, offset: usize, value: u32) void {
    data[offset] = @intCast(value & 0xff);
    data[offset + 1] = @intCast((value >> 8) & 0xff);
    data[offset + 2] = @intCast((value >> 16) & 0xff);
    data[offset + 3] = @intCast((value >> 24) & 0xff);
}

fn copyBytes(
    destination: []u8,
    source: []const u8,
    source_offset: usize,
    count: usize,
) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        destination[i] = source[source_offset + i];
    }
}

fn copyInto(destination: []u8, offset: usize, source: []const u8) void {
    var i: usize = 0;
    while (i < source.len) : (i += 1) {
        destination[offset + i] = source[i];
    }
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}
