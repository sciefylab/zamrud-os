//! Zamrud OS - ZAM Binary Header Parser
//! Parses and validates the 4096-byte ZAMRUD header prepended to ELF64 payloads
//!
//! Layout V2 (4096 bytes - Anti-Quantum SLOR Signature Ready):
//!   [0..4]     magic: "ZAMR"
//!   [4..6]     version: u16 (2)
//!   [6..8]     header_size: u16 (4096)
//!   [8..12]    flags: u32 (including FLAG_DEV_KEY)
//!   [12..44]   elf_hash: SHA-256 of ELF payload (32 bytes)
//!   [44..1100] signature: SLOR Signature Struct (z array + c hash) (1056 bytes)
//!   [1100..2156] signer_pubkey: SLOR Public Key Struct (t array + seed) (1056 bytes)
//!   [2156..2160] required_caps: u32
//!   [2160..2161] trust_level: u8
//!   [2161..2163] max_mem_pages: u16
//!   [2163..2164] unveil_count: u8
//!   [2164..2168] trust_block_ref: u32
//!   [2168..2172] elf_offset: u32
//!   [2172..2176] elf_size: u32
//!   [2176..4096] Reserved/Padding

const serial = @import("../drivers/serial/serial.zig");
const hash_mod = @import("../crypto/hash.zig");
const slor_sign = @import("../crypto/slor_sign.zig");

// ============================================================================
// Constants
// ============================================================================

pub const ZAM_MAGIC: [4]u8 = .{ 'Z', 'A', 'M', 'R' };
pub const ZAM_VERSION: u16 = 2;
pub const ZAM_HEADER_SIZE: usize = 4096;

pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = slor_sign.SIGNATURE_SIZE; // 1056
pub const PUBKEY_SIZE: usize = slor_sign.PUBKEY_SIZE; // 1056

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

// Errors
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
};

// ============================================================================
// ZAM Header Structure
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
        if (!self.hasValidVersion()) return .BadVersion;
        if (!self.hasValidHeaderSize()) return .BadHeaderSize;
        if (!self.hasValidElfLocation()) return .BadElfOffset;
        if (!self.hasValidTrustLevel()) return .InvalidTrust;
        return .None;
    }

    pub fn verifyHash(self: *const ZamHeader, elf_data: []const u8) bool {
        if (elf_data.len == 0) return false;
        var computed: [HASH_SIZE]u8 = undefined;
        hash_mod.sha256Into(elf_data, &computed);
        var i: usize = 0;
        while (i < HASH_SIZE) : (i += 1) {
            if (self.elf_hash[i] != computed[i]) return false;
        }
        return true;
    }

    pub fn verifyQuantumSignature(self: *const ZamHeader, elf_data: []const u8) bool {
        if (!self.isSigned() or elf_data.len == 0) return false;
        const pk: *const slor_sign.SlorSignPubKey = @ptrCast(@alignCast(&self.signer_pubkey));
        const s: *const slor_sign.SlorSignature = @ptrCast(@alignCast(&self.sig));
        return slor_sign.verify(pk, elf_data, s);
    }

    // Alias compatibility untuk file test lawas
    pub fn verifySignature(self: *const ZamHeader, elf_data: []const u8) bool {
        return self.verifyQuantumSignature(elf_data);
    }
};

// ============================================================================
// Parser
// ============================================================================

pub fn parse(data: []const u8) ?ZamHeader {
    if (data.len < ZAM_HEADER_SIZE) return null;

    var hdr: ZamHeader = undefined;
    hdr.magic[0] = data[0];
    hdr.magic[1] = data[1];
    hdr.magic[2] = data[2];
    hdr.magic[3] = data[3];
    hdr.version = readU16(data, 4);
    hdr.header_size = readU16(data, 6);
    hdr.flags = readU32(data, 8);

    copyBytes(&hdr.elf_hash, data, 12, HASH_SIZE);
    copyBytes(&hdr.sig, data, 44, SIGNATURE_SIZE);
    copyBytes(&hdr.signer_pubkey, data, 1100, PUBKEY_SIZE);

    hdr.required_caps = readU32(data, 2156);
    hdr.trust_level = data[2160];
    hdr.max_mem_pages = readU16(data, 2161);
    hdr.unveil_count = data[2163];
    hdr.trust_block_ref = readU32(data, 2164);
    hdr.elf_offset = readU32(data, 2168);
    hdr.elf_size = readU32(data, 2172);

    return hdr;
}

pub fn parseAndValidate(data: []const u8) ?ZamHeader {
    const hdr = parse(data) orelse return null;
    if (hdr.validate() != .None) return null;
    return hdr;
}

pub fn getElfPayload(data: []const u8) ?[]const u8 {
    const hdr = parse(data) orelse return null;
    const start = hdr.elf_offset;
    const end = start + hdr.elf_size;
    if (end > data.len) return null;
    return data[start..end];
}

// ============================================================================
// Builder & Helpers
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

    var i: usize = 0;
    while (i < ZAM_HEADER_SIZE) : (i += 1) out[i] = 0;

    out[0] = 'Z';
    out[1] = 'A';
    out[2] = 'M';
    out[3] = 'R';
    writeU16(out, 4, ZAM_VERSION);
    writeU16(out, 6, ZAM_HEADER_SIZE);
    writeU32(out, 8, flags);

    var elf_hash: [HASH_SIZE]u8 = undefined;
    hash_mod.sha256Into(elf_data, &elf_hash);
    i = 0;
    while (i < HASH_SIZE) : (i += 1) out[12 + i] = elf_hash[i];

    writeU32(out, 2156, caps);
    out[2160] = trust;
    writeU16(out, 2161, max_pages);
    out[2163] = 0;
    writeU32(out, 2164, 0);
    writeU32(out, 2168, @intCast(ZAM_HEADER_SIZE));
    writeU32(out, 2172, @intCast(elf_data.len));

    return ZAM_HEADER_SIZE;
}

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
    };
}

fn readU16(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) | (@as(u16, data[offset + 1]) << 8);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) | (@as(u32, data[offset + 1]) << 8) |
        (@as(u32, data[offset + 2]) << 16) | (@as(u32, data[offset + 3]) << 24);
}

fn writeU16(data: []u8, offset: usize, val: u16) void {
    data[offset] = @intCast(val & 0xFF);
    data[offset + 1] = @intCast((val >> 8) & 0xFF);
}

fn writeU32(data: []u8, offset: usize, val: u32) void {
    data[offset] = @intCast(val & 0xFF);
    data[offset + 1] = @intCast((val >> 8) & 0xFF);
    data[offset + 2] = @intCast((val >> 16) & 0xFF);
    data[offset + 3] = @intCast((val >> 24) & 0xFF);
}

fn copyBytes(dst: []u8, src: []const u8, src_offset: usize, count: usize) void {
    var i: usize = 0;
    while (i < count) : (i += 1) dst[i] = src[src_offset + i];
}
