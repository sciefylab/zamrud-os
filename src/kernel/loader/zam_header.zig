//! Zamrud OS - ZAM Binary Header Parser
//! Parses and validates the 128-byte ZAMRUD header prepended to ELF64 payloads
//!
//! Layout (128 bytes):
//!   [0..4]     magic: "ZAMR"
//!   [4..6]     version: u16 (1)
//!   [6..8]     header_size: u16 (128)
//!   [8..12]    flags: u32
//!   [12..44]   elf_hash: SHA-256 of ELF payload
//!   [44..108]  signature: HMAC-SHA256 signature (64 bytes)
//!   [108..140] signer_pubkey: signer's public key (32 bytes)
//!   [140..144] required_caps: u32
//!   [144..145] trust_level: u8
//!   [145..147] max_mem_pages: u16
//!   [147..148] unveil_count: u8
//!   [148..152] trust_block_ref: u32
//!   [152..156] elf_offset: u32
//!   [156..160] elf_size: u32
//!
//! NOTE: Redesigned from original 128-byte spec to accommodate full 64-byte
//! signatures. Header is now 160 bytes. All offsets adjusted accordingly.

const serial = @import("../drivers/serial/serial.zig");
const hash_mod = @import("../crypto/hash.zig");
const signature = @import("../crypto/signature.zig");

// ============================================================================
// Constants
// ============================================================================

pub const ZAM_MAGIC: [4]u8 = .{ 'Z', 'A', 'M', 'R' };
pub const ZAM_VERSION: u16 = 1;
pub const ZAM_HEADER_SIZE: usize = 160;

pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const PUBKEY_SIZE: usize = 32;

// Flags
pub const FLAG_SIGNED: u32 = 1 << 0;
pub const FLAG_TRUSTED: u32 = 1 << 1;
pub const FLAG_SANDBOX: u32 = 1 << 2;
pub const FLAG_DEBUG: u32 = 1 << 3;

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
    // Identity
    magic: [4]u8,
    version: u16,
    header_size: u16,
    flags: u32,

    // Integrity
    elf_hash: [HASH_SIZE]u8,

    // Authentication
    sig: [SIGNATURE_SIZE]u8,
    signer_pubkey: [PUBKEY_SIZE]u8,

    // Security policy
    required_caps: u32,
    trust_level: u8,
    max_mem_pages: u16,
    unveil_count: u8,
    trust_block_ref: u32,

    // Payload location
    elf_offset: u32,
    elf_size: u32,

    // ========================================================================
    // Validation
    // ========================================================================

    /// Check if magic is valid
    pub fn hasValidMagic(self: *const ZamHeader) bool {
        return self.magic[0] == 'Z' and
            self.magic[1] == 'A' and
            self.magic[2] == 'M' and
            self.magic[3] == 'R';
    }

    /// Check if version is supported
    pub fn hasValidVersion(self: *const ZamHeader) bool {
        return self.version == ZAM_VERSION;
    }

    /// Check if header size field is correct
    pub fn hasValidHeaderSize(self: *const ZamHeader) bool {
        return self.header_size == ZAM_HEADER_SIZE;
    }

    /// Check if trust level is valid
    pub fn hasValidTrustLevel(self: *const ZamHeader) bool {
        return self.trust_level <= TRUST_KERNEL;
    }

    /// Check if ELF offset/size are consistent
    pub fn hasValidElfLocation(self: *const ZamHeader) bool {
        if (self.elf_offset != ZAM_HEADER_SIZE) return false;
        if (self.elf_size == 0) return false;
        return true;
    }

    /// Check if signed flag is set
    pub fn isSigned(self: *const ZamHeader) bool {
        return (self.flags & FLAG_SIGNED) != 0;
    }

    /// Check if trusted flag is set
    pub fn isTrusted(self: *const ZamHeader) bool {
        return (self.flags & FLAG_TRUSTED) != 0;
    }

    /// Check if sandbox flag is set
    pub fn isSandboxed(self: *const ZamHeader) bool {
        return (self.flags & FLAG_SANDBOX) != 0;
    }

    /// Full structural validation (no crypto)
    pub fn validate(self: *const ZamHeader) ZamError {
        if (!self.hasValidMagic()) return .BadMagic;
        if (!self.hasValidVersion()) return .BadVersion;
        if (!self.hasValidHeaderSize()) return .BadHeaderSize;
        if (!self.hasValidElfLocation()) return .BadElfOffset;
        if (!self.hasValidTrustLevel()) return .InvalidTrust;
        return .None;
    }

    // ========================================================================
    // Crypto verification
    // ========================================================================

    /// Verify SHA-256 hash of ELF payload
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

    /// Verify identity signature using embedded public key
    pub fn verifySignature(self: *const ZamHeader, elf_data: []const u8) bool {
        if (!self.isSigned()) return false;
        if (elf_data.len == 0) return false;

        // Signature covers the ELF payload
        return signature.verify(
            &self.signer_pubkey,
            elf_data,
            &self.sig,
        );
    }

    // ========================================================================
    // Info display
    // ========================================================================

    pub fn printInfo(self: *const ZamHeader) void {
        serial.writeString("\n=== ZAM Header Info ===\n");

        serial.writeString("  Magic:       ");
        serial.writeChar(self.magic[0]);
        serial.writeChar(self.magic[1]);
        serial.writeChar(self.magic[2]);
        serial.writeChar(self.magic[3]);
        serial.writeString("\n");

        serial.writeString("  Version:     ");
        printDec16(self.version);
        serial.writeString("\n");

        serial.writeString("  Header size: ");
        printDec16(self.header_size);
        serial.writeString("\n");

        serial.writeString("  Flags:       0x");
        printHex32(self.flags);
        serial.writeString(" [");
        if (self.isSigned()) serial.writeString("SIGNED ");
        if (self.isTrusted()) serial.writeString("TRUSTED ");
        if (self.isSandboxed()) serial.writeString("SANDBOX ");
        if ((self.flags & FLAG_DEBUG) != 0) serial.writeString("DEBUG ");
        serial.writeString("]\n");

        serial.writeString("  ELF hash:    ");
        printBytes(&self.elf_hash, 8);
        serial.writeString("...\n");

        serial.writeString("  Signature:   ");
        printBytes(&self.sig, 8);
        serial.writeString("...\n");

        serial.writeString("  Signer key:  ");
        printBytes(&self.signer_pubkey, 8);
        serial.writeString("...\n");

        serial.writeString("  Caps:        0x");
        printHex32(self.required_caps);
        serial.writeString("\n");

        serial.writeString("  Trust level: ");
        switch (self.trust_level) {
            TRUST_UNTRUSTED => serial.writeString("UNTRUSTED"),
            TRUST_USER => serial.writeString("USER"),
            TRUST_SYSTEM => serial.writeString("SYSTEM"),
            TRUST_KERNEL => serial.writeString("KERNEL"),
            else => serial.writeString("UNKNOWN"),
        }
        serial.writeString("\n");

        serial.writeString("  Max pages:   ");
        printDec16(self.max_mem_pages);
        serial.writeString("\n");

        serial.writeString("  Unveil cnt:  ");
        printDec8(self.unveil_count);
        serial.writeString("\n");

        serial.writeString("  ELF offset:  ");
        printDec32(self.elf_offset);
        serial.writeString("\n");

        serial.writeString("  ELF size:    ");
        printDec32(self.elf_size);
        serial.writeString("\n");

        serial.writeString("  Validation:  ");
        const err = self.validate();
        if (err == .None) {
            serial.writeString("OK\n");
        } else {
            serial.writeString("FAIL (");
            printErrorName(err);
            serial.writeString(")\n");
        }

        serial.writeString("=======================\n");
    }
};

// ============================================================================
// Parser
// ============================================================================

/// Parse ZAM header from raw bytes
/// Returns null if data is too small
pub fn parse(data: []const u8) ?ZamHeader {
    if (data.len < ZAM_HEADER_SIZE) return null;

    var hdr: ZamHeader = undefined;

    // Magic
    hdr.magic[0] = data[0];
    hdr.magic[1] = data[1];
    hdr.magic[2] = data[2];
    hdr.magic[3] = data[3];

    // Version & header size
    hdr.version = readU16(data, 4);
    hdr.header_size = readU16(data, 6);

    // Flags
    hdr.flags = readU32(data, 8);

    // ELF hash (32 bytes at offset 12)
    copyBytes(&hdr.elf_hash, data, 12, HASH_SIZE);

    // Signature (64 bytes at offset 44)
    copyBytes(&hdr.sig, data, 44, SIGNATURE_SIZE);

    // Signer public key (32 bytes at offset 108)
    copyBytes(&hdr.signer_pubkey, data, 108, PUBKEY_SIZE);

    // Security policy
    hdr.required_caps = readU32(data, 140);
    hdr.trust_level = data[144];
    hdr.max_mem_pages = readU16(data, 145);
    hdr.unveil_count = data[147];
    hdr.trust_block_ref = readU32(data, 148);

    // Payload location
    hdr.elf_offset = readU32(data, 152);
    hdr.elf_size = readU32(data, 156);

    return hdr;
}

/// Parse and validate in one step
pub fn parseAndValidate(data: []const u8) ?ZamHeader {
    const hdr = parse(data) orelse return null;
    if (hdr.validate() != .None) return null;
    return hdr;
}

/// Get ELF payload slice from full .zam data
pub fn getElfPayload(data: []const u8) ?[]const u8 {
    const hdr = parse(data) orelse return null;
    const start = hdr.elf_offset;
    const end = start + hdr.elf_size;
    if (end > data.len) return null;
    return data[start..end];
}

// ============================================================================
// Builder (for creating .zam files / test data)
// ============================================================================

/// Build a ZAM header into a byte buffer
/// Returns number of bytes written (ZAM_HEADER_SIZE) or 0 on failure
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

    // Zero out header
    var i: usize = 0;
    while (i < ZAM_HEADER_SIZE) : (i += 1) {
        out[i] = 0;
    }

    // Magic
    out[0] = 'Z';
    out[1] = 'A';
    out[2] = 'M';
    out[3] = 'R';

    // Version
    writeU16(out, 4, ZAM_VERSION);

    // Header size
    writeU16(out, 6, ZAM_HEADER_SIZE);

    // Flags
    writeU32(out, 8, flags);

    // Hash ELF payload
    var elf_hash: [HASH_SIZE]u8 = undefined;
    hash_mod.sha256Into(elf_data, &elf_hash);
    i = 0;
    while (i < HASH_SIZE) : (i += 1) {
        out[12 + i] = elf_hash[i];
    }

    // Sign if keypair is available and SIGNED flag set
    if ((flags & FLAG_SIGNED) != 0 and signature.KeyPair.isValid()) {
        const sig = signature.KeyPair.sign(elf_data);
        i = 0;
        while (i < SIGNATURE_SIZE) : (i += 1) {
            out[44 + i] = sig[i];
        }

        const pubkey = signature.KeyPair.getPublicKey();
        i = 0;
        while (i < PUBKEY_SIZE) : (i += 1) {
            out[108 + i] = pubkey[i];
        }
    }

    // Security policy
    writeU32(out, 140, caps);
    out[144] = trust;
    writeU16(out, 145, max_pages);
    out[147] = 0; // unveil_count
    writeU32(out, 148, 0); // trust_block_ref

    // Payload location
    writeU32(out, 152, ZAM_HEADER_SIZE);
    writeU32(out, 156, @intCast(elf_data.len));

    return ZAM_HEADER_SIZE;
}

// ============================================================================
// Error name helper
// ============================================================================

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

fn printErrorName(err: ZamError) void {
    serial.writeString(errorName(err));
}

// ============================================================================
// Byte helpers (little-endian, no alignment requirements)
// ============================================================================

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
    while (i < count) : (i += 1) {
        dst[i] = src[src_offset + i];
    }
}

// ============================================================================
// Print helpers
// ============================================================================

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printDec8(val: u8) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [3]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printDec16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [5]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printDec32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printBytes(data: []const u8, max: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        serial.writeChar(hex[data[i] >> 4]);
        serial.writeChar(hex[data[i] & 0xF]);
    }
}
