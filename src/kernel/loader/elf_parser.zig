//! Zamrud OS - ELF64 Parser
//! Parses and validates ELF64 executables for the ZAM binary loader
//!
//! Supports:
//!   - ELF64 header validation
//!   - Program header parsing (PT_LOAD segments)
//!   - x86_64 little-endian executables only
//!   - Segment bounds validation

const serial = @import("../drivers/serial/serial.zig");

// ============================================================================
// ELF64 Constants
// ============================================================================

// Magic
pub const ELF_MAGIC: [4]u8 = .{ 0x7F, 'E', 'L', 'F' };

// Class
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

// Data encoding
pub const ELFDATA2LSB: u8 = 1; // Little-endian
pub const ELFDATA2MSB: u8 = 2; // Big-endian

// Type
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

// Machine
pub const EM_X86_64: u16 = 62;
pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_AARCH64: u16 = 183;

// Program header types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;

// Program header flags
pub const PF_X: u32 = 1; // Execute
pub const PF_W: u32 = 2; // Write
pub const PF_R: u32 = 4; // Read

// Sizes
pub const ELF64_HEADER_SIZE: usize = 64;
pub const ELF64_PHDR_SIZE: usize = 56;

// Limits
pub const MAX_PROGRAM_HEADERS: usize = 16;

// ============================================================================
// Error types
// ============================================================================

pub const ElfError = enum(u8) {
    None = 0,
    TooSmall = 1,
    BadMagic = 2,
    Not64Bit = 3,
    NotLittleEndian = 4,
    NotExecutable = 5,
    NotX86_64 = 6,
    BadVersion = 7,
    BadHeaderSize = 8,
    TooManyPhdrs = 9,
    SegmentOutOfBounds = 10,
    OverlappingSegments = 11,
    NoLoadSegments = 12,
    Truncated = 13,
};

// ============================================================================
// ELF64 Header (64 bytes)
// ============================================================================

pub const Elf64Header = struct {
    // e_ident
    magic: [4]u8,
    class: u8,
    data: u8,
    ei_version: u8,
    osabi: u8,
    pad: [8]u8,

    // Fields
    e_type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64, // Program header table offset
    shoff: u64, // Section header table offset
    flags: u32,
    ehsize: u16, // ELF header size
    phentsize: u16, // Program header entry size
    phnum: u16, // Number of program headers
    shentsize: u16, // Section header entry size
    shnum: u16, // Number of section headers
    shstrndx: u16, // Section name string table index

    // ========================================================================
    // Validation
    // ========================================================================

    pub fn hasValidMagic(self: *const Elf64Header) bool {
        return self.magic[0] == 0x7F and
            self.magic[1] == 'E' and
            self.magic[2] == 'L' and
            self.magic[3] == 'F';
    }

    pub fn is64Bit(self: *const Elf64Header) bool {
        return self.class == ELFCLASS64;
    }

    pub fn isLittleEndian(self: *const Elf64Header) bool {
        return self.data == ELFDATA2LSB;
    }

    pub fn isExecutable(self: *const Elf64Header) bool {
        return self.e_type == ET_EXEC;
    }

    pub fn isX86_64(self: *const Elf64Header) bool {
        return self.machine == EM_X86_64;
    }

    /// Full validation
    pub fn validate(self: *const Elf64Header) ElfError {
        if (!self.hasValidMagic()) return .BadMagic;
        if (!self.is64Bit()) return .Not64Bit;
        if (!self.isLittleEndian()) return .NotLittleEndian;
        if (!self.isExecutable()) return .NotExecutable;
        if (!self.isX86_64()) return .NotX86_64;
        if (self.version != 1) return .BadVersion;
        if (self.phnum > MAX_PROGRAM_HEADERS) return .TooManyPhdrs;
        return .None;
    }

    // ========================================================================
    // Info
    // ========================================================================

    pub fn printInfo(self: *const Elf64Header) void {
        serial.writeString("\n=== ELF64 Header ===\n");

        serial.writeString("  Magic:      ");
        printHex8(self.magic[0]);
        serial.writeChar(' ');
        serial.writeChar(self.magic[1]);
        serial.writeChar(self.magic[2]);
        serial.writeChar(self.magic[3]);
        serial.writeString("\n");

        serial.writeString("  Class:      ");
        if (self.class == ELFCLASS64) serial.writeString("ELF64") else serial.writeString("ELF32");
        serial.writeString("\n");

        serial.writeString("  Data:       ");
        if (self.data == ELFDATA2LSB) serial.writeString("Little-endian") else serial.writeString("Big-endian");
        serial.writeString("\n");

        serial.writeString("  Type:       ");
        switch (self.e_type) {
            ET_EXEC => serial.writeString("EXEC"),
            ET_DYN => serial.writeString("DYN"),
            ET_REL => serial.writeString("REL"),
            else => serial.writeString("OTHER"),
        }
        serial.writeString("\n");

        serial.writeString("  Machine:    ");
        switch (self.machine) {
            EM_X86_64 => serial.writeString("x86_64"),
            EM_386 => serial.writeString("i386"),
            EM_AARCH64 => serial.writeString("AArch64"),
            else => serial.writeString("unknown"),
        }
        serial.writeString("\n");

        serial.writeString("  Entry:      0x");
        printHex64(self.entry);
        serial.writeString("\n");

        serial.writeString("  PH offset:  ");
        printDec64(self.phoff);
        serial.writeString("\n");

        serial.writeString("  PH count:   ");
        printDec16(self.phnum);
        serial.writeString("\n");

        serial.writeString("  PH entsize: ");
        printDec16(self.phentsize);
        serial.writeString("\n");

        serial.writeString("  Validation: ");
        const err = self.validate();
        if (err == .None) {
            serial.writeString("OK\n");
        } else {
            serial.writeString("FAIL (");
            serial.writeString(elfErrorName(err));
            serial.writeString(")\n");
        }

        serial.writeString("====================\n");
    }
};

// ============================================================================
// Program Header (56 bytes)
// ============================================================================

pub const ProgramHeader = struct {
    p_type: u32,
    flags: u32,
    offset: u64, // Offset in file
    vaddr: u64, // Virtual address
    paddr: u64, // Physical address (unused)
    filesz: u64, // Size in file
    memsz: u64, // Size in memory
    align_val: u64, // Alignment

    pub fn isLoad(self: *const ProgramHeader) bool {
        return self.p_type == PT_LOAD;
    }

    pub fn isReadable(self: *const ProgramHeader) bool {
        return (self.flags & PF_R) != 0;
    }

    pub fn isWritable(self: *const ProgramHeader) bool {
        return (self.flags & PF_W) != 0;
    }

    pub fn isExecutable(self: *const ProgramHeader) bool {
        return (self.flags & PF_X) != 0;
    }

    /// Check if this segment needs BSS (memsz > filesz)
    pub fn hasBss(self: *const ProgramHeader) bool {
        return self.memsz > self.filesz;
    }

    /// Get BSS size
    pub fn bssSize(self: *const ProgramHeader) u64 {
        if (self.memsz > self.filesz) return self.memsz - self.filesz;
        return 0;
    }

    /// Get end virtual address
    pub fn vend(self: *const ProgramHeader) u64 {
        return self.vaddr + self.memsz;
    }

    pub fn printInfo(self: *const ProgramHeader) void {
        switch (self.p_type) {
            PT_LOAD => serial.writeString("  LOAD  "),
            PT_NULL => serial.writeString("  NULL  "),
            PT_DYNAMIC => serial.writeString("  DYN   "),
            PT_NOTE => serial.writeString("  NOTE  "),
            PT_PHDR => serial.writeString("  PHDR  "),
            else => serial.writeString("  OTHER "),
        }

        serial.writeString("off=0x");
        printHex64(self.offset);
        serial.writeString(" va=0x");
        printHex64(self.vaddr);
        serial.writeString(" fsz=0x");
        printHex64(self.filesz);
        serial.writeString(" msz=0x");
        printHex64(self.memsz);
        serial.writeString(" [");
        if (self.isReadable()) serial.writeChar('R') else serial.writeChar('-');
        if (self.isWritable()) serial.writeChar('W') else serial.writeChar('-');
        if (self.isExecutable()) serial.writeChar('X') else serial.writeChar('-');
        serial.writeString("]\n");
    }
};

// ============================================================================
// Parsed ELF result
// ============================================================================

pub const ParsedElf = struct {
    header: Elf64Header,
    phdrs: [MAX_PROGRAM_HEADERS]ProgramHeader,
    phdr_count: usize,
    load_count: usize, // Number of PT_LOAD segments

    /// Get entry point
    pub fn entryPoint(self: *const ParsedElf) u64 {
        return self.header.entry;
    }

    /// Get PT_LOAD segment by index (only LOAD segments)
    pub fn getLoadSegment(self: *const ParsedElf, index: usize) ?*const ProgramHeader {
        var load_idx: usize = 0;
        var i: usize = 0;
        while (i < self.phdr_count) : (i += 1) {
            if (self.phdrs[i].isLoad()) {
                if (load_idx == index) return &self.phdrs[i];
                load_idx += 1;
            }
        }
        return null;
    }

    pub fn printInfo(self: *const ParsedElf) void {
        self.header.printInfo();

        serial.writeString("Program Headers (");
        printDec16(@intCast(self.phdr_count));
        serial.writeString(" total, ");
        printDec16(@intCast(self.load_count));
        serial.writeString(" LOAD):\n");

        var i: usize = 0;
        while (i < self.phdr_count) : (i += 1) {
            self.phdrs[i].printInfo();
        }
    }
};

// ============================================================================
// Parser functions
// ============================================================================

/// Parse ELF64 header from raw bytes
pub fn parseHeader(data: []const u8) ?Elf64Header {
    if (data.len < ELF64_HEADER_SIZE) return null;

    var hdr: Elf64Header = undefined;

    // e_ident (16 bytes)
    hdr.magic[0] = data[0];
    hdr.magic[1] = data[1];
    hdr.magic[2] = data[2];
    hdr.magic[3] = data[3];
    hdr.class = data[4];
    hdr.data = data[5];
    hdr.ei_version = data[6];
    hdr.osabi = data[7];
    var pi: usize = 0;
    while (pi < 8) : (pi += 1) {
        hdr.pad[pi] = data[8 + pi];
    }

    // Fields (little-endian)
    hdr.e_type = readU16(data, 16);
    hdr.machine = readU16(data, 18);
    hdr.version = readU32(data, 20);
    hdr.entry = readU64(data, 24);
    hdr.phoff = readU64(data, 32);
    hdr.shoff = readU64(data, 40);
    hdr.flags = readU32(data, 48);
    hdr.ehsize = readU16(data, 52);
    hdr.phentsize = readU16(data, 54);
    hdr.phnum = readU16(data, 56);
    hdr.shentsize = readU16(data, 58);
    hdr.shnum = readU16(data, 60);
    hdr.shstrndx = readU16(data, 62);

    return hdr;
}

/// Parse a single program header
fn parseProgramHeader(data: []const u8, offset: usize) ?ProgramHeader {
    if (offset + ELF64_PHDR_SIZE > data.len) return null;

    return ProgramHeader{
        .p_type = readU32(data, offset),
        .flags = readU32(data, offset + 4),
        .offset = readU64(data, offset + 8),
        .vaddr = readU64(data, offset + 16),
        .paddr = readU64(data, offset + 24),
        .filesz = readU64(data, offset + 32),
        .memsz = readU64(data, offset + 40),
        .align_val = readU64(data, offset + 48),
    };
}

/// Full ELF parse: header + program headers + validation
pub fn parseElf(data: []const u8) ?ParsedElf {
    const hdr = parseHeader(data) orelse return null;

    // Validate header
    const err = hdr.validate();
    if (err != .None) {
        serial.writeString("[ELF] Validation failed: ");
        serial.writeString(elfErrorName(err));
        serial.writeString("\n");
        return null;
    }

    var result: ParsedElf = undefined;
    result.header = hdr;
    result.phdr_count = 0;
    result.load_count = 0;

    // Zero out phdrs
    var zi: usize = 0;
    while (zi < MAX_PROGRAM_HEADERS) : (zi += 1) {
        result.phdrs[zi] = .{
            .p_type = 0,
            .flags = 0,
            .offset = 0,
            .vaddr = 0,
            .paddr = 0,
            .filesz = 0,
            .memsz = 0,
            .align_val = 0,
        };
    }

    // Parse program headers
    if (hdr.phnum > 0 and hdr.phoff > 0) {
        var i: usize = 0;
        while (i < hdr.phnum and i < MAX_PROGRAM_HEADERS) : (i += 1) {
            const ph_offset = @as(usize, @intCast(hdr.phoff)) + i * @as(usize, @intCast(hdr.phentsize));

            if (parseProgramHeader(data, ph_offset)) |phdr| {
                result.phdrs[result.phdr_count] = phdr;
                result.phdr_count += 1;

                if (phdr.isLoad()) {
                    result.load_count += 1;
                }
            } else {
                serial.writeString("[ELF] Truncated program header\n");
                return null;
            }
        }
    }

    return result;
}

/// Validate segments don't go out of file bounds
pub fn validateSegmentBounds(parsed: *const ParsedElf, file_size: usize) ElfError {
    var i: usize = 0;
    while (i < parsed.phdr_count) : (i += 1) {
        const ph = &parsed.phdrs[i];
        if (ph.isLoad()) {
            // Check file bounds
            const seg_end = ph.offset + ph.filesz;
            if (seg_end > file_size) return .SegmentOutOfBounds;
        }
    }
    return .None;
}

/// Check for overlapping LOAD segments
pub fn checkOverlappingSegments(parsed: *const ParsedElf) ElfError {
    var i: usize = 0;
    while (i < parsed.phdr_count) : (i += 1) {
        if (!parsed.phdrs[i].isLoad()) continue;
        const a = &parsed.phdrs[i];

        var j: usize = i + 1;
        while (j < parsed.phdr_count) : (j += 1) {
            if (!parsed.phdrs[j].isLoad()) continue;
            const b = &parsed.phdrs[j];

            // Check virtual address overlap
            if (a.vaddr < b.vend() and b.vaddr < a.vend()) {
                return .OverlappingSegments;
            }
        }
    }
    return .None;
}

/// Full validation pipeline
pub fn validateFull(data: []const u8) ElfError {
    if (data.len < ELF64_HEADER_SIZE) return .TooSmall;

    const hdr = parseHeader(data) orelse return .TooSmall;
    const hdr_err = hdr.validate();
    if (hdr_err != .None) return hdr_err;

    const parsed = parseElf(data) orelse return .Truncated;

    if (parsed.load_count == 0) return .NoLoadSegments;

    const bounds_err = validateSegmentBounds(&parsed, data.len);
    if (bounds_err != .None) return bounds_err;

    const overlap_err = checkOverlappingSegments(&parsed);
    if (overlap_err != .None) return overlap_err;

    return .None;
}

// ============================================================================
// Error name
// ============================================================================

pub fn elfErrorName(err: ElfError) []const u8 {
    return switch (err) {
        .None => "None",
        .TooSmall => "TooSmall",
        .BadMagic => "BadMagic",
        .Not64Bit => "Not64Bit",
        .NotLittleEndian => "NotLittleEndian",
        .NotExecutable => "NotExecutable",
        .NotX86_64 => "NotX86_64",
        .BadVersion => "BadVersion",
        .BadHeaderSize => "BadHeaderSize",
        .TooManyPhdrs => "TooManyPhdrs",
        .SegmentOutOfBounds => "SegmentOutOfBounds",
        .OverlappingSegments => "OverlappingSegments",
        .NoLoadSegments => "NoLoadSegments",
        .Truncated => "Truncated",
    };
}

// ============================================================================
// Byte helpers (little-endian)
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

fn readU64(data: []const u8, offset: usize) u64 {
    return @as(u64, data[offset]) |
        (@as(u64, data[offset + 1]) << 8) |
        (@as(u64, data[offset + 2]) << 16) |
        (@as(u64, data[offset + 3]) << 24) |
        (@as(u64, data[offset + 4]) << 32) |
        (@as(u64, data[offset + 5]) << 40) |
        (@as(u64, data[offset + 6]) << 48) |
        (@as(u64, data[offset + 7]) << 56);
}

// ============================================================================
// Print helpers
// ============================================================================

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
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

fn printDec64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast(@as(u8, @truncate(v % 10)) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
