//! Zamrud OS - Binary Loader Module Root
//! Re-exports all loader components

pub const zam_header = @import("zam_header.zig");
pub const elf_parser = @import("elf_parser.zig");
pub const segment_loader = @import("segment_loader.zig");
pub const elf_exec = @import("elf_exec.zig");
pub const builtins = @import("builtins.zig");

const serial = @import("../drivers/serial/serial.zig");

// ============================================================================
// Type aliases for convenience
// ============================================================================

pub const ZamHeader = zam_header.ZamHeader;
pub const ZamError = zam_header.ZamError;

pub const Elf64Header = elf_parser.Elf64Header;
pub const ProgramHeader = elf_parser.ProgramHeader;
pub const ParsedElf = elf_parser.ParsedElf;
pub const ElfError = elf_parser.ElfError;

pub const LoadResult = segment_loader.LoadResult;
pub const LoadError = segment_loader.LoadError;
pub const LoadedSegment = segment_loader.LoadedSegment;

pub const ExecResult = elf_exec.ExecResult;
pub const ExecError = elf_exec.ExecError;

// ============================================================================
// Constants
// ============================================================================

pub const ZAM_HEADER_SIZE = zam_header.ZAM_HEADER_SIZE;
pub const ELF64_HEADER_SIZE = elf_parser.ELF64_HEADER_SIZE;

// ============================================================================
// Module init
// ============================================================================

var initialized: bool = false;

pub fn init() void {
    serial.writeString("[LOADER] Initializing ZAM binary loader...\n");
    elf_exec.init();
    builtins.init();
    initialized = true;
    serial.writeString("[LOADER] ZAM binary loader ready (F5.0-F5.4)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Unified parse: .zam file → ZamHeader + ParsedElf
// ============================================================================

pub const ParsedZam = struct {
    zam: ZamHeader,
    elf: ParsedElf,
    elf_data_offset: usize,
    elf_data_size: usize,
};

/// Parse a complete .zam file (ZAM header + ELF payload)
pub fn parseZamFile(data: []const u8) ?ParsedZam {
    const zam = zam_header.parseAndValidate(data) orelse {
        serial.writeString("[LOADER] ZAM header parse failed\n");
        return null;
    };

    const elf_start = zam.elf_offset;
    const elf_end = elf_start + zam.elf_size;

    if (elf_end > data.len) {
        serial.writeString("[LOADER] ELF payload extends beyond file\n");
        return null;
    }

    const elf_data = data[elf_start..elf_end];

    const elf = elf_parser.parseElf(elf_data) orelse {
        serial.writeString("[LOADER] ELF parse failed\n");
        return null;
    };

    return ParsedZam{
        .zam = zam,
        .elf = elf,
        .elf_data_offset = elf_start,
        .elf_data_size = zam.elf_size,
    };
}

/// Verify integrity of a .zam file (hash check)
pub fn verifyZamIntegrity(data: []const u8) bool {
    const zam = zam_header.parse(data) orelse return false;

    const elf_start = zam.elf_offset;
    const elf_end = elf_start + zam.elf_size;
    if (elf_end > data.len) return false;

    const elf_data = data[elf_start..elf_end];
    return zam.verifyHash(elf_data);
}

// ============================================================================
// F5.1: Load .zam file into memory
// ============================================================================

/// Load a .zam file: parse → verify → load segments → return result
pub fn loadZamFile(data: []const u8, user_mode: bool) ?LoadResult {
    const parsed = parseZamFile(data) orelse return null;

    if (!verifyZamIntegrity(data)) {
        serial.writeString("[LOADER] Integrity check failed\n");
        return null;
    }

    const elf_data = data[parsed.elf_data_offset .. parsed.elf_data_offset + parsed.elf_data_size];

    const result = segment_loader.loadSegments(&parsed.elf, elf_data, user_mode);

    if (result.err != .None) {
        serial.writeString("[LOADER] Segment loading failed: ");
        serial.writeString(segment_loader.loadErrorName(result.err));
        serial.writeString("\n");
        return null;
    }

    serial.writeString("[LOADER] .zam loaded successfully\n");
    return result;
}

/// Unload a previously loaded binary
pub fn unloadBinary(result: *LoadResult) void {
    segment_loader.cleanupAllSegments(result);
    serial.writeString("[LOADER] Binary unloaded\n");
}

// ============================================================================
// F5.2: Execute .zam or raw ELF
// ============================================================================

/// Execute a .zam binary (full pipeline)
pub fn execZam(data: []const u8, name: []const u8) ExecResult {
    return elf_exec.execZam(data, name);
}

/// Execute raw ELF data
pub fn execRawElf(data: []const u8, name: []const u8, caps: u32) ExecResult {
    return elf_exec.execRawElf(data, name, caps);
}

/// Cleanup an ELF process
pub fn cleanupElfProcess(pid: u32) bool {
    return elf_exec.cleanupProcess(pid);
}
