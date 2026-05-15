//! Zamrud OS - Binary Loader Module Root
//! Re-exports all loader components
//! 🆕 E3.6: SLOR Anti-Quantum Signature Verification integrated

pub const zam_header = @import("zam_header.zig");
pub const elf_parser = @import("elf_parser.zig");
pub const segment_loader = @import("segment_loader.zig");
pub const elf_exec = @import("elf_exec.zig");
pub const builtins = @import("builtins.zig");

const serial = @import("../drivers/serial/serial.zig");

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

pub const ZAM_HEADER_SIZE = zam_header.ZAM_HEADER_SIZE;
pub const ELF64_HEADER_SIZE = elf_parser.ELF64_HEADER_SIZE;

var initialized: bool = false;

pub fn init() void {
    serial.writeString("[LOADER] Initializing ZAM binary loader...\n");
    elf_exec.init();
    builtins.init();
    initialized = true;
    serial.writeString("[LOADER] ZAM binary loader ready (F5.0-F5.4 & E3.6 Anti-Quantum)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub const ParsedZam = struct {
    zam: ZamHeader,
    elf: ParsedElf,
    elf_data_offset: usize,
    elf_data_size: usize,
};

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

/// Verify integrity & Anti-Quantum Signature of a .zam file
pub fn verifyZamIntegrity(data: []const u8) bool {
    const zam = zam_header.parse(data) orelse return false;

    const elf_start = zam.elf_offset;
    const elf_end = elf_start + zam.elf_size;
    if (elf_end > data.len) return false;

    const elf_data = data[elf_start..elf_end];

    // 1. Cek SHA-256 Hash
    if (!zam.verifyHash(elf_data)) {
        serial.writeString("[LOADER] SHA-256 Hash mismatch!\n");
        return false;
    }

    // 2. Cek Anti-Quantum Signature (E3.6)
    if (zam.isSigned()) {
        if (!zam.verifyQuantumSignature(elf_data)) {
            serial.writeString("[LOADER] [CRITICAL] SLOR Anti-Quantum Signature INVALID!\n");
            return false;
        }

        // 3. Dev Key vs Authority Key Isolation
        if (zam.isDevKey()) {
            serial.writeString("[LOADER] App signed with Local Dev Key. Executing in Ephemeral Sandbox.\n");
            // Di sini kita bisa menurunkan Capabilities paksa karena ini cuma Dev Key
        } else {
            serial.writeString("[LOADER] App signed with Global Authority Key. Trust established.\n");
        }
    }

    return true;
}

pub fn loadZamFile(data: []const u8, user_mode: bool) ?LoadResult {
    const parsed = parseZamFile(data) orelse return null;

    if (!verifyZamIntegrity(data)) {
        serial.writeString("[LOADER] Integrity / Signature check failed\n");
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

pub fn unloadBinary(result: *LoadResult) void {
    segment_loader.cleanupAllSegments(result);
    serial.writeString("[LOADER] Binary unloaded\n");
}

pub fn execZam(data: []const u8, name: []const u8) ExecResult {
    return elf_exec.execZam(data, name);
}

pub fn execRawElf(data: []const u8, name: []const u8, caps: u32) ExecResult {
    return elf_exec.execRawElf(data, name, caps);
}

pub fn cleanupElfProcess(pid: u32) bool {
    return elf_exec.cleanupProcess(pid);
}
