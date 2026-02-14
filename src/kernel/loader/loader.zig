//! Zamrud OS - Binary Loader Module Root
//! Re-exports all loader components

pub const zam_header = @import("zam_header.zig");
pub const elf_parser = @import("elf_parser.zig");

// Future modules (F5.1+):
// pub const elf_loader = @import("elf_loader.zig");
// pub const zam_security = @import("zam_security.zig");
// pub const zam_exec = @import("zam_exec.zig");
// pub const zam_builtins = @import("zam_builtins.zig");
// pub const zam_disk = @import("zam_disk.zig");
// pub const zam_tool = @import("zam_tool.zig");

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
    initialized = true;
    serial.writeString("[LOADER] ZAM binary loader ready\n");
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
    // Parse ZAM header
    const zam = zam_header.parseAndValidate(data) orelse {
        serial.writeString("[LOADER] ZAM header parse failed\n");
        return null;
    };

    // Get ELF payload
    const elf_start = zam.elf_offset;
    const elf_end = elf_start + zam.elf_size;

    if (elf_end > data.len) {
        serial.writeString("[LOADER] ELF payload extends beyond file\n");
        return null;
    }

    const elf_data = data[elf_start..elf_end];

    // Parse ELF
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
