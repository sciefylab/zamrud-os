//! Zamrud OS - Shell Commands for ZAM Binary Loader (F5.0)
//! Commands: zamtest, zaminfo, elfinfo, zamverify

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const serial = @import("../../drivers/serial/serial.zig");

const loader = @import("../../loader/loader.zig");
const zam_header = @import("../../loader/zam_header.zig");
const elf_parser = @import("../../loader/elf_parser.zig");
const test_zam_elf = @import("../../tests/test_zam_elf.zig");

// ============================================================================
// Main dispatcher
// ============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const sub = parsed.cmd;

    if (sub.len == 0 or helpers.strEql(sub, "help")) {
        cmdHelp();
    } else if (helpers.strEql(sub, "test")) {
        cmdZamTest();
    } else if (helpers.strEql(sub, "info")) {
        cmdZamInfo(parsed.rest);
    } else if (helpers.strEql(sub, "elfinfo")) {
        cmdElfInfo(parsed.rest);
    } else if (helpers.strEql(sub, "verify")) {
        cmdZamVerify(parsed.rest);
    } else if (helpers.strEql(sub, "status")) {
        cmdStatus();
    } else if (helpers.strEql(sub, "demo")) {
        cmdDemo();
    } else if (helpers.strEql(sub, "segtest")) {
        cmdSegTest();
    } else if (helpers.strEql(sub, "exectest")) {
        cmdExecTest();
    } else {
        shell.printError("Unknown zam subcommand: ");
        shell.print(sub);
        shell.newLine();
        shell.println("  Type 'zam help' for usage");
    }
}

// ============================================================================
// Help
// ============================================================================

fn cmdHelp() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Binary Loader (F5.0) ===");
    shell.println("");
    shell.println("  zam status       Show loader status");
    shell.println("  zam test         Run F5.0 parser tests (25 tests)");
    shell.println("  zam demo         Parse a built-in test .zam binary");
    shell.println("  zam info         Show test ZAM header info");
    shell.println("  zam elfinfo      Show test ELF64 header info");
    shell.println("  zam verify       Verify test ZAM hash + signature");
    shell.println("  zam segtest      Run F5.1 segment loader tests (20 tests)");
    shell.println("  zam exectest     Run F5.2 process execution tests (20 tests)");
    shell.println("  zam help         This help");
    shell.println("");
    shell.println("  Header: 160 bytes (ZAMR magic + SHA-256 + sig + caps)");
    shell.println("  Payload: ELF64 x86_64 executable");

    shell.println("");
}

// ============================================================================
// Status
// ============================================================================

fn cmdStatus() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Loader Status ===");

    shell.print("  Loader initialized: ");
    if (loader.isInitialized()) {
        shell.printInfoLine("YES");
    } else {
        shell.printError("NO");
        shell.newLine();
    }

    shell.print("  ZAM header size:    ");
    helpers.printDec(zam_header.ZAM_HEADER_SIZE);
    shell.println(" bytes");

    shell.print("  ELF64 header size:  ");
    helpers.printDec(elf_parser.ELF64_HEADER_SIZE);
    shell.println(" bytes");

    shell.print("  Max program hdrs:   ");
    helpers.printDec(elf_parser.MAX_PROGRAM_HEADERS);
    shell.newLine();

    shell.print("  Signature size:     ");
    helpers.printDec(zam_header.SIGNATURE_SIZE);
    shell.println(" bytes");

    shell.print("  Hash size:          ");
    helpers.printDec(zam_header.HASH_SIZE);
    shell.println(" bytes");

    shell.println("");
}

// ============================================================================
// Test — runs the 25-test suite
// ============================================================================

pub fn cmdZamTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.0 ZAM/ELF Parser Tests ===");
    shell.println("");

    test_zam_elf.runTests();

    shell.println("");
}

// ============================================================================
// Demo — build and parse a test .zam in-memory
// ============================================================================

fn cmdDemo() void {
    shell.println("");
    shell.printInfoLine("=== ZAM Demo: Build & Parse Test Binary ===");
    shell.println("");

    // Build test .zam
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);

    if (size == 0) {
        shell.printError("Failed to build demo .zam binary");
        shell.newLine();
        return;
    }

    shell.print("  Built demo .zam: ");
    helpers.printDec(size);
    shell.println(" bytes");

    // Parse it
    if (loader.parseZamFile(buf[0..size])) |parsed| {
        shell.printInfoLine("  Parse: OK");

        shell.print("  Entry point: 0x");
        helpers.printHex64(parsed.elf.entryPoint());
        shell.newLine();

        shell.print("  LOAD segments: ");
        helpers.printDec(parsed.elf.load_count);
        shell.newLine();

        shell.print("  Caps required: 0x");
        helpers.printHex32(parsed.zam.required_caps);
        shell.newLine();

        shell.print("  Trust level: ");
        switch (parsed.zam.trust_level) {
            zam_header.TRUST_UNTRUSTED => shell.print("UNTRUSTED"),
            zam_header.TRUST_USER => shell.print("USER"),
            zam_header.TRUST_SYSTEM => shell.print("SYSTEM"),
            zam_header.TRUST_KERNEL => shell.print("KERNEL"),
            else => shell.print("UNKNOWN"),
        }
        shell.newLine();

        // Verify integrity
        shell.print("  Hash verify: ");
        if (loader.verifyZamIntegrity(buf[0..size])) {
            shell.printInfoLine("PASS");
        } else {
            shell.printError("FAIL");
            shell.newLine();
        }
    } else {
        shell.printError("  Parse: FAILED");
        shell.newLine();
    }

    shell.println("");
}

fn cmdSegTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.1 Segment Loader Tests ===");
    shell.println("");

    const test_seg = @import("../../tests/test_segment_loader.zig");
    test_seg.runTests();

    shell.println("");
}

fn cmdExecTest() void {
    shell.println("");
    shell.printInfoLine("=== Running F5.2 Process Execution Tests ===");
    shell.println("");

    const test_exec = @import("../../tests/test_elf_exec.zig");
    test_exec.runTests();

    shell.println("");
}

// ============================================================================
// ZAM Info — display header details of test binary
// ============================================================================

fn cmdZamInfo(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ZAM Header Info (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);

    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        shell.print("  Magic:       ");
        shell.printChar(hdr.magic[0]);
        shell.printChar(hdr.magic[1]);
        shell.printChar(hdr.magic[2]);
        shell.printChar(hdr.magic[3]);
        shell.newLine();

        shell.print("  Version:     ");
        helpers.printDec(hdr.version);
        shell.newLine();

        shell.print("  Header size: ");
        helpers.printDec(hdr.header_size);
        shell.println(" bytes");

        shell.print("  Flags:       0x");
        helpers.printHex32(hdr.flags);
        shell.print(" [");
        if (hdr.isSigned()) shell.print("SIGNED ");
        if (hdr.isTrusted()) shell.print("TRUSTED ");
        if (hdr.isSandboxed()) shell.print("SANDBOX ");
        shell.println("]");

        shell.print("  ELF hash:    ");
        printBytesShell(&hdr.elf_hash, 8);
        shell.println("...");

        shell.print("  Caps:        0x");
        helpers.printHex32(hdr.required_caps);
        shell.newLine();

        shell.print("  Trust:       ");
        switch (hdr.trust_level) {
            zam_header.TRUST_UNTRUSTED => shell.print("UNTRUSTED"),
            zam_header.TRUST_USER => shell.print("USER"),
            zam_header.TRUST_SYSTEM => shell.print("SYSTEM"),
            zam_header.TRUST_KERNEL => shell.print("KERNEL"),
            else => shell.print("UNKNOWN"),
        }
        shell.newLine();

        shell.print("  Max pages:   ");
        helpers.printDec(hdr.max_mem_pages);
        shell.newLine();

        shell.print("  ELF offset:  ");
        helpers.printDec(hdr.elf_offset);
        shell.newLine();

        shell.print("  ELF size:    ");
        helpers.printDec(hdr.elf_size);
        shell.println(" bytes");

        shell.print("  Validation:  ");
        const err = hdr.validate();
        if (err == .None) {
            shell.printInfoLine("OK");
        } else {
            shell.printError(zam_header.errorName(err));
            shell.newLine();
        }
    } else {
        shell.printError("Failed to parse ZAM header");
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// ELF Info — display ELF64 header details of test binary
// ============================================================================

fn cmdElfInfo(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ELF64 Header Info (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);

    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    // Get ELF payload from .zam
    if (zam_header.getElfPayload(buf[0..size])) |elf_data| {
        if (elf_parser.parseElf(elf_data)) |parsed| {
            const hdr = &parsed.header;

            shell.print("  Magic:      0x");
            helpers.printHex8(hdr.magic[0]);
            shell.print(" ");
            shell.printChar(hdr.magic[1]);
            shell.printChar(hdr.magic[2]);
            shell.printChar(hdr.magic[3]);
            shell.newLine();

            shell.print("  Class:      ");
            if (hdr.is64Bit()) shell.println("ELF64") else shell.println("ELF32");

            shell.print("  Data:       ");
            if (hdr.isLittleEndian()) shell.println("Little-endian") else shell.println("Big-endian");

            shell.print("  Type:       ");
            switch (hdr.e_type) {
                elf_parser.ET_EXEC => shell.println("EXEC (executable)"),
                elf_parser.ET_DYN => shell.println("DYN (shared object)"),
                elf_parser.ET_REL => shell.println("REL (relocatable)"),
                else => shell.println("OTHER"),
            }

            shell.print("  Machine:    ");
            switch (hdr.machine) {
                elf_parser.EM_X86_64 => shell.println("x86_64"),
                elf_parser.EM_386 => shell.println("i386"),
                elf_parser.EM_AARCH64 => shell.println("AArch64"),
                else => shell.println("unknown"),
            }

            shell.print("  Entry:      0x");
            helpers.printHex64(hdr.entry);
            shell.newLine();

            shell.print("  PH offset:  ");
            helpers.printDec64(hdr.phoff);
            shell.newLine();

            shell.print("  PH count:   ");
            helpers.printDec(hdr.phnum);
            shell.newLine();

            shell.print("  LOAD segs:  ");
            helpers.printDec(parsed.load_count);
            shell.newLine();

            shell.print("  Validation: ");
            const err = hdr.validate();
            if (err == .None) {
                shell.printInfoLine("OK");
            } else {
                shell.printError(elf_parser.elfErrorName(err));
                shell.newLine();
            }

            // Print program headers
            if (parsed.phdr_count > 0) {
                shell.println("");
                shell.println("  Program Headers:");
                var i: usize = 0;
                while (i < parsed.phdr_count) : (i += 1) {
                    const ph = &parsed.phdrs[i];
                    shell.print("    [");
                    helpers.printDec(i);
                    shell.print("] ");

                    switch (ph.p_type) {
                        elf_parser.PT_LOAD => shell.print("LOAD  "),
                        elf_parser.PT_NULL => shell.print("NULL  "),
                        elf_parser.PT_NOTE => shell.print("NOTE  "),
                        elf_parser.PT_PHDR => shell.print("PHDR  "),
                        else => shell.print("OTHER "),
                    }

                    shell.print("va=0x");
                    helpers.printHex64(ph.vaddr);
                    shell.print(" fsz=");
                    helpers.printDec64(ph.filesz);
                    shell.print(" msz=");
                    helpers.printDec64(ph.memsz);
                    shell.print(" [");
                    if (ph.isReadable()) shell.printChar('R') else shell.printChar('-');
                    if (ph.isWritable()) shell.printChar('W') else shell.printChar('-');
                    if (ph.isExecutable()) shell.printChar('X') else shell.printChar('-');
                    shell.println("]");
                }
            }
        } else {
            shell.printError("Failed to parse ELF");
            shell.newLine();
        }
    } else {
        shell.printError("Failed to extract ELF payload");
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// Verify — hash + signature check on test binary
// ============================================================================

fn cmdZamVerify(_: []const u8) void {
    shell.println("");
    shell.printInfoLine("=== ZAM Verify (test binary) ===");
    shell.println("");

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildDemoZam(&buf);

    if (size == 0) {
        shell.printError("Failed to build test binary");
        shell.newLine();
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        // Structural validation
        shell.print("  Structure:  ");
        const struct_err = hdr.validate();
        if (struct_err == .None) {
            shell.printInfoLine("OK");
        } else {
            shell.printError("FAIL (");
            shell.print(zam_header.errorName(struct_err));
            shell.println(")");
        }

        // Hash verification
        const elf_start = hdr.elf_offset;
        const elf_end = elf_start + hdr.elf_size;
        if (elf_end <= size) {
            const elf_data = buf[elf_start..elf_end];

            shell.print("  Hash:       ");
            if (hdr.verifyHash(elf_data)) {
                shell.printInfoLine("PASS (SHA-256 match)");
            } else {
                shell.printError("FAIL (SHA-256 mismatch)");
                shell.newLine();
            }

            // Signature (only if signed)
            shell.print("  Signature:  ");
            if (hdr.isSigned()) {
                if (hdr.verifySignature(elf_data)) {
                    shell.printInfoLine("PASS (valid)");
                } else {
                    shell.printError("FAIL (invalid or unknown signer)");
                    shell.newLine();
                }
            } else {
                shell.println("NOT SIGNED");
            }

            // ELF validation
            shell.print("  ELF format: ");
            const elf_err = elf_parser.validateFull(elf_data);
            if (elf_err == .None) {
                shell.printInfoLine("OK (valid x86_64 ELF64)");
            } else {
                shell.printError("FAIL (");
                shell.print(elf_parser.elfErrorName(elf_err));
                shell.println(")");
            }
        } else {
            shell.printError("  ELF payload out of bounds!");
            shell.newLine();
        }

        // Integrity check
        shell.print("  Integrity:  ");
        if (loader.verifyZamIntegrity(buf[0..size])) {
            shell.printInfoLine("VERIFIED");
        } else {
            shell.printError("COMPROMISED");
            shell.newLine();
        }
    } else {
        shell.printError("Failed to parse ZAM header");
        shell.newLine();
    }

    shell.println("");
}

// ============================================================================
// Internal: build a demo .zam binary for display/testing
// ============================================================================

fn buildDemoZam(buf: []u8) usize {
    if (buf.len < zam_header.ZAM_HEADER_SIZE + 136) return 0;

    // Build minimal ELF
    var elf_buf: [256]u8 = [_]u8{0} ** 256;
    const elf_size = buildMinimalElf(&elf_buf);
    if (elf_size == 0) return 0;

    // Build ZAM header
    const hdr_size = zam_header.buildHeader(
        buf,
        elf_buf[0..elf_size],
        0x0000000F, // basic caps
        zam_header.TRUST_USER,
        64,
        0, // unsigned for demo
    );

    if (hdr_size == 0) return 0;

    // Copy ELF after header
    var i: usize = 0;
    while (i < elf_size) : (i += 1) {
        buf[hdr_size + i] = elf_buf[i];
    }

    return hdr_size + elf_size;
}

fn buildMinimalElf(buf: []u8) usize {
    if (buf.len < 136) return 0;

    var i: usize = 0;
    while (i < buf.len and i < 256) : (i += 1) {
        buf[i] = 0;
    }

    // ELF magic
    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = elf_parser.ELFCLASS64;
    buf[5] = elf_parser.ELFDATA2LSB;
    buf[6] = 1; // version
    buf[7] = 0; // OS/ABI

    // e_type: ET_EXEC
    writeU16(buf, 16, elf_parser.ET_EXEC);
    // e_machine: x86_64
    writeU16(buf, 18, elf_parser.EM_X86_64);
    // e_version
    writeU32(buf, 20, 1);
    // e_entry
    writeU64(buf, 24, 0x400000);
    // e_phoff
    writeU64(buf, 32, 64);
    // e_ehsize
    writeU16(buf, 52, 64);
    // e_phentsize
    writeU16(buf, 54, 56);
    // e_phnum
    writeU16(buf, 56, 1);
    // e_shentsize
    writeU16(buf, 58, 64);

    // Program header at offset 64
    writeU32(buf, 64, elf_parser.PT_LOAD); // p_type
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X); // p_flags
    writeU64(buf, 72, 0); // p_offset
    writeU64(buf, 80, 0x400000); // p_vaddr
    writeU64(buf, 88, 0x400000); // p_paddr
    writeU64(buf, 96, 136); // p_filesz
    writeU64(buf, 104, 136); // p_memsz
    writeU64(buf, 112, 0x1000); // p_align

    // Minimal x86_64 code: exit(0)
    buf[120] = 0xB8; // mov eax, 60
    buf[121] = 0x3C;
    buf[122] = 0x00;
    buf[123] = 0x00;
    buf[124] = 0x00;
    buf[125] = 0x31; // xor edi, edi
    buf[126] = 0xFF;
    buf[127] = 0x0F; // syscall
    buf[128] = 0x05;

    return 136;
}

// ============================================================================
// Byte helpers
// ============================================================================

fn writeU16(buf: []u8, offset: usize, val: u16) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
}

fn writeU32(buf: []u8, offset: usize, val: u32) void {
    buf[offset] = @intCast(val & 0xFF);
    buf[offset + 1] = @intCast((val >> 8) & 0xFF);
    buf[offset + 2] = @intCast((val >> 16) & 0xFF);
    buf[offset + 3] = @intCast((val >> 24) & 0xFF);
}

fn writeU64(buf: []u8, offset: usize, val: u64) void {
    var j: usize = 0;
    while (j < 8) : (j += 1) {
        buf[offset + j] = @intCast((val >> @intCast(j * 8)) & 0xFF);
    }
}

fn printBytesShell(data: []const u8, max: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        shell.printChar(hex[data[i] >> 4]);
        shell.printChar(hex[data[i] & 0xF]);
    }
}
