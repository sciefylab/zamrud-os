//! Zamrud OS - F5.0 Tests: ZAM Header & ELF64 Parser
//! 25 tests covering header parsing, validation, and error rejection

const serial = @import("../drivers/serial/serial.zig");
const zam_header = @import("../loader/zam_header.zig");
const elf_parser = @import("../loader/elf_parser.zig");
const loader = @import("../loader/loader.zig");
const hash_mod = @import("../crypto/hash.zig");
const signature = @import("../crypto/signature.zig");

// ============================================================================
// Test infrastructure
// ============================================================================

var tests_passed: u32 = 0;
var tests_failed: u32 = 0;

fn pass(name: []const u8) void {
    tests_passed += 1;
    serial.writeString("  [PASS] ");
    serial.writeString(name);
    serial.writeString("\n");
}

fn fail(name: []const u8) void {
    tests_failed += 1;
    serial.writeString("  [FAIL] ");
    serial.writeString(name);
    serial.writeString("\n");
}

// ============================================================================
// Test data builders
// ============================================================================

/// Build a minimal valid ELF64 header (64 bytes) with one PT_LOAD
/// Returns total size used
fn buildMinimalElf(buf: []u8) usize {
    if (buf.len < 120 + 16) return 0; // 64 hdr + 56 phdr + some code

    // Zero out
    var i: usize = 0;
    while (i < buf.len and i < 256) : (i += 1) {
        buf[i] = 0;
    }

    // ELF magic
    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';

    // Class: 64-bit
    buf[4] = elf_parser.ELFCLASS64;
    // Data: little-endian
    buf[5] = elf_parser.ELFDATA2LSB;
    // Version
    buf[6] = 1;
    // OS/ABI
    buf[7] = 0;

    // e_type: ET_EXEC (offset 16)
    writeU16(buf, 16, elf_parser.ET_EXEC);
    // e_machine: x86_64 (offset 18)
    writeU16(buf, 18, elf_parser.EM_X86_64);
    // e_version (offset 20)
    writeU32(buf, 20, 1);
    // e_entry (offset 24)
    writeU64(buf, 24, 0x400000);
    // e_phoff (offset 32) — program headers start at byte 64
    writeU64(buf, 32, 64);
    // e_shoff (offset 40)
    writeU64(buf, 40, 0);
    // e_flags (offset 48)
    writeU32(buf, 48, 0);
    // e_ehsize (offset 52)
    writeU16(buf, 52, 64);
    // e_phentsize (offset 54)
    writeU16(buf, 54, 56);
    // e_phnum (offset 56) — 1 program header
    writeU16(buf, 56, 1);
    // e_shentsize (offset 58)
    writeU16(buf, 58, 64);
    // e_shnum (offset 60)
    writeU16(buf, 60, 0);
    // e_shstrndx (offset 62)
    writeU16(buf, 62, 0);

    // Program header at offset 64 (56 bytes)
    // p_type: PT_LOAD (offset 64)
    writeU32(buf, 64, elf_parser.PT_LOAD);
    // p_flags: RX (offset 68)
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X);
    // p_offset: 0 (offset 72)
    writeU64(buf, 72, 0);
    // p_vaddr: 0x400000 (offset 80)
    writeU64(buf, 80, 0x400000);
    // p_paddr (offset 88)
    writeU64(buf, 88, 0x400000);
    // p_filesz: 136 (offset 96) — covers header + phdr + small code
    writeU64(buf, 96, 136);
    // p_memsz: 136 (offset 104)
    writeU64(buf, 104, 136);
    // p_align (offset 112)
    writeU64(buf, 112, 0x1000);

    // Small "code" after program header (offset 120)
    // x86_64: mov eax, 60; xor edi, edi; syscall (exit(0))
    buf[120] = 0xB8; // mov eax, imm32
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

/// Build a complete .zam file (ZAM header + ELF payload)
fn buildTestZam(buf: []u8, sign: bool) usize {
    if (buf.len < zam_header.ZAM_HEADER_SIZE + 136) return 0;

    // Build ELF payload after header
    var elf_buf: [256]u8 = [_]u8{0} ** 256;
    const elf_size = buildMinimalElf(&elf_buf);
    if (elf_size == 0) return 0;

    var flags: u32 = 0;
    if (sign) flags |= zam_header.FLAG_SIGNED;

    // Build header
    const hdr_size = zam_header.buildHeader(
        buf,
        elf_buf[0..elf_size],
        0x0000000F, // caps
        zam_header.TRUST_USER,
        64, // max pages
        flags,
    );

    if (hdr_size == 0) return 0;

    // Copy ELF payload after header
    var i: usize = 0;
    while (i < elf_size) : (i += 1) {
        buf[hdr_size + i] = elf_buf[i];
    }

    return hdr_size + elf_size;
}

// ============================================================================
// ZAM Header Tests (T01-T10)
// ============================================================================

fn t01_zam_header_parse_valid() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);

    if (size == 0) {
        fail("T01: ZAM header parse valid (build failed)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.hasValidMagic() and hdr.hasValidVersion()) {
            pass("T01: ZAM header parse valid");
        } else {
            fail("T01: ZAM header parse valid (bad fields)");
        }
    } else {
        fail("T01: ZAM header parse valid (parse returned null)");
    }
}

fn t02_zam_magic_validation() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T02: ZAM magic validation (build failed)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.magic[0] == 'Z' and hdr.magic[1] == 'A' and
            hdr.magic[2] == 'M' and hdr.magic[3] == 'R')
        {
            pass("T02: ZAM magic validation");
        } else {
            fail("T02: ZAM magic validation");
        }
    } else {
        fail("T02: ZAM magic validation (null)");
    }
}

fn t03_zam_version_check() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T03: ZAM version check (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.version == zam_header.ZAM_VERSION) {
            pass("T03: ZAM version check");
        } else {
            fail("T03: ZAM version check");
        }
    } else {
        fail("T03: ZAM version check (null)");
    }
}

fn t04_zam_hash_verification() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T04: ZAM hash verification (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        const elf_start = hdr.elf_offset;
        const elf_end = elf_start + hdr.elf_size;
        if (elf_end <= size) {
            if (hdr.verifyHash(buf[elf_start..elf_end])) {
                pass("T04: ZAM hash verification");
            } else {
                fail("T04: ZAM hash verification (mismatch)");
            }
        } else {
            fail("T04: ZAM hash verification (bounds)");
        }
    } else {
        fail("T04: ZAM hash verification (null)");
    }
}

fn t05_zam_signature_verification() void {
    // Generate keypair for signing
    signature.KeyPair.generate();

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, true);
    if (size == 0) {
        fail("T05: ZAM signature verification (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        const elf_start = hdr.elf_offset;
        const elf_end = elf_start + hdr.elf_size;
        if (elf_end <= size) {
            if (hdr.verifySignature(buf[elf_start..elf_end])) {
                pass("T05: ZAM signature verification");
            } else {
                fail("T05: ZAM signature verification (failed)");
            }
        } else {
            fail("T05: ZAM signature verification (bounds)");
        }
    } else {
        fail("T05: ZAM signature verification (null)");
    }
}

fn t06_zam_caps_extraction() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T06: ZAM caps extraction (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.required_caps == 0x0000000F) {
            pass("T06: ZAM caps extraction");
        } else {
            fail("T06: ZAM caps extraction (wrong value)");
        }
    } else {
        fail("T06: ZAM caps extraction (null)");
    }
}

fn t07_zam_trust_level_extraction() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T07: ZAM trust level (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.trust_level == zam_header.TRUST_USER) {
            pass("T07: ZAM trust level extraction");
        } else {
            fail("T07: ZAM trust level extraction (wrong)");
        }
    } else {
        fail("T07: ZAM trust level extraction (null)");
    }
}

fn t08_zam_reject_invalid_magic() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T08: ZAM reject invalid magic (build)");
        return;
    }

    // Corrupt magic
    buf[0] = 'X';

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.validate() == .BadMagic) {
            pass("T08: ZAM reject invalid magic");
        } else {
            fail("T08: ZAM reject invalid magic (wrong error)");
        }
    } else {
        fail("T08: ZAM reject invalid magic (null)");
    }
}

fn t09_zam_reject_corrupt_header() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T09: ZAM reject corrupt header (build)");
        return;
    }

    // Set bad version
    buf[4] = 0xFF;
    buf[5] = 0xFF;

    if (zam_header.parse(buf[0..size])) |hdr| {
        if (hdr.validate() != .None) {
            pass("T09: ZAM reject corrupt header");
        } else {
            fail("T09: ZAM reject corrupt header (accepted)");
        }
    } else {
        fail("T09: ZAM reject corrupt header (null)");
    }
}

fn t10_zam_reject_hash_mismatch() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T10: ZAM reject hash mismatch (build)");
        return;
    }

    if (zam_header.parse(buf[0..size])) |hdr| {
        // Corrupt ELF payload to cause hash mismatch
        const elf_start = hdr.elf_offset;
        buf[elf_start + 10] ^= 0xFF;

        const elf_end = elf_start + hdr.elf_size;
        if (elf_end <= size) {
            if (!hdr.verifyHash(buf[elf_start..elf_end])) {
                pass("T10: ZAM reject hash mismatch");
            } else {
                fail("T10: ZAM reject hash mismatch (accepted)");
            }
        } else {
            fail("T10: ZAM reject hash mismatch (bounds)");
        }
    } else {
        fail("T10: ZAM reject hash mismatch (null)");
    }
}

// ============================================================================
// ELF Parser Tests (T11-T22)
// ============================================================================

fn t11_elf_magic_validation() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    const size = buildMinimalElf(&buf);
    if (size == 0) {
        fail("T11: ELF magic validation (build)");
        return;
    }

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.hasValidMagic()) {
            pass("T11: ELF magic validation");
        } else {
            fail("T11: ELF magic validation (bad)");
        }
    } else {
        fail("T11: ELF magic validation (null)");
    }
}

fn t12_elf_class_64bit() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.is64Bit()) {
            pass("T12: ELF class 64-bit check");
        } else {
            fail("T12: ELF class 64-bit check");
        }
    } else {
        fail("T12: ELF class 64-bit check (null)");
    }
}

fn t13_elf_type_exec() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.isExecutable()) {
            pass("T13: ELF type EXEC check");
        } else {
            fail("T13: ELF type EXEC check");
        }
    } else {
        fail("T13: ELF type EXEC (null)");
    }
}

fn t14_elf_machine_x86_64() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.isX86_64()) {
            pass("T14: ELF machine x86_64 check");
        } else {
            fail("T14: ELF machine x86_64 check");
        }
    } else {
        fail("T14: ELF machine x86_64 (null)");
    }
}

fn t15_elf_entry_point() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.entry == 0x400000) {
            pass("T15: ELF entry point extraction");
        } else {
            fail("T15: ELF entry point extraction (wrong)");
        }
    } else {
        fail("T15: ELF entry point (null)");
    }
}

fn t16_elf_program_header_parse() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseElf(&buf)) |parsed| {
        if (parsed.phdr_count == 1) {
            pass("T16: ELF program header parse");
        } else {
            fail("T16: ELF program header parse (count)");
        }
    } else {
        fail("T16: ELF program header parse (null)");
    }
}

fn t17_elf_pt_load_segment() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseElf(&buf)) |parsed| {
        if (parsed.load_count == 1) {
            if (parsed.getLoadSegment(0)) |seg| {
                if (seg.vaddr == 0x400000 and seg.isLoad()) {
                    pass("T17: ELF PT_LOAD segment extraction");
                } else {
                    fail("T17: ELF PT_LOAD (wrong values)");
                }
            } else {
                fail("T17: ELF PT_LOAD (no segment)");
            }
        } else {
            fail("T17: ELF PT_LOAD (count)");
        }
    } else {
        fail("T17: ELF PT_LOAD (null)");
    }
}

fn t18_elf_segment_flags() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    if (elf_parser.parseElf(&buf)) |parsed| {
        if (parsed.getLoadSegment(0)) |seg| {
            if (seg.isReadable() and seg.isExecutable() and !seg.isWritable()) {
                pass("T18: ELF segment flags (RX)");
            } else {
                fail("T18: ELF segment flags (wrong)");
            }
        } else {
            fail("T18: ELF segment flags (no seg)");
        }
    } else {
        fail("T18: ELF segment flags (null)");
    }
}

fn t19_elf_reject_32bit() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    // Change class to 32-bit
    buf[4] = elf_parser.ELFCLASS32;

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.validate() == .Not64Bit) {
            pass("T19: ELF reject 32-bit");
        } else {
            fail("T19: ELF reject 32-bit (wrong error)");
        }
    } else {
        fail("T19: ELF reject 32-bit (null)");
    }
}

fn t20_elf_reject_bad_magic() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    buf[0] = 0x00;

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.validate() == .BadMagic) {
            pass("T20: ELF reject bad magic");
        } else {
            fail("T20: ELF reject bad magic (wrong error)");
        }
    } else {
        fail("T20: ELF reject bad magic (null)");
    }
}

fn t21_elf_reject_non_x86_64() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    // Change machine to ARM
    writeU16(&buf, 18, elf_parser.EM_ARM);

    if (elf_parser.parseHeader(&buf)) |hdr| {
        if (hdr.validate() == .NotX86_64) {
            pass("T21: ELF reject non-x86_64");
        } else {
            fail("T21: ELF reject non-x86_64 (wrong error)");
        }
    } else {
        fail("T21: ELF reject non-x86_64 (null)");
    }
}

fn t22_elf_reject_truncated() void {
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = buildMinimalElf(&buf);

    // Try parsing with only 30 bytes (too small for 64-byte header)
    if (elf_parser.parseHeader(buf[0..30])) |_| {
        fail("T22: ELF reject truncated (accepted)");
    } else {
        pass("T22: ELF reject truncated file");
    }
}

// ============================================================================
// Combined Tests (T23-T25)
// ============================================================================

fn t23_combined_zam_elf_parse() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T23: Combined ZAM+ELF parse (build)");
        return;
    }

    if (loader.parseZamFile(buf[0..size])) |parsed| {
        if (parsed.zam.hasValidMagic() and
            parsed.elf.header.hasValidMagic() and
            parsed.elf.load_count >= 1)
        {
            pass("T23: Combined ZAM+ELF parse");
        } else {
            fail("T23: Combined ZAM+ELF parse (bad fields)");
        }
    } else {
        fail("T23: Combined ZAM+ELF parse (null)");
    }
}

fn t24_full_validation_pipeline() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T24: Full validation pipeline (build)");
        return;
    }

    // Parse ZAM
    const zam = zam_header.parseAndValidate(buf[0..size]) orelse {
        fail("T24: Full validation pipeline (zam parse)");
        return;
    };

    // Get ELF payload
    const elf_data = zam_header.getElfPayload(buf[0..size]) orelse {
        fail("T24: Full validation pipeline (elf payload)");
        return;
    };

    // Validate hash
    if (!zam.verifyHash(elf_data)) {
        fail("T24: Full validation pipeline (hash)");
        return;
    }

    // Validate ELF
    const elf_err = elf_parser.validateFull(elf_data);
    if (elf_err != .None) {
        fail("T24: Full validation pipeline (elf validate)");
        return;
    }

    pass("T24: Full validation pipeline");
}

fn t25_integrity_verification() void {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, false);
    if (size == 0) {
        fail("T25: Integrity verification (build)");
        return;
    }

    // Verify integrity (should pass)
    if (!loader.verifyZamIntegrity(buf[0..size])) {
        fail("T25: Integrity verification (valid rejected)");
        return;
    }

    // Corrupt a byte in ELF payload
    buf[zam_header.ZAM_HEADER_SIZE + 5] ^= 0xFF;

    // Should now fail
    if (loader.verifyZamIntegrity(buf[0..size])) {
        fail("T25: Integrity verification (corrupt accepted)");
        return;
    }

    pass("T25: Integrity verification");
}

// ============================================================================
// Byte helpers for test data construction
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
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        buf[offset + i] = @intCast((val >> @intCast(i * 8)) & 0xFF);
    }
}

// ============================================================================
// Test Runner
// ============================================================================

pub fn runTests() void {
    serial.writeString("\n");
    serial.writeString("========================================\n");
    serial.writeString("  F5.0: ZAM Header & ELF64 Parser Tests\n");
    serial.writeString("========================================\n\n");

    tests_passed = 0;
    tests_failed = 0;

    // ZAM Header tests (T01-T10)
    serial.writeString("--- ZAM Header Tests ---\n");
    t01_zam_header_parse_valid();
    t02_zam_magic_validation();
    t03_zam_version_check();
    t04_zam_hash_verification();
    t05_zam_signature_verification();
    t06_zam_caps_extraction();
    t07_zam_trust_level_extraction();
    t08_zam_reject_invalid_magic();
    t09_zam_reject_corrupt_header();
    t10_zam_reject_hash_mismatch();

    // ELF Parser tests (T11-T22)
    serial.writeString("\n--- ELF Parser Tests ---\n");
    t11_elf_magic_validation();
    t12_elf_class_64bit();
    t13_elf_type_exec();
    t14_elf_machine_x86_64();
    t15_elf_entry_point();
    t16_elf_program_header_parse();
    t17_elf_pt_load_segment();
    t18_elf_segment_flags();
    t19_elf_reject_32bit();
    t20_elf_reject_bad_magic();
    t21_elf_reject_non_x86_64();
    t22_elf_reject_truncated();

    // Combined tests (T23-T25)
    serial.writeString("\n--- Combined Tests ---\n");
    t23_combined_zam_elf_parse();
    t24_full_validation_pipeline();
    t25_integrity_verification();

    // Summary
    serial.writeString("\n========================================\n");
    serial.writeString("  Results: ");
    printDec(tests_passed);
    serial.writeString(" passed, ");
    printDec(tests_failed);
    serial.writeString(" failed (of 25)\n");
    serial.writeString("========================================\n\n");
}

fn printDec(val: u32) void {
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
