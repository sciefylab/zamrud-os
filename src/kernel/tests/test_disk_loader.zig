//! Zamrud OS - F5.3 FAT32 Integration Tests
//! 20 tests for loading .zam/.elf from disk

const shell = @import("../shell/shell.zig");
const helpers = @import("../shell/commands/helpers.zig");

const fat32 = @import("../fs/fat32.zig");
const loader = @import("../loader/loader.zig");
const elf_exec = @import("../loader/elf_exec.zig");
const elf_parser = @import("../loader/elf_parser.zig");
const zam_header = @import("../loader/zam_header.zig");
const capability = @import("../security/capability.zig");
const pmm = @import("../mm/pmm.zig");

// ============================================================================
// Test runner
// ============================================================================

pub fn runTests() void {
    shell.println("========================================");
    shell.println("  F5.3: FAT32 Integration Tests");
    shell.println("========================================");

    var passed: u32 = 0;
    var failed: u32 = 0;

    shell.println("");
    shell.println("--- FAT32 Status Tests ---");
    passed += helpers.doTest("T01: FAT32 initialized", testFat32Init(), &failed);
    passed += helpers.doTest("T02: FAT32 mounted", testFat32Mounted(), &failed);

    shell.println("");
    shell.println("--- File Write Tests ---");
    passed += helpers.doTest("T03: Write .zam to disk", testWriteZam(), &failed);
    passed += helpers.doTest("T04: Write .elf to disk", testWriteElf(), &failed);
    passed += helpers.doTest("T05: Find .zam on disk", testFindZam(), &failed);
    passed += helpers.doTest("T06: Find .elf on disk", testFindElf(), &failed);

    shell.println("");
    shell.println("--- File Read Tests ---");
    passed += helpers.doTest("T07: Read .zam from disk", testReadZam(), &failed);
    passed += helpers.doTest("T08: Read .elf from disk", testReadElf(), &failed);
    passed += helpers.doTest("T09: Validate .zam size", testValidateZamSize(), &failed);
    passed += helpers.doTest("T10: Validate .elf size", testValidateElfSize(), &failed);

    shell.println("");
    shell.println("--- Parse Tests ---");
    passed += helpers.doTest("T11: Parse .zam from disk", testParseZamFromDisk(), &failed);
    passed += helpers.doTest("T12: Parse .elf from disk", testParseElfFromDisk(), &failed);
    passed += helpers.doTest("T13: ZAM integrity check", testZamIntegrity(), &failed);
    passed += helpers.doTest("T14: ELF validation", testElfValidation(), &failed);

    shell.println("");
    shell.println("--- Exec from Disk Tests ---");
    passed += helpers.doTest("T15: Exec .zam from disk", testExecZamFromDisk(), &failed);
    passed += helpers.doTest("T16: Exec .elf from disk", testExecElfFromDisk(), &failed);
    passed += helpers.doTest("T17: Exec cleanup frees", testExecCleanup(), &failed);

    shell.println("");
    shell.println("--- Error Handling Tests ---");
    passed += helpers.doTest("T18: Reject missing file", testRejectMissing(), &failed);
    passed += helpers.doTest("T19: Reject non-ELF file", testRejectNonElf(), &failed);
    passed += helpers.doTest("T20: Cleanup test files", testCleanupFiles(), &failed);

    helpers.printTestResults(passed, failed);
}

// ============================================================================
// T01-T02: FAT32 status
// ============================================================================

fn testFat32Init() bool {
    return fat32.isInitialized();
}

fn testFat32Mounted() bool {
    return fat32.isMounted();
}

// ============================================================================
// T03-T06: Write & find files on disk
// ============================================================================

fn testWriteZam() bool {
    if (!fat32.isMounted()) return false;

    // Remove if exists
    _ = fat32.deleteFile("TEST.ZAM");

    // Build test .zam
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf);
    if (size == 0) return false;

    return fat32.createFile("TEST.ZAM", buf[0..size]);
}

fn testWriteElf() bool {
    if (!fat32.isMounted()) return false;

    _ = fat32.deleteFile("TEST.ELF");

    var buf: [256]u8 = [_]u8{0} ** 256;
    const size = buildTestElf(&buf);
    if (size == 0) return false;

    return fat32.createFile("TEST.ELF", buf[0..size]);
}

fn testFindZam() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot("TEST.ZAM") != null;
}

fn testFindElf() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot("TEST.ELF") != null;
}

// ============================================================================
// T07-T10: Read & validate files
// ============================================================================

fn testReadZam() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ZAM") orelse return false;

    var buf: [512]u8 = [_]u8{0} ** 512;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    return bytes > 0 and bytes >= zam_header.ZAM_HEADER_SIZE;
}

fn testReadElf() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;

    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    return bytes > 0 and bytes >= elf_parser.ELF64_HEADER_SIZE;
}

fn testValidateZamSize() bool {
    if (!fat32.isMounted()) return false;
    const file_info = fat32.findInRoot("TEST.ZAM") orelse return false;
    return file_info.size > zam_header.ZAM_HEADER_SIZE and file_info.size < 65536;
}

fn testValidateElfSize() bool {
    if (!fat32.isMounted()) return false;
    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;
    return file_info.size >= elf_parser.ELF64_HEADER_SIZE and file_info.size < 65536;
}

// ============================================================================
// T11-T14: Parse from disk
// ============================================================================

fn testParseZamFromDisk() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ZAM") orelse return false;

    var buf: [512]u8 = [_]u8{0} ** 512;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    return loader.parseZamFile(buf[0..bytes]) != null;
}

fn testParseElfFromDisk() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;

    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    return elf_parser.parseElf(buf[0..bytes]) != null;
}

fn testZamIntegrity() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ZAM") orelse return false;

    var buf: [512]u8 = [_]u8{0} ** 512;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    return loader.verifyZamIntegrity(buf[0..bytes]);
}

fn testElfValidation() bool {
    if (!fat32.isMounted()) return false;

    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;

    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    return elf_parser.validateFull(buf[0..bytes]) == .None;
}

// ============================================================================
// T15-T17: Execute from disk
// ============================================================================

fn testExecZamFromDisk() bool {
    if (!fat32.isMounted()) return false;
    if (!elf_exec.isInitialized()) return false;

    const file_info = fat32.findInRoot("TEST.ZAM") orelse return false;

    var buf: [512]u8 = [_]u8{0} ** 512;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    const result = elf_exec.execZam(buf[0..bytes], "TEST.ZAM");
    if (result.err != .None) return false;

    const ok = result.pid > 0 and result.entry_point == 0x400000;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testExecElfFromDisk() bool {
    if (!fat32.isMounted()) return false;
    if (!elf_exec.isInitialized()) return false;

    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;

    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    const result = elf_exec.execRawElf(buf[0..bytes], "TEST.ELF", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    const ok = result.pid > 0;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testExecCleanup() bool {
    if (!fat32.isMounted()) return false;
    if (!elf_exec.isInitialized()) return false;

    const free_before = pmm.getFreePages();

    const file_info = fat32.findInRoot("TEST.ELF") orelse return false;

    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);
    if (bytes == 0) return false;

    const result = elf_exec.execRawElf(buf[0..bytes], "CLEANUP", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    _ = elf_exec.cleanupProcess(result.pid);

    const free_after = pmm.getFreePages();
    return free_after >= free_before - 1;
}

// ============================================================================
// T18-T20: Error handling & cleanup
// ============================================================================

fn testRejectMissing() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot("NOEXIST.ZAM") == null;
}

fn testRejectNonElf() bool {
    if (!fat32.isMounted()) return false;

    // Write a non-ELF file
    _ = fat32.deleteFile("NOTELF.BIN");
    const garbage = "This is not an ELF file!";
    if (!fat32.createFile("NOTELF.BIN", garbage)) return false;

    // Try to parse as ELF — should fail
    const file_info = fat32.findInRoot("NOTELF.BIN") orelse return false;
    var buf: [256]u8 = [_]u8{0} ** 256;
    const read_size = @min(@as(usize, file_info.size), buf.len);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    const is_elf = (bytes >= 4 and buf[0] == 0x7F and buf[1] == 'E' and buf[2] == 'L' and buf[3] == 'F');

    _ = fat32.deleteFile("NOTELF.BIN");
    return !is_elf;
}

fn testCleanupFiles() bool {
    if (!fat32.isMounted()) return false;

    _ = fat32.deleteFile("TEST.ZAM");
    _ = fat32.deleteFile("TEST.ELF");

    // Verify deleted
    return fat32.findInRoot("TEST.ZAM") == null and
        fat32.findInRoot("TEST.ELF") == null;
}

// ============================================================================
// Build test binaries
// ============================================================================

fn buildTestZam(buf: []u8) usize {
    if (buf.len < 400) return 0;

    var elf_buf: [256]u8 = [_]u8{0} ** 256;
    const elf_size = buildTestElf(&elf_buf);
    if (elf_size == 0) return 0;

    const hdr_size = zam_header.buildHeader(
        buf,
        elf_buf[0..elf_size],
        capability.CAP_USER_DEFAULT,
        zam_header.TRUST_USER,
        64,
        0,
    );
    if (hdr_size == 0) return 0;

    var i: usize = 0;
    while (i < elf_size) : (i += 1) {
        buf[hdr_size + i] = elf_buf[i];
    }
    return hdr_size + elf_size;
}

fn buildTestElf(buf: []u8) usize {
    if (buf.len < 184) return 0;

    var i: usize = 0;
    while (i < 184) : (i += 1) {
        buf[i] = 0;
    }

    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = elf_parser.ELFCLASS64;
    buf[5] = elf_parser.ELFDATA2LSB;
    buf[6] = 1;

    writeU16(buf, 16, elf_parser.ET_EXEC);
    writeU16(buf, 18, elf_parser.EM_X86_64);
    writeU32(buf, 20, 1);
    writeU64(buf, 24, 0x400000);
    writeU64(buf, 32, 64);
    writeU16(buf, 52, 64);
    writeU16(buf, 54, 56);
    writeU16(buf, 56, 1);
    writeU16(buf, 58, 64);

    writeU32(buf, 64, elf_parser.PT_LOAD);
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X);
    writeU64(buf, 72, 0);
    writeU64(buf, 80, 0x400000);
    writeU64(buf, 88, 0x400000);
    writeU64(buf, 96, 64);
    writeU64(buf, 104, 64);
    writeU64(buf, 112, 0x1000);

    buf[120] = 0xB8;
    buf[121] = 0x3C;
    buf[122] = 0x00;
    buf[123] = 0x00;
    buf[124] = 0x00;
    buf[125] = 0x0F;
    buf[126] = 0x05;

    return 184;
}

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
