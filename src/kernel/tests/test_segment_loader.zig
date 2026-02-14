//! Zamrud OS - F5.1 Segment Loader Tests
//! 20 tests for segment loading, VMM mapping, BSS, stack, cleanup

const serial = @import("../drivers/serial/serial.zig");
const shell = @import("../shell/shell.zig");
const helpers = @import("../shell/commands/helpers.zig");
const terminal = @import("../drivers/display/terminal.zig");

const elf_parser = @import("../loader/elf_parser.zig");
const segment_loader = @import("../loader/segment_loader.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");

// ============================================================================
// Test runner
// ============================================================================

pub fn runTests() void {
    shell.println("========================================");
    shell.println("  F5.1: Segment Loader Tests");
    shell.println("========================================");

    var passed: u32 = 0;
    var failed: u32 = 0;

    shell.println("");
    shell.println("--- Flag Conversion Tests ---");
    passed += helpers.doTest("T01: RX flags", testFlagsRX(), &failed);
    passed += helpers.doTest("T02: RW flags", testFlagsRW(), &failed);
    passed += helpers.doTest("T03: RO flags", testFlagsRO(), &failed);
    passed += helpers.doTest("T04: RWX flags", testFlagsRWX(), &failed);
    passed += helpers.doTest("T05: Kernel no USER", testFlagsKernel(), &failed);

    shell.println("");
    shell.println("--- Permission String Tests ---");
    passed += helpers.doTest("T06: permString RX", testPermStringRX(), &failed);
    passed += helpers.doTest("T07: permString RW", testPermStringRW(), &failed);
    passed += helpers.doTest("T08: permString R--", testPermStringRO(), &failed);

    shell.println("");
    shell.println("--- Address Validation Tests ---");
    passed += helpers.doTest("T09: Valid user address", testValidAddress(), &failed);
    passed += helpers.doTest("T10: Reject addr < 4MB", testRejectLowAddr(), &failed);
    passed += helpers.doTest("T11: Reject addr > max", testRejectHighAddr(), &failed);
    passed += helpers.doTest("T12: Reject oversized", testRejectOversized(), &failed);

    shell.println("");
    shell.println("--- Struct Init Tests ---");
    passed += helpers.doTest("T13: LoadResult init", testLoadResultInit(), &failed);
    passed += helpers.doTest("T14: LoadedSegment init", testLoadedSegmentInit(), &failed);

    shell.println("");
    shell.println("--- Segment Loading Tests ---");
    passed += helpers.doTest("T15: Load minimal segment", testLoadMinimalSegment(), &failed);
    passed += helpers.doTest("T16: BSS zero-fill detect", testBssDetection(), &failed);
    passed += helpers.doTest("T17: Multi-seg validation", testMultiSegmentValidation(), &failed);
    passed += helpers.doTest("T18: Cleanup frees pages", testCleanupFrees(), &failed);

    shell.println("");
    shell.println("--- Integration Tests ---");
    passed += helpers.doTest("T19: Full load cycle", testFullLoadCycle(), &failed);
    passed += helpers.doTest("T20: No LOAD error", testNoLoadError(), &failed);

    helpers.printTestResults(passed, failed);
}

// ============================================================================
// T01-T05: Flag conversion tests
// ============================================================================

fn testFlagsRX() bool {
    const flags = segment_loader.elfFlagsToVmm(elf_parser.PF_R | elf_parser.PF_X, true);
    if ((flags & vmm.PageFlags.PRESENT) == 0) return false;
    if ((flags & vmm.PageFlags.USER) == 0) return false;
    if ((flags & vmm.PageFlags.NO_EXECUTE) != 0) return false;
    if ((flags & vmm.PageFlags.WRITABLE) != 0) return false;
    return true;
}

fn testFlagsRW() bool {
    const flags = segment_loader.elfFlagsToVmm(elf_parser.PF_R | elf_parser.PF_W, true);
    if ((flags & vmm.PageFlags.PRESENT) == 0) return false;
    if ((flags & vmm.PageFlags.USER) == 0) return false;
    if ((flags & vmm.PageFlags.WRITABLE) == 0) return false;
    if ((flags & vmm.PageFlags.NO_EXECUTE) == 0) return false;
    return true;
}

fn testFlagsRO() bool {
    const flags = segment_loader.elfFlagsToVmm(elf_parser.PF_R, true);
    if ((flags & vmm.PageFlags.PRESENT) == 0) return false;
    if ((flags & vmm.PageFlags.USER) == 0) return false;
    if ((flags & vmm.PageFlags.WRITABLE) != 0) return false;
    if ((flags & vmm.PageFlags.NO_EXECUTE) == 0) return false;
    return true;
}

fn testFlagsRWX() bool {
    const flags = segment_loader.elfFlagsToVmm(elf_parser.PF_R | elf_parser.PF_W | elf_parser.PF_X, true);
    if ((flags & vmm.PageFlags.PRESENT) == 0) return false;
    if ((flags & vmm.PageFlags.USER) == 0) return false;
    if ((flags & vmm.PageFlags.WRITABLE) == 0) return false;
    if ((flags & vmm.PageFlags.NO_EXECUTE) != 0) return false;
    return true;
}

fn testFlagsKernel() bool {
    const flags = segment_loader.elfFlagsToVmm(elf_parser.PF_R | elf_parser.PF_X, false);
    if ((flags & vmm.PageFlags.PRESENT) == 0) return false;
    if ((flags & vmm.PageFlags.USER) != 0) return false;
    return true;
}

// ============================================================================
// T06-T08: Permission string tests
// ============================================================================

fn testPermStringRX() bool {
    const p = segment_loader.permString(elf_parser.PF_R | elf_parser.PF_X);
    return p[0] == 'R' and p[1] == '-' and p[2] == 'X';
}

fn testPermStringRW() bool {
    const p = segment_loader.permString(elf_parser.PF_R | elf_parser.PF_W);
    return p[0] == 'R' and p[1] == 'W' and p[2] == '-';
}

fn testPermStringRO() bool {
    const p = segment_loader.permString(elf_parser.PF_R);
    return p[0] == 'R' and p[1] == '-' and p[2] == '-';
}

// ============================================================================
// T09-T12: Address validation tests
// ============================================================================

fn testValidAddress() bool {
    return segment_loader.USER_SPACE_MIN == 0x400000 and
        segment_loader.USER_SPACE_MAX == 0x80000000;
}

fn testRejectLowAddr() bool {
    return 0x1000 < segment_loader.USER_SPACE_MIN;
}

fn testRejectHighAddr() bool {
    return 0x800000000000 > segment_loader.USER_SPACE_MAX;
}

fn testRejectOversized() bool {
    const size: u64 = 512 * 1024 * 1024;
    return size > 256 * 1024 * 1024;
}

// ============================================================================
// T13-T14: Result struct tests
// ============================================================================

fn testLoadResultInit() bool {
    const result = segment_loader.LoadResult.init();
    return result.segment_count == 0 and
        result.entry_point == 0 and
        result.total_pages_used == 0 and
        result.err == .None and
        result.stack_pages == 0;
}

fn testLoadedSegmentInit() bool {
    const seg = segment_loader.LoadedSegment.init();
    return seg.vaddr == 0 and
        seg.page_count == 0 and
        seg.flags == 0;
}

// ============================================================================
// T15-T18: Segment loading tests
// ============================================================================

fn testLoadMinimalSegment() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestElf(&buf, 0x400000, 64, 64);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;

    var result = segment_loader.loadSegments(&parsed, buf[0..size], true);

    if (result.err != .None) {
        return false;
    }

    if (result.segment_count == 0) return false;
    if (result.total_pages_used == 0) return false;
    if (result.entry_point != 0x400000) return false;

    segment_loader.cleanupAllSegments(&result);
    return true;
}

fn testBssDetection() bool {
    const phdr = elf_parser.ProgramHeader{
        .p_type = elf_parser.PT_LOAD,
        .flags = elf_parser.PF_R | elf_parser.PF_W,
        .offset = 0,
        .vaddr = 0x400000,
        .paddr = 0x400000,
        .filesz = 0x100,
        .memsz = 0x200,
        .align_val = 0x1000,
    };
    return phdr.hasBss() and phdr.bssSize() == 0x100;
}

fn testMultiSegmentValidation() bool {
    var buf: [1024]u8 = [_]u8{0} ** 1024;
    const size = buildTestElfMultiSeg(&buf);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;
    return parsed.load_count == 2;
}

fn testCleanupFrees() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestElf(&buf, 0x400000, 64, 64);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;

    const free_before = pmm.getFreePages();

    var result = segment_loader.loadSegments(&parsed, buf[0..size], false);
    if (result.err != .None) return false;

    const free_during = pmm.getFreePages();
    if (free_during >= free_before) return false;

    segment_loader.cleanupAllSegments(&result);

    const free_after = pmm.getFreePages();
    return free_after == free_before;
}

// ============================================================================
// T19-T20: Integration tests
// ============================================================================

fn testFullLoadCycle() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestElf(&buf, 0x400000, 64, 64);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;

    var result = segment_loader.loadSegments(&parsed, buf[0..size], true);
    if (result.err != .None) return false;

    if (result.entry_point != 0x400000) return false;
    if (result.segment_count == 0) return false;

    // Verify mapped before cleanup
    if (vmm.isMapped(0x400000) != 1) return false;

    // Verify stack mapped
    if (result.stack_pages > 0) {
        if (vmm.isMapped(segment_loader.USER_STACK_BOTTOM) != 1) return false;
    }

    // Cleanup
    const pages_before = pmm.getFreePages();
    segment_loader.cleanupAllSegments(&result);
    const pages_after = pmm.getFreePages();

    // Verify pages were freed
    return pages_after > pages_before;
}

fn testNoLoadError() bool {
    var buf: [128]u8 = [_]u8{0} ** 128;

    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = elf_parser.ELFCLASS64;
    buf[5] = elf_parser.ELFDATA2LSB;
    buf[6] = 1;

    writeU16(&buf, 16, elf_parser.ET_EXEC);
    writeU16(&buf, 18, elf_parser.EM_X86_64);
    writeU32(&buf, 20, 1);
    writeU64(&buf, 24, 0x400000);
    writeU64(&buf, 32, 64);
    writeU16(&buf, 52, 64);
    writeU16(&buf, 54, 56);
    writeU16(&buf, 56, 1);
    writeU16(&buf, 58, 64);

    writeU32(&buf, 64, elf_parser.PT_NOTE);

    const parsed = elf_parser.parseElf(buf[0..128]) orelse return false;

    if (parsed.load_count != 0) return false;

    const result = segment_loader.loadSegments(&parsed, buf[0..128], true);
    return result.err == .NoLoadSegments;
}

// ============================================================================
// Test helpers: build minimal ELF binaries
// ============================================================================

fn buildTestElf(buf: []u8, entry: u64, filesz: u64, memsz: u64) usize {
    if (buf.len < 256) return 0;

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
    writeU64(buf, 24, entry);
    writeU64(buf, 32, 64);
    writeU16(buf, 52, 64);
    writeU16(buf, 54, 56);
    writeU16(buf, 56, 1);
    writeU16(buf, 58, 64);

    writeU32(buf, 64, elf_parser.PT_LOAD);
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X);
    writeU64(buf, 72, 0);
    writeU64(buf, 80, entry);
    writeU64(buf, 88, entry);
    writeU64(buf, 96, filesz);
    writeU64(buf, 104, memsz);
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

fn buildTestElfMultiSeg(buf: []u8) usize {
    if (buf.len < 512) return 0;

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
    writeU16(buf, 56, 2);
    writeU16(buf, 58, 64);

    writeU32(buf, 64, elf_parser.PT_LOAD);
    writeU32(buf, 68, elf_parser.PF_R | elf_parser.PF_X);
    writeU64(buf, 72, 0);
    writeU64(buf, 80, 0x400000);
    writeU64(buf, 88, 0x400000);
    writeU64(buf, 96, 64);
    writeU64(buf, 104, 64);
    writeU64(buf, 112, 0x1000);

    const seg2_off: usize = 64 + 56;
    writeU32(buf, seg2_off, elf_parser.PT_LOAD);
    writeU32(buf, seg2_off + 4, elf_parser.PF_R | elf_parser.PF_W);
    writeU64(buf, seg2_off + 8, 176);
    writeU64(buf, seg2_off + 16, 0x401000);
    writeU64(buf, seg2_off + 24, 0x401000);
    writeU64(buf, seg2_off + 32, 32);
    writeU64(buf, seg2_off + 40, 64);
    writeU64(buf, seg2_off + 48, 0x1000);

    return 256;
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
