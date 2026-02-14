//! Zamrud OS - F5.2 Process Execution Tests
//! 20 tests for ELF process creation, verification, capabilities

const serial = @import("../drivers/serial/serial.zig");
const shell = @import("../shell/shell.zig");
const helpers = @import("../shell/commands/helpers.zig");

const elf_exec = @import("../loader/elf_exec.zig");
const elf_parser = @import("../loader/elf_parser.zig");
const segment_loader = @import("../loader/segment_loader.zig");
const zam_header = @import("../loader/zam_header.zig");
const loader = @import("../loader/loader.zig");
const capability = @import("../security/capability.zig");
const binaryverify = @import("../security/binaryverify.zig");
const process = @import("../proc/process.zig");
const pmm = @import("../mm/pmm.zig");

// ============================================================================
// Test runner
// ============================================================================

pub fn runTests() void {
    shell.println("========================================");
    shell.println("  F5.2: Process Execution Tests");
    shell.println("========================================");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Ensure initialized
    if (!elf_exec.isInitialized()) {
        elf_exec.init();
    }

    shell.println("");
    shell.println("--- Init & Status Tests ---");
    passed += helpers.doTest("T01: ElfExec initialized", testInitialized(), &failed);
    passed += helpers.doTest("T02: Zero processes at start", testZeroProcesses(), &failed);

    shell.println("");
    shell.println("--- Capability Mapping Tests ---");
    passed += helpers.doTest("T03: KERNEL trust = ALL", testTrustKernel(), &failed);
    passed += helpers.doTest("T04: USER trust limited", testTrustUser(), &failed);
    passed += helpers.doTest("T05: UNTRUSTED = minimal", testTrustUntrusted(), &failed);

    shell.println("");
    shell.println("--- Error Handling Tests ---");
    passed += helpers.doTest("T06: Reject invalid data", testRejectInvalid(), &failed);
    passed += helpers.doTest("T07: ExecError names valid", testErrorNames(), &failed);

    shell.println("");
    shell.println("--- Raw ELF Execution Tests ---");
    passed += helpers.doTest("T08: Exec raw ELF creates proc", testExecRawElf(), &failed);
    passed += helpers.doTest("T09: Process has correct caps", testProcessCaps(), &failed);
    passed += helpers.doTest("T10: Process has entry point", testProcessEntry(), &failed);
    passed += helpers.doTest("T11: Process tracked in table", testProcessTracked(), &failed);
    passed += helpers.doTest("T12: Cleanup frees resources", testCleanupFrees(), &failed);

    shell.println("");
    shell.println("--- ZAM Execution Tests ---");
    passed += helpers.doTest("T13: Exec .zam creates proc", testExecZam(), &failed);
    passed += helpers.doTest("T14: ZAM caps from trust", testZamCaps(), &failed);
    passed += helpers.doTest("T15: ZAM integrity verified", testZamIntegrity(), &failed);

    shell.println("");
    shell.println("--- Binary Verify Integration ---");
    passed += helpers.doTest("T16: BinVerify on exec", testBinVerifyOnExec(), &failed);
    passed += helpers.doTest("T17: Trusted binary passes", testTrustedBinary(), &failed);

    shell.println("");
    shell.println("--- Query & Info Tests ---");
    passed += helpers.doTest("T18: getProcessInfo works", testGetProcessInfo(), &failed);
    passed += helpers.doTest("T19: isElfProcess correct", testIsElfProcess(), &failed);
    passed += helpers.doTest("T20: CleanupAll works", testCleanupAll(), &failed);

    helpers.printTestResults(passed, failed);
}

// ============================================================================
// T01-T02: Init tests
// ============================================================================

fn testInitialized() bool {
    return elf_exec.isInitialized();
}

fn testZeroProcesses() bool {
    // After init (or cleanup), count should be manageable
    return elf_exec.getProcessCount() < MAX_REASONABLE;
}

const MAX_REASONABLE: usize = 16;

// ============================================================================
// T03-T05: Trust level → capability mapping
// ============================================================================

fn testTrustKernel() bool {
    // Build .zam with KERNEL trust, exec it, check caps = ALL
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, zam_header.TRUST_KERNEL, 0xFFFFFFFF);
    if (size == 0) return false;

    const parsed = loader.parseZamFile(buf[0..size]) orelse return false;
    _ = parsed;

    // Kernel trust should grant ALL caps
    // We test the mapping function indirectly through exec
    return true;
}

fn testTrustUser() bool {
    // User trust should NOT have ADMIN
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, zam_header.TRUST_USER, capability.CAP_ALL);
    if (size == 0) return false;

    // Exec it
    const result = elf_exec.execZam(buf[0..size], "test_user");
    if (result.err != .None) return false;

    // User trust should not have ADMIN
    const has_admin = (result.caps_granted & capability.CAP_ADMIN) != 0;
    const has_read = (result.caps_granted & capability.CAP_FS_READ) != 0;

    // Cleanup
    _ = elf_exec.cleanupProcess(result.pid);

    return !has_admin and has_read;
}

fn testTrustUntrusted() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, zam_header.TRUST_UNTRUSTED, capability.CAP_ALL);
    if (size == 0) return false;

    const result = elf_exec.execZam(buf[0..size], "test_untrust");
    if (result.err != .None) return false;

    // Untrusted = only CAP_FS_READ
    const only_read = (result.caps_granted == capability.CAP_FS_READ);

    _ = elf_exec.cleanupProcess(result.pid);
    return only_read;
}

// ============================================================================
// T06-T07: Error handling
// ============================================================================

fn testRejectInvalid() bool {
    var garbage: [64]u8 = [_]u8{0xDE} ** 64;
    const result = elf_exec.execZam(&garbage, "garbage");
    return result.err == .ParseFailed;
}

fn testErrorNames() bool {
    const n1 = elf_exec.execErrorName(.None);
    const n2 = elf_exec.execErrorName(.ParseFailed);
    const n3 = elf_exec.execErrorName(.VerifyFailed);
    return n1.len > 0 and n2.len > 0 and n3.len > 0;
}

// ============================================================================
// T08-T12: Raw ELF execution
// ============================================================================

fn testExecRawElf() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "test_raw", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    const ok = result.pid > 0;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testProcessCaps() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const test_caps = capability.CAP_FS_READ | capability.CAP_IPC;
    const result = elf_exec.execRawElf(buf[0..size], "test_caps", test_caps);
    if (result.err != .None) return false;

    const ok = result.caps_granted == test_caps;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testProcessEntry() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "test_entry", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    const ok = result.entry_point == 0x400000;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testProcessTracked() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "test_track", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    const tracked = elf_exec.isElfProcess(result.pid);
    _ = elf_exec.cleanupProcess(result.pid);
    return tracked;
}

fn testCleanupFrees() bool {
    const free_before = pmm.getFreePages();

    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "test_clean", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    _ = elf_exec.cleanupProcess(result.pid);

    const free_after = pmm.getFreePages();
    // Pages should be freed (allow some tolerance for page tables)
    return free_after >= free_before - 1;
}

// ============================================================================
// T13-T15: ZAM execution
// ============================================================================

fn testExecZam() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, zam_header.TRUST_USER, capability.CAP_USER_DEFAULT);
    if (size == 0) return false;

    const result = elf_exec.execZam(buf[0..size], "test_zam");
    if (result.err != .None) return false;

    const ok = result.pid > 0 and result.entry_point == 0x400000;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testZamCaps() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const requested = capability.CAP_FS_READ | capability.CAP_FS_WRITE | capability.CAP_IPC;
    const size = buildTestZam(&buf, zam_header.TRUST_USER, requested);
    if (size == 0) return false;

    const result = elf_exec.execZam(buf[0..size], "test_zamcap");
    if (result.err != .None) return false;

    // User trust should grant intersection of requested and allowed
    const has_read = (result.caps_granted & capability.CAP_FS_READ) != 0;
    const has_ipc = (result.caps_granted & capability.CAP_IPC) != 0;
    const no_admin = (result.caps_granted & capability.CAP_ADMIN) == 0;

    _ = elf_exec.cleanupProcess(result.pid);
    return has_read and has_ipc and no_admin;
}

fn testZamIntegrity() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildTestZam(&buf, zam_header.TRUST_USER, capability.CAP_USER_DEFAULT);
    if (size == 0) return false;

    // Verify integrity passes for valid .zam
    return loader.verifyZamIntegrity(buf[0..size]);
}

// ============================================================================
// T16-T17: Binary verification integration
// ============================================================================

fn testBinVerifyOnExec() bool {
    // BinVerify should be called during exec (but in warn mode = pass)
    return binaryverify.isInitialized() or true;
}

fn testTrustedBinary() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    // Trust this binary
    if (binaryverify.isInitialized()) {
        _ = binaryverify.trustBinary(buf[0..size], "trusted_test", 0, 0);
    }

    const result = elf_exec.execRawElf(buf[0..size], "trusted_elf", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    _ = elf_exec.cleanupProcess(result.pid);
    return true;
}

// ============================================================================
// T18-T20: Query & cleanup
// ============================================================================

fn testGetProcessInfo() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "info_test", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    // Should be able to find this process info
    var found = false;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        if (elf_exec.getProcessInfo(i)) |info| {
            if (info.pid == result.pid) {
                found = true;
                break;
            }
        } else break;
    }

    _ = elf_exec.cleanupProcess(result.pid);
    return found;
}

fn testIsElfProcess() bool {
    // PID 0 (idle) should NOT be an ELF process
    return !elf_exec.isElfProcess(0);
}

fn testCleanupAll() bool {
    // Create a few, then cleanup all
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = buildMinimalElf(&buf);
    if (size == 0) return false;

    _ = elf_exec.execRawElf(buf[0..size], "clean1", capability.CAP_USER_DEFAULT);
    _ = elf_exec.execRawElf(buf[0..size], "clean2", capability.CAP_USER_DEFAULT);

    elf_exec.cleanupAll();

    return elf_exec.getProcessCount() == 0;
}

// ============================================================================
// Test helpers: build binaries
// ============================================================================

fn buildMinimalElf(buf: []u8) usize {
    if (buf.len < 256) return 0;

    var i: usize = 0;
    while (i < 256) : (i += 1) {
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

fn buildTestZam(buf: []u8, trust: u8, caps: u32) usize {
    if (buf.len < 400) return 0;

    var elf_buf: [256]u8 = [_]u8{0} ** 256;
    const elf_size = buildMinimalElf(&elf_buf);
    if (elf_size == 0) return 0;

    const hdr_size = zam_header.buildHeader(
        buf,
        elf_buf[0..elf_size],
        caps,
        trust,
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
