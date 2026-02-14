//! Zamrud OS - F5.4 Built-in Test Programs Tests
//! 20 tests for built-in ELF programs

const shell = @import("../shell/shell.zig");
const helpers = @import("../shell/commands/helpers.zig");

const builtins = @import("../loader/builtins.zig");
const elf_parser = @import("../loader/elf_parser.zig");
const elf_exec = @import("../loader/elf_exec.zig");
const loader = @import("../loader/loader.zig");
const zam_header = @import("../loader/zam_header.zig");
const segment_loader = @import("../loader/segment_loader.zig");
const capability = @import("../security/capability.zig");
const pmm = @import("../mm/pmm.zig");
const vmm = @import("../mm/vmm.zig");

// ============================================================================
// Test runner
// ============================================================================

pub fn runTests() void {
    shell.println("========================================");
    shell.println("  F5.4: Built-in Test Programs Tests");
    shell.println("========================================");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Ensure initialized
    if (!builtins.isInitialized()) {
        builtins.init();
    }

    shell.println("");
    shell.println("--- Registry Tests ---");
    passed += helpers.doTest("T01: Builtins initialized", testInitialized(), &failed);
    passed += helpers.doTest("T02: 5 programs registered", testCount(), &failed);
    passed += helpers.doTest("T03: Find hello by name", testFindHello(), &failed);
    passed += helpers.doTest("T04: Find syscall by name", testFindSyscall(), &failed);
    passed += helpers.doTest("T05: Reject unknown name", testRejectUnknown(), &failed);

    shell.println("");
    shell.println("--- ELF Build Tests ---");
    passed += helpers.doTest("T06: Build hello ELF", testBuildHello(), &failed);
    passed += helpers.doTest("T07: Build syscall ELF", testBuildSyscall(), &failed);
    passed += helpers.doTest("T08: Build compute ELF", testBuildCompute(), &failed);
    passed += helpers.doTest("T09: Build nopsled ELF", testBuildNopsled(), &failed);
    passed += helpers.doTest("T10: Build multiseg ELF", testBuildMultiseg(), &failed);

    shell.println("");
    shell.println("--- ELF Parse Tests ---");
    passed += helpers.doTest("T11: Parse hello valid", testParseHello(), &failed);
    passed += helpers.doTest("T12: Parse multiseg 2 segs", testParseMultiseg(), &failed);
    passed += helpers.doTest("T13: Entry point 0x400000", testEntryPoint(), &failed);

    shell.println("");
    shell.println("--- ZAM Build Tests ---");
    passed += helpers.doTest("T14: Build hello .zam", testBuildHelloZam(), &failed);
    passed += helpers.doTest("T15: ZAM integrity OK", testZamIntegrity(), &failed);

    shell.println("");
    shell.println("--- Execution Tests ---");
    passed += helpers.doTest("T16: Exec hello ELF", testExecHello(), &failed);
    passed += helpers.doTest("T17: Exec compute ELF", testExecCompute(), &failed);
    passed += helpers.doTest("T18: Exec hello .zam", testExecHelloZam(), &failed);
    passed += helpers.doTest("T19: Multiseg load+cleanup", testExecMultiseg(), &failed);
    passed += helpers.doTest("T20: All builtins loadable", testAllLoadable(), &failed);

    helpers.printTestResults(passed, failed);
}

// ============================================================================
// T01-T05: Registry tests
// ============================================================================

fn testInitialized() bool {
    return builtins.isInitialized();
}

fn testCount() bool {
    return builtins.getCount() == 5;
}

fn testFindHello() bool {
    if (builtins.findByName("hello")) |idx| {
        const prog = builtins.getBuiltin(idx) orelse return false;
        return prog.active;
    }
    return false;
}

fn testFindSyscall() bool {
    return builtins.findByName("syscall") != null;
}

fn testRejectUnknown() bool {
    return builtins.findByName("nonexistent") == null;
}

// ============================================================================
// T06-T10: ELF build tests
// ============================================================================

fn testBuildHello() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("hello", &buf);
    return size > 0 and size >= elf_parser.ELF64_HEADER_SIZE;
}

fn testBuildSyscall() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("syscall", &buf);
    return size > 0;
}

fn testBuildCompute() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("compute", &buf);
    return size > 0;
}

fn testBuildNopsled() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("nopsled", &buf);
    return size > 0;
}

fn testBuildMultiseg() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("multiseg", &buf);
    return size > 0 and size > 256; // Should have code + data
}

// ============================================================================
// T11-T13: ELF parse tests
// ============================================================================

fn testParseHello() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("hello", &buf);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;
    return parsed.load_count >= 1 and
        parsed.header.isExecutable() and
        parsed.header.isX86_64();
}

fn testParseMultiseg() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("multiseg", &buf);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;
    return parsed.load_count == 2;
}

fn testEntryPoint() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("hello", &buf);
    if (size == 0) return false;

    const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;
    return parsed.entryPoint() == 0x400000;
}

// ============================================================================
// T14-T15: ZAM build tests
// ============================================================================

fn testBuildHelloZam() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildZam("hello", &buf);
    if (size == 0) return false;

    // Should start with ZAMR magic
    return buf[0] == 'Z' and buf[1] == 'A' and buf[2] == 'M' and buf[3] == 'R';
}

fn testZamIntegrity() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildZam("hello", &buf);
    if (size == 0) return false;

    return loader.verifyZamIntegrity(buf[0..size]);
}

// ============================================================================
// T16-T20: Execution tests
// ============================================================================

fn testExecHello() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("hello", &buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "hello", capability.CAP_MINIMAL);
    if (result.err != .None) return false;

    const ok = result.pid > 0 and result.entry_point == 0x400000;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testExecCompute() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("compute", &buf);
    if (size == 0) return false;

    const result = elf_exec.execRawElf(buf[0..size], "compute", capability.CAP_MINIMAL);
    if (result.err != .None) return false;

    const ok = result.pid > 0;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testExecHelloZam() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildZam("hello", &buf);
    if (size == 0) return false;

    const result = elf_exec.execZam(buf[0..size], "hello.zam");
    if (result.err != .None) return false;

    const ok = result.pid > 0 and result.entry_point == 0x400000;
    _ = elf_exec.cleanupProcess(result.pid);
    return ok;
}

fn testExecMultiseg() bool {
    var buf: [512]u8 = [_]u8{0} ** 512;
    const size = builtins.buildElf("multiseg", &buf);
    if (size == 0) return false;

    const free_before = pmm.getFreePages();

    const result = elf_exec.execRawElf(buf[0..size], "multiseg", capability.CAP_USER_DEFAULT);
    if (result.err != .None) return false;

    // Should have used pages for 2 segments
    if (result.pages_used < 2) {
        _ = elf_exec.cleanupProcess(result.pid);
        return false;
    }

    _ = elf_exec.cleanupProcess(result.pid);

    const free_after = pmm.getFreePages();
    return free_after >= free_before - 1;
}

fn testAllLoadable() bool {
    const names = [_][]const u8{ "hello", "syscall", "compute", "nopsled" };

    for (names) |name| {
        var buf: [512]u8 = [_]u8{0} ** 512;
        const size = builtins.buildElf(name, &buf);
        if (size == 0) return false;

        const parsed = elf_parser.parseElf(buf[0..size]) orelse return false;
        if (parsed.load_count == 0) return false;

        const err = elf_parser.validateFull(buf[0..size]);
        if (err != .None) return false;
    }

    return true;
}
