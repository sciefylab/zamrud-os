//! Zamrud OS - Syscall Commands

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const syscall_dispatcher = @import("../../syscall/syscall.zig");
const gdt = @import("../../arch/x86_64/gdt.zig");
const user = @import("../../proc/user.zig");

var test_buf: [64]u8 = [_]u8{0} ** 64;

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "list")) {
        showList();
    } else if (helpers.strEql(parsed.cmd, "stats")) {
        showStats();
    } else if (helpers.strEql(parsed.cmd, "call")) {
        manualCall(parsed.rest);
    } else {
        shell.printError("syscall: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'syscall help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  SYSCALL - System Call Interface");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: syscall <command> [args]");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  help              Show this help");
    shell.println("  list              Show syscall numbers");
    shell.println("  stats             Show statistics");
    shell.println("  call <num>        Manually invoke syscall");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run all syscall tests");
    shell.println("  test quick        Quick health check");
    shell.println("  test gdt          Test GDT/TSS");
    shell.println("  test msr          Test SYSCALL MSRs");
    shell.println("  test core         Test core syscalls");
    shell.println("  test io           Test I/O syscalls");
    shell.println("  test error        Test error handling");
    shell.newLine();
}

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(opt, "gdt")) {
        runGdtTests();
    } else if (helpers.strEql(opt, "msr")) {
        runMsrTests();
    } else if (helpers.strEql(opt, "core")) {
        runCoreTests();
    } else if (helpers.strEql(opt, "io")) {
        runIoTests();
    } else if (helpers.strEql(opt, "error")) {
        runErrorTests();
    } else {
        shell.println("syscall test options: all, quick, gdt, msr, core, io, error");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Syscall Quick Test...");
    shell.newLine();

    var ok = true;

    shell.print("  Dispatcher:   ");
    if (syscall_dispatcher.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  GETPID:       ");
    if (syscall_dispatcher.dispatch(39, 0, 0, 0, 0, 0) >= 0) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  User mode:    ");
    if (user.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("Syscall", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("SYSCALL TEST SUITE");

    var p: u32 = 0;
    var f: u32 = 0;

    shell.printInfoLine("=== GDT & TSS ===");
    p += helpers.doTest("Kernel CS = 0x08", helpers.getCS() == 0x08, &f);
    p += helpers.doTest("Kernel DS = 0x10", helpers.getDS() == 0x10, &f);
    p += helpers.doTest("User DS = 0x1B", gdt.user_ds == 0x1B, &f);
    p += helpers.doTest("User CS = 0x23", gdt.user_cs == 0x23, &f);
    p += helpers.doTest("TSS RSP0 valid", gdt.getKernelStack() != 0, &f);

    shell.newLine();
    shell.printInfoLine("=== SYSCALL MSRs ===");
    p += helpers.doTest("User mode init", user.isInitialized(), &f);
    const efer = helpers.readMSR(0xC0000080);
    p += helpers.doTest("EFER.SCE enabled", (efer & 1) != 0, &f);
    p += helpers.doTest("LSTAR set", helpers.readMSR(0xC0000082) != 0, &f);
    p += helpers.doTest("SFMASK set", helpers.readMSR(0xC0000084) != 0, &f);

    shell.newLine();
    shell.printInfoLine("=== Core Syscalls ===");
    p += helpers.doTest("GETPID (39)", syscall_dispatcher.dispatch(39, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETUID (102)", syscall_dispatcher.dispatch(102, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GET_TICKS (401)", syscall_dispatcher.dispatch(401, 0, 0, 0, 0, 0) > 0, &f);

    shell.newLine();
    shell.printInfoLine("=== I/O Syscalls ===");
    test_buf[0] = 'T';
    test_buf[1] = 'S';
    p += helpers.doTest("WRITE stdout", syscall_dispatcher.dispatch(1, 1, @intFromPtr(&test_buf), 2, 0, 0) > 0, &f);
    p += helpers.doTest("DEBUG_PRINT", syscall_dispatcher.dispatch(400, @intFromPtr(&test_buf), 2, 0, 0, 0) > 0, &f);

    shell.newLine();
    shell.printInfoLine("=== Error Handling ===");
    p += helpers.doTest("Invalid = -ENOSYS", syscall_dispatcher.dispatch(999, 0, 0, 0, 0, 0) == -38, &f);
    p += helpers.doTest("Bad fd = -EBADF", syscall_dispatcher.dispatch(1, 99, @intFromPtr(&test_buf), 1, 0, 0) == -9, &f);
    p += helpers.doTest("NULL = -EFAULT", syscall_dispatcher.dispatch(1, 1, 0, 10, 0, 0) == -14, &f);

    helpers.printTestResults(p, f);
}

fn runGdtTests() void {
    shell.printInfoLine("Testing GDT/TSS...");
    var p: u32 = 0;
    var f: u32 = 0;
    p += helpers.doTest("Kernel CS", helpers.getCS() == 0x08, &f);
    p += helpers.doTest("Kernel DS", helpers.getDS() == 0x10, &f);
    p += helpers.doTest("User CS", gdt.user_cs == 0x23, &f);
    p += helpers.doTest("User DS", gdt.user_ds == 0x1B, &f);
    p += helpers.doTest("TSS RSP0", gdt.getKernelStack() != 0, &f);
    helpers.printTestResults(p, f);
}

fn runMsrTests() void {
    shell.printInfoLine("Testing SYSCALL MSRs...");
    var p: u32 = 0;
    var f: u32 = 0;
    const efer = helpers.readMSR(0xC0000080);
    p += helpers.doTest("EFER.SCE", (efer & 1) != 0, &f);
    p += helpers.doTest("LSTAR", helpers.readMSR(0xC0000082) != 0, &f);
    p += helpers.doTest("SFMASK", helpers.readMSR(0xC0000084) != 0, &f);
    helpers.printTestResults(p, f);
}

fn runCoreTests() void {
    shell.printInfoLine("Testing Core Syscalls...");
    var p: u32 = 0;
    var f: u32 = 0;
    p += helpers.doTest("GETPID", syscall_dispatcher.dispatch(39, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETPPID", syscall_dispatcher.dispatch(110, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETUID", syscall_dispatcher.dispatch(102, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GET_TICKS", syscall_dispatcher.dispatch(401, 0, 0, 0, 0, 0) > 0, &f);
    helpers.printTestResults(p, f);
}

fn runIoTests() void {
    shell.printInfoLine("Testing I/O Syscalls...");
    var p: u32 = 0;
    var f: u32 = 0;
    test_buf[0] = 'I';
    test_buf[1] = 'O';
    p += helpers.doTest("WRITE stdout", syscall_dispatcher.dispatch(1, 1, @intFromPtr(&test_buf), 2, 0, 0) > 0, &f);
    p += helpers.doTest("DEBUG_PRINT", syscall_dispatcher.dispatch(400, @intFromPtr(&test_buf), 2, 0, 0, 0) > 0, &f);
    helpers.printTestResults(p, f);
}

fn runErrorTests() void {
    shell.printInfoLine("Testing Error Handling...");
    var p: u32 = 0;
    var f: u32 = 0;
    p += helpers.doTest("Invalid syscall", syscall_dispatcher.dispatch(999, 0, 0, 0, 0, 0) == -38, &f);
    p += helpers.doTest("Bad fd", syscall_dispatcher.dispatch(1, 99, @intFromPtr(&test_buf), 1, 0, 0) == -9, &f);
    p += helpers.doTest("NULL pointer", syscall_dispatcher.dispatch(1, 1, 0, 10, 0, 0) == -14, &f);
    helpers.printTestResults(p, f);
}

fn showList() void {
    shell.printInfoLine("Syscall Number Ranges:");
    shell.println("  0-99:     Linux-compatible (read, write, getpid...)");
    shell.println("  100-119:  Identity (create, unlock, lock...)");
    shell.println("  120-139:  Integrity (register, verify...)");
    shell.println("  140-159:  Boot/Security (status, policy...)");
    shell.println("  160-179:  Crypto (hash, random, sign...)");
    shell.println("  400+:     Zamrud extensions (debug, ticks...)");
    shell.newLine();
}

fn showStats() void {
    shell.printInfoLine("Syscall Statistics:");
    shell.print("  Total calls:  ");
    helpers.printUsize(@intCast(syscall_dispatcher.getSyscallCount() & 0xFFFFFFFF));
    shell.newLine();
    shell.print("  Last syscall: ");
    helpers.printUsize(@intCast(syscall_dispatcher.getLastSyscall() & 0xFFFF));
    shell.newLine();
    shell.print("  Initialized:  ");
    if (syscall_dispatcher.isInitialized()) shell.printSuccessLine("Yes") else shell.printErrorLine("No");
    shell.newLine();
}

fn manualCall(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: syscall call <number>");
        return;
    }
    const num = helpers.parseU32(args) orelse {
        shell.printErrorLine("Invalid number");
        return;
    };
    shell.print("Calling syscall ");
    helpers.printU32(num);
    shell.println("...");
    const result = syscall_dispatcher.dispatch(num, 0, 0, 0, 0, 0);
    shell.print("  Result: ");
    if (result >= 0) {
        helpers.printU64(@intCast(result));
        shell.printSuccessLine(" (OK)");
    } else {
        shell.print("-");
        helpers.printU64(@intCast(-result));
        shell.printErrorLine(" (error)");
    }
}
