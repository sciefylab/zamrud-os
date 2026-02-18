//! Zamrud OS - Syscall Commands (SC1 + SC2 + SC3 + SC4 + SC5 + SC6)

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const syscall_dispatcher = @import("../../syscall/table.zig");
const numbers = @import("../../syscall/numbers.zig");
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
    shell.println("  test proc         Test process syscalls (SC2)");
    shell.println("  test ipc          Test IPC syscalls (SC3)");
    shell.println("  test shm          Test shared memory (SC4)");
    shell.println("  test user         Test user/auth (SC5)");
    shell.println("  test net          Test network sockets (SC6)");
    shell.println("  test enc          Test encrypted FS & ELF (SC7)");
    shell.println("  test fs           Test FS extended (SC8)");
    shell.println("  test gui          Test GUI prep (SC9)");
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
    } else if (helpers.strEql(opt, "proc")) {
        runProcTests();
    } else if (helpers.strEql(opt, "ipc")) {
        runIpcTests();
    } else if (helpers.strEql(opt, "shm")) {
        runShmTests();
    } else if (helpers.strEql(opt, "user")) {
        runUserTests();
    } else if (helpers.strEql(opt, "net")) {
        runNetTests();
    } else if (helpers.strEql(opt, "enc")) {
        runEncTests();
    } else if (helpers.strEql(opt, "fs")) {
        runFsTests();
    } else if (helpers.strEql(opt, "gui")) {
        runGuiTests();
    } else {
        shell.println("syscall test options: all, quick, gdt, msr, core, io, error, proc, ipc, shm, user, net, enc, fs, gui");
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
    if (syscall_dispatcher.dispatch(numbers.SYS_GETPID, 0, 0, 0, 0, 0, 0) >= 0) {
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

    // === SC1: GDT & TSS ===
    shell.printInfoLine("=== GDT & TSS ===");
    p += helpers.doTest("Kernel CS = 0x08", helpers.getCS() == 0x08, &f);
    p += helpers.doTest("Kernel DS = 0x10", helpers.getDS() == 0x10, &f);
    p += helpers.doTest("User DS = 0x1B", gdt.user_ds == 0x1B, &f);
    p += helpers.doTest("User CS = 0x23", gdt.user_cs == 0x23, &f);
    p += helpers.doTest("TSS RSP0 valid", gdt.getKernelStack() != 0, &f);

    // === SC1: SYSCALL MSRs ===
    shell.newLine();
    shell.printInfoLine("=== SYSCALL MSRs ===");
    p += helpers.doTest("User mode init", user.isInitialized(), &f);
    const efer = helpers.readMSR(0xC0000080);
    p += helpers.doTest("EFER.SCE enabled", (efer & 1) != 0, &f);
    p += helpers.doTest("LSTAR set", helpers.readMSR(0xC0000082) != 0, &f);
    p += helpers.doTest("SFMASK set", helpers.readMSR(0xC0000084) != 0, &f);

    // === SC1: Core Syscalls ===
    shell.newLine();
    shell.printInfoLine("=== Core Syscalls ===");
    p += helpers.doTest("GETPID", syscall_dispatcher.dispatch(numbers.SYS_GETPID, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETUID", syscall_dispatcher.dispatch(numbers.SYS_GETUID, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GET_TICKS", syscall_dispatcher.dispatch(numbers.SYS_GET_TICKS, 0, 0, 0, 0, 0, 0) > 0, &f);

    // === SC1: I/O Syscalls ===
    shell.newLine();
    shell.printInfoLine("=== I/O Syscalls ===");
    test_buf[0] = 'T';
    test_buf[1] = 'S';
    p += helpers.doTest("WRITE stdout", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 1, @intFromPtr(&test_buf), 2, 0, 0, 0) > 0, &f);
    p += helpers.doTest("DEBUG_PRINT", syscall_dispatcher.dispatch(numbers.SYS_DEBUG_PRINT, @intFromPtr(&test_buf), 2, 0, 0, 0, 0) > 0, &f);

    // === SC1: Error Handling ===
    shell.newLine();
    shell.printInfoLine("=== Error Handling ===");
    p += helpers.doTest("Invalid = -ENOSYS", syscall_dispatcher.dispatch(999, 0, 0, 0, 0, 0, 0) == numbers.ENOSYS, &f);
    p += helpers.doTest("Bad fd = -EBADF", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 99, @intFromPtr(&test_buf), 1, 0, 0, 0) == numbers.EBADF, &f);
    p += helpers.doTest("NULL = -EFAULT", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 1, 0, 10, 0, 0, 0) == numbers.EFAULT, &f);

    // === SC2: Process Extended ===
    shell.newLine();
    shell.printInfoLine("=== SC2: Process Extended ===");
    p += helpers.doTest("GETPRIORITY self", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("SETPRIORITY self=5", syscall_dispatcher.dispatch(numbers.SYS_SETPRIORITY, 0, 5, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("GETPRIORITY == 5", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 0, 0, 0, 0, 0, 0) == 5, &f);
    p += helpers.doTest("PROC_YIELD", syscall_dispatcher.dispatch(numbers.SYS_PROC_YIELD, 0, 0, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("KILL pid=0 fail", syscall_dispatcher.dispatch(numbers.SYS_PROC_KILL, 0, 0, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("KILL pid=9999", syscall_dispatcher.dispatch(numbers.SYS_PROC_KILL, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("WAITPID noexist", syscall_dispatcher.dispatch(numbers.SYS_PROC_WAITPID, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("SPAWN null fail", syscall_dispatcher.dispatch(numbers.SYS_SPAWN, 0, 0, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("GETPRI noexist", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("SETPRI noexist", syscall_dispatcher.dispatch(numbers.SYS_SETPRIORITY, 9999, 10, 0, 0, 0, 0) == numbers.ESRCH, &f);

    // === SC3: IPC ===
    shell.newLine();
    shell.printInfoLine("=== SC3: IPC ===");
    p += helpers.doTest("MSG_SEND self", syscall_dispatcher.dispatch(numbers.SYS_MSG_SEND, 0, 0, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("MSG_RECV empty", syscall_dispatcher.dispatch(numbers.SYS_MSG_RECV, 0, 0, 0, 0, 0, 0) >= 0, &f);
    const pipe_result = syscall_dispatcher.dispatch(numbers.SYS_PIPE_CREATE, 0, 0, 0, 0, 0, 0);
    p += helpers.doTest("PIPE_CREATE", pipe_result > 0, &f);
    test_buf[0] = 'H';
    test_buf[1] = 'I';
    const pw = syscall_dispatcher.dispatch(numbers.SYS_PIPE_WRITE, @intCast(pipe_result), @intFromPtr(&test_buf), 2, 0, 0, 0);
    p += helpers.doTest("PIPE_WRITE", pw == 2, &f);
    var read_buf: [64]u8 = [_]u8{0} ** 64;
    const pr = syscall_dispatcher.dispatch(numbers.SYS_PIPE_READ, @intCast(pipe_result), @intFromPtr(&read_buf), 64, 0, 0, 0);
    p += helpers.doTest("PIPE_READ", pr == 2, &f);
    p += helpers.doTest("SIG_MASK get", syscall_dispatcher.dispatch(numbers.SYS_SIG_MASK, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("SIG_MASK block", syscall_dispatcher.dispatch(numbers.SYS_SIG_MASK, 1, 10, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("SIG_SEND invalid", syscall_dispatcher.dispatch(numbers.SYS_SIG_SEND, 0, 99, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("PIPE_READ bad", syscall_dispatcher.dispatch(numbers.SYS_PIPE_READ, 9999, @intFromPtr(&read_buf), 64, 0, 0, 0) == numbers.EBADF, &f);

    // === SC4: Shared Memory ===
    shell.newLine();
    shell.printInfoLine("=== SC4: Shared Memory ===");
    runShmTestsInline(&p, &f);

    // === SC5: User/Auth ===
    shell.newLine();
    shell.printInfoLine("=== SC5: User/Auth ===");
    runUserTestsInline(&p, &f);

    // === SC6: Network ===
    shell.newLine();
    shell.printInfoLine("=== SC6: Network ===");
    runNetTestsInline(&p, &f);

    // === SC7: Encrypted FS & ELF ===
    shell.newLine();
    shell.printInfoLine("=== SC7: Encrypted FS & ELF ===");
    runEncTestsInline(&p, &f);

    // === SC8: FS Extended ===
    shell.newLine();
    shell.printInfoLine("=== SC8: FS Extended ===");
    runFsTestsInline(&p, &f);

    // === SC9: GUI Prep ===
    shell.newLine();
    shell.printInfoLine("=== SC9: GUI Prep ===");
    runGuiTestsInline(&p, &f);

    helpers.printTestResults(p, f);
}

// =============================================================================
// SC4: Shared Memory Tests
// =============================================================================

fn runShmTestsInline(p: *u32, f: *u32) void {
    const shm_name = "test_shm";
    const shm_create = syscall_dispatcher.dispatch(numbers.SYS_SHM_CREATE, @intFromPtr(shm_name.ptr), shm_name.len, 1024, 0, 0, 0);
    p.* += helpers.doTest("SHM_CREATE", shm_create > 0, f);

    const shm_dup = syscall_dispatcher.dispatch(numbers.SYS_SHM_CREATE, @intFromPtr(shm_name.ptr), shm_name.len, 1024, 0, 0, 0);
    p.* += helpers.doTest("SHM_CREATE dup", shm_dup == numbers.EEXIST, f);

    const no_name = "empty_shm";
    p.* += helpers.doTest("SHM_CREATE sz=0", syscall_dispatcher.dispatch(numbers.SYS_SHM_CREATE, @intFromPtr(no_name.ptr), no_name.len, 0, 0, 0, 0) == numbers.EINVAL, f);
    p.* += helpers.doTest("SHM_CREATE no name", syscall_dispatcher.dispatch(numbers.SYS_SHM_CREATE, 0, 0, 512, 0, 0, 0) == numbers.EINVAL, f);

    const shm_id: u64 = @intCast(shm_create);
    const write_data = "HELLO";
    p.* += helpers.doTest("SHM_WRITE", syscall_dispatcher.dispatch(numbers.SYS_SHM_WRITE, shm_id, 0, @intFromPtr(write_data.ptr), write_data.len, 0, 0) == 5, f);

    var shm_read_buf: [64]u8 = [_]u8{0} ** 64;
    const shm_read = syscall_dispatcher.dispatch(numbers.SYS_SHM_READ, shm_id, 0, @intFromPtr(&shm_read_buf), 5, 0, 0);
    const data_ok = shm_read == 5 and shm_read_buf[0] == 'H' and shm_read_buf[1] == 'E' and shm_read_buf[2] == 'L' and shm_read_buf[3] == 'L' and shm_read_buf[4] == 'O';
    p.* += helpers.doTest("SHM_READ verify", data_ok, f);

    p.* += helpers.doTest("SHM_READ bad id", syscall_dispatcher.dispatch(numbers.SYS_SHM_READ, 9999, 0, @intFromPtr(&shm_read_buf), 5, 0, 0) == numbers.EBADF, f);
    p.* += helpers.doTest("SHM_WRITE null", syscall_dispatcher.dispatch(numbers.SYS_SHM_WRITE, shm_id, 0, 0, 10, 0, 0) == numbers.EFAULT, f);
    p.* += helpers.doTest("SHM_DESTROY", syscall_dispatcher.dispatch(numbers.SYS_SHM_DESTROY, shm_id, 0, 0, 0, 0, 0) == 0, f);
    p.* += helpers.doTest("SHM_DESTROY again", syscall_dispatcher.dispatch(numbers.SYS_SHM_DESTROY, shm_id, 0, 0, 0, 0, 0) == numbers.EBADF, f);
    p.* += helpers.doTest("SHM_READ destroyed", syscall_dispatcher.dispatch(numbers.SYS_SHM_READ, shm_id, 0, @intFromPtr(&shm_read_buf), 5, 0, 0) == numbers.EBADF, f);
}

fn runShmTests() void {
    shell.printInfoLine("Testing SC4: Shared Memory...");
    var p: u32 = 0;
    var f: u32 = 0;
    runShmTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// SC5: User/Auth Tests
// =============================================================================

fn runUserTestsInline(p: *u32, f: *u32) void {
    var name_buf: [64]u8 = [_]u8{0} ** 64;
    p.* += helpers.doTest("GET_USERNAME cur", syscall_dispatcher.dispatch(numbers.SYS_GET_USERNAME, 0xFFFF, @intFromPtr(&name_buf), 64, 0, 0, 0) > 0, f);
    p.* += helpers.doTest("GET_USERNAME null", syscall_dispatcher.dispatch(numbers.SYS_GET_USERNAME, 0xFFFF, 0, 64, 0, 0, 0) == numbers.EFAULT, f);
    p.* += helpers.doTest("GET_USERNAME len=0", syscall_dispatcher.dispatch(numbers.SYS_GET_USERNAME, 0xFFFF, @intFromPtr(&name_buf), 0, 0, 0, 0) == numbers.EINVAL, f);

    const setuid_result = syscall_dispatcher.dispatch(numbers.SYS_SETUID, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("SETUID basic", setuid_result == numbers.EPERM or setuid_result == numbers.SUCCESS, f);

    const setgid_result = syscall_dispatcher.dispatch(numbers.SYS_SETGID, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("SETGID basic", setgid_result == numbers.EPERM or setgid_result == numbers.SUCCESS, f);

    p.* += helpers.doTest("LOGIN null name", syscall_dispatcher.dispatch(numbers.SYS_LOGIN, 0, 0, @intFromPtr(&name_buf), 4, 0, 0) == numbers.EINVAL, f);

    const login_name = "testuser";
    p.* += helpers.doTest("LOGIN null pin", syscall_dispatcher.dispatch(numbers.SYS_LOGIN, @intFromPtr(login_name.ptr), login_name.len, 0, 0, 0, 0) == numbers.EINVAL, f);

    const logout_result = syscall_dispatcher.dispatch(numbers.SYS_LOGOUT, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("LOGOUT basic", logout_result == numbers.EPERM or logout_result == numbers.SUCCESS, f);

    p.* += helpers.doTest("LOGOUT no session", syscall_dispatcher.dispatch(numbers.SYS_LOGOUT, 0, 0, 0, 0, 0, 0) == numbers.EPERM, f);
}

fn runUserTests() void {
    shell.printInfoLine("Testing SC5: User/Auth...");
    var p: u32 = 0;
    var f: u32 = 0;
    runUserTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// SC6: Network Socket Tests
// =============================================================================

fn runNetTestsInline(p: *u32, f: *u32) void {
    // SOCKET create UDP
    const sock_udp = syscall_dispatcher.dispatch(numbers.SYS_SOCKET, 1, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("SOCKET UDP", sock_udp > 0, f);

    // SOCKET create TCP
    const sock_tcp = syscall_dispatcher.dispatch(numbers.SYS_SOCKET, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("SOCKET TCP", sock_tcp > 0, f);

    // SOCKET invalid type
    p.* += helpers.doTest("SOCKET bad type", syscall_dispatcher.dispatch(numbers.SYS_SOCKET, 99, 0, 0, 0, 0, 0) == numbers.EINVAL, f);

    // BIND UDP to port 5000
    if (sock_udp > 0) {
        const bind_r = syscall_dispatcher.dispatch(numbers.SYS_BIND, @intCast(sock_udp), 0, 5000, 0, 0, 0);
        p.* += helpers.doTest("BIND udp:5000", bind_r == 0, f);

        // BIND port=0 invalid
        const sock_tmp = syscall_dispatcher.dispatch(numbers.SYS_SOCKET, 1, 0, 0, 0, 0, 0);
        if (sock_tmp > 0) {
            p.* += helpers.doTest("BIND port=0", syscall_dispatcher.dispatch(numbers.SYS_BIND, @intCast(sock_tmp), 0, 0, 0, 0, 0) == numbers.EINVAL, f);
        } else {
            p.* += helpers.doTest("BIND port=0", true, f); // skip if no socket
        }
    } else {
        p.* += helpers.doTest("BIND udp:5000", false, f);
        p.* += helpers.doTest("BIND port=0", false, f);
    }

    // BIND bad handle
    p.* += helpers.doTest("BIND bad handle", syscall_dispatcher.dispatch(numbers.SYS_BIND, 9999, 0, 8080, 0, 0, 0) == numbers.EBADF, f);

    // LISTEN on TCP socket (must bind first)
    if (sock_tcp > 0) {
        const bind_tcp = syscall_dispatcher.dispatch(numbers.SYS_BIND, @intCast(sock_tcp), 0, 8080, 0, 0, 0);
        if (bind_tcp == 0) {
            p.* += helpers.doTest("LISTEN tcp", syscall_dispatcher.dispatch(numbers.SYS_LISTEN, @intCast(sock_tcp), 5, 0, 0, 0, 0) == 0, f);
        } else {
            p.* += helpers.doTest("LISTEN tcp", false, f);
        }
    } else {
        p.* += helpers.doTest("LISTEN tcp", false, f);
    }

    // LISTEN on UDP → should fail
    if (sock_udp > 0) {
        p.* += helpers.doTest("LISTEN udp fail", syscall_dispatcher.dispatch(numbers.SYS_LISTEN, @intCast(sock_udp), 5, 0, 0, 0, 0) == numbers.EINVAL, f);
    } else {
        p.* += helpers.doTest("LISTEN udp fail", true, f);
    }

    // ACCEPT on listening TCP → EAGAIN (no connections)
    if (sock_tcp > 0) {
        p.* += helpers.doTest("ACCEPT no conn", syscall_dispatcher.dispatch(numbers.SYS_ACCEPT, @intCast(sock_tcp), 0, 0, 0, 0, 0) == numbers.EAGAIN, f);
    } else {
        p.* += helpers.doTest("ACCEPT no conn", true, f);
    }

    // CONNECT invalid ip=0
    const sock_conn = syscall_dispatcher.dispatch(numbers.SYS_SOCKET, 1, 0, 0, 0, 0, 0);
    if (sock_conn > 0) {
        p.* += helpers.doTest("CONNECT ip=0", syscall_dispatcher.dispatch(numbers.SYS_CONNECT, @intCast(sock_conn), 0, 1234, 0, 0, 0) == numbers.EINVAL, f);

        // CONNECT port=0
        p.* += helpers.doTest("CONNECT port=0", syscall_dispatcher.dispatch(numbers.SYS_CONNECT, @intCast(sock_conn), 0x0A000202, 0, 0, 0, 0) == numbers.EINVAL, f);
    } else {
        p.* += helpers.doTest("CONNECT ip=0", true, f);
        p.* += helpers.doTest("CONNECT port=0", true, f);
    }

    // SENDTO null data
    if (sock_udp > 0) {
        p.* += helpers.doTest("SENDTO null", syscall_dispatcher.dispatch(numbers.SYS_SENDTO, @intCast(sock_udp), 0, 10, 0, 0, 0) == numbers.EFAULT, f);
    } else {
        p.* += helpers.doTest("SENDTO null", true, f);
    }

    // RECVFROM null buf
    p.* += helpers.doTest("RECVFROM null", syscall_dispatcher.dispatch(numbers.SYS_RECVFROM, 1, 0, 64, 0, 0, 0) == numbers.EFAULT, f);

    // RECVFROM bad handle
    var recv_buf: [64]u8 = [_]u8{0} ** 64;
    p.* += helpers.doTest("RECVFROM bad hnd", syscall_dispatcher.dispatch(numbers.SYS_RECVFROM, 9999, @intFromPtr(&recv_buf), 64, 0, 0, 0) == numbers.EBADF, f);
}

fn runNetTests() void {
    shell.printInfoLine("Testing SC6: Network Sockets...");
    var p: u32 = 0;
    var f: u32 = 0;
    runNetTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// Individual Test Suites (SC1-SC3)
// =============================================================================

fn runIpcTests() void {
    var p: u32 = 0;
    var f: u32 = 0;
    shell.newLine();
    shell.printInfoLine("=== SC3: IPC ===");
    p += helpers.doTest("MSG_SEND self", syscall_dispatcher.dispatch(numbers.SYS_MSG_SEND, 0, 0, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("MSG_RECV empty", syscall_dispatcher.dispatch(numbers.SYS_MSG_RECV, 0, 0, 0, 0, 0, 0) >= 0, &f);
    const pipe_result = syscall_dispatcher.dispatch(numbers.SYS_PIPE_CREATE, 0, 0, 0, 0, 0, 0);
    p += helpers.doTest("PIPE_CREATE", pipe_result > 0, &f);
    test_buf[0] = 'H';
    test_buf[1] = 'I';
    p += helpers.doTest("PIPE_WRITE", syscall_dispatcher.dispatch(numbers.SYS_PIPE_WRITE, @intCast(pipe_result), @intFromPtr(&test_buf), 2, 0, 0, 0) == 2, &f);
    var read_buf: [64]u8 = [_]u8{0} ** 64;
    p += helpers.doTest("PIPE_READ", syscall_dispatcher.dispatch(numbers.SYS_PIPE_READ, @intCast(pipe_result), @intFromPtr(&read_buf), 64, 0, 0, 0) == 2, &f);
    p += helpers.doTest("SIG_MASK get", syscall_dispatcher.dispatch(numbers.SYS_SIG_MASK, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("SIG_MASK block", syscall_dispatcher.dispatch(numbers.SYS_SIG_MASK, 1, 10, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("SIG_SEND invalid", syscall_dispatcher.dispatch(numbers.SYS_SIG_SEND, 0, 99, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("PIPE_READ bad", syscall_dispatcher.dispatch(numbers.SYS_PIPE_READ, 9999, @intFromPtr(&read_buf), 64, 0, 0, 0) == numbers.EBADF, &f);
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
    p += helpers.doTest("GETPID", syscall_dispatcher.dispatch(numbers.SYS_GETPID, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETPPID", syscall_dispatcher.dispatch(numbers.SYS_GETPPID, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GETUID", syscall_dispatcher.dispatch(numbers.SYS_GETUID, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("GET_TICKS", syscall_dispatcher.dispatch(numbers.SYS_GET_TICKS, 0, 0, 0, 0, 0, 0) > 0, &f);
    helpers.printTestResults(p, f);
}

fn runIoTests() void {
    shell.printInfoLine("Testing I/O Syscalls...");
    var p: u32 = 0;
    var f: u32 = 0;
    test_buf[0] = 'I';
    test_buf[1] = 'O';
    p += helpers.doTest("WRITE stdout", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 1, @intFromPtr(&test_buf), 2, 0, 0, 0) > 0, &f);
    p += helpers.doTest("DEBUG_PRINT", syscall_dispatcher.dispatch(numbers.SYS_DEBUG_PRINT, @intFromPtr(&test_buf), 2, 0, 0, 0, 0) > 0, &f);
    helpers.printTestResults(p, f);
}

fn runErrorTests() void {
    shell.printInfoLine("Testing Error Handling...");
    var p: u32 = 0;
    var f: u32 = 0;
    p += helpers.doTest("Invalid syscall", syscall_dispatcher.dispatch(999, 0, 0, 0, 0, 0, 0) == numbers.ENOSYS, &f);
    p += helpers.doTest("Bad fd", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 99, @intFromPtr(&test_buf), 1, 0, 0, 0) == numbers.EBADF, &f);
    p += helpers.doTest("NULL pointer", syscall_dispatcher.dispatch(numbers.SYS_WRITE, 1, 0, 10, 0, 0, 0) == numbers.EFAULT, &f);
    helpers.printTestResults(p, f);
}

fn runProcTests() void {
    shell.printInfoLine("Testing SC2: Process Extended...");
    var p: u32 = 0;
    var f: u32 = 0;
    p += helpers.doTest("GETPRIORITY self", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 0, 0, 0, 0, 0, 0) >= 0, &f);
    p += helpers.doTest("SETPRIORITY self=3", syscall_dispatcher.dispatch(numbers.SYS_SETPRIORITY, 0, 3, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("GETPRIORITY == 3", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 0, 0, 0, 0, 0, 0) == 3, &f);
    p += helpers.doTest("PROC_YIELD", syscall_dispatcher.dispatch(numbers.SYS_PROC_YIELD, 0, 0, 0, 0, 0, 0) == 0, &f);
    p += helpers.doTest("KILL pid=0 fail", syscall_dispatcher.dispatch(numbers.SYS_PROC_KILL, 0, 0, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("KILL noexist", syscall_dispatcher.dispatch(numbers.SYS_PROC_KILL, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("WAITPID noexist", syscall_dispatcher.dispatch(numbers.SYS_PROC_WAITPID, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("SPAWN null fail", syscall_dispatcher.dispatch(numbers.SYS_SPAWN, 0, 0, 0, 0, 0, 0) == numbers.EINVAL, &f);
    p += helpers.doTest("GETPRI noexist", syscall_dispatcher.dispatch(numbers.SYS_GETPRIORITY, 9999, 0, 0, 0, 0, 0) == numbers.ESRCH, &f);
    p += helpers.doTest("SETPRI noexist", syscall_dispatcher.dispatch(numbers.SYS_SETPRIORITY, 9999, 10, 0, 0, 0, 0) == numbers.ESRCH, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// SC7: Encrypted FS & ELF Tests
// =============================================================================

fn runEncTestsInline(p: *u32, f: *u32) void {
    // ENC_STATUS — should return flags
    const status = syscall_dispatcher.dispatch(numbers.SYS_ENC_STATUS, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("ENC_STATUS", status >= 0, f);

    // ENC_SETKEY with passphrase
    const pass = "testkey1234";
    const setkey = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_SETKEY,
        0, // method=passphrase
        @intFromPtr(pass.ptr),
        pass.len,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("ENC_SETKEY pass", setkey == 0, f);

    // ENC_STATUS should now show key set (bit 1)
    const status2 = syscall_dispatcher.dispatch(numbers.SYS_ENC_STATUS, 0, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("ENC key set", (status2 & 2) != 0, f);

    // ENC_WRITE — encrypt a file
    const fname = "sc7test.enc";
    const fdata = "Hello SC7!";
    const enc_write = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_WRITE,
        @intFromPtr(fname.ptr),
        fname.len,
        @intFromPtr(fdata.ptr),
        fdata.len,
        0,
        0,
    );
    p.* += helpers.doTest("ENC_WRITE", enc_write == 0, f);

    // ENC_WRITE duplicate → EEXIST
    const enc_dup = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_WRITE,
        @intFromPtr(fname.ptr),
        fname.len,
        @intFromPtr(fdata.ptr),
        fdata.len,
        0,
        0,
    );
    p.* += helpers.doTest("ENC_WRITE dup", enc_dup == numbers.EEXIST, f);

    // ENC_READ — decrypt and verify
    var read_buf: [64]u8 = [_]u8{0} ** 64;
    const enc_read = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_READ,
        @intFromPtr(fname.ptr),
        fname.len,
        @intFromPtr(&read_buf),
        64,
        0,
        0,
    );
    const read_ok = enc_read == 10 and
        read_buf[0] == 'H' and read_buf[1] == 'e' and
        read_buf[2] == 'l' and read_buf[3] == 'l' and
        read_buf[4] == 'o';
    p.* += helpers.doTest("ENC_READ verify", read_ok, f);

    // ENC_READ nonexistent → ENOENT
    const nofile = "noexist.enc";
    const enc_nofile = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_READ,
        @intFromPtr(nofile.ptr),
        nofile.len,
        @intFromPtr(&read_buf),
        64,
        0,
        0,
    );
    p.* += helpers.doTest("ENC_READ noexist", enc_nofile == numbers.ENOENT, f);

    // ENC_WRITE null data → EINVAL
    p.* += helpers.doTest("ENC_WRITE null", syscall_dispatcher.dispatch(
        numbers.SYS_ENC_WRITE,
        @intFromPtr(fname.ptr),
        fname.len,
        0,
        10,
        0,
        0,
    ) == numbers.EINVAL, f);

    // ENC_SETKEY lock (method=3)
    const lock = syscall_dispatcher.dispatch(numbers.SYS_ENC_SETKEY, 3, 0, 0, 0, 0, 0);
    p.* += helpers.doTest("ENC_SETKEY lock", lock == 0, f);

    // ENC_READ after lock → EACCES
    const enc_locked = syscall_dispatcher.dispatch(
        numbers.SYS_ENC_READ,
        @intFromPtr(fname.ptr),
        fname.len,
        @intFromPtr(&read_buf),
        64,
        0,
        0,
    );
    p.* += helpers.doTest("ENC_READ locked", enc_locked == numbers.EACCES, f);

    // EXEC_ELF with null data → EINVAL
    p.* += helpers.doTest("EXEC_ELF null", syscall_dispatcher.dispatch(
        numbers.SYS_EXEC_ELF,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EINVAL, f);

    // EXEC_ZAM with null data → EINVAL
    p.* += helpers.doTest("EXEC_ZAM null", syscall_dispatcher.dispatch(
        numbers.SYS_EXEC_ZAM,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EINVAL, f);
}

fn runEncTests() void {
    shell.printInfoLine("Testing SC7: Encrypted FS & ELF...");
    var p: u32 = 0;
    var f: u32 = 0;
    runEncTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// SC8: FS Extended Tests
// =============================================================================

fn runFsTestsInline(p: *u32, f: *u32) void {
    // STAT on root "/"
    const root_path = "/";
    var stat_buf: [32]u8 = [_]u8{0} ** 32;
    const stat_r = syscall_dispatcher.dispatch(
        numbers.SYS_FSTAT_PATH,
        @intFromPtr(root_path.ptr),
        @intFromPtr(&stat_buf),
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("STAT /", stat_r == 0, f);

    // STAT nonexistent
    const nopath = "/nonexistent_path_xyz";
    const stat_no = syscall_dispatcher.dispatch(
        numbers.SYS_FSTAT_PATH,
        @intFromPtr(nopath.ptr),
        @intFromPtr(&stat_buf),
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("STAT noexist", stat_no == numbers.ENOENT, f);

    // STAT null path → EFAULT
    p.* += helpers.doTest("STAT null", syscall_dispatcher.dispatch(
        numbers.SYS_FSTAT_PATH,
        0,
        @intFromPtr(&stat_buf),
        0,
        0,
        0,
        0,
    ) == numbers.EFAULT, f);

    // READDIR on root, index 0 → should return 1 (entry found) or 0
    var dir_buf: [280]u8 = [_]u8{0} ** 280;
    const readdir_r = syscall_dispatcher.dispatch(
        numbers.SYS_READDIR,
        @intFromPtr(root_path.ptr),
        0, // index 0
        @intFromPtr(&dir_buf),
        0,
        0,
        0,
    );
    p.* += helpers.doTest("READDIR /[0]", readdir_r >= 0, f);

    // READDIR high index → 0 (no more entries)
    const readdir_hi = syscall_dispatcher.dispatch(
        numbers.SYS_READDIR,
        @intFromPtr(root_path.ptr),
        9999,
        @intFromPtr(&dir_buf),
        0,
        0,
        0,
    );
    p.* += helpers.doTest("READDIR end", readdir_hi == 0, f);

    // SEEK bad fd → EBADF
    p.* += helpers.doTest("SEEK bad fd", syscall_dispatcher.dispatch(
        numbers.SYS_SEEK,
        999,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EBADF, f);

    // SEEK invalid whence
    // First need a valid fd — open a test file if VFS has one
    // For safety, just test with bad fd
    p.* += helpers.doTest("SEEK fd<3", syscall_dispatcher.dispatch(
        numbers.SYS_SEEK,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EBADF, f);

    // RENAME → ENOSYS (stub)
    const old_name = "/old.txt";
    const new_name = "/new.txt";
    p.* += helpers.doTest("RENAME stub", syscall_dispatcher.dispatch(
        numbers.SYS_RENAME,
        @intFromPtr(old_name.ptr),
        @intFromPtr(new_name.ptr),
        0,
        0,
        0,
        0,
    ) == numbers.ENOSYS, f);

    // TRUNCATE → ENOSYS (stub)
    p.* += helpers.doTest("TRUNCATE stub", syscall_dispatcher.dispatch(
        numbers.SYS_TRUNCATE,
        @intFromPtr(root_path.ptr),
        0,
        0,
        0,
        0,
        0,
    ) == numbers.ENOSYS, f);
}

fn runFsTests() void {
    shell.printInfoLine("Testing SC8: FS Extended...");
    var p: u32 = 0;
    var f: u32 = 0;
    runFsTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// SC9: GUI Prep Tests
// =============================================================================

fn runGuiTestsInline(p: *u32, f: *u32) void {
    // FB_GET_INFO — should succeed if framebuffer present, ENODEV otherwise
    var fb_info: [64]u8 = [_]u8{0} ** 64;
    const fb_r = syscall_dispatcher.dispatch(
        numbers.SYS_FB_GET_INFO,
        @intFromPtr(&fb_info),
        0,
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("FB_GET_INFO", fb_r == 0 or fb_r == numbers.ENODEV, f);

    // FB_GET_INFO null → EFAULT
    p.* += helpers.doTest("FB_GET_INFO null", syscall_dispatcher.dispatch(
        numbers.SYS_FB_GET_INFO,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EFAULT, f);

    // FB_MAP — returns address (bitcast, may be negative as i64) or ENODEV
    const fb_map = syscall_dispatcher.dispatch(
        numbers.SYS_FB_MAP,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    // Address in higher-half will be negative when interpreted as i64.
    // ENODEV is -19. Valid address is a large negative (< -1000).
    // So: either ENODEV, or a non-zero value that isn't a small error code.
    const fb_map_ok = (fb_map == numbers.ENODEV) or (fb_map != 0 and (fb_map > 0 or fb_map < -1000));
    p.* += helpers.doTest("FB_MAP", fb_map_ok, f);

    // FB_UNMAP — always succeeds
    p.* += helpers.doTest("FB_UNMAP", syscall_dispatcher.dispatch(
        numbers.SYS_FB_UNMAP,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == 0, f);

    // FB_FLUSH — succeeds or ENODEV
    const fb_flush = syscall_dispatcher.dispatch(
        numbers.SYS_FB_FLUSH,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("FB_FLUSH", fb_flush == 0 or fb_flush == numbers.ENODEV, f);

    // CURSOR_SET_POS
    const cursor_r = syscall_dispatcher.dispatch(
        numbers.SYS_CURSOR_SET_POS,
        10,
        20,
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("CURSOR_POS", cursor_r == 0 or cursor_r == numbers.ENODEV, f);

    // CURSOR_SET_VISIBLE
    p.* += helpers.doTest("CURSOR_VIS", syscall_dispatcher.dispatch(
        numbers.SYS_CURSOR_SET_VISIBLE,
        1,
        0,
        0,
        0,
        0,
        0,
    ) == 0, f);

    // CURSOR_SET_TYPE
    p.* += helpers.doTest("CURSOR_TYPE", syscall_dispatcher.dispatch(
        numbers.SYS_CURSOR_SET_TYPE,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == 0, f);

    // SCREEN_GET_ORIENTATION
    const orient = syscall_dispatcher.dispatch(
        numbers.SYS_SCREEN_GET_ORIENTATION,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("SCREEN_ORIENT", orient >= 0 or orient == numbers.ENODEV, f);

    // INPUT_POLL — returns 0 (no input) or 1 (got key)
    var event_buf: [64]u8 = [_]u8{0} ** 64;
    const poll_r = syscall_dispatcher.dispatch(
        numbers.SYS_INPUT_POLL,
        @intFromPtr(&event_buf),
        0,
        0,
        0,
        0,
        0,
    );
    p.* += helpers.doTest("INPUT_POLL", poll_r >= 0, f);

    // INPUT_POLL null → EFAULT
    p.* += helpers.doTest("INPUT_POLL null", syscall_dispatcher.dispatch(
        numbers.SYS_INPUT_POLL,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EFAULT, f);

    // INPUT_GET_TOUCH_CAPS
    var touch_buf: [16]u8 = [_]u8{0} ** 16;
    p.* += helpers.doTest("TOUCH_CAPS", syscall_dispatcher.dispatch(
        numbers.SYS_INPUT_GET_TOUCH_CAPS,
        @intFromPtr(&touch_buf),
        0,
        0,
        0,
        0,
        0,
    ) == 0, f);

    // TOUCH_CAPS null → EFAULT
    p.* += helpers.doTest("TOUCH_CAPS null", syscall_dispatcher.dispatch(
        numbers.SYS_INPUT_GET_TOUCH_CAPS,
        0,
        0,
        0,
        0,
        0,
        0,
    ) == numbers.EFAULT, f);
}

fn runGuiTests() void {
    shell.printInfoLine("Testing SC9: GUI Prep...");
    var p: u32 = 0;
    var f: u32 = 0;
    runGuiTestsInline(&p, &f);
    helpers.printTestResults(p, f);
}

// =============================================================================
// List & Stats & Manual Call
// =============================================================================

fn showList() void {
    shell.printInfoLine("Syscall Number Ranges (SC1-SC6):");
    shell.println("  0-49:     Core POSIX (read, write, open, close, getpid...)");
    shell.println("  50-99:    Process (fork, exec, wait, kill...)");
    shell.println("  100-119:  Identity (create, unlock, lock, sign...)");
    shell.println("  120-139:  Integrity (register, verify, quarantine...)");
    shell.println("  140-159:  Boot/Security (status, policy...)");
    shell.println("  160-179:  Crypto (hash, random, sign, verify...)");
    shell.println("  180-199:  Chain/Blockchain");
    shell.println("  200-209:  IPC (msg send/recv, pipe, signal) [SC3]");
    shell.println("  210-219:  Shared Memory (create/attach/rw/destroy) [SC4]");
    shell.println("  220-229:  User/Auth (setuid, login, logout...) [SC5]");
    shell.println("  230-239:  Process Extended (spawn, kill, yield...) [SC2]");
    shell.println("  240-249:  Capability (get, check, drop)");
    shell.println("  250-259:  Network (socket, bind, listen, send...) [SC6]");
    shell.println("  260-269:  Encrypted FS (write/read/setkey/status) [SC7]");
    shell.println("  270-279:  ELF/ZAM Loader (exec_elf, exec_zam) [SC7]");
    shell.println("  280-289:  FS Extended (stat, readdir, seek...) [SC8]");
    shell.println("  300-319:  Graphics/Framebuffer [SC9]");
    shell.println("  320-339:  Input (poll, wait, touch) [SC9]");
    shell.println("  400-419:  Zamrud Debug (ticks, uptime, count...)");
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
    const result = syscall_dispatcher.dispatch(num, 0, 0, 0, 0, 0, 0);
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
