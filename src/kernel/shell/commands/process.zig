//! Zamrud OS - Process Commands (E3.1: with Capability Display)
//! ps, spawn, kill, sched, caps, grant, revoke

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const process = @import("../../proc/process.zig");
const scheduler = @import("../../proc/scheduler.zig");
const test_procs = @import("../../proc/test_procs.zig");
const capability = @import("../../security/capability.zig");

pub fn cmdPs(_: []const u8) void {
    shell.printInfoLine("Process List:");
    shell.println("  PID   STATE       PRI  CAPABILITIES");
    shell.println("  ----  ----------  ---  --------------------------------");

    var count: u32 = 0;
    var i: usize = 0;

    while (i < 8) : (i += 1) {
        if (process.process_used[i]) {
            const info = process.getProcessInfo(i) orelse continue;

            shell.print("  ");
            helpers.printU32(info.pid);
            shell.print("     ");

            switch (@intFromEnum(info.state)) {
                0 => shell.print("Created   "),
                1 => shell.print("Ready     "),
                2 => shell.print("Running   "),
                3 => shell.print("Blocked   "),
                4 => shell.print("Terminated"),
                else => shell.print("???       "),
            }

            shell.print("  ");
            helpers.printU8(info.priority);
            shell.print("  ");

            // Format capability flags
            var cap_buf: [64]u8 = undefined;
            const cap_len = capability.formatCaps(info.caps, &cap_buf);
            if (cap_len > 0) {
                shell.print(cap_buf[0..cap_len]);
            } else {
                shell.print("NONE");
            }
            shell.newLine();

            count += 1;
        }
    }

    shell.println("  ----  ----------  ---  --------------------------------");
    shell.print("  Total: ");
    helpers.printU32(count);
    shell.println(" processes");
}

pub fn cmdSpawn(_: []const u8) void {
    shell.printInfoLine("Spawning test process...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithEntry(
        "counter",
        @intFromPtr(&test_procs.counterProcess),
        id,
    );

    if (pid_result) |p| {
        shell.printSuccess("Created process PID: ");
        helpers.printU32(p);
        shell.newLine();
    } else {
        shell.printErrorLine("Failed to create process!");
    }
}

/// Spawn a sandboxed process with limited capabilities
pub fn cmdSpawnSandbox(_: []const u8) void {
    shell.printInfoLine("Spawning sandboxed process (FS_READ only)...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithCaps(
        "sandboxed",
        @intFromPtr(&test_procs.counterProcess),
        id,
        capability.CAP_MINIMAL,
    );

    if (pid_result) |p| {
        shell.printSuccess("Sandboxed PID: ");
        helpers.printU32(p);
        shell.println(" (caps: FS_READ only)");
    } else {
        shell.printErrorLine("Failed to create sandboxed process!");
    }
}

pub fn cmdKill(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("kill: usage: kill <pid>");
        return;
    }

    const pid_val = helpers.parseU32(trimmed) orelse {
        shell.printErrorLine("kill: invalid PID");
        return;
    };

    if (pid_val == 0) {
        shell.printErrorLine("Cannot kill idle process (PID 0)!");
        return;
    }

    if (process.terminate(pid_val)) {
        shell.printSuccessLine("Process terminated");
    } else {
        shell.printErrorLine("Process not found!");
    }
}

pub fn cmdSched(_: []const u8) void {
    shell.printInfoLine("Scheduler Status:");

    shell.print("  Enabled: ");
    if (scheduler.isEnabled()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }

    shell.print("  Ticks: ");
    helpers.printU64(scheduler.getTicks());
    shell.newLine();

    shell.print("  Switches: ");
    helpers.printU64(scheduler.getSwitchCount());
    shell.newLine();

    shell.print("  Processes: ");
    helpers.printU32(process.getCount());
    shell.newLine();
}

pub fn cmdSchedEnable(_: []const u8) void {
    scheduler.enable();
    shell.printSuccessLine("Scheduler enabled");
}

pub fn cmdSchedDisable(_: []const u8) void {
    scheduler.disable();
    shell.printWarningLine("Scheduler disabled");
}

// =============================================================================
// E3.1: Capability Management Commands
// =============================================================================

/// Show capabilities for all processes, specific PID, or run tests
pub fn cmdCaps(args: []const u8) void {
    const trimmed = helpers.trim(args);

    // Handle subcommands
    if (trimmed.len > 0) {
        // caps test - run capability tests
        if (helpers.strEql(trimmed, "test")) {
            runCapabilityTest();
            return;
        }

        // caps help
        if (helpers.strEql(trimmed, "help")) {
            printCapsHelp();
            return;
        }

        // caps list - same as no args
        if (helpers.strEql(trimmed, "list")) {
            showAllCaps();
            return;
        }

        // caps <pid> - show specific PID
        const pid_val = helpers.parseU32(trimmed) orelse {
            shell.printErrorLine("caps: unknown subcommand or invalid PID");
            shell.println("  Usage: caps [test|list|help|<pid>]");
            return;
        };

        showPidCaps(pid_val);
        return;
    }

    // No args: show all
    showAllCaps();
}

fn printCapsHelp() void {
    shell.printInfoLine("Capability Commands:");
    shell.println("  caps              Show all process capabilities");
    shell.println("  caps <pid>        Show caps for specific PID");
    shell.println("  caps list         Same as 'caps'");
    shell.println("  caps test         Run capability system tests");
    shell.println("  caps help         This help message");
    shell.println("");
    shell.println("  grant <pid> <cap> Grant capability to process");
    shell.println("  revoke <pid> <cap> Revoke capability from process");
    shell.println("  sandbox           Spawn sandboxed process");
    shell.println("  violations        Show security violations");
    shell.println("");
    shell.println("  Available caps:");
    shell.println("    NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
    shell.println("    GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
}

fn showAllCaps() void {
    shell.printInfoLine("Process Capabilities:");
    shell.println("  PID   CAPS(hex)   FLAGS                VIOLATIONS");
    shell.println("  ----  ----------  -------------------  ----------");

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (process.process_used[i]) {
            const info = process.getProcessInfo(i) orelse continue;

            shell.print("  ");
            helpers.printU32(info.pid);
            shell.print("     0x");
            helpers.printHexU32(info.caps);
            shell.print("  ");

            var buf: [64]u8 = undefined;
            const len = capability.formatCaps(info.caps, &buf);

            // Print caps with padding
            if (len > 0) {
                shell.print(buf[0..len]);
            } else {
                shell.print("NONE");
            }

            // Pad to column
            var pad: usize = if (len < 20) 20 - len else 1;
            while (pad > 0) : (pad -= 1) {
                shell.print(" ");
            }

            // Violation count
            const vcount = capability.getViolationCount(info.pid);
            helpers.printU32(@as(u32, vcount));
            if (vcount >= capability.KILL_THRESHOLD) {
                shell.print(" (!)");
            }
            shell.newLine();
        }
    }

    shell.println("  ----  ----------  -------------------  ----------");
    shell.print("  Total violations: ");
    helpers.printU64(capability.getTotalViolations());
    shell.newLine();
}

fn showPidCaps(pid_val: u32) void {
    const caps = process.getProcessCaps(pid_val);

    shell.printInfoLine("Capability Details:");
    shell.print("  PID:        ");
    helpers.printU32(pid_val);
    shell.newLine();

    shell.print("  Caps (hex): 0x");
    helpers.printHexU32(caps);
    shell.newLine();

    shell.print("  Caps (str): ");
    var buf: [64]u8 = undefined;
    const len = capability.formatCaps(caps, &buf);
    shell.println(buf[0..len]);

    shell.println("");
    shell.println("  Individual Capabilities:");

    const cap_list = [_]struct { bit: u32, name: []const u8 }{
        .{ .bit = capability.CAP_NET, .name = "NET        - Network access" },
        .{ .bit = capability.CAP_FS_READ, .name = "FS_READ    - Filesystem read" },
        .{ .bit = capability.CAP_FS_WRITE, .name = "FS_WRITE   - Filesystem write" },
        .{ .bit = capability.CAP_IPC, .name = "IPC        - Inter-process communication" },
        .{ .bit = capability.CAP_EXEC, .name = "EXEC       - Execute/spawn processes" },
        .{ .bit = capability.CAP_DEVICE, .name = "DEVICE     - Direct device access" },
        .{ .bit = capability.CAP_GRAPHICS, .name = "GRAPHICS   - Framebuffer/display" },
        .{ .bit = capability.CAP_CRYPTO, .name = "CRYPTO     - Crypto operations" },
        .{ .bit = capability.CAP_CHAIN, .name = "CHAIN      - Blockchain operations" },
        .{ .bit = capability.CAP_ADMIN, .name = "ADMIN      - Admin/root operations" },
        .{ .bit = capability.CAP_RAW_IO, .name = "RAW_IO     - Raw I/O port access" },
        .{ .bit = capability.CAP_MEMORY, .name = "MEMORY     - Direct memory mapping" },
    };

    for (cap_list) |cap| {
        shell.print("    ");
        if ((caps & cap.bit) != 0) {
            shell.print("[*] ");
        } else {
            shell.print("[ ] ");
        }
        shell.println(cap.name);
    }

    // Violation info
    shell.println("");
    const vcount = capability.getViolationCount(pid_val);
    shell.print("  Violations: ");
    helpers.printU32(@as(u32, vcount));
    if (vcount >= capability.KILL_THRESHOLD) {
        shell.printErrorLine(" (KILL THRESHOLD REACHED!)");
    } else if (vcount > 0) {
        shell.print("/");
        helpers.printU32(@as(u32, capability.KILL_THRESHOLD));
        shell.println(" until auto-kill");
    } else {
        shell.printSuccessLine(" (clean)");
    }
}

/// Grant capability: grant <pid> <cap_name>
pub fn cmdGrant(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("grant: usage: grant <pid> <cap>");
        shell.println("  Caps: NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
        shell.println("        GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
        return;
    }

    // Parse PID (first token)
    var space_idx: usize = 0;
    while (space_idx < trimmed.len and trimmed[space_idx] != ' ') : (space_idx += 1) {}

    if (space_idx >= trimmed.len) {
        shell.printErrorLine("grant: usage: grant <pid> <cap>");
        return;
    }

    const pid_str = trimmed[0..space_idx];
    var cap_start = space_idx + 1;
    while (cap_start < trimmed.len and trimmed[cap_start] == ' ') : (cap_start += 1) {}
    const cap_str = trimmed[cap_start..];

    const pid_val = helpers.parseU32(pid_str) orelse {
        shell.printErrorLine("grant: invalid PID");
        return;
    };

    const cap = parseCapName(cap_str) orelse {
        shell.printErrorLine("grant: unknown capability");
        shell.println("  Valid: NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
        shell.println("         GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
        return;
    };

    if (process.grantProcessCap(pid_val, cap)) {
        shell.printSuccess("Granted ");
        shell.print(cap_str);
        shell.print(" to PID ");
        helpers.printU32(pid_val);
        shell.newLine();
    } else {
        shell.printErrorLine("Process not found!");
    }
}

/// Revoke capability: revoke <pid> <cap_name>
pub fn cmdRevoke(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("revoke: usage: revoke <pid> <cap>");
        return;
    }

    var space_idx: usize = 0;
    while (space_idx < trimmed.len and trimmed[space_idx] != ' ') : (space_idx += 1) {}

    if (space_idx >= trimmed.len) {
        shell.printErrorLine("revoke: usage: revoke <pid> <cap>");
        return;
    }

    const pid_str = trimmed[0..space_idx];
    var cap_start = space_idx + 1;
    while (cap_start < trimmed.len and trimmed[cap_start] == ' ') : (cap_start += 1) {}
    const cap_str = trimmed[cap_start..];

    const pid_val = helpers.parseU32(pid_str) orelse {
        shell.printErrorLine("revoke: invalid PID");
        return;
    };

    if (pid_val == 0) {
        shell.printErrorLine("Cannot revoke from kernel (PID 0)!");
        return;
    }

    const cap = parseCapName(cap_str) orelse {
        shell.printErrorLine("revoke: unknown capability");
        return;
    };

    if (process.revokeProcessCap(pid_val, cap)) {
        shell.printSuccess("Revoked ");
        shell.print(cap_str);
        shell.print(" from PID ");
        helpers.printU32(pid_val);
        shell.newLine();
    } else {
        shell.printErrorLine("Process not found!");
    }
}

/// Show violation log
pub fn cmdViolations(_: []const u8) void {
    if (!capability.isInitialized()) {
        shell.printErrorLine("Capability system not initialized!");
        return;
    }

    shell.printInfoLine("Security Violations:");
    shell.print("  Total violations: ");
    helpers.printU64(capability.getTotalViolations());
    shell.newLine();
    shell.print("  Kill threshold:   ");
    helpers.printU32(@as(u32, capability.KILL_THRESHOLD));
    shell.println(" violations");

    if (capability.getTotalViolations() == 0) {
        shell.newLine();
        shell.printSuccessLine("  No violations recorded. System clean.");
        return;
    }

    shell.newLine();
    shell.println("  PID   ATTEMPTED    SYSCALL   TIME");
    shell.println("  ----  -----------  --------  ----------");

    var recent: [16]capability.Violation = undefined;
    const count = capability.getRecentViolations(&recent);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        shell.print("  ");
        helpers.printU32(recent[i].pid);
        shell.print("     ");

        var buf: [16]u8 = undefined;
        const len = capability.formatCaps(recent[i].attempted_cap, &buf);
        shell.print(buf[0..len]);

        // Pad
        var pad: usize = if (len < 12) 12 - len else 1;
        while (pad > 0) : (pad -= 1) shell.print(" ");

        helpers.printU64(recent[i].syscall_num);
        shell.print("      ");
        helpers.printU64(recent[i].timestamp);
        shell.newLine();
    }
}

// =============================================================================
// E3.1: Capability Test Suite
// =============================================================================

fn runCapabilityTest() void {
    shell.newLine();
    shell.println("  ========================================");
    shell.println("    E3.1 CAPABILITY SYSTEM TEST SUITE");
    shell.println("  ========================================");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: System initialized
    passed += helpers.doTest("Cap system init", capability.isInitialized(), &failed);

    // Test 2: PID 0 has ALL caps
    passed += helpers.doTest("PID 0 = CAP_ALL", capability.getCaps(0) == capability.CAP_ALL, &failed);

    // Test 3: PID 0 check always passes
    const pid0_net = capability.check(0, capability.CAP_NET);
    const pid0_admin = capability.check(0, capability.CAP_ADMIN);
    const pid0_all = capability.check(0, capability.CAP_ALL);
    passed += helpers.doTest("PID 0 passes all checks", pid0_net and pid0_admin and pid0_all, &failed);

    // Test 4: Register process with specific caps
    const test_pid: u32 = 98;
    const test_caps = capability.CAP_FS_READ | capability.CAP_IPC;
    const reg_ok = capability.registerProcess(test_pid, test_caps);
    passed += helpers.doTest("Register process", reg_ok, &failed);

    // Test 5: Check granted caps work
    const has_read = capability.check(test_pid, capability.CAP_FS_READ);
    const has_ipc = capability.check(test_pid, capability.CAP_IPC);
    passed += helpers.doTest("Granted caps pass", has_read and has_ipc, &failed);

    // Test 6: Check denied caps fail
    const no_net = !capability.check(test_pid, capability.CAP_NET);
    const no_admin = !capability.check(test_pid, capability.CAP_ADMIN);
    const no_exec = !capability.check(test_pid, capability.CAP_EXEC);
    passed += helpers.doTest("Denied caps blocked", no_net and no_admin and no_exec, &failed);

    // Test 7: Grant capability
    const grant_ok = capability.grantCap(test_pid, capability.CAP_NET);
    const now_has_net = capability.check(test_pid, capability.CAP_NET);
    passed += helpers.doTest("Grant cap works", grant_ok and now_has_net, &failed);

    // Test 8: Revoke capability
    const revoke_ok = capability.revokeCap(test_pid, capability.CAP_NET);
    const no_net_now = !capability.check(test_pid, capability.CAP_NET);
    passed += helpers.doTest("Revoke cap works", revoke_ok and no_net_now, &failed);

    // Test 9: Still has original caps after grant/revoke
    const still_read = capability.check(test_pid, capability.CAP_FS_READ);
    const still_ipc = capability.check(test_pid, capability.CAP_IPC);
    passed += helpers.doTest("Original caps preserved", still_read and still_ipc, &failed);

    // Test 10: Set caps (replace all)
    const set_ok = capability.setCaps(test_pid, capability.CAP_GRAPHICS | capability.CAP_CRYPTO);
    const has_gfx = capability.check(test_pid, capability.CAP_GRAPHICS);
    const has_cry = capability.check(test_pid, capability.CAP_CRYPTO);
    const lost_read = !capability.check(test_pid, capability.CAP_FS_READ);
    passed += helpers.doTest("Set caps (replace)", set_ok and has_gfx and has_cry and lost_read, &failed);

    // Test 11: formatCaps output
    var buf: [64]u8 = undefined;
    const len1 = capability.formatCaps(capability.CAP_ALL, &buf);
    const is_all = helpers.strEql(buf[0..len1], "ALL");
    passed += helpers.doTest("Format ALL", is_all, &failed);

    // Test 12: formatCaps NONE
    const len2 = capability.formatCaps(capability.CAP_NONE, &buf);
    const is_none = helpers.strEql(buf[0..len2], "NONE");
    passed += helpers.doTest("Format NONE", is_none, &failed);

    // Test 13: formatCaps specific
    const len3 = capability.formatCaps(capability.CAP_NET | capability.CAP_FS_READ, &buf);
    passed += helpers.doTest("Format NET|R", len3 > 0, &failed);

    // Test 14: Violation recording
    const pre_viol = capability.getTotalViolations();
    capability.recordViolationPublic(test_pid, capability.CAP_ADMIN, 999, 12345);
    const post_viol = capability.getTotalViolations();
    passed += helpers.doTest("Violation recorded", post_viol == pre_viol + 1, &failed);

    // Test 15: Per-PID violation count
    const pid_viol = capability.getViolationCount(test_pid);
    passed += helpers.doTest("PID violation count", pid_viol >= 1, &failed);

    // Test 16: checkAndEnforce (should fail and record)
    const pre_v2 = capability.getTotalViolations();
    const enforce_result = capability.checkAndEnforce(test_pid, capability.CAP_ADMIN, 777, 99999);
    const post_v2 = capability.getTotalViolations();
    passed += helpers.doTest("checkAndEnforce deny", !enforce_result and post_v2 == pre_v2 + 1, &failed);

    // Test 17: checkAndEnforce (should pass)
    const enforce_pass = capability.checkAndEnforce(test_pid, capability.CAP_GRAPHICS, 100, 100);
    passed += helpers.doTest("checkAndEnforce allow", enforce_pass, &failed);

    // Test 18: Recent violations retrieval
    var recent: [8]capability.Violation = undefined;
    const recent_count = capability.getRecentViolations(&recent);
    passed += helpers.doTest("Recent violations", recent_count >= 1, &failed);

    // Test 19: Syscall->cap mapping
    const read_cap = capability.syscallRequiredCap(0); // SYS_READ
    const write_cap = capability.syscallRequiredCap(1); // SYS_WRITE
    const exit_cap = capability.syscallRequiredCap(60); // SYS_EXIT = none
    passed += helpers.doTest("Syscall->cap mapping", read_cap == capability.CAP_FS_READ and write_cap == capability.CAP_FS_WRITE and exit_cap == capability.CAP_NONE, &failed);

    // Test 20: checkWrite special (stdout always allowed)
    const stdout_ok = capability.checkWrite(test_pid, 1);
    const stderr_ok = capability.checkWrite(test_pid, 2);
    passed += helpers.doTest("stdout/stderr bypass", stdout_ok and stderr_ok, &failed);

    // Test 21: Unregister cleanup
    capability.unregisterProcess(test_pid);
    const after_unreg = capability.getViolationCount(test_pid);
    passed += helpers.doTest("Unregister clears count", after_unreg == 0, &failed);

    // Test 22: Unregistered process gets ALL (backward compat)
    const unreg_caps = capability.getCaps(test_pid);
    passed += helpers.doTest("Unregistered = CAP_ALL", unreg_caps == capability.CAP_ALL, &failed);

    // Test 23: Process integration - spawn with caps
    const spawn_pid = process.createWithCaps("test", @intFromPtr(&dummyEntry), 0, capability.CAP_FS_READ | capability.CAP_NET);
    if (spawn_pid) |spid| {
        const spawn_caps = process.getProcessCaps(spid);
        const spawn_ok = (spawn_caps & capability.CAP_FS_READ) != 0 and
            (spawn_caps & capability.CAP_NET) != 0 and
            (spawn_caps & capability.CAP_ADMIN) == 0;
        passed += helpers.doTest("Process spawn with caps", spawn_ok, &failed);

        // Test 24: Process grant/revoke
        const pg_ok = process.grantProcessCap(spid, capability.CAP_EXEC);
        const has_exec = (process.getProcessCaps(spid) & capability.CAP_EXEC) != 0;
        passed += helpers.doTest("Process grant cap", pg_ok and has_exec, &failed);

        const pr_ok = process.revokeProcessCap(spid, capability.CAP_NET);
        const no_net_p = (process.getProcessCaps(spid) & capability.CAP_NET) == 0;
        passed += helpers.doTest("Process revoke cap", pr_ok and no_net_p, &failed);

        // Cleanup
        _ = process.terminate(spid);
    } else {
        helpers.doSkip("Process spawn with caps");
        helpers.doSkip("Process grant cap");
        helpers.doSkip("Process revoke cap");
    }

    // Print results
    helpers.printTestResults(passed, failed);
}

fn dummyEntry() void {
    // Dummy process entry for testing
    while (true) {
        asm volatile ("hlt");
    }
}

// =============================================================================
// Cap Name Parser
// =============================================================================

fn parseCapName(name: []const u8) ?u32 {
    if (strEqlIgnoreCase(name, "NET")) return capability.CAP_NET;
    if (strEqlIgnoreCase(name, "FS_READ")) return capability.CAP_FS_READ;
    if (strEqlIgnoreCase(name, "FS_WRITE")) return capability.CAP_FS_WRITE;
    if (strEqlIgnoreCase(name, "IPC")) return capability.CAP_IPC;
    if (strEqlIgnoreCase(name, "EXEC")) return capability.CAP_EXEC;
    if (strEqlIgnoreCase(name, "DEVICE")) return capability.CAP_DEVICE;
    if (strEqlIgnoreCase(name, "GRAPHICS")) return capability.CAP_GRAPHICS;
    if (strEqlIgnoreCase(name, "CRYPTO")) return capability.CAP_CRYPTO;
    if (strEqlIgnoreCase(name, "CHAIN")) return capability.CAP_CHAIN;
    if (strEqlIgnoreCase(name, "ADMIN")) return capability.CAP_ADMIN;
    if (strEqlIgnoreCase(name, "RAW_IO")) return capability.CAP_RAW_IO;
    if (strEqlIgnoreCase(name, "MEMORY")) return capability.CAP_MEMORY;
    if (strEqlIgnoreCase(name, "ALL")) return capability.CAP_ALL;
    if (strEqlIgnoreCase(name, "NONE")) return capability.CAP_NONE;
    return null;
}

fn strEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la: u8 = if (ca >= 'a' and ca <= 'z') ca - 32 else ca;
        const lb: u8 = if (cb >= 'a' and cb <= 'z') cb - 32 else cb;
        if (la != lb) return false;
    }
    return true;
}
