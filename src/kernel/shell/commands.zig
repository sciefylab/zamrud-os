//! Zamrud OS - Shell Commands Main Dispatcher

const shell = @import("shell.zig");

// Import all command modules
const helpers = @import("commands/helpers.zig");
const system = @import("commands/system.zig");
const filesystem = @import("commands/filesystem.zig");
const device = @import("commands/device.zig");
const process_cmd = @import("commands/process.zig");
const crypto_cmd = @import("commands/crypto.zig");
const chain_cmd = @import("commands/chain.zig");
const integrity_cmd = @import("commands/integrity.zig");
const identity_cmd = @import("commands/identity.zig");
const syscall_cmd = @import("commands/syscall.zig");
const boot_cmd = @import("commands/boot.zig");
const power_cmd = @import("commands/power.zig");
const network_cmd = @import("commands/network.zig");
const p2p_cmd = @import("commands/p2p.zig");
const gateway_cmd = @import("commands/gateway.zig");
const security_cmd = @import("commands/security.zig");
const smoke_cmd = @import("commands/smoke.zig");
const disk_cmd = @import("commands/disk.zig");
const config_cmd = @import("commands/config.zig");

// =============================================================================
// Command Execution
// =============================================================================

pub fn execute(input: []const u8) void {
    const parsed = helpers.parseArgs(input);
    const command = parsed.cmd;
    const args = parsed.rest;

    if (command.len == 0) return;

    // System commands
    if (helpers.strEql(command, "help")) {
        system.cmdHelp(args);
    } else if (helpers.strEql(command, "clear")) {
        system.cmdClear(args);
    } else if (helpers.strEql(command, "info")) {
        system.cmdInfo(args);
    } else if (helpers.strEql(command, "uptime")) {
        system.cmdUptime(args);
    } else if (helpers.strEql(command, "mem") or helpers.strEql(command, "memory")) {
        system.cmdMemory(args);
    } else if (helpers.strEql(command, "history")) {
        system.cmdHistory(args);
    } else if (helpers.strEql(command, "echo")) {
        system.cmdEcho(args);
    } else if (helpers.strEql(command, "theme")) {
        system.cmdTheme(args);
    }
    // Filesystem commands
    else if (helpers.strEql(command, "ls")) {
        filesystem.cmdLs(args);
    } else if (helpers.strEql(command, "cd")) {
        filesystem.cmdCd(args);
    } else if (helpers.strEql(command, "pwd")) {
        filesystem.cmdPwd(args);
    } else if (helpers.strEql(command, "mkdir")) {
        filesystem.cmdMkdir(args);
    } else if (helpers.strEql(command, "touch")) {
        filesystem.cmdTouch(args);
    } else if (helpers.strEql(command, "rm")) {
        filesystem.cmdRm(args);
    } else if (helpers.strEql(command, "rmdir")) {
        filesystem.cmdRmdir(args);
    } else if (helpers.strEql(command, "cat")) {
        filesystem.cmdCat(args);
    } else if (helpers.strEql(command, "write")) {
        filesystem.cmdWrite(args);
    }
    // Device commands
    else if (helpers.strEql(command, "lsdev")) {
        device.cmdLsDev(args);
    } else if (helpers.strEql(command, "devtest")) {
        device.cmdDevTest(args);
    }
    // Disk commands
    else if (helpers.strEql(command, "disk")) {
        disk_cmd.execute(args);
    } else if (helpers.strEql(command, "diskinfo")) {
        disk_cmd.execute("list");
    }
    // Config commands (D3)
    else if (helpers.strEql(command, "config")) {
        config_cmd.execute(args);
    }
    // Process commands
    else if (helpers.strEql(command, "ps")) {
        process_cmd.cmdPs(args);
    } else if (helpers.strEql(command, "spawn")) {
        process_cmd.cmdSpawn(args);
    } else if (helpers.strEql(command, "kill")) {
        process_cmd.cmdKill(args);
    } else if (helpers.strEql(command, "sched")) {
        process_cmd.cmdSched(args);
    } else if (helpers.strEql(command, "sched-enable")) {
        process_cmd.cmdSchedEnable(args);
    } else if (helpers.strEql(command, "sched-disable")) {
        process_cmd.cmdSchedDisable(args);
    }
    // === E3.1: Capability Commands ===
    else if (helpers.strEql(command, "caps")) {
        process_cmd.cmdCaps(args);
    } else if (helpers.strEql(command, "grant")) {
        process_cmd.cmdGrant(args);
    } else if (helpers.strEql(command, "revoke")) {
        process_cmd.cmdRevoke(args);
    } else if (helpers.strEql(command, "violations")) {
        process_cmd.cmdViolations(args);
    } else if (helpers.strEql(command, "sandbox")) {
        process_cmd.cmdSpawnSandbox(args);
    }
    // Crypto command
    else if (helpers.strEql(command, "crypto")) {
        crypto_cmd.execute(args);
    }
    // Chain command
    else if (helpers.strEql(command, "chain")) {
        chain_cmd.execute(args);
    }
    // Integrity command
    else if (helpers.strEql(command, "integrity")) {
        integrity_cmd.execute(args);
    }
    // Identity commands
    else if (helpers.strEql(command, "identity")) {
        identity_cmd.execute(args);
    } else if (helpers.strEql(command, "whoami")) {
        identity_cmd.whoami();
    }
    // Network commands
    else if (helpers.strEql(command, "net")) {
        network_cmd.execute(args);
    } else if (helpers.strEql(command, "ifconfig") or helpers.strEql(command, "ip")) {
        network_cmd.cmdIfconfig(args);
    } else if (helpers.strEql(command, "ping")) {
        network_cmd.cmdPing(args);
    } else if (helpers.strEql(command, "netstat")) {
        network_cmd.cmdNetstat(args);
    } else if (helpers.strEql(command, "arp")) {
        network_cmd.cmdArp(args);
    } else if (helpers.strEql(command, "nettest")) {
        network_cmd.runTest("all");
    }
    // P2P commands
    else if (helpers.strEql(command, "p2p")) {
        p2p_cmd.execute(args);
    }
    // Gateway commands
    else if (helpers.strEql(command, "gateway") or helpers.strEql(command, "gw")) {
        gateway_cmd.execute(args);
    }
    // Security commands
    else if (helpers.strEql(command, "security")) {
        security_cmd.execute(args);
    } else if (helpers.strEql(command, "firewall")) {
        var buffer: [256]u8 = undefined;
        var len: usize = 0;

        const prefix = "firewall ";
        for (prefix) |c| {
            if (len < buffer.len) {
                buffer[len] = c;
                len += 1;
            }
        }

        for (args) |c| {
            if (len < buffer.len) {
                buffer[len] = c;
                len += 1;
            }
        }

        security_cmd.execute(buffer[0..len]);
    }
    // Smoke test command
    else if (helpers.strEql(command, "smoke")) {
        smoke_cmd.execute(args);
    }
    // Syscall command
    else if (helpers.strEql(command, "syscall")) {
        syscall_cmd.execute(args);
    }
    // Boot command
    else if (helpers.strEql(command, "boot")) {
        boot_cmd.execute(args);
    }
    // Power commands
    else if (helpers.strEql(command, "reboot")) {
        power_cmd.reboot();
    } else if (helpers.strEql(command, "shutdown") or helpers.strEql(command, "halt")) {
        power_cmd.shutdown();
    } else if (helpers.strEql(command, "exit")) {
        power_cmd.exit();
    } else if (helpers.strEql(command, "power")) {
        power_cmd.execute(args);
    }
    // Test all command
    else if (helpers.strEql(command, "testall")) {
        runAllTests();
    }
    // Unknown command
    else {
        shell.printError("Unknown command: ");
        shell.print(command);
        shell.newLine();
        shell.println("  Type 'help' for available commands");
    }
}

// =============================================================================
// Test All - Comprehensive System Test
// =============================================================================

fn runAllTests() void {
    const helpers_mod = @import("commands/helpers.zig");

    helpers_mod.printTestHeader("ZAMRUD OS - COMPLETE TEST SUITE");

    // 0. Smoke tests
    shell.printInfoLine("=== SMOKE TESTS ===");
    smoke_cmd.execute("run");
    shell.newLine();

    // 1. Network tests
    shell.printInfoLine("=== NETWORK TESTS ===");
    network_cmd.runTest("all");
    shell.newLine();

    // 2. P2P tests
    shell.printInfoLine("=== P2P TESTS ===");
    p2p_cmd.runTest("all");
    shell.newLine();

    // 3. Gateway tests
    shell.printInfoLine("=== GATEWAY TESTS ===");
    gateway_cmd.execute("test");
    shell.newLine();

    // 4. Security/Firewall tests
    shell.printInfoLine("=== SECURITY/FIREWALL TESTS ===");
    security_cmd.runTest("all");
    shell.newLine();

    // 5. Crypto tests
    shell.printInfoLine("=== CRYPTO TESTS ===");
    crypto_cmd.execute("test");
    shell.newLine();

    // 6. Syscall tests
    shell.printInfoLine("=== SYSCALL TESTS ===");
    syscall_cmd.execute("test");
    shell.newLine();

    // 7. Boot tests
    shell.printInfoLine("=== BOOT TESTS ===");
    boot_cmd.execute("test");
    shell.newLine();

    // 8. Disk tests
    shell.printInfoLine("=== DISK TESTS ===");
    disk_cmd.execute("test");
    shell.newLine();

    // 9. Config persistence tests (D3)
    shell.printInfoLine("=== CONFIG PERSISTENCE TESTS ===");
    config_cmd.execute("test");
    shell.newLine();

    // 10. Capability tests (E3.1)
    shell.printInfoLine("=== CAPABILITY TESTS (E3.1) ===");
    runCapabilityTests();
    shell.newLine();

    // Final summary
    shell.printInfoLine("########################################");
    shell.printInfoLine("##  COMPLETE TEST SUITE FINISHED      ##");
    shell.printInfoLine("########################################");
    shell.newLine();
}

// =============================================================================
// E3.1: Capability Inline Tests
// =============================================================================

fn runCapabilityTests() void {
    const capability = @import("../security/capability.zig");

    // Test 1: System initialized
    shell.print("  Cap system init:    ");
    if (capability.isInitialized()) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 2: PID 0 has ALL
    shell.print("  PID 0 = ALL caps:   ");
    if (capability.getCaps(0) == capability.CAP_ALL) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 3: PID 0 check always passes
    shell.print("  PID 0 check pass:   ");
    if (capability.check(0, capability.CAP_NET) and capability.check(0, capability.CAP_ADMIN)) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 4: Register + check
    shell.print("  Register+check:     ");
    const test_pid: u32 = 99;
    _ = capability.registerProcess(test_pid, capability.CAP_FS_READ | capability.CAP_IPC);

    const has_read = capability.check(test_pid, capability.CAP_FS_READ);
    const has_ipc = capability.check(test_pid, capability.CAP_IPC);
    const no_net = !capability.check(test_pid, capability.CAP_NET);
    const no_admin = !capability.check(test_pid, capability.CAP_ADMIN);

    if (has_read and has_ipc and no_net and no_admin) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 5: Grant
    shell.print("  Grant cap:          ");
    _ = capability.grantCap(test_pid, capability.CAP_NET);
    if (capability.check(test_pid, capability.CAP_NET)) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 6: Revoke
    shell.print("  Revoke cap:         ");
    _ = capability.revokeCap(test_pid, capability.CAP_NET);
    if (!capability.check(test_pid, capability.CAP_NET)) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 7: formatCaps
    shell.print("  Format caps:        ");
    var buf: [64]u8 = undefined;
    const len = capability.formatCaps(capability.CAP_FS_READ | capability.CAP_IPC, &buf);
    if (len > 0) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Test 8: Violations initially 0
    shell.print("  Zero violations:    ");
    const pre_count = capability.getTotalViolations();
    // Record a test violation
    capability.recordViolationPublic(test_pid, capability.CAP_ADMIN, 999, 12345);
    if (capability.getTotalViolations() == pre_count + 1) {
        shell.printSuccessLine("PASS");
    } else {
        shell.printErrorLine("FAIL");
    }

    // Cleanup
    capability.unregisterProcess(test_pid);

    shell.printInfoLine("  Capability tests complete");
}
