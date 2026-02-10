//! Zamrud OS - Shell Commands Main Dispatcher
//! Phases A-E3.4 Complete

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

// E3.4: Network Capability - direct kernel import for inline commands
const net_capability = @import("../security/net_capability.zig");
const terminal = @import("../drivers/display/terminal.zig");

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
    // === E3.2: Unveil Commands ===
    else if (helpers.strEql(command, "unveil")) {
        process_cmd.cmdUnveil(args);
    } else if (helpers.strEql(command, "paths")) {
        process_cmd.cmdPaths(args);
    } else if (helpers.strEql(command, "sandbox-fs")) {
        process_cmd.cmdSandboxFs(args);
    }
    // === E3.3: Binary Verification Commands ===
    else if (helpers.strEql(command, "verify")) {
        process_cmd.cmdVerifyBin(args);
    } else if (helpers.strEql(command, "trust")) {
        process_cmd.cmdTrust(args);
    } else if (helpers.strEql(command, "untrust")) {
        process_cmd.cmdUntrust(args);
    } else if (helpers.strEql(command, "trusted")) {
        process_cmd.cmdTrusted(args);
    }
    // === E3.4: Network Capability Commands ===
    else if (helpers.strEql(command, "netcap")) {
        cmdNetcap(args);
    } else if (helpers.strEql(command, "netprocs")) {
        cmdNetprocs(args);
    } else if (helpers.strEql(command, "netsockets")) {
        cmdNetsockets(args);
    } else if (helpers.strEql(command, "netallow")) {
        cmdNetallow(args);
    } else if (helpers.strEql(command, "netdeny")) {
        cmdNetdeny(args);
    } else if (helpers.strEql(command, "netrevoke")) {
        cmdNetrevoke(args);
    } else if (helpers.strEql(command, "netrestrict")) {
        cmdNetrestrict(args);
    } else if (helpers.strEql(command, "netreset")) {
        cmdNetreset(args);
    } else if (helpers.strEql(command, "netviolations")) {
        cmdNetviolations(args);
    } else if (helpers.strEql(command, "netreg")) {
        cmdNetreg(args);
    } else if (helpers.strEql(command, "nettest")) {
        cmdNettest(args);
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
    } else if (helpers.strEql(command, "ntest")) {
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
// E3.4: Network Capability Commands (inline)
// =============================================================================

/// netcap — show network capability status
fn cmdNetcap(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NETWORK CAPABILITY STATUS (E3.4) ===");
    shell.println("  ─────────────────────────────────────────");

    const s = net_capability.getStats();

    shell.print("  Registered processes: ");
    helpers.printDec(net_capability.getProcessCount());
    shell.newLine();

    shell.print("  Active sockets:       ");
    helpers.printDec(net_capability.getActiveSocketCount());
    shell.newLine();

    shell.print("  Per-process rules:    ");
    helpers.printDec(net_capability.getNetRuleCount());
    shell.newLine();

    shell.println("  ─────────────────────────────────────────");

    shell.print("  Checks total:     ");
    helpers.printDec64(s.checks_total);
    shell.newLine();

    shell.print("  Checks allowed:   ");
    helpers.printDec64(s.checks_allowed);
    shell.newLine();

    shell.print("  Checks blocked:   ");
    helpers.printDec64(s.checks_blocked);
    shell.newLine();

    shell.print("  Violations total: ");
    helpers.printDec64(s.violations_total);
    shell.newLine();

    shell.print("  Processes killed: ");
    helpers.printDec64(s.processes_killed);
    shell.newLine();

    shell.print("  Sockets created:  ");
    helpers.printDec64(s.sockets_created);
    shell.newLine();

    shell.print("  Sockets closed:   ");
    helpers.printDec64(s.sockets_closed);
    shell.newLine();

    shell.println("  ─────────────────────────────────────────");
    shell.println("");
}

/// netprocs — show per-process network table
fn cmdNetprocs(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NET-CAP PROCESS TABLE ===");
    shell.println("  PID  NET  MODE        SOCKS  VIOLS  STATUS");
    shell.println("  ───  ───  ──────────  ─────  ─────  ──────");

    // Use serial print since it has the table display
    net_capability.printProcessTable();

    shell.println("  (See serial output for detailed table)");
    shell.println("");
}

/// netsockets — show socket ownership
fn cmdNetsockets(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === SOCKET OWNERSHIP ===");

    var count: usize = 0;
    while (count < 32) : (count += 1) {
        if (net_capability.getSocketOwnerEntry(count)) |o| {
            shell.print("  sock[");
            helpers.printDec(o.socket_idx);
            shell.print("] pid=");
            helpers.printDec(o.pid);
            shell.print(" type=");
            shell.print(switch (o.sock_type) {
                0 => "TCP",
                1 => "UDP",
                2 => "RAW",
                else => "???",
            });
            shell.print(" port=");
            helpers.printDec(o.local_port);
            shell.newLine();
        } else break;
    }

    if (count == 0) {
        shell.println("  (no active sockets)");
    }
    shell.println("");
}

/// netreg <pid> [caps] — register process for net capability tracking
fn cmdNetreg(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netreg <pid> [caps_hex]");
        shell.println("  Example: netreg 5 0008    (register pid 5 with CAP_NET)");
        shell.println("  Example: netreg 10 0000   (register pid 10, no net)");
        return;
    }

    // Parse PID
    const parsed = helpers.parseArgs(args);
    const pid = helpers.parseDec16(parsed.cmd) orelse {
        shell.println("  Invalid PID");
        return;
    };

    // Parse optional caps
    var caps: u32 = 0;
    if (parsed.rest.len > 0) {
        caps = helpers.parseHex32(parsed.rest) orelse 0;
    }

    if (net_capability.registerProcess(pid, caps)) {
        shell.print("  Registered pid=");
        helpers.printDec(pid);
        shell.print(" caps=0x");
        helpers.printHex32(caps);
        shell.print(" cap_net=");
        shell.println(if ((caps & 0x0008) != 0) "YES" else "NO");
    } else {
        shell.println("  Failed: table full");
    }
}

/// netallow <pid> — grant CAP_NET to process
fn cmdNetallow(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netallow <pid>");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    if (net_capability.grantNetCapability(pid)) {
        shell.print("  Granted CAP_NET to pid ");
        helpers.printDec(pid);
        shell.newLine();
    } else {
        shell.println("  Failed: register process first (netreg <pid>)");
    }
}

/// netdeny <pid> — set deny_all mode (block ALL network)
fn cmdNetdeny(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netdeny <pid>");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    if (net_capability.setNetMode(pid, .deny_all)) {
        shell.print("  Set DENY_ALL for pid ");
        helpers.printDec(pid);
        shell.println(" — all network blocked");
    } else {
        shell.println("  Failed: process not registered");
    }
}

/// netrevoke <pid> — revoke CAP_NET + close all sockets
fn cmdNetrevoke(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netrevoke <pid>");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    if (net_capability.revokeNetCapability(pid)) {
        shell.print("  Revoked CAP_NET for pid ");
        helpers.printDec(pid);
        shell.println(" — sockets closed");
    } else {
        shell.println("  Failed: process not registered");
    }
}

/// netrestrict <pid> — set restricted mode (only allowed IPs/ports)
fn cmdNetrestrict(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netrestrict <pid>");
        shell.println("  Then use addip/addport to configure allowlist");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    if (net_capability.setNetMode(pid, .restricted)) {
        shell.print("  Set RESTRICTED mode for pid ");
        helpers.printDec(pid);
        shell.newLine();
    } else {
        shell.println("  Failed: process not registered");
    }
}

/// netreset <pid> — reset violations and un-kill process
fn cmdNetreset(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netreset <pid>");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    net_capability.resetViolations(pid);
    shell.print("  Reset violations for pid ");
    helpers.printDec(pid);
    shell.newLine();
}

/// netviolations — show all violation stats
fn cmdNetviolations(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NETWORK VIOLATION REPORT ===");
    shell.println("  ────────────────────────────────");

    const s = net_capability.getStats();

    shell.print("  Total checks:     ");
    helpers.printDec64(s.checks_total);
    shell.newLine();

    shell.print("  Blocked:          ");
    helpers.printDec64(s.checks_blocked);
    shell.newLine();

    shell.print("  Violations:       ");
    helpers.printDec64(s.violations_total);
    shell.newLine();

    shell.print("  Processes killed: ");
    helpers.printDec64(s.processes_killed);
    shell.newLine();

    shell.println("  ────────────────────────────────");

    // Show per-process detail via serial
    net_capability.printProcessTable();
    shell.println("  (Detailed table on serial)");
    shell.println("");
}

/// nettest — run E3.4 test suite (simple format like other tests)
fn cmdNettest(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    helpers.printTestHeader("E3.4 NETWORK CAPABILITY");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1
    passed += helpers.doTest("NetCap initialized", net_capability.isInitialized(), &failed);

    // Test 2
    passed += helpers.doTest("Register pid=100 +NET", net_capability.registerProcess(100, 0x0008), &failed);

    // Test 3
    passed += helpers.doTest("Register pid=200 noNET", net_capability.registerProcess(200, 0x0000), &failed);

    // Test 4
    const r4 = net_capability.checkCreate(0);
    passed += helpers.doTest("Kernel create allowed", r4.action == .allowed, &failed);

    // Test 5
    const r5 = net_capability.checkCreate(100);
    passed += helpers.doTest("pid=100 create OK", r5.action == .allowed, &failed);

    // Test 6
    const r6 = net_capability.checkCreate(200);
    passed += helpers.doTest("pid=200 create BLOCKED", r6.action == .blocked_no_cap, &failed);

    // Test 7
    _ = net_capability.registerSocket(0, 100, 1, 8080);
    const owner7 = net_capability.getSocketOwner(0);
    passed += helpers.doTest("Socket ownership", owner7 != null and owner7.? == 100, &failed);

    // Test 8
    const r8 = net_capability.checkBind(100, 0, 8080);
    passed += helpers.doTest("pid=100 bind OK", r8.action == .allowed, &failed);

    // Test 9
    const r9 = net_capability.checkBind(200, 0, 8080);
    passed += helpers.doTest("pid=200 bind BLOCKED", r9.action == .blocked_no_cap, &failed);

    // Test 10
    const r10 = net_capability.checkConnect(100, 0x0A000203, 53);
    passed += helpers.doTest("pid=100 connect OK", r10.action == .allowed, &failed);

    // Test 11
    const r11 = net_capability.checkConnect(200, 0x0A000203, 53);
    passed += helpers.doTest("pid=200 connect BLOCK", r11.action == .blocked_no_cap, &failed);

    // Test 12
    const r12 = net_capability.checkSend(100);
    passed += helpers.doTest("pid=100 send OK", r12.action == .allowed, &failed);

    // Test 13
    const r13 = net_capability.checkSend(200);
    passed += helpers.doTest("pid=200 send BLOCKED", r13.action != .allowed, &failed);

    // Test 14
    passed += helpers.doTest("pid=200 violations>=3", net_capability.getViolations(200) >= 3, &failed);

    // Test 15
    passed += helpers.doTest("pid=200 auto-killed", net_capability.isKilled(200), &failed);

    // Test 16
    _ = net_capability.registerProcess(300, 0x0008);
    const set_ok = net_capability.setNetMode(300, .restricted);
    const add_ok = net_capability.addAllowedIP(300, 0x01020304);
    passed += helpers.doTest("Restricted mode setup", set_ok and add_ok, &failed);

    // Test 17
    const r17 = net_capability.checkConnect(300, 0x01020304, 80);
    passed += helpers.doTest("Allowed IP connect OK", r17.action == .allowed, &failed);

    // Test 18
    const r18 = net_capability.checkConnect(300, 0x05060708, 80);
    passed += helpers.doTest("Bad IP BLOCKED", r18.action == .blocked_restricted, &failed);

    // Test 19
    const revoked = net_capability.revokeNetCapability(100);
    passed += helpers.doTest("Revoke CAP_NET", revoked and !net_capability.hasNetCapability(100), &failed);

    // Test 20
    const r20 = net_capability.checkCreate(100);
    passed += helpers.doTest("After revoke BLOCKED", r20.action == .blocked_no_cap, &failed);

    // Cleanup
    net_capability.unregisterProcess(100);
    net_capability.unregisterProcess(200);
    net_capability.unregisterProcess(300);

    helpers.printTestResults(passed, failed);
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
    process_cmd.cmdCaps("test");
    shell.newLine();

    // 11. Unveil tests (E3.2)
    shell.printInfoLine("=== UNVEIL TESTS (E3.2) ===");
    process_cmd.cmdUnveil("test");
    shell.newLine();

    // 12. Binary verification tests (E3.3)
    shell.printInfoLine("=== BINARY VERIFY TESTS (E3.3) ===");
    process_cmd.cmdVerifyBin("test");
    shell.newLine();

    // 13. Network capability tests (E3.4)
    shell.printInfoLine("=== NETWORK CAPABILITY TESTS (E3.4) ===");
    cmdNettest("");
    shell.newLine();

    // Final summary
    shell.printInfoLine("########################################");
    shell.printInfoLine("##  COMPLETE TEST SUITE FINISHED      ##");
    shell.printInfoLine("########################################");
    shell.newLine();
}
