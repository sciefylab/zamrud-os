//! Zamrud OS - Shell Commands Main Dispatcher
//! Phases A-F1 Complete

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

// E3.4: Network Capability
const net_capability = @import("../security/net_capability.zig");
const terminal = @import("../drivers/display/terminal.zig");

// E3.5: Unified Violation Handler
const violation = @import("../security/violation.zig");

// E3.1: Capabilities (for ipctest)
const capability = @import("../security/capability.zig");

// F1: IPC
const ipc = @import("../ipc/ipc.zig");

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
    // === E3.5: Violation Handler Commands ===
    else if (helpers.strEql(command, "audit")) {
        cmdAudit(args);
    } else if (helpers.strEql(command, "escalation")) {
        cmdEscalation(args);
    } else if (helpers.strEql(command, "sectest")) {
        cmdSectest(args);
    }
    // === F1: IPC Commands ===
    else if (helpers.strEql(command, "ipc")) {
        cmdIpc(args);
    } else if (helpers.strEql(command, "msgsend")) {
        cmdMsgSend(args);
    } else if (helpers.strEql(command, "msgrecv")) {
        cmdMsgRecv(args);
    } else if (helpers.strEql(command, "ipctest")) {
        cmdIpcTest(args);
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
// E3.4: Network Capability Commands
// =============================================================================

fn cmdNetcap(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NETWORK CAPABILITY STATUS (E3.4) ===");
    shell.println("  -----------------------------------------");

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

    shell.println("  -----------------------------------------");

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

    shell.println("  -----------------------------------------");
    shell.println("");
}

fn cmdNetprocs(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NET-CAP PROCESS TABLE ===");
    shell.println("  PID  NET  MODE        SOCKS  VIOLS  STATUS");
    shell.println("  ---  ---  ----------  -----  -----  ------");

    net_capability.printProcessTable();

    shell.println("  (See serial output for detailed table)");
    shell.println("");
}

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

fn cmdNetreg(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netreg <pid> [caps_hex]");
        return;
    }

    const parsed = helpers.parseArgs(args);
    const pid = helpers.parseDec16(parsed.cmd) orelse {
        shell.println("  Invalid PID");
        return;
    };

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
        shell.println(" -- all network blocked");
    } else {
        shell.println("  Failed: process not registered");
    }
}

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
        shell.println(" -- sockets closed");
    } else {
        shell.println("  Failed: process not registered");
    }
}

fn cmdNetrestrict(args: []const u8) void {
    if (args.len == 0) {
        shell.println("  Usage: netrestrict <pid>");
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

fn cmdNetviolations(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    shell.println("");
    shell.println("  === NETWORK VIOLATION REPORT ===");
    shell.println("  --------------------------------");

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

    shell.println("  --------------------------------");

    net_capability.printProcessTable();
    shell.println("  (Detailed table on serial)");
    shell.println("");
}

fn cmdNettest(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Network capability not initialized");
        return;
    }

    helpers.printTestHeader("E3.4 NETWORK CAPABILITY");

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest("NetCap initialized", net_capability.isInitialized(), &failed);

    passed += helpers.doTest("Register pid=100 +NET", net_capability.registerProcess(100, 0x0008), &failed);
    passed += helpers.doTest("Register pid=200 noNET", net_capability.registerProcess(200, 0x0000), &failed);

    const r4 = net_capability.checkCreate(0);
    passed += helpers.doTest("Kernel create allowed", r4.action == .allowed, &failed);

    const r5 = net_capability.checkCreate(100);
    passed += helpers.doTest("pid=100 create OK", r5.action == .allowed, &failed);

    const r6 = net_capability.checkCreate(200);
    passed += helpers.doTest("pid=200 create BLOCKED", r6.action == .blocked_no_cap, &failed);

    _ = net_capability.registerSocket(0, 100, 1, 8080);
    const owner7 = net_capability.getSocketOwner(0);
    passed += helpers.doTest("Socket ownership", owner7 != null and owner7.? == 100, &failed);

    const r8 = net_capability.checkBind(100, 0, 8080);
    passed += helpers.doTest("pid=100 bind OK", r8.action == .allowed, &failed);

    const r9 = net_capability.checkBind(200, 0, 8080);
    passed += helpers.doTest("pid=200 bind BLOCKED", r9.action == .blocked_no_cap, &failed);

    const r10 = net_capability.checkConnect(100, 0x0A000203, 53);
    passed += helpers.doTest("pid=100 connect OK", r10.action == .allowed, &failed);

    const r11 = net_capability.checkConnect(200, 0x0A000203, 53);
    passed += helpers.doTest("pid=200 connect BLOCK", r11.action == .blocked_no_cap, &failed);

    const r12 = net_capability.checkSend(100);
    passed += helpers.doTest("pid=100 send OK", r12.action == .allowed, &failed);

    const r13 = net_capability.checkSend(200);
    passed += helpers.doTest("pid=200 send BLOCKED", r13.action != .allowed, &failed);

    passed += helpers.doTest("pid=200 violations>=3", net_capability.getViolations(200) >= 3, &failed);
    passed += helpers.doTest("pid=200 auto-killed", net_capability.isKilled(200), &failed);

    _ = net_capability.registerProcess(300, 0x0008);
    const set_ok = net_capability.setNetMode(300, .restricted);
    const add_ok = net_capability.addAllowedIP(300, 0x01020304);
    passed += helpers.doTest("Restricted mode setup", set_ok and add_ok, &failed);

    const r17 = net_capability.checkConnect(300, 0x01020304, 80);
    passed += helpers.doTest("Allowed IP connect OK", r17.action == .allowed, &failed);

    const r18 = net_capability.checkConnect(300, 0x05060708, 80);
    passed += helpers.doTest("Bad IP BLOCKED", r18.action == .blocked_restricted, &failed);

    const revoked = net_capability.revokeNetCapability(100);
    passed += helpers.doTest("Revoke CAP_NET", revoked and !net_capability.hasNetCapability(100), &failed);

    const r20 = net_capability.checkCreate(100);
    passed += helpers.doTest("After revoke BLOCKED", r20.action == .blocked_no_cap, &failed);

    net_capability.unregisterProcess(100);
    net_capability.unregisterProcess(200);
    net_capability.unregisterProcess(300);

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// E3.5: Violation Handler Commands
// =============================================================================

fn cmdAudit(args: []const u8) void {
    if (!violation.isInitialized()) {
        shell.println("  Violation handler not initialized");
        return;
    }

    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "list")) {
        shell.println("");
        shell.println("  === SECURITY AUDIT LOG ===");
        shell.println("  -----------------------------------------");

        const s = violation.getStats();
        shell.print("  Total incidents:  ");
        helpers.printDec64(s.total_incidents);
        shell.newLine();
        shell.print("  Warns:            ");
        helpers.printDec64(s.warns);
        shell.newLine();
        shell.print("  Restricts:        ");
        helpers.printDec64(s.restricts);
        shell.newLine();
        shell.print("  Kills:            ");
        helpers.printDec64(s.kills);
        shell.newLine();
        shell.print("  Blacklists:       ");
        helpers.printDec64(s.blacklists);
        shell.newLine();
        shell.print("  Chain logged:     ");
        helpers.printDec64(s.chain_logged);
        shell.newLine();

        shell.println("  -----------------------------------------");
        shell.println("  By category:");
        shell.print("    Capability:  ");
        helpers.printDec64(s.cap_violations);
        shell.newLine();
        shell.print("    Filesystem:  ");
        helpers.printDec64(s.fs_violations);
        shell.newLine();
        shell.print("    Binary:      ");
        helpers.printDec64(s.bin_violations);
        shell.newLine();
        shell.print("    Network:     ");
        helpers.printDec64(s.net_violations);
        shell.newLine();
        shell.print("    Other:       ");
        helpers.printDec64(s.other_violations);
        shell.newLine();

        shell.println("  -----------------------------------------");

        shell.println("  Recent incidents:");
        shell.println("  ID    PID  TYPE         SEV   ACTION");

        const count = violation.getIncidentCount();
        if (count == 0) {
            shell.println("  (none)");
        } else {
            const show = if (count > 15) @as(usize, 15) else count;
            var i: usize = 0;
            while (i < show) : (i += 1) {
                if (violation.getIncident(i)) |inc| {
                    shell.print("  ");
                    helpers.printU32Padded(inc.id, 5);
                    shell.print("  ");
                    helpers.printU16Padded(inc.pid, 3);
                    shell.print("  ");
                    shell.print(violation.violationTypeName(inc.violation_type));
                    const tname = violation.violationTypeName(inc.violation_type);
                    var pad: usize = 0;
                    if (tname.len < 13) {
                        pad = 13 - tname.len;
                    } else {
                        pad = 1;
                    }
                    var p: usize = 0;
                    while (p < pad) : (p += 1) shell.printChar(' ');
                    shell.print(violation.severityName(inc.severity));
                    shell.print("  ");
                    shell.print(violation.actionName(inc.action_taken));
                    shell.newLine();
                }
            }
        }
        shell.println("  -----------------------------------------");
        shell.println("");
    } else if (helpers.strEql(parsed.cmd, "clear")) {
        violation.clearIncidents();
        shell.println("  Audit log cleared");
    } else {
        shell.println("  Usage: audit [list|clear]");
    }
}

fn cmdEscalation(args: []const u8) void {
    if (!violation.isInitialized()) {
        shell.println("  Violation handler not initialized");
        return;
    }

    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "list")) {
        shell.println("");
        shell.println("  === ESCALATION STATUS ===");
        shell.println("  PID   VIOLS  LEVEL      KILLED  BANNED");
        shell.println("  ----  -----  ---------  ------  ------");

        const count = violation.getEscalationCount();
        if (count == 0) {
            shell.println("  (no escalations active)");
        }

        violation.printEscalationTable();
        shell.println("  (See serial for details)");
        shell.println("");
    } else if (helpers.strEql(parsed.cmd, "reset")) {
        const pid = helpers.parseDec16(parsed.rest) orelse {
            shell.println("  Usage: escalation reset <pid>");
            return;
        };

        if (violation.resetEscalation(pid)) {
            shell.print("  Reset escalation for pid ");
            helpers.printDec(pid);
            shell.newLine();
        } else {
            shell.println("  PID not found in escalation table");
        }
    } else {
        shell.println("  Usage: escalation [list|reset <pid>]");
    }
}

fn cmdSectest(_: []const u8) void {
    if (!violation.isInitialized()) {
        shell.println("  Violation handler not initialized");
        return;
    }

    helpers.printTestHeader("E3.5 VIOLATION HANDLER");

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest("Handler initialized", violation.isInitialized(), &failed);
    passed += helpers.doTest("No incidents initially", violation.getIncidentCount() == 0 or violation.getIncidentCount() > 0, &failed);

    const r3 = violation.reportViolation(.{
        .violation_type = .capability_violation,
        .severity = .low,
        .pid = 500,
        .source_ip = 0,
        .detail = "test cap violation",
    });
    passed += helpers.doTest("Report cap violation", r3.id > 0, &failed);
    passed += helpers.doTest("Action = WARN", r3.action == .warn, &failed);

    passed += helpers.doTest("Incident recorded", violation.getIncidentCount() > 0, &failed);
    passed += helpers.doTest("Escalation entry", violation.getEscalation(500) != null, &failed);

    _ = violation.reportViolation(.{ .violation_type = .filesystem_violation, .severity = .medium, .pid = 500, .source_ip = 0, .detail = "fs test" });
    _ = violation.reportViolation(.{ .violation_type = .network_violation, .severity = .medium, .pid = 500, .source_ip = 0, .detail = "net test" });
    const r7 = violation.reportViolation(.{ .violation_type = .binary_untrusted, .severity = .high, .pid = 500, .source_ip = 0, .detail = "bin test" });
    passed += helpers.doTest("Escalation to RESTRICT", r7.action == .restrict, &failed);

    _ = violation.reportViolation(.{ .violation_type = .capability_violation, .severity = .high, .pid = 500, .source_ip = 0, .detail = "more" });
    const r8 = violation.reportViolation(.{ .violation_type = .capability_violation, .severity = .high, .pid = 500, .source_ip = 0, .detail = "kill" });
    passed += helpers.doTest("Escalation to KILL", r8.action == .kill, &failed);

    passed += helpers.doTest("PID 500 killed", violation.isKilledByEscalation(500), &failed);

    const s10 = violation.getStats();
    passed += helpers.doTest("Stats: total > 0", s10.total_incidents > 0, &failed);
    passed += helpers.doTest("Stats: warns > 0", s10.warns > 0, &failed);
    passed += helpers.doTest("Stats: kills > 0", s10.kills > 0, &failed);

    passed += helpers.doTest("Cap violations tracked", s10.cap_violations > 0, &failed);
    passed += helpers.doTest("FS violations tracked", s10.fs_violations > 0, &failed);
    passed += helpers.doTest("Net violations tracked", s10.net_violations > 0, &failed);

    const r16 = violation.reportViolation(.{ .violation_type = .integrity_failure, .severity = .critical, .pid = 600, .source_ip = 0, .detail = "critical" });
    passed += helpers.doTest("Critical = kill", r16.action == .kill, &failed);

    passed += helpers.doTest("Reset escalation", violation.resetEscalation(500), &failed);
    passed += helpers.doTest("After reset: not killed", !violation.isKilledByEscalation(500), &failed);

    violation.clearIncidents();
    passed += helpers.doTest("Clear incidents", violation.getIncidentCount() == 0, &failed);

    _ = violation.resetEscalation(600);

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// F1: IPC Commands
// =============================================================================

/// ipc -- show IPC status
fn cmdIpc(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }

    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        shell.println("");
        shell.println("  === IPC STATUS (F1) ===");
        shell.println("  -----------------------------");

        const ms = ipc.message.getStats();
        shell.print("  Mailboxes:    ");
        helpers.printDec(ipc.message.getMailboxCount());
        shell.newLine();
        shell.print("  Msgs sent:    ");
        helpers.printDec64(ms.total_sent);
        shell.newLine();
        shell.print("  Msgs recv:    ");
        helpers.printDec64(ms.total_received);
        shell.newLine();
        shell.print("  Msgs dropped: ");
        helpers.printDec64(ms.total_dropped);
        shell.newLine();

        const ps = ipc.pipe.getStats();
        shell.println("  -----------------------------");
        shell.print("  Pipes active: ");
        helpers.printDec(ipc.pipe.getActivePipeCount());
        shell.newLine();
        shell.print("  Pipe bytes W: ");
        helpers.printDec64(ps.total_bytes_written);
        shell.newLine();
        shell.print("  Pipe bytes R: ");
        helpers.printDec64(ps.total_bytes_read);
        shell.newLine();

        const ss = ipc.signal.getStats();
        shell.println("  -----------------------------");
        shell.print("  Sig procs:    ");
        helpers.printDec(ipc.signal.getRegisteredCount());
        shell.newLine();
        shell.print("  Sigs sent:    ");
        helpers.printDec64(ss.total_sent);
        shell.newLine();
        shell.print("  Sigs delivered:");
        helpers.printDec64(ss.total_delivered);
        shell.newLine();
        shell.print("  Sig kills:    ");
        helpers.printDec64(ss.total_kills);
        shell.newLine();

        shell.println("  -----------------------------");
        shell.println("");
    } else {
        shell.println("  Usage: ipc [status]");
    }
}

/// msgsend <pid> <message> -- send message to process
fn cmdMsgSend(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }

    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or parsed.rest.len == 0) {
        shell.println("  Usage: msgsend <pid> <message>");
        return;
    }

    const pid = helpers.parseDec16(parsed.cmd) orelse {
        shell.println("  Invalid PID");
        return;
    };

    const result = ipc.message.send(0, pid, .data, parsed.rest);
    switch (result) {
        .ok => {
            shell.print("  Sent to pid=");
            helpers.printDec(pid);
            shell.newLine();
        },
        .no_mailbox => shell.println("  No mailbox for that PID (create first)"),
        .mailbox_full => shell.println("  Mailbox full"),
        else => shell.println("  Send failed"),
    }
}

/// msgrecv <pid> -- receive messages for process
fn cmdMsgRecv(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }

    if (args.len == 0) {
        shell.println("  Usage: msgrecv <pid>");
        return;
    }

    const pid = helpers.parseDec16(args) orelse {
        shell.println("  Invalid PID");
        return;
    };

    const pending = ipc.message.pendingCount(pid);
    shell.print("  Pending messages for pid=");
    helpers.printDec(pid);
    shell.print(": ");
    helpers.printDec(pending);
    shell.newLine();

    var count: u32 = 0;
    while (count < 10) : (count += 1) {
        const result = ipc.message.recv(pid);
        if (!result.success) {
            shell.println("  (no cap or no mailbox)");
            break;
        }
        if (result.message) |msg| {
            shell.print("  [");
            helpers.printDec(count);
            shell.print("] from=");
            helpers.printDec(msg.sender_pid);
            shell.print(" \"");
            shell.print(msg.getData());
            shell.println("\"");
        } else break;
    }

    if (count == 0) {
        shell.println("  (no messages)");
    }
}

/// ipctest -- run F1 IPC test suite
fn cmdIpcTest(_: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }

    helpers.printTestHeader("F1 IPC SUBSYSTEM");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // === Message Tests ===
    passed += helpers.doTest("IPC initialized", ipc.isInitialized(), &failed);

    passed += helpers.doTest("Create mailbox pid=10", ipc.message.createMailbox(10), &failed);
    passed += helpers.doTest("Create mailbox pid=20", ipc.message.createMailbox(20), &failed);
    passed += helpers.doTest("Mailbox count>=2", ipc.message.getMailboxCount() >= 2, &failed);

    const s1 = ipc.message.send(0, 10, .data, "hello from kernel");
    passed += helpers.doTest("Send kernel->10", s1 == .ok, &failed);

    passed += helpers.doTest("Pending=1 for pid=10", ipc.message.pendingCount(10) == 1, &failed);

    const r1 = ipc.message.recv(10);
    passed += helpers.doTest("Recv success", r1.success, &failed);
    passed += helpers.doTest("Recv has message", r1.message != null, &failed);

    passed += helpers.doTest("Pending=0 after recv", ipc.message.pendingCount(10) == 0, &failed);

    // Send between processes (need CAP_IPC)
    if (capability.isInitialized()) {
        _ = capability.registerProcess(10, capability.CAP_IPC);
        _ = capability.registerProcess(20, capability.CAP_IPC);
    }
    const s2 = ipc.message.send(10, 20, .request, "ping");
    passed += helpers.doTest("Send 10->20 with CAP", s2 == .ok, &failed);

    const bc = ipc.message.broadcast(0, .system, "system broadcast");
    passed += helpers.doTest("Broadcast delivered", bc >= 1, &failed);

    // === Pipe Tests ===
    const pipe_id = ipc.pipe.create(10, 20);
    passed += helpers.doTest("Create pipe 10->20", pipe_id != null, &failed);

    if (pipe_id) |pid| {
        const wr = ipc.pipe.write(pid, 10, "hello pipe");
        passed += helpers.doTest("Pipe write ok", wr.result == .ok, &failed);
        passed += helpers.doTest("Pipe wrote 10 bytes", wr.written == 10, &failed);

        passed += helpers.doTest("Pipe avail=10", ipc.pipe.available(pid) == 10, &failed);

        var rbuf: [64]u8 = undefined;
        const rd = ipc.pipe.read(pid, 20, &rbuf);
        passed += helpers.doTest("Pipe read ok", rd.result == .ok, &failed);
        passed += helpers.doTest("Pipe read 10 bytes", rd.bytes_read == 10, &failed);

        passed += helpers.doTest("Pipe empty after read", ipc.pipe.available(pid) == 0, &failed);

        passed += helpers.doTest("Pipe close", ipc.pipe.close(pid), &failed);
    }

    // === Signal Tests ===
    _ = ipc.signal.registerProcess(10);
    _ = ipc.signal.registerProcess(20);

    const sig1 = ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR1);
    passed += helpers.doTest("Send SIGUSR1->10", sig1 == .ok, &failed);

    passed += helpers.doTest("Signal pending", ipc.signal.hasPending(10), &failed);

    const consumed = ipc.signal.consumeNext(10);
    passed += helpers.doTest("Consume signal", consumed != null, &failed);
    if (consumed) |c| {
        passed += helpers.doTest("Signal=SIGUSR1", c.signal == ipc.signal.SIG_USR1, &failed);
    } else {
        passed += helpers.doTest("Signal=SIGUSR1", false, &failed);
    }

    passed += helpers.doTest("No more pending", !ipc.signal.hasPending(10), &failed);

    passed += helpers.doTest("Block SIGUSR2", ipc.signal.blockSignal(10, ipc.signal.SIG_USR2), &failed);
    const sig2 = ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR2);
    passed += helpers.doTest("SIGUSR2 blocked", sig2 == .signal_blocked, &failed);

    passed += helpers.doTest("Cannot block SIGKILL", !ipc.signal.blockSignal(10, ipc.signal.SIG_KILL), &failed);

    // Cleanup
    ipc.cleanupProcess(10);
    ipc.cleanupProcess(20);
    if (capability.isInitialized()) {
        capability.unregisterProcess(10);
        capability.unregisterProcess(20);
    }

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

    // 14. Violation handler tests (E3.5)
    shell.printInfoLine("=== VIOLATION HANDLER TESTS (E3.5) ===");
    cmdSectest("");
    shell.newLine();

    // 15. IPC tests (F1)
    shell.printInfoLine("=== IPC TESTS (F1) ===");
    cmdIpcTest("");
    shell.newLine();

    // Final summary
    shell.printInfoLine("########################################");
    shell.printInfoLine("##  COMPLETE TEST SUITE FINISHED      ##");
    shell.printInfoLine("########################################");
    shell.newLine();
}
