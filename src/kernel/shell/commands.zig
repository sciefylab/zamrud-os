//! Zamrud OS - Shell Commands Main Dispatcher
//! Phases A-F2 Complete

const shell = @import("shell.zig");

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

const net_capability = @import("../security/net_capability.zig");
const terminal = @import("../drivers/display/terminal.zig");
const violation = @import("../security/violation.zig");
const capability = @import("../security/capability.zig");
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
    // Filesystem
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
    // Device
    else if (helpers.strEql(command, "lsdev")) {
        device.cmdLsDev(args);
    } else if (helpers.strEql(command, "devtest")) {
        device.cmdDevTest(args);
    }
    // Disk
    else if (helpers.strEql(command, "disk")) {
        disk_cmd.execute(args);
    } else if (helpers.strEql(command, "diskinfo")) {
        disk_cmd.execute("list");
    }
    // Config (D3)
    else if (helpers.strEql(command, "config")) {
        config_cmd.execute(args);
    }
    // Process
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
    // E3.1: Capability
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
    // E3.2: Unveil
    else if (helpers.strEql(command, "unveil")) {
        process_cmd.cmdUnveil(args);
    } else if (helpers.strEql(command, "paths")) {
        process_cmd.cmdPaths(args);
    } else if (helpers.strEql(command, "sandbox-fs")) {
        process_cmd.cmdSandboxFs(args);
    }
    // E3.3: Binary Verification
    else if (helpers.strEql(command, "verify")) {
        process_cmd.cmdVerifyBin(args);
    } else if (helpers.strEql(command, "trust")) {
        process_cmd.cmdTrust(args);
    } else if (helpers.strEql(command, "untrust")) {
        process_cmd.cmdUntrust(args);
    } else if (helpers.strEql(command, "trusted")) {
        process_cmd.cmdTrusted(args);
    }
    // E3.4: Network Capability
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
    // E3.5: Violation Handler
    else if (helpers.strEql(command, "audit")) {
        cmdAudit(args);
    } else if (helpers.strEql(command, "escalation")) {
        cmdEscalation(args);
    } else if (helpers.strEql(command, "sectest")) {
        cmdSectest(args);
    }
    // F1: IPC
    else if (helpers.strEql(command, "ipc")) {
        cmdIpc(args);
    } else if (helpers.strEql(command, "msgsend")) {
        cmdMsgSend(args);
    } else if (helpers.strEql(command, "msgrecv")) {
        cmdMsgRecv(args);
    } else if (helpers.strEql(command, "ipctest")) {
        cmdIpcTest(args);
    }
    // F2: Shared Memory
    else if (helpers.strEql(command, "shmem")) {
        cmdShmem(args);
    } else if (helpers.strEql(command, "shmtest")) {
        cmdShmTest(args);
    }
    // Crypto
    else if (helpers.strEql(command, "crypto")) {
        crypto_cmd.execute(args);
    }
    // Chain
    else if (helpers.strEql(command, "chain")) {
        chain_cmd.execute(args);
    }
    // Integrity
    else if (helpers.strEql(command, "integrity")) {
        integrity_cmd.execute(args);
    }
    // Identity
    else if (helpers.strEql(command, "identity")) {
        identity_cmd.execute(args);
    } else if (helpers.strEql(command, "whoami")) {
        identity_cmd.whoami();
    }
    // Network
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
    // P2P
    else if (helpers.strEql(command, "p2p")) {
        p2p_cmd.execute(args);
    }
    // Gateway
    else if (helpers.strEql(command, "gateway") or helpers.strEql(command, "gw")) {
        gateway_cmd.execute(args);
    }
    // Security
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
    // Smoke
    else if (helpers.strEql(command, "smoke")) {
        smoke_cmd.execute(args);
    }
    // Syscall
    else if (helpers.strEql(command, "syscall")) {
        syscall_cmd.execute(args);
    }
    // Boot
    else if (helpers.strEql(command, "boot")) {
        boot_cmd.execute(args);
    }
    // Power
    else if (helpers.strEql(command, "reboot")) {
        power_cmd.reboot();
    } else if (helpers.strEql(command, "shutdown") or helpers.strEql(command, "halt")) {
        power_cmd.shutdown();
    } else if (helpers.strEql(command, "exit")) {
        power_cmd.exit();
    } else if (helpers.strEql(command, "power")) {
        power_cmd.execute(args);
    }
    // Test all
    else if (helpers.strEql(command, "testall")) {
        runAllTests();
    }
    // Unknown
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
        shell.println("  Not initialized");
        return;
    }
    shell.println("");
    shell.println("  === NET-CAP PROCESS TABLE ===");
    net_capability.printProcessTable();
    shell.println("  (See serial for details)");
    shell.println("");
}

fn cmdNetsockets(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Not initialized");
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
            shell.print(" port=");
            helpers.printDec(o.local_port);
            shell.newLine();
        } else break;
    }
    if (count == 0) shell.println("  (none)");
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
    if (parsed.rest.len > 0) caps = helpers.parseHex32(parsed.rest) orelse 0;
    if (net_capability.registerProcess(pid, caps)) {
        shell.print("  Registered pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else shell.println("  Failed");
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
    } else shell.println("  Failed");
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
        shell.print("  DENY_ALL pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else shell.println("  Failed");
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
        shell.print("  Revoked pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else shell.println("  Failed");
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
        shell.print("  Restricted pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else shell.println("  Failed");
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
    shell.print("  Reset pid=");
    helpers.printDec(pid);
    shell.newLine();
}

fn cmdNetviolations(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }
    const s = net_capability.getStats();
    shell.println("");
    shell.println("  === NET VIOLATIONS ===");
    shell.print("  Blocked: ");
    helpers.printDec64(s.checks_blocked);
    shell.newLine();
    shell.print("  Violations: ");
    helpers.printDec64(s.violations_total);
    shell.newLine();
    shell.print("  Killed: ");
    helpers.printDec64(s.processes_killed);
    shell.newLine();
    shell.println("");
}

fn cmdNettest(_: []const u8) void {
    if (!net_capability.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }
    helpers.printTestHeader("E3.4 NETWORK CAPABILITY");
    var passed: u32 = 0;
    var failed: u32 = 0;
    passed += helpers.doTest("NetCap initialized", net_capability.isInitialized(), &failed);
    passed += helpers.doTest("Register pid=100 +NET", net_capability.registerProcess(100, 0x0008), &failed);
    passed += helpers.doTest("Register pid=200 noNET", net_capability.registerProcess(200, 0x0000), &failed);
    passed += helpers.doTest("Kernel create allowed", net_capability.checkCreate(0).action == .allowed, &failed);
    passed += helpers.doTest("pid=100 create OK", net_capability.checkCreate(100).action == .allowed, &failed);
    passed += helpers.doTest("pid=200 create BLOCKED", net_capability.checkCreate(200).action == .blocked_no_cap, &failed);
    _ = net_capability.registerSocket(0, 100, 1, 8080);
    const o7 = net_capability.getSocketOwner(0);
    passed += helpers.doTest("Socket ownership", o7 != null and o7.? == 100, &failed);
    passed += helpers.doTest("pid=100 bind OK", net_capability.checkBind(100, 0, 8080).action == .allowed, &failed);
    passed += helpers.doTest("pid=200 bind BLOCKED", net_capability.checkBind(200, 0, 8080).action == .blocked_no_cap, &failed);
    passed += helpers.doTest("pid=100 connect OK", net_capability.checkConnect(100, 0x0A000203, 53).action == .allowed, &failed);
    passed += helpers.doTest("pid=200 connect BLOCK", net_capability.checkConnect(200, 0x0A000203, 53).action == .blocked_no_cap, &failed);
    passed += helpers.doTest("pid=100 send OK", net_capability.checkSend(100).action == .allowed, &failed);
    passed += helpers.doTest("pid=200 send BLOCKED", net_capability.checkSend(200).action != .allowed, &failed);
    passed += helpers.doTest("pid=200 violations>=3", net_capability.getViolations(200) >= 3, &failed);
    passed += helpers.doTest("pid=200 auto-killed", net_capability.isKilled(200), &failed);
    _ = net_capability.registerProcess(300, 0x0008);
    const sok = net_capability.setNetMode(300, .restricted);
    const aok = net_capability.addAllowedIP(300, 0x01020304);
    passed += helpers.doTest("Restricted setup", sok and aok, &failed);
    passed += helpers.doTest("Allowed IP OK", net_capability.checkConnect(300, 0x01020304, 80).action == .allowed, &failed);
    passed += helpers.doTest("Bad IP BLOCKED", net_capability.checkConnect(300, 0x05060708, 80).action == .blocked_restricted, &failed);
    const rev = net_capability.revokeNetCapability(100);
    passed += helpers.doTest("Revoke CAP_NET", rev and !net_capability.hasNetCapability(100), &failed);
    passed += helpers.doTest("After revoke BLOCKED", net_capability.checkCreate(100).action == .blocked_no_cap, &failed);
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
        shell.println("  Not initialized");
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
        shell.print("  Kills:            ");
        helpers.printDec64(s.kills);
        shell.newLine();
        shell.print("  Blacklists:       ");
        helpers.printDec64(s.blacklists);
        shell.newLine();
        shell.println("  -----------------------------------------");
        const count = violation.getIncidentCount();
        if (count == 0) {
            shell.println("  (none)");
        } else {
            const show = if (count > 15) @as(usize, 15) else count;
            var i: usize = 0;
            while (i < show) : (i += 1) {
                if (violation.getIncident(i)) |inc| {
                    shell.print("  #");
                    helpers.printU32Padded(inc.id, 3);
                    shell.print(" pid=");
                    helpers.printU16Padded(inc.pid, 3);
                    shell.print(" ");
                    shell.print(violation.violationTypeName(inc.violation_type));
                    shell.print(" ");
                    shell.print(violation.actionName(inc.action_taken));
                    shell.newLine();
                }
            }
        }
        shell.println("");
    } else if (helpers.strEql(parsed.cmd, "clear")) {
        violation.clearIncidents();
        shell.println("  Cleared");
    } else shell.println("  Usage: audit [list|clear]");
}

fn cmdEscalation(args: []const u8) void {
    if (!violation.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "list")) {
        violation.printEscalationTable();
        shell.println("  (See serial)");
    } else if (helpers.strEql(parsed.cmd, "reset")) {
        const pid = helpers.parseDec16(parsed.rest) orelse {
            shell.println("  Usage: escalation reset <pid>");
            return;
        };
        if (violation.resetEscalation(pid)) {
            shell.print("  Reset pid=");
            helpers.printDec(pid);
            shell.newLine();
        } else shell.println("  Not found");
    } else shell.println("  Usage: escalation [list|reset <pid>]");
}

fn cmdSectest(_: []const u8) void {
    if (!violation.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }
    helpers.printTestHeader("E3.5 VIOLATION HANDLER");
    var passed: u32 = 0;
    var failed: u32 = 0;
    passed += helpers.doTest("Handler initialized", violation.isInitialized(), &failed);
    passed += helpers.doTest("Incident state ok", violation.getIncidentCount() == 0 or violation.getIncidentCount() > 0, &failed);
    const r3 = violation.reportViolation(.{ .violation_type = .capability_violation, .severity = .low, .pid = 500, .source_ip = 0, .detail = "test" });
    passed += helpers.doTest("Report violation", r3.id > 0, &failed);
    passed += helpers.doTest("Action = WARN", r3.action == .warn, &failed);
    passed += helpers.doTest("Incident recorded", violation.getIncidentCount() > 0, &failed);
    passed += helpers.doTest("Escalation entry", violation.getEscalation(500) != null, &failed);
    _ = violation.reportViolation(.{ .violation_type = .filesystem_violation, .severity = .medium, .pid = 500, .source_ip = 0, .detail = "fs" });
    _ = violation.reportViolation(.{ .violation_type = .network_violation, .severity = .medium, .pid = 500, .source_ip = 0, .detail = "net" });
    const r7 = violation.reportViolation(.{ .violation_type = .binary_untrusted, .severity = .high, .pid = 500, .source_ip = 0, .detail = "bin" });
    passed += helpers.doTest("Escalation RESTRICT", r7.action == .restrict, &failed);
    _ = violation.reportViolation(.{ .violation_type = .capability_violation, .severity = .high, .pid = 500, .source_ip = 0, .detail = "m" });
    const r8 = violation.reportViolation(.{ .violation_type = .capability_violation, .severity = .high, .pid = 500, .source_ip = 0, .detail = "k" });
    passed += helpers.doTest("Escalation KILL", r8.action == .kill, &failed);
    passed += helpers.doTest("PID 500 killed", violation.isKilledByEscalation(500), &failed);
    const s10 = violation.getStats();
    passed += helpers.doTest("Stats: total > 0", s10.total_incidents > 0, &failed);
    passed += helpers.doTest("Stats: warns > 0", s10.warns > 0, &failed);
    passed += helpers.doTest("Stats: kills > 0", s10.kills > 0, &failed);
    passed += helpers.doTest("Cap tracked", s10.cap_violations > 0, &failed);
    passed += helpers.doTest("FS tracked", s10.fs_violations > 0, &failed);
    passed += helpers.doTest("Net tracked", s10.net_violations > 0, &failed);
    const r16 = violation.reportViolation(.{ .violation_type = .integrity_failure, .severity = .critical, .pid = 600, .source_ip = 0, .detail = "crit" });
    passed += helpers.doTest("Critical = kill", r16.action == .kill, &failed);
    passed += helpers.doTest("Reset escalation", violation.resetEscalation(500), &failed);
    passed += helpers.doTest("After reset: ok", !violation.isKilledByEscalation(500), &failed);
    violation.clearIncidents();
    passed += helpers.doTest("Clear incidents", violation.getIncidentCount() == 0, &failed);
    _ = violation.resetEscalation(600);
    helpers.printTestResults(passed, failed);
}

// =============================================================================
// F1: IPC Commands
// =============================================================================

fn cmdIpc(args: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        shell.println("");
        shell.println("  === IPC STATUS (F1+F2) ===");
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
        const shm = ipc.shared_mem.getStats();
        shell.println("  -----------------------------");
        shell.print("  Shm regions:  ");
        helpers.printDec(ipc.shared_mem.getActiveRegionCount());
        shell.newLine();
        shell.print("  Shm created:  ");
        helpers.printDec64(shm.total_created);
        shell.newLine();
        shell.print("  Shm bytes W:  ");
        helpers.printDec64(shm.bytes_written);
        shell.newLine();
        shell.print("  Shm bytes R:  ");
        helpers.printDec64(shm.bytes_read);
        shell.newLine();
        shell.println("  -----------------------------");
        shell.println("");
    } else shell.println("  Usage: ipc [status]");
}

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
    if (result == .ok) {
        shell.print("  Sent to pid=");
        helpers.printDec(pid);
        shell.newLine();
    } else if (result == .no_mailbox) shell.println("  No mailbox") else shell.println("  Send failed");
}

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
    var count: u32 = 0;
    while (count < 10) : (count += 1) {
        const result = ipc.message.recv(pid);
        if (!result.success) {
            shell.println("  (no access)");
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
    if (count == 0) shell.println("  (no messages)");
}

fn cmdIpcTest(_: []const u8) void {
    if (!ipc.isInitialized()) {
        shell.println("  IPC not initialized");
        return;
    }
    helpers.printTestHeader("F1 IPC SUBSYSTEM");
    var passed: u32 = 0;
    var failed: u32 = 0;
    passed += helpers.doTest("IPC initialized", ipc.isInitialized(), &failed);
    passed += helpers.doTest("Create mbox pid=10", ipc.message.createMailbox(10), &failed);
    passed += helpers.doTest("Create mbox pid=20", ipc.message.createMailbox(20), &failed);
    passed += helpers.doTest("Mailbox count>=2", ipc.message.getMailboxCount() >= 2, &failed);
    const s1 = ipc.message.send(0, 10, .data, "hello from kernel");
    passed += helpers.doTest("Send kernel->10", s1 == .ok, &failed);
    passed += helpers.doTest("Pending=1", ipc.message.pendingCount(10) == 1, &failed);
    const r1 = ipc.message.recv(10);
    passed += helpers.doTest("Recv success", r1.success, &failed);
    passed += helpers.doTest("Recv has msg", r1.message != null, &failed);
    passed += helpers.doTest("Pending=0", ipc.message.pendingCount(10) == 0, &failed);
    if (capability.isInitialized()) {
        _ = capability.registerProcess(10, capability.CAP_IPC);
        _ = capability.registerProcess(20, capability.CAP_IPC);
    }
    passed += helpers.doTest("Send 10->20", ipc.message.send(10, 20, .request, "ping") == .ok, &failed);
    passed += helpers.doTest("Broadcast", ipc.message.broadcast(0, .system, "bcast") >= 1, &failed);
    const pid = ipc.pipe.create(10, 20);
    passed += helpers.doTest("Create pipe", pid != null, &failed);
    if (pid) |p| {
        const wr = ipc.pipe.write(p, 10, "hello pipe");
        passed += helpers.doTest("Pipe write ok", wr.result == .ok, &failed);
        passed += helpers.doTest("Pipe wrote 10", wr.written == 10, &failed);
        passed += helpers.doTest("Pipe avail=10", ipc.pipe.available(p) == 10, &failed);
        var rbuf: [64]u8 = undefined;
        const rd = ipc.pipe.read(p, 20, &rbuf);
        passed += helpers.doTest("Pipe read ok", rd.result == .ok, &failed);
        passed += helpers.doTest("Pipe read 10", rd.bytes_read == 10, &failed);
        passed += helpers.doTest("Pipe empty", ipc.pipe.available(p) == 0, &failed);
        passed += helpers.doTest("Pipe close", ipc.pipe.close(p), &failed);
    }
    _ = ipc.signal.registerProcess(10);
    _ = ipc.signal.registerProcess(20);
    passed += helpers.doTest("Send SIGUSR1", ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR1) == .ok, &failed);
    passed += helpers.doTest("Sig pending", ipc.signal.hasPending(10), &failed);
    const con = ipc.signal.consumeNext(10);
    passed += helpers.doTest("Consume sig", con != null, &failed);
    if (con) |c| {
        passed += helpers.doTest("Sig=USR1", c.signal == ipc.signal.SIG_USR1, &failed);
    } else {
        passed += helpers.doTest("Sig=USR1", false, &failed);
    }
    passed += helpers.doTest("No pending", !ipc.signal.hasPending(10), &failed);
    passed += helpers.doTest("Block USR2", ipc.signal.blockSignal(10, ipc.signal.SIG_USR2), &failed);
    passed += helpers.doTest("USR2 blocked", ipc.signal.sendSignal(0, 10, ipc.signal.SIG_USR2) == .signal_blocked, &failed);
    passed += helpers.doTest("Cant block KILL", !ipc.signal.blockSignal(10, ipc.signal.SIG_KILL), &failed);
    ipc.cleanupProcess(10);
    ipc.cleanupProcess(20);
    if (capability.isInitialized()) {
        capability.unregisterProcess(10);
        capability.unregisterProcess(20);
    }
    helpers.printTestResults(passed, failed);
}

// =============================================================================
// F2: Shared Memory Commands
// =============================================================================

/// shmem -- show shared memory status
fn cmdShmem(args: []const u8) void {
    if (!ipc.shared_mem.isInitialized()) {
        shell.println("  Shared memory not initialized");
        return;
    }
    const parsed = helpers.parseArgs(args);
    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        shell.println("");
        shell.println("  === SHARED MEMORY STATUS (F2) ===");
        shell.println("  ---------------------------------");
        const s = ipc.shared_mem.getStats();
        shell.print("  Active regions: ");
        helpers.printDec(ipc.shared_mem.getActiveRegionCount());
        shell.newLine();
        shell.print("  Created:        ");
        helpers.printDec64(s.total_created);
        shell.newLine();
        shell.print("  Destroyed:      ");
        helpers.printDec64(s.total_destroyed);
        shell.newLine();
        shell.print("  Attached:       ");
        helpers.printDec64(s.total_attached);
        shell.newLine();
        shell.print("  Detached:       ");
        helpers.printDec64(s.total_detached);
        shell.newLine();
        shell.print("  Reads:          ");
        helpers.printDec64(s.total_reads);
        shell.newLine();
        shell.print("  Writes:         ");
        helpers.printDec64(s.total_writes);
        shell.newLine();
        shell.print("  Bytes read:     ");
        helpers.printDec64(s.bytes_read);
        shell.newLine();
        shell.print("  Bytes written:  ");
        helpers.printDec64(s.bytes_written);
        shell.newLine();
        shell.print("  CAP violations: ");
        helpers.printDec64(s.cap_violations);
        shell.newLine();
        shell.println("  ---------------------------------");
        ipc.shared_mem.printStatus();
        shell.println("  (See serial for details)");
        shell.println("");
    } else shell.println("  Usage: shmem [status]");
}

/// shmtest -- run F2 shared memory test suite
fn cmdShmTest(_: []const u8) void {
    if (!ipc.shared_mem.isInitialized()) {
        shell.println("  Shared memory not initialized");
        return;
    }

    helpers.printTestHeader("F2 SHARED MEMORY");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Register test processes with CAP_MEMORY
    if (capability.isInitialized()) {
        _ = capability.registerProcess(30, capability.CAP_MEMORY | capability.CAP_IPC);
        _ = capability.registerProcess(40, capability.CAP_MEMORY | capability.CAP_IPC);
        _ = capability.registerProcess(50, capability.CAP_IPC); // NO CAP_MEMORY
    }

    passed += helpers.doTest("SHM initialized", ipc.shared_mem.isInitialized(), &failed);

    // Create region
    const c1 = ipc.shared_mem.create(30, "test_region", 1024);
    passed += helpers.doTest("Create region", c1.result == .ok, &failed);
    passed += helpers.doTest("Region ID > 0", c1.id > 0, &failed);

    // Active count
    passed += helpers.doTest("Active regions >= 1", ipc.shared_mem.getActiveRegionCount() >= 1, &failed);

    // Duplicate name blocked
    const c2 = ipc.shared_mem.create(30, "test_region", 512);
    passed += helpers.doTest("Dup name blocked", c2.result == .already_exists, &failed);

    // Too large blocked
    const c3 = ipc.shared_mem.create(30, "huge", 100 * 1024);
    passed += helpers.doTest("Too large blocked", c3.result == .too_large, &failed);

    // Owner auto-attached as RW
    passed += helpers.doTest("Owner attached", ipc.shared_mem.isAttached(30, c1.id), &failed);
    passed += helpers.doTest("Owner perm=RW", ipc.shared_mem.getAttachmentPerm(30, c1.id) == .read_write, &failed);

    // Write data
    const w1 = ipc.shared_mem.writeData(30, c1.id, 0, "Hello SharedMem!");
    passed += helpers.doTest("Write ok", w1.result == .ok, &failed);
    passed += helpers.doTest("Wrote 16 bytes", w1.written == 16, &failed);

    // Read data back
    var rbuf: [64]u8 = undefined;
    const r1 = ipc.shared_mem.readData(30, c1.id, 0, &rbuf);
    passed += helpers.doTest("Read ok", r1.result == .ok, &failed);
    passed += helpers.doTest("Read correct len", r1.bytes_read >= 16, &failed);

    // Verify content
    const match = rbuf[0] == 'H' and rbuf[5] == ' ' and rbuf[6] == 'S';
    passed += helpers.doTest("Content matches", match, &failed);

    // Attach pid=40 as read-only
    const a1 = ipc.shared_mem.attach(40, c1.id, .read_only);
    passed += helpers.doTest("Attach pid=40 RO", a1 == .ok, &failed);

    // pid=40 can read
    var rbuf2: [64]u8 = undefined;
    const r2 = ipc.shared_mem.readData(40, c1.id, 0, &rbuf2);
    passed += helpers.doTest("pid=40 read ok", r2.result == .ok, &failed);

    // pid=40 cannot write (RO)
    const w2 = ipc.shared_mem.writeData(40, c1.id, 0, "hack!");
    passed += helpers.doTest("pid=40 write denied", w2.result == .permission_denied, &failed);

    // pid=50 no CAP_MEMORY - attach blocked
    const a2 = ipc.shared_mem.attach(50, c1.id, .read_only);
    passed += helpers.doTest("No CAP_MEMORY blocked", a2 == .no_cap, &failed);

    // Not attached pid cannot read
    const r3 = ipc.shared_mem.readData(99, c1.id, 0, &rbuf);
    passed += helpers.doTest("Unattached read denied", r3.result == .not_attached, &failed);

    // Lock region
    passed += helpers.doTest("Lock region", ipc.shared_mem.lockRegion(30, c1.id) == .ok, &failed);

    // Write while locked
    const w3 = ipc.shared_mem.writeData(30, c1.id, 0, "locked!");
    passed += helpers.doTest("Write while locked", w3.result == .region_locked, &failed);

    // Unlock
    passed += helpers.doTest("Unlock region", ipc.shared_mem.unlockRegion(30, c1.id) == .ok, &failed);

    // Write after unlock
    const w4 = ipc.shared_mem.writeData(30, c1.id, 0, "unlocked!");
    passed += helpers.doTest("Write after unlock", w4.result == .ok, &failed);

    // Out of bounds
    const w5 = ipc.shared_mem.writeData(30, c1.id, 2000, "oob");
    passed += helpers.doTest("OOB write denied", w5.result == .out_of_bounds, &failed);

    // Find by name
    const found = ipc.shared_mem.findRegionByName("test_region");
    passed += helpers.doTest("Find by name", found != null and found.? == c1.id, &failed);

    // Detach pid=40
    passed += helpers.doTest("Detach pid=40", ipc.shared_mem.detach(40, c1.id) == .ok, &failed);
    passed += helpers.doTest("pid=40 detached", !ipc.shared_mem.isAttached(40, c1.id), &failed);

    // Destroy
    passed += helpers.doTest("Destroy region", ipc.shared_mem.destroy(30, c1.id) == .ok, &failed);
    passed += helpers.doTest("Region gone", ipc.shared_mem.findRegionByName("test_region") == null, &failed);

    // Stats
    const st = ipc.shared_mem.getStats();
    passed += helpers.doTest("Stats: created>0", st.total_created > 0, &failed);
    passed += helpers.doTest("Stats: writes>0", st.total_writes > 0, &failed);
    passed += helpers.doTest("Stats: reads>0", st.total_reads > 0, &failed);

    // Cleanup
    if (capability.isInitialized()) {
        capability.unregisterProcess(30);
        capability.unregisterProcess(40);
        capability.unregisterProcess(50);
    }

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Test All
// =============================================================================

fn runAllTests() void {
    helpers.printTestHeader("ZAMRUD OS - COMPLETE TEST SUITE");

    shell.printInfoLine("=== SMOKE TESTS ===");
    smoke_cmd.execute("run");
    shell.newLine();

    shell.printInfoLine("=== NETWORK TESTS ===");
    network_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== P2P TESTS ===");
    p2p_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== GATEWAY TESTS ===");
    gateway_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== SECURITY/FIREWALL TESTS ===");
    security_cmd.runTest("all");
    shell.newLine();

    shell.printInfoLine("=== CRYPTO TESTS ===");
    crypto_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== SYSCALL TESTS ===");
    syscall_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== BOOT TESTS ===");
    boot_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== DISK TESTS ===");
    disk_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== CONFIG PERSISTENCE TESTS ===");
    config_cmd.execute("test");
    shell.newLine();

    shell.printInfoLine("=== CAPABILITY TESTS (E3.1) ===");
    process_cmd.cmdCaps("test");
    shell.newLine();

    shell.printInfoLine("=== UNVEIL TESTS (E3.2) ===");
    process_cmd.cmdUnveil("test");
    shell.newLine();

    shell.printInfoLine("=== BINARY VERIFY TESTS (E3.3) ===");
    process_cmd.cmdVerifyBin("test");
    shell.newLine();

    shell.printInfoLine("=== NETWORK CAPABILITY TESTS (E3.4) ===");
    cmdNettest("");
    shell.newLine();

    shell.printInfoLine("=== VIOLATION HANDLER TESTS (E3.5) ===");
    cmdSectest("");
    shell.newLine();

    shell.printInfoLine("=== IPC TESTS (F1) ===");
    cmdIpcTest("");
    shell.newLine();

    shell.printInfoLine("=== SHARED MEMORY TESTS (F2) ===");
    cmdShmTest("");
    shell.newLine();

    shell.printInfoLine("########################################");
    shell.printInfoLine("##  COMPLETE TEST SUITE FINISHED      ##");
    shell.printInfoLine("########################################");
    shell.newLine();
}
