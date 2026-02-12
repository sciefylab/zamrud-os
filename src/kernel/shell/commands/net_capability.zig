// =============================================================================
// E3.4: Network Capability Commands
// =============================================================================

const net_capability = @import("../../security/net_capability.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const violation = @import("../../security/violation.zig");
const capability = @import("../../security/capability.zig");
const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");

pub fn cmdNetcap(_: []const u8) void {
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

pub fn cmdNetprocs(_: []const u8) void {
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

pub fn cmdNetsockets(_: []const u8) void {
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

pub fn cmdNetreg(args: []const u8) void {
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

pub fn cmdNetallow(args: []const u8) void {
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

pub fn cmdNetdeny(args: []const u8) void {
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

pub fn cmdNetrevoke(args: []const u8) void {
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

pub fn cmdNetrestrict(args: []const u8) void {
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

pub fn cmdNetreset(args: []const u8) void {
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

pub fn cmdNetviolations(_: []const u8) void {
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

pub fn cmdNettest(_: []const u8) void {
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
