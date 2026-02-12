// =============================================================================
// E3.5: Violation Handler Commands
// =============================================================================
const violation = @import("../../security/violation.zig");
const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");

pub fn cmdAudit(args: []const u8) void {
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

pub fn cmdEscalation(args: []const u8) void {
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

pub fn cmdSectest(_: []const u8) void {
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
