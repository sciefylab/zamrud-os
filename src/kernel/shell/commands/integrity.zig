//! Zamrud OS - Integrity Commands

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const serial = @import("../../drivers/serial/serial.zig");
const integrity = @import("../../integrity/integrity.zig");

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        integrityHelp();
    } else if (helpers.strEql(parsed.cmd, "info")) {
        integrityInfo();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        integrityTest();
    } else if (helpers.strEql(parsed.cmd, "verify")) {
        integrityVerify();
    } else {
        shell.printError("integrity: unknown subcommand '");
        shell.print(parsed.cmd);
        shell.println("'");
    }
}

fn integrityHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  INTEGRITY - File Integrity System");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: integrity <subcommand>");
    shell.newLine();

    shell.println("Subcommands:");
    shell.println("  help     Show this help");
    shell.println("  info     Show integrity status");
    shell.println("  test     Run integrity tests");
    shell.println("  verify   Verify system files");
    shell.newLine();
}

fn integrityInfo() void {
    const registry = @import("../../integrity/registry.zig");
    const quarantine = @import("../../integrity/quarantine.zig");
    const monitor = @import("../../integrity/monitor.zig");

    shell.printInfoLine("========================================");
    shell.printInfoLine("  INTEGRITY STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized: ");
    if (integrity.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    const stats = registry.getStats();

    shell.print("  Registered: ");
    helpers.printU32(@intCast(stats.total));
    shell.newLine();

    shell.print("  Valid: ");
    helpers.printU32(@intCast(stats.valid));
    shell.newLine();

    shell.print("  Modified: ");
    helpers.printU32(@intCast(stats.modified));
    shell.newLine();

    shell.print("  Quarantined: ");
    helpers.printU32(@intCast(quarantine.getCount()));
    shell.newLine();

    shell.print("  Monitor: ");
    if (monitor.isEnabled()) {
        shell.printSuccessLine("ENABLED");
    } else {
        shell.printWarningLine("DISABLED");
    }

    shell.print("  System valid: ");
    if (registry.isSystemValid()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("COMPROMISED!");
    }

    shell.newLine();
}

pub fn integrityTest() void {
    const registry = @import("../../integrity/registry.zig");
    const verify_mod = @import("../../integrity/verify.zig");
    const quarantine = @import("../../integrity/quarantine.zig");
    const monitor = @import("../../integrity/monitor.zig");

    helpers.printTestHeader("INTEGRITY TEST SUITE");

    var passed: u32 = 0;
    var failed: u32 = 0;

    shell.println("[1/4] Registry...");
    if (registry.test_registry()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[2/4] Verify...");
    if (verify_mod.test_verify()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[3/4] Quarantine...");
    if (quarantine.test_quarantine()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[4/4] Monitor...");
    if (monitor.test_monitor()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    helpers.printTestResults(passed, failed);
}

fn integrityVerify() void {
    const registry = @import("../../integrity/registry.zig");

    shell.printInfoLine("Verifying system integrity...");
    shell.newLine();

    if (registry.isSystemValid()) {
        shell.printSuccessLine("System integrity: VALID");
    } else {
        shell.printErrorLine("System integrity: COMPROMISED!");
    }

    shell.newLine();
}
