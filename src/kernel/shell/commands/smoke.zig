//! Zamrud OS - Smoke Test Shell Command
//! Shell interface for running smoke tests

const shell = @import("../shell.zig");
const smoke_tests = @import("../../tests/smoke.zig");
const helpers = @import("helpers.zig");
const config = @import("../../config.zig");

// =============================================================================
// Main Command Handler
// =============================================================================

pub fn execute(args: []const u8) void {
    if (args.len == 0) {
        // Default: run smoke tests
        smoke_tests.runSmokeTests();
        return;
    }

    const trimmed = helpers.trim(args);

    if (helpers.startsWith(trimmed, "run")) {
        smoke_tests.runSmokeTests();
    } else if (helpers.startsWith(trimmed, "full") or helpers.startsWith(trimmed, "all")) {
        smoke_tests.runFullTests();
    } else if (helpers.startsWith(trimmed, "status")) {
        showStatus();
    } else if (helpers.startsWith(trimmed, "config")) {
        showConfig();
    } else if (helpers.startsWith(trimmed, "help")) {
        showHelp();
    } else {
        shell.println("Unknown smoke command. Type 'smoke help'");
    }
}

// =============================================================================
// Status Display
// =============================================================================

fn showStatus() void {
    shell.newLine();
    shell.println("=== Smoke Test Status ===");
    shell.newLine();

    shell.print("Tests Run:    ");
    helpers.printU32(smoke_tests.getTestsRun());
    shell.newLine();

    shell.print("Tests Passed: ");
    helpers.printU32(smoke_tests.getTestsPassed());
    shell.newLine();

    shell.print("Tests Failed: ");
    helpers.printU32(smoke_tests.getTestsFailed());
    shell.newLine();

    shell.newLine();

    if (smoke_tests.allTestsPassed()) {
        shell.println("Result: ALL PASSED");
    } else if (smoke_tests.getTestsRun() == 0) {
        shell.println("Result: No tests run yet");
    } else {
        shell.println("Result: SOME FAILED");
    }

    shell.newLine();
}

// =============================================================================
// Configuration Display
// =============================================================================

fn showConfig() void {
    shell.newLine();
    shell.println("=== Smoke Test Configuration ===");
    shell.newLine();

    shell.print("Profile:          ");
    shell.println(config.getProfileString());

    shell.print("Smoke Test:       ");
    shell.println(if (config.ENABLE_SMOKE_TEST) "ENABLED" else "DISABLED");

    shell.print("Display Mode:     ");
    shell.println(switch (config.SMOKE_TEST_DISPLAY) {
        .always => "ALWAYS (show all)",
        .on_failure => "ON_FAILURE (silent if pass)",
        .never => "NEVER (completely silent)",
        .verbose => "VERBOSE (detailed)",
    });

    shell.print("Verbose Boot:     ");
    shell.println(if (config.VERBOSE_BOOT) "YES" else "NO");

    shell.print("Serial Debug:     ");
    shell.println(if (config.SERIAL_DEBUG) "YES" else "NO");

    shell.newLine();
    shell.println("To change profile, edit config.zig:");
    shell.println("  pub const PROFILE: Profile = .development;");
    shell.newLine();
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.newLine();
    shell.println("=== Smoke Test Commands ===");
    shell.newLine();
    shell.println("  smoke           - Run smoke tests");
    shell.println("  smoke run       - Run smoke tests");
    shell.println("  smoke full      - Run full test suite");
    shell.println("  smoke all       - Run full test suite");
    shell.println("  smoke status    - Show last test results");
    shell.println("  smoke config    - Show test configuration");
    shell.println("  smoke help      - Show this help");
    shell.newLine();
    shell.println("Related commands:");
    shell.println("  testall         - Run ALL system tests");
    shell.println("  firewall test   - Firewall test suite");
    shell.println("  gateway test    - Gateway test suite");
    shell.newLine();
}
