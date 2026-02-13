//! Zamrud OS - F4.2: System Encryption Shell Commands
//! Commands: sysenc, sysenctest

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const sys_encrypt = @import("../../crypto/sys_encrypt.zig");
const test_sys_encrypt = @import("../../tests/test_sys_encrypt.zig");

// ============================================================================
// sysenc — System encryption status & management
// ============================================================================

pub fn cmdSysEnc(args: []const u8) void {
    if (args.len == 0 or helpers.strEql(args, "status")) {
        showStatus();
    } else if (helpers.strEql(args, "init")) {
        cmdInit();
    } else if (helpers.strEql(args, "stats")) {
        showStats();
    } else if (helpers.strEql(args, "clear")) {
        cmdClear();
    } else if (helpers.strEql(args, "help")) {
        showHelp();
    } else {
        // Try "setkey <passphrase>"
        const parsed = helpers.parseArgs(args);
        if (helpers.strEql(parsed.cmd, "setkey")) {
            cmdSetKey(parsed.rest);
        } else {
            shell.printError("Unknown sysenc subcommand: ");
            shell.print(args);
            shell.newLine();
            showHelp();
        }
    }
}

fn cmdInit() void {
    sys_encrypt.init();
    shell.printInfoLine("System encryption initialized");
}

fn cmdSetKey(args: []const u8) void {
    if (args.len == 0) {
        shell.printError("Usage: sysenc setkey <passphrase>");
        shell.newLine();
        return;
    }

    sys_encrypt.setMasterKeyFromPassphrase(args);
    shell.printInfoLine("Master key set from passphrase");

    // Show domain key status
    const domains = [_]sys_encrypt.KeyDomain{ .config, .identity, .ipc, .chain };
    for (domains) |d| {
        if (sys_encrypt.getDomainKey(d)) |_| {
            shell.print("  ");
            shell.print(d.name());
            shell.println(": derived ✅");
        }
    }
}

fn cmdClear() void {
    sys_encrypt.clearMasterKey();
    shell.printInfoLine("Master key cleared — all encrypted data inaccessible");
}

fn showStatus() void {
    shell.newLine();
    shell.printInfoLine("=== SYSTEM ENCRYPTION STATUS ===");

    shell.print("  Initialized:  ");
    shell.println(if (sys_encrypt.isInitialized()) "YES" else "NO");

    shell.print("  Master key:   ");
    shell.println(if (sys_encrypt.isMasterKeySet()) "SET ✅" else "NOT SET ❌");

    shell.println("  Domain keys:");
    const domains = [_]sys_encrypt.KeyDomain{ .config, .identity, .ipc, .chain };
    for (domains) |d| {
        shell.print("    ");
        shell.print(d.name());
        shell.print(": ");
        if (sys_encrypt.isMasterKeySet()) {
            if (sys_encrypt.getDomainKey(d)) |_| {
                shell.println("derived ✅");
            } else {
                shell.println("error ❌");
            }
        } else {
            shell.println("pending");
        }
    }

    showStats();
}

fn showStats() void {
    const s = sys_encrypt.getStats();
    shell.println("  Statistics:");
    shell.print("    Encryptions: ");
    helpers.printU64(s.encrypts);
    shell.newLine();
    shell.print("    Decryptions: ");
    helpers.printU64(s.decrypts);
    shell.newLine();
    shell.print("    Failures:    ");
    helpers.printU64(s.failures);
    shell.newLine();
}

fn showHelp() void {
    shell.newLine();
    shell.printInfoLine("System Encryption (F4.2) Commands:");
    shell.println("  sysenc              Show status");
    shell.println("  sysenc status       Show status");
    shell.println("  sysenc init         Initialize encryption");
    shell.println("  sysenc setkey <pw>  Set master key from passphrase");
    shell.println("  sysenc clear        Clear master key");
    shell.println("  sysenc stats        Show statistics");
    shell.println("  sysenc help         This help");
    shell.println("  sysenctest          Run F4.2 test suite (25 tests)");
    shell.newLine();
}

// ============================================================================
// sysenctest — Run F4.2 test suite
// ============================================================================

pub fn cmdSysEncTest(_: []const u8) void {
    shell.newLine();
    shell.printInfoLine("Running F4.2 System Encryption Tests...");
    shell.newLine();

    const passed = test_sys_encrypt.runTests();

    if (passed) {
        shell.printInfoLine("F4.2 System Encryption: ALL PASSED [OK]");
    } else {
        shell.printError("F4.2 System Encryption: SOME FAILED [!!]");
        shell.newLine();
    }
    shell.newLine();
}
