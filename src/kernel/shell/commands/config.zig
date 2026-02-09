//! Zamrud OS - Config Shell Commands
//! Shell interface for runtime configuration management

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const config_store = @import("../../persist/config_store.zig");
const identity_store = @import("../../persist/identity_store.zig");

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "show")) {
        showConfig(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "set")) {
        setConfig(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "get")) {
        getConfig(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "delete") or helpers.strEql(parsed.cmd, "del")) {
        deleteConfig(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "save")) {
        saveConfig();
    } else if (helpers.strEql(parsed.cmd, "load")) {
        loadConfig();
    } else if (helpers.strEql(parsed.cmd, "reset")) {
        resetConfig();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else {
        shell.printError("config: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'config help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CONFIG - Runtime Configuration");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: config <command> [args]");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  help              Show this help");
    shell.println("  show              Show all config entries");
    shell.println("  show <section>    Show section (system/network/security)");
    shell.println("  get <key>         Get specific value");
    shell.println("  set <key> <value> Set config value");
    shell.println("  delete <key>      Delete config entry");
    shell.println("  save              Save config to disk");
    shell.println("  load              Load config from disk");
    shell.println("  reset             Reset to defaults");
    shell.newLine();

    shell.println("Sections: system, network, security, identity, chain");
    shell.newLine();

    shell.println("Examples:");
    shell.println("  config set system.hostname my-node");
    shell.println("  config get network.p2p_port");
    shell.println("  config show security");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run config persistence tests");
    shell.println("  test quick        Quick health check");
    shell.newLine();
}

fn showConfig(section: []const u8) void {
    if (!config_store.isInitialized()) {
        shell.printErrorLine("Config not initialized");
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine("  RUNTIME CONFIGURATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Entries:      ");
    helpers.printUsize(config_store.getEntryCount());
    shell.newLine();

    shell.print("  Saved on disk:");
    if (config_store.hasSavedConfig()) {
        shell.printSuccessLine(" YES");
    } else {
        shell.printWarningLine(" NO");
    }

    shell.print("  Loaded from:  ");
    if (config_store.wasLoadedFromDisk()) {
        shell.printSuccessLine("Disk");
    } else {
        shell.println("Defaults");
    }

    shell.print("  Unsaved:      ");
    if (config_store.isDirty()) {
        shell.printWarningLine("YES");
    } else {
        shell.printSuccessLine("NO");
    }

    shell.newLine();

    const trimmed = helpers.trim(section);
    var shown: usize = 0;
    var i: usize = 0;

    while (i < 64) : (i += 1) {
        const entry = config_store.getEntryByIndex(i) orelse break;

        // Filter by section if specified
        if (trimmed.len > 0) {
            if (!startsWith(entry.key, trimmed)) continue;
        }

        shell.print("  ");
        shell.print(entry.key);

        // Padding
        var pad: usize = 0;
        while (pad + entry.key.len < 28) : (pad += 1) {
            shell.print(" ");
        }

        shell.print("= ");
        shell.println(entry.value);
        shown += 1;
    }

    if (shown == 0 and trimmed.len > 0) {
        shell.print("  No entries matching '");
        shell.print(trimmed);
        shell.println("'");
    }

    shell.newLine();
}

fn getConfig(args: []const u8) void {
    const key = helpers.trim(args);
    if (key.len == 0) {
        shell.println("Usage: config get <key>");
        return;
    }

    if (config_store.get(key)) |value| {
        shell.print(key);
        shell.print(" = ");
        shell.println(value);
    } else {
        shell.printError("Key not found: ");
        shell.println(key);
    }
}

fn setConfig(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: config set <key> <value>");
        return;
    }

    const parsed = helpers.splitFirst(args, ' ');
    if (parsed.rest.len == 0) {
        shell.printErrorLine("Missing value");
        return;
    }

    const key = parsed.first;
    const value = helpers.trim(parsed.rest);

    if (config_store.set(key, value)) {
        shell.printSuccess("[OK] ");
        shell.print(key);
        shell.print(" = ");
        shell.println(value);
    } else {
        shell.printErrorLine("Failed to set config");
    }
}

fn deleteConfig(args: []const u8) void {
    const key = helpers.trim(args);
    if (key.len == 0) {
        shell.println("Usage: config delete <key>");
        return;
    }

    if (config_store.delete(key)) {
        shell.printSuccess("[OK] Deleted: ");
        shell.println(key);
    } else {
        shell.printError("Key not found: ");
        shell.println(key);
    }
}

fn saveConfig() void {
    shell.printInfoLine("Saving config to disk...");

    if (config_store.saveToDisk()) {
        shell.printSuccessLine("[OK] Config saved to /disk/CONFIG.DAT");
    } else {
        shell.printErrorLine("Failed to save config!");
    }
}

fn loadConfig() void {
    shell.printInfoLine("Loading config from disk...");

    if (config_store.loadFromDisk()) {
        shell.printSuccessLine("[OK] Config loaded from /disk/CONFIG.DAT");
        shell.print("  Entries: ");
        helpers.printUsize(config_store.getEntryCount());
        shell.newLine();
    } else {
        shell.printErrorLine("Failed to load config (or no saved config)");
    }
}

fn resetConfig() void {
    shell.printWarningLine("Resetting config to defaults...");
    config_store.init();
    shell.printSuccessLine("[OK] Config reset to defaults");
}

fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else {
        shell.println("config test options: all, quick");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Config Quick Test...");
    shell.newLine();

    var ok = true;

    shell.print("  Initialized:  ");
    if (config_store.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Has entries:  ");
    if (config_store.getEntryCount() > 0) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Get works:    ");
    if (config_store.get("system.hostname") != null) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("Config", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("CONFIG PERSISTENCE TEST SUITE");

    var p: u32 = 0;
    var f: u32 = 0;

    // Config store tests
    helpers.printTestCategory(1, 2, "Config Store");
    if (config_store.test_config_store()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    // Identity store tests
    helpers.printTestCategory(2, 2, "Identity Store");
    if (identity_store.test_identity_store()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestResults(p, f);
}

// =============================================================================
// Utility
// =============================================================================

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (str[i] != prefix[i]) return false;
    }
    // Must be followed by '.' or end
    if (str.len == prefix.len) return true;
    return str[prefix.len] == '.';
}
