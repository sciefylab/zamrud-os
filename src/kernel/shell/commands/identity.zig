//! Zamrud OS - Identity Commands

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const identity = @import("../../identity/identity.zig");
const identity_store = @import("../../persist/identity_store.zig");

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "info")) {
        showInfo();
    } else if (helpers.strEql(parsed.cmd, "list")) {
        listIdentities();
    } else if (helpers.strEql(parsed.cmd, "create")) {
        createIdentity(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "unlock")) {
        unlockIdentity(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "lock")) {
        lockSession();
    } else if (helpers.strEql(parsed.cmd, "privacy")) {
        showPrivacy();
    } else if (helpers.strEql(parsed.cmd, "export")) {
        exportIdentities();
    } else if (helpers.strEql(parsed.cmd, "import")) {
        importIdentities();
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showPersistStatus();
    } else {
        shell.printError("identity: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'identity help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  IDENTITY - User Identity Management");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: identity <command> [args]");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  help              Show this help");
    shell.println("  info              Show current identity");
    shell.println("  list              List all identities");
    shell.println("  create <n> <pin>  Create new identity");
    shell.println("  unlock <n> <pin>  Unlock identity");
    shell.println("  lock              Lock current session");
    shell.println("  privacy           Show privacy settings");
    shell.newLine();

    shell.println("Persistence:");
    shell.println("  export            Save identities to disk");
    shell.println("  import            Load identities from disk");
    shell.println("  status            Show persistence status");
    shell.newLine();

    shell.println("Test Commands:");
    shell.println("  test              Run all identity tests");
    shell.println("  test quick        Quick health check");
    shell.println("  test keyring      Test keyring module");
    shell.println("  test auth         Test auth module");
    shell.println("  test privacy      Test privacy module");
    shell.newLine();

    shell.println("Related: whoami, config");
    shell.newLine();
}

fn exportIdentities() void {
    shell.printInfoLine("Exporting identities to disk...");

    if (identity.getIdentityCount() == 0) {
        shell.printWarningLine("No identities to export");
        return;
    }

    if (identity_store.saveToDisk()) {
        shell.printSuccessLine("[OK] Identities saved to /disk/IDENTITY.DAT");
        shell.print("  Exported: ");
        helpers.printUsize(identity.getIdentityCount());
        shell.println(" identities");
        shell.println("  Note: Private keys stored encrypted (PIN required to unlock)");
    } else {
        shell.printErrorLine("Failed to export identities!");
    }
}

fn importIdentities() void {
    shell.printInfoLine("Importing identities from disk...");

    if (!identity_store.hasSavedIdentities()) {
        shell.printWarningLine("No saved identities found on disk");
        return;
    }

    shell.printWarningLine("Warning: This will replace current identities!");

    if (identity_store.loadFromDisk()) {
        shell.printSuccessLine("[OK] Identities loaded from /disk/IDENTITY.DAT");
        shell.print("  Imported: ");
        helpers.printUsize(identity.getIdentityCount());
        shell.println(" identities");
        shell.println("  Note: All identities are LOCKED. Use 'identity unlock <name> <pin>'");
    } else {
        shell.printErrorLine("Failed to import identities!");
    }
}

fn showPersistStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  IDENTITY PERSISTENCE STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Store initialized: ");
    if (identity_store.isInitialized()) shell.printSuccessLine("Yes") else shell.printErrorLine("No");

    shell.print("  Loaded from disk:  ");
    if (identity_store.wasLoadedFromDisk()) shell.printSuccessLine("Yes") else shell.println("No");

    shell.print("  Saved on disk:     ");
    if (identity_store.hasSavedIdentities()) shell.printSuccessLine("Yes (/disk/IDENTITY.DAT)") else shell.println("No");

    shell.print("  Current count:     ");
    helpers.printUsize(identity.getIdentityCount());
    shell.newLine();

    shell.print("  Last save count:   ");
    helpers.printUsize(identity_store.getLastSaveCount());
    shell.newLine();

    shell.newLine();
}

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else if (helpers.strEql(opt, "keyring")) {
        runModuleTest("keyring");
    } else if (helpers.strEql(opt, "auth")) {
        runModuleTest("auth");
    } else if (helpers.strEql(opt, "privacy")) {
        runModuleTest("privacy");
    } else if (helpers.strEql(opt, "names")) {
        runModuleTest("names");
    } else if (helpers.strEql(opt, "persist")) {
        runModuleTest("persist");
    } else {
        shell.println("identity test options: all, quick, keyring, auth, privacy, names, persist");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("Identity Quick Test...");
    shell.newLine();

    var ok = true;

    shell.print("  Initialized:  ");
    if (identity.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Count works:  ");
    if (identity.getIdentityCount() >= 0) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Store ready:  ");
    if (identity_store.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("Identity", ok);
}

fn runAllTests() void {
    const keyring = @import("../../identity/keyring.zig");
    const auth = @import("../../identity/auth.zig");
    const privacy = @import("../../identity/privacy.zig");
    const names = @import("../../identity/names.zig");

    helpers.printTestHeader("IDENTITY TEST SUITE");

    var p: u32 = 0;
    var f: u32 = 0;

    helpers.printTestCategory(1, 5, "Keyring");
    if (keyring.test_keyring()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestCategory(2, 5, "Auth");
    if (auth.test_auth()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestCategory(3, 5, "Privacy");
    if (privacy.test_privacy()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestCategory(4, 5, "Names");
    if (names.test_names()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestCategory(5, 5, "Persistence");
    if (identity_store.test_identity_store()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestResults(p, f);
}

fn runModuleTest(module: []const u8) void {
    shell.printInfo("Testing ");
    shell.print(module);
    shell.println("...");

    const result = if (helpers.strEql(module, "keyring"))
        @import("../../identity/keyring.zig").test_keyring()
    else if (helpers.strEql(module, "auth"))
        @import("../../identity/auth.zig").test_auth()
    else if (helpers.strEql(module, "privacy"))
        @import("../../identity/privacy.zig").test_privacy()
    else if (helpers.strEql(module, "names"))
        @import("../../identity/names.zig").test_names()
    else if (helpers.strEql(module, "persist"))
        identity_store.test_identity_store()
    else
        false;

    if (result) {
        shell.printSuccessLine("PASSED");
    } else {
        shell.printErrorLine("FAILED");
    }
}

fn showInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  IDENTITY STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized:  ");
    if (identity.isInitialized()) shell.printSuccessLine("Yes") else shell.printErrorLine("No");

    shell.print("  Identities:   ");
    helpers.printUsize(identity.getIdentityCount());
    shell.newLine();

    shell.print("  Session:      ");
    if (identity.isUnlocked()) shell.printSuccessLine("Unlocked") else shell.printWarningLine("Locked");

    shell.print("  Persisted:    ");
    if (identity_store.wasLoadedFromDisk()) shell.printSuccessLine("Yes (from disk)") else shell.println("No");

    if (identity.getCurrentIdentity()) |id| {
        shell.newLine();
        shell.println("  Current:");
        shell.print("    Name:       ");
        const name = id.getName();
        if (name.len > 0) shell.println(name) else shell.println("(anonymous)");
        shell.print("    Address:    ");
        shell.println(id.getAddress());
    }

    shell.newLine();
    shell.print("  Privacy:      ");
    switch (identity.getPrivacyMode()) {
        .stealth => shell.printSuccessLine("Stealth"),
        .pseudonymous => shell.println("Pseudonymous"),
        .public => shell.printWarningLine("Public"),
    }
    shell.newLine();
}

fn listIdentities() void {
    shell.printInfoLine("Registered Identities:");

    const count = identity.getIdentityCount();
    if (count == 0) {
        shell.println("  (none)");
        shell.println("  Use: identity create <name> <pin>");
        if (identity_store.hasSavedIdentities()) {
            shell.println("  Or:  identity import  (load from disk)");
        }
        return;
    }

    const keyring = @import("../../identity/keyring.zig");
    var shown: usize = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const id = keyring.getIdentityByIndex(i);
        if (id != null and id.?.active) {
            shell.print("  ");
            helpers.printUsize(shown + 1);
            shell.print(". ");
            const name = id.?.getName();
            if (name.len > 0) shell.print(name) else shell.print("(anonymous)");
            if (id.?.unlocked) shell.printSuccess(" [UNLOCKED]");
            shell.newLine();
            shown += 1;
        }
    }
    shell.newLine();
}

fn createIdentity(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: identity create <name> <pin>");
        return;
    }

    const parsed = helpers.splitFirst(args, ' ');
    if (parsed.rest.len == 0) {
        shell.printErrorLine("Missing PIN");
        return;
    }

    const name = parsed.first;
    const pin = helpers.trim(parsed.rest);

    if (pin.len < 4) {
        shell.printErrorLine("PIN must be >= 4 chars");
        return;
    }

    shell.print("Creating '");
    shell.print(name);
    shell.println("'...");

    if (identity.createIdentity(name, pin)) |id| {
        shell.printSuccessLine("Created!");
        shell.print("  Address: ");
        shell.println(id.getAddress());

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Auto-saved to disk");
            }
        }
    } else {
        shell.printErrorLine("Failed to create");
    }
}

fn unlockIdentity(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: identity unlock <name> <pin>");
        return;
    }

    const parsed = helpers.splitFirst(args, ' ');
    if (parsed.rest.len == 0) {
        shell.printErrorLine("Missing PIN");
        return;
    }

    if (identity.unlock(parsed.first, helpers.trim(parsed.rest))) {
        shell.printSuccessLine("Unlocked!");
    } else {
        shell.printErrorLine("Wrong name or PIN");
    }
}

fn lockSession() void {
    identity.lock();
    shell.printSuccessLine("Session locked");
}

fn showPrivacy() void {
    const privacy = @import("../../identity/privacy.zig");
    const settings = privacy.getSettings();

    shell.printInfoLine("Privacy Settings:");
    shell.newLine();

    shell.print("  Mode:           ");
    switch (settings.mode) {
        .stealth => shell.printSuccessLine("Stealth"),
        .pseudonymous => shell.println("Pseudonymous"),
        .public => shell.printWarningLine("Public"),
    }

    shell.print("  Hide IP:        ");
    if (settings.hide_ip) shell.printSuccessLine("Yes") else shell.println("No");

    shell.print("  Rotate NodeID:  ");
    if (settings.rotate_node_id) shell.printSuccessLine("Yes") else shell.println("No");

    shell.print("  E2E Encrypt:    ");
    if (settings.encrypt_p2p) shell.printSuccessLine("Yes") else shell.println("No");

    shell.newLine();
}

pub fn whoami() void {
    if (!identity.isInitialized()) {
        shell.printErrorLine("Identity not initialized");
        return;
    }
    if (identity.getCurrentIdentity()) |id| {
        const name = id.getName();
        if (name.len > 0) shell.print(name) else shell.print("(anonymous)");
        shell.print(" (");
        shell.print(id.getAddress());
        shell.println(")");
        if (!id.unlocked) shell.printWarningLine("  [LOCKED]");
    } else {
        shell.printWarningLine("No identity set");
    }
}
