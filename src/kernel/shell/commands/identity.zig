//! Zamrud OS - Identity Commands
//! H.7.1: Added PIN management subcommands

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const ui = @import("../ui.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const keyboard = @import("../../drivers/input/keyboard.zig");
const identity = @import("../../identity/identity.zig");
const identity_store = @import("../../persist/identity_store.zig");
const keyring = @import("../../identity/keyring.zig");
const auth = @import("../../identity/auth.zig");
const constant_time = @import("../../crypto/constant_time.zig");

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
    } else if (helpers.strEql(parsed.cmd, "pin")) {
        // H.7.1: PIN subcommands
        handlePinCommand(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "password")) {
        // Password change
        handlePasswordCommand(parsed.rest);
    } else {
        shell.printError("identity: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'identity help'");
    }
}

fn showHelp() void {
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
        terminal.setBold(true);
    }
    shell.println("  IDENTITY - User Identity Management");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("  ════════════════════════════════════════");
    shell.newLine();

    shell.println("  Usage: identity <command> [args]");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  Basic Commands:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("    help              Show this help");
    shell.println("    info              Show current identity");
    shell.println("    list              List all identities");
    shell.println("    create <n> <pwd>  Create new identity");
    shell.println("    unlock <n> <pwd>  Unlock identity");
    shell.println("    lock              Lock current session");
    shell.println("    privacy           Show privacy settings");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  PIN Management (H.7.1):");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("    pin               Show PIN status");
    shell.println("    pin set           Setup quick-unlock PIN");
    shell.println("    pin change        Change existing PIN");
    shell.println("    pin remove        Remove PIN");
    shell.println("    pin help          PIN detailed help");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  Password Management:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("    password change   Change password");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  Persistence:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("    export            Save identities to disk");
    shell.println("    import            Load identities from disk");
    shell.println("    status            Show persistence status");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  Test Commands:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("    test              Run all identity tests");
    shell.println("    test quick        Quick health check");
    shell.println("    test keyring      Test keyring module");
    shell.println("    test auth         Test auth module");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    shell.println("  Related: whoami, config, ceremony");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();
}

// =============================================================================
// H.7.1: PIN Command Handler
// =============================================================================

fn handlePinCommand(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        showPinStatus();
    } else if (helpers.strEql(parsed.cmd, "set")) {
        cmdPinSet();
    } else if (helpers.strEql(parsed.cmd, "change")) {
        cmdPinChange();
    } else if (helpers.strEql(parsed.cmd, "remove") or helpers.strEql(parsed.cmd, "rm")) {
        cmdPinRemove();
    } else if (helpers.strEql(parsed.cmd, "help")) {
        showPinHelp();
    } else {
        shell.printErrorLine("Unknown PIN command. Use 'identity pin help'");
    }
}

fn showPinStatus() void {
    const theme = ui.getTheme();

    if (!auth.isUnlocked()) {
        shell.printErrorLine("Must be logged in to view PIN status");
        return;
    }

    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
        terminal.setBold(true);
    }
    shell.println("  PIN Status");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.text_normal);
    }

    shell.println("  ────────────────────────────");

    const current = keyring.getCurrentIdentity();
    if (current == null) {
        shell.printErrorLine("  No current identity");
        return;
    }

    shell.print("  Identity:   ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println(current.?.getName());
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }

    shell.print("  Quick PIN:  ");
    if (current.?.has_pin) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_success);
        }
        shell.println("ENABLED ✓");
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_dim);
        }
        shell.println("Not configured");
    }

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }

    shell.newLine();

    if (!current.?.has_pin) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_dim);
        }
        shell.println("  Tip: Use 'identity pin set' to enable quick unlock.");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_dim);
        }
        shell.println("  You can login with PIN or password.");
        shell.println("  Password is required for sensitive operations.");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
    }

    shell.newLine();
}

fn cmdPinSet() void {
    const theme = ui.getTheme();

    if (!auth.isUnlocked()) {
        shell.printErrorLine("Must be logged in to setup PIN");
        return;
    }

    // Check if already has PIN
    if (auth.hasPinConfigured()) {
        shell.printWarningLine("PIN already configured. Use 'identity pin change' to update.");
        return;
    }

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    shell.println("  Setup Quick PIN");
    shell.println("  ────────────────────────────");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();

    // Step 1: Verify password
    shell.print("  Current password: ");
    var password_buf: [64]u8 = [_]u8{0} ** 64;
    const password_len = readPassword(&password_buf);

    if (password_len == 0) {
        shell.newLine();
        shell.printErrorLine("  Cancelled");
        return;
    }

    shell.newLine();

    // Verify password works
    const current = keyring.getCurrentIdentity();
    if (current == null) {
        wipeBuffer(&password_buf);
        shell.printErrorLine("  No current identity");
        return;
    }

    var test_key: [32]u8 = undefined;
    if (!keyring.decryptPrivateKey(current.?, password_buf[0..password_len], &test_key)) {
        wipeBuffer(&password_buf);
        shell.printErrorLine("  Incorrect password");
        return;
    }
    constant_time.secureZero32(&test_key);

    // Step 2: Get new PIN
    shell.print("  New PIN (4-8 digits): ");
    var pin_buf: [16]u8 = [_]u8{0} ** 16;
    const pin_len = readPin(&pin_buf);

    if (pin_len == 0) {
        wipeBuffer(&password_buf);
        shell.newLine();
        shell.printErrorLine("  Cancelled");
        return;
    }

    if (pin_len < 4) {
        wipeBuffer(&password_buf);
        wipeSmallBuffer(&pin_buf);
        shell.newLine();
        shell.printErrorLine("  PIN must be at least 4 digits");
        return;
    }

    shell.newLine();

    // Step 3: Confirm PIN
    shell.print("  Confirm PIN: ");
    var pin_confirm: [16]u8 = [_]u8{0} ** 16;
    const confirm_len = readPin(&pin_confirm);

    shell.newLine();

    if (pin_len != confirm_len or !sliceEql(pin_buf[0..pin_len], pin_confirm[0..confirm_len])) {
        wipeBuffer(&password_buf);
        wipeSmallBuffer(&pin_buf);
        wipeSmallBuffer(&pin_confirm);
        shell.printErrorLine("  PINs do not match");
        return;
    }

    wipeSmallBuffer(&pin_confirm);

    // Step 4: Setup PIN
    if (keyring.setupSecondaryPin(current.?, password_buf[0..password_len], pin_buf[0..pin_len])) {
        shell.newLine();
        shell.printSuccessLine("  PIN configured successfully!");
        shell.newLine();

        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_dim);
        }
        shell.println("  You can now use your PIN for quick login.");
        shell.println("  Password is still required for sensitive operations.");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Changes saved to disk.");
            }
        }
    } else {
        shell.printErrorLine("  Failed to setup PIN");
    }

    // Wipe sensitive data
    wipeBuffer(&password_buf);
    wipeSmallBuffer(&pin_buf);

    shell.newLine();
}

fn cmdPinRemove() void {
    const theme = ui.getTheme();

    if (!auth.isUnlocked()) {
        shell.printErrorLine("Must be logged in to remove PIN");
        return;
    }

    if (!auth.hasPinConfigured()) {
        shell.printInfoLine("No PIN configured");
        return;
    }

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
    }
    shell.println("  Remove Quick PIN");
    shell.println("  ────────────────────────────");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();

    // Verify password
    shell.print("  Password to confirm: ");
    var password_buf: [64]u8 = [_]u8{0} ** 64;
    const password_len = readPassword(&password_buf);

    if (password_len == 0) {
        shell.newLine();
        shell.printErrorLine("  Cancelled");
        return;
    }

    shell.newLine();

    if (auth.removePin(password_buf[0..password_len])) {
        shell.newLine();
        shell.printSuccessLine("  PIN removed");
        shell.println("  Quick unlock is now disabled.");

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Changes saved to disk.");
            }
        }
    } else {
        shell.printErrorLine("  Incorrect password or removal failed");
    }

    wipeBuffer(&password_buf);
    shell.newLine();
}

fn cmdPinChange() void {
    const theme = ui.getTheme();

    if (!auth.isUnlocked()) {
        shell.printErrorLine("Must be logged in to change PIN");
        return;
    }

    if (!auth.hasPinConfigured()) {
        shell.printInfoLine("No PIN configured. Use 'identity pin set' first.");
        return;
    }

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    shell.println("  Change Quick PIN");
    shell.println("  ────────────────────────────");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();

    // Step 1: Verify password (not old PIN — password is always authority)
    shell.print("  Password: ");
    var password_buf: [64]u8 = [_]u8{0} ** 64;
    const password_len = readPassword(&password_buf);

    if (password_len == 0) {
        shell.newLine();
        shell.printErrorLine("  Cancelled");
        return;
    }

    shell.newLine();

    // Verify
    const current = keyring.getCurrentIdentity();
    if (current == null) {
        wipeBuffer(&password_buf);
        shell.printErrorLine("  No current identity");
        return;
    }

    var test_key: [32]u8 = undefined;
    if (!keyring.decryptPrivateKey(current.?, password_buf[0..password_len], &test_key)) {
        wipeBuffer(&password_buf);
        shell.printErrorLine("  Incorrect password");
        return;
    }
    constant_time.secureZero32(&test_key);

    // Step 2: Get new PIN
    shell.print("  New PIN (4-8 digits): ");
    var pin_buf: [16]u8 = [_]u8{0} ** 16;
    const pin_len = readPin(&pin_buf);

    if (pin_len < 4) {
        wipeBuffer(&password_buf);
        wipeSmallBuffer(&pin_buf);
        shell.newLine();
        shell.printErrorLine("  PIN must be at least 4 digits");
        return;
    }

    shell.newLine();

    // Step 3: Confirm
    shell.print("  Confirm new PIN: ");
    var pin_confirm: [16]u8 = [_]u8{0} ** 16;
    const confirm_len = readPin(&pin_confirm);

    shell.newLine();

    if (pin_len != confirm_len or !sliceEql(pin_buf[0..pin_len], pin_confirm[0..confirm_len])) {
        wipeBuffer(&password_buf);
        wipeSmallBuffer(&pin_buf);
        wipeSmallBuffer(&pin_confirm);
        shell.printErrorLine("  PINs do not match");
        return;
    }

    wipeSmallBuffer(&pin_confirm);

    // Step 4: Change PIN
    if (keyring.changeSecondaryPin(current.?, password_buf[0..password_len], pin_buf[0..pin_len])) {
        shell.newLine();
        shell.printSuccessLine("  PIN changed successfully");

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Changes saved to disk.");
            }
        }
    } else {
        shell.printErrorLine("  Failed to change PIN");
    }

    wipeBuffer(&password_buf);
    wipeSmallBuffer(&pin_buf);
    shell.newLine();
}

fn showPinHelp() void {
    const theme = ui.getTheme();

    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
        terminal.setBold(true);
    }
    shell.println("  PIN Management (H.7.1)");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("  ════════════════════════════════════════");
    shell.newLine();

    shell.println("  Quick PIN allows faster login with a 4-8 digit code.");
    shell.println("  Your password remains the primary credential for");
    shell.println("  sensitive operations.");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    shell.println("  Commands:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }

    shell.println("    identity pin           Show PIN status");
    shell.println("    identity pin set       Setup a new PIN");
    shell.println("    identity pin change    Change existing PIN");
    shell.println("    identity pin remove    Remove PIN (disable quick unlock)");
    shell.newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
    }
    shell.println("  Security notes:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    shell.println("    • PIN is for convenience, not maximum security");
    shell.println("    • Password always required for:");
    shell.println("        - Changing password");
    shell.println("        - Exporting keys/seed phrase");
    shell.println("        - Setting up or removing PIN");
    shell.println("    • Changing password invalidates PIN (must re-setup)");
    shell.println("    • Both PIN and password can be used at login");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();
}

// =============================================================================
// Password Command Handler
// =============================================================================

fn handlePasswordCommand(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        shell.println("Usage: identity password change");
    } else if (helpers.strEql(parsed.cmd, "change")) {
        cmdPasswordChange();
    } else {
        shell.printErrorLine("Unknown password command");
    }
}

fn cmdPasswordChange() void {
    const theme = ui.getTheme();

    if (!auth.isUnlocked()) {
        shell.printErrorLine("Must be logged in to change password");
        return;
    }

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    shell.println("  Change Password");
    shell.println("  ────────────────────────────");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();

    // Step 1: Current password
    shell.print("  Current password: ");
    var old_password: [64]u8 = [_]u8{0} ** 64;
    const old_len = readPassword(&old_password);

    if (old_len == 0) {
        shell.newLine();
        shell.printErrorLine("  Cancelled");
        return;
    }

    shell.newLine();

    // Verify old password
    const current = keyring.getCurrentIdentity();
    if (current == null) {
        wipeBuffer(&old_password);
        shell.printErrorLine("  No current identity");
        return;
    }

    var test_key: [32]u8 = undefined;
    if (!keyring.decryptPrivateKey(current.?, old_password[0..old_len], &test_key)) {
        wipeBuffer(&old_password);
        shell.printErrorLine("  Incorrect current password");
        return;
    }
    constant_time.secureZero32(&test_key);

    // Step 2: New password
    shell.print("  New password (8+ chars): ");
    var new_password: [64]u8 = [_]u8{0} ** 64;
    const new_len = readPassword(&new_password);

    if (new_len < 8) {
        wipeBuffer(&old_password);
        wipeBuffer(&new_password);
        shell.newLine();
        shell.printErrorLine("  Password must be at least 8 characters");
        return;
    }

    if (!keyring.isStrongPassword(new_password[0..new_len])) {
        wipeBuffer(&old_password);
        wipeBuffer(&new_password);
        shell.newLine();
        shell.printErrorLine("  Password must include uppercase, lowercase, and number");
        return;
    }

    shell.newLine();

    // Step 3: Confirm new password
    shell.print("  Confirm new password: ");
    var confirm_password: [64]u8 = [_]u8{0} ** 64;
    const confirm_len = readPassword(&confirm_password);

    shell.newLine();

    if (new_len != confirm_len or !sliceEql(new_password[0..new_len], confirm_password[0..confirm_len])) {
        wipeBuffer(&old_password);
        wipeBuffer(&new_password);
        wipeBuffer(&confirm_password);
        shell.printErrorLine("  Passwords do not match");
        return;
    }

    wipeBuffer(&confirm_password);

    // Step 4: Change password
    if (keyring.reEncryptPrivateKey(current.?, old_password[0..old_len], new_password[0..new_len])) {
        shell.newLine();
        shell.printSuccessLine("  Password changed successfully!");

        // Note about PIN
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_warning);
        }
        shell.println("  Note: If you had a PIN, it has been invalidated.");
        shell.println("  Use 'identity pin set' to setup a new PIN.");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Changes saved to disk.");
            }
        }
    } else {
        shell.printErrorLine("  Failed to change password");
    }

    wipeBuffer(&old_password);
    wipeBuffer(&new_password);
    shell.newLine();
}

// =============================================================================
// Input Helpers
// =============================================================================

fn readPassword(buf: *[64]u8) usize {
    var len: usize = 0;

    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                return len;
            }

            if (key == 0x1B) { // ESC
                return 0;
            }

            if (key == keyboard.KEY_BACKSPACE or key == 127) {
                if (len > 0) {
                    len -= 1;
                    buf[len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key == keyboard.KEY_CTRL_C) {
                return 0;
            }

            if (key >= 32 and key < 127 and len < 63) {
                buf[len] = key;
                len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar('*');
                }
            }
        }
        asm volatile ("pause");
    }
}

fn readPin(buf: *[16]u8) usize {
    var len: usize = 0;

    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                return len;
            }

            if (key == 0x1B) { // ESC
                return 0;
            }

            if (key == keyboard.KEY_BACKSPACE or key == 127) {
                if (len > 0) {
                    len -= 1;
                    buf[len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key == keyboard.KEY_CTRL_C) {
                return 0;
            }

            // Only accept digits for PIN
            if (key >= '0' and key <= '9' and len < 8) {
                buf[len] = key;
                len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar('*');
                }
            }
        }
        asm volatile ("pause");
    }
}

fn wipeBuffer(buf: *[64]u8) void {
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        buf[i] = 0;
    }
}

fn wipeSmallBuffer(buf: *[16]u8) void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        buf[i] = 0;
    }
}

fn sliceEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// =============================================================================
// Existing Commands (unchanged)
// =============================================================================

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
        shell.println("  Note: Private keys stored encrypted (password/PIN required)");
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
        shell.println("  Note: All identities are LOCKED. Use 'identity unlock <name> <pwd>'");
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

    shell.print("  Auth ready:   ");
    if (auth.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("Identity", ok);
}

fn runAllTests() void {
    const privacy = @import("../../identity/privacy.zig");
    const names = @import("../../identity/names.zig");

    helpers.printTestHeader("IDENTITY TEST SUITE (H.7.1)");

    var p: u32 = 0;
    var f: u32 = 0;

    helpers.printTestCategory(1, 5, "Keyring (Dual Credential)");
    if (keyring.test_keyring()) {
        shell.printSuccessLine("      PASSED");
        p += 1;
    } else {
        shell.printErrorLine("      FAILED");
        f += 1;
    }

    helpers.printTestCategory(2, 5, "Auth (PIN + Password)");
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
        keyring.test_keyring()
    else if (helpers.strEql(module, "auth"))
        auth.test_auth()
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
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
        terminal.setBold(true);
    }
    shell.println("  IDENTITY STATUS");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("  ════════════════════════════════════════");
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
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_success);
        }
        shell.println("  Current Identity:");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
        shell.print("    Name:       ");
        const name = id.getName();
        if (name.len > 0) shell.println(name) else shell.println("(anonymous)");
        shell.print("    Address:    ");
        shell.println(id.getAddress());
        shell.print("    Type:       ");
        switch (id.credential_type) {
            .password => shell.println("Password"),
            .pin => shell.println("PIN"),
            .none => shell.println("None"),
        }
        shell.print("    Quick PIN:  ");
        if (id.has_pin) {
            shell.printSuccessLine("Enabled");
        } else {
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_dim);
            }
            shell.println("Not configured");
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_normal);
            }
        }
        shell.print("    Is Owner:   ");
        if (id.is_owner) shell.printSuccessLine("Yes") else shell.println("No");
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
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    shell.println("  Registered Identities:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("  ────────────────────────────");

    const count = identity.getIdentityCount();
    if (count == 0) {
        shell.println("  (none)");
        shell.println("  Use: identity create <name> <password>");
        if (identity_store.hasSavedIdentities()) {
            shell.println("  Or:  identity import  (load from disk)");
        }
        shell.newLine();
        return;
    }

    var shown: usize = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const id = keyring.getIdentityByIndex(i);
        if (id != null and id.?.active) {
            shell.print("  ");
            helpers.printUsize(shown + 1);
            shell.print(". ");

            const name = id.?.getName();
            if (name.len > 0) {
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_success);
                }
                shell.print(name);
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_normal);
                }
            } else {
                shell.print("(anonymous)");
            }

            // Status indicators
            if (id.?.unlocked) {
                shell.printSuccess(" [UNLOCKED]");
            }
            if (id.?.has_pin) {
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_info);
                }
                shell.print(" [PIN]");
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_normal);
                }
            }
            if (id.?.is_owner) {
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_warning);
                }
                shell.print(" [OWNER]");
                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_normal);
                }
            }

            shell.newLine();
            shown += 1;
        }
    }
    shell.newLine();
}

fn createIdentity(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: identity create <name> <password>");
        shell.println("  Password: 8+ chars, must include uppercase, lowercase, number");
        return;
    }

    const parsed = helpers.splitFirst(args, ' ');
    if (parsed.rest.len == 0) {
        shell.printErrorLine("Missing password");
        return;
    }

    const name = parsed.first;
    const password = helpers.trim(parsed.rest);

    if (password.len < 8) {
        shell.printErrorLine("Password must be >= 8 chars");
        return;
    }

    if (!keyring.isStrongPassword(password)) {
        shell.printErrorLine("Password must include uppercase, lowercase, and number");
        return;
    }

    shell.print("Creating '");
    shell.print(name);
    shell.println("'...");

    if (keyring.createIdentityWithPassword(name, password)) |id| {
        shell.printSuccessLine("Created!");
        shell.print("  Address: ");
        shell.println(id.getAddress());
        shell.println("  Tip: Use 'identity pin set' to enable quick unlock");

        // Auto-save to disk
        if (identity_store.isInitialized()) {
            if (identity_store.saveToDisk()) {
                shell.printSuccessLine("  Auto-saved to disk");
            }
        }
    } else {
        shell.printErrorLine("Failed to create (weak password or name exists)");
    }
}

fn unlockIdentity(args: []const u8) void {
    if (args.len == 0) {
        shell.println("Usage: identity unlock <name> <password|pin>");
        return;
    }

    const parsed = helpers.splitFirst(args, ' ');
    if (parsed.rest.len == 0) {
        shell.printErrorLine("Missing password or PIN");
        return;
    }

    const credential = helpers.trim(parsed.rest);

    if (auth.unlock(parsed.first, credential)) {
        shell.printSuccessLine("Unlocked!");

        // Show how they unlocked
        if (auth.getLastUnlockMethod() == .pin) {
            shell.println("  (via PIN)");
        } else {
            shell.println("  (via password)");
        }
    } else {
        shell.printErrorLine("Wrong name, password, or PIN");
    }
}

fn lockSession() void {
    identity.lock();
    auth.lock();
    shell.printSuccessLine("Session locked");
}

fn showPrivacy() void {
    const privacy = @import("../../identity/privacy.zig");
    const settings = privacy.getSettings();
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    shell.println("  Privacy Settings:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    shell.println("  ────────────────────────────");
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
