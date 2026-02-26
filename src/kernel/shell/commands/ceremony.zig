//! Zamrud OS - Trust Ceremony Shell Commands
//! H.7: Updated for v2 ceremony with trust anchors + proper reset

const serial = @import("../../drivers/serial/serial.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const keyboard = @import("../../drivers/input/keyboard.zig");
const trust_ceremony = @import("../../boot/trust_ceremony.zig");
const keyring = @import("../../identity/keyring.zig");
const identity = @import("../../identity/identity.zig");
const identity_store = @import("../../persist/identity_store.zig");
const config_store = @import("../../persist/config_store.zig");
const fat32 = @import("../../fs/fat32.zig");
const sys_encrypt = @import("../../crypto/sys_encrypt.zig");

pub fn execute(args: []const u8) void {
    if (args.len == 0 or strEql(args, "status")) {
        showStatus();
    } else if (strEql(args, "start")) {
        startCeremony();
    } else if (strEql(args, "reset")) {
        resetCeremony();
    } else if (strEql(args, "verify")) {
        verifyTrust();
    } else if (strEql(args, "test")) {
        _ = trust_ceremony.runTests();
    } else if (strEql(args, "help")) {
        showHelp();
    } else {
        printStr("Usage: ceremony [status|start|reset|verify|test|help]\n");
    }
}

fn showHelp() void {
    printStr("\n");
    printStr("Trust Ceremony Commands:\n");
    printStr("  ceremony status  - Show ceremony and trust anchor status\n");
    printStr("  ceremony start   - Run first-boot trust ceremony wizard\n");
    printStr("  ceremony reset   - Delete all identity data and reset\n");
    printStr("  ceremony verify  - Verify trust anchor integrity\n");
    printStr("  ceremony test    - Run H.7 ceremony tests\n");
    printStr("\n");
}

fn showStatus() void {
    printStr("\n=== Trust Ceremony Status ===\n\n");

    printStr("  Initialized:  ");
    if (trust_ceremony.isInitialized()) printStr("YES\n") else printStr("NO\n");

    printStr("  First boot:   ");
    if (trust_ceremony.isFirstBoot()) printStr("YES\n") else printStr("NO\n");

    printStr("  Complete:     ");
    if (trust_ceremony.isCeremonyComplete()) printStr("YES\n") else printStr("NO\n");

    printStr("  Version:      ");
    printNum(trust_ceremony.getCeremonyVersion());
    printStr("\n");

    printStr("  Owner:        ");
    if (trust_ceremony.getSystemOwner()) |owner| {
        printStr("@");
        printStr(owner);
        printStr("\n");
    } else {
        printStr("(none)\n");
    }

    // H.7: Show file status
    printStr("\n  Files on disk:\n");
    printStr("    IDENTITY.DAT: ");
    if (identity_store.hasIdentityFile()) {
        if (identity_store.hasSavedIdentities()) {
            printStr("VALID\n");
        } else {
            printStr("EXISTS (invalid format)\n");
        }
    } else {
        printStr("NOT FOUND\n");
    }

    printStr("    CONFIG.DAT:   ");
    if (config_store.hasSavedConfig()) {
        printStr("EXISTS\n");
    } else {
        printStr("NOT FOUND\n");
    }

    // H.7: Show trust anchor status
    printStr("\n  Trust anchor: ");
    if (trust_ceremony.getTrustAnchor()) |anchor| {
        var shown: usize = 0;
        while (shown < 16 and shown < anchor.len) : (shown += 1) {
            if (terminal.isInitialized()) terminal.writeChar(anchor[shown]);
        }
        printStr("...\n");
    } else {
        printStr("(not set)\n");
    }

    // H.7: Show owner identity details
    if (keyring.getSystemOwner()) |owner_id| {
        printStr("\n  Owner Identity:\n");
        printStr("    Address:    ");
        printStr(owner_id.getAddress());
        printStr("\n");
        printStr("    Credential: ");
        if (owner_id.credential_type == .password) {
            printStr("PASSWORD\n");
        } else {
            printStr("PIN\n");
        }
        printStr("    Trust OK:   ");
        if (keyring.verifyTrustHash(owner_id)) {
            printStr("YES\n");
        } else {
            printStr("FAILED!\n");
        }
    }

    printStr("\n");
}

fn startCeremony() void {
    // Check if already complete AND files exist
    if (trust_ceremony.isCeremonyComplete() and identity_store.hasIdentityFile()) {
        printStr("\n");
        printStr("  Ceremony already completed!\n");
        printStr("  Run 'ceremony reset' first to redo setup.\n");
        printStr("\n");
        return;
    }

    // Run ceremony
    if (trust_ceremony.runCeremony()) {
        printStr("\n  Ceremony completed successfully!\n");
        printStr("  Please reboot to apply changes.\n\n");
    }
}

fn verifyTrust() void {
    printStr("\n=== Trust Anchor Verification ===\n\n");

    if (!trust_ceremony.isCeremonyComplete()) {
        printStr("  Ceremony not complete - nothing to verify.\n\n");
        return;
    }

    printStr("  Verifying trust anchor... ");
    if (trust_ceremony.verifyTrustAnchor()) {
        printStr("PASSED\n");
        printStr("  System owner identity matches stored trust anchor.\n");
    } else {
        printStr("FAILED!\n");
        printStr("  WARNING: Trust anchor mismatch! System may be compromised.\n");
    }
    printStr("\n");
}

fn resetCeremony() void {
    printStr("\n");
    printStr("  +========================================+\n");
    printStr("  |  WARNING: DESTRUCTIVE OPERATION       |\n");
    printStr("  +========================================+\n");
    printStr("  |  This will DELETE:                    |\n");
    printStr("  |    - All stored identities            |\n");
    printStr("  |    - Trust anchors                    |\n");
    printStr("  |    - System configuration             |\n");
    printStr("  |    - Encryption keys                  |\n");
    printStr("  |                                       |\n");
    printStr("  |  You will need your 24-word seed     |\n");
    printStr("  |  phrase to recover your identity!    |\n");
    printStr("  +========================================+\n");
    printStr("\n");
    printStr("  Type 'YES' to confirm, or press ESC to cancel: ");

    // Wait for confirmation
    var confirm_buf: [8]u8 = [_]u8{0} ** 8;
    var confirm_len: usize = 0;

    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == 0x1B) {
                // ESC - cancel
                printStr("\n\n  Reset cancelled.\n\n");
                return;
            }

            if (key == '\n' or key == '\r') {
                break;
            }

            if (key == 0x08 or key == 127) {
                if (confirm_len > 0) {
                    confirm_len -= 1;
                    confirm_buf[confirm_len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                        terminal.writeChar(' ');
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key >= 32 and key < 127 and confirm_len < 7) {
                confirm_buf[confirm_len] = key;
                confirm_len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar(key);
                }
            }
        }
        asm volatile ("pause");
    }

    printStr("\n\n");

    // Check confirmation
    if (!strEql(confirm_buf[0..confirm_len], "YES")) {
        printStr("  Confirmation failed. Reset cancelled.\n\n");
        return;
    }

    printStr("  Performing full reset...\n\n");

    var success = true;

    // Step 1: Delete disk files
    printStr("  [1/5] Deleting disk files...\n");

    if (fat32.isMounted()) {
        // Delete IDENTITY.DAT
        if (fat32.findInRoot("IDENTITY.DAT") != null) {
            if (fat32.deleteFile("IDENTITY.DAT")) {
                printStr("        [OK] IDENTITY.DAT deleted\n");
            } else {
                printStr("        [FAIL] Could not delete IDENTITY.DAT\n");
                success = false;
            }
        } else {
            printStr("        [--] IDENTITY.DAT not found\n");
        }

        // Delete CONFIG.DAT
        if (fat32.findInRoot("CONFIG.DAT") != null) {
            if (fat32.deleteFile("CONFIG.DAT")) {
                printStr("        [OK] CONFIG.DAT deleted\n");
            } else {
                printStr("        [FAIL] Could not delete CONFIG.DAT\n");
                success = false;
            }
        } else {
            printStr("        [--] CONFIG.DAT not found\n");
        }
    } else {
        printStr("        [FAIL] Disk not mounted!\n");
        success = false;
    }

    // Step 2: Clear system encryption key
    printStr("  [2/5] Clearing encryption keys...\n");
    sys_encrypt.clearMasterKey();
    printStr("        [OK] Master key cleared\n");

    // Step 3: Reset keyring
    printStr("  [3/5] Resetting keyring...\n");
    keyring.init();
    printStr("        [OK] Keyring cleared\n");

    // Step 4: Reset config to defaults
    printStr("  [4/5] Resetting configuration...\n");
    config_store.init();
    printStr("        [OK] Config reset to defaults\n");

    // Step 5: Reset ceremony state
    printStr("  [5/5] Resetting ceremony state...\n");
    if (trust_ceremony.resetCeremony()) {
        printStr("        [OK] Ceremony state reset\n");
    } else {
        printStr("        [FAIL] Could not reset ceremony\n");
        success = false;
    }

    printStr("\n");

    if (success) {
        printStr("  +========================================+\n");
        printStr("  |  RESET COMPLETE                       |\n");
        printStr("  +========================================+\n");
        printStr("  |                                       |\n");
        printStr("  |  Next steps:                          |\n");
        printStr("  |    1. Run 'reboot'                    |\n");
        printStr("  |    2. Ceremony will start on boot     |\n");
        printStr("  |                                       |\n");
        printStr("  |  Or run 'ceremony start' now          |\n");
        printStr("  |                                       |\n");
        printStr("  +========================================+\n");
    } else {
        printStr("  +========================================+\n");
        printStr("  |  RESET INCOMPLETE                     |\n");
        printStr("  +========================================+\n");
        printStr("  |                                       |\n");
        printStr("  |  Some operations failed.              |\n");
        printStr("  |  Try rebooting and running            |\n");
        printStr("  |  'ceremony reset' again.              |\n");
        printStr("  |                                       |\n");
        printStr("  +========================================+\n");
    }

    printStr("\n");

    // Verify files are gone
    printStr("  Verification:\n");
    printStr("    IDENTITY.DAT: ");
    if (fat32.findInRoot("IDENTITY.DAT") != null) {
        printStr("STILL EXISTS!\n");
    } else {
        printStr("DELETED\n");
    }

    printStr("    CONFIG.DAT:   ");
    if (fat32.findInRoot("CONFIG.DAT") != null) {
        printStr("STILL EXISTS!\n");
    } else {
        printStr("DELETED\n");
    }

    printStr("    First boot:   ");
    if (trust_ceremony.isFirstBoot()) {
        printStr("YES (ready for ceremony)\n");
    } else {
        printStr("NO (may need reboot)\n");
    }

    printStr("\n");
}

fn printStr(s: []const u8) void {
    if (terminal.isInitialized()) {
        for (s) |c| terminal.writeChar(c);
    }
    serial.writeString(s);
}

fn printNum(val: u32) void {
    if (val == 0) {
        printStr("0");
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        if (terminal.isInitialized()) terminal.writeChar(buf[i]);
        serial.writeChar(buf[i]);
    }
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}
