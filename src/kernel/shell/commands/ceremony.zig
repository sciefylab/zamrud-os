//! Zamrud OS - Trust Ceremony Shell Commands
//! H.7: Updated for v2 ceremony with trust anchors + proper reset
//! 🆕 F4.3: Auto-Hardware Binding integrated into Genesis Ceremony
//! 🛠️ FIX: Replaced interactive prompt with 'reset confirm' argument to prevent IRQ locks

const serial = @import("../../drivers/serial/serial.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const trust_ceremony = @import("../../boot/trust_ceremony.zig");
const keyring = @import("../../identity/keyring.zig");
const identity = @import("../../identity/identity.zig");
const identity_store = @import("../../persist/identity_store.zig");
const config_store = @import("../../persist/config_store.zig");
const fat32 = @import("../../fs/fat32.zig");
const sys_encrypt = @import("../../crypto/sys_encrypt.zig");

// 🆕 F4.3: Imports for Hardware Binding
const storage = @import("../../drivers/storage/storage.zig");
const registry = @import("../../integrity/registry.zig");
const hash_mod = @import("../../crypto/hash.zig");

pub fn execute(args: []const u8) void {
    if (args.len == 0 or strEql(args, "status")) {
        showStatus();
    } else if (strEql(args, "start")) {
        startCeremony();
    } else if (strEql(args, "reset")) {
        resetCeremony(false); // Membutuhkan konfirmasi
    } else if (strEql(args, "reset confirm")) {
        resetCeremony(true); // Konfirmasi berhasil
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
    printStr("  ceremony status          - Show ceremony and trust anchor status\n");
    printStr("  ceremony start           - Run first-boot trust ceremony wizard\n");
    printStr("  ceremony reset           - View reset warning\n");
    printStr("  ceremony reset confirm   - Delete all identity data and reset (Destructive)\n");
    printStr("  ceremony verify          - Verify trust anchor integrity\n");
    printStr("  ceremony test            - Run H.7 ceremony tests\n");
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

    // 🆕 F4.3: Show Hardware Binding Status
    printStr("\n  Hardware Binding:\n");
    printStr("    Status:     ");
    const target_drive_idx = if (storage.findFAT32Partition()) |p| p.drive_index else 0;
    if (storage.getDriveSerial(target_drive_idx)) |serial_str| {
        var serial_hash: [32]u8 = undefined;
        hash_mod.sha256Into(serial_str, &serial_hash);
        if (registry.isInitialized() and registry.isRegistered(&serial_hash)) {
            printStr("SECURE (Bound to Ledger)\n");
        } else {
            printStr("UNREGISTERED (Vulnerable)\n");
        }
    } else {
        printStr("UNKNOWN (No Serial)\n");
    }

    printStr("\n");
}

fn startCeremony() void {
    if (trust_ceremony.isCeremonyComplete() and identity_store.hasIdentityFile()) {
        printStr("\n");
        printStr("  Ceremony already completed!\n");
        printStr("  Run 'ceremony reset' first to redo setup.\n");
        printStr("\n");
        return;
    }

    if (trust_ceremony.runCeremony()) {
        printStr("\n  Ceremony completed successfully!\n");

        // --- 🆕 F4.3: AUTO HARDWARE BINDING SAAT GENESIS CEREMONY ---
        printStr("  Securing hardware identity...\n");
        const target_drive_idx = if (storage.findFAT32Partition()) |p| p.drive_index else 0;

        if (storage.getDriveSerial(target_drive_idx)) |serial_str| {
            var serial_hash: [32]u8 = undefined;
            hash_mod.sha256Into(serial_str, &serial_hash);

            if (registry.registerFile("Drive-Binding", &serial_hash, .physical_drive, 1)) {
                printStr("  [SECURITY] Anti-Evil Maid Protection Automatically Activated!\n");
                printStr("  [SECURITY] Hardware permanently bound to this OS instance.\n");
            } else {
                printStr("  [WARNING] Failed to bind hardware to Ledger. Registry full?\n");
            }
        } else {
            printStr("  [WARNING] Could not extract Hardware DNA for binding.\n");
        }
        // ------------------------------------------------------

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

fn resetCeremony(confirmed: bool) void {
    printStr("\n");
    printStr("  +========================================+\n");
    printStr("  |  WARNING: DESTRUCTIVE OPERATION        |\n");
    printStr("  +========================================+\n");
    printStr("  |  This will DELETE:                     |\n");
    printStr("  |    - All stored identities             |\n");
    printStr("  |    - Trust anchors                     |\n");
    printStr("  |    - System configuration              |\n");
    printStr("  |    - Encryption keys                   |\n");
    printStr("  |    - Hardware Binding Ledger           |\n");
    printStr("  |                                        |\n");
    printStr("  |  You will need your 24-word seed       |\n");
    printStr("  |  phrase to recover your identity!      |\n");
    printStr("  +========================================+\n\n");

    // 🛡️ FIX: Jika user hanya mengetik 'ceremony reset', blokir dan beri tahu perintah yang benar
    if (!confirmed) {
        printStr("  To proceed with the reset, you must explicitly type:\n");
        printStr("    ceremony reset confirm\n\n");
        return;
    }

    printStr("  Performing full reset...\n\n");

    var success = true;

    printStr("  [1/6] Deleting disk files...\n");
    if (fat32.isMounted()) {
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

    printStr("  [2/6] Clearing encryption keys...\n");
    sys_encrypt.clearMasterKey();
    printStr("        [OK] Master key cleared\n");

    printStr("  [3/6] Resetting keyring...\n");
    keyring.init();
    printStr("        [OK] Keyring cleared\n");

    printStr("  [4/6] Resetting configuration...\n");
    config_store.init();
    printStr("        [OK] Config reset to defaults\n");

    printStr("  [5/6] Clearing Hardware Ledger...\n");
    registry.init();
    printStr("        [OK] Ledger Registry flushed\n");

    printStr("  [6/6] Resetting ceremony state...\n");
    if (trust_ceremony.resetCeremony()) {
        printStr("        [OK] Ceremony state reset\n");
    } else {
        printStr("        [FAIL] Could not reset ceremony\n");
        success = false;
    }

    printStr("\n");

    if (success) {
        printStr("  +========================================+\n");
        printStr("  |  RESET COMPLETE                        |\n");
        printStr("  +========================================+\n");
        printStr("  |                                        |\n");
        printStr("  |  Next steps:                           |\n");
        printStr("  |    1. Run 'reboot'                     |\n");
        printStr("  |    2. Ceremony will start on boot      |\n");
        printStr("  |                                        |\n");
        printStr("  |  Or run 'ceremony start' now           |\n");
        printStr("  |                                        |\n");
        printStr("  +========================================+\n");
    } else {
        printStr("  +========================================+\n");
        printStr("  |  RESET INCOMPLETE                      |\n");
        printStr("  +========================================+\n");
        printStr("  |                                        |\n");
        printStr("  |  Some operations failed.               |\n");
        printStr("  |  Try rebooting and running             |\n");
        printStr("  |  'ceremony reset confirm' again.       |\n");
        printStr("  |                                        |\n");
        printStr("  +========================================+\n");
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
