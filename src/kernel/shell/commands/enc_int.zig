//! F4.1 & F4.3 Shell Commands — Encryption & Hardware Integration
//! Commands: encwho, encfiles, encinttest

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const enc_integration = @import("../../fs/enc_integration.zig");
const encryptfs = @import("../../fs/encryptfs.zig");
const storage = @import("../../drivers/storage/storage.zig");
const registry = @import("../../integrity/registry.zig");
const hash_mod = @import("../../crypto/hash.zig");

// =============================================================================
// encwho — Show current encryption identity & Hardware Binding
// =============================================================================

pub fn encWhoCommand(_: []const u8) void {
    shell.newLine();
    shell.printInfoLine("=== Encryption Identity & Hardware ===");

    if (!enc_integration.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }

    shell.print("  UID:   ");
    helpers.printU16(enc_integration.getCurrentOwnerUid());
    shell.newLine();

    shell.print("  Role:  ");
    shell.println(enc_integration.getCurrentOwnerRole().toString());

    shell.print("  Key:   ");
    if (enc_integration.isKeyActive()) {
        shell.println("ACTIVE (unlocked)");
    } else {
        shell.println("LOCKED");
    }

    shell.print("  EncFS: ");
    if (encryptfs.isKeySet()) {
        shell.println("key set");
    } else {
        shell.println("no key");
    }

    // 🆕 F4.3 Hardware Binding Status (ROBUST FIX)
    shell.print("  HW Bind: ");
    if (storage.getDriveCount() > 0) {
        // Cari secara otomatis drive mana yang memegang partisi utama
        const target_drive_idx = if (storage.findFAT32Partition()) |p| p.drive_index else 0;

        if (storage.getDriveSerial(target_drive_idx)) |serial_str| {
            var serial_hash: [32]u8 = undefined;
            hash_mod.sha256Into(serial_str, &serial_hash);

            if (registry.isInitialized() and registry.isRegistered(&serial_hash)) {
                shell.println("SECURE (Bound to Ledger)");
            } else {
                shell.println("UNREGISTERED (Untrusted Drive)");
            }
        } else {
            shell.println("UNKNOWN (Failed to extract serial)");
        }
    } else {
        shell.println("VIRTUAL (No Physical Drive)");
    }

    const s = enc_integration.getStats();
    shell.print("  Auto-keys: ");
    helpers.printU64(s.auto_keys);
    shell.newLine();
    shell.print("  Denied:    ");
    helpers.printU64(s.access_denied);
    shell.newLine();
    shell.print("  Overrides: ");
    helpers.printU64(s.root_overrides);
    shell.newLine();
}

// =============================================================================
// encfiles — List encrypted files with ownership
// =============================================================================

pub fn encFilesCommand(_: []const u8) void {
    shell.newLine();
    shell.printInfoLine("=== Encrypted Files ===");

    if (!encryptfs.isInitialized()) {
        shell.println("  Not initialized");
        return;
    }

    const count = encryptfs.getFileCount();
    if (count == 0) {
        shell.println("  (no files)");
        return;
    }

    shell.println("  NAME                    UID   ROLE   SIZE");
    shell.println("  ----                    ---   ----   ----");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (encryptfs.getFileByIndex(i)) |f| {
            shell.print("  ");
            shell.print(f.getName());

            // Pad name to 24 chars
            var pad = f.getName().len;
            while (pad < 24) : (pad += 1) {
                shell.print(" ");
            }

            helpers.printU16(f.owner_uid);
            shell.print("   ");
            shell.print(f.owner_role.toString());
            shell.print("   ");
            helpers.printUsize(f.original_size);
            shell.println("B");
        }
    }

    shell.print("  Total: ");
    helpers.printUsize(count);
    shell.newLine();
}

// =============================================================================
// encinttest — Run F4.1 integration tests
// =============================================================================

pub fn encIntTestCommand(_: []const u8) void {
    shell.newLine();
    shell.println("Running F4.1 & F4.3 integration tests...");
    const result = enc_integration.runTests();
    if (result) {
        shell.printInfoLine("F4.1: ALL TESTS PASSED");
    } else {
        shell.printError("F4.1: SOME TESTS FAILED");
        shell.newLine();
    }
}
