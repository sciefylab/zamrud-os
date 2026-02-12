//! Zamrud OS - Encrypted Filesystem Shell Commands (F4)
//! Commands: encfs, encrypt, decrypt, enctest

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const encryptfs = @import("../../fs/encryptfs.zig");
const aes = @import("../../crypto/aes.zig");
const identity = @import("../../identity/identity.zig");
const serial = @import("../../drivers/serial/serial.zig");

// =============================================================================
// Print helper (since helpers.zig may not have printNum)
// =============================================================================

fn printNum(val: u64) void {
    if (val == 0) {
        shell.print("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    // Print in reverse
    while (i > 0) {
        i -= 1;
        const s: [1]u8 = .{buf[i]};
        shell.print(&s);
    }
}

// =============================================================================
// Main dispatcher
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const subcmd = parsed.cmd;

    if (subcmd.len == 0 or helpers.strEql(subcmd, "status")) {
        cmdStatus();
    } else if (helpers.strEql(subcmd, "help")) {
        cmdHelp();
    } else if (helpers.strEql(subcmd, "test")) {
        cmdEncTest();
    } else {
        shell.printError("Unknown encfs subcommand: ");
        shell.print(subcmd);
        shell.newLine();
        shell.println("  Use: encfs help");
    }
}

// =============================================================================
// encfs status
// =============================================================================

fn cmdStatus() void {
    shell.println("");
    shell.printInfoLine("=== Encrypted Filesystem (F4) ===");

    shell.print("  Initialized: ");
    shell.println(if (encryptfs.isInitialized()) "YES" else "NO");

    shell.print("  Key set:     ");
    shell.println(if (encryptfs.isKeySet()) "YES (unlocked)" else "NO (locked)");

    const stats = encryptfs.getStats();
    shell.print("  Files:       ");
    printNum(@intCast(stats.files));
    shell.newLine();

    shell.print("  Encrypts:    ");
    printNum(stats.encrypts);
    shell.newLine();

    shell.print("  Decrypts:    ");
    printNum(stats.decrypts);
    shell.newLine();

    shell.print("  Violations:  ");
    printNum(stats.violations);
    shell.newLine();

    // List files
    if (stats.files > 0) {
        shell.println("");
        shell.println("  Files:");
        var i: usize = 0;
        while (i < stats.files) : (i += 1) {
            if (encryptfs.getFileByIndex(i)) |f| {
                shell.print("    ");
                shell.print(f.getName());
                shell.print(" (");
                printNum(@intCast(f.original_size));
                shell.print(" bytes, stored: ");
                printNum(@intCast(f.data_len));
                shell.println(" bytes)");
            }
        }
    }

    shell.println("");
}

// =============================================================================
// encrypt <filename> <data>
// =============================================================================

pub fn cmdEncrypt(args: []const u8) void {
    if (!encryptfs.isInitialized()) {
        shell.printError("Encrypted filesystem not initialized");
        shell.newLine();
        return;
    }

    if (!encryptfs.isKeySet()) {
        shell.printError("No encryption key set! Use: enckey <passphrase>");
        shell.newLine();
        return;
    }

    const parsed = helpers.parseArgs(args);
    const filename = parsed.cmd;
    const data = parsed.rest;

    if (filename.len == 0 or data.len == 0) {
        shell.println("Usage: encrypt <filename> <data>");
        return;
    }

    if (encryptfs.encryptFile(filename, data)) {
        shell.print("  Encrypted: ");
        shell.println(filename);
    } else {
        shell.printError("Encryption failed!");
        shell.newLine();
    }
}

// =============================================================================
// decrypt <filename>
// =============================================================================

pub fn cmdDecrypt(args: []const u8) void {
    if (!encryptfs.isInitialized()) {
        shell.printError("Encrypted filesystem not initialized");
        shell.newLine();
        return;
    }

    if (!encryptfs.isKeySet()) {
        shell.printError("No encryption key set! Use: enckey <passphrase>");
        shell.newLine();
        return;
    }

    const parsed = helpers.parseArgs(args);
    const filename = parsed.cmd;

    if (filename.len == 0) {
        shell.println("Usage: decrypt <filename>");
        return;
    }

    if (encryptfs.decryptFile(filename)) |data| {
        shell.print("  ");
        shell.print(data);
        shell.newLine();
    } else {
        shell.printError("Decryption failed (wrong key or file not found)");
        shell.newLine();
    }
}

// =============================================================================
// enckey <passphrase> — set encryption key
// =============================================================================

pub fn cmdEncKey(args: []const u8) void {
    if (!encryptfs.isInitialized()) {
        shell.printError("Encrypted filesystem not initialized");
        shell.newLine();
        return;
    }

    const parsed = helpers.parseArgs(args);
    const passphrase = parsed.cmd;

    if (passphrase.len == 0) {
        shell.println("Usage: enckey <passphrase>");
        shell.println("       enckey identity    (use current identity)");
        shell.println("       enckey lock        (clear key)");
        return;
    }

    if (helpers.strEql(passphrase, "lock")) {
        encryptfs.clearKey();
        shell.println("  Key cleared (filesystem locked)");
        return;
    }

    if (helpers.strEql(passphrase, "identity")) {
        if (identity.getCurrentIdentity()) |id| {
            if (encryptfs.setKeyFromIdentity(id.getPublicKey())) {
                shell.println("  Key set from identity");
            } else {
                shell.printError("Failed to set key from identity");
                shell.newLine();
            }
        } else {
            shell.printError("No current identity! Create one with: identity create <name> <pin>");
            shell.newLine();
        }
        return;
    }

    if (encryptfs.setKeyFromPassphrase(passphrase)) {
        shell.println("  Key set from passphrase");
    } else {
        shell.printError("Failed to set key (min 4 chars, need CAP_CRYPTO)");
        shell.newLine();
    }
}

// =============================================================================
// encdel <filename> — delete encrypted file
// =============================================================================

pub fn cmdEncDel(args: []const u8) void {
    if (!encryptfs.isInitialized()) {
        shell.printError("Encrypted filesystem not initialized");
        shell.newLine();
        return;
    }

    const parsed = helpers.parseArgs(args);
    const filename = parsed.cmd;

    if (filename.len == 0) {
        shell.println("Usage: encdel <filename>");
        return;
    }

    if (encryptfs.deleteFile(filename)) {
        shell.print("  Deleted: ");
        shell.println(filename);
    } else {
        shell.printError("Delete failed (not found or no permission)");
        shell.newLine();
    }
}

// =============================================================================
// enctest — run F4 tests
// =============================================================================

pub fn cmdEncTest() void {
    // Run AES tests first
    if (aes.test_aes()) {
        shell.println("  AES-256: ALL PASSED");
    } else {
        shell.printError("  AES-256: SOME FAILED");
        shell.newLine();
    }

    shell.newLine();

    // Run encryptfs tests
    _ = encryptfs.test_encryptfs();
}

// =============================================================================
// Help
// =============================================================================

fn cmdHelp() void {
    shell.println("");
    shell.printInfoLine("=== Encrypted Filesystem Commands (F4) ===");
    shell.println("  encfs           Status & file listing");
    shell.println("  encfs help      This help");
    shell.println("  encfs test      Run F4 tests");
    shell.println("  enckey <pass>   Set encryption key from passphrase");
    shell.println("  enckey identity Use current identity as key");
    shell.println("  enckey lock     Clear key (lock filesystem)");
    shell.println("  encrypt <f> <d> Encrypt data to file");
    shell.println("  decrypt <f>     Decrypt and display file");
    shell.println("  encdel <f>      Delete encrypted file");
    shell.println("");
}
