//! Zamrud OS - Identity Export/Import Commands (H.7.2)
//!
//! Subcommands for identity command:
//! - identity export full <name>
//! - identity export mnemonic <name>
//! - identity export public <name>
//! - identity import bundle <file>
//! - identity import mnemonic

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const ui = @import("../ui.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const keyboard = @import("../../drivers/input/keyboard.zig");
const identity_export = @import("../../identity/export.zig");
const keyring = @import("../../identity/keyring.zig");
const identity_store = @import("../../persist/identity_store.zig");
const constant_time = @import("../../crypto/constant_time.zig");

// =============================================================================
// Public Command Handlers (called from identity.zig)
// =============================================================================

pub fn handleExportCommand(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showExportHelp();
    } else if (helpers.strEql(parsed.cmd, "full") or helpers.strEql(parsed.cmd, "bundle")) {
        cmdExportFull(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "mnemonic") or helpers.strEql(parsed.cmd, "seed") or helpers.strEql(parsed.cmd, "words")) {
        cmdExportMnemonic(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "public") or helpers.strEql(parsed.cmd, "pub")) {
        cmdExportPublic(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "verify") or helpers.strEql(parsed.cmd, "check")) {
        cmdVerifyBackup(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "test")) {
        cmdExportTest();
    } else {
        // Try to treat it as identity name for 'export full'
        if (keyring.findIdentity(parsed.cmd) != null) {
            cmdExportFull(parsed.cmd);
        } else {
            shell.printError("export: unknown '");
            shell.print(parsed.cmd);
            shell.println("'. Use 'identity export help'");
        }
    }
}

pub fn handleImportCommand(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showImportHelp();
    } else if (helpers.strEql(parsed.cmd, "bundle") or helpers.strEql(parsed.cmd, "file")) {
        cmdImportBundle(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "mnemonic") or helpers.strEql(parsed.cmd, "seed") or
        helpers.strEql(parsed.cmd, "words") or helpers.strEql(parsed.cmd, "recover"))
    {
        cmdImportMnemonic();
    } else {
        // Try to treat as filename for bundle import
        if (parsed.cmd.len > 4) {
            cmdImportBundle(parsed.cmd);
        } else {
            shell.printError("import: unknown '");
            shell.print(parsed.cmd);
            shell.println("'. Use 'identity import help'");
        }
    }
}

/// Run export/import tests - public for identity.zig
pub fn cmdExportTest() void {
    shell.newLine();
    shell.println("Running H.7.2 Export/Import tests...");
    shell.newLine();

    const result = identity_export.runTests();

    shell.newLine();
    if (result) {
        shell.printSuccessLine("All export/import tests passed!");
    } else {
        shell.printErrorLine("Some export/import tests failed.");
    }
    shell.newLine();
}

/// Run export tests and return result - public for identity.zig
pub fn runExportTests() bool {
    return identity_export.runTests();
}

/// Import from mnemonic - public for 'identity recover' alias
pub fn cmdImportMnemonic() void {
    const theme = ui.getTheme();

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.println("  RECOVER IDENTITY FROM 24-WORD PHRASE");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    // Step 1: Get name
    setColor(theme.text_info);
    shell.println("Step 1: Choose a name for the recovered identity");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("Name (3-32 chars): @");
    var name: [32]u8 = [_]u8{0} ** 32;
    const name_len = readLine(&name);

    if (name_len < 3) {
        shell.newLine();
        shell.printErrorLine("Name must be at least 3 characters.");
        return;
    }

    if (keyring.findIdentity(name[0..name_len]) != null) {
        shell.newLine();
        shell.printErrorLine("An identity with this name already exists.");
        return;
    }

    shell.newLine();

    // Step 2: Get 24 words
    setColor(theme.text_info);
    shell.println("Step 2: Enter your 24 recovery words");
    setColor(theme.text_dim);
    shell.println("(Enter words separated by spaces, 4-6 words per line)");
    setColor(theme.text_normal);
    shell.newLine();

    var words: [24][16]u8 = undefined;
    var word_slices: [24][]const u8 = undefined;
    var word_count: usize = 0;

    for (&words) |*w| {
        for (w) |*c| {
            c.* = 0;
        }
    }

    while (word_count < 24) {
        setColor(theme.text_dim);
        shell.print("Words ");
        helpers.printUsize(word_count + 1);
        shell.print("-");
        helpers.printUsize(@min(word_count + 6, 24));
        shell.print(": ");
        setColor(theme.text_normal);

        var line: [128]u8 = [_]u8{0} ** 128;
        const line_len = readLine(&line);

        if (line_len == 0) {
            if (word_count == 0) {
                shell.println("Cancelled.");
                return;
            }
            continue;
        }

        var pos: usize = 0;
        while (pos < line_len and word_count < 24) {
            while (pos < line_len and (line[pos] == ' ' or line[pos] == '\t')) {
                pos += 1;
            }
            if (pos >= line_len) break;

            const start = pos;
            while (pos < line_len and line[pos] != ' ' and line[pos] != '\t') {
                pos += 1;
            }

            const word_len = @min(pos - start, 15);
            var i: usize = 0;
            while (i < word_len) : (i += 1) {
                var c = line[start + i];
                if (c >= 'A' and c <= 'Z') {
                    c = c + 32;
                }
                words[word_count][i] = c;
            }
            word_slices[word_count] = words[word_count][0..word_len];
            word_count += 1;
        }

        setColor(theme.text_dim);
        shell.print("  (");
        helpers.printUsize(word_count);
        shell.println("/24 words entered)");
        setColor(theme.text_normal);
    }

    shell.newLine();

    // Step 3: Set password
    setColor(theme.text_info);
    shell.println("Step 3: Set password for recovered identity");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("Password (min 8 chars): ");
    var new_pass: [64]u8 = [_]u8{0} ** 64;
    const np_len = readPassword(&new_pass);

    if (np_len < 8) {
        shell.newLine();
        shell.printErrorLine("Password must be at least 8 characters.");
        return;
    }

    shell.newLine();

    shell.print("Confirm password: ");
    var confirm_pass: [64]u8 = [_]u8{0} ** 64;
    const cp_len = readPassword(&confirm_pass);

    shell.newLine();

    if (np_len != cp_len or !sliceEql(new_pass[0..np_len], confirm_pass[0..cp_len])) {
        shell.printErrorLine("Passwords do not match.");
        secureWipe(&new_pass);
        secureWipe(&confirm_pass);
        return;
    }
    secureWipe(&confirm_pass);

    shell.newLine();
    setColor(theme.text_info);
    shell.println("Step 4: Recovering identity...");
    setColor(theme.text_normal);

    const result = identity_export.importFromMnemonic(
        word_slices[0..24],
        name[0..name_len],
        new_pass[0..np_len],
    );

    secureWipe(&new_pass);

    for (&words) |*w| {
        for (w) |*c| {
            c.* = 0;
        }
    }

    shell.newLine();

    if (!result.success) {
        shell.println("════════════════════════════════════════════════════════════");
        shell.printErrorLine("  RECOVERY FAILED");
        shell.println("════════════════════════════════════════════════════════════");

        if (result.error_msg) |msg| {
            shell.print("  Error: ");
            shell.println(msg);
        }
        shell.newLine();
        shell.println("  Please check that all words are spelled correctly");
        shell.println("  and in the correct order.");
        shell.newLine();
        return;
    }

    shell.println("════════════════════════════════════════════════════════════");
    shell.printSuccessLine("  RECOVERY SUCCESSFUL");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    shell.print("  Identity: @");
    shell.println(result.getName());

    if (result.is_owner) {
        shell.printWarningLine("  Note: This is the first identity (system owner)");
    }

    shell.newLine();

    if (identity_store.saveToDisk()) {
        shell.printSuccessLine("  Identity saved to disk.");
    } else {
        shell.printWarningLine("  Warning: Could not save to disk (in memory only)");
    }

    shell.newLine();
}

// =============================================================================
// Help Screens
// =============================================================================

fn showExportHelp() void {
    const theme = ui.getTheme();

    shell.newLine();
    setColor(theme.text_info);
    shell.println("  IDENTITY EXPORT - Backup Your Identity (H.7.2)");
    setColor(theme.text_normal);
    shell.println("  ════════════════════════════════════════════════");
    shell.newLine();

    setColor(theme.text_success);
    shell.println("  Backup Options:");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity export full <name>");
    setColor(theme.text_dim);
    shell.println("      Create encrypted backup file (.zib)");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity export mnemonic <name>");
    setColor(theme.text_dim);
    shell.println("      Display 24-word recovery phrase");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity export public <name>");
    setColor(theme.text_dim);
    shell.println("      Export public key only (.zpub)");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity export verify <file> [name]");
    setColor(theme.text_dim);
    shell.println("      Check if backup file is valid");
    setColor(theme.text_normal);
    shell.newLine();

    setColor(theme.text_info);
    shell.println("  Examples:");
    setColor(theme.text_dim);
    shell.println("    identity export full alice");
    shell.println("    identity export mnemonic alice");
    setColor(theme.text_normal);
    shell.newLine();
}

fn showImportHelp() void {
    const theme = ui.getTheme();

    shell.newLine();
    setColor(theme.text_info);
    shell.println("  IDENTITY IMPORT - Restore Your Identity (H.7.2)");
    setColor(theme.text_normal);
    shell.println("  ════════════════════════════════════════════════");
    shell.newLine();

    setColor(theme.text_success);
    shell.println("  Restore Options:");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity import bundle <file.zib>");
    setColor(theme.text_dim);
    shell.println("      Restore from encrypted backup file");
    setColor(theme.text_normal);
    shell.newLine();

    shell.println("    identity import mnemonic");
    shell.println("    identity recover");
    setColor(theme.text_dim);
    shell.println("      Recover identity from 24-word phrase");
    setColor(theme.text_normal);
    shell.newLine();

    setColor(theme.text_info);
    shell.println("  Examples:");
    setColor(theme.text_dim);
    shell.println("    identity import bundle ALICE.ZIB");
    shell.println("    identity recover");
    setColor(theme.text_normal);
    shell.newLine();
}

// =============================================================================
// Export Commands
// =============================================================================

fn cmdExportFull(args: []const u8) void {
    const name = helpers.trim(args);

    if (name.len == 0) {
        shell.println("Usage: identity export full <name>");
        return;
    }

    if (keyring.findIdentity(name) == null) {
        shell.printError("Identity not found: @");
        shell.println(name);
        return;
    }

    const theme = ui.getTheme();

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.println("  EXPORT ENCRYPTED IDENTITY BUNDLE");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    shell.print("Identity: @");
    shell.println(name);
    shell.newLine();

    // Step 1: Verify password
    setColor(theme.text_info);
    shell.println("Step 1: Verify your identity");
    setColor(theme.text_normal);
    shell.print("Enter your password: ");

    var credential: [64]u8 = [_]u8{0} ** 64;
    const cred_len = readPassword(&credential);

    if (cred_len == 0) {
        shell.newLine();
        shell.println("Cancelled.");
        return;
    }

    shell.newLine();

    const id = keyring.findIdentity(name).?;
    var test_key: [32]u8 = undefined;
    if (!keyring.decryptPrivateKey(id, credential[0..cred_len], &test_key)) {
        shell.printErrorLine("Invalid password.");
        secureWipe(&credential);
        return;
    }
    constant_time.secureZero32(&test_key);

    shell.printSuccessLine("Password verified.");
    shell.newLine();

    // Step 2: Backup password
    setColor(theme.text_info);
    shell.println("Step 2: Create backup password");
    setColor(theme.text_dim);
    shell.println("(This password encrypts your backup file.)");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("Enter backup password (min 8 chars): ");
    var export_pass: [64]u8 = [_]u8{0} ** 64;
    const exp_len = readPassword(&export_pass);

    if (exp_len < 8) {
        shell.newLine();
        shell.printErrorLine("Backup password must be at least 8 characters.");
        secureWipe(&credential);
        secureWipe(&export_pass);
        return;
    }

    shell.newLine();

    shell.print("Confirm backup password: ");
    var confirm_pass: [64]u8 = [_]u8{0} ** 64;
    const conf_len = readPassword(&confirm_pass);

    shell.newLine();

    if (exp_len != conf_len or !sliceEql(export_pass[0..exp_len], confirm_pass[0..conf_len])) {
        shell.printErrorLine("Passwords do not match.");
        secureWipe(&credential);
        secureWipe(&export_pass);
        secureWipe(&confirm_pass);
        return;
    }
    secureWipe(&confirm_pass);

    // Step 3: Export
    setColor(theme.text_info);
    shell.println("Step 3: Creating encrypted backup...");
    setColor(theme.text_normal);

    const result = identity_export.exportFull(name, credential[0..cred_len], export_pass[0..exp_len]);

    secureWipe(&credential);
    secureWipe(&export_pass);

    if (!result.success) {
        shell.printError("Export failed: ");
        if (result.error_msg) |msg| shell.println(msg) else shell.println("Unknown error");
        return;
    }

    var filename: [16]u8 = [_]u8{0} ** 16;
    const fname_len = formatFilename(name, ".ZIB", &filename);
    const saved = identity_export.saveToFile(filename[0..fname_len], result.getData());

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.printSuccessLine("  EXPORT SUCCESSFUL");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    if (saved) {
        shell.print("  File: ");
        shell.println(filename[0..fname_len]);
    } else {
        shell.printWarningLine("  Warning: Could not save to disk");
    }

    shell.print("  Size: ");
    helpers.printUsize(result.len);
    shell.println(" bytes");

    shell.newLine();
    setColor(theme.text_warning);
    shell.println("  IMPORTANT: Store this file securely!");
    setColor(theme.text_normal);
    shell.newLine();
}

fn cmdExportMnemonic(args: []const u8) void {
    const name = helpers.trim(args);

    if (name.len == 0) {
        shell.println("Usage: identity export mnemonic <name>");
        return;
    }

    if (keyring.findIdentity(name) == null) {
        shell.printError("Identity not found: @");
        shell.println(name);
        return;
    }

    const theme = ui.getTheme();

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    setColor(theme.text_error);
    shell.println("  WARNING: SENSITIVE INFORMATION");
    setColor(theme.text_normal);
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    setColor(theme.text_warning);
    shell.println("  Your 24-word recovery phrase will be displayed.");
    shell.println("  * Make sure no one else can see your screen");
    shell.println("  * Write the words down on paper");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("  Continue? (yes/no): ");
    var confirm: [8]u8 = undefined;
    const conf_len = readLine(&confirm);

    if (conf_len < 3 or !helpers.strEql(confirm[0..conf_len], "yes")) {
        shell.newLine();
        shell.println("Cancelled.");
        return;
    }

    shell.newLine();
    shell.print("Enter your password: ");

    var credential: [64]u8 = [_]u8{0} ** 64;
    const cred_len = readPassword(&credential);

    if (cred_len == 0) {
        shell.newLine();
        shell.println("Cancelled.");
        return;
    }

    shell.newLine();

    const result = identity_export.exportMnemonic(name, credential[0..cred_len]);
    secureWipe(&credential);

    if (!result.success) {
        shell.printErrorLine("Failed to export mnemonic. Invalid password?");
        return;
    }

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.println("  YOUR 24-WORD RECOVERY PHRASE");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    var word_idx: usize = 0;
    while (word_idx < 24) {
        shell.print("  ");
        var col: usize = 0;
        while (col < 4 and word_idx < 24) : (col += 1) {
            setColor(theme.text_dim);
            if (word_idx + 1 < 10) shell.print(" ");
            helpers.printUsize(word_idx + 1);
            shell.print(". ");
            setColor(theme.text_bright);

            const word = result.getWord(word_idx);
            shell.print(word);

            var pad: usize = 12;
            if (word.len < 12) pad = 12 - word.len else pad = 1;
            while (pad > 0) : (pad -= 1) shell.print(" ");

            word_idx += 1;
        }
        shell.newLine();
    }

    setColor(theme.text_normal);
    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    setColor(theme.text_warning);
    shell.println("  Write these words down NOW!");
    setColor(theme.text_normal);
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    shell.print("Press ENTER when done...");
    _ = waitForEnter();
    shell.newLine();
}

fn cmdExportPublic(args: []const u8) void {
    const name = helpers.trim(args);

    if (name.len == 0) {
        shell.println("Usage: identity export public <name>");
        return;
    }

    const id = keyring.findIdentity(name) orelse {
        shell.printError("Identity not found: @");
        shell.println(name);
        return;
    };

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.println("  PUBLIC IDENTITY EXPORT");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    const result = identity_export.exportPublic(name);

    if (!result.success) {
        shell.printErrorLine("Export failed.");
        return;
    }

    shell.print("  Name:       @");
    shell.println(name);
    shell.print("  Address:    ");
    shell.println(id.getAddress());
    shell.print("  Public Key: ");
    printHex(&id.keypair.public_key, 16);
    shell.println("...");
    shell.newLine();

    var filename: [16]u8 = [_]u8{0} ** 16;
    const fname_len = formatFilename(name, ".ZPUB", &filename);
    const saved = identity_export.saveToFile(filename[0..fname_len], result.getData());

    if (saved) {
        shell.print("  Saved to: ");
        shell.println(filename[0..fname_len]);
    }

    shell.newLine();
    shell.printSuccessLine("  This file is SAFE to share with others.");
    shell.newLine();
}

fn cmdVerifyBackup(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const filename = parsed.cmd;
    const identity_name = if (parsed.rest.len > 0) helpers.trim(parsed.rest) else "";

    if (filename.len == 0) {
        shell.println("Usage: identity export verify <filename.zib> [name]");
        return;
    }

    shell.newLine();
    shell.print("Verifying backup: ");
    shell.println(filename);
    shell.newLine();

    var bundle_data: [512]u8 = [_]u8{0} ** 512;
    const loaded = identity_export.loadFromFile(filename, &bundle_data) orelse {
        shell.printErrorLine("Error: Could not read file");
        return;
    };

    shell.print("File size: ");
    helpers.printUsize(loaded);
    shell.println(" bytes");

    if (loaded < 4 or bundle_data[0] != 'Z' or bundle_data[1] != 'I' or bundle_data[2] != 'B') {
        shell.printErrorLine("Error: Not a valid .zib backup file");
        return;
    }

    shell.printSuccessLine("File format: Valid ZIB bundle");

    if (identity_name.len > 0) {
        shell.newLine();
        shell.print("Enter backup password to verify against @");
        shell.print(identity_name);
        shell.println(":");

        var pass: [64]u8 = [_]u8{0} ** 64;
        const pass_len = readPassword(&pass);

        if (pass_len == 0) {
            shell.newLine();
            shell.println("Cancelled.");
            return;
        }

        shell.newLine();

        if (identity_export.verifyBackup(bundle_data[0..loaded], pass[0..pass_len], identity_name)) {
            shell.printSuccessLine("Backup verified! Matches identity.");
        } else {
            shell.printErrorLine("Verification failed.");
        }

        secureWipe(&pass);
    }

    shell.newLine();
}

// =============================================================================
// Import Commands
// =============================================================================

fn cmdImportBundle(args: []const u8) void {
    const filename = helpers.trim(args);

    if (filename.len == 0) {
        shell.println("Usage: identity import bundle <filename.zib>");
        return;
    }

    const theme = ui.getTheme();

    shell.newLine();
    shell.println("════════════════════════════════════════════════════════════");
    shell.println("  IMPORT IDENTITY FROM BACKUP");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    shell.print("Loading: ");
    shell.println(filename);

    var bundle_data: [512]u8 = [_]u8{0} ** 512;
    const loaded = identity_export.loadFromFile(filename, &bundle_data) orelse {
        shell.printErrorLine("Error: Could not read file");
        return;
    };

    shell.print("Read ");
    helpers.printUsize(loaded);
    shell.println(" bytes");
    shell.newLine();

    // Step 1: Backup password
    setColor(theme.text_info);
    shell.println("Step 1: Enter backup password");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("Backup password: ");
    var backup_pass: [64]u8 = [_]u8{0} ** 64;
    const bp_len = readPassword(&backup_pass);

    if (bp_len == 0) {
        shell.newLine();
        shell.println("Cancelled.");
        return;
    }

    shell.newLine();
    shell.newLine();

    // Step 2: New password
    setColor(theme.text_info);
    shell.println("Step 2: Set password for imported identity");
    setColor(theme.text_normal);
    shell.newLine();

    shell.print("New password (min 8 chars): ");
    var new_cred: [64]u8 = [_]u8{0} ** 64;
    const nc_len = readPassword(&new_cred);

    if (nc_len < 8) {
        shell.newLine();
        shell.printErrorLine("Password must be at least 8 characters.");
        secureWipe(&backup_pass);
        secureWipe(&new_cred);
        return;
    }

    shell.newLine();

    shell.print("Confirm new password: ");
    var confirm_cred: [64]u8 = [_]u8{0} ** 64;
    const cc_len = readPassword(&confirm_cred);

    shell.newLine();

    if (nc_len != cc_len or !sliceEql(new_cred[0..nc_len], confirm_cred[0..cc_len])) {
        shell.printErrorLine("Passwords do not match.");
        secureWipe(&backup_pass);
        secureWipe(&new_cred);
        secureWipe(&confirm_cred);
        return;
    }
    secureWipe(&confirm_cred);

    shell.newLine();
    setColor(theme.text_info);
    shell.println("Step 3: Importing...");
    setColor(theme.text_normal);

    const result = identity_export.importFromBundle(
        bundle_data[0..loaded],
        backup_pass[0..bp_len],
        new_cred[0..nc_len],
    );

    secureWipe(&backup_pass);
    secureWipe(&new_cred);

    shell.newLine();

    if (!result.success) {
        shell.println("════════════════════════════════════════════════════════════");
        shell.printErrorLine("  IMPORT FAILED");
        shell.println("════════════════════════════════════════════════════════════");

        if (result.error_msg) |msg| {
            shell.print("  Error: ");
            shell.println(msg);
        }
        shell.newLine();
        return;
    }

    shell.println("════════════════════════════════════════════════════════════");
    shell.printSuccessLine("  IMPORT SUCCESSFUL");
    shell.println("════════════════════════════════════════════════════════════");
    shell.newLine();

    shell.print("  Identity: @");
    shell.println(result.getName());

    if (result.is_owner) {
        shell.printWarningLine("  Note: This identity is marked as system owner");
    }

    shell.newLine();

    if (identity_store.saveToDisk()) {
        shell.printSuccessLine("  Identity saved to disk.");
    } else {
        shell.printWarningLine("  Warning: Could not save to disk (in memory only)");
    }

    shell.newLine();
}

// =============================================================================
// Helper Functions
// =============================================================================

fn setColor(color: u32) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(color);
    }
}

fn readPassword(buf: *[64]u8) usize {
    var len: usize = 0;

    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                return len;
            }

            if (key == 0x1B) {
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

fn readLine(buf: []u8) usize {
    var len: usize = 0;

    while (len < buf.len) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                shell.newLine();
                return len;
            }

            if (key == 0x1B) {
                shell.newLine();
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

            if (key >= 32 and key < 127) {
                buf[len] = key;
                len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar(key);
                }
            }
        }
        asm volatile ("pause");
    }

    return len;
}

fn waitForEnter() bool {
    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == '\n' or key == '\r') return true;
            if (key == 0x1B) return false;
        }
        asm volatile ("pause");
    }
}

fn secureWipe(buf: []u8) void {
    for (buf) |*b| {
        b.* = 0;
    }
    asm volatile ("" ::: .{ .memory = true });
}

fn sliceEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn formatFilename(name: []const u8, ext: []const u8, buf: *[16]u8) usize {
    var pos: usize = 0;
    var i: usize = 0;
    var name_start: usize = 0;

    if (name.len > 0 and name[0] == '@') {
        name_start = 1;
    }

    while (i < 8 and name_start + i < name.len and pos < 16) : (i += 1) {
        var c = name[name_start + i];
        if (c >= 'a' and c <= 'z') {
            c = c - 32;
        }
        if ((c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9')) {
            buf[pos] = c;
            pos += 1;
        }
    }

    i = 0;
    while (i < ext.len and pos < 16) : (i += 1) {
        buf[pos] = ext[i];
        pos += 1;
    }

    return pos;
}

fn printHex(data: []const u8, max: usize) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < max and i < data.len) : (i += 1) {
        const byte = data[i];
        if (terminal.isInitialized()) {
            terminal.writeChar(hex[byte >> 4]);
            terminal.writeChar(hex[byte & 0xF]);
        }
    }
}
