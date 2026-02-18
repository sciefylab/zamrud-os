//! Zamrud OS - System Commands
//! help, clear, info, uptime, memory, history, echo, theme
//! T4.2: set, unset, env, export, printenv

const shell = @import("../shell.zig");
const ui = @import("../ui.zig");
const helpers = @import("helpers.zig");
const env = @import("../env.zig");

const terminal = @import("../../drivers/display/terminal.zig");
const timer = @import("../../drivers/timer/timer.zig");
const heap = @import("../../mm/heap.zig");
const vfs = @import("../../fs/vfs.zig");
const devfs = @import("../../fs/devfs.zig");
const process = @import("../../proc/process.zig");
const user = @import("../../proc/user.zig");
const crypto = @import("../../crypto/crypto.zig");
const chain = @import("../../chain/chain.zig");
const net = @import("../../net/net.zig");
const syscall_mod = @import("../../syscall/table.zig");
const storage = @import("../../drivers/storage/storage.zig");

// =============================================================================
// T4.1: Colored Help with Categories
// =============================================================================

pub fn cmdHelp(_: []const u8) void {
    const theme = ui.getTheme();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  ZAMRUD OS - Command Reference");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  =====================================");

    // System
    printCategory("System");
    printCmd("help", "Show this help");
    printCmd("clear", "Clear screen");
    printCmd("info", "System information");
    printCmd("uptime", "Show system uptime");
    printCmd("mem", "Memory statistics");
    printCmd("history", "Command history");
    printCmd("echo <text>", "Print text ($VAR expanded)");
    printCmd("theme <name>", "Change color theme");

    // Environment
    printCategory("Environment");
    printCmd("set VAR=value", "Set environment variable");
    printCmd("unset VAR", "Remove environment variable");
    printCmd("env", "List all variables");
    printCmd("export VAR=val", "Set and mark for export");
    printCmd("printenv [VAR]", "Print variable value");

    // Filesystem
    printCategory("Filesystem");
    printCmd("ls [path]", "List directory contents");
    printCmd("cd <path>", "Change directory (~ supported)");
    printCmd("pwd", "Print working directory");
    printCmd("mkdir <name>", "Create directory");
    printCmd("touch <name>", "Create empty file");
    printCmd("rm <file>", "Remove file");
    printCmd("rmdir <dir>", "Remove empty directory");
    printCmd("cat <file>", "Display file contents");
    printCmd("write <f> <t>", "Write text to file");

    // Device & Storage
    printCategory("Device & Storage");
    printCmd("lsdev", "List devices");
    printCmd("devtest", "Test device drivers");
    printCmd("disk list", "List detected drives");
    printCmd("disk read <lba>", "Read sector at LBA");
    printCmd("disk test", "Test disk driver");

    // Process
    printCategory("Process");
    printCmd("ps", "List processes");
    printCmd("spawn <name>", "Create new process");
    printCmd("kill <pid>", "Terminate process");
    printCmd("sched", "Scheduler status");

    // Network
    printCategory("Network");
    printCmd("net", "Network status");
    printCmd("ifconfig", "Interface configuration");
    printCmd("ping <host>", "Send ICMP ping");
    printCmd("netstat", "Network statistics");
    printCmd("arp", "ARP table");
    printCmd("firewall", "Firewall status");
    printCmd("p2p", "P2P network status");
    printCmd("gateway", "Gateway status");

    // Security
    printCategory("Security & Crypto");
    printCmd("crypto", "Cryptography status");
    printCmd("chain", "Blockchain status");
    printCmd("integrity", "Integrity monitoring");
    printCmd("identity", "Identity management");
    printCmd("boot", "Boot verification");
    printCmd("sysenc", "System encryption");

    // User
    printCategory("User & Session");
    printCmd("login", "Login as user");
    printCmd("logout", "End current session");
    printCmd("whoami", "Show current user");
    printCmd("id", "Show user/group IDs");
    printCmd("su <user>", "Switch user");
    printCmd("sudo <cmd>", "Run as admin");
    printCmd("user", "User management");

    // I/O Redirection
    printCategory("I/O Redirection");
    printCmd("> file", "Redirect output to file");
    printCmd(">> file", "Append output to file");
    printCmd("< file", "Read input from file");
    printCmd("cmd1 | cmd2", "Pipe output to command");

    // Test
    printCategory("Testing");
    printCmd("testall", "Run all tests");
    printCmd("smoke", "Quick smoke test");

    // Power
    printCategory("Power");
    printCmd("reboot", "Restart system");
    printCmd("shutdown", "Power off");
    printCmd("exit", "Exit shell");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    shell.println("  =====================================");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    shell.println("  Tab=complete  Arrows=history  Ctrl+L=clear  $VAR=expand");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
}

fn printCategory(name: []const u8) void {
    const theme = ui.getTheme();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
        terminal.setBold(true);
    }
    shell.print("  ");
    shell.println(name);
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.text_normal);
    }
}

fn printCmd(cmd: []const u8, desc: []const u8) void {
    const theme = ui.getTheme();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
    }
    shell.print("    ");
    shell.print(cmd);

    const pad: usize = 18;
    if (cmd.len < pad) {
        var p: usize = 0;
        while (p < pad - cmd.len) : (p += 1) {
            shell.printChar(' ');
        }
    } else {
        shell.printChar(' ');
    }

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    shell.println(desc);
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
}

// =============================================================================
// T4.2: Environment Variable Commands
// =============================================================================

pub fn cmdSet(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        cmdEnv("");
        return;
    }

    if (env.parseAssignment(trimmed)) |assignment| {
        env.setVar(assignment.key, assignment.value) catch |err| {
            switch (err) {
                env.EnvError.TooManyVars => shell.printErrorLine("set: too many variables (max 64)"),
                env.EnvError.KeyTooLong => shell.printErrorLine("set: variable name too long (max 32)"),
                env.EnvError.ValueTooLong => shell.printErrorLine("set: value too long (max 128)"),
                env.EnvError.InvalidKey => shell.printErrorLine("set: invalid variable name"),
            }
            shell.setLastExitSuccess(false);
            return;
        };
        shell.setLastExitSuccess(true);
    } else {
        if (env.getVar(trimmed)) |val| {
            shell.print(trimmed);
            shell.print("=");
            shell.println(val);
        } else {
            shell.printError("set: ");
            shell.print(trimmed);
            shell.println(" not set");
            shell.setLastExitSuccess(false);
        }
    }
}

pub fn cmdUnset(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.printErrorLine("Usage: unset <VAR>");
        shell.setLastExitSuccess(false);
        return;
    }

    if (env.getVar(trimmed) != null) {
        env.unsetVar(trimmed);
        shell.setLastExitSuccess(true);
    } else {
        shell.printError("unset: ");
        shell.print(trimmed);
        shell.println(": not set");
        shell.setLastExitSuccess(false);
    }
}

pub fn cmdEnv(_: []const u8) void {
    const theme = ui.getTheme();

    if (!env.isInitialized()) {
        shell.printErrorLine("env: environment not initialized");
        return;
    }

    var entries: [64]env.EnvEntry = undefined;
    const count = env.getSortedEntries(&entries);

    if (count == 0) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.println("  (no variables set)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = entries[i];

        if (terminal.isInitialized()) {
            if (entry.exported) {
                terminal.setFgColor(theme.status_accent);
            } else {
                terminal.setFgColor(theme.text_info);
            }
        }
        shell.print(entry.key);

        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.print("=");

        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        shell.println(entry.value);
    }

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.print("  ");
    helpers.printUsize(count);
    shell.println(" variables");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
}

pub fn cmdExport(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        const theme = ui.getTheme();
        var entries: [64]env.EnvEntry = undefined;
        const count = env.getSortedEntries(&entries);

        var found: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (entries[i].exported) {
                if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
                shell.print("declare -x ");
                if (terminal.isInitialized()) terminal.setFgColor(theme.status_accent);
                shell.print(entries[i].key);
                if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
                shell.print("=\"");
                if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
                shell.print(entries[i].value);
                if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
                shell.println("\"");
                found += 1;
            }
        }

        if (found == 0) {
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
            shell.println("  (no exported variables)");
        }
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        return;
    }

    if (env.parseAssignment(trimmed)) |assignment| {
        env.setVar(assignment.key, assignment.value) catch |err| {
            switch (err) {
                env.EnvError.TooManyVars => shell.printErrorLine("export: too many variables"),
                env.EnvError.KeyTooLong => shell.printErrorLine("export: name too long"),
                env.EnvError.ValueTooLong => shell.printErrorLine("export: value too long"),
                env.EnvError.InvalidKey => shell.printErrorLine("export: invalid name"),
            }
            shell.setLastExitSuccess(false);
            return;
        };
        env.markExported(assignment.key);
        shell.setLastExitSuccess(true);
    } else {
        if (env.getVar(trimmed) != null) {
            env.markExported(trimmed);
            shell.setLastExitSuccess(true);
        } else {
            env.setVar(trimmed, "") catch {
                shell.printErrorLine("export: cannot create variable");
                shell.setLastExitSuccess(false);
                return;
            };
            env.markExported(trimmed);
            shell.setLastExitSuccess(true);
        }
    }
}

pub fn cmdPrintenv(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        cmdEnv("");
        return;
    }

    if (env.getVar(trimmed)) |val| {
        shell.println(val);
        shell.setLastExitSuccess(true);
    } else {
        shell.setLastExitSuccess(false);
    }
}

// =============================================================================
// T4.2: Environment Variable Tests
// =============================================================================

pub fn cmdEnvTest(_: []const u8) void {
    var passed: u32 = 0;
    var failed: u32 = 0;

    helpers.printTestHeader("ENVIRONMENT VARIABLES - T4.2");

    helpers.printSubsection("Built-in Variables");
    passed += helpers.doTest("$SHELL exists", env.getVar("SHELL") != null, &failed);
    passed += helpers.doTest("$TERM exists", env.getVar("TERM") != null, &failed);
    passed += helpers.doTest("$OS exists", env.getVar("OS") != null, &failed);
    passed += helpers.doTest("$VERSION exists", env.getVar("VERSION") != null, &failed);

    helpers.printSubsection("Set/Get Operations");
    env.setVar("TEST_VAR", "hello_world") catch {};
    const got = env.getVar("TEST_VAR");
    passed += helpers.doTest("set/get basic", got != null and helpers.strEql(got.?, "hello_world"), &failed);

    env.setVar("TEST_VAR", "updated_value") catch {};
    const got2 = env.getVar("TEST_VAR");
    passed += helpers.doTest("update existing", got2 != null and helpers.strEql(got2.?, "updated_value"), &failed);

    env.unsetVar("TEST_VAR");
    passed += helpers.doTest("unset removes var", env.getVar("TEST_VAR") == null, &failed);

    helpers.printSubsection("Key Validation");
    const r1 = env.setVar("123BAD", "value");
    passed += helpers.doTest("reject numeric start", r1 == env.EnvError.InvalidKey, &failed);

    const r2 = env.setVar("GOOD_NAME", "value");
    passed += helpers.doTest("accept underscore", r2 != env.EnvError.InvalidKey, &failed);
    env.unsetVar("GOOD_NAME");

    const r3 = env.setVar("has space", "value");
    passed += helpers.doTest("reject spaces", r3 == env.EnvError.InvalidKey, &failed);

    helpers.printSubsection("Variable Expansion");
    env.setVar("FOO", "bar") catch {};
    env.setVar("GREETING", "hello") catch {};

    const exp1 = env.expandVars("$FOO");
    passed += helpers.doTest("$FOO -> bar", helpers.strEql(exp1, "bar"), &failed);

    const exp2 = env.expandVars("${FOO}");
    passed += helpers.doTest("${FOO} -> bar", helpers.strEql(exp2, "bar"), &failed);

    const exp3 = env.expandVars("say $GREETING world");
    passed += helpers.doTest("inline expansion", helpers.strEql(exp3, "say hello world"), &failed);

    const exp4 = env.expandVars("$NONEXISTENT");
    passed += helpers.doTest("missing var -> empty", helpers.strEql(exp4, ""), &failed);

    const exp5 = env.expandVars("no vars here");
    passed += helpers.doTest("no expansion needed", helpers.strEql(exp5, "no vars here"), &failed);

    const exp6 = env.expandVars("${GREETING}_${FOO}");
    passed += helpers.doTest("multiple ${} expand", helpers.strEql(exp6, "hello_bar"), &failed);

    const exp7 = env.expandVars("'$FOO'");
    passed += helpers.doTest("single quotes literal", helpers.strEql(exp7, "$FOO"), &failed);

    shell.setLastExitSuccess(true);
    const exp8 = env.expandVars("$?");
    passed += helpers.doTest("$? returns 0", helpers.strEql(exp8, "0"), &failed);

    shell.setLastExitSuccess(false);
    const exp9 = env.expandVars("$?");
    passed += helpers.doTest("$? returns 1", helpers.strEql(exp9, "1"), &failed);
    shell.setLastExitSuccess(true);

    helpers.printSubsection("Assignment Parsing");
    const a1 = env.parseAssignment("KEY=value");
    passed += helpers.doTest("parse KEY=value", a1 != null and helpers.strEql(a1.?.key, "KEY") and helpers.strEql(a1.?.value, "value"), &failed);

    const a2 = env.parseAssignment("KEY=\"quoted value\"");
    passed += helpers.doTest("parse quoted value", a2 != null and helpers.strEql(a2.?.value, "quoted value"), &failed);

    const a3 = env.parseAssignment("KEY=");
    passed += helpers.doTest("parse empty value", a3 != null and helpers.strEql(a3.?.value, ""), &failed);

    const a4 = env.parseAssignment("noequals");
    passed += helpers.doTest("reject no equals", a4 == null, &failed);

    helpers.printSubsection("Dynamic Variables");
    const pwd_val = env.getVar("PWD");
    const actual_cwd = vfs.getcwd();
    passed += helpers.doTest("$PWD matches cwd", pwd_val != null and helpers.strEql(pwd_val.?, actual_cwd), &failed);

    env.unsetVar("FOO");
    env.unsetVar("GREETING");

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Other Commands
// =============================================================================

pub fn cmdClear(_: []const u8) void {
    shell.clearScreen();
}

pub fn cmdInfo(_: []const u8) void {
    const theme = ui.getTheme();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  ZAMRUD OS v0.1.0");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  -----------------------------------");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }

    printInfoRow("Kernel", "64-bit x86_64");

    if (terminal.isInitialized()) {
        shell.print("  Resolution:    ");
        helpers.printU32(terminal.getWidth());
        shell.print("x");
        helpers.printU32(terminal.getHeight());
        shell.print(" (");
        helpers.printU32(terminal.getCols());
        shell.print("x");
        helpers.printU32(terminal.getRows());
        shell.println(" chars)");
    }

    shell.print("  Processes:     ");
    helpers.printU32(process.getCount());
    shell.newLine();

    printStatusRow("VFS", vfs.exists("/"));
    printStatusRow("DevFS", devfs.isInitialized());

    shell.print("  Storage:       ");
    if (storage.isInitialized()) {
        const drive_count = storage.getDriveCount();
        if (drive_count > 0) {
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_success);
            helpers.printUsize(drive_count);
            shell.println(if (drive_count == 1) " drive" else " drives");
        } else {
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_warning);
            shell.println("No drives");
        }
    } else {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_error);
        shell.println("N/A");
    }
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    printStatusRow("Network", net.isInitialized());
    printStatusRow("User Mode", user.isInitialized());

    shell.print("  Crypto:        ");
    if (crypto.isInitialized()) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_success);
        if (crypto.random.hasHardwareRng()) {
            shell.println("RDRAND");
        } else {
            shell.println("Software");
        }
    } else {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_error);
        shell.println("N/A");
    }
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    printStatusRow("Blockchain", chain.isInitialized());

    shell.print("  Syscalls:      ");
    helpers.printU32(@intCast(syscall_mod.getSyscallCount() & 0xFFFFFFFF));
    shell.println(" executed");

    shell.print("  Env vars:      ");
    helpers.printUsize(env.getVarCount());
    shell.println(" set");
}

fn printInfoRow(label: []const u8, value: []const u8) void {
    shell.print("  ");
    shell.print(label);
    shell.print(":");
    const pad: usize = 14;
    if (label.len < pad) {
        var p: usize = 0;
        while (p < pad - label.len) : (p += 1) {
            shell.printChar(' ');
        }
    } else {
        shell.printChar(' ');
    }
    shell.println(value);
}

fn printStatusRow(label: []const u8, ok: bool) void {
    const theme = ui.getTheme();
    shell.print("  ");
    shell.print(label);
    shell.print(":");
    const pad: usize = 14;
    if (label.len < pad) {
        var p: usize = 0;
        while (p < pad - label.len) : (p += 1) {
            shell.printChar(' ');
        }
    } else {
        shell.printChar(' ');
    }
    if (ok) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_success);
        shell.println("OK");
    } else {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_error);
        shell.println("N/A");
    }
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
}

pub fn cmdUptime(_: []const u8) void {
    const theme = ui.getTheme();
    const seconds = timer.getSeconds();
    const hours = seconds / 3600;
    const minutes = (seconds % 3600) / 60;
    const secs = seconds % 60;

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
    shell.print("  Uptime: ");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    if (hours > 0) {
        helpers.printUsize(hours);
        shell.print("h ");
    }
    if (minutes > 0 or hours > 0) {
        helpers.printUsize(minutes);
        shell.print("m ");
    }
    helpers.printUsize(secs);
    shell.println("s");

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.print("  Ticks: ");
    helpers.printU64(timer.getTicks());
    shell.newLine();
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
}

pub fn cmdMemory(_: []const u8) void {
    const theme = ui.getTheme();
    const stats = heap.getStats();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  Memory Statistics");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  -----------------------------------");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    shell.print("  Heap size:     ");
    helpers.printUsize(stats.heap_size / 1024);
    shell.println(" KB");

    shell.print("  Allocated:     ");
    helpers.printUsize(stats.total_allocated);
    shell.println(" bytes");

    shell.print("  Freed:         ");
    helpers.printUsize(stats.total_freed);
    shell.println(" bytes");

    const in_use = if (stats.total_allocated >= stats.total_freed)
        stats.total_allocated - stats.total_freed
    else
        0;

    shell.print("  In use:        ");
    if (terminal.isInitialized()) {
        if (in_use > stats.heap_size / 2) {
            terminal.setFgColor(theme.text_warning);
        } else {
            terminal.setFgColor(theme.text_success);
        }
    }
    helpers.printUsize(in_use);
    shell.println(" bytes");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    shell.print("  Active allocs: ");
    helpers.printUsize(stats.allocation_count);
    shell.newLine();

    shell.print("  Free blocks:   ");
    helpers.printUsize(stats.free_blocks);
    shell.newLine();
}

pub fn cmdHistory(_: []const u8) void {
    const theme = ui.getTheme();

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
    shell.println("  Command History:");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    const count = shell.getHistoryCount();
    if (count == 0) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.println("  (empty)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.print("  ");
        helpers.printUsize(i + 1);
        shell.print(". ");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        if (shell.getHistoryEntry(i)) |entry| {
            shell.println(entry);
        }
    }
}

pub fn cmdEcho(args: []const u8) void {
    var i: usize = 0;
    var redirect_pos: ?usize = null;

    while (i < args.len) : (i += 1) {
        if (args[i] == '>') {
            redirect_pos = i;
            break;
        }
    }

    if (redirect_pos) |pos| {
        var text_end = pos;
        while (text_end > 0 and args[text_end - 1] == ' ') {
            text_end -= 1;
        }
        const text = args[0..text_end];

        var filename_start = pos + 1;
        while (filename_start < args.len and args[filename_start] == ' ') {
            filename_start += 1;
        }

        if (filename_start >= args.len) {
            shell.printErrorLine("echo: missing filename after '>'");
            shell.setLastExitSuccess(false);
            return;
        }

        const filename = helpers.trim(args[filename_start..]);

        if (!vfs.exists(filename)) {
            if (vfs.createFile(filename) == null) {
                shell.printErrorLine("echo: cannot create file");
                shell.setLastExitSuccess(false);
                return;
            }
        }

        var flags = vfs.OpenFlags.O_WRONLY;
        flags.write = true;
        flags.truncate = true;
        const file = vfs.open(filename, flags);
        if (file == null) {
            shell.printErrorLine("echo: cannot open file");
            shell.setLastExitSuccess(false);
            return;
        }

        _ = vfs.write(file.?, text);
        _ = vfs.write(file.?, "\n");
        vfs.close(file.?);

        shell.printSuccess("Written to: ");
        shell.println(filename);
    } else {
        shell.println(args);
    }
    shell.setLastExitSuccess(true);
}

// =============================================================================
// Theme Command
// =============================================================================

pub fn cmdTheme(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "list")) {
        ui.listThemes();
        return;
    }

    if (ui.getThemeByName(trimmed)) |theme| {
        ui.setTheme(theme);
        if (terminal.isInitialized()) {
            terminal.setBgColor(ui.BG_FOREST);
        }
        shell.clearScreen();
        shell.printSuccess("Theme set to: ");
        shell.println(trimmed);
    } else {
        shell.printError("Unknown theme: ");
        shell.println(trimmed);
        shell.println("  Use 'theme list' to see available themes");
    }
}
