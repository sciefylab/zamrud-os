//! Zamrud OS - Process Commands (E3.1 + E3.2 + E3.3)
//! ps, spawn, kill, sched, caps, grant, revoke, unveil, paths,
//! sandbox-fs, verify, trust, untrust, trusted

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const process = @import("../../proc/process.zig");
const scheduler = @import("../../proc/scheduler.zig");
const test_procs = @import("../../proc/test_procs.zig");
const capability = @import("../../security/capability.zig");
const unveil = @import("../../security/unveil.zig");
const binaryverify = @import("../../security/binaryverify.zig");
const hash_mod = @import("../../crypto/hash.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const ui = @import("../ui.zig");

// =============================================================================
// Process Commands
// =============================================================================

pub fn cmdPs(_: []const u8) void {
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  Process List");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  ─────────────────────────────────────────────────────");

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.println("  PID  STATE       PRI  CAPABILITIES          UNVEIL");
    shell.println("  ───  ──────────  ───  ────────────────────  ──────");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    var count: u32 = 0;
    var i: usize = 0;

    while (i < 8) : (i += 1) {
        if (process.process_used[i]) {
            const info = process.getProcessInfo(i) orelse continue;

            shell.print("  ");

            // PID
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_bright);
            helpers.printU32Padded(info.pid, 3);

            shell.print("  ");

            // STATE with color
            if (terminal.isInitialized()) {
                switch (@intFromEnum(info.state)) {
                    2 => terminal.setFgColor(theme.text_success), // Running
                    1 => terminal.setFgColor(theme.text_info), // Ready
                    3 => terminal.setFgColor(theme.text_warning), // Blocked
                    4 => terminal.setFgColor(theme.text_error), // Terminated
                    else => terminal.setFgColor(theme.text_dim), // Created
                }
            }
            switch (@intFromEnum(info.state)) {
                0 => shell.print("Created   "),
                1 => shell.print("Ready     "),
                2 => shell.print("Running   "),
                3 => shell.print("Blocked   "),
                4 => shell.print("Terminated"),
                else => shell.print("???       "),
            }

            shell.print("  ");

            // Priority
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
            helpers.printU8(info.priority);
            shell.print("    ");

            // Capabilities
            var cap_buf: [64]u8 = undefined;
            const cap_len = capability.formatCaps(info.caps, &cap_buf);
            if (terminal.isInitialized()) {
                if (info.caps == capability.CAP_ALL) {
                    terminal.setFgColor(theme.text_warning);
                } else if (info.caps == capability.CAP_NONE or info.caps == capability.CAP_MINIMAL) {
                    terminal.setFgColor(theme.text_dim);
                } else {
                    terminal.setFgColor(theme.text_info);
                }
            }
            if (cap_len > 0) {
                const show_len = @min(cap_len, 20);
                shell.print(cap_buf[0..show_len]);
                var pad: usize = if (20 > show_len) 20 - show_len else 0;
                while (pad > 0) : (pad -= 1) shell.printChar(' ');
            } else {
                shell.print("NONE                ");
            }

            shell.print("  ");

            // Unveil status
            if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
            if (unveil.hasTable(info.pid)) {
                helpers.printU8(unveil.getEntryCount(info.pid));
                if (unveil.isLocked(info.pid)) {
                    if (terminal.isInitialized()) terminal.setFgColor(theme.text_warning);
                    shell.print("L");
                } else {
                    shell.print(" ");
                }
            } else {
                shell.print("--");
            }

            if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
            shell.newLine();
            count += 1;
        }
    }

    if (terminal.isInitialized()) terminal.setFgColor(theme.border);
    shell.println("  ───  ──────────  ───  ────────────────────  ──────");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.print("  ");
    helpers.printU32(count);
    shell.println(" processes");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    shell.newLine();
}

pub fn cmdSpawn(_: []const u8) void {
    shell.printInfoLine("Spawning test process...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithEntry(
        "counter",
        @intFromPtr(&test_procs.counterProcess),
        id,
    );

    if (pid_result) |p| {
        shell.printSuccess("Created process PID: ");
        helpers.printU32(p);
        shell.newLine();
    } else {
        shell.printErrorLine("Failed to create process!");
    }
}

pub fn cmdSpawnSandbox(_: []const u8) void {
    shell.printInfoLine("Spawning sandboxed process (FS_READ only)...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithCaps(
        "sandboxed",
        @intFromPtr(&test_procs.counterProcess),
        id,
        capability.CAP_MINIMAL,
    );

    if (pid_result) |p| {
        shell.printSuccess("Sandboxed PID: ");
        helpers.printU32(p);
        shell.println(" (caps: FS_READ only)");
    } else {
        shell.printErrorLine("Failed to create sandboxed process!");
    }
}

pub fn cmdKill(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("kill: usage: kill <pid>");
        return;
    }

    const pid_val = helpers.parseU32(trimmed) orelse {
        shell.printErrorLine("kill: invalid PID");
        return;
    };

    if (pid_val == 0) {
        shell.printErrorLine("Cannot kill idle process (PID 0)!");
        return;
    }

    if (process.terminate(pid_val)) {
        shell.printSuccessLine("Process terminated");
    } else {
        shell.printErrorLine("Process not found!");
    }
}

pub fn cmdSched(_: []const u8) void {
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  Scheduler Status");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  ─────────────────────────────────────");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    shell.print("  Enabled:     ");
    if (scheduler.isEnabled()) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_success);
        shell.println("YES");
    } else {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_error);
        shell.println("NO");
    }
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    shell.print("  Ticks:       ");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
    helpers.printU64(scheduler.getTicks());
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    shell.newLine();

    shell.print("  Switches:    ");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_info);
    helpers.printU64(scheduler.getSwitchCount());
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    shell.newLine();

    shell.print("  Processes:   ");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_bright);
    helpers.printU32(process.getCount());
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    shell.newLine();
    shell.newLine();
}

pub fn cmdSchedEnable(_: []const u8) void {
    scheduler.enable();
    shell.printSuccessLine("Scheduler enabled");
}

pub fn cmdSchedDisable(_: []const u8) void {
    scheduler.disable();
    shell.printWarningLine("Scheduler disabled");
}

// =============================================================================
// E3.1: Capability Commands
// =============================================================================

pub fn cmdCaps(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len > 0) {
        if (helpers.strEql(trimmed, "test")) {
            runCapabilityTest();
            return;
        }
        if (helpers.strEql(trimmed, "help")) {
            printCapsHelp();
            return;
        }
        if (helpers.strEql(trimmed, "list")) {
            showAllCaps();
            return;
        }

        const pid_val = helpers.parseU32(trimmed) orelse {
            shell.printErrorLine("caps: unknown subcommand or invalid PID");
            shell.println("  Usage: caps [test|list|help|<pid>]");
            return;
        };
        showPidCaps(pid_val);
        return;
    }

    showAllCaps();
}

fn printCapsHelp() void {
    shell.printInfoLine("Capability Commands:");
    shell.println("  caps              Show all process capabilities");
    shell.println("  caps <pid>        Show caps for specific PID");
    shell.println("  caps list         Same as 'caps'");
    shell.println("  caps test         Run capability system tests");
    shell.println("  caps help         This help message");
    shell.println("");
    shell.println("  grant <pid> <cap> Grant capability to process");
    shell.println("  revoke <pid> <cap> Revoke capability from process");
    shell.println("  sandbox           Spawn sandboxed process");
    shell.println("  violations        Show security violations");
    shell.println("");
    shell.println("  Available caps:");
    shell.println("    NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
    shell.println("    GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
}

fn showAllCaps() void {
    shell.printInfoLine("Process Capabilities:");
    shell.println("  PID   CAPS(hex)   FLAGS                VIOLATIONS");
    shell.println("  ----  ----------  -------------------  ----------");

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (process.process_used[i]) {
            const info = process.getProcessInfo(i) orelse continue;

            shell.print("  ");
            helpers.printU32(info.pid);
            shell.print("     0x");
            helpers.printHexU32(info.caps);
            shell.print("  ");

            var buf: [64]u8 = undefined;
            const len = capability.formatCaps(info.caps, &buf);

            if (len > 0) {
                shell.print(buf[0..len]);
            } else {
                shell.print("NONE");
            }

            var pad: usize = if (len < 20) 20 - len else 1;
            while (pad > 0) : (pad -= 1) shell.print(" ");

            const vcount = capability.getViolationCount(info.pid);
            helpers.printU32(@as(u32, vcount));
            if (vcount >= capability.KILL_THRESHOLD) {
                shell.print(" (!)");
            }
            shell.newLine();
        }
    }

    shell.println("  ----  ----------  -------------------  ----------");
    shell.print("  Total violations: ");
    helpers.printU64(capability.getTotalViolations());
    shell.newLine();
}

fn showPidCaps(pid_val: u32) void {
    const caps = process.getProcessCaps(pid_val);

    shell.printInfoLine("Capability Details:");
    shell.print("  PID:        ");
    helpers.printU32(pid_val);
    shell.newLine();

    shell.print("  Caps (hex): 0x");
    helpers.printHexU32(caps);
    shell.newLine();

    shell.print("  Caps (str): ");
    var buf: [64]u8 = undefined;
    const len = capability.formatCaps(caps, &buf);
    shell.println(buf[0..len]);

    shell.println("");
    shell.println("  Individual Capabilities:");

    const cap_list = [_]struct { bit: u32, name: []const u8 }{
        .{ .bit = capability.CAP_NET, .name = "NET        - Network access" },
        .{ .bit = capability.CAP_FS_READ, .name = "FS_READ    - Filesystem read" },
        .{ .bit = capability.CAP_FS_WRITE, .name = "FS_WRITE   - Filesystem write" },
        .{ .bit = capability.CAP_IPC, .name = "IPC        - Inter-process communication" },
        .{ .bit = capability.CAP_EXEC, .name = "EXEC       - Execute/spawn processes" },
        .{ .bit = capability.CAP_DEVICE, .name = "DEVICE     - Direct device access" },
        .{ .bit = capability.CAP_GRAPHICS, .name = "GRAPHICS   - Framebuffer/display" },
        .{ .bit = capability.CAP_CRYPTO, .name = "CRYPTO     - Crypto operations" },
        .{ .bit = capability.CAP_CHAIN, .name = "CHAIN      - Blockchain operations" },
        .{ .bit = capability.CAP_ADMIN, .name = "ADMIN      - Admin/root operations" },
        .{ .bit = capability.CAP_RAW_IO, .name = "RAW_IO     - Raw I/O port access" },
        .{ .bit = capability.CAP_MEMORY, .name = "MEMORY     - Direct memory mapping" },
    };

    for (cap_list) |cap| {
        shell.print("    ");
        if ((caps & cap.bit) != 0) {
            shell.print("[*] ");
        } else {
            shell.print("[ ] ");
        }
        shell.println(cap.name);
    }

    shell.println("");
    const vcount = capability.getViolationCount(pid_val);
    shell.print("  Violations: ");
    helpers.printU32(@as(u32, vcount));
    if (vcount >= capability.KILL_THRESHOLD) {
        shell.printErrorLine(" (KILL THRESHOLD REACHED!)");
    } else if (vcount > 0) {
        shell.print("/");
        helpers.printU32(@as(u32, capability.KILL_THRESHOLD));
        shell.println(" until auto-kill");
    } else {
        shell.printSuccessLine(" (clean)");
    }
}

pub fn cmdGrant(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("grant: usage: grant <pid> <cap>");
        shell.println("  Caps: NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
        shell.println("        GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
        return;
    }

    var space_idx: usize = 0;
    while (space_idx < trimmed.len and trimmed[space_idx] != ' ') : (space_idx += 1) {}

    if (space_idx >= trimmed.len) {
        shell.printErrorLine("grant: usage: grant <pid> <cap>");
        return;
    }

    const pid_str = trimmed[0..space_idx];
    var cap_start = space_idx + 1;
    while (cap_start < trimmed.len and trimmed[cap_start] == ' ') : (cap_start += 1) {}
    const cap_str = trimmed[cap_start..];

    const pid_val = helpers.parseU32(pid_str) orelse {
        shell.printErrorLine("grant: invalid PID");
        return;
    };

    const cap = parseCapName(cap_str) orelse {
        shell.printErrorLine("grant: unknown capability");
        shell.println("  Valid: NET, FS_READ, FS_WRITE, IPC, EXEC, DEVICE,");
        shell.println("         GRAPHICS, CRYPTO, CHAIN, ADMIN, RAW_IO, MEMORY, ALL");
        return;
    };

    if (process.grantProcessCap(pid_val, cap)) {
        shell.printSuccess("Granted ");
        shell.print(cap_str);
        shell.print(" to PID ");
        helpers.printU32(pid_val);
        shell.newLine();
    } else {
        shell.printErrorLine("Process not found!");
    }
}

pub fn cmdRevoke(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("revoke: usage: revoke <pid> <cap>");
        return;
    }

    var space_idx: usize = 0;
    while (space_idx < trimmed.len and trimmed[space_idx] != ' ') : (space_idx += 1) {}

    if (space_idx >= trimmed.len) {
        shell.printErrorLine("revoke: usage: revoke <pid> <cap>");
        return;
    }

    const pid_str = trimmed[0..space_idx];
    var cap_start = space_idx + 1;
    while (cap_start < trimmed.len and trimmed[cap_start] == ' ') : (cap_start += 1) {}
    const cap_str = trimmed[cap_start..];

    const pid_val = helpers.parseU32(pid_str) orelse {
        shell.printErrorLine("revoke: invalid PID");
        return;
    };

    if (pid_val == 0) {
        shell.printErrorLine("Cannot revoke from kernel (PID 0)!");
        return;
    }

    const cap = parseCapName(cap_str) orelse {
        shell.printErrorLine("revoke: unknown capability");
        return;
    };

    if (process.revokeProcessCap(pid_val, cap)) {
        shell.printSuccess("Revoked ");
        shell.print(cap_str);
        shell.print(" from PID ");
        helpers.printU32(pid_val);
        shell.newLine();
    } else {
        shell.printErrorLine("Process not found!");
    }
}

pub fn cmdViolations(_: []const u8) void {
    if (!capability.isInitialized()) {
        shell.printErrorLine("Capability system not initialized!");
        return;
    }

    shell.printInfoLine("Security Violations:");
    shell.print("  Cap violations:    ");
    helpers.printU64(capability.getTotalViolations());
    shell.newLine();
    shell.print("  Unveil violations: ");
    helpers.printU64(unveil.getViolationCount());
    shell.newLine();
    shell.print("  Bin blocked:       ");
    helpers.printU64(binaryverify.getBlockCount());
    shell.newLine();
    shell.print("  Kill threshold:    ");
    helpers.printU32(@as(u32, capability.KILL_THRESHOLD));
    shell.println(" violations");

    if (capability.getTotalViolations() == 0 and unveil.getViolationCount() == 0 and binaryverify.getBlockCount() == 0) {
        shell.newLine();
        shell.printSuccessLine("  No violations recorded. System clean.");
        return;
    }

    if (capability.getTotalViolations() > 0) {
        shell.newLine();
        shell.println("  Cap Violations (recent):");
        shell.println("  PID   ATTEMPTED    SYSCALL   TIME");
        shell.println("  ----  -----------  --------  ----------");

        var recent: [16]capability.Violation = undefined;
        const count = capability.getRecentViolations(&recent);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            shell.print("  ");
            helpers.printU32(recent[i].pid);
            shell.print("     ");

            var buf: [16]u8 = undefined;
            const len = capability.formatCaps(recent[i].attempted_cap, &buf);
            shell.print(buf[0..len]);

            var pad: usize = if (len < 12) 12 - len else 1;
            while (pad > 0) : (pad -= 1) shell.print(" ");

            helpers.printU64(recent[i].syscall_num);
            shell.print("      ");
            helpers.printU64(recent[i].timestamp);
            shell.newLine();
        }
    }
}

// =============================================================================
// E3.2: Unveil Commands
// =============================================================================

pub fn cmdUnveil(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        shell.printInfoLine("Unveil Commands:");
        shell.println("  unveil <pid> <path> <perms>  Add allowed path");
        shell.println("  unveil lock <pid>            Lock table");
        shell.println("  unveil test                  Run unveil tests");
        shell.println("  paths <pid>                  Show allowed paths");
        shell.println("");
        shell.println("  Perms: r=read, w=write, x=exec, c=create");
        shell.println("  Example: unveil 1 /home rw");
        return;
    }

    if (helpers.strEql(trimmed, "test")) {
        runUnveilTest();
        return;
    }

    // unveil lock <pid>
    if (helpers.startsWith(trimmed, "lock ")) {
        const pid_str = helpers.trim(trimmed[5..]);
        const pid_val = helpers.parseU32(pid_str) orelse {
            shell.printErrorLine("unveil: invalid PID");
            return;
        };
        if (unveil.lock(pid_val)) {
            shell.printSuccessLine("Unveil table locked");
        } else {
            shell.printErrorLine("No unveil table for this PID");
        }
        return;
    }

    // Parse: <pid> <path> <perms>
    const parsed1 = helpers.splitFirst(trimmed, ' ');
    const pid_val = helpers.parseU32(parsed1.first) orelse {
        shell.printErrorLine("unveil: invalid PID");
        return;
    };

    if (parsed1.rest.len == 0) {
        shell.printErrorLine("unveil: need path and perms");
        return;
    }

    const parsed2 = helpers.splitFirst(parsed1.rest, ' ');
    const path_str = parsed2.first;
    const perm_str = if (parsed2.rest.len > 0) parsed2.rest else "r";

    // Ensure table exists
    if (!unveil.hasTable(pid_val)) {
        if (!unveil.createTable(pid_val)) {
            shell.printErrorLine("Failed to create unveil table");
            return;
        }
    }

    const perms = unveil.parsePerms(perm_str);
    if (unveil.addEntry(pid_val, path_str, perms)) {
        shell.printSuccess("Added: ");
        shell.print(path_str);
        shell.print(" [");
        var pbuf: [8]u8 = undefined;
        const plen = unveil.formatPerms(perms, &pbuf);
        shell.print(pbuf[0..plen]);
        shell.println("]");
    } else {
        shell.printErrorLine("Failed to add unveil entry");
    }
}

pub fn cmdPaths(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.printInfoLine("Processes with Unveil Tables:");
        shell.println("  PID   ENTRIES  LOCKED  FIRST PATH");
        shell.println("  ----  -------  ------  ----------");

        var found = false;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            if (process.process_used[i]) {
                const info = process.getProcessInfo(i) orelse continue;
                if (unveil.hasTable(info.pid)) {
                    found = true;
                    shell.print("  ");
                    helpers.printU32(info.pid);
                    shell.print("     ");
                    helpers.printU8(unveil.getEntryCount(info.pid));
                    shell.print("       ");
                    if (unveil.isLocked(info.pid)) {
                        shell.print("YES   ");
                    } else {
                        shell.print("NO    ");
                    }

                    if (unveil.getEntry(info.pid, 0)) |entry| {
                        shell.print(entry.path);
                        var pbuf: [8]u8 = undefined;
                        const plen = unveil.formatPerms(entry.perms, &pbuf);
                        shell.print(" [");
                        shell.print(pbuf[0..plen]);
                        shell.print("]");
                    }
                    shell.newLine();
                }
            }
        }

        if (!found) {
            shell.println("  (no unveil tables active)");
        }

        shell.print("  FS violations: ");
        helpers.printU64(unveil.getViolationCount());
        shell.newLine();
        return;
    }

    const pid_val = helpers.parseU32(trimmed) orelse {
        shell.printErrorLine("paths: invalid PID");
        return;
    };

    if (!unveil.hasTable(pid_val)) {
        shell.print("  PID ");
        helpers.printU32(pid_val);
        shell.println(": no unveil table (full access)");
        return;
    }

    shell.print("  PID ");
    helpers.printU32(pid_val);
    shell.print(" unveil paths (");
    if (unveil.isLocked(pid_val)) {
        shell.print("LOCKED");
    } else {
        shell.print("unlocked");
    }
    shell.println("):");

    const count = unveil.getEntryCount(pid_val);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (unveil.getEntry(pid_val, i)) |entry| {
            shell.print("    ");
            var pbuf: [8]u8 = undefined;
            const plen = unveil.formatPerms(entry.perms, &pbuf);
            shell.print("[");
            shell.print(pbuf[0..plen]);
            shell.print("] ");
            shell.println(entry.path);
        }
    }

    if (count == 0) {
        shell.println("    (empty - all paths blocked)");
    }
}

pub fn cmdSandboxFs(args: []const u8) void {
    const trimmed = helpers.trim(args);

    shell.printInfoLine("Spawning FS-sandboxed process...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithCaps(
        "fs-sandbox",
        @intFromPtr(&dummyEntry),
        id,
        capability.CAP_FS_READ,
    );

    if (pid_result) |pid| {
        if (unveil.createTable(pid)) {
            if (trimmed.len > 0) {
                _ = unveil.addEntry(pid, trimmed, unveil.PERM_RW);
                shell.printSuccess("Sandboxed PID ");
                helpers.printU32(pid);
                shell.print(" visible: ");
                shell.println(trimmed);
            } else {
                _ = unveil.addEntry(pid, "/tmp", unveil.PERM_RW);
                shell.printSuccess("Sandboxed PID ");
                helpers.printU32(pid);
                shell.println(" visible: /tmp [rw]");
            }
        }
    } else {
        shell.printErrorLine("Failed to create sandboxed process!");
    }
}

// =============================================================================
// E3.3: Binary Verification Commands
// =============================================================================

pub fn cmdVerifyBin(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        shell.printInfoLine("Binary Verification:");
        shell.println("  verify test           Run verification tests");
        shell.println("  verify status         Show verification status");
        shell.println("  verify enforce        Enable enforcement mode");
        shell.println("  verify warn           Switch to warn mode");
        shell.println("  trust <name> <data>   Trust a binary by name+data");
        shell.println("  untrust <name>        Remove from whitelist");
        shell.println("  trusted               List trusted binaries");
        return;
    }

    if (helpers.strEql(trimmed, "test")) {
        runBinaryVerifyTest();
        return;
    }

    if (helpers.strEql(trimmed, "status")) {
        shell.printInfoLine("Binary Verification Status:");
        shell.print("  Mode:      ");
        if (binaryverify.isEnforcing()) {
            shell.printErrorLine("ENFORCING");
        } else {
            shell.printWarningLine("WARN");
        }
        shell.print("  Trusted:   ");
        helpers.printUsize(binaryverify.getTrustCount());
        shell.newLine();
        shell.print("  Verified:  ");
        helpers.printU64(binaryverify.getVerifyCount());
        shell.newLine();
        shell.print("  Allowed:   ");
        helpers.printU64(binaryverify.getAllowCount());
        shell.newLine();
        shell.print("  Blocked:   ");
        helpers.printU64(binaryverify.getBlockCount());
        shell.newLine();
        return;
    }

    if (helpers.strEql(trimmed, "enforce")) {
        binaryverify.setEnforce(true);
        shell.printWarningLine("Binary verification: ENFORCING mode");
        shell.println("  Unsigned binaries will be BLOCKED!");
        return;
    }

    if (helpers.strEql(trimmed, "warn")) {
        binaryverify.setEnforce(false);
        shell.printSuccessLine("Binary verification: WARN mode");
        return;
    }

    shell.printErrorLine("verify: unknown subcommand");
    shell.println("  Use 'verify help' for usage");
}

pub fn cmdTrust(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.printErrorLine("trust: usage: trust <name> [data]");
        shell.println("  Example: trust myapp hello_world_binary");
        return;
    }

    const parsed = helpers.splitFirst(trimmed, ' ');
    const name = parsed.first;
    const data = if (parsed.rest.len > 0) parsed.rest else name;

    if (binaryverify.trustBinary(data, name, 0, 0)) {
        shell.printSuccess("Trusted: ");
        shell.print(name);
        shell.print(" hash=");

        var h = binaryverify.computeHash(data);
        var hex_buf: [64]u8 = undefined;
        const hex_len = binaryverify.formatHash(&h, &hex_buf);
        const show_len = @min(hex_len, 16);
        shell.print(hex_buf[0..show_len]);
        shell.println("...");
    } else {
        shell.printErrorLine("Failed to trust binary (table full?)");
    }
}

pub fn cmdUntrust(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.printErrorLine("untrust: usage: untrust <name>");
        return;
    }

    if (binaryverify.untrustByName(trimmed)) {
        shell.printSuccess("Untrusted: ");
        shell.println(trimmed);
    } else {
        shell.printErrorLine("Not found in trust list");
    }
}

pub fn cmdTrusted(args: []const u8) void {
    _ = args;

    shell.printInfoLine("Trusted Binaries:");
    shell.print("  Mode: ");
    if (binaryverify.isEnforcing()) {
        shell.printErrorLine("ENFORCING");
    } else {
        shell.printWarningLine("WARN");
    }

    const count = binaryverify.getTrustCount();
    shell.print("  Count: ");
    helpers.printUsize(count);
    shell.newLine();

    if (count == 0) {
        shell.println("  (no trusted binaries)");
        return;
    }

    shell.println("");
    shell.println("  #   NAME                HASH");
    shell.println("  --  ------------------  --------------------------------");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (binaryverify.getEntry(i)) |entry| {
            shell.print("  ");
            helpers.printU32(@as(u32, @intCast(i)));
            shell.print("   ");
            shell.print(entry.name);

            // Pad name
            var pad: usize = if (entry.name.len < 20) 20 - entry.name.len else 1;
            while (pad > 0) : (pad -= 1) shell.print(" ");

            // Print hash (first 32 chars)
            var hex_buf: [64]u8 = undefined;
            const hex_len = binaryverify.formatHash(entry.hash_ptr, &hex_buf);
            const show = @min(hex_len, 32);
            shell.print(hex_buf[0..show]);
            shell.println("...");
        }
    }

    shell.println("");
    shell.print("  Verified: ");
    helpers.printU64(binaryverify.getVerifyCount());
    shell.print("  Allowed: ");
    helpers.printU64(binaryverify.getAllowCount());
    shell.print("  Blocked: ");
    helpers.printU64(binaryverify.getBlockCount());
    shell.newLine();
}

// =============================================================================
// E3.1: Capability Test Suite
// =============================================================================

fn runCapabilityTest() void {
    shell.newLine();
    shell.println("  ========================================");
    shell.println("    E3.1 CAPABILITY SYSTEM TEST SUITE");
    shell.println("  ========================================");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest("Cap system init", capability.isInitialized(), &failed);
    passed += helpers.doTest("PID 0 = CAP_ALL", capability.getCaps(0) == capability.CAP_ALL, &failed);

    const pid0_net = capability.check(0, capability.CAP_NET);
    const pid0_admin = capability.check(0, capability.CAP_ADMIN);
    const pid0_all = capability.check(0, capability.CAP_ALL);
    passed += helpers.doTest("PID 0 passes all checks", pid0_net and pid0_admin and pid0_all, &failed);

    const test_pid: u32 = 98;
    const test_caps = capability.CAP_FS_READ | capability.CAP_IPC;
    const reg_ok = capability.registerProcess(test_pid, test_caps);
    passed += helpers.doTest("Register process", reg_ok, &failed);

    const has_read = capability.check(test_pid, capability.CAP_FS_READ);
    const has_ipc = capability.check(test_pid, capability.CAP_IPC);
    passed += helpers.doTest("Granted caps pass", has_read and has_ipc, &failed);

    const no_net = !capability.check(test_pid, capability.CAP_NET);
    const no_admin = !capability.check(test_pid, capability.CAP_ADMIN);
    const no_exec = !capability.check(test_pid, capability.CAP_EXEC);
    passed += helpers.doTest("Denied caps blocked", no_net and no_admin and no_exec, &failed);

    const grant_ok = capability.grantCap(test_pid, capability.CAP_NET);
    const now_has_net = capability.check(test_pid, capability.CAP_NET);
    passed += helpers.doTest("Grant cap works", grant_ok and now_has_net, &failed);

    const revoke_ok = capability.revokeCap(test_pid, capability.CAP_NET);
    const no_net_now = !capability.check(test_pid, capability.CAP_NET);
    passed += helpers.doTest("Revoke cap works", revoke_ok and no_net_now, &failed);

    const still_read = capability.check(test_pid, capability.CAP_FS_READ);
    const still_ipc = capability.check(test_pid, capability.CAP_IPC);
    passed += helpers.doTest("Original caps preserved", still_read and still_ipc, &failed);

    const set_ok = capability.setCaps(test_pid, capability.CAP_GRAPHICS | capability.CAP_CRYPTO);
    const has_gfx = capability.check(test_pid, capability.CAP_GRAPHICS);
    const has_cry = capability.check(test_pid, capability.CAP_CRYPTO);
    const lost_read = !capability.check(test_pid, capability.CAP_FS_READ);
    passed += helpers.doTest("Set caps (replace)", set_ok and has_gfx and has_cry and lost_read, &failed);

    var buf: [64]u8 = undefined;
    const len1 = capability.formatCaps(capability.CAP_ALL, &buf);
    const is_all = helpers.strEql(buf[0..len1], "ALL");
    passed += helpers.doTest("Format ALL", is_all, &failed);

    const len2 = capability.formatCaps(capability.CAP_NONE, &buf);
    const is_none = helpers.strEql(buf[0..len2], "NONE");
    passed += helpers.doTest("Format NONE", is_none, &failed);

    const len3 = capability.formatCaps(capability.CAP_NET | capability.CAP_FS_READ, &buf);
    passed += helpers.doTest("Format NET|R", len3 > 0, &failed);

    const pre_viol = capability.getTotalViolations();
    capability.recordViolationPublic(test_pid, capability.CAP_ADMIN, 999, 12345);
    const post_viol = capability.getTotalViolations();
    passed += helpers.doTest("Violation recorded", post_viol == pre_viol + 1, &failed);

    const pid_viol = capability.getViolationCount(test_pid);
    passed += helpers.doTest("PID violation count", pid_viol >= 1, &failed);

    const pre_v2 = capability.getTotalViolations();
    const enforce_result = capability.checkAndEnforce(test_pid, capability.CAP_ADMIN, 777, 99999);
    const post_v2 = capability.getTotalViolations();
    passed += helpers.doTest("checkAndEnforce deny", !enforce_result and post_v2 == pre_v2 + 1, &failed);

    const enforce_pass = capability.checkAndEnforce(test_pid, capability.CAP_GRAPHICS, 100, 100);
    passed += helpers.doTest("checkAndEnforce allow", enforce_pass, &failed);

    var recent: [8]capability.Violation = undefined;
    const recent_count = capability.getRecentViolations(&recent);
    passed += helpers.doTest("Recent violations", recent_count >= 1, &failed);

    const read_cap = capability.syscallRequiredCap(0);
    const write_cap = capability.syscallRequiredCap(1);
    const exit_cap = capability.syscallRequiredCap(60);
    passed += helpers.doTest("Syscall->cap mapping", read_cap == capability.CAP_FS_READ and write_cap == capability.CAP_FS_WRITE and exit_cap == capability.CAP_NONE, &failed);

    const stdout_ok = capability.checkWrite(test_pid, 1);
    const stderr_ok = capability.checkWrite(test_pid, 2);
    passed += helpers.doTest("stdout/stderr bypass", stdout_ok and stderr_ok, &failed);

    capability.unregisterProcess(test_pid);
    const after_unreg = capability.getViolationCount(test_pid);
    passed += helpers.doTest("Unregister clears count", after_unreg == 0, &failed);

    const unreg_caps = capability.getCaps(test_pid);
    passed += helpers.doTest("Unregistered = CAP_ALL", unreg_caps == capability.CAP_ALL, &failed);

    const spawn_pid = process.createWithCaps("test", @intFromPtr(&dummyEntry), 0, capability.CAP_FS_READ | capability.CAP_NET);
    if (spawn_pid) |spid| {
        const spawn_caps = process.getProcessCaps(spid);
        const spawn_ok = (spawn_caps & capability.CAP_FS_READ) != 0 and
            (spawn_caps & capability.CAP_NET) != 0 and
            (spawn_caps & capability.CAP_ADMIN) == 0;
        passed += helpers.doTest("Process spawn with caps", spawn_ok, &failed);

        const pg_ok = process.grantProcessCap(spid, capability.CAP_EXEC);
        const has_exec_p = (process.getProcessCaps(spid) & capability.CAP_EXEC) != 0;
        passed += helpers.doTest("Process grant cap", pg_ok and has_exec_p, &failed);

        const pr_ok = process.revokeProcessCap(spid, capability.CAP_NET);
        const no_net_p = (process.getProcessCaps(spid) & capability.CAP_NET) == 0;
        passed += helpers.doTest("Process revoke cap", pr_ok and no_net_p, &failed);

        _ = process.terminate(spid);
    } else {
        helpers.doSkip("Process spawn with caps");
        helpers.doSkip("Process grant cap");
        helpers.doSkip("Process revoke cap");
    }

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// E3.2: Unveil Test Suite
// =============================================================================

fn runUnveilTest() void {
    shell.newLine();
    shell.println("  ========================================");
    shell.println("    E3.2 UNVEIL SANDBOX TEST SUITE");
    shell.println("  ========================================");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest("Unveil system init", unveil.isInitialized(), &failed);

    const pid0_ok = unveil.checkAccess(0, "/anything", unveil.PERM_ALL);
    passed += helpers.doTest("PID 0 always allowed", pid0_ok, &failed);

    const no_table_ok = unveil.checkAccess(97, "/secret", unveil.PERM_READ);
    passed += helpers.doTest("No table = full access", no_table_ok, &failed);

    const test_pid: u32 = 97;
    const create_ok = unveil.createTable(test_pid);
    passed += helpers.doTest("Create unveil table", create_ok, &failed);

    const empty_blocked = !unveil.checkAccess(test_pid, "/home", unveil.PERM_READ);
    passed += helpers.doTest("Empty table = blocked", empty_blocked, &failed);

    const add_ok = unveil.addEntry(test_pid, "/home", unveil.PERM_READ);
    passed += helpers.doTest("Add unveil entry", add_ok, &failed);

    const home_ok = unveil.checkAccess(test_pid, "/home", unveil.PERM_READ);
    passed += helpers.doTest("Allowed path passes", home_ok, &failed);

    const sub_ok = unveil.checkAccess(test_pid, "/home/user/file.txt", unveil.PERM_READ);
    passed += helpers.doTest("Subpath passes", sub_ok, &failed);

    const other_blocked = !unveil.checkAccess(test_pid, "/etc/passwd", unveil.PERM_READ);
    passed += helpers.doTest("Other path blocked", other_blocked, &failed);

    const write_blocked = !unveil.checkAccess(test_pid, "/home", unveil.PERM_WRITE);
    passed += helpers.doTest("Wrong perm blocked", write_blocked, &failed);

    _ = unveil.addEntry(test_pid, "/tmp", unveil.PERM_RW);
    const tmp_rw = unveil.checkAccess(test_pid, "/tmp/data", unveil.PERM_WRITE);
    passed += helpers.doTest("RW entry works", tmp_rw, &failed);

    const test_pid2: u32 = 96;
    _ = unveil.createTable(test_pid2);
    _ = unveil.addEntry(test_pid2, "/", unveil.PERM_READ);
    const root_match = unveil.checkAccess(test_pid2, "/any/deep/path", unveil.PERM_READ);
    passed += helpers.doTest("Root entry = match all", root_match, &failed);

    const lock_ok = unveil.lock(test_pid);
    passed += helpers.doTest("Lock table", lock_ok, &failed);

    const add_after_lock = !unveil.addEntry(test_pid, "/new", unveil.PERM_READ);
    passed += helpers.doTest("Locked rejects add", add_after_lock, &failed);

    var pbuf: [8]u8 = undefined;
    const plen = unveil.formatPerms(unveil.PERM_RW, &pbuf);
    const is_rw = plen == 2 and pbuf[0] == 'r' and pbuf[1] == 'w';
    passed += helpers.doTest("Format perms rw", is_rw, &failed);

    const parsed = unveil.parsePerms("rwxc");
    passed += helpers.doTest("Parse perms rwxc", parsed == unveil.PERM_ALL, &failed);

    const ec = unveil.getEntryCount(test_pid);
    passed += helpers.doTest("Entry count correct", ec == 2, &failed);

    const entry = unveil.getEntry(test_pid, 0);
    passed += helpers.doTest("Get entry works", entry != null, &failed);

    const pre_v = unveil.getViolationCount();
    _ = unveil.checkAndEnforce(test_pid, "/forbidden", unveil.PERM_READ);
    const post_v = unveil.getViolationCount();
    passed += helpers.doTest("Violation counted", post_v == pre_v + 1, &failed);

    unveil.destroyTable(test_pid);
    unveil.destroyTable(test_pid2);
    const after_destroy = !unveil.hasTable(test_pid);
    passed += helpers.doTest("Destroy table", after_destroy, &failed);

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// E3.3: Binary Verification Test Suite
// =============================================================================

fn runBinaryVerifyTest() void {
    shell.newLine();
    shell.println("  ========================================");
    shell.println("    E3.3 BINARY VERIFICATION TEST SUITE");
    shell.println("  ========================================");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: System initialized
    passed += helpers.doTest("BinVerify system init", binaryverify.isInitialized(), &failed);

    // Test 2: Default mode = warn
    passed += helpers.doTest("Default mode = warn", !binaryverify.isEnforcing(), &failed);

    // Test 3: Empty whitelist
    passed += helpers.doTest("Empty whitelist", binaryverify.getTrustCount() == 0, &failed);

    // Test 4: Trust a binary
    const test_data = "test_binary_data_12345";
    const trust_ok = binaryverify.trustBinary(test_data, "test_app", 0, 100);
    passed += helpers.doTest("Trust binary", trust_ok, &failed);

    // Test 5: Trust count increased
    passed += helpers.doTest("Trust count = 1", binaryverify.getTrustCount() == 1, &failed);

    // Test 6: Verify trusted binary = Trusted
    const result1 = binaryverify.verifyBinary(test_data);
    passed += helpers.doTest("Verify trusted = ok", result1 == .Trusted, &failed);

    // Test 7: Verify unknown binary = Untrusted
    const result2 = binaryverify.verifyBinary("unknown_binary");
    passed += helpers.doTest("Verify unknown = untrusted", result2 == .Untrusted, &failed);

    // Test 8: checkExec in warn mode = allow
    const exec_ok = binaryverify.checkExec("unknown_binary");
    passed += helpers.doTest("Warn mode allows unknown", exec_ok, &failed);

    // Test 9: Switch to enforce mode
    binaryverify.setEnforce(true);
    passed += helpers.doTest("Enforce mode set", binaryverify.isEnforcing(), &failed);

    // Test 10: checkExec in enforce mode = block unknown
    const exec_blocked = !binaryverify.checkExec("unknown_binary");
    passed += helpers.doTest("Enforce blocks unknown", exec_blocked, &failed);

    // Test 11: checkExec trusted still allowed
    const exec_trusted = binaryverify.checkExec(test_data);
    passed += helpers.doTest("Enforce allows trusted", exec_trusted, &failed);

    // Test 12: Block count increased
    passed += helpers.doTest("Block count > 0", binaryverify.getBlockCount() > 0, &failed);

    // Test 13: Verify count tracking
    passed += helpers.doTest("Verify count > 0", binaryverify.getVerifyCount() > 0, &failed);

    // Test 14: Hash computation
    const h1 = binaryverify.computeHash("hello");
    const h2 = binaryverify.computeHash("world");
    const h3 = binaryverify.computeHash("hello");
    const same = hash_mod.hashEqual(&h1, &h3);
    const diff = !hash_mod.hashEqual(&h1, &h2);
    passed += helpers.doTest("Hash deterministic", same and diff, &failed);

    // Test 15: formatHash
    var hex_buf: [64]u8 = undefined;
    const hex_len = binaryverify.formatHash(&h1, &hex_buf);
    passed += helpers.doTest("Format hash", hex_len == 64, &failed);

    // Test 16: parseHexHash
    var parsed_hash: [32]u8 = undefined;
    const parse_ok = binaryverify.parseHexHash(hex_buf[0..64], &parsed_hash);
    const parse_match = parse_ok and hash_mod.hashEqual(&h1, &parsed_hash);
    passed += helpers.doTest("Parse hex hash", parse_match, &failed);

    // Test 17: Trust duplicate = ok (idempotent)
    const dup_ok = binaryverify.trustBinary(test_data, "test_app", 0, 200);
    passed += helpers.doTest("Trust duplicate ok", dup_ok and binaryverify.getTrustCount() == 1, &failed);

    // Test 18: Trust second binary
    const trust2 = binaryverify.trustBinary("another_binary", "app2", 0, 300);
    passed += helpers.doTest("Trust second binary", trust2 and binaryverify.getTrustCount() == 2, &failed);

    // Test 19: Untrust by name
    const untrust_ok = binaryverify.untrustByName("app2");
    passed += helpers.doTest("Untrust by name", untrust_ok and binaryverify.getTrustCount() == 1, &failed);

    // Test 20: getEntry
    const bv_entry = binaryverify.getEntry(0);
    const entry_ok = bv_entry != null;
    var name_ok = false;
    if (bv_entry) |e| {
        name_ok = helpers.strEql(e.name, "test_app");
    }
    passed += helpers.doTest("Get entry works", entry_ok and name_ok, &failed);

    // Cleanup
    _ = binaryverify.untrustByName("test_app");
    binaryverify.setEnforce(false);

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Helpers
// =============================================================================

fn dummyEntry() void {
    while (true) {
        asm volatile ("hlt");
    }
}

fn parseCapName(name: []const u8) ?u32 {
    if (strEqlIgnoreCase(name, "NET")) return capability.CAP_NET;
    if (strEqlIgnoreCase(name, "FS_READ")) return capability.CAP_FS_READ;
    if (strEqlIgnoreCase(name, "FS_WRITE")) return capability.CAP_FS_WRITE;
    if (strEqlIgnoreCase(name, "IPC")) return capability.CAP_IPC;
    if (strEqlIgnoreCase(name, "EXEC")) return capability.CAP_EXEC;
    if (strEqlIgnoreCase(name, "DEVICE")) return capability.CAP_DEVICE;
    if (strEqlIgnoreCase(name, "GRAPHICS")) return capability.CAP_GRAPHICS;
    if (strEqlIgnoreCase(name, "CRYPTO")) return capability.CAP_CRYPTO;
    if (strEqlIgnoreCase(name, "CHAIN")) return capability.CAP_CHAIN;
    if (strEqlIgnoreCase(name, "ADMIN")) return capability.CAP_ADMIN;
    if (strEqlIgnoreCase(name, "RAW_IO")) return capability.CAP_RAW_IO;
    if (strEqlIgnoreCase(name, "MEMORY")) return capability.CAP_MEMORY;
    if (strEqlIgnoreCase(name, "ALL")) return capability.CAP_ALL;
    if (strEqlIgnoreCase(name, "NONE")) return capability.CAP_NONE;
    return null;
}

fn strEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la: u8 = if (ca >= 'a' and ca <= 'z') ca - 32 else ca;
        const lb: u8 = if (cb >= 'a' and cb <= 'z') cb - 32 else cb;
        if (la != lb) return false;
    }
    return true;
}
