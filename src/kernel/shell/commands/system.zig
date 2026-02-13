//! Zamrud OS - System Commands
//! help, clear, info, uptime, memory, history, echo, theme

const shell = @import("../shell.zig");
const ui = @import("../ui.zig");
const helpers = @import("helpers.zig");

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
const syscall_mod = @import("../../syscall/syscall.zig");
const storage = @import("../../drivers/storage/storage.zig");

pub fn cmdHelp(_: []const u8) void {
    shell.printInfoLine("Zamrud OS - Available Commands");
    shell.newLine();

    shell.println("  System:");
    shell.println("    help            - Show this help");
    shell.println("    clear           - Clear screen");
    shell.println("    info            - System information");
    shell.println("    uptime          - Show system uptime");
    shell.println("    mem             - Memory statistics");
    shell.println("    history         - Command history");
    shell.println("    echo <text>     - Print text");
    shell.println("    theme <name>    - Change theme");
    shell.newLine();

    shell.println("  File System:");
    shell.println("    ls, cd, pwd, mkdir, touch, rm, rmdir, cat, write");
    shell.newLine();

    shell.println("  Device:");
    shell.println("    lsdev, devtest");
    shell.newLine();

    shell.println("  Disk/Storage:");
    shell.println("    disk list       - List detected drives");
    shell.println("    disk read <lba> - Read sector at LBA");
    shell.println("    disk test       - Test disk driver");
    shell.println("    diskinfo        - Alias for disk list");
    shell.newLine();

    shell.println("  Process:");
    shell.println("    ps, spawn, kill, sched");
    shell.newLine();

    shell.println("  Network:");
    shell.println("    net, nettest, ifconfig, ping, netstat, arp");
    shell.println("    p2p, gateway, security, firewall");
    shell.newLine();

    shell.println("  Security:");
    shell.println("    crypto, chain, integrity, identity, boot, syscall");
    shell.newLine();

    shell.println("  User/Group (F3):");
    shell.println("    login logout whoami id su sudo sudoend user usertest");

    // Di bagian help text, tambahkan:
    shell.println("  sysenc              System encryption management");
    shell.println("  sysenctest          Run F4.2 encryption test suite");

    shell.println("  Test:");
    shell.println("    testall, smoke");
    shell.newLine();

    shell.println("  Power:");
    shell.println("    reboot, shutdown, exit");
    shell.newLine();
}

pub fn cmdClear(_: []const u8) void {
    shell.clearScreen();
}

pub fn cmdInfo(_: []const u8) void {
    shell.printInfoLine("Zamrud OS v0.1.0");
    shell.println("  Kernel: 64-bit x86_64");

    shell.print("  Resolution: ");
    if (terminal.isInitialized()) {
        helpers.printU32(terminal.getWidth());
        shell.print("x");
        helpers.printU32(terminal.getHeight());
        shell.print(" (");
        helpers.printU32(terminal.getCols());
        shell.print("x");
        helpers.printU32(terminal.getRows());
        shell.println(" chars)");
    } else {
        shell.println("N/A");
    }

    shell.print("  Processes: ");
    helpers.printU32(process.getCount());
    shell.newLine();

    shell.print("  VFS: ");
    if (vfs.exists("/")) {
        shell.printSuccessLine("Mounted");
    } else {
        shell.printErrorLine("Not mounted");
    }

    shell.print("  DevFS: ");
    if (devfs.isInitialized()) {
        shell.printSuccess("Mounted (");
        helpers.printUsize(devfs.getDeviceCount());
        shell.println(" devices)");
    } else {
        shell.printErrorLine("Not mounted");
    }

    shell.print("  Storage: ");
    if (storage.isInitialized()) {
        const drive_count = storage.getDriveCount();
        if (drive_count > 0) {
            shell.printSuccess("Ready (");
            helpers.printUsize(drive_count);
            if (drive_count == 1) {
                shell.println(" drive)");
            } else {
                shell.println(" drives)");
            }
        } else {
            shell.printWarningLine("No drives detected");
        }
    } else {
        shell.printErrorLine("Not initialized");
    }

    shell.print("  Network: ");
    if (net.isInitialized()) {
        shell.printSuccessLine("Ready");
    } else {
        shell.printErrorLine("Not initialized");
    }

    shell.print("  User Mode: ");
    if (user.isInitialized()) {
        shell.printSuccessLine("Ready");
    } else {
        shell.printErrorLine("Not initialized");
    }

    shell.print("  Crypto: ");
    if (crypto.isInitialized()) {
        if (crypto.random.hasHardwareRng()) {
            shell.printSuccessLine("Ready (RDRAND)");
        } else {
            shell.printSuccessLine("Ready (Software RNG)");
        }
    } else {
        shell.printErrorLine("Not initialized");
    }

    shell.print("  Blockchain: ");
    if (chain.isInitialized()) {
        shell.printSuccessLine("Ready");
    } else {
        shell.printWarningLine("Not initialized");
    }

    shell.print("  Syscalls: ");
    helpers.printU32(@intCast(syscall_mod.getSyscallCount() & 0xFFFFFFFF));
    shell.println(" executed");
}

pub fn cmdUptime(_: []const u8) void {
    const seconds = timer.getSeconds();
    const hours = seconds / 3600;
    const minutes = (seconds % 3600) / 60;
    const secs = seconds % 60;

    shell.printInfo("Uptime: ");
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

    shell.print("  Total: ");
    helpers.printUsize(seconds);
    shell.println(" seconds");

    shell.print("  Ticks: ");
    helpers.printU64(timer.getTicks());
    shell.newLine();
}

pub fn cmdMemory(_: []const u8) void {
    const stats = heap.getStats();

    shell.printInfoLine("Memory Statistics:");

    shell.print("  Heap size:     ");
    helpers.printUsize(stats.heap_size);
    shell.print(" bytes (");
    helpers.printUsize(stats.heap_size / 1024);
    shell.println(" KB)");

    shell.print("  Allocated:     ");
    helpers.printUsize(stats.total_allocated);
    shell.println(" bytes");

    shell.print("  Freed:         ");
    helpers.printUsize(stats.total_freed);
    shell.println(" bytes");

    shell.print("  In use:        ");
    const in_use = if (stats.total_allocated >= stats.total_freed)
        stats.total_allocated - stats.total_freed
    else
        0;
    helpers.printUsize(in_use);
    shell.println(" bytes");

    shell.print("  Active allocs: ");
    helpers.printUsize(stats.allocation_count);
    shell.newLine();

    shell.print("  Free blocks:   ");
    helpers.printUsize(stats.free_blocks);
    shell.newLine();
}

pub fn cmdHistory(_: []const u8) void {
    shell.printInfoLine("Command History:");

    const count = shell.getHistoryCount();
    if (count == 0) {
        shell.println("  (empty)");
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        shell.print("  ");
        helpers.printUsize(i + 1);
        shell.print(". ");
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
            return;
        }

        const filename = helpers.trim(args[filename_start..]);

        if (!vfs.exists(filename)) {
            if (vfs.createFile(filename) == null) {
                shell.printErrorLine("echo: cannot create file");
                return;
            }
        }

        var flags = vfs.OpenFlags.O_WRONLY;
        flags.write = true;
        flags.truncate = true;
        const file = vfs.open(filename, flags);
        if (file == null) {
            shell.printErrorLine("echo: cannot open file");
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
}

pub fn cmdTheme(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        shell.printInfoLine("Available themes:");
        shell.println("  theme dark    - Dark theme (default)");
        shell.println("  theme light   - Light theme");
        shell.println("  theme matrix  - Matrix/hacker theme");
        shell.println("  theme dracula - Dracula theme");
    } else if (helpers.strEql(trimmed, "dark")) {
        ui.setTheme(&ui.themes.dark);
        shell.printSuccessLine("Theme set to: dark");
    } else if (helpers.strEql(trimmed, "light")) {
        ui.setTheme(&ui.themes.light);
        shell.printSuccessLine("Theme set to: light");
    } else if (helpers.strEql(trimmed, "matrix")) {
        ui.setTheme(&ui.themes.matrix);
        shell.printSuccessLine("Theme set to: matrix");
    } else if (helpers.strEql(trimmed, "dracula")) {
        ui.setTheme(&ui.themes.dracula);
        shell.printSuccessLine("Theme set to: dracula");
    } else {
        shell.printError("Unknown theme: ");
        shell.println(trimmed);
    }
}
