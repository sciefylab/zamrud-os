//! Zamrud OS - Device Commands
//! lsdev, devtest
//! T4.1: Colored output with table formatting

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const ui = @import("../ui.zig");
const vfs = @import("../../fs/vfs.zig");
const devfs = @import("../../fs/devfs.zig");

var test_buf: [8]u8 = [_]u8{0} ** 8;

// =============================================================================
// T4.1: Colored lsdev with table formatting
// =============================================================================

pub fn cmdLsDev(_: []const u8) void {
    const theme = ui.getTheme();

    shell.newLine();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
    }
    shell.println("  Devices (/dev)");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
        terminal.setFgColor(theme.border);
    }
    shell.println("  ─────────────────────────────────────");

    if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
    shell.println("  Name              Type       Status");
    shell.println("  ────────────────  ─────────  ──────");
    if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);

    var index: usize = 0;
    var char_count: usize = 0;
    var block_count: usize = 0;
    var other_count: usize = 0;

    while (true) {
        const entry = vfs.readdir("/dev", index);
        if (entry == null) break;

        const name = entry.?.getName();

        shell.print("  ");

        // Device name with color
        if (terminal.isInitialized()) {
            if (entry.?.file_type == .CharDevice) {
                terminal.setFgColor(theme.text_warning);
                char_count += 1;
            } else if (entry.?.file_type == .BlockDevice) {
                terminal.setFgColor(theme.text_info);
                block_count += 1;
            } else {
                terminal.setFgColor(theme.text_normal);
                other_count += 1;
            }
        }

        shell.print(name);

        // Pad name to 16 chars
        var pad: usize = if (16 > name.len) 16 - name.len else 1;
        while (pad > 0) : (pad -= 1) shell.printChar(' ');

        // Type column
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        if (entry.?.file_type == .CharDevice) {
            shell.print("[CHAR]     ");
        } else if (entry.?.file_type == .BlockDevice) {
            shell.print("[BLOCK]    ");
        } else if (entry.?.file_type == .Directory) {
            shell.print("[DIR]      ");
        } else {
            shell.print("[FILE]     ");
        }

        // Status column
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_success);
        shell.print("OK");

        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
        shell.newLine();
        index += 1;
    }

    if (index == 0) {
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.println("  (no devices)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    } else {
        if (terminal.isInitialized()) terminal.setFgColor(theme.border);
        shell.println("  ────────────────  ─────────  ──────");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_dim);
        shell.print("  ");
        helpers.printUsize(index);
        shell.print(" devices (");
        helpers.printUsize(char_count);
        shell.print(" char, ");
        helpers.printUsize(block_count);
        shell.print(" block, ");
        helpers.printUsize(other_count);
        shell.println(" other)");
        if (terminal.isInitialized()) terminal.setFgColor(theme.text_normal);
    }
    shell.newLine();
}

// =============================================================================
// Device Tests (unchanged logic, colored output via helpers)
// =============================================================================

pub fn cmdDevTest(_: []const u8) void {
    helpers.printTestHeader("DEVICE TEST SUITE");

    var passed: u32 = 0;
    var failed: u32 = 0;

    passed += helpers.doTest("/dev/null write", testDevNullWrite(), &failed);
    passed += helpers.doTest("/dev/null read", testDevNullRead(), &failed);
    passed += helpers.doTest("/dev/zero read", testDevZeroRead(), &failed);
    passed += helpers.doTest("/dev/random read", testDevRandomRead(), &failed);
    passed += helpers.doTest("/dev/console write", testDevConsoleWrite(), &failed);
    passed += helpers.doTest("/dev/serial write", testDevSerialWrite(), &failed);

    helpers.printTestResults(passed, failed);
}

fn testDevNullWrite() bool {
    var flags = vfs.OpenFlags.O_WRONLY;
    flags.write = true;
    const file = vfs.open("/dev/null", flags);
    if (file == null) return false;
    const written = vfs.write(file.?, "test data");
    vfs.close(file.?);
    return written > 0;
}

fn testDevNullRead() bool {
    var flags = vfs.OpenFlags.O_RDONLY;
    flags.read = true;
    const file = vfs.open("/dev/null", flags);
    if (file == null) return false;

    @memset(&test_buf, 0);
    const bytes_read = vfs.read(file.?, test_buf[0..8]);
    vfs.close(file.?);
    return bytes_read == 0;
}

fn testDevZeroRead() bool {
    var flags = vfs.OpenFlags.O_RDONLY;
    flags.read = true;
    const file = vfs.open("/dev/zero", flags);
    if (file == null) return false;

    @memset(&test_buf, 0xFF);
    const bytes_read = vfs.read(file.?, test_buf[0..8]);
    vfs.close(file.?);
    if (bytes_read <= 0) return false;

    for (test_buf) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn testDevRandomRead() bool {
    var flags = vfs.OpenFlags.O_RDONLY;
    flags.read = true;
    const file = vfs.open("/dev/random", flags);
    if (file == null) return false;

    @memset(&test_buf, 0);
    const bytes_read = vfs.read(file.?, test_buf[0..4]);
    vfs.close(file.?);
    return bytes_read > 0;
}

fn testDevConsoleWrite() bool {
    var flags = vfs.OpenFlags.O_WRONLY;
    flags.write = true;
    const file = vfs.open("/dev/console", flags);
    if (file == null) return false;
    const written = vfs.write(file.?, "[console test]");
    vfs.close(file.?);
    return written > 0;
}

fn testDevSerialWrite() bool {
    var flags = vfs.OpenFlags.O_WRONLY;
    flags.write = true;
    const file = vfs.open("/dev/serial", flags);
    if (file == null) return false;
    const written = vfs.write(file.?, "[serial test]");
    vfs.close(file.?);
    return written > 0;
}
