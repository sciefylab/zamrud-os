//! Zamrud OS - Device Commands
//! lsdev, devtest

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const vfs = @import("../../fs/vfs.zig");
const devfs = @import("../../fs/devfs.zig");

var test_buf: [8]u8 = [_]u8{0} ** 8;

pub fn cmdLsDev(_: []const u8) void {
    shell.printInfoLine("Devices in /dev:");

    var index: usize = 0;
    while (true) {
        const entry = vfs.readdir("/dev", index);
        if (entry == null) break;

        shell.print("  ");
        shell.println(entry.?.getName());
        index += 1;
    }

    if (index == 0) {
        shell.println("  (no devices)");
    } else {
        shell.newLine();
        shell.print("  Total: ");
        helpers.printUsize(index);
        shell.println(" devices");
    }
}

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
