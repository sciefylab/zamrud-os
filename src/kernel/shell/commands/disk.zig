//! Zamrud OS - Disk Commands

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const storage = @import("../../drivers/storage/storage.zig");

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "list")) {
        listDrives();
    } else if (helpers.strEql(parsed.cmd, "read")) {
        readSector(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest();
    } else {
        shell.printError("disk: unknown command\n");
    }
}

fn showHelp() void {
    shell.printInfoLine("=== DISK COMMANDS ===");
    shell.println("  disk list       - List detected drives");
    shell.println("  disk read <lba> - Read sector at LBA");
    shell.println("  disk test       - Run disk tests");
}

fn listDrives() void {
    const count = storage.getDriveCount();

    shell.print("Detected drives: ");
    helpers.printUsize(count);
    shell.newLine();

    if (count == 0) {
        shell.println("  No drives found");
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (storage.getDrive(i)) |drv| {
            shell.print("  Drive ");
            helpers.printUsize(i);
            shell.print(": ");

            // Print model
            for (drv.model) |c| {
                if (c == 0) break;
                shell.printChar(c);
            }

            shell.print(" - ");
            helpers.printUsize(drv.size_mb);
            shell.println(" MB");
        }
    }
}

fn readSector(args: []const u8) void {
    const lba = helpers.parseU32(args) orelse 0;

    shell.print("Reading sector ");
    helpers.printUsize(lba);
    shell.println("...");

    var buffer: [512]u8 = [_]u8{0} ** 512;

    if (storage.readSector(0, lba, &buffer)) {
        shell.println("Success! First 64 bytes:");

        var i: usize = 0;
        while (i < 64) : (i += 1) {
            if (i % 16 == 0) {
                shell.print("  ");
            }
            helpers.printHexByte(buffer[i]);
            shell.print(" ");
            if ((i + 1) % 16 == 0) {
                shell.newLine();
            }
        }
    } else |_| {
        shell.printErrorLine("Read failed!");
    }
}

fn runTest() void {
    if (storage.test_storage()) {
        shell.printSuccessLine("Disk test PASSED");
    } else {
        shell.printErrorLine("Disk test FAILED");
    }
}
