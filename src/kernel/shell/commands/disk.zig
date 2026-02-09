//! Zamrud OS - Disk Commands

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const storage = @import("../../drivers/storage/storage.zig");
const mbr = @import("../../drivers/storage/mbr.zig");

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "list")) {
        listDrives();
    } else if (helpers.strEql(parsed.cmd, "info")) {
        showInfo(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "part") or helpers.strEql(parsed.cmd, "partitions")) {
        listPartitions();
    } else if (helpers.strEql(parsed.cmd, "read")) {
        readSector(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "format")) {
        formatDisk(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest();
    } else {
        shell.printError("disk: unknown command '");
        shell.print(parsed.cmd);
        shell.println("'");
        shell.println("Type 'disk help' for usage");
    }
}

fn showHelp() void {
    shell.println("");
    shell.printInfoLine("=== DISK COMMANDS ===");
    shell.println("");
    shell.println("  disk list           - List detected drives");
    shell.println("  disk info [n]       - Show drive info (default: 0)");
    shell.println("  disk part           - List partitions");
    shell.println("  disk read <lba>     - Read sector at LBA");
    shell.println("  disk format         - Format disk (interactive)");
    shell.println("  disk format confirm - Format disk (no prompt)");
    shell.println("  disk test           - Run disk tests");
    shell.println("");
}

fn listDrives() void {
    const count = storage.getDriveCount();

    shell.println("");
    shell.printInfoLine("=== DETECTED DRIVES ===");
    shell.println("");

    if (count == 0) {
        shell.println("  No drives detected");
        shell.println("");
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (storage.getDrive(i)) |drv| {
            shell.print("  [");
            helpers.printUsize(i);
            shell.print("] ");

            // Print model
            var model_printed = false;
            for (drv.model) |c| {
                if (c == 0) break;
                shell.printChar(c);
                model_printed = true;
            }
            if (!model_printed) {
                shell.print("Unknown");
            }

            shell.print(" - ");
            helpers.printUsize(drv.size_mb);
            shell.print(" MB");

            if (drv.lba48) {
                shell.print(" (LBA48)");
            }

            shell.newLine();
        }
    }
    shell.println("");
}

fn showInfo(args: []const u8) void {
    const drive_idx = helpers.parseU32(args) orelse 0;

    shell.println("");
    shell.printInfoLine("=== DRIVE INFO ===");
    shell.println("");

    if (storage.getDrive(drive_idx)) |drv| {
        shell.print("  Drive:     ");
        helpers.printUsize(drive_idx);
        shell.newLine();

        shell.print("  Model:     ");
        for (drv.model) |c| {
            if (c == 0) break;
            shell.printChar(c);
        }
        shell.newLine();

        shell.print("  Serial:    ");
        for (drv.serial) |c| {
            if (c == 0) break;
            shell.printChar(c);
        }
        shell.newLine();

        shell.print("  Size:      ");
        helpers.printUsize(drv.size_mb);
        shell.println(" MB");

        shell.print("  Sectors:   ");
        printU64(drv.sectors);
        shell.newLine();

        shell.print("  LBA48:     ");
        if (drv.lba48) {
            shell.println("Yes");
        } else {
            shell.println("No");
        }

        shell.print("  Bus:       ");
        if (drv.bus == 0) {
            shell.print("Primary ");
        } else {
            shell.print("Secondary ");
        }
        if (drv.drive == 0) {
            shell.println("Master");
        } else {
            shell.println("Slave");
        }
    } else {
        shell.print("  Drive ");
        helpers.printUsize(drive_idx);
        shell.println(" not found");
    }
    shell.println("");
}

fn listPartitions() void {
    shell.println("");
    shell.printInfoLine("=== PARTITION TABLE ===");
    shell.println("");

    const count = storage.getPartitionCount();

    if (count == 0) {
        shell.println("  No partitions found");
        shell.println("  Disk may be unformatted");
        shell.println("");
        shell.println("  Use 'disk format' to create partition table");
        shell.println("");
        return;
    }

    shell.print("  Found ");
    helpers.printUsize(count);
    shell.println(" partition(s):");
    shell.println("");

    // Header
    shell.println("  #  Type          Size      Start LBA   Flags");
    shell.println("  ─────────────────────────────────────────────");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (storage.getPartition(i)) |p| {
            shell.print("  ");
            helpers.printUsize(i);
            shell.print("  ");

            // Type name (padded)
            const type_name = p.getTypeName();
            shell.print(type_name);
            padSpaces(14 - type_name.len);

            // Size
            helpers.printUsize(p.size_mb);
            shell.print(" MB");
            padSpaces(6 - countDigits(p.size_mb));

            // Start LBA
            helpers.printUsize(p.start_lba);
            padSpaces(12 - countDigits(p.start_lba));

            // Flags
            if (p.bootable) {
                shell.print("BOOT ");
            }
            if (p.isSupported()) {
                shell.print("RW");
            } else {
                shell.print("RO");
            }

            shell.newLine();
        }
    }

    shell.println("");

    // Show FAT32 info
    if (storage.findFAT32Partition()) |fat32| {
        shell.print("  FAT32 partition at LBA ");
        helpers.printUsize(fat32.start_lba);
        shell.println(" (ready for use)");
        shell.println("");
    }
}

fn formatDisk(args: []const u8) void {
    shell.println("");

    // Check if drives exist
    if (storage.getDriveCount() == 0) {
        shell.printErrorLine("No drives detected!");
        shell.println("");
        return;
    }

    // Check for confirmation flag
    const confirmed = helpers.strEql(args, "confirm") or
        helpers.strEql(args, "--confirm") or
        helpers.strEql(args, "-y");

    if (!confirmed) {
        // Show warning
        shell.println("  ┌────────────────────────────────────────┐");
        shell.println("  │  ⚠️  WARNING: FORMAT DISK              │");
        shell.println("  ├────────────────────────────────────────┤");
        shell.println("  │  This will ERASE ALL DATA on drive 0!  │");
        shell.println("  │                                        │");
        shell.println("  │  A new MBR partition table will be     │");
        shell.println("  │  created with a single FAT32 partition │");
        shell.println("  └────────────────────────────────────────┘");
        shell.println("");
        shell.println("  To proceed, type:");
        shell.println("    disk format confirm");
        shell.println("");
        return;
    }

    // Show what we're doing
    if (storage.getDrive(0)) |drv| {
        shell.println("  ┌────────────────────────────────────────┐");
        shell.println("  │  FORMATTING DISK                       │");
        shell.println("  └────────────────────────────────────────┘");
        shell.println("");
        shell.print("  Drive: ");
        for (drv.model) |c| {
            if (c == 0) break;
            shell.printChar(c);
        }
        shell.newLine();
        shell.print("  Size:  ");
        helpers.printUsize(drv.size_mb);
        shell.println(" MB");
        shell.println("  Type:  FAT32 LBA");
        shell.println("");
    }

    shell.print("  Creating MBR partition table...");

    // Do the format
    if (storage.formatDriveFAT32(0, storage.CONFIRM_FORMAT)) {
        shell.println(" OK");
        shell.print("  Rescanning partitions...");
        storage.rescanPartitions();
        shell.println(" OK");

        shell.println("");
        shell.printSuccessLine("Format complete!");
        shell.println("");

        // Show result
        const count = storage.getPartitionCount();
        if (count > 0) {
            shell.print("  Created ");
            helpers.printUsize(count);
            shell.println(" partition(s)");

            if (storage.getPartition(0)) |p| {
                shell.print("  [0] ");
                shell.print(p.getTypeName());
                shell.print(" - ");
                helpers.printUsize(p.size_mb);
                shell.println(" MB");
            }
        }
    } else {
        shell.println(" FAILED");
        shell.println("");
        shell.printErrorLine("Format failed!");
        shell.println("  Check drive connection and try again");
    }

    shell.println("");
}

fn readSector(args: []const u8) void {
    const lba = helpers.parseU32(args) orelse 0;

    shell.println("");
    shell.print("  Reading sector ");
    helpers.printUsize(lba);
    shell.println("...");
    shell.println("");

    var buffer: [512]u8 = [_]u8{0} ** 512;

    if (storage.readSector(0, lba, &buffer)) {
        shell.println("  Hex dump (first 128 bytes):");
        shell.println("");

        var i: usize = 0;
        while (i < 128) : (i += 1) {
            if (i % 16 == 0) {
                shell.print("  ");
                printHex16(@intCast(i));
                shell.print(": ");
            }
            helpers.printHexByte(buffer[i]);
            shell.print(" ");
            if ((i + 1) % 16 == 0) {
                // Print ASCII
                shell.print(" |");
                var j: usize = i - 15;
                while (j <= i) : (j += 1) {
                    const c = buffer[j];
                    if (c >= 0x20 and c < 0x7F) {
                        shell.printChar(c);
                    } else {
                        shell.printChar('.');
                    }
                }
                shell.println("|");
            }
        }

        // Check for MBR signature
        if (lba == 0) {
            shell.println("");
            if (buffer[510] == 0x55 and buffer[511] == 0xAA) {
                shell.printSuccessLine("  Valid MBR signature (55 AA)");
            } else {
                shell.println("  No MBR signature (disk unformatted)");
            }
        }
    } else |_| {
        shell.printErrorLine("  Read failed!");
    }

    shell.println("");
}

fn runTest() void {
    shell.println("");
    shell.printInfoLine("========================================");
    shell.printInfoLine("  STORAGE TEST SUITE (Step 1-4)");
    shell.printInfoLine("========================================");
    shell.println("");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: ATA Driver
    shell.println("[1/5] ATA Driver");
    passed += helpers.doTest("Drive detection", storage.getDriveCount() > 0, &failed);

    // Test 2: MBR
    shell.println("");
    shell.println("[2/5] MBR Partition Table");
    passed += helpers.doTest("Partition found", storage.getPartitionCount() > 0, &failed);
    passed += helpers.doTest("FAT32 partition", storage.findFAT32Partition() != null, &failed);

    // Test 3: FAT32 Basic
    shell.println("");
    shell.println("[3/5] FAT32 Filesystem");
    const fat32_mod = @import("../../fs/fat32.zig");
    passed += helpers.doTest("FAT32 mounted", fat32_mod.isMounted(), &failed);

    if (fat32_mod.isMounted()) {
        // Write test
        const test_data = "Step4 integration test OK";
        const write_ok = fat32_mod.createFile("STEP4.TXT", test_data);
        passed += helpers.doTest("Create file", write_ok, &failed);

        // Read test - use file size to limit read
        if (fat32_mod.findInRoot("STEP4.TXT")) |file| {
            var buf: [256]u8 = [_]u8{0} ** 256;
            const file_size: usize = @intCast(file.size);
            const bytes = fat32_mod.readFile(file.cluster, buf[0..file_size]);
            const read_ok = (bytes == test_data.len);
            passed += helpers.doTest("Read file", read_ok, &failed);

            // Verify content
            var match = true;
            if (bytes >= test_data.len) {
                for (test_data, 0..) |c, i| {
                    if (buf[i] != c) {
                        match = false;
                        break;
                    }
                }
            } else {
                match = false;
            }
            passed += helpers.doTest("Verify content", match, &failed);
        } else {
            passed += helpers.doTest("Read file", false, &failed);
            passed += helpers.doTest("Verify content", false, &failed);
        }

        // Delete test
        const del_ok = fat32_mod.deleteFile("STEP4.TXT");
        passed += helpers.doTest("Delete file", del_ok, &failed);
        passed += helpers.doTest("Verify deleted", fat32_mod.findInRoot("STEP4.TXT") == null, &failed);
    } else {
        helpers.doSkip("Create file");
        helpers.doSkip("Read file");
        helpers.doSkip("Verify content");
        helpers.doSkip("Delete file");
        helpers.doSkip("Verify deleted");
    }

    // Test 4: VFS Integration
    shell.println("");
    shell.println("[4/5] VFS Integration");
    const vfs = @import("../../fs/vfs.zig");

    // Check /disk mount point
    const disk_exists = vfs.resolvePath("/disk") != null;
    passed += helpers.doTest("Mount /disk", disk_exists, &failed);

    if (fat32_mod.isMounted() and disk_exists) {
        // Create a file via FAT32 and read via VFS
        _ = fat32_mod.createFile("VFSTEST.TXT", "VFS works!");

        // Check via VFS readdir
        const dir_entry = vfs.readdir("/disk", 0);
        passed += helpers.doTest("VFS readdir", dir_entry != null, &failed);

        // Check via VFS lookup
        const lookup = vfs.resolvePath("/disk/VFSTEST.TXT");
        passed += helpers.doTest("VFS lookup", lookup != null, &failed);

        // Cleanup
        _ = fat32_mod.deleteFile("VFSTEST.TXT");
    } else {
        helpers.doSkip("VFS readdir");
        helpers.doSkip("VFS lookup");
    }

    // Test 5: Shell Integration
    shell.println("");
    shell.println("[5/5] Shell Integration");
    passed += helpers.doTest("ls /disk ready", fat32_mod.isMounted(), &failed);
    passed += helpers.doTest("cat /disk ready", fat32_mod.isMounted(), &failed);
    passed += helpers.doTest("write /disk ready", fat32_mod.isMounted(), &failed);

    // Summary
    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Helper Functions
// =============================================================================

fn padSpaces(count: usize) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        shell.printChar(' ');
    }
}

fn countDigits(n: anytype) usize {
    if (n == 0) return 1;
    var count: usize = 0;
    var v = n;
    while (v > 0) : (count += 1) {
        v /= 10;
    }
    return count;
}

fn printU64(val: u64) void {
    if (val == 0) {
        shell.printChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        shell.printChar(buf[i]);
    }
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    shell.printChar(hex[(val >> 12) & 0xF]);
    shell.printChar(hex[(val >> 8) & 0xF]);
    shell.printChar(hex[(val >> 4) & 0xF]);
    shell.printChar(hex[val & 0xF]);
}
