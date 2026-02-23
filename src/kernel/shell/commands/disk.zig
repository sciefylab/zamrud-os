//! Zamrud OS - Disk Commands
//! B2.2: FAT32 write tests
//! B2.3: Rename, copy, truncate tests
//! B2.4: AHCI driver tests
//!
//! Production test suite — all tests are:
//!   ✓ Idempotent (can run repeatedly without side effects)
//!   ✓ Non-destructive (no raw sector writes to critical areas)
//!   ✓ Self-cleaning (temp files deleted after each group)
//!   ✓ Bounds-checked (no buffer overflows)

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const storage = @import("../../drivers/storage/storage.zig");
const mbr = @import("../../drivers/storage/mbr.zig");
const ahci = @import("../../drivers/storage/ahci.zig");

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
    } else if (helpers.strEql(parsed.cmd, "backend")) {
        showBackend();
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
    shell.println("  disk backend        - Show storage backend info");
    shell.println("  disk test           - Run disk tests (B2.2-B2.4)");
    shell.println("");
}

// =============================================================================
// B2.4: Backend Info Command
// =============================================================================

fn showBackend() void {
    shell.println("");
    shell.printInfoLine("=== STORAGE BACKEND ===");
    shell.println("");

    shell.print("  Active: ");
    shell.println(storage.getBackendName());

    shell.print("  Drives: ");
    helpers.printUsize(storage.getDriveCount());
    shell.newLine();

    if (ahci.isDetected()) {
        shell.println("");
        shell.printInfoLine("  AHCI Controller:");
        shell.print("    Status:      ");
        shell.println(if (ahci.isInitialized()) "Initialized" else "Detected but not initialized");
        shell.print("    IRQ:         ");
        helpers.printUsize(ahci.getIrq());
        shell.newLine();
        shell.print("    SATA Drives: ");
        helpers.printUsize(ahci.getDriveCount());
        shell.newLine();

        var i: usize = 0;
        while (i < ahci.getDriveCount()) : (i += 1) {
            shell.print("    [");
            helpers.printUsize(i);
            shell.print("] ");
            shell.print(ahci.getDriveModel(i));
            shell.print(" - ");
            helpers.printUsize(ahci.getDriveSizeMB(i));
            shell.print(" MB");
            if (ahci.getDriveLba48(i)) {
                shell.print(" (LBA48)");
            }
            shell.newLine();
        }
    } else {
        shell.println("");
        shell.println("  AHCI: Not detected (using ATA PIO fallback)");
    }

    shell.println("");
}

// =============================================================================
// Drive Listing
// =============================================================================

fn listDrives() void {
    const count = storage.getDriveCount();

    shell.println("");
    shell.printInfoLine("=== DETECTED DRIVES ===");

    shell.print("  Backend: ");
    shell.println(storage.getBackendName());
    shell.println("");

    if (count == 0) {
        shell.println("  No drives detected");
        shell.println("");
        return;
    }

    if (storage.getBackend() == .ahci_dma) {
        var i: usize = 0;
        while (i < ahci.getDriveCount()) : (i += 1) {
            shell.print("  [");
            helpers.printUsize(i);
            shell.print("] ");
            shell.print(ahci.getDriveModel(i));
            shell.print(" - ");
            helpers.printUsize(ahci.getDriveSizeMB(i));
            shell.print(" MB");
            if (ahci.getDriveLba48(i)) {
                shell.print(" (LBA48, AHCI/DMA)");
            } else {
                shell.print(" (AHCI/DMA)");
            }
            shell.newLine();
        }
    } else {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (storage.getDrive(i)) |drv| {
                shell.print("  [");
                helpers.printUsize(i);
                shell.print("] ");

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
                    shell.print(" (LBA48, ATA/PIO)");
                } else {
                    shell.print(" (ATA/PIO)");
                }

                shell.newLine();
            }
        }
    }
    shell.println("");
}

// =============================================================================
// Drive Info
// =============================================================================

fn showInfo(args: []const u8) void {
    const drive_idx = helpers.parseU32(args) orelse 0;

    shell.println("");
    shell.printInfoLine("=== DRIVE INFO ===");
    shell.println("");

    shell.print("  Backend:   ");
    shell.println(storage.getBackendName());

    if (storage.getBackend() == .ahci_dma and drive_idx < ahci.getDriveCount()) {
        shell.print("  Drive:     ");
        helpers.printUsize(drive_idx);
        shell.newLine();

        shell.print("  Model:     ");
        shell.println(ahci.getDriveModel(drive_idx));

        shell.print("  Size:      ");
        helpers.printUsize(ahci.getDriveSizeMB(drive_idx));
        shell.println(" MB");

        shell.print("  Sectors:   ");
        printU64(ahci.getDriveSectors(drive_idx));
        shell.newLine();

        shell.print("  LBA48:     ");
        shell.println(if (ahci.getDriveLba48(drive_idx)) "Yes" else "No");

        shell.print("  Interface: AHCI/SATA (DMA)\n");
        shell.print("  IRQ:       ");
        helpers.printUsize(ahci.getIrq());
        shell.newLine();
    } else if (storage.getDrive(drive_idx)) |drv| {
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
        shell.println(if (drv.lba48) "Yes" else "No");

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

        shell.print("  Interface: ATA PIO\n");
    } else {
        shell.print("  Drive ");
        helpers.printUsize(drive_idx);
        shell.println(" not found");
    }
    shell.println("");
}

// =============================================================================
// Partition Listing
// =============================================================================

fn listPartitions() void {
    shell.println("");
    shell.printInfoLine("=== PARTITION TABLE ===");
    shell.print("  Backend: ");
    shell.println(storage.getBackendName());
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

    shell.println("  #  Type          Size      Start LBA   Flags");
    shell.println("  ─────────────────────────────────────────────");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (storage.getPartition(i)) |p| {
            shell.print("  ");
            helpers.printUsize(i);
            shell.print("  ");

            const type_name = p.getTypeName();
            shell.print(type_name);
            padSpaces(14 - type_name.len);

            helpers.printUsize(p.size_mb);
            shell.print(" MB");
            padSpaces(6 - countDigits(p.size_mb));

            helpers.printUsize(p.start_lba);
            padSpaces(12 - countDigits(p.start_lba));

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

    if (storage.findFAT32Partition()) |fat32| {
        shell.print("  FAT32 partition at LBA ");
        helpers.printUsize(fat32.start_lba);
        shell.println(" (ready for use)");
        shell.println("");
    }
}

// =============================================================================
// Format Disk
// =============================================================================

fn formatDisk(args: []const u8) void {
    shell.println("");

    if (storage.getDriveCount() == 0) {
        shell.printErrorLine("No drives detected!");
        shell.println("");
        return;
    }

    const confirmed = helpers.strEql(args, "confirm") or
        helpers.strEql(args, "--confirm") or
        helpers.strEql(args, "-y");

    if (!confirmed) {
        shell.println("  ┌────────────────────────────────────────┐");
        shell.println("  │  WARNING: FORMAT DISK                  │");
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

    shell.println("  ┌────────────────────────────────────────┐");
    shell.println("  │  FORMATTING DISK                       │");
    shell.println("  └────────────────────────────────────────┘");
    shell.println("");

    shell.print("  Backend: ");
    shell.println(storage.getBackendName());

    if (storage.getBackend() == .ahci_dma and ahci.getDriveCount() > 0) {
        shell.print("  Drive: ");
        shell.println(ahci.getDriveModel(0));
        shell.print("  Size:  ");
        helpers.printUsize(ahci.getDriveSizeMB(0));
        shell.println(" MB");
    } else if (storage.getDrive(0)) |drv| {
        shell.print("  Drive: ");
        for (drv.model) |c| {
            if (c == 0) break;
            shell.printChar(c);
        }
        shell.newLine();
        shell.print("  Size:  ");
        helpers.printUsize(drv.size_mb);
        shell.println(" MB");
    }
    shell.println("  Type:  FAT32 LBA");
    shell.println("");

    shell.print("  Creating MBR partition table...");

    if (storage.formatDriveFAT32(0, storage.CONFIRM_FORMAT)) {
        shell.println(" OK");
        shell.print("  Rescanning partitions...");
        storage.rescanPartitions();
        shell.println(" OK");

        shell.println("");
        shell.printSuccessLine("Format complete!");
        shell.println("");

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

// =============================================================================
// Read Sector (hex dump)
// =============================================================================

fn readSector(args: []const u8) void {
    const lba = helpers.parseU32(args) orelse 0;

    shell.println("");
    shell.print("  Reading sector ");
    helpers.printUsize(lba);
    shell.print(" via ");
    shell.print(storage.getBackendName());
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

// =============================================================================
// Production Test Suite (B2.2 + B2.3 + B2.4)
//
// Design principles:
//   1. Idempotent — safe to run any number of times
//   2. Non-destructive — never writes raw sectors to filesystem metadata
//   3. Self-cleaning — all temp files removed after each group
//   4. Bounds-checked — all buffers clamped via @min
//   5. Leak-verified — final test confirms no temp files remain
// =============================================================================

fn runTest() void {
    shell.println("");
    shell.printInfoLine("========================================");
    shell.printInfoLine("  STORAGE TEST SUITE (B2.2-B2.4)");
    shell.printInfoLine("========================================");
    shell.println("");

    var passed: u32 = 0;
    var failed: u32 = 0;

    const fat32_mod = @import("../../fs/fat32.zig");
    const vfs = @import("../../fs/vfs.zig");

    // Pre-cleanup: remove ALL possible leftover files from previous runs
    if (fat32_mod.isMounted()) {
        cleanupAllTestFiles(fat32_mod);
    }

    // =========================================================================
    // [1/11] B2.4 — Backend Detection
    // =========================================================================
    shell.println("[1/11] B2.4 Storage Backend");
    shell.print("  Backend: ");
    shell.println(storage.getBackendName());
    passed += helpers.doTest("Backend active", storage.getBackend() != .none, &failed);
    passed += helpers.doTest("Drive count > 0", storage.getDriveCount() > 0, &failed);

    // =========================================================================
    // [2/11] B2.4 — AHCI Controller
    // =========================================================================
    shell.println("");
    shell.println("[2/11] B2.4 AHCI Controller");
    if (ahci.isDetected()) {
        passed += helpers.doTest("AHCI detected", true, &failed);
        passed += helpers.doTest("AHCI initialized", ahci.isInitialized(), &failed);

        if (ahci.isInitialized()) {
            passed += helpers.doTest("AHCI drives > 0", ahci.getDriveCount() > 0, &failed);

            if (ahci.getDriveCount() > 0) {
                shell.print("  Model: ");
                shell.println(ahci.getDriveModel(0));
                shell.print("  Size:  ");
                helpers.printUsize(ahci.getDriveSizeMB(0));
                shell.println(" MB");

                passed += helpers.doTest("Drive size > 0", ahci.getDriveSizeMB(0) > 0, &failed);
                passed += helpers.doTest("Drive sectors > 0", ahci.getDriveSectors(0) > 0, &failed);
            }
        } else {
            helpers.doSkip("AHCI drives > 0");
            helpers.doSkip("Drive size > 0");
            helpers.doSkip("Drive sectors > 0");
        }
    } else {
        shell.println("  AHCI not detected — using ATA PIO fallback");
        passed += helpers.doTest("ATA fallback active", storage.getBackend() == .ata_pio, &failed);
        helpers.doSkip("AHCI initialized");
        helpers.doSkip("AHCI drives > 0");
        helpers.doSkip("Drive size > 0");
        helpers.doSkip("Drive sectors > 0");
    }

    // =========================================================================
    // [3/11] B2.4 — Sector I/O (read-only MBR + safe write via FAT32 file)
    // =========================================================================
    shell.println("");
    shell.print("[3/11] B2.4 Sector I/O (via ");
    shell.print(storage.getBackendName());
    shell.println(")");

    if (storage.getDriveCount() > 0) {
        // Read sector 0 (MBR) — purely non-destructive
        var buf: [512]u8 = [_]u8{0} ** 512;
        if (storage.readSector(0, 0, &buf)) {
            passed += helpers.doTest("Read sector 0", true, &failed);
            passed += helpers.doTest("MBR signature", buf[510] == 0x55 and buf[511] == 0xAA, &failed);
        } else |_| {
            passed += helpers.doTest("Read sector 0", false, &failed);
            passed += helpers.doTest("MBR signature", false, &failed);
        }

        // Write/Read roundtrip via FAT32 temp file (safe — no raw sector writes)
        // Old code wrote to backup boot sector (LBA+6) which risked corruption
        var roundtrip_ok = false;
        if (fat32_mod.isMounted()) {
            const wr_data = "AHCI_DMA_ROUNDTRIP_VERIFY_OK";
            _ = fat32_mod.deleteFile("_IOTEST.TMP"); // Pre-cleanup
            if (fat32_mod.createFile("_IOTEST.TMP", wr_data)) {
                if (fat32_mod.findInRoot("_IOTEST.TMP")) |f| {
                    var wr_buf: [64]u8 = [_]u8{0} ** 64;
                    const wr_sz: usize = @min(@as(usize, @intCast(f.size)), wr_buf.len);
                    const bytes = fat32_mod.readFile(f.cluster, wr_buf[0..wr_sz]);
                    if (bytes == wr_data.len) {
                        roundtrip_ok = true;
                        for (wr_data, 0..) |c, i| {
                            if (wr_buf[i] != c) {
                                roundtrip_ok = false;
                                break;
                            }
                        }
                    }
                }
                _ = fat32_mod.deleteFile("_IOTEST.TMP");
            }
        }
        passed += helpers.doTest("Write/Read roundtrip", roundtrip_ok, &failed);
    } else {
        helpers.doSkip("Read sector 0");
        helpers.doSkip("MBR signature");
        helpers.doSkip("Write/Read roundtrip");
    }

    // =========================================================================
    // [4/11] MBR Partition Table
    // =========================================================================
    shell.println("");
    shell.println("[4/11] MBR Partition Table");
    passed += helpers.doTest("Partition found", storage.getPartitionCount() > 0, &failed);
    passed += helpers.doTest("FAT32 partition", storage.findFAT32Partition() != null, &failed);

    // =========================================================================
    // [5/11] FAT32 Basic Read/Write
    // =========================================================================
    shell.println("");
    shell.println("[5/11] FAT32 Filesystem");
    passed += helpers.doTest("FAT32 mounted", fat32_mod.isMounted(), &failed);

    if (fat32_mod.isMounted()) {
        const test_data = "B2.4 AHCI integration test OK";

        // Pre-cleanup
        _ = fat32_mod.deleteFile("B24TEST.TXT");

        const write_ok = fat32_mod.createFile("B24TEST.TXT", test_data);
        passed += helpers.doTest("Create file", write_ok, &failed);

        if (fat32_mod.findInRoot("B24TEST.TXT")) |file| {
            var fbuf: [256]u8 = [_]u8{0} ** 256;
            // Bounds-checked: clamp file_size to buffer length
            const file_size: usize = @min(@as(usize, @intCast(file.size)), fbuf.len);
            const bytes = fat32_mod.readFile(file.cluster, fbuf[0..file_size]);
            const read_ok = (bytes == test_data.len);
            passed += helpers.doTest("Read file", read_ok, &failed);

            var match = true;
            if (bytes >= test_data.len) {
                for (test_data, 0..) |c, i| {
                    if (fbuf[i] != c) {
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

        const del_ok = fat32_mod.deleteFile("B24TEST.TXT");
        passed += helpers.doTest("Delete file", del_ok, &failed);
        passed += helpers.doTest("Verify deleted", fat32_mod.findInRoot("B24TEST.TXT") == null, &failed);
    } else {
        helpers.doSkip("Create file");
        helpers.doSkip("Read file");
        helpers.doSkip("Verify content");
        helpers.doSkip("Delete file");
        helpers.doSkip("Verify deleted");
    }

    // =========================================================================
    // [6/11] VFS Integration
    // =========================================================================
    shell.println("");
    shell.println("[6/11] VFS Integration");

    const disk_exists = vfs.resolvePath("/disk") != null;
    passed += helpers.doTest("Mount /disk", disk_exists, &failed);

    if (fat32_mod.isMounted() and disk_exists) {
        _ = fat32_mod.deleteFile("VFSTEST.TXT");
        _ = fat32_mod.createFile("VFSTEST.TXT", "VFS works!");

        const dir_entry = vfs.readdir("/disk", 0);
        passed += helpers.doTest("VFS readdir", dir_entry != null, &failed);

        const lookup = vfs.resolvePath("/disk/VFSTEST.TXT");
        passed += helpers.doTest("VFS lookup", lookup != null, &failed);

        _ = fat32_mod.deleteFile("VFSTEST.TXT");
    } else {
        helpers.doSkip("VFS readdir");
        helpers.doSkip("VFS lookup");
    }

    // =========================================================================
    // [7/11] B2.3 — Rename
    // =========================================================================
    shell.println("");
    shell.println("[7/11] B2.3 Rename");

    if (fat32_mod.isMounted()) {
        // Pre-cleanup
        _ = fat32_mod.deleteFile("RNTEST.TXT");
        _ = fat32_mod.deleteFile("RENAMED.TXT");
        _ = fat32_mod.deleteFile("EXIST.TXT");

        const rn_create = fat32_mod.createFile("RNTEST.TXT", "rename test data");
        passed += helpers.doTest("Create source", rn_create, &failed);

        const rn_ok = fat32_mod.renameFile("RNTEST.TXT", "RENAMED.TXT");
        passed += helpers.doTest("Rename file", rn_ok, &failed);

        passed += helpers.doTest("Old name gone", fat32_mod.findInRoot("RNTEST.TXT") == null, &failed);
        passed += helpers.doTest("New name exists", fat32_mod.findInRoot("RENAMED.TXT") != null, &failed);

        // Verify content preserved after rename
        if (fat32_mod.findInRoot("RENAMED.TXT")) |file| {
            var rbuf: [64]u8 = [_]u8{0} ** 64;
            const rsize: usize = @min(@as(usize, @intCast(file.size)), rbuf.len);
            const rbytes = fat32_mod.readFile(file.cluster, rbuf[0..rsize]);
            const expected = "rename test data";
            var content_ok = (rbytes == expected.len);
            if (content_ok) {
                for (expected, 0..) |c, i| {
                    if (rbuf[i] != c) {
                        content_ok = false;
                        break;
                    }
                }
            }
            passed += helpers.doTest("Content preserved", content_ok, &failed);
        } else {
            passed += helpers.doTest("Content preserved", false, &failed);
        }

        // Rename to existing name should fail
        _ = fat32_mod.createFile("EXIST.TXT", "x");
        const rn_dup = fat32_mod.renameFile("RENAMED.TXT", "EXIST.TXT");
        passed += helpers.doTest("Rename dup fails", !rn_dup, &failed);

        // Rename to self should succeed (no-op)
        const rn_self = fat32_mod.renameFile("RENAMED.TXT", "RENAMED.TXT");
        passed += helpers.doTest("Rename self = no-op", rn_self, &failed);

        // Rename nonexistent should fail
        const rn_ghost = fat32_mod.renameFile("GHOST.TXT", "OUT.TXT");
        passed += helpers.doTest("Rename nonexist fails", !rn_ghost, &failed);

        // Cleanup
        _ = fat32_mod.deleteFile("RENAMED.TXT");
        _ = fat32_mod.deleteFile("EXIST.TXT");
    } else {
        helpers.doSkip("Create source");
        helpers.doSkip("Rename file");
        helpers.doSkip("Old name gone");
        helpers.doSkip("New name exists");
        helpers.doSkip("Content preserved");
        helpers.doSkip("Rename dup fails");
        helpers.doSkip("Rename self = no-op");
        helpers.doSkip("Rename nonexist fails");
    }

    // =========================================================================
    // [8/11] B2.3 — Copy
    // =========================================================================
    shell.println("");
    shell.println("[8/11] B2.3 Copy");

    if (fat32_mod.isMounted()) {
        // Pre-cleanup
        _ = fat32_mod.deleteFile("CPSRC.TXT");
        _ = fat32_mod.deleteFile("CPDST.TXT");

        const cp_data = "copy test content 123";
        const cp_create = fat32_mod.createFile("CPSRC.TXT", cp_data);
        passed += helpers.doTest("Create source", cp_create, &failed);

        const cp_ok = fat32_mod.copyFile("CPSRC.TXT", "CPDST.TXT");
        passed += helpers.doTest("Copy file", cp_ok, &failed);

        passed += helpers.doTest("Source intact", fat32_mod.findInRoot("CPSRC.TXT") != null, &failed);
        passed += helpers.doTest("Dest exists", fat32_mod.findInRoot("CPDST.TXT") != null, &failed);

        // Verify copied content matches
        if (fat32_mod.findInRoot("CPDST.TXT")) |file| {
            var cbuf: [64]u8 = [_]u8{0} ** 64;
            const csize: usize = @min(@as(usize, @intCast(file.size)), cbuf.len);
            const cbytes = fat32_mod.readFile(file.cluster, cbuf[0..csize]);
            var cp_match = (cbytes == cp_data.len);
            if (cp_match) {
                for (cp_data, 0..) |c, i| {
                    if (cbuf[i] != c) {
                        cp_match = false;
                        break;
                    }
                }
            }
            passed += helpers.doTest("Dest content OK", cp_match, &failed);
        } else {
            passed += helpers.doTest("Dest content OK", false, &failed);
        }

        // Copy to existing should fail
        const cp_dup = fat32_mod.copyFile("CPSRC.TXT", "CPDST.TXT");
        passed += helpers.doTest("Copy dup fails", !cp_dup, &failed);

        // Copy nonexistent should fail
        const cp_ghost = fat32_mod.copyFile("GHOST.TXT", "OUT.TXT");
        passed += helpers.doTest("Copy nonexist fails", !cp_ghost, &failed);

        // Cleanup
        _ = fat32_mod.deleteFile("CPSRC.TXT");
        _ = fat32_mod.deleteFile("CPDST.TXT");
    } else {
        helpers.doSkip("Create source");
        helpers.doSkip("Copy file");
        helpers.doSkip("Source intact");
        helpers.doSkip("Dest exists");
        helpers.doSkip("Dest content OK");
        helpers.doSkip("Copy dup fails");
        helpers.doSkip("Copy nonexist fails");
    }

    // =========================================================================
    // [9/11] B2.3 — Truncate
    // =========================================================================
    shell.println("");
    shell.println("[9/11] B2.3 Truncate");

    if (fat32_mod.isMounted()) {
        // Pre-cleanup
        _ = fat32_mod.deleteFile("TRUNC.TXT");

        const tr_data = "abcdefghijklmnopqrstuvwxyz";
        const tr_create = fat32_mod.createFile("TRUNC.TXT", tr_data);
        passed += helpers.doTest("Create 26-byte file", tr_create, &failed);

        // Verify initial size
        if (fat32_mod.findInRoot("TRUNC.TXT")) |f| {
            passed += helpers.doTest("Initial size=26", f.size == 26, &failed);
        } else {
            passed += helpers.doTest("Initial size=26", false, &failed);
        }

        // Shrink to 10
        const tr_shrink = fat32_mod.truncateFile("TRUNC.TXT", 10);
        passed += helpers.doTest("Truncate to 10", tr_shrink, &failed);

        if (fat32_mod.findInRoot("TRUNC.TXT")) |f| {
            passed += helpers.doTest("Size now 10", f.size == 10, &failed);

            // Verify first 10 bytes preserved
            var tbuf: [32]u8 = [_]u8{0} ** 32;
            const tbytes = fat32_mod.readFile(f.cluster, tbuf[0..10]);
            var tr_match = (tbytes == 10);
            if (tr_match) {
                const expected_10 = "abcdefghij";
                for (expected_10, 0..) |c, i| {
                    if (tbuf[i] != c) {
                        tr_match = false;
                        break;
                    }
                }
            }
            passed += helpers.doTest("Content preserved", tr_match, &failed);
        } else {
            passed += helpers.doTest("Size now 10", false, &failed);
            passed += helpers.doTest("Content preserved", false, &failed);
        }

        // Truncate to 0
        const tr_zero = fat32_mod.truncateFile("TRUNC.TXT", 0);
        passed += helpers.doTest("Truncate to 0", tr_zero, &failed);

        if (fat32_mod.findInRoot("TRUNC.TXT")) |f| {
            passed += helpers.doTest("Size now 0", f.size == 0, &failed);
        } else {
            passed += helpers.doTest("Size now 0", false, &failed);
        }

        // Extend to 100
        const tr_grow = fat32_mod.truncateFile("TRUNC.TXT", 100);
        passed += helpers.doTest("Truncate extend 100", tr_grow, &failed);

        if (fat32_mod.findInRoot("TRUNC.TXT")) |f| {
            passed += helpers.doTest("Size now 100", f.size == 100, &failed);
        } else {
            passed += helpers.doTest("Size now 100", false, &failed);
        }

        // Same size = no-op (should succeed)
        const tr_same = fat32_mod.truncateFile("TRUNC.TXT", 100);
        passed += helpers.doTest("Truncate same size", tr_same, &failed);

        // Truncate nonexistent should fail
        const tr_ghost = fat32_mod.truncateFile("GHOST.TXT", 10);
        passed += helpers.doTest("Truncate nonexist", !tr_ghost, &failed);

        // Truncate directory should fail
        _ = fat32_mod.deleteDirectory("TRDIR");
        _ = fat32_mod.createDirectory("TRDIR");
        const tr_dir = fat32_mod.truncateFile("TRDIR", 0);
        passed += helpers.doTest("Truncate dir fails", !tr_dir, &failed);
        _ = fat32_mod.deleteDirectory("TRDIR");

        // Cleanup
        _ = fat32_mod.deleteFile("TRUNC.TXT");
    } else {
        helpers.doSkip("Create 26-byte file");
        helpers.doSkip("Initial size=26");
        helpers.doSkip("Truncate to 10");
        helpers.doSkip("Size now 10");
        helpers.doSkip("Content preserved");
        helpers.doSkip("Truncate to 0");
        helpers.doSkip("Size now 0");
        helpers.doSkip("Truncate extend 100");
        helpers.doSkip("Size now 100");
        helpers.doSkip("Truncate same size");
        helpers.doSkip("Truncate nonexist");
        helpers.doSkip("Truncate dir fails");
    }

    // =========================================================================
    // [10/11] Directory Operations
    // =========================================================================
    shell.println("");
    shell.println("[10/11] Directory Operations");

    if (fat32_mod.isMounted()) {
        // Pre-cleanup
        _ = fat32_mod.deleteDirectory("TESTDIR");
        _ = fat32_mod.deleteDirectory("TESTDIR2");

        // Create directory
        const mkdir_ok = fat32_mod.createDirectory("TESTDIR");
        passed += helpers.doTest("Create directory", mkdir_ok, &failed);

        // Verify it's a directory
        if (fat32_mod.findInRoot("TESTDIR")) |d| {
            passed += helpers.doTest("Dir is directory", d.is_dir, &failed);
        } else {
            passed += helpers.doTest("Dir is directory", false, &failed);
        }

        // Empty dir should be deletable
        const rmdir_ok = fat32_mod.deleteDirectory("TESTDIR");
        passed += helpers.doTest("Delete empty dir", rmdir_ok, &failed);
        passed += helpers.doTest("Dir gone", fat32_mod.findInRoot("TESTDIR") == null, &failed);

        // Create duplicate should fail
        _ = fat32_mod.createDirectory("TESTDIR2");
        const dup_dir = fat32_mod.createDirectory("TESTDIR2");
        passed += helpers.doTest("Mkdir dup fails", !dup_dir, &failed);

        // Cleanup
        _ = fat32_mod.deleteDirectory("TESTDIR2");
    } else {
        helpers.doSkip("Create directory");
        helpers.doSkip("Dir is directory");
        helpers.doSkip("Delete empty dir");
        helpers.doSkip("Dir gone");
        helpers.doSkip("Mkdir dup fails");
    }

    // =========================================================================
    // [11/11] Backend Consistency & Leak Verification
    // =========================================================================
    shell.println("");
    shell.println("[11/11] Backend Consistency");

    // Verify no test files leaked on disk
    if (fat32_mod.isMounted()) {
        passed += helpers.doTest("No leaked B24TEST", fat32_mod.findInRoot("B24TEST.TXT") == null, &failed);
        passed += helpers.doTest("No leaked VFSTEST", fat32_mod.findInRoot("VFSTEST.TXT") == null, &failed);
        passed += helpers.doTest("No leaked RNTEST", fat32_mod.findInRoot("RNTEST.TXT") == null, &failed);
        passed += helpers.doTest("No leaked RENAMED", fat32_mod.findInRoot("RENAMED.TXT") == null, &failed);
        passed += helpers.doTest("No leaked CPSRC", fat32_mod.findInRoot("CPSRC.TXT") == null, &failed);
        passed += helpers.doTest("No leaked CPDST", fat32_mod.findInRoot("CPDST.TXT") == null, &failed);
        passed += helpers.doTest("No leaked TRUNC", fat32_mod.findInRoot("TRUNC.TXT") == null, &failed);
        passed += helpers.doTest("No leaked _IOTEST", fat32_mod.findInRoot("_IOTEST.TMP") == null, &failed);
    } else {
        helpers.doSkip("No leaked B24TEST");
        helpers.doSkip("No leaked VFSTEST");
        helpers.doSkip("No leaked RNTEST");
        helpers.doSkip("No leaked RENAMED");
        helpers.doSkip("No leaked CPSRC");
        helpers.doSkip("No leaked CPDST");
        helpers.doSkip("No leaked TRUNC");
        helpers.doSkip("No leaked _IOTEST");
    }

    // Backend consistency check
    if (storage.getBackend() == .ahci_dma) {
        passed += helpers.doTest("AHCI consistent", ahci.isInitialized(), &failed);
    } else if (storage.getBackend() == .ata_pio) {
        passed += helpers.doTest("ATA consistent", storage.getDriveCount() > 0, &failed);
    } else {
        passed += helpers.doTest("Backend consistent", false, &failed);
    }

    // FAT32 still alive after all tests
    passed += helpers.doTest("FAT32 still mounted", fat32_mod.isMounted(), &failed);

    // =========================================================================
    // Summary
    // =========================================================================
    shell.println("");
    shell.print("  Backend: ");
    shell.println(storage.getBackendName());
    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Pre-cleanup: remove ALL possible test files for idempotency
// =============================================================================

fn cleanupAllTestFiles(fat32_mod: anytype) void {
    _ = fat32_mod.deleteFile("B24TEST.TXT");
    _ = fat32_mod.deleteFile("VFSTEST.TXT");
    _ = fat32_mod.deleteFile("RNTEST.TXT");
    _ = fat32_mod.deleteFile("RENAMED.TXT");
    _ = fat32_mod.deleteFile("EXIST.TXT");
    _ = fat32_mod.deleteFile("CPSRC.TXT");
    _ = fat32_mod.deleteFile("CPDST.TXT");
    _ = fat32_mod.deleteFile("TRUNC.TXT");
    _ = fat32_mod.deleteFile("_IOTEST.TMP");
    _ = fat32_mod.deleteFile("OUT.TXT");
    _ = fat32_mod.deleteDirectory("TRDIR");
    _ = fat32_mod.deleteDirectory("TESTDIR");
    _ = fat32_mod.deleteDirectory("TESTDIR2");
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

    var buf_local: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf_local[i] = @intCast((v % 10) + '0');
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        shell.printChar(buf_local[i]);
    }
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    shell.printChar(hex[(val >> 12) & 0xF]);
    shell.printChar(hex[(val >> 8) & 0xF]);
    shell.printChar(hex[(val >> 4) & 0xF]);
    shell.printChar(hex[val & 0xF]);
}
