//! Zamrud OS - Storage Subsystem
//! Unified storage interface with partition support

pub const ata = @import("ata.zig");
pub const mbr = @import("mbr.zig");
const fat32 = @import("../../fs/fat32.zig");

const serial = @import("../serial/serial.zig");

pub const SECTOR_SIZE = ata.SECTOR_SIZE;
pub const Drive = ata.Drive;
pub const AtaError = ata.AtaError;
pub const Partition = mbr.Partition;
pub const FormatType = mbr.FormatType;
pub const FormatOptions = mbr.FormatOptions;
pub const FormatError = mbr.FormatError;
pub const CONFIRM_FORMAT = mbr.CONFIRM_FORMAT;

// Configuration
pub const Config = struct {
    auto_format_empty: bool = true,
    default_format: FormatType = .FAT32,
};

pub var config = Config{};

var initialized: bool = false;

pub fn init() void {
    serial.writeString("[STORAGE] Initializing storage subsystem...\n");

    // Initialize ATA driver
    ata.init();

    const drive_count = ata.getDriveCount();

    if (drive_count > 0) {
        // Wait for disk to be ready before reading
        ataWarmup(0);

        // Scan for existing partitions
        mbr.init();

        // Auto-format ONLY if disk is truly empty (verified with retry)
        if (config.auto_format_empty and mbr.getPartitionCount() == 0) {
            if (isDiskTrulyEmpty(0)) {
                autoFormatEmptyDisks();
            } else {
                serial.writeString("[STORAGE] Disk has data but no valid MBR - skipping auto-format\n");
                serial.writeString("[STORAGE] Use 'disk format confirm' to manually format\n");
            }
        }
    }

    initialized = true;
    serial.writeString("[STORAGE] Storage subsystem ready\n");
}

/// Give ATA controller time to stabilize after QEMU cold boot
fn ataWarmup(drive_idx: usize) void {
    var sector: [512]u8 = [_]u8{0} ** 512;

    // Do a few dummy reads to let the controller settle
    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        if (ata.readSector(drive_idx, 0, &sector)) {
            return; // Controller is ready
        } else |_| {
            // Small delay between retries
            ioDelay(1000);
        }
    }
}

fn ioDelay(iterations: usize) void {
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause");
    }
}

/// Verify disk is truly empty with multiple retries
/// Returns true ONLY if we can read sector 0 AND it has no MBR signature
fn isDiskTrulyEmpty(drive_idx: usize) bool {
    var sector: [512]u8 = [_]u8{0} ** 512;
    var attempt: usize = 0;

    while (attempt < 5) : (attempt += 1) {
        if (ata.readSector(drive_idx, 0, &sector)) {
            const sig = @as(u16, sector[510]) | (@as(u16, sector[511]) << 8);

            if (sig == mbr.MBR_SIGNATURE) {
                // Disk has MBR! NOT empty
                serial.writeString("[STORAGE] MBR found on retry ");
                printU32(@intCast(attempt));
                serial.writeString(" - disk is NOT empty\n");
                return false;
            }

            // Also check if sector is all zeros (truly blank disk)
            var all_zero = true;
            for (sector) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }

            if (all_zero) {
                serial.writeString("[STORAGE] Sector 0 is all zeros - disk is empty\n");
                return true;
            }

            // Has some data but no MBR signature - could be corrupt
            // Don't auto-format, let user decide
            serial.writeString("[STORAGE] Sector 0 has data but no MBR signature\n");
            return false;
        } else |_| {
            // Read failed, retry with delay
            ioDelay(5000);
        }
    }

    // All reads failed - don't format, something is wrong
    serial.writeString("[STORAGE] Cannot read disk after 5 attempts - not formatting\n");
    return false;
}

fn autoFormatEmptyDisks() void {
    const drive_count = ata.getDriveCount();
    var i: usize = 0;

    while (i < drive_count) : (i += 1) {
        if (isDiskTrulyEmpty(i)) {
            serial.writeString("[STORAGE] Drive ");
            printU32(@intCast(i));
            serial.writeString(" is empty, auto-formatting...\n");

            if (mbr.formatDiskSimple(i, CONFIRM_FORMAT)) {
                serial.writeString("[STORAGE] Drive ");
                printU32(@intCast(i));
                serial.writeString(" formatted successfully\n");
            } else {
                serial.writeString("[STORAGE] Drive ");
                printU32(@intCast(i));
                serial.writeString(" format failed!\n");
            }
        }
    }

    // Rescan after formatting
    mbr.rescan();
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Drive API
// =============================================================================

pub fn getDriveCount() usize {
    return ata.getDriveCount();
}

pub fn getDrive(idx: usize) ?*const Drive {
    return ata.getDrive(idx);
}

// =============================================================================
// Sector API
// =============================================================================

pub fn readSector(drive: usize, lba: u64, buffer: *[SECTOR_SIZE]u8) AtaError!void {
    return ata.readSector(drive, lba, buffer);
}

pub fn writeSector(drive: usize, lba: u64, buffer: *const [SECTOR_SIZE]u8) AtaError!void {
    return ata.writeSector(drive, lba, buffer);
}

pub fn readSectors(drive: usize, lba: u64, count: u8, buffer: []u8) AtaError!void {
    return ata.readSectors(drive, lba, count, buffer);
}

pub fn writeSectors(drive: usize, lba: u64, count: u8, buffer: []const u8) AtaError!void {
    return ata.writeSectors(drive, lba, count, buffer);
}

// =============================================================================
// Partition API
// =============================================================================

pub fn getPartitionCount() usize {
    return mbr.getPartitionCount();
}

pub fn getPartition(idx: usize) ?*const Partition {
    return mbr.getPartition(idx);
}

pub fn findFAT32Partition() ?*const Partition {
    return mbr.findFAT32();
}

pub fn findBootablePartition() ?*const Partition {
    return mbr.findBootable();
}

// =============================================================================
// Format API (with Safeguards)
// =============================================================================

pub fn formatDrive(drive_idx: usize, options: FormatOptions) FormatError!void {
    return mbr.formatDisk(drive_idx, options);
}

pub fn formatDriveFAT32(drive_idx: usize, confirm: u32) bool {
    return mbr.formatDiskSimple(drive_idx, confirm);
}

pub fn rescanPartitions() void {
    mbr.rescan();
}

// =============================================================================
// Tests
// =============================================================================

pub fn test_storage() bool {
    serial.writeString("\n");
    serial.writeString("========================================\n");
    serial.writeString("  STORAGE TEST SUITE\n");
    serial.writeString("========================================\n\n");

    var all_passed = true;
    var tests_run: u32 = 0;
    var tests_passed: u32 = 0;

    // Test 1: ATA Driver
    serial.writeString("[1/3] ATA Driver\n");
    tests_run += 1;
    if (ata.test_ata()) {
        tests_passed += 1;
    } else {
        all_passed = false;
    }

    // Test 2: MBR/Partition Table
    serial.writeString("\n[2/3] MBR Partition Table\n");
    tests_run += 1;
    if (ata.getDriveCount() > 0) {
        if (mbr.test_mbr()) {
            tests_passed += 1;
        } else {
            all_passed = false;
        }
    } else {
        serial.writeString("  No drives - SKIP\n");
        tests_passed += 1;
    }

    // Test 3: FAT32 Filesystem
    serial.writeString("\n[3/3] FAT32 Filesystem\n");
    tests_run += 1;
    if (fat32.isMounted()) {
        if (fat32.test_fat32()) {
            tests_passed += 1;
        } else {
            all_passed = false;
        }
    } else {
        serial.writeString("  FAT32 not mounted - SKIP\n");
        tests_passed += 1;
    }

    // Summary
    serial.writeString("\n========================================\n");
    serial.writeString("  Results: ");
    printU32(tests_passed);
    serial.writeString("/");
    printU32(tests_run);
    serial.writeString(" passed\n");
    serial.writeString("========================================\n");

    return all_passed;
}

// =============================================================================
// Utility
// =============================================================================

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
