//! Zamrud OS - Storage Subsystem
//! Unified storage interface with partition support
//! B2.4: AHCI/SATA support with ATA PIO fallback
//! 🆕 F4.3: Hardware Serial DNA Extraction

pub const ata = @import("ata.zig");
pub const mbr = @import("mbr.zig");
pub const ahci = @import("ahci.zig");
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

// =============================================================================
// B2.4: Backend Selection
// =============================================================================

/// Which storage backend is active
pub const Backend = enum {
    none,
    ata_pio,
    ahci_dma,
};

var active_backend: Backend = .none;

pub fn getBackend() Backend {
    return active_backend;
}

pub fn getBackendName() []const u8 {
    return switch (active_backend) {
        .none => "None",
        .ata_pio => "ATA PIO",
        .ahci_dma => "AHCI DMA",
    };
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[STORAGE] Initializing storage subsystem...\n");

    // 1. Try AHCI first (faster, DMA-based)
    if (ahci.init()) {
        active_backend = .ahci_dma;
        serial.writeString("[STORAGE] Using AHCI/SATA backend (DMA)\n");
    } else {
        // 2. Fallback to ATA PIO
        ata.init();
        if (ata.getDriveCount() > 0) {
            active_backend = .ata_pio;
            serial.writeString("[STORAGE] Using ATA PIO backend\n");
        } else {
            active_backend = .none;
            serial.writeString("[STORAGE] No storage devices found\n");
        }
    }

    // B2.4: Setup MBR I/O routing BEFORE scanning partitions
    mbr.setIoFunctions(readSectorForMbr, writeSectorForMbr);

    const drive_count = getDriveCount();

    if (drive_count > 0) {
        // Wait for disk to be ready before reading
        if (active_backend == .ata_pio) {
            ataWarmup(0);
        }

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
    serial.writeString("[STORAGE] Storage subsystem ready (");
    serial.writeString(getBackendName());
    serial.writeString(")\n");
}

/// Give ATA controller time to stabilize after QEMU cold boot
fn ataWarmup(drive_idx: usize) void {
    var sector: [512]u8 = [_]u8{0} ** 512;

    // Do a few dummy reads to let the controller settle
    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        if (readSectorInternal(drive_idx, 0, &sector)) {
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
fn isDiskTrulyEmpty(drive_idx: usize) bool {
    var sector: [512]u8 = [_]u8{0} ** 512;
    var attempt: usize = 0;

    while (attempt < 5) : (attempt += 1) {
        if (readSectorInternal(drive_idx, 0, &sector)) {
            const sig = @as(u16, sector[510]) | (@as(u16, sector[511]) << 8);

            if (sig == mbr.MBR_SIGNATURE) {
                serial.writeString("[STORAGE] MBR found on retry ");
                printU32(@intCast(attempt));
                serial.writeString(" - disk is NOT empty\n");
                return false;
            }

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

            serial.writeString("[STORAGE] Sector 0 has data but no MBR signature\n");
            return false;
        } else |_| {
            ioDelay(5000);
        }
    }

    serial.writeString("[STORAGE] Cannot read disk after 5 attempts - not formatting\n");
    return false;
}

fn autoFormatEmptyDisks() void {
    const drive_count = getDriveCount();
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

    mbr.rescan();
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Drive API (backend-agnostic)
// =============================================================================

pub fn getDriveCount() usize {
    return switch (active_backend) {
        .ahci_dma => ahci.getDriveCount(),
        .ata_pio => ata.getDriveCount(),
        .none => 0,
    };
}

pub fn getDrive(idx: usize) ?*const Drive {
    return switch (active_backend) {
        .ata_pio => ata.getDrive(idx),
        else => ata.getDrive(idx), // Fallback — AHCI returns null from ATA
    };
}

// 🆕 F4.3: Hardware DNA Extraction (Universal)
pub fn getDriveSerial(idx: usize) ?[]const u8 {
    return switch (active_backend) {
        .ahci_dma => ahci.getDriveSerial(idx),
        .ata_pio => if (ata.getDrive(idx)) |drv| blk: {
            var len: usize = 0;
            while (len < 20 and drv.serial[len] != 0) : (len += 1) {}
            break :blk drv.serial[0..len];
        } else null,
        .none => null,
    };
}

// =============================================================================
// Sector API (backend-agnostic) — THE KEY ROUTING LAYER
// =============================================================================

/// Internal read — used by storage.zig functions only
fn readSectorInternal(drive: usize, lba: u64, buffer: *[SECTOR_SIZE]u8) AtaError!void {
    switch (active_backend) {
        .ahci_dma => {
            ahci.readSector(drive, lba, buffer) catch |err| {
                return switch (err) {
                    ahci.AhciError.NoDrive => AtaError.NoDrive,
                    ahci.AhciError.NotReady => AtaError.NotReady,
                    ahci.AhciError.ReadError => AtaError.ReadError,
                    ahci.AhciError.WriteError => AtaError.WriteError,
                    ahci.AhciError.InvalidLBA => AtaError.InvalidLBA,
                    ahci.AhciError.Timeout => AtaError.Timeout,
                    ahci.AhciError.NotInitialized => AtaError.NoDrive,
                };
            };
        },
        .ata_pio => return ata.readSector(drive, lba, buffer),
        .none => return AtaError.NoDrive,
    }
}

pub fn readSector(drive: usize, lba: u64, buffer: *[SECTOR_SIZE]u8) AtaError!void {
    return readSectorInternal(drive, lba, buffer);
}

pub fn writeSector(drive: usize, lba: u64, buffer: *const [SECTOR_SIZE]u8) AtaError!void {
    switch (active_backend) {
        .ahci_dma => {
            ahci.writeSector(drive, lba, buffer) catch |err| {
                return switch (err) {
                    ahci.AhciError.NoDrive => AtaError.NoDrive,
                    ahci.AhciError.NotReady => AtaError.NotReady,
                    ahci.AhciError.ReadError => AtaError.ReadError,
                    ahci.AhciError.WriteError => AtaError.WriteError,
                    ahci.AhciError.InvalidLBA => AtaError.InvalidLBA,
                    ahci.AhciError.Timeout => AtaError.Timeout,
                    ahci.AhciError.NotInitialized => AtaError.NoDrive,
                };
            };
        },
        .ata_pio => return ata.writeSector(drive, lba, buffer),
        .none => return AtaError.NoDrive,
    }
}

pub fn readSectors(drive: usize, lba: u64, count: u8, buffer: []u8) AtaError!void {
    switch (active_backend) {
        .ahci_dma => {
            ahci.readSectors(drive, lba, count, buffer) catch |err| {
                return switch (err) {
                    ahci.AhciError.NoDrive => AtaError.NoDrive,
                    ahci.AhciError.NotReady => AtaError.NotReady,
                    ahci.AhciError.ReadError => AtaError.ReadError,
                    ahci.AhciError.WriteError => AtaError.WriteError,
                    ahci.AhciError.InvalidLBA => AtaError.InvalidLBA,
                    ahci.AhciError.Timeout => AtaError.Timeout,
                    ahci.AhciError.NotInitialized => AtaError.NoDrive,
                };
            };
        },
        .ata_pio => return ata.readSectors(drive, lba, count, buffer),
        .none => return AtaError.NoDrive,
    }
}

pub fn writeSectors(drive: usize, lba: u64, count: u8, buffer: []const u8) AtaError!void {
    switch (active_backend) {
        .ahci_dma => {
            ahci.writeSectors(drive, lba, count, buffer) catch |err| {
                return switch (err) {
                    ahci.AhciError.NoDrive => AtaError.NoDrive,
                    ahci.AhciError.NotReady => AtaError.NotReady,
                    ahci.AhciError.ReadError => AtaError.ReadError,
                    ahci.AhciError.WriteError => AtaError.WriteError,
                    ahci.AhciError.InvalidLBA => AtaError.InvalidLBA,
                    ahci.AhciError.Timeout => AtaError.Timeout,
                    ahci.AhciError.NotInitialized => AtaError.NoDrive,
                };
            };
        },
        .ata_pio => return ata.writeSectors(drive, lba, count, buffer),
        .none => return AtaError.NoDrive,
    }
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

    // Test 0: Backend detection
    serial.writeString("[0/4] Storage Backend\n");
    tests_run += 1;
    serial.writeString("  Backend: ");
    serial.writeString(getBackendName());
    serial.writeString("\n");
    if (active_backend != .none) {
        tests_passed += 1;
        serial.writeString("  Backend test: PASS\n");
    } else {
        all_passed = false;
        serial.writeString("  Backend test: FAIL (no backend)\n");
    }

    // Test 1: Drive detection
    serial.writeString("\n[1/4] Drive Detection\n");
    tests_run += 1;
    if (getDriveCount() > 0) {
        tests_passed += 1;
        serial.writeString("  Drives: ");
        printU32(@intCast(getDriveCount()));
        serial.writeString("  PASS\n");

        // Print AHCI-specific info
        if (active_backend == .ahci_dma) {
            var i: usize = 0;
            while (i < ahci.getDriveCount()) : (i += 1) {
                serial.writeString("  [AHCI ");
                printU32(@intCast(i));
                serial.writeString("] ");
                serial.writeString(ahci.getDriveModel(i));
                serial.writeString(" - ");
                printU32(ahci.getDriveSizeMB(i));
                serial.writeString(" MB\n");
            }
        }
    } else {
        all_passed = false;
        serial.writeString("  No drives - FAIL\n");
    }

    // Test 2: MBR/Partition Table
    serial.writeString("\n[2/4] MBR Partition Table\n");
    tests_run += 1;
    if (getDriveCount() > 0) {
        if (mbr.test_mbr()) {
            tests_passed += 1;
        } else {
            all_passed = false;
        }
    } else {
        serial.writeString("  No drives - SKIP\n");
        tests_passed += 1;
    }

    // Test 3: Sector Read/Write
    serial.writeString("\n[3/4] Sector I/O\n");
    tests_run += 1;
    if (getDriveCount() > 0) {
        var buf: [512]u8 = [_]u8{0} ** 512;
        if (readSector(0, 0, &buf)) {
            serial.writeString("  Read sector 0: PASS\n");
            serial.writeString("  Sig: ");
            printHex8(buf[510]);
            serial.writeString(" ");
            printHex8(buf[511]);
            serial.writeString("\n");
            tests_passed += 1;
        } else |_| {
            serial.writeString("  Read sector 0: FAIL\n");
            all_passed = false;
        }
    } else {
        serial.writeString("  No drives - SKIP\n");
        tests_passed += 1;
    }

    // Test 4: FAT32
    serial.writeString("\n[4/4] FAT32 Filesystem\n");
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
    serial.writeString(" passed (");
    serial.writeString(getBackendName());
    serial.writeString(")\n");
    serial.writeString("========================================\n");

    return all_passed;
}

// =============================================================================
// B2.4: MBR I/O Routing Wrappers
// =============================================================================

fn readSectorForMbr(drive: usize, lba: u64, buffer: *[SECTOR_SIZE]u8) AtaError!void {
    return readSectorInternal(drive, lba, buffer);
}

fn writeSectorForMbr(drive: usize, lba: u64, buffer: *const [SECTOR_SIZE]u8) AtaError!void {
    return writeSector(drive, lba, buffer);
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

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[val >> 4]);
    serial.writeChar(hex[val & 0xF]);
}
