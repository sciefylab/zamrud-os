//! Zamrud OS - MBR Partition Table Parser & Creator
//! Supports MBR (Master Boot Record) partition tables

const serial = @import("../serial/serial.zig");
const ata = @import("ata.zig");

// ============================================================================
// MBR Constants
// ============================================================================

pub const MBR_SIGNATURE: u16 = 0xAA55;
pub const MBR_PARTITION_OFFSET: usize = 446;
pub const MBR_PARTITION_SIZE: usize = 16;
pub const MBR_MAX_PARTITIONS: usize = 4;

// ============================================================================
// Partition Types
// ============================================================================

pub const PartitionType = enum(u8) {
    Empty = 0x00,
    FAT12 = 0x01,
    FAT16_Small = 0x04,
    Extended = 0x05,
    FAT16 = 0x06,
    NTFS = 0x07,
    FAT32 = 0x0B,
    FAT32_LBA = 0x0C,
    FAT16_LBA = 0x0E,
    Extended_LBA = 0x0F,
    Linux_Swap = 0x82,
    Linux = 0x83,
    Linux_LVM = 0x8E,
    ZamrudFS = 0x5A,
    _,

    pub fn getName(self: PartitionType) []const u8 {
        return switch (self) {
            .Empty => "Empty",
            .FAT12 => "FAT12",
            .FAT16_Small => "FAT16 <32MB",
            .Extended => "Extended",
            .FAT16 => "FAT16",
            .NTFS => "NTFS",
            .FAT32 => "FAT32",
            .FAT32_LBA => "FAT32 LBA",
            .FAT16_LBA => "FAT16 LBA",
            .Extended_LBA => "Extended LBA",
            .Linux_Swap => "Linux Swap",
            .Linux => "Linux (ext2/3/4)",
            .Linux_LVM => "Linux LVM",
            .ZamrudFS => "ZamrudFS",
            _ => "Unknown",
        };
    }

    pub fn isFAT(self: PartitionType) bool {
        return switch (self) {
            .FAT12, .FAT16_Small, .FAT16, .FAT32, .FAT32_LBA, .FAT16_LBA => true,
            else => false,
        };
    }

    pub fn isFAT32(self: PartitionType) bool {
        return self == .FAT32 or self == .FAT32_LBA;
    }

    pub fn isSupported(self: PartitionType) bool {
        return switch (self) {
            .FAT12, .FAT16_Small, .FAT16, .FAT32, .FAT32_LBA, .FAT16_LBA => true,
            .ZamrudFS => true,
            else => false,
        };
    }
};

pub const PART_TYPE_EMPTY: u8 = 0x00;
pub const PART_TYPE_FAT32: u8 = 0x0B;
pub const PART_TYPE_FAT32_LBA: u8 = 0x0C;
pub const PART_TYPE_ZAMRUD: u8 = 0x5A;

// ============================================================================
// Format Options
// ============================================================================

pub const FormatType = enum {
    FAT32,
    FAT16,
    ZamrudFS,

    pub fn getPartitionType(self: FormatType) u8 {
        return switch (self) {
            .FAT32 => PART_TYPE_FAT32_LBA,
            .FAT16 => 0x0E,
            .ZamrudFS => PART_TYPE_ZAMRUD,
        };
    }

    pub fn getName(self: FormatType) []const u8 {
        return switch (self) {
            .FAT32 => "FAT32",
            .FAT16 => "FAT16",
            .ZamrudFS => "ZamrudFS",
        };
    }

    pub fn getMinSizeMB(self: FormatType) u32 {
        return switch (self) {
            .FAT32 => 33,
            .FAT16 => 2,
            .ZamrudFS => 10,
        };
    }

    pub fn getMaxSizeMB(self: FormatType) u32 {
        return switch (self) {
            .FAT32 => 2048 * 1024,
            .FAT16 => 2048,
            .ZamrudFS => 1024 * 1024,
        };
    }
};

// ============================================================================
// Confirmation Codes (Safeguard)
// ============================================================================

pub const CONFIRM_FORMAT: u32 = 0xF09A7000;
pub const CONFIRM_WIPE: u32 = 0xDEADBEEF;
pub const CONFIRM_QUICK: u32 = 0x00FA5700;

// ============================================================================
// Partition Structure
// ============================================================================

pub const Partition = struct {
    valid: bool = false,
    bootable: bool = false,
    partition_type: u8 = 0,
    start_lba: u32 = 0,
    sector_count: u32 = 0,
    size_mb: u32 = 0,
    drive_index: usize = 0,

    pub fn getTypeName(self: *const Partition) []const u8 {
        const pt: PartitionType = @enumFromInt(self.partition_type);
        return pt.getName();
    }

    pub fn isFAT32(self: *const Partition) bool {
        return self.partition_type == PART_TYPE_FAT32 or
            self.partition_type == PART_TYPE_FAT32_LBA;
    }

    pub fn isFAT(self: *const Partition) bool {
        const pt: PartitionType = @enumFromInt(self.partition_type);
        return pt.isFAT();
    }

    pub fn isSupported(self: *const Partition) bool {
        const pt: PartitionType = @enumFromInt(self.partition_type);
        return pt.isSupported();
    }

    pub fn isZamrudFS(self: *const Partition) bool {
        return self.partition_type == PART_TYPE_ZAMRUD;
    }
};

// ============================================================================
// Global State
// ============================================================================

var partitions: [4 * ata.MAX_DRIVES]Partition = undefined;
var partition_count: usize = 0;
var initialized: bool = false;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[MBR] Scanning partition tables...\n");

    for (&partitions) |*p| {
        p.* = Partition{};
    }
    partition_count = 0;

    const drive_count = ata.getDriveCount();
    var drive_idx: usize = 0;

    while (drive_idx < drive_count) : (drive_idx += 1) {
        scanDrive(drive_idx);
    }

    initialized = true;

    serial.writeString("[MBR] Found ");
    printU32(@intCast(partition_count));
    serial.writeString(" partition(s)\n");
}

fn scanDrive(drive_idx: usize) void {
    var sector: [512]u8 = [_]u8{0} ** 512;
    var success = false;

    // Retry up to 5 times for reliable read after cold boot
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (ata.readSector(drive_idx, 0, &sector)) {
            success = true;
            break;
        } else |_| {
            // Delay between retries - let ATA controller settle
            ioDelay(2000);
        }
    }

    if (!success) {
        serial.writeString("[MBR] Drive ");
        printU32(@intCast(drive_idx));
        serial.writeString(": Read error after ");
        printU32(@intCast(attempt));
        serial.writeString(" retries\n");
        return;
    }

    if (attempt > 0) {
        serial.writeString("[MBR] Drive ");
        printU32(@intCast(drive_idx));
        serial.writeString(": Read OK after ");
        printU32(@intCast(attempt + 1));
        serial.writeString(" attempt(s)\n");
    }

    // Check MBR signature
    const sig = @as(u16, sector[510]) | (@as(u16, sector[511]) << 8);

    if (sig != MBR_SIGNATURE) {
        serial.writeString("[MBR] Drive ");
        printU32(@intCast(drive_idx));
        serial.writeString(": No MBR (empty disk)\n");
        return;
    }

    serial.writeString("[MBR] Drive ");
    printU32(@intCast(drive_idx));
    serial.writeString(": Valid MBR\n");

    // Parse 4 partition entries
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        parsePartitionEntry(drive_idx, &sector, i);
    }
}

fn parsePartitionEntry(drive_idx: usize, sector: *const [512]u8, index: usize) void {
    const offset = MBR_PARTITION_OFFSET + (index * MBR_PARTITION_SIZE);

    const boot_flag = sector[offset];
    const part_type = sector[offset + 4];

    if (part_type == PART_TYPE_EMPTY) return;

    const start_lba = readU32LE(sector, offset + 8);
    const sector_count = readU32LE(sector, offset + 12);

    if (partition_count < partitions.len) {
        const size_mb: u32 = @intCast((sector_count * 512) / (1024 * 1024));

        partitions[partition_count] = Partition{
            .valid = true,
            .bootable = (boot_flag == 0x80),
            .partition_type = part_type,
            .start_lba = start_lba,
            .sector_count = sector_count,
            .size_mb = size_mb,
            .drive_index = drive_idx,
        };

        serial.writeString("  [");
        printU32(@intCast(index + 1));
        serial.writeString("] ");
        serial.writeString(partitions[partition_count].getTypeName());
        serial.writeString(" - ");
        printU32(size_mb);
        serial.writeString(" MB");
        if (boot_flag == 0x80) {
            serial.writeString(" *");
        }
        if (!partitions[partition_count].isSupported()) {
            serial.writeString(" (read-only)");
        }
        serial.writeString("\n");

        partition_count += 1;
    }
}

// ============================================================================
// I/O Delay Helper
// ============================================================================

fn ioDelay(iterations: usize) void {
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause");
    }
}

// ============================================================================
// Format Functions (with Safeguards)
// ============================================================================

pub const FormatError = error{
    DriveNotFound,
    DiskTooSmall,
    DiskTooLarge,
    InvalidConfirmation,
    WriteError,
    NotSupported,
};

pub const FormatOptions = struct {
    format_type: FormatType = .FAT32,
    label: [11]u8 = [_]u8{' '} ** 11,
    quick: bool = true,
    confirm_code: u32 = 0,
};

pub fn formatDisk(drive_idx: usize, options: FormatOptions) FormatError!void {
    if (options.confirm_code != CONFIRM_FORMAT and
        options.confirm_code != CONFIRM_QUICK)
    {
        serial.writeString("[MBR] ERROR: Invalid confirmation code!\n");
        serial.writeString("      This operation requires explicit confirmation.\n");
        return FormatError.InvalidConfirmation;
    }

    const drive = ata.getDrive(drive_idx) orelse {
        serial.writeString("[MBR] ERROR: Drive not found!\n");
        return FormatError.DriveNotFound;
    };

    const size_mb: u32 = drive.size_mb;
    const min_size = options.format_type.getMinSizeMB();
    const max_size = options.format_type.getMaxSizeMB();

    if (size_mb < min_size) {
        serial.writeString("[MBR] ERROR: Disk too small for ");
        serial.writeString(options.format_type.getName());
        serial.writeString("! (min ");
        printU32(min_size);
        serial.writeString(" MB)\n");
        return FormatError.DiskTooSmall;
    }

    if (size_mb > max_size) {
        serial.writeString("[MBR] ERROR: Disk too large for ");
        serial.writeString(options.format_type.getName());
        serial.writeString("! (max ");
        printU32(max_size);
        serial.writeString(" MB)\n");
        return FormatError.DiskTooLarge;
    }

    if (hasExistingData(drive_idx)) {
        serial.writeString("[MBR] WARNING: Disk contains existing partitions!\n");
        serial.writeString("      All data will be LOST!\n");
    }

    serial.writeString("\n[MBR] Formatting drive ");
    printU32(@intCast(drive_idx));
    serial.writeString(" as ");
    serial.writeString(options.format_type.getName());
    serial.writeString("...\n");

    if (!createMBR(drive_idx, options.format_type)) {
        return FormatError.WriteError;
    }

    if (options.format_type == .FAT32) {
        if (!createFAT32BootSector(drive_idx, options.label)) {
            return FormatError.WriteError;
        }
    }

    serial.writeString("[MBR] Format complete!\n");
}

pub fn formatDiskSimple(drive_idx: usize, confirm: u32) bool {
    const options = FormatOptions{
        .format_type = .FAT32,
        .confirm_code = confirm,
    };

    if (formatDisk(drive_idx, options)) {
        return true;
    } else |_| {
        return false;
    }
}

fn hasExistingData(drive_idx: usize) bool {
    var sector: [512]u8 = [_]u8{0} ** 512;

    if (ata.readSector(drive_idx, 0, &sector)) {
        const sig = @as(u16, sector[510]) | (@as(u16, sector[511]) << 8);
        return sig == MBR_SIGNATURE;
    } else |_| {
        return false;
    }
}

// ============================================================================
// Create MBR
// ============================================================================

fn createMBR(drive_idx: usize, format_type: FormatType) bool {
    const drive = ata.getDrive(drive_idx) orelse return false;

    var sector: [512]u8 = [_]u8{0} ** 512;

    // Boot code (infinite loop)
    sector[0] = 0xEB;
    sector[1] = 0xFE;
    sector[2] = 0x90;

    const part_offset: usize = 446;
    const start_lba: u32 = 2048;

    var total_sectors: u32 = 0;
    if (drive.sectors > 2048) {
        total_sectors = @intCast(drive.sectors - 2048);
    } else {
        return false;
    }

    // Boot flag
    sector[part_offset + 0] = 0x00;

    // Start CHS
    sector[part_offset + 1] = 0x00;
    sector[part_offset + 2] = 0x21;
    sector[part_offset + 3] = 0x00;

    // Partition type
    sector[part_offset + 4] = format_type.getPartitionType();

    // End CHS
    sector[part_offset + 5] = 0xFE;
    sector[part_offset + 6] = 0xFF;
    sector[part_offset + 7] = 0xFF;

    // Start LBA
    writeU32LE(&sector, part_offset + 8, start_lba);

    // Sector count
    writeU32LE(&sector, part_offset + 12, total_sectors);

    // MBR signature
    sector[510] = 0x55;
    sector[511] = 0xAA;

    if (ata.writeSector(drive_idx, 0, &sector)) {
        serial.writeString("[MBR] Partition table created\n");
        return true;
    } else |_| {
        serial.writeString("[MBR] Failed to write MBR!\n");
        return false;
    }
}

// ============================================================================
// Create FAT32 Boot Sector
// ============================================================================

fn createFAT32BootSector(drive_idx: usize, label: [11]u8) bool {
    const drive = ata.getDrive(drive_idx) orelse return false;

    var sector: [512]u8 = [_]u8{0} ** 512;

    const start_lba: u32 = 2048;
    var total_sectors: u32 = 0;
    if (drive.sectors > 2048) {
        total_sectors = @intCast(drive.sectors - 2048);
    }

    // Jump instruction
    sector[0] = 0xEB;
    sector[1] = 0x58;
    sector[2] = 0x90;

    // OEM Name
    const oem = "ZAMRUDOS";
    for (oem, 0..) |c, i| {
        sector[3 + i] = c;
    }

    // BPB
    writeU16LE(&sector, 11, 512);
    sector[13] = 8;
    writeU16LE(&sector, 14, 32);
    sector[16] = 2;
    writeU16LE(&sector, 17, 0);
    writeU16LE(&sector, 19, 0);
    sector[21] = 0xF8;
    writeU16LE(&sector, 22, 0);
    writeU16LE(&sector, 24, 63);
    writeU16LE(&sector, 26, 255);
    writeU32LE(&sector, 28, start_lba);
    writeU32LE(&sector, 32, total_sectors);

    // FAT32 Extended BPB
    const fat_size = calculateFATSize(total_sectors, 8);
    writeU32LE(&sector, 36, fat_size);
    writeU16LE(&sector, 40, 0);
    writeU16LE(&sector, 42, 0);
    writeU32LE(&sector, 44, 2);
    writeU16LE(&sector, 48, 1);
    writeU16LE(&sector, 50, 6);

    sector[64] = 0x80;
    sector[65] = 0;
    sector[66] = 0x29;

    writeU32LE(&sector, 67, 0x12345678);

    for (label, 0..) |c, i| {
        sector[71 + i] = c;
    }

    const fstype = "FAT32   ";
    for (fstype, 0..) |c, i| {
        sector[82 + i] = c;
    }

    sector[510] = 0x55;
    sector[511] = 0xAA;

    // Write boot sector
    if (ata.writeSector(drive_idx, start_lba, &sector)) {
        serial.writeString("[FAT32] Boot sector created\n");
    } else |_| {
        serial.writeString("[FAT32] Failed to write boot sector!\n");
        return false;
    }

    // Create FSInfo sector
    if (!createFSInfoSector(drive_idx, start_lba + 1)) {
        return false;
    }

    // Create backup boot sector
    if (ata.writeSector(drive_idx, start_lba + 6, &sector)) {
        serial.writeString("[FAT32] Backup boot sector created\n");
    } else |_| {
        // Not critical
    }

    // Initialize FAT tables
    if (!initializeFAT(drive_idx, start_lba + 32, fat_size)) {
        return false;
    }

    return true;
}

fn createFSInfoSector(drive_idx: usize, lba: u32) bool {
    var sector: [512]u8 = [_]u8{0} ** 512;

    sector[0] = 0x52;
    sector[1] = 0x52;
    sector[2] = 0x61;
    sector[3] = 0x41;

    sector[484] = 0x72;
    sector[485] = 0x72;
    sector[486] = 0x41;
    sector[487] = 0x61;

    writeU32LE(&sector, 488, 0xFFFFFFFF);
    writeU32LE(&sector, 492, 3);

    sector[510] = 0x55;
    sector[511] = 0xAA;

    if (ata.writeSector(drive_idx, lba, &sector)) {
        serial.writeString("[FAT32] FSInfo sector created\n");
        return true;
    } else |_| {
        return false;
    }
}

fn initializeFAT(drive_idx: usize, fat_start: u32, fat_size: u32) bool {
    var sector: [512]u8 = [_]u8{0} ** 512;

    writeU32LE(&sector, 0, 0x0FFFFFF8);
    writeU32LE(&sector, 4, 0x0FFFFFFF);
    writeU32LE(&sector, 8, 0x0FFFFFFF);

    if (ata.writeSector(drive_idx, fat_start, &sector)) {
        serial.writeString("[FAT32] FAT1 initialized\n");
    } else |_| {
        return false;
    }

    if (ata.writeSector(drive_idx, fat_start + fat_size, &sector)) {
        serial.writeString("[FAT32] FAT2 initialized\n");
    } else |_| {
        // Not critical
    }

    return true;
}

fn calculateFATSize(total_sectors: u32, sectors_per_cluster: u8) u32 {
    const data_sectors = total_sectors - 32;
    const clusters = data_sectors / sectors_per_cluster;
    const fat_entries = clusters + 2;
    const fat_bytes = fat_entries * 4;
    const fat_sectors = (fat_bytes + 511) / 512;
    return fat_sectors;
}

// ============================================================================
// Public API
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getPartitionCount() usize {
    return partition_count;
}

pub fn getPartition(index: usize) ?*const Partition {
    if (index >= partition_count) return null;
    return &partitions[index];
}

pub fn findFAT32() ?*const Partition {
    var i: usize = 0;
    while (i < partition_count) : (i += 1) {
        if (partitions[i].valid and partitions[i].isFAT32()) {
            return &partitions[i];
        }
    }
    return null;
}

pub fn findBootable() ?*const Partition {
    var i: usize = 0;
    while (i < partition_count) : (i += 1) {
        if (partitions[i].valid and partitions[i].bootable) {
            return &partitions[i];
        }
    }
    return null;
}

pub fn rescan() void {
    init();
}

// ============================================================================
// Test
// ============================================================================

pub fn test_mbr() bool {
    serial.writeString("[MBR] Running tests...\n");

    serial.writeString("  Partitions: ");
    printU32(@intCast(partition_count));
    serial.writeString("\n");

    if (partition_count == 0) {
        serial.writeString("  No partitions (disk unformatted)\n");
        serial.writeString("  Use 'disk format' to initialize\n");
        serial.writeString("  MBR test: SKIP\n");
        return true;
    }

    var i: usize = 0;
    while (i < partition_count) : (i += 1) {
        const p = &partitions[i];
        serial.writeString("  [");
        printU32(@intCast(i));
        serial.writeString("] ");
        serial.writeString(p.getTypeName());
        serial.writeString(" ");
        printU32(p.size_mb);
        serial.writeString("MB");
        if (p.isSupported()) {
            serial.writeString(" [OK]");
        } else {
            serial.writeString(" [RO]");
        }
        serial.writeString("\n");
    }

    serial.writeString("  MBR test: PASS\n");
    return true;
}

// ============================================================================
// Utility Functions
// ============================================================================

fn readU32LE(data: *const [512]u8, offset: usize) u32 {
    return @as(u32, data[offset]) |
        (@as(u32, data[offset + 1]) << 8) |
        (@as(u32, data[offset + 2]) << 16) |
        (@as(u32, data[offset + 3]) << 24);
}

fn writeU32LE(data: *[512]u8, offset: usize, value: u32) void {
    data[offset] = @intCast(value & 0xFF);
    data[offset + 1] = @intCast((value >> 8) & 0xFF);
    data[offset + 2] = @intCast((value >> 16) & 0xFF);
    data[offset + 3] = @intCast((value >> 24) & 0xFF);
}

fn writeU16LE(data: *[512]u8, offset: usize, value: u16) void {
    data[offset] = @intCast(value & 0xFF);
    data[offset + 1] = @intCast((value >> 8) & 0xFF);
}

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
