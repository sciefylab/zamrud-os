//! Zamrud OS - ATA PIO Driver
//! Basic IDE/ATA disk driver using PIO mode
//! Supports LBA28 (up to 128GB) and LBA48 (up to 128PB)

const serial = @import("../serial/serial.zig");

// ============================================================================
// ATA I/O Ports
// ============================================================================

// Primary ATA Bus
const ATA_PRIMARY_IO: u16 = 0x1F0;
const ATA_PRIMARY_CTRL: u16 = 0x3F6;

// Secondary ATA Bus
const ATA_SECONDARY_IO: u16 = 0x170;
const ATA_SECONDARY_CTRL: u16 = 0x376;

// Register offsets from base I/O port
const ATA_REG_DATA: u16 = 0; // Read/Write data (16-bit)
const ATA_REG_ERROR: u16 = 1; // Error register (read)
const ATA_REG_FEATURES: u16 = 1; // Features register (write)
const ATA_REG_SECCOUNT: u16 = 2; // Sector count
const ATA_REG_LBA_LO: u16 = 3; // LBA low byte
const ATA_REG_LBA_MID: u16 = 4; // LBA mid byte
const ATA_REG_LBA_HI: u16 = 5; // LBA high byte
const ATA_REG_DRIVE: u16 = 6; // Drive/Head register
const ATA_REG_STATUS: u16 = 7; // Status register (read)
const ATA_REG_COMMAND: u16 = 7; // Command register (write)

// Control register offsets
const ATA_REG_ALT_STATUS: u16 = 0; // Alternate status (read)
const ATA_REG_DEV_CTRL: u16 = 0; // Device control (write)

// ============================================================================
// ATA Commands
// ============================================================================

const ATA_CMD_READ_PIO: u8 = 0x20; // Read sectors (LBA28)
const ATA_CMD_READ_PIO_EXT: u8 = 0x24; // Read sectors (LBA48)
const ATA_CMD_WRITE_PIO: u8 = 0x30; // Write sectors (LBA28)
const ATA_CMD_WRITE_PIO_EXT: u8 = 0x34; // Write sectors (LBA48)
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7; // Flush write cache
const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA; // Flush write cache (LBA48)
const ATA_CMD_IDENTIFY: u8 = 0xEC; // Identify drive

// ============================================================================
// Status Register Bits
// ============================================================================

const ATA_SR_BSY: u8 = 0x80; // Busy
const ATA_SR_DRDY: u8 = 0x40; // Drive ready
const ATA_SR_DF: u8 = 0x20; // Drive fault
const ATA_SR_DSC: u8 = 0x10; // Drive seek complete
const ATA_SR_DRQ: u8 = 0x08; // Data request ready
const ATA_SR_CORR: u8 = 0x04; // Corrected data
const ATA_SR_IDX: u8 = 0x02; // Index
const ATA_SR_ERR: u8 = 0x01; // Error

// ============================================================================
// Error Register Bits
// ============================================================================

const ATA_ER_BBK: u8 = 0x80; // Bad block
const ATA_ER_UNC: u8 = 0x40; // Uncorrectable data
const ATA_ER_MC: u8 = 0x20; // Media changed
const ATA_ER_IDNF: u8 = 0x10; // ID mark not found
const ATA_ER_MCR: u8 = 0x08; // Media change request
const ATA_ER_ABRT: u8 = 0x04; // Command aborted
const ATA_ER_TK0NF: u8 = 0x02; // Track 0 not found
const ATA_ER_AMNF: u8 = 0x01; // Address mark not found

// ============================================================================
// Drive Selection
// ============================================================================

const ATA_DRIVE_MASTER: u8 = 0xA0;
const ATA_DRIVE_SLAVE: u8 = 0xB0;
const ATA_DRIVE_LBA: u8 = 0x40; // Use LBA addressing

// ============================================================================
// Constants
// ============================================================================

pub const SECTOR_SIZE: usize = 512;
pub const MAX_DRIVES: usize = 4;

// ============================================================================
// Drive Information
// ============================================================================

pub const DriveType = enum {
    None,
    ATA,
    ATAPI,
    SATA,
    Unknown,
};

pub const Drive = struct {
    present: bool,
    drive_type: DriveType,
    bus: u8, // 0 = primary, 1 = secondary
    drive: u8, // 0 = master, 1 = slave
    lba48: bool, // Supports LBA48?
    sectors: u64, // Total sectors
    size_mb: u32, // Size in MB
    model: [41]u8, // Model string (40 chars + null)
    serial: [21]u8, // Serial number (20 chars + null)

    pub fn init() Drive {
        return Drive{
            .present = false,
            .drive_type = .None,
            .bus = 0,
            .drive = 0,
            .lba48 = false,
            .sectors = 0,
            .size_mb = 0,
            .model = [_]u8{0} ** 41,
            .serial = [_]u8{0} ** 21,
        };
    }
};

// ============================================================================
// Global State
// ============================================================================

var drives: [MAX_DRIVES]Drive = undefined;
var drive_count: usize = 0;
var initialized: bool = false;

// Static buffer for sector operations
var sector_buffer: [SECTOR_SIZE]u8 = [_]u8{0} ** SECTOR_SIZE;

// ============================================================================
// Port I/O
// ============================================================================

inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "{dx}" (port),
    );
}

// ============================================================================
// Low-level ATA Operations
// ============================================================================

fn ioDelay() void {
    // Read alternate status register 4 times for 400ns delay
    _ = inb(ATA_PRIMARY_CTRL);
    _ = inb(ATA_PRIMARY_CTRL);
    _ = inb(ATA_PRIMARY_CTRL);
    _ = inb(ATA_PRIMARY_CTRL);
}

fn getBasePort(bus: u8) u16 {
    return if (bus == 0) ATA_PRIMARY_IO else ATA_SECONDARY_IO;
}

fn getCtrlPort(bus: u8) u16 {
    return if (bus == 0) ATA_PRIMARY_CTRL else ATA_SECONDARY_CTRL;
}

fn selectDrive(bus: u8, drive: u8) void {
    const base = getBasePort(bus);
    const drive_byte = if (drive == 0) ATA_DRIVE_MASTER else ATA_DRIVE_SLAVE;
    outb(base + ATA_REG_DRIVE, drive_byte | ATA_DRIVE_LBA);
    ioDelay();
}

fn waitNotBusy(bus: u8) bool {
    const base = getBasePort(bus);
    var timeout: u32 = 100000;

    while (timeout > 0) : (timeout -= 1) {
        const status = inb(base + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0) {
            return true;
        }
    }
    return false;
}

fn waitDrq(bus: u8) bool {
    const base = getBasePort(bus);
    var timeout: u32 = 100000;

    while (timeout > 0) : (timeout -= 1) {
        const status = inb(base + ATA_REG_STATUS);
        if ((status & ATA_SR_ERR) != 0) {
            return false;
        }
        if ((status & ATA_SR_DRQ) != 0) {
            return true;
        }
    }
    return false;
}

fn waitReady(bus: u8) bool {
    const base = getBasePort(bus);
    var timeout: u32 = 100000;

    while (timeout > 0) : (timeout -= 1) {
        const status = inb(base + ATA_REG_STATUS);
        if ((status & ATA_SR_BSY) == 0 and (status & ATA_SR_DRDY) != 0) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Drive Detection
// ============================================================================

fn identifyDrive(bus: u8, drive_num: u8) ?Drive {
    const base = getBasePort(bus);

    // Select drive
    selectDrive(bus, drive_num);

    // Clear sector count and LBA registers
    outb(base + ATA_REG_SECCOUNT, 0);
    outb(base + ATA_REG_LBA_LO, 0);
    outb(base + ATA_REG_LBA_MID, 0);
    outb(base + ATA_REG_LBA_HI, 0);

    // Send IDENTIFY command
    outb(base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    ioDelay();

    // Check if drive exists
    const status = inb(base + ATA_REG_STATUS);
    if (status == 0) {
        return null; // No drive
    }

    // Wait for BSY to clear
    if (!waitNotBusy(bus)) {
        return null;
    }

    // Check for ATAPI
    const lba_mid = inb(base + ATA_REG_LBA_MID);
    const lba_hi = inb(base + ATA_REG_LBA_HI);

    if (lba_mid != 0 or lba_hi != 0) {
        // Not ATA - could be ATAPI
        return null;
    }

    // Wait for DRQ or ERR
    if (!waitDrq(bus)) {
        return null;
    }

    // Read identify data (256 words = 512 bytes)
    var identify_data: [256]u16 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        identify_data[i] = inw(base + ATA_REG_DATA);
    }

    // Parse identify data
    var drv = Drive.init();
    drv.present = true;
    drv.drive_type = .ATA;
    drv.bus = bus;
    drv.drive = drive_num;

    // Check LBA48 support (bit 10 of word 83)
    drv.lba48 = (identify_data[83] & (1 << 10)) != 0;

    // Get sector count
    if (drv.lba48) {
        // LBA48: words 100-103
        drv.sectors = @as(u64, identify_data[100]) |
            (@as(u64, identify_data[101]) << 16) |
            (@as(u64, identify_data[102]) << 32) |
            (@as(u64, identify_data[103]) << 48);
    } else {
        // LBA28: words 60-61
        drv.sectors = @as(u64, identify_data[60]) |
            (@as(u64, identify_data[61]) << 16);
    }

    // Calculate size in MB
    drv.size_mb = @intCast((drv.sectors * SECTOR_SIZE) / (1024 * 1024));

    // Extract model string (words 27-46, byte-swapped)
    i = 0;
    while (i < 20) : (i += 1) {
        const word = identify_data[27 + i];
        drv.model[i * 2] = @intCast((word >> 8) & 0xFF);
        drv.model[i * 2 + 1] = @intCast(word & 0xFF);
    }
    drv.model[40] = 0;
    trimString(&drv.model);

    // Extract serial number (words 10-19, byte-swapped)
    i = 0;
    while (i < 10) : (i += 1) {
        const word = identify_data[10 + i];
        drv.serial[i * 2] = @intCast((word >> 8) & 0xFF);
        drv.serial[i * 2 + 1] = @intCast(word & 0xFF);
    }
    drv.serial[20] = 0;
    trimString(&drv.serial);

    return drv;
}

fn trimString(s: []u8) void {
    // Trim trailing spaces
    var i: usize = s.len;
    while (i > 0) {
        i -= 1;
        if (s[i] != ' ' and s[i] != 0) {
            if (i + 1 < s.len) {
                s[i + 1] = 0;
            }
            break;
        }
        s[i] = 0;
    }
}

// ============================================================================
// Read/Write Operations
// ============================================================================

pub const AtaError = error{
    NoDrive,
    NotReady,
    ReadError,
    WriteError,
    InvalidLBA,
    Timeout,
};

/// Read sectors from disk
pub fn readSectors(drive_idx: usize, lba: u64, count: u8, buffer: []u8) AtaError!void {
    if (drive_idx >= drive_count or !drives[drive_idx].present) {
        return AtaError.NoDrive;
    }

    const drv = &drives[drive_idx];
    const base = getBasePort(drv.bus);

    // Validate LBA
    if (lba + count > drv.sectors) {
        return AtaError.InvalidLBA;
    }

    // Validate buffer size
    if (buffer.len < @as(usize, count) * SECTOR_SIZE) {
        return AtaError.InvalidLBA;
    }

    // Select drive with LBA mode
    const drive_byte = if (drv.drive == 0) ATA_DRIVE_MASTER else ATA_DRIVE_SLAVE;

    if (drv.lba48 and lba > 0x0FFFFFFF) {
        // LBA48 mode
        outb(base + ATA_REG_DRIVE, drive_byte | ATA_DRIVE_LBA);
        ioDelay();

        // High bytes first
        outb(base + ATA_REG_SECCOUNT, 0);
        outb(base + ATA_REG_LBA_LO, @intCast((lba >> 24) & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 32) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 40) & 0xFF));

        // Low bytes
        outb(base + ATA_REG_SECCOUNT, count);
        outb(base + ATA_REG_LBA_LO, @intCast(lba & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 8) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 16) & 0xFF));

        outb(base + ATA_REG_COMMAND, ATA_CMD_READ_PIO_EXT);
    } else {
        // LBA28 mode
        outb(base + ATA_REG_DRIVE, drive_byte | ATA_DRIVE_LBA | @as(u8, @intCast((lba >> 24) & 0x0F)));
        ioDelay();

        outb(base + ATA_REG_SECCOUNT, count);
        outb(base + ATA_REG_LBA_LO, @intCast(lba & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 8) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 16) & 0xFF));

        outb(base + ATA_REG_COMMAND, ATA_CMD_READ_PIO);
    }

    // Read sectors
    var sector: u8 = 0;
    while (sector < count) : (sector += 1) {
        if (!waitDrq(drv.bus)) {
            return AtaError.ReadError;
        }

        // Read 256 words (512 bytes)
        const offset = @as(usize, sector) * SECTOR_SIZE;
        var i: usize = 0;
        while (i < SECTOR_SIZE) : (i += 2) {
            const word = inw(base + ATA_REG_DATA);
            buffer[offset + i] = @intCast(word & 0xFF);
            buffer[offset + i + 1] = @intCast((word >> 8) & 0xFF);
        }
    }

    return;
}

/// Write sectors to disk
pub fn writeSectors(drive_idx: usize, lba: u64, count: u8, buffer: []const u8) AtaError!void {
    if (drive_idx >= drive_count or !drives[drive_idx].present) {
        return AtaError.NoDrive;
    }

    const drv = &drives[drive_idx];
    const base = getBasePort(drv.bus);

    // Validate LBA
    if (lba + count > drv.sectors) {
        return AtaError.InvalidLBA;
    }

    // Validate buffer size
    if (buffer.len < @as(usize, count) * SECTOR_SIZE) {
        return AtaError.InvalidLBA;
    }

    // Select drive with LBA mode
    const drive_byte = if (drv.drive == 0) ATA_DRIVE_MASTER else ATA_DRIVE_SLAVE;

    if (drv.lba48 and lba > 0x0FFFFFFF) {
        // LBA48 mode
        outb(base + ATA_REG_DRIVE, drive_byte | ATA_DRIVE_LBA);
        ioDelay();

        outb(base + ATA_REG_SECCOUNT, 0);
        outb(base + ATA_REG_LBA_LO, @intCast((lba >> 24) & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 32) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 40) & 0xFF));

        outb(base + ATA_REG_SECCOUNT, count);
        outb(base + ATA_REG_LBA_LO, @intCast(lba & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 8) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 16) & 0xFF));

        outb(base + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO_EXT);
    } else {
        // LBA28 mode
        outb(base + ATA_REG_DRIVE, drive_byte | ATA_DRIVE_LBA | @as(u8, @intCast((lba >> 24) & 0x0F)));
        ioDelay();

        outb(base + ATA_REG_SECCOUNT, count);
        outb(base + ATA_REG_LBA_LO, @intCast(lba & 0xFF));
        outb(base + ATA_REG_LBA_MID, @intCast((lba >> 8) & 0xFF));
        outb(base + ATA_REG_LBA_HI, @intCast((lba >> 16) & 0xFF));

        outb(base + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);
    }

    // Write sectors
    var sector: u8 = 0;
    while (sector < count) : (sector += 1) {
        if (!waitDrq(drv.bus)) {
            return AtaError.WriteError;
        }

        // Write 256 words (512 bytes)
        const offset = @as(usize, sector) * SECTOR_SIZE;
        var i: usize = 0;
        while (i < SECTOR_SIZE) : (i += 2) {
            const word: u16 = @as(u16, buffer[offset + i]) |
                (@as(u16, buffer[offset + i + 1]) << 8);
            outw(base + ATA_REG_DATA, word);
        }
    }

    // Flush cache
    if (drv.lba48) {
        outb(base + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH_EXT);
    } else {
        outb(base + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    }

    if (!waitNotBusy(drv.bus)) {
        return AtaError.WriteError;
    }

    return;
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize ATA driver and detect drives
pub fn init() void {
    serial.writeString("[ATA] Initializing ATA driver...\n");

    // Initialize drive array
    var i: usize = 0;
    while (i < MAX_DRIVES) : (i += 1) {
        drives[i] = Drive.init();
    }
    drive_count = 0;

    // Scan for drives
    // Primary Master
    if (identifyDrive(0, 0)) |drv| {
        drives[drive_count] = drv;
        drive_count += 1;
        serial.writeString("[ATA] Primary Master: ");
        printDriveInfo(&drv);
    }

    // Primary Slave
    if (identifyDrive(0, 1)) |drv| {
        drives[drive_count] = drv;
        drive_count += 1;
        serial.writeString("[ATA] Primary Slave: ");
        printDriveInfo(&drv);
    }

    // Secondary Master
    if (identifyDrive(1, 0)) |drv| {
        drives[drive_count] = drv;
        drive_count += 1;
        serial.writeString("[ATA] Secondary Master: ");
        printDriveInfo(&drv);
    }

    // Secondary Slave
    if (identifyDrive(1, 1)) |drv| {
        drives[drive_count] = drv;
        drive_count += 1;
        serial.writeString("[ATA] Secondary Slave: ");
        printDriveInfo(&drv);
    }

    initialized = true;

    serial.writeString("[ATA] Found ");
    printU32(@intCast(drive_count));
    serial.writeString(" drive(s)\n");
}

fn printDriveInfo(drv: *const Drive) void {
    // Print model
    for (drv.model) |c| {
        if (c == 0) break;
        serial.writeChar(c);
    }
    serial.writeString(" - ");
    printU32(drv.size_mb);
    serial.writeString(" MB");
    if (drv.lba48) {
        serial.writeString(" (LBA48)");
    }
    serial.writeString("\n");
}

/// Get number of detected drives
pub fn getDriveCount() usize {
    return drive_count;
}

/// Get drive information
pub fn getDrive(idx: usize) ?*const Drive {
    if (idx >= drive_count) return null;
    return &drives[idx];
}

/// Check if driver is initialized
pub fn isInitialized() bool {
    return initialized;
}

/// Read a single sector
pub fn readSector(drive_idx: usize, lba: u64, buffer: *[SECTOR_SIZE]u8) AtaError!void {
    return readSectors(drive_idx, lba, 1, buffer);
}

/// Write a single sector
pub fn writeSector(drive_idx: usize, lba: u64, buffer: *const [SECTOR_SIZE]u8) AtaError!void {
    return writeSectors(drive_idx, lba, 1, buffer);
}

// ============================================================================
// Test Functions
// ============================================================================

pub fn test_ata() bool {
    serial.writeString("[ATA] Running tests...\n");

    if (!initialized) {
        serial.writeString("  Driver not initialized\n");
        return false;
    }

    serial.writeString("  Drives detected: ");
    printU32(@intCast(drive_count));
    serial.writeString("\n");

    if (drive_count == 0) {
        serial.writeString("  No drives found - SKIP\n");
        return true; // Not a failure, just no drives
    }

    // Test read from first drive
    serial.writeString("  Reading sector 0...\n");
    var buffer: [SECTOR_SIZE]u8 = [_]u8{0} ** SECTOR_SIZE;

    if (readSector(0, 0, &buffer)) {
        serial.writeString("  Read OK, first bytes: ");
        printHex(buffer[0]);
        serial.writeString(" ");
        printHex(buffer[1]);
        serial.writeString(" ");
        printHex(buffer[510]);
        serial.writeString(" ");
        printHex(buffer[511]);
        serial.writeString("\n");

        // Check for MBR signature (0x55AA at offset 510-511)
        if (buffer[510] == 0x55 and buffer[511] == 0xAA) {
            serial.writeString("  Valid MBR signature found!\n");
        }

        serial.writeString("  ATA test: PASS\n");
        return true;
    } else |err| {
        serial.writeString("  Read failed: ");
        switch (err) {
            AtaError.NoDrive => serial.writeString("No drive\n"),
            AtaError.NotReady => serial.writeString("Not ready\n"),
            AtaError.ReadError => serial.writeString("Read error\n"),
            AtaError.WriteError => serial.writeString("Write error\n"),
            AtaError.InvalidLBA => serial.writeString("Invalid LBA\n"),
            AtaError.Timeout => serial.writeString("Timeout\n"),
        }
        return false;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

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

fn printHex(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[val >> 4]);
    serial.writeChar(hex[val & 0xF]);
}
