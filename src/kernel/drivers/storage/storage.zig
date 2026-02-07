//! Zamrud OS - Storage Subsystem
//! Unified storage interface

pub const ata = @import("ata.zig");

const serial = @import("../serial/serial.zig");

pub const SECTOR_SIZE = ata.SECTOR_SIZE;
pub const Drive = ata.Drive;
pub const AtaError = ata.AtaError;

var initialized: bool = false;

pub fn init() void {
    serial.writeString("[STORAGE] Initializing storage subsystem...\n");

    // Initialize ATA driver
    ata.init();

    initialized = true;
    serial.writeString("[STORAGE] Storage subsystem ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn getDriveCount() usize {
    return ata.getDriveCount();
}

pub fn getDrive(idx: usize) ?*const Drive {
    return ata.getDrive(idx);
}

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

pub fn test_storage() bool {
    return ata.test_ata();
}
