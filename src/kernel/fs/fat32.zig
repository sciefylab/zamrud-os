//! Zamrud OS - FAT32 Filesystem Driver
//! Read/Write support for FAT32 partitions
//! B2.2: Full write support including VFS integration

const serial = @import("../drivers/serial/serial.zig");
const storage = @import("../drivers/storage/storage.zig");
const ata = @import("../drivers/storage/ata.zig");
const mbr = @import("../drivers/storage/mbr.zig");

// ============================================================================
// FAT32 Constants
// ============================================================================

pub const SECTOR_SIZE: u32 = 512;
pub const DIR_ENTRY_SIZE: u32 = 32;
pub const ENTRIES_PER_SECTOR: u32 = SECTOR_SIZE / DIR_ENTRY_SIZE;

// FAT Entry Values
pub const FAT_FREE: u32 = 0x00000000;
pub const FAT_RESERVED_START: u32 = 0x0FFFFFF0;
pub const FAT_BAD_CLUSTER: u32 = 0x0FFFFFF7;
pub const FAT_END_OF_CHAIN: u32 = 0x0FFFFFF8;
pub const FAT_MASK: u32 = 0x0FFFFFFF;

// Directory Entry Attributes
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;

// ============================================================================
// Directory Entry (32 bytes)
// ============================================================================

pub const DirEntry = extern struct {
    name: [8]u8,
    ext: [3]u8,
    attr: u8,
    reserved: u8,
    create_time_tenth: u8,
    create_time: u16,
    create_date: u16,
    access_date: u16,
    cluster_high: u16,
    modify_time: u16,
    modify_date: u16,
    cluster_low: u16,
    file_size: u32,

    pub fn isDeleted(self: *const DirEntry) bool {
        return self.name[0] == 0xE5;
    }

    pub fn isEmpty(self: *const DirEntry) bool {
        return self.name[0] == 0x00;
    }

    pub fn isLongName(self: *const DirEntry) bool {
        return self.attr == ATTR_LONG_NAME;
    }

    pub fn isDirectory(self: *const DirEntry) bool {
        return (self.attr & ATTR_DIRECTORY) != 0;
    }

    pub fn isVolumeLabel(self: *const DirEntry) bool {
        return (self.attr & ATTR_VOLUME_ID) != 0;
    }

    pub fn isFile(self: *const DirEntry) bool {
        return !self.isDirectory() and !self.isVolumeLabel() and !self.isLongName();
    }

    pub fn getCluster(self: *const DirEntry) u32 {
        return (@as(u32, self.cluster_high) << 16) | @as(u32, self.cluster_low);
    }

    pub fn setCluster(self: *DirEntry, cluster: u32) void {
        self.cluster_high = @intCast((cluster >> 16) & 0xFFFF);
        self.cluster_low = @intCast(cluster & 0xFFFF);
    }

    pub fn getName(self: *const DirEntry, buffer: *[12]u8) []u8 {
        var i: usize = 0;

        var name_len: usize = 8;
        while (name_len > 0 and self.name[name_len - 1] == ' ') {
            name_len -= 1;
        }
        for (self.name[0..name_len]) |c| {
            buffer[i] = c;
            i += 1;
        }

        var ext_len: usize = 3;
        while (ext_len > 0 and self.ext[ext_len - 1] == ' ') {
            ext_len -= 1;
        }
        if (ext_len > 0) {
            buffer[i] = '.';
            i += 1;
            for (self.ext[0..ext_len]) |c| {
                buffer[i] = c;
                i += 1;
            }
        }

        return buffer[0..i];
    }
};

comptime {
    if (@sizeOf(DirEntry) != 32) @compileError("DirEntry must be exactly 32 bytes");
}

// ============================================================================
// Safe DirEntry reader/writer
// ============================================================================

fn readDirEntry(buffer: []const u8, offset: usize) DirEntry {
    var entry: DirEntry = undefined;
    const entry_bytes = @as([*]u8, @ptrCast(&entry))[0..@sizeOf(DirEntry)];
    for (entry_bytes, 0..) |*b, i| {
        b.* = buffer[offset + i];
    }
    return entry;
}

fn writeDirEntryToBuffer(buffer: []u8, offset: usize, entry: *const DirEntry) void {
    const entry_bytes = @as([*]const u8, @ptrCast(entry))[0..@sizeOf(DirEntry)];
    for (entry_bytes, 0..) |b, i| {
        buffer[offset + i] = b;
    }
}

// ============================================================================
// File Info (user-friendly)
// ============================================================================

pub const FileInfo = struct {
    name: [12]u8,
    name_len: u8,
    is_dir: bool,
    size: u32,
    cluster: u32,
    attr: u8,

    pub fn getName(self: *const FileInfo) []const u8 {
        return self.name[0..self.name_len];
    }
};

// ============================================================================
// FAT32 Filesystem State
// ============================================================================

pub const Fat32 = struct {
    drive_index: usize,
    partition_start: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size: u32,
    root_cluster: u32,
    total_sectors: u32,
    fat_start_lba: u32,
    data_start_lba: u32,
    cluster_count: u32,
    mounted: bool,

    pub fn init() Fat32 {
        return Fat32{
            .drive_index = 0,
            .partition_start = 0,
            .bytes_per_sector = 512,
            .sectors_per_cluster = 8,
            .reserved_sectors = 32,
            .num_fats = 2,
            .fat_size = 0,
            .root_cluster = 2,
            .total_sectors = 0,
            .fat_start_lba = 0,
            .data_start_lba = 0,
            .cluster_count = 0,
            .mounted = false,
        };
    }

    /// Get bytes per cluster
    pub fn getBytesPerCluster(self: *const Fat32) u32 {
        return @as(u32, self.sectors_per_cluster) * @as(u32, self.bytes_per_sector);
    }
};

// ============================================================================
// Global State
// ============================================================================

var fs: Fat32 = Fat32.init();
var initialized: bool = false;
var sector_buffer: [512]u8 align(4) = [_]u8{0} ** 512;

// Secondary buffer for operations that need two sectors
var sector_buffer2: [512]u8 align(4) = [_]u8{0} ** 512;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[FAT32] Initializing filesystem driver...\n");

    const partition = storage.findFAT32Partition() orelse {
        serial.writeString("[FAT32] No FAT32 partition found\n");
        initialized = true;
        return;
    };

    if (mountPartition(partition.drive_index, partition.start_lba)) {
        serial.writeString("[FAT32] Mounted successfully\n");
    } else {
        serial.writeString("[FAT32] Mount failed!\n");
    }

    initialized = true;
}

pub fn mountPartition(drive_index: usize, partition_start: u32) bool {
    serial.writeString("[FAT32] Mounting partition at LBA ");
    printU32(partition_start);
    serial.writeString("...\n");

    fs.drive_index = drive_index;
    fs.partition_start = partition_start;

    if (ata.readSector(drive_index, partition_start, &sector_buffer)) {
        fs.bytes_per_sector = readU16LE(&sector_buffer, 11);
        fs.sectors_per_cluster = sector_buffer[13];
        fs.reserved_sectors = readU16LE(&sector_buffer, 14);
        fs.num_fats = sector_buffer[16];
        fs.total_sectors = readU32LE(&sector_buffer, 32);
        fs.fat_size = readU32LE(&sector_buffer, 36);
        fs.root_cluster = readU32LE(&sector_buffer, 44);

        if (fs.bytes_per_sector != 512) {
            serial.writeString("[FAT32] Invalid sector size!\n");
            return false;
        }

        if (fs.sectors_per_cluster == 0) {
            serial.writeString("[FAT32] Invalid cluster size!\n");
            return false;
        }

        fs.fat_start_lba = partition_start + fs.reserved_sectors;
        fs.data_start_lba = fs.fat_start_lba + (fs.num_fats * fs.fat_size);

        const data_sectors = fs.total_sectors - fs.reserved_sectors - (fs.num_fats * fs.fat_size);
        fs.cluster_count = data_sectors / fs.sectors_per_cluster;

        fs.mounted = true;

        serial.writeString("[FAT32] Bytes/sector:     ");
        printU32(fs.bytes_per_sector);
        serial.writeString("\n");

        serial.writeString("[FAT32] Sectors/cluster:  ");
        printU32(fs.sectors_per_cluster);
        serial.writeString("\n");

        serial.writeString("[FAT32] FAT size:         ");
        printU32(fs.fat_size);
        serial.writeString(" sectors\n");

        serial.writeString("[FAT32] Data start:       LBA ");
        printU32(fs.data_start_lba);
        serial.writeString("\n");

        serial.writeString("[FAT32] Total clusters:   ");
        printU32(fs.cluster_count);
        serial.writeString("\n");

        return true;
    } else |_| {
        serial.writeString("[FAT32] Failed to read boot sector!\n");
        return false;
    }
}

// ============================================================================
// Cluster Operations
// ============================================================================

fn clusterToLba(cluster: u32) u32 {
    return fs.data_start_lba + ((cluster - 2) * fs.sectors_per_cluster);
}

fn readFatEntry(cluster: u32) ?u32 {
    const fat_offset = cluster * 4;
    const fat_sector = fs.fat_start_lba + (fat_offset / 512);
    const entry_offset = fat_offset % 512;

    if (ata.readSector(fs.drive_index, fat_sector, &sector_buffer)) {
        return readU32LE(&sector_buffer, entry_offset) & FAT_MASK;
    } else |_| {
        return null;
    }
}

fn writeFatEntry(cluster: u32, value: u32) bool {
    const fat_offset = cluster * 4;
    const fat_sector = fs.fat_start_lba + (fat_offset / 512);
    const entry_offset = fat_offset % 512;

    if (ata.readSector(fs.drive_index, fat_sector, &sector_buffer)) {
        writeU32LE(&sector_buffer, entry_offset, value & FAT_MASK);

        if (ata.writeSector(fs.drive_index, fat_sector, &sector_buffer)) {
            // Write to backup FAT
            const fat2_sector = fat_sector + fs.fat_size;
            ata.writeSector(fs.drive_index, fat2_sector, &sector_buffer) catch {};
            return true;
        } else |_| {
            return false;
        }
    } else |_| {
        return false;
    }
}

fn findFreeCluster() ?u32 {
    var cluster: u32 = 2;
    while (cluster < fs.cluster_count + 2) : (cluster += 1) {
        if (readFatEntry(cluster)) |entry| {
            if (entry == FAT_FREE) {
                return cluster;
            }
        }
    }
    return null;
}

/// Allocate a chain of clusters for a given size
fn allocateClusterChain(size: u32) ?u32 {
    if (size == 0) {
        // Even empty files need one cluster for directory entry
        const cluster = findFreeCluster() orelse return null;
        if (!writeFatEntry(cluster, FAT_END_OF_CHAIN)) return null;
        return cluster;
    }

    const bytes_per_cluster = fs.getBytesPerCluster();
    const clusters_needed = (size + bytes_per_cluster - 1) / bytes_per_cluster;

    var first_cluster: ?u32 = null;
    var prev_cluster: u32 = 0;
    var allocated: u32 = 0;

    while (allocated < clusters_needed) {
        const cluster = findFreeCluster() orelse {
            // Rollback: free already allocated clusters
            if (first_cluster) |fc| {
                freeClusterChain(fc);
            }
            return null;
        };

        // Mark as end of chain (will be updated if more clusters follow)
        if (!writeFatEntry(cluster, FAT_END_OF_CHAIN)) {
            if (first_cluster) |fc| {
                freeClusterChain(fc);
            }
            return null;
        }

        if (first_cluster == null) {
            first_cluster = cluster;
        } else {
            // Link previous cluster to this one
            if (!writeFatEntry(prev_cluster, cluster)) {
                freeClusterChain(first_cluster.?);
                return null;
            }
        }

        prev_cluster = cluster;
        allocated += 1;
    }

    return first_cluster;
}

/// Free a cluster chain
fn freeClusterChain(start_cluster: u32) void {
    var cluster = start_cluster;
    while (cluster >= 2 and cluster < FAT_END_OF_CHAIN) {
        const next = readFatEntry(cluster) orelse break;
        _ = writeFatEntry(cluster, FAT_FREE);
        if (next >= FAT_END_OF_CHAIN) break;
        cluster = next;
    }
}

/// Extend a cluster chain to accommodate new size
fn extendClusterChain(start_cluster: u32, current_size: u32, new_size: u32) bool {
    if (new_size <= current_size) return true;

    const bytes_per_cluster = fs.getBytesPerCluster();
    const current_clusters = if (current_size == 0) 0 else (current_size + bytes_per_cluster - 1) / bytes_per_cluster;
    const needed_clusters = (new_size + bytes_per_cluster - 1) / bytes_per_cluster;

    if (needed_clusters <= current_clusters) return true;

    // Find last cluster in chain
    var last_cluster = start_cluster;
    while (true) {
        const next = readFatEntry(last_cluster) orelse return false;
        if (next >= FAT_END_OF_CHAIN) break;
        last_cluster = next;
    }

    // Allocate additional clusters
    var added: u32 = 0;
    const to_add = needed_clusters - current_clusters;

    while (added < to_add) {
        const new_cluster = findFreeCluster() orelse return false;
        if (!writeFatEntry(new_cluster, FAT_END_OF_CHAIN)) return false;
        if (!writeFatEntry(last_cluster, new_cluster)) return false;
        last_cluster = new_cluster;
        added += 1;
    }

    return true;
}

fn isEndOfChain(cluster: u32) bool {
    return cluster >= FAT_END_OF_CHAIN;
}

// ============================================================================
// Directory Operations
// ============================================================================

pub fn readDirectory(cluster: u32, entries: []FileInfo) usize {
    if (!fs.mounted) return 0;

    var entry_count: usize = 0;
    var current_cluster = cluster;

    while (!isEndOfChain(current_cluster) and entry_count < entries.len) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster and entry_count < entries.len) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                var i: usize = 0;
                while (i < ENTRIES_PER_SECTOR and entry_count < entries.len) : (i += 1) {
                    const offset = i * DIR_ENTRY_SIZE;
                    const dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty()) {
                        return entry_count;
                    }

                    if (dir_entry.isDeleted() or dir_entry.isLongName() or dir_entry.isVolumeLabel()) {
                        continue;
                    }

                    var name_buf: [12]u8 = undefined;
                    const name = dir_entry.getName(&name_buf);

                    entries[entry_count] = FileInfo{
                        .name = [_]u8{0} ** 12,
                        .name_len = @intCast(name.len),
                        .is_dir = dir_entry.isDirectory(),
                        .size = dir_entry.file_size,
                        .cluster = dir_entry.getCluster(),
                        .attr = dir_entry.attr,
                    };

                    for (name, 0..) |c, j| {
                        entries[entry_count].name[j] = c;
                    }

                    entry_count += 1;
                }
            } else |_| {
                return entry_count;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return entry_count;
}

pub fn listRoot(entries: []FileInfo) usize {
    if (!fs.mounted) return 0;
    return readDirectory(fs.root_cluster, entries);
}

// ============================================================================
// File Read Operations
// ============================================================================

pub fn readFile(cluster: u32, buffer: []u8) usize {
    if (!fs.mounted) return 0;

    var bytes_read: usize = 0;
    var current_cluster = cluster;

    while (!isEndOfChain(current_cluster) and bytes_read < buffer.len) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster) : (sector += 1) {
            if (bytes_read >= buffer.len) break;

            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                const remaining = buffer.len - bytes_read;
                const to_copy = if (remaining < 512) remaining else 512;

                for (sector_buffer[0..to_copy], 0..) |byte, i| {
                    buffer[bytes_read + i] = byte;
                }
                bytes_read += to_copy;
            } else |_| {
                return bytes_read;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return bytes_read;
}

/// Read file at specific offset
pub fn readFileAt(cluster: u32, offset: u64, buffer: []u8, file_size: u64) usize {
    if (!fs.mounted) return 0;
    if (offset >= file_size) return 0;

    const bytes_per_cluster = fs.getBytesPerCluster();

    // Skip to the cluster containing offset
    var current_cluster = cluster;
    const target_cluster_idx = offset / bytes_per_cluster;

    var idx: u64 = 0;
    while (idx < target_cluster_idx) : (idx += 1) {
        const next = readFatEntry(current_cluster) orelse return 0;
        if (isEndOfChain(next)) return 0;
        current_cluster = next;
    }

    // Calculate offset within cluster
    const offset_in_cluster = offset % bytes_per_cluster;
    const max_to_read = @min(buffer.len, file_size - offset);

    var bytes_read: usize = 0;
    var first_sector = true;
    const start_sector_in_cluster: u32 = @intCast(offset_in_cluster / 512);
    const offset_in_sector: usize = @intCast(offset_in_cluster % 512);

    while (bytes_read < max_to_read and !isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);
        const start_sec: u32 = if (first_sector) start_sector_in_cluster else 0;

        var sector: u32 = start_sec;
        while (sector < fs.sectors_per_cluster and bytes_read < max_to_read) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                const sec_offset: usize = if (first_sector and sector == start_sec) offset_in_sector else 0;
                first_sector = false;

                const remaining = max_to_read - bytes_read;
                const avail = 512 - sec_offset;
                const to_copy = @min(remaining, avail);

                for (sector_buffer[sec_offset..][0..to_copy], 0..) |byte, i| {
                    buffer[bytes_read + i] = byte;
                }
                bytes_read += to_copy;
            } else |_| {
                return bytes_read;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return bytes_read;
}

pub fn findFile(dir_cluster: u32, name: []const u8) ?FileInfo {
    var entries: [64]FileInfo = undefined;
    const count = readDirectory(dir_cluster, &entries);

    for (entries[0..count]) |entry| {
        if (strEqualNoCase(entry.getName(), name)) {
            return entry;
        }
    }

    return null;
}

pub fn findInRoot(name: []const u8) ?FileInfo {
    if (!fs.mounted) return null;
    return findFile(fs.root_cluster, name);
}

// ============================================================================
// File Write Operations (B2.2)
// ============================================================================

/// Create a new file with initial data
pub fn createFile(name: []const u8, data: []const u8) bool {
    if (!fs.mounted) return false;

    serial.writeString("[FAT32] Creating file: ");
    serial.writeString(name);
    serial.writeString("\n");

    // Check if file already exists
    if (findInRoot(name) != null) {
        serial.writeString("[FAT32] File already exists!\n");
        return false;
    }

    // Allocate cluster chain for data
    const cluster = allocateClusterChain(@intCast(data.len)) orelse {
        serial.writeString("[FAT32] No free clusters!\n");
        return false;
    };

    // Write data to clusters
    if (!writeToClusterChain(cluster, data)) {
        freeClusterChain(cluster);
        serial.writeString("[FAT32] Write failed!\n");
        return false;
    }

    // Add directory entry
    if (!addDirEntry(fs.root_cluster, name, cluster, @intCast(data.len), ATTR_ARCHIVE)) {
        freeClusterChain(cluster);
        serial.writeString("[FAT32] Failed to create directory entry!\n");
        return false;
    }

    serial.writeString("[FAT32] File created successfully\n");
    return true;
}

/// Write data to a cluster chain
fn writeToClusterChain(start_cluster: u32, data: []const u8) bool {
    var current_cluster = start_cluster;
    var written: usize = 0;

    while (written < data.len and !isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster and written < data.len) : (sector += 1) {
            // Clear sector buffer
            for (&sector_buffer) |*b| b.* = 0;

            // Copy data to buffer
            const remaining = data.len - written;
            const to_copy = if (remaining < 512) remaining else 512;
            for (data[written..][0..to_copy], 0..) |byte, i| {
                sector_buffer[i] = byte;
            }
            written += to_copy;

            // Write sector
            if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                // OK
            } else |_| {
                return false;
            }
        }

        if (written < data.len) {
            if (readFatEntry(current_cluster)) |next| {
                current_cluster = next;
            } else {
                break;
            }
        }
    }

    return written >= data.len;
}

/// Write data to file at specific offset (for VFS write)
pub fn writeFileAt(cluster: u32, offset: u64, data: []const u8, current_size: u64) WriteResult {
    if (!fs.mounted) return .{ .bytes_written = 0, .new_size = current_size };

    const new_end = offset + data.len;
    const bytes_per_cluster = fs.getBytesPerCluster();

    // Extend cluster chain if needed
    if (new_end > current_size) {
        if (!extendClusterChain(cluster, @intCast(current_size), @intCast(new_end))) {
            return .{ .bytes_written = 0, .new_size = current_size };
        }
    }

    // Navigate to correct cluster
    var current_cluster = cluster;
    const target_cluster_idx = offset / bytes_per_cluster;

    var idx: u64 = 0;
    while (idx < target_cluster_idx) : (idx += 1) {
        const next = readFatEntry(current_cluster) orelse {
            return .{ .bytes_written = 0, .new_size = current_size };
        };
        if (isEndOfChain(next)) {
            return .{ .bytes_written = 0, .new_size = current_size };
        }
        current_cluster = next;
    }

    // Write data
    var bytes_written: usize = 0;
    const offset_in_cluster = offset % bytes_per_cluster;
    var first_sector = true;
    const start_sector_in_cluster: u32 = @intCast(offset_in_cluster / 512);
    const offset_in_sector: usize = @intCast(offset_in_cluster % 512);

    while (bytes_written < data.len and !isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);
        const start_sec: u32 = if (first_sector) start_sector_in_cluster else 0;

        var sector: u32 = start_sec;
        while (sector < fs.sectors_per_cluster and bytes_written < data.len) : (sector += 1) {
            const sec_offset: usize = if (first_sector and sector == start_sec) offset_in_sector else 0;
            first_sector = false;

            // Read existing sector if partial write
            if (sec_offset > 0 or (data.len - bytes_written) < 512) {
                if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                    // OK
                } else |_| {
                    // Sector may not exist yet, clear it
                    for (&sector_buffer) |*b| b.* = 0;
                }
            } else {
                for (&sector_buffer) |*b| b.* = 0;
            }

            // Copy data
            const remaining = data.len - bytes_written;
            const avail = 512 - sec_offset;
            const to_copy = @min(remaining, avail);

            for (data[bytes_written..][0..to_copy], 0..) |byte, i| {
                sector_buffer[sec_offset + i] = byte;
            }
            bytes_written += to_copy;

            // Write sector
            if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                // OK
            } else |_| {
                break;
            }
        }

        if (bytes_written < data.len) {
            if (readFatEntry(current_cluster)) |next| {
                current_cluster = next;
            } else {
                break;
            }
        }
    }

    const final_size = @max(current_size, offset + bytes_written);
    return .{ .bytes_written = bytes_written, .new_size = final_size };
}

pub const WriteResult = struct {
    bytes_written: usize,
    new_size: u64,
};

/// Update an existing file with new data (overwrite)
pub fn updateFile(name: []const u8, data: []const u8) bool {
    if (!fs.mounted) return false;

    const file = findInRoot(name) orelse return false;

    // Free old cluster chain
    if (file.cluster >= 2) {
        freeClusterChain(file.cluster);
    }

    // Allocate new cluster chain
    const new_cluster = allocateClusterChain(@intCast(data.len)) orelse return false;

    // Write data
    if (!writeToClusterChain(new_cluster, data)) {
        freeClusterChain(new_cluster);
        return false;
    }

    // Update directory entry
    return updateDirEntry(fs.root_cluster, name, new_cluster, @intCast(data.len));
}

/// Update file size in directory entry
pub fn updateFileSize(name: []const u8, new_size: u32) bool {
    if (!fs.mounted) return false;

    var current_cluster = fs.root_cluster;

    while (!isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                var i: usize = 0;
                while (i < ENTRIES_PER_SECTOR) : (i += 1) {
                    const offset = i * DIR_ENTRY_SIZE;
                    var dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty()) return false;
                    if (dir_entry.isDeleted() or dir_entry.isLongName()) continue;

                    var name_buf: [12]u8 = undefined;
                    const entry_name = dir_entry.getName(&name_buf);

                    if (strEqualNoCase(entry_name, name)) {
                        dir_entry.file_size = new_size;
                        writeDirEntryToBuffer(&sector_buffer, offset, &dir_entry);

                        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                            return true;
                        } else |_| {
                            return false;
                        }
                    }
                }
            } else |_| {
                return false;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return false;
}

fn updateDirEntry(dir_cluster: u32, name: []const u8, new_cluster: u32, new_size: u32) bool {
    var current_cluster = dir_cluster;

    while (!isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                var i: usize = 0;
                while (i < ENTRIES_PER_SECTOR) : (i += 1) {
                    const offset = i * DIR_ENTRY_SIZE;
                    var dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty()) return false;
                    if (dir_entry.isDeleted() or dir_entry.isLongName()) continue;

                    var name_buf: [12]u8 = undefined;
                    const entry_name = dir_entry.getName(&name_buf);

                    if (strEqualNoCase(entry_name, name)) {
                        dir_entry.setCluster(new_cluster);
                        dir_entry.file_size = new_size;
                        writeDirEntryToBuffer(&sector_buffer, offset, &dir_entry);

                        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                            return true;
                        } else |_| {
                            return false;
                        }
                    }
                }
            } else |_| {
                return false;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return false;
}

fn addDirEntry(dir_cluster: u32, name: []const u8, cluster: u32, size: u32, attr: u8) bool {
    var current_cluster = dir_cluster;

    while (!isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                var i: usize = 0;
                while (i < ENTRIES_PER_SECTOR) : (i += 1) {
                    const offset = i * DIR_ENTRY_SIZE;
                    var dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty() or dir_entry.isDeleted()) {
                        formatDirEntry(&dir_entry, name, cluster, size, attr);
                        writeDirEntryToBuffer(&sector_buffer, offset, &dir_entry);

                        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                            return true;
                        } else |_| {
                            return false;
                        }
                    }
                }
            } else |_| {
                return false;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return false;
}

fn formatDirEntry(entry: *DirEntry, name: []const u8, cluster: u32, size: u32, attr: u8) void {
    const ptr = @as([*]u8, @ptrCast(entry));
    for (ptr[0..@sizeOf(DirEntry)]) |*b| b.* = 0;

    var name_part: [8]u8 = [_]u8{' '} ** 8;
    var ext_part: [3]u8 = [_]u8{' '} ** 3;

    var dot_pos: ?usize = null;
    for (name, 0..) |c, i| {
        if (c == '.') {
            dot_pos = i;
            break;
        }
    }

    const name_end = dot_pos orelse name.len;
    const copy_len = if (name_end > 8) 8 else name_end;
    for (name[0..copy_len], 0..) |c, i| {
        name_part[i] = toUpper(c);
    }

    if (dot_pos) |pos| {
        if (pos + 1 < name.len) {
            const ext = name[pos + 1 ..];
            const ext_len = if (ext.len > 3) 3 else ext.len;
            for (ext[0..ext_len], 0..) |c, i| {
                ext_part[i] = toUpper(c);
            }
        }
    }

    entry.name = name_part;
    entry.ext = ext_part;
    entry.attr = if (attr == 0) ATTR_ARCHIVE else attr;
    entry.setCluster(cluster);
    entry.file_size = size;
}

// ============================================================================
// Directory Creation (B2.2)
// ============================================================================

/// Create a subdirectory in root
pub fn createDirectory(name: []const u8) bool {
    if (!fs.mounted) return false;

    serial.writeString("[FAT32] Creating directory: ");
    serial.writeString(name);
    serial.writeString("\n");

    // Check if already exists
    if (findInRoot(name) != null) {
        serial.writeString("[FAT32] Already exists!\n");
        return false;
    }

    // Allocate cluster for directory
    const cluster = findFreeCluster() orelse {
        serial.writeString("[FAT32] No free clusters!\n");
        return false;
    };

    if (!writeFatEntry(cluster, FAT_END_OF_CHAIN)) {
        return false;
    }

    // Initialize directory cluster with . and .. entries
    if (!initDirectoryCluster(cluster, fs.root_cluster)) {
        _ = writeFatEntry(cluster, FAT_FREE);
        return false;
    }

    // Add entry to root directory
    if (!addDirEntry(fs.root_cluster, name, cluster, 0, ATTR_DIRECTORY)) {
        _ = writeFatEntry(cluster, FAT_FREE);
        serial.writeString("[FAT32] Failed to create directory entry!\n");
        return false;
    }

    serial.writeString("[FAT32] Directory created successfully\n");
    return true;
}

fn initDirectoryCluster(cluster: u32, parent_cluster: u32) bool {
    const lba = clusterToLba(cluster);

    // Clear all sectors in cluster
    for (&sector_buffer) |*b| b.* = 0;

    var sector: u32 = 0;
    while (sector < fs.sectors_per_cluster) : (sector += 1) {
        if (sector == 0) {
            // First sector contains . and .. entries
            var dot_entry: DirEntry = undefined;
            formatDirEntry(&dot_entry, ".", cluster, 0, ATTR_DIRECTORY);
            writeDirEntryToBuffer(&sector_buffer, 0, &dot_entry);

            var dotdot_entry: DirEntry = undefined;
            formatDirEntry(&dotdot_entry, "..", parent_cluster, 0, ATTR_DIRECTORY);
            writeDirEntryToBuffer(&sector_buffer, DIR_ENTRY_SIZE, &dotdot_entry);
        }

        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
            // Clear for next sector
            for (&sector_buffer) |*b| b.* = 0;
        } else |_| {
            return false;
        }
    }

    return true;
}

// ============================================================================
// Delete Operations
// ============================================================================

pub fn deleteFile(name: []const u8) bool {
    if (!fs.mounted) return false;

    const file = findInRoot(name) orelse {
        serial.writeString("[FAT32] File not found: ");
        serial.writeString(name);
        serial.writeString("\n");
        return false;
    };

    // Free cluster chain
    if (file.cluster >= 2) {
        freeClusterChain(file.cluster);
    }

    // Mark directory entry as deleted
    if (markDeleted(fs.root_cluster, name)) {
        serial.writeString("[FAT32] Deleted: ");
        serial.writeString(name);
        serial.writeString("\n");
        return true;
    }

    return false;
}

/// Delete directory (must be empty)
pub fn deleteDirectory(name: []const u8) bool {
    if (!fs.mounted) return false;

    const dir = findInRoot(name) orelse return false;
    if (!dir.is_dir) return false;

    // Check if directory is empty (only . and ..)
    var entries: [4]FileInfo = undefined;
    const count = readDirectory(dir.cluster, &entries);

    // Should only have . and .. or be completely empty
    var real_count: usize = 0;
    for (entries[0..count]) |entry| {
        const ename = entry.getName();
        if (ename.len == 1 and ename[0] == '.') continue;
        if (ename.len == 2 and ename[0] == '.' and ename[1] == '.') continue;
        real_count += 1;
    }

    if (real_count > 0) {
        serial.writeString("[FAT32] Directory not empty!\n");
        return false;
    }

    // Free cluster
    if (dir.cluster >= 2) {
        freeClusterChain(dir.cluster);
    }

    // Mark deleted
    return markDeleted(fs.root_cluster, name);
}

fn markDeleted(dir_cluster: u32, name: []const u8) bool {
    var current_cluster = dir_cluster;

    while (!isEndOfChain(current_cluster)) {
        const lba = clusterToLba(current_cluster);

        var sector: u32 = 0;
        while (sector < fs.sectors_per_cluster) : (sector += 1) {
            if (ata.readSector(fs.drive_index, lba + sector, &sector_buffer)) {
                var i: usize = 0;
                while (i < ENTRIES_PER_SECTOR) : (i += 1) {
                    const offset = i * DIR_ENTRY_SIZE;
                    const dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty()) return false;
                    if (dir_entry.isDeleted() or dir_entry.isLongName()) continue;

                    var name_buf: [12]u8 = undefined;
                    const entry_name = dir_entry.getName(&name_buf);

                    if (strEqualNoCase(entry_name, name)) {
                        sector_buffer[offset] = 0xE5;

                        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
                            return true;
                        } else |_| {
                            return false;
                        }
                    }
                }
            } else |_| {
                return false;
            }
        }

        if (readFatEntry(current_cluster)) |next| {
            current_cluster = next;
        } else {
            break;
        }
    }

    return false;
}

// ============================================================================
// Public API
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn isMounted() bool {
    return fs.mounted;
}

pub fn getRootCluster() u32 {
    return fs.root_cluster;
}

pub fn getClusterCount() u32 {
    return fs.cluster_count;
}

pub fn getFreeClusterCount() u32 {
    if (!fs.mounted) return 0;

    var free: u32 = 0;
    var cluster: u32 = 2;
    while (cluster < fs.cluster_count + 2) : (cluster += 1) {
        if (readFatEntry(cluster)) |entry| {
            if (entry == FAT_FREE) {
                free += 1;
            }
        }
    }
    return free;
}

pub fn getBytesPerCluster() u32 {
    return fs.getBytesPerCluster();
}

// ============================================================================
// VFS Integration
// ============================================================================

const vfs = @import("vfs.zig");
const inode_mod = @import("inode.zig");
const dirent_mod = @import("dirent.zig");
const file_mod = @import("file.zig");

var fat32_filesystem: vfs.FileSystem = .{};
var fat32_root_inode: inode_mod.Inode = inode_mod.Inode.initDirectory(9000);
var fat32_dir_entry: dirent_mod.DirEntry = .{};

const MAX_FAT32_INODES: usize = 64;
var inode_pool: [MAX_FAT32_INODES]inode_mod.Inode = undefined;
var inode_pool_used: [MAX_FAT32_INODES]bool = [_]bool{false} ** MAX_FAT32_INODES;

// Track file metadata for VFS inodes
const InodeMeta = struct {
    cluster: u32,
    size: u64,
    name: [12]u8,
    name_len: u8,
};
var inode_meta: [MAX_FAT32_INODES]InodeMeta = undefined;

const fat32_inode_ops = inode_mod.InodeOps{
    .lookup = fat32VfsLookup,
    .readdir = fat32VfsReaddir,
    .create = fat32VfsCreate,
    .mkdir = fat32VfsMkdir,
    .unlink = fat32VfsUnlink,
    .rmdir = fat32VfsRmdir,
};

const fat32_file_ops = file_mod.FileOps{
    .read = fat32VfsRead,
    .write = fat32VfsWrite,
    .close = null,
    .seek = null,
    .flush = fat32VfsFlush,
};

fn allocInode(id: u64, file_type: inode_mod.FileType, size: u64, cluster: u32) ?*inode_mod.Inode {
    var i: usize = 0;
    while (i < MAX_FAT32_INODES) : (i += 1) {
        if (!inode_pool_used[i]) {
            inode_pool_used[i] = true;
            inode_pool[i] = inode_mod.Inode.init(id, file_type);
            inode_pool[i].size = size;
            inode_pool[i].ops = &fat32_inode_ops;
            inode_pool[i].dev_major = @intCast((cluster >> 16) & 0xFFFF);
            inode_pool[i].dev_minor = @intCast(cluster & 0xFFFF);
            return &inode_pool[i];
        }
    }
    return null;
}

fn allocInodeWithMeta(id: u64, file_type: inode_mod.FileType, size: u64, cluster: u32, name: []const u8) ?*inode_mod.Inode {
    var i: usize = 0;
    while (i < MAX_FAT32_INODES) : (i += 1) {
        if (!inode_pool_used[i]) {
            inode_pool_used[i] = true;
            inode_pool[i] = inode_mod.Inode.init(id, file_type);
            inode_pool[i].size = size;
            inode_pool[i].ops = &fat32_inode_ops;
            inode_pool[i].dev_major = @intCast((cluster >> 16) & 0xFFFF);
            inode_pool[i].dev_minor = @intCast(cluster & 0xFFFF);

            // Store metadata
            inode_meta[i].cluster = cluster;
            inode_meta[i].size = size;
            inode_meta[i].name_len = @intCast(@min(name.len, 12));
            for (name[0..inode_meta[i].name_len], 0..) |c, j| {
                inode_meta[i].name[j] = c;
            }

            return &inode_pool[i];
        }
    }
    return null;
}

fn getInodeIndex(ino: *inode_mod.Inode) ?usize {
    const addr = @intFromPtr(ino);
    const base = @intFromPtr(&inode_pool[0]);
    const size = @sizeOf(inode_mod.Inode);

    if (addr < base) return null;
    const offset = addr - base;
    if (offset % size != 0) return null;
    const idx = offset / size;
    if (idx >= MAX_FAT32_INODES) return null;
    return idx;
}

fn getInodeCluster(ino: *inode_mod.Inode) u32 {
    return (@as(u32, ino.dev_major) << 16) | @as(u32, ino.dev_minor);
}

fn getInodeName(ino: *inode_mod.Inode) ?[]const u8 {
    const idx = getInodeIndex(ino) orelse return null;
    if (!inode_pool_used[idx]) return null;
    return inode_meta[idx].name[0..inode_meta[idx].name_len];
}

fn freeAllInodes() void {
    var i: usize = 0;
    while (i < MAX_FAT32_INODES) : (i += 1) {
        inode_pool_used[i] = false;
    }
}

fn fat32VfsLookup(parent: *inode_mod.Inode, name: []const u8) ?*inode_mod.Inode {
    _ = parent;
    if (!fs.mounted) return null;

    freeAllInodes();

    const file_info = findInRoot(name) orelse return null;

    const ftype: inode_mod.FileType = if (file_info.is_dir) .Directory else .Regular;
    return allocInodeWithMeta(
        @as(u64, file_info.cluster),
        ftype,
        @as(u64, file_info.size),
        file_info.cluster,
        file_info.getName(),
    );
}

fn fat32VfsReaddir(inode: *inode_mod.Inode, index: usize) ?*dirent_mod.DirEntry {
    _ = inode;
    if (!fs.mounted) return null;

    var entries: [64]FileInfo = undefined;
    const count = listRoot(&entries);

    if (index >= count) return null;

    const entry = &entries[index];

    fat32_dir_entry = .{};
    fat32_dir_entry.setName(entry.getName());
    fat32_dir_entry.file_type = if (entry.is_dir) .Directory else .Regular;
    fat32_dir_entry.ino = @as(u64, entry.cluster);

    return &fat32_dir_entry;
}

fn fat32VfsCreate(parent: *inode_mod.Inode, name: []const u8, mode: inode_mod.FileMode) ?*inode_mod.Inode {
    _ = parent;
    _ = mode;
    if (!fs.mounted) return null;

    // Create empty file
    if (!createFile(name, "")) return null;

    // Find and return inode
    const file_info = findInRoot(name) orelse return null;
    return allocInodeWithMeta(
        @as(u64, file_info.cluster),
        .Regular,
        0,
        file_info.cluster,
        name,
    );
}

fn fat32VfsMkdir(parent: *inode_mod.Inode, name: []const u8, mode: inode_mod.FileMode) ?*inode_mod.Inode {
    _ = parent;
    _ = mode;
    if (!fs.mounted) return null;

    if (!createDirectory(name)) return null;

    const dir_info = findInRoot(name) orelse return null;
    return allocInodeWithMeta(
        @as(u64, dir_info.cluster),
        .Directory,
        0,
        dir_info.cluster,
        name,
    );
}

fn fat32VfsUnlink(parent: *inode_mod.Inode, name: []const u8) bool {
    _ = parent;
    return deleteFile(name);
}

fn fat32VfsRmdir(parent: *inode_mod.Inode, name: []const u8) bool {
    _ = parent;
    return deleteDirectory(name);
}

fn fat32VfsRead(file: *file_mod.File, buf: []u8) i64 {
    if (!fs.mounted) return -1;

    const cluster = getInodeCluster(file.inode);
    if (cluster < 2) return -1;

    const file_size = file.inode.size;
    const pos = file.position;

    if (pos >= file_size) return 0;

    const bytes = readFileAt(cluster, pos, buf, file_size);
    file.position += bytes;

    return @intCast(bytes);
}

fn fat32VfsWrite(file: *file_mod.File, buf: []const u8) i64 {
    if (!fs.mounted) return -1;

    const cluster = getInodeCluster(file.inode);
    if (cluster < 2) return -1;

    const pos = file.position;
    const current_size = file.inode.size;

    const result = writeFileAt(cluster, pos, buf, current_size);

    if (result.bytes_written > 0) {
        file.position += result.bytes_written;
        file.inode.size = result.new_size;

        // Update file size in directory entry
        const name = getInodeName(file.inode);
        if (name) |n| {
            _ = updateFileSize(n, @intCast(result.new_size));
        }
    }

    return @intCast(result.bytes_written);
}

fn fat32VfsFlush(file: *file_mod.File) bool {
    _ = file;
    // ATA writes are synchronous, nothing to flush
    return true;
}

pub fn mountToVfs() bool {
    if (!fs.mounted) {
        serial.writeString("[FAT32] Cannot mount to VFS - not mounted\n");
        return false;
    }

    fat32_filesystem = .{};
    fat32_filesystem.setName("fat32");
    fat32_filesystem.file_ops = &fat32_file_ops;

    fat32_root_inode = inode_mod.Inode.initDirectory(9000);
    fat32_root_inode.ops = &fat32_inode_ops;
    fat32_filesystem.root = &fat32_root_inode;

    if (vfs.mount("/disk", &fat32_filesystem)) {
        serial.writeString("[FAT32] Mounted to VFS at /disk\n");
        return true;
    } else {
        serial.writeString("[FAT32] Failed to mount to VFS!\n");
        return false;
    }
}

pub fn getFilesystem() *vfs.FileSystem {
    return &fat32_filesystem;
}

// ============================================================================
// Test
// ============================================================================

pub fn test_fat32() bool {
    serial.writeString("[FAT32] Running tests...\n");

    if (!fs.mounted) {
        serial.writeString("  Not mounted - SKIP\n");
        return true;
    }

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: List root
    serial.writeString("  [1] List root directory...\n");
    var entries: [32]FileInfo = undefined;
    const count = listRoot(&entries);
    serial.writeString("      Found ");
    printU32(@intCast(count));
    serial.writeString(" entries\n");
    passed += 1;

    // Test 2: Create file
    serial.writeString("  [2] Create test file...\n");
    const test_name = "B22TEST.TXT";
    const test_data = "B2.2 FAT32 Write Test!\n";

    // Delete if exists
    _ = deleteFile(test_name);

    if (createFile(test_name, test_data)) {
        passed += 1;
        serial.writeString("      Created OK\n");
    } else {
        failed += 1;
        serial.writeString("      Create FAILED\n");
    }

    // Test 3: Read back
    serial.writeString("  [3] Read back file...\n");
    if (findInRoot(test_name)) |file| {
        var read_buf: [64]u8 = [_]u8{0} ** 64;
        const bytes = readFile(file.cluster, &read_buf);
        if (bytes == test_data.len) {
            passed += 1;
            serial.writeString("      Read OK: ");
            serial.writeString(read_buf[0..bytes]);
        } else {
            failed += 1;
            serial.writeString("      Read size mismatch\n");
        }
    } else {
        failed += 1;
        serial.writeString("      File not found!\n");
    }

    // Test 4: Update file
    serial.writeString("  [4] Update file...\n");
    const new_data = "Updated content for B2.2 test.\n";
    if (updateFile(test_name, new_data)) {
        passed += 1;
        serial.writeString("      Update OK\n");
    } else {
        failed += 1;
        serial.writeString("      Update FAILED\n");
    }

    // Test 5: Verify update
    serial.writeString("  [5] Verify update...\n");
    if (findInRoot(test_name)) |file| {
        var read_buf: [64]u8 = [_]u8{0} ** 64;
        const bytes = readFile(file.cluster, &read_buf);
        if (bytes == new_data.len) {
            passed += 1;
            serial.writeString("      Verify OK\n");
        } else {
            failed += 1;
            serial.writeString("      Verify FAILED\n");
        }
    } else {
        failed += 1;
    }

    // Test 6: Create directory
    serial.writeString("  [6] Create directory...\n");
    const dir_name = "TESTDIR";
    _ = deleteDirectory(dir_name);
    if (createDirectory(dir_name)) {
        passed += 1;
        serial.writeString("      Directory created OK\n");
    } else {
        failed += 1;
        serial.writeString("      Directory create FAILED\n");
    }

    // Test 7: Delete directory
    serial.writeString("  [7] Delete directory...\n");
    if (deleteDirectory(dir_name)) {
        passed += 1;
        serial.writeString("      Directory deleted OK\n");
    } else {
        failed += 1;
        serial.writeString("      Directory delete FAILED\n");
    }

    // Test 8: Delete test file
    serial.writeString("  [8] Delete test file...\n");
    if (deleteFile(test_name)) {
        passed += 1;
        serial.writeString("      Delete OK\n");
    } else {
        failed += 1;
        serial.writeString("      Delete FAILED\n");
    }

    // Summary
    serial.writeString("  FAT32 B2.2 Tests: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");

    return failed == 0;
}

// ============================================================================
// Utility Functions
// ============================================================================

fn readU16LE(data: []const u8, offset: usize) u16 {
    return @as(u16, data[offset]) | (@as(u16, data[offset + 1]) << 8);
}

fn readU32LE(data: []const u8, offset: usize) u32 {
    return @as(u32, data[offset]) |
        (@as(u32, data[offset + 1]) << 8) |
        (@as(u32, data[offset + 2]) << 16) |
        (@as(u32, data[offset + 3]) << 24);
}

fn writeU32LE(data: []u8, offset: usize, value: u32) void {
    data[offset] = @intCast(value & 0xFF);
    data[offset + 1] = @intCast((value >> 8) & 0xFF);
    data[offset + 2] = @intCast((value >> 16) & 0xFF);
    data[offset + 3] = @intCast((value >> 24) & 0xFF);
}

fn strEqualNoCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toUpper(ca) != toUpper(cb)) return false;
    }
    return true;
}

fn toUpper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
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
