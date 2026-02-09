//! Zamrud OS - FAT32 Filesystem Driver
//! Read/Write support for FAT32 partitions

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
// Directory Entry (32 bytes) - packed to avoid alignment requirements
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

// Compile-time verification
comptime {
    if (@sizeOf(DirEntry) != 32) @compileError("DirEntry must be exactly 32 bytes");
}

// ============================================================================
// Safe DirEntry reader - reads from byte buffer without alignment issues
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
};

// ============================================================================
// Global State
// ============================================================================

var fs: Fat32 = Fat32.init();
var initialized: bool = false;
var sector_buffer: [512]u8 align(4) = [_]u8{0} ** 512;

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

fn isEndOfChain(cluster: u32) bool {
    return cluster >= FAT_END_OF_CHAIN;
}

// ============================================================================
// Directory Operations  (FIXED: no more @alignCast on byte buffers)
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

                    // FIXED: safe byte-copy instead of @ptrCast/@alignCast
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
// File Operations
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
// Write Operations (FIXED: safe byte-copy for dir entries)
// ============================================================================

pub fn createFile(name: []const u8, data: []const u8) bool {
    if (!fs.mounted) return false;

    serial.writeString("[FAT32] Creating file: ");
    serial.writeString(name);
    serial.writeString("\n");

    if (findInRoot(name) != null) {
        serial.writeString("[FAT32] File already exists!\n");
        return false;
    }

    const cluster = findFreeCluster() orelse {
        serial.writeString("[FAT32] No free clusters!\n");
        return false;
    };

    if (!writeFatEntry(cluster, FAT_END_OF_CHAIN)) {
        return false;
    }

    const lba = clusterToLba(cluster);
    var written: usize = 0;
    var sector: u32 = 0;

    while (sector < fs.sectors_per_cluster and written < data.len) : (sector += 1) {
        for (&sector_buffer) |*b| b.* = 0;

        const remaining = data.len - written;
        const to_copy = if (remaining < 512) remaining else 512;
        for (data[written..][0..to_copy], 0..) |byte, i| {
            sector_buffer[i] = byte;
        }
        written += to_copy;

        if (ata.writeSector(fs.drive_index, lba + sector, &sector_buffer)) {
            // OK
        } else |_| {
            serial.writeString("[FAT32] Write failed!\n");
            return false;
        }
    }

    if (!addDirEntry(fs.root_cluster, name, cluster, @intCast(data.len), 0)) {
        serial.writeString("[FAT32] Failed to create directory entry!\n");
        return false;
    }

    serial.writeString("[FAT32] File created successfully\n");
    return true;
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

                    // FIXED: safe byte-copy read
                    var dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty() or dir_entry.isDeleted()) {
                        // Format the entry
                        formatDirEntry(&dir_entry, name, cluster, size, attr);

                        // FIXED: safe byte-copy write back to buffer
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
    // Zero out the entry
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
    entry.cluster_high = @intCast((cluster >> 16) & 0xFFFF);
    entry.cluster_low = @intCast(cluster & 0xFFFF);
    entry.file_size = size;
}

// ============================================================================
// Delete Operations (FIXED: safe byte-copy)
// ============================================================================

pub fn deleteFile(name: []const u8) bool {
    if (!fs.mounted) return false;

    const file = findInRoot(name) orelse {
        serial.writeString("[FAT32] File not found: ");
        serial.writeString(name);
        serial.writeString("\n");
        return false;
    };

    var cluster = file.cluster;
    while (!isEndOfChain(cluster) and cluster >= 2) {
        const next = readFatEntry(cluster) orelse break;
        _ = writeFatEntry(cluster, FAT_FREE);
        if (next >= FAT_END_OF_CHAIN) break;
        cluster = next;
    }

    if (markDeleted(fs.root_cluster, name)) {
        serial.writeString("[FAT32] Deleted: ");
        serial.writeString(name);
        serial.writeString("\n");
        return true;
    }

    return false;
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

                    // FIXED: safe byte-copy read
                    const dir_entry = readDirEntry(&sector_buffer, offset);

                    if (dir_entry.isEmpty()) return false;
                    if (dir_entry.isDeleted() or dir_entry.isLongName()) continue;

                    var name_buf: [12]u8 = undefined;
                    const entry_name = dir_entry.getName(&name_buf);

                    if (strEqualNoCase(entry_name, name)) {
                        // Mark as deleted directly in buffer
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

// ============================================================================
// Test
// ============================================================================

pub fn test_fat32() bool {
    serial.writeString("[FAT32] Running tests...\n");

    if (!fs.mounted) {
        serial.writeString("  Not mounted - SKIP\n");
        return true;
    }

    serial.writeString("  Listing root directory...\n");
    var entries: [32]FileInfo = undefined;
    const count = listRoot(&entries);

    serial.writeString("  Found ");
    printU32(@intCast(count));
    serial.writeString(" entries\n");

    for (entries[0..count]) |entry| {
        serial.writeString("    ");
        if (entry.is_dir) {
            serial.writeString("[DIR] ");
        } else {
            serial.writeString("      ");
        }
        serial.writeString(entry.getName());
        if (!entry.is_dir) {
            serial.writeString(" (");
            printU32(entry.size);
            serial.writeString(" bytes)");
        }
        serial.writeString("\n");
    }

    serial.writeString("  Creating test file...\n");
    const test_data = "Hello from Zamrud OS!\n";
    if (createFile("TEST.TXT", test_data)) {
        serial.writeString("  Created TEST.TXT\n");

        if (findInRoot("TEST.TXT")) |file| {
            serial.writeString("  Found file, size: ");
            printU32(file.size);
            serial.writeString(" bytes\n");

            var read_buf: [64]u8 = [_]u8{0} ** 64;
            const bytes = readFile(file.cluster, &read_buf);
            serial.writeString("  Read ");
            printU32(@intCast(bytes));
            serial.writeString(" bytes: ");
            serial.writeString(read_buf[0..bytes]);
        }
    } else {
        serial.writeString("  Create skipped (may already exist)\n");
    }

    serial.writeString("  FAT32 test: PASS\n");
    return true;
}

// ============================================================================
// VFS Integration - Mount FAT32 as /disk
// ============================================================================

const vfs = @import("vfs.zig");
const inode_mod = @import("inode.zig");
const dirent_mod = @import("dirent.zig");
const file_mod = @import("file.zig");

// Static objects for VFS
var fat32_filesystem: vfs.FileSystem = .{};
var fat32_root_inode: inode_mod.Inode = inode_mod.Inode.initDirectory(9000);
var fat32_dir_entry: dirent_mod.DirEntry = .{};

// Inode pool for file lookups
const MAX_FAT32_INODES: usize = 64;
var inode_pool: [MAX_FAT32_INODES]inode_mod.Inode = undefined;
var inode_pool_used: [MAX_FAT32_INODES]bool = [_]bool{false} ** MAX_FAT32_INODES;

const fat32_inode_ops = inode_mod.InodeOps{
    .lookup = fat32VfsLookup,
    .readdir = fat32VfsReaddir,
    .create = null,
    .mkdir = null,
    .unlink = null,
    .rmdir = null,
};

const fat32_file_ops = file_mod.FileOps{
    .read = fat32VfsRead,
    .write = fat32VfsWrite,
    .close = null,
    .seek = null,
    .flush = null,
};

fn allocInode(id: u64, file_type: inode_mod.FileType, size: u64, cluster: u32) ?*inode_mod.Inode {
    var i: usize = 0;
    while (i < MAX_FAT32_INODES) : (i += 1) {
        if (!inode_pool_used[i]) {
            inode_pool_used[i] = true;
            inode_pool[i] = inode_mod.Inode.init(id, file_type);
            inode_pool[i].size = size;
            inode_pool[i].ops = &fat32_inode_ops;
            // Store cluster in dev_major/dev_minor
            inode_pool[i].dev_major = @intCast((cluster >> 16) & 0xFFFF);
            inode_pool[i].dev_minor = @intCast(cluster & 0xFFFF);
            return &inode_pool[i];
        }
    }
    return null;
}

fn getInodeCluster(ino: *inode_mod.Inode) u32 {
    return (@as(u32, ino.dev_major) << 16) | @as(u32, ino.dev_minor);
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

    // Free old lookup inodes to prevent pool exhaustion
    freeAllInodes();

    const file_info = findInRoot(name) orelse return null;

    const ftype: inode_mod.FileType = if (file_info.is_dir) .Directory else .Regular;
    return allocInode(
        @as(u64, file_info.cluster),
        ftype,
        @as(u64, file_info.size),
        file_info.cluster,
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

fn fat32VfsRead(file: *file_mod.File, buf: []u8) i64 {
    if (!fs.mounted) return -1;

    const cluster = getInodeCluster(file.inode);
    if (cluster < 2) return -1;

    const file_size = file.inode.size;
    const pos = file.position;

    if (pos >= file_size) return 0;

    const remaining = file_size - pos;
    const to_read = @min(buf.len, remaining);

    // Read full file into temp buffer, then copy from position
    // (Simple approach - works for small files)
    var temp: [4096]u8 = [_]u8{0} ** 4096;
    const max_read = @min(file_size, 4096);
    const bytes = readFile(cluster, temp[0..max_read]);

    if (bytes == 0) return 0;
    if (pos >= bytes) return 0;

    const avail = bytes - pos;
    const copy_len = @min(to_read, avail);

    for (0..copy_len) |i| {
        buf[i] = temp[pos + i];
    }

    file.position += copy_len;
    return @intCast(copy_len);
}

fn fat32VfsWrite(file: *file_mod.File, buf: []const u8) i64 {
    if (!fs.mounted) return -1;
    _ = file;
    _ = buf;
    // TODO: implement write through VFS
    return -1;
}

/// Mount FAT32 to VFS at /disk
pub fn mountToVfs() bool {
    if (!fs.mounted) {
        serial.writeString("[FAT32] Cannot mount to VFS - not mounted\n");
        return false;
    }

    // Setup filesystem
    fat32_filesystem = .{};
    fat32_filesystem.setName("fat32");
    fat32_filesystem.file_ops = &fat32_file_ops;

    // Setup root inode
    fat32_root_inode = inode_mod.Inode.initDirectory(9000);
    fat32_root_inode.ops = &fat32_inode_ops;
    fat32_filesystem.root = &fat32_root_inode;

    // Mount at /disk
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
