//! Zamrud OS - Device File System (DevFS)
//! Provides /dev directory with device files

const serial = @import("../drivers/serial/serial.zig");
const heap = @import("../mm/heap.zig");
const vfs = @import("vfs.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_DEVICES: usize = 32;

// =============================================================================
// Device Types
// =============================================================================

pub const DeviceType = enum(u8) {
    Null = 0,
    Zero = 1,
    Serial = 2,
    Random = 3,
    Console = 4,
};

// =============================================================================
// Device Entry
// =============================================================================

pub const DeviceEntry = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    device_type: DeviceType = .Null,
    inode: vfs.Inode = .{},
    in_use: bool = false,

    pub fn getName(self: *const DeviceEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *DeviceEntry, new_name: []const u8) void {
        const len = @min(new_name.len, 31);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = new_name[i];
        }
        self.name_len = @intCast(len);
    }
};

// =============================================================================
// Global State
// =============================================================================

var devices: [MAX_DEVICES]DeviceEntry = undefined;
var device_count: usize = 0;
var root_inode: vfs.Inode = undefined;
var filesystem: vfs.FileSystem = undefined;
var next_inode_id: u64 = 1000;
var initialized: bool = false;

var static_dirent: vfs.DirEntry = undefined;

var random_seed: u32 = 12345;

// =============================================================================
// Device Operations - Null Device
// =============================================================================

fn nullRead(file: *vfs.File, buf: []u8) i64 {
    _ = file;
    _ = buf;
    return 0;
}

fn nullWrite(file: *vfs.File, buf: []const u8) i64 {
    _ = file;
    return @intCast(buf.len);
}

// =============================================================================
// Device Operations - Zero Device
// =============================================================================

fn zeroRead(file: *vfs.File, buf: []u8) i64 {
    _ = file;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        buf[i] = 0;
    }
    return @intCast(buf.len);
}

fn zeroWrite(file: *vfs.File, buf: []const u8) i64 {
    _ = file;
    return @intCast(buf.len);
}

// =============================================================================
// Device Operations - Serial Device
// =============================================================================

fn serialRead(file: *vfs.File, buf: []u8) i64 {
    _ = file;
    _ = buf;
    return 0;
}

fn serialWrite(file: *vfs.File, buf: []const u8) i64 {
    _ = file;
    serial.writeString(buf);
    return @intCast(buf.len);
}

// =============================================================================
// Device Operations - Random Device
// =============================================================================

fn randomRead(file: *vfs.File, buf: []u8) i64 {
    _ = file;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        random_seed = random_seed *% 1103515245 +% 12345;
        buf[i] = @truncate((random_seed >> 16) & 0xFF);
    }
    return @intCast(buf.len);
}

fn randomWrite(file: *vfs.File, buf: []const u8) i64 {
    _ = file;
    if (buf.len >= 4) {
        random_seed = @as(u32, buf[0]) |
            (@as(u32, buf[1]) << 8) |
            (@as(u32, buf[2]) << 16) |
            (@as(u32, buf[3]) << 24);
    }
    return @intCast(buf.len);
}

// =============================================================================
// Device Operations - Console Device
// =============================================================================

fn consoleRead(file: *vfs.File, buf: []u8) i64 {
    _ = file;
    _ = buf;
    return 0;
}

fn consoleWrite(file: *vfs.File, buf: []const u8) i64 {
    _ = file;
    serial.writeString(buf);
    return @intCast(buf.len);
}

// =============================================================================
// Generic Device File Operations
// =============================================================================

fn devfsRead(file: *vfs.File, buf: []u8) i64 {
    const dev = getDeviceFromInode(file.inode) orelse return -1;

    return switch (dev.device_type) {
        .Null => nullRead(file, buf),
        .Zero => zeroRead(file, buf),
        .Serial => serialRead(file, buf),
        .Random => randomRead(file, buf),
        .Console => consoleRead(file, buf),
    };
}

fn devfsWrite(file: *vfs.File, buf: []const u8) i64 {
    const dev = getDeviceFromInode(file.inode) orelse return -1;

    return switch (dev.device_type) {
        .Null => nullWrite(file, buf),
        .Zero => zeroWrite(file, buf),
        .Serial => serialWrite(file, buf),
        .Random => randomWrite(file, buf),
        .Console => consoleWrite(file, buf),
    };
}

fn devfsSeek(file: *vfs.File, offset: i64, whence: vfs.SeekWhence) i64 {
    _ = file;
    _ = offset;
    _ = whence;
    return 0;
}

fn devfsClose(file: *vfs.File) void {
    _ = file;
}

const devfs_file_ops = vfs.FileOps{
    .read = &devfsRead,
    .write = &devfsWrite,
    .seek = &devfsSeek,
    .close = &devfsClose,
};

// =============================================================================
// Inode Operations
// =============================================================================

fn devfsLookup(inode: *vfs.Inode, name: []const u8) ?*vfs.Inode {
    _ = inode;

    var i: usize = 0;
    while (i < MAX_DEVICES) : (i += 1) {
        if (devices[i].in_use) {
            if (strEqual(devices[i].getName(), name)) {
                return &devices[i].inode;
            }
        }
    }

    return null;
}

fn devfsReaddir(inode: *vfs.Inode, index: usize) ?*vfs.DirEntry {
    _ = inode;

    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_DEVICES) : (i += 1) {
        if (devices[i].in_use) {
            if (count == index) {
                static_dirent.setName(devices[i].getName());
                static_dirent.inode = &devices[i].inode;
                static_dirent.file_type = .CharDevice;
                return &static_dirent;
            }
            count += 1;
        }
    }

    return null;
}

const devfs_inode_ops = vfs.InodeOps{
    .lookup = &devfsLookup,
    .create = null,
    .mkdir = null,
    .unlink = null,
    .rmdir = null,
    .readdir = &devfsReaddir,
};

// =============================================================================
// Helper Functions
// =============================================================================

fn getDeviceFromInode(inode: *vfs.Inode) ?*DeviceEntry {
    var i: usize = 0;
    while (i < MAX_DEVICES) : (i += 1) {
        if (devices[i].in_use and &devices[i].inode == inode) {
            return &devices[i];
        }
    }
    return null;
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn allocDevice() ?*DeviceEntry {
    var i: usize = 0;
    while (i < MAX_DEVICES) : (i += 1) {
        if (!devices[i].in_use) {
            devices[i].in_use = true;
            return &devices[i];
        }
    }
    return null;
}

fn registerDevice(name: []const u8, dev_type: DeviceType) bool {
    const dev = allocDevice() orelse return false;

    dev.setName(name);
    dev.device_type = dev_type;
    dev.inode.id = next_inode_id;
    next_inode_id += 1;
    dev.inode.file_type = .CharDevice;
    dev.inode.mode = vfs.FileMode.regular();
    dev.inode.size = 0;
    dev.inode.link_count = 1;
    dev.inode.fs_data = @ptrCast(dev);
    dev.inode.ops = &devfs_inode_ops;

    device_count += 1;

    serial.writeString("[DEVFS] Registered: /dev/");
    serial.writeString(name);
    serial.writeString("\n");

    return true;
}

// =============================================================================
// Public API
// =============================================================================

pub fn init() bool {
    serial.writeString("[DEVFS] Initializing...\n");

    var i: usize = 0;
    while (i < MAX_DEVICES) : (i += 1) {
        devices[i].in_use = false;
        devices[i].name_len = 0;
    }
    device_count = 0;

    root_inode.id = next_inode_id;
    next_inode_id += 1;
    root_inode.file_type = .Directory;
    root_inode.mode = vfs.FileMode.directory();
    root_inode.size = 0;
    root_inode.link_count = 2;
    root_inode.fs_data = null;
    root_inode.ops = &devfs_inode_ops;

    i = 0;
    while (i < vfs.MAX_FILENAME) : (i += 1) {
        static_dirent.name[i] = 0;
    }

    if (!registerDevice("null", .Null)) return false;
    if (!registerDevice("zero", .Zero)) return false;
    if (!registerDevice("serial", .Serial)) return false;
    if (!registerDevice("random", .Random)) return false;
    if (!registerDevice("console", .Console)) return false;

    i = 0;
    while (i < 32) : (i += 1) {
        filesystem.name[i] = 0;
    }
    filesystem.name[0] = 'd';
    filesystem.name[1] = 'e';
    filesystem.name[2] = 'v';
    filesystem.name[3] = 'f';
    filesystem.name[4] = 's';
    filesystem.name_len = 5;
    filesystem.root = &root_inode;
    filesystem.ops = null;
    filesystem.file_ops = &devfs_file_ops;
    filesystem.fs_data = null;

    initialized = true;
    serial.writeString("[DEVFS] Initialized\n");

    return true;
}

pub fn getFileOps() *const vfs.FileOps {
    return &devfs_file_ops;
}

pub fn getRoot() *vfs.Inode {
    return &root_inode;
}

pub fn getFilesystem() *vfs.FileSystem {
    return &filesystem;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn getDeviceCount() usize {
    return device_count;
}

pub fn addDevice(name: []const u8, dev_type: DeviceType) bool {
    if (!initialized) return false;
    return registerDevice(name, dev_type);
}
