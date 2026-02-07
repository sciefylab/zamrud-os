//! Zamrud OS - Inode Structure
//! Core inode definitions for the Virtual File System

const vfs = @import("vfs.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_FILENAME: usize = 128;

// =============================================================================
// File Types
// =============================================================================

pub const FileType = enum(u8) {
    Regular = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Pipe = 5,
    Socket = 6,
    Symlink = 7,

    pub fn isDevice(self: FileType) bool {
        return self == .CharDevice or self == .BlockDevice;
    }

    pub fn toString(self: FileType) []const u8 {
        return switch (self) {
            .Regular => "regular",
            .Directory => "directory",
            .CharDevice => "chardev",
            .BlockDevice => "blockdev",
            .Pipe => "pipe",
            .Socket => "socket",
            .Symlink => "symlink",
        };
    }
};

// =============================================================================
// File Mode (Permissions)
// =============================================================================

pub const FileMode = packed struct(u16) {
    // Other permissions (bits 0-2)
    other_exec: bool = false,
    other_write: bool = false,
    other_read: bool = false,

    // Group permissions (bits 3-5)
    group_exec: bool = false,
    group_write: bool = false,
    group_read: bool = false,

    // Owner permissions (bits 6-8)
    owner_exec: bool = false,
    owner_write: bool = false,
    owner_read: bool = false,

    // Special bits (bits 9-11)
    sticky: bool = false,
    setgid: bool = false,
    setuid: bool = false,

    // File type (bits 12-15)
    file_type: u4 = 0,

    // Pre-defined modes
    pub const DIR_MODE: FileMode = .{
        .owner_read = true,
        .owner_write = true,
        .owner_exec = true,
        .group_read = true,
        .group_exec = true,
        .other_read = true,
        .other_exec = true,
    };

    pub const FILE_MODE: FileMode = .{
        .owner_read = true,
        .owner_write = true,
        .group_read = true,
        .other_read = true,
    };

    pub const EXEC_MODE: FileMode = .{
        .owner_read = true,
        .owner_write = true,
        .owner_exec = true,
        .group_read = true,
        .group_exec = true,
        .other_read = true,
        .other_exec = true,
    };

    pub const READONLY_MODE: FileMode = .{
        .owner_read = true,
        .group_read = true,
        .other_read = true,
    };

    pub fn directory() FileMode {
        return DIR_MODE;
    }

    pub fn regular() FileMode {
        return FILE_MODE;
    }

    pub fn executable() FileMode {
        return EXEC_MODE;
    }

    pub fn readonly() FileMode {
        return READONLY_MODE;
    }

    /// Check if owner can read
    pub fn canOwnerRead(self: FileMode) bool {
        return self.owner_read;
    }

    /// Check if owner can write
    pub fn canOwnerWrite(self: FileMode) bool {
        return self.owner_write;
    }

    /// Check if owner can execute
    pub fn canOwnerExec(self: FileMode) bool {
        return self.owner_exec;
    }

    /// Get numeric mode (like 0755)
    pub fn toOctal(self: FileMode) u16 {
        var mode: u16 = 0;

        if (self.owner_read) mode |= 0o400;
        if (self.owner_write) mode |= 0o200;
        if (self.owner_exec) mode |= 0o100;

        if (self.group_read) mode |= 0o040;
        if (self.group_write) mode |= 0o020;
        if (self.group_exec) mode |= 0o010;

        if (self.other_read) mode |= 0o004;
        if (self.other_write) mode |= 0o002;
        if (self.other_exec) mode |= 0o001;

        if (self.sticky) mode |= 0o1000;
        if (self.setgid) mode |= 0o2000;
        if (self.setuid) mode |= 0o4000;

        return mode;
    }

    /// Create from numeric mode
    pub fn fromOctal(mode: u16) FileMode {
        return FileMode{
            .owner_read = (mode & 0o400) != 0,
            .owner_write = (mode & 0o200) != 0,
            .owner_exec = (mode & 0o100) != 0,
            .group_read = (mode & 0o040) != 0,
            .group_write = (mode & 0o020) != 0,
            .group_exec = (mode & 0o010) != 0,
            .other_read = (mode & 0o004) != 0,
            .other_write = (mode & 0o002) != 0,
            .other_exec = (mode & 0o001) != 0,
            .sticky = (mode & 0o1000) != 0,
            .setgid = (mode & 0o2000) != 0,
            .setuid = (mode & 0o4000) != 0,
        };
    }
};

// =============================================================================
// Inode Operations
// =============================================================================

pub const InodeOps = struct {
    /// Look up a child inode by name
    lookup: ?*const fn (inode: *Inode, name: []const u8) ?*Inode = null,

    /// Create a new file
    create: ?*const fn (parent: *Inode, name: []const u8, mode: FileMode) ?*Inode = null,

    /// Create a new directory
    mkdir: ?*const fn (parent: *Inode, name: []const u8, mode: FileMode) ?*Inode = null,

    /// Remove a file
    unlink: ?*const fn (parent: *Inode, name: []const u8) bool = null,

    /// Remove a directory
    rmdir: ?*const fn (parent: *Inode, name: []const u8) bool = null,

    /// Read directory entry at index
    readdir: ?*const fn (inode: *Inode, index: usize) ?*vfs.DirEntry = null,

    /// Rename a file/directory
    rename: ?*const fn (old_parent: *Inode, old_name: []const u8, new_parent: *Inode, new_name: []const u8) bool = null,

    /// Create a symbolic link
    symlink: ?*const fn (parent: *Inode, name: []const u8, target: []const u8) ?*Inode = null,

    /// Read symbolic link target
    readlink: ?*const fn (inode: *Inode, buf: []u8) i64 = null,

    /// Get file attributes
    getattr: ?*const fn (inode: *Inode) ?*InodeAttr = null,

    /// Set file attributes
    setattr: ?*const fn (inode: *Inode, attr: *const InodeAttr) bool = null,
};

// =============================================================================
// Inode Attributes
// =============================================================================

pub const InodeAttr = struct {
    size: u64 = 0,
    mode: FileMode = .{},
    uid: u32 = 0,
    gid: u32 = 0,
    atime: u64 = 0,
    mtime: u64 = 0,
    ctime: u64 = 0,
};

// =============================================================================
// Inode Structure
// =============================================================================

pub const Inode = struct {
    /// Unique inode identifier
    id: u64 = 0,

    /// File type
    file_type: FileType = .Regular,

    /// File permissions
    mode: FileMode = .{},

    /// File size in bytes
    size: u64 = 0,

    /// Timestamps
    created: u64 = 0,
    modified: u64 = 0,
    accessed: u64 = 0,

    /// Link count (number of hard links)
    link_count: u32 = 1,

    /// Owner user ID
    uid: u32 = 0,

    /// Owner group ID
    gid: u32 = 0,

    /// Device major number (for device files)
    dev_major: u16 = 0,

    /// Device minor number (for device files)
    dev_minor: u16 = 0,

    /// Filesystem-specific data pointer
    fs_data: ?*anyopaque = null,

    /// Inode operations
    ops: ?*const InodeOps = null,

    // =========================================================================
    // Constructor
    // =========================================================================

    pub fn init(id: u64, file_type: FileType) Inode {
        return Inode{
            .id = id,
            .file_type = file_type,
            .mode = if (file_type == .Directory) FileMode.directory() else FileMode.regular(),
        };
    }

    pub fn initDirectory(id: u64) Inode {
        return Inode{
            .id = id,
            .file_type = .Directory,
            .mode = FileMode.directory(),
            .link_count = 2,
        };
    }

    pub fn initFile(id: u64) Inode {
        return Inode{
            .id = id,
            .file_type = .Regular,
            .mode = FileMode.regular(),
            .link_count = 1,
        };
    }

    pub fn initDevice(id: u64, dev_type: FileType, major: u16, minor: u16) Inode {
        return Inode{
            .id = id,
            .file_type = dev_type,
            .mode = FileMode.regular(),
            .link_count = 1,
            .dev_major = major,
            .dev_minor = minor,
        };
    }

    // =========================================================================
    // Type Checks
    // =========================================================================

    pub fn isRegular(self: *const Inode) bool {
        return self.file_type == .Regular;
    }

    pub fn isDirectory(self: *const Inode) bool {
        return self.file_type == .Directory;
    }

    pub fn isDevice(self: *const Inode) bool {
        return self.file_type == .CharDevice or self.file_type == .BlockDevice;
    }

    pub fn isCharDevice(self: *const Inode) bool {
        return self.file_type == .CharDevice;
    }

    pub fn isBlockDevice(self: *const Inode) bool {
        return self.file_type == .BlockDevice;
    }

    pub fn isSymlink(self: *const Inode) bool {
        return self.file_type == .Symlink;
    }

    pub fn isPipe(self: *const Inode) bool {
        return self.file_type == .Pipe;
    }

    pub fn isSocket(self: *const Inode) bool {
        return self.file_type == .Socket;
    }

    // =========================================================================
    // Operations
    // =========================================================================

    /// Look up a child by name
    pub fn lookup(self: *Inode, name: []const u8) ?*Inode {
        if (self.ops) |ops| {
            if (ops.lookup) |lookup_fn| {
                return lookup_fn(self, name);
            }
        }
        return null;
    }

    /// Create a child file
    pub fn create(self: *Inode, name: []const u8, mode: FileMode) ?*Inode {
        if (self.ops) |ops| {
            if (ops.create) |create_fn| {
                return create_fn(self, name, mode);
            }
        }
        return null;
    }

    /// Create a child directory
    pub fn mkdir(self: *Inode, name: []const u8, mode: FileMode) ?*Inode {
        if (self.ops) |ops| {
            if (ops.mkdir) |mkdir_fn| {
                return mkdir_fn(self, name, mode);
            }
        }
        return null;
    }

    /// Remove a child file
    pub fn unlink(self: *Inode, name: []const u8) bool {
        if (self.ops) |ops| {
            if (ops.unlink) |unlink_fn| {
                return unlink_fn(self, name);
            }
        }
        return false;
    }

    /// Remove a child directory
    pub fn rmdir(self: *Inode, name: []const u8) bool {
        if (self.ops) |ops| {
            if (ops.rmdir) |rmdir_fn| {
                return rmdir_fn(self, name);
            }
        }
        return false;
    }

    /// Read directory entry at index
    pub fn readdir(self: *Inode, index: usize) ?*vfs.DirEntry {
        if (self.ops) |ops| {
            if (ops.readdir) |readdir_fn| {
                return readdir_fn(self, index);
            }
        }
        return null;
    }

    /// Update access time
    pub fn touch(self: *Inode, time: u64) void {
        self.accessed = time;
    }

    /// Update modification time
    pub fn modify(self: *Inode, time: u64) void {
        self.modified = time;
        self.accessed = time;
    }

    /// Increment link count
    pub fn incLink(self: *Inode) void {
        self.link_count += 1;
    }

    /// Decrement link count
    pub fn decLink(self: *Inode) bool {
        if (self.link_count > 0) {
            self.link_count -= 1;
            return self.link_count == 0;
        }
        return true;
    }

    /// Get device number as combined value
    pub fn getDevice(self: *const Inode) u32 {
        return (@as(u32, self.dev_major) << 16) | @as(u32, self.dev_minor);
    }

    /// Set device number from combined value
    pub fn setDevice(self: *Inode, dev: u32) void {
        self.dev_major = @truncate(dev >> 16);
        self.dev_minor = @truncate(dev & 0xFFFF);
    }
};

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test FileMode
    const mode = FileMode.fromOctal(0o755);
    if (mode.owner_read and mode.owner_write and mode.owner_exec) {
        passed += 1;
    } else {
        failed += 1;
    }

    if (mode.toOctal() == 0o755) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test Inode creation
    const inode = Inode.initDirectory(1);
    if (inode.isDirectory()) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test device inode
    var dev_inode = Inode.initDevice(2, .CharDevice, 1, 5);
    if (dev_inode.isDevice() and dev_inode.getDevice() == 0x00010005) {
        passed += 1;
    } else {
        failed += 1;
    }

    return failed == 0;
}
