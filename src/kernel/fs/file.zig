//! Zamrud OS - File Handle Management
//! File descriptor and file operations

const inode = @import("inode.zig");
const Inode = inode.Inode;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_OPEN_FILES: usize = 64;

// =============================================================================
// Open Flags
// =============================================================================

pub const OpenFlags = struct {
    read: bool = false,
    write: bool = false,
    append: bool = false,
    create: bool = false,
    truncate: bool = false,
    exclusive: bool = false,
    nonblock: bool = false,
    sync: bool = false,
    directory: bool = false,

    // Pre-defined flag combinations
    pub const O_RDONLY: OpenFlags = .{ .read = true };
    pub const O_WRONLY: OpenFlags = .{ .write = true };
    pub const O_RDWR: OpenFlags = .{ .read = true, .write = true };
    pub const O_CREAT: OpenFlags = .{ .create = true };
    pub const O_TRUNC: OpenFlags = .{ .truncate = true };
    pub const O_APPEND: OpenFlags = .{ .append = true };
    pub const O_EXCL: OpenFlags = .{ .exclusive = true };
    pub const O_NONBLOCK: OpenFlags = .{ .nonblock = true };
    pub const O_SYNC: OpenFlags = .{ .sync = true };
    pub const O_DIRECTORY: OpenFlags = .{ .directory = true };

    /// Combine with another set of flags
    pub fn combine(self: OpenFlags, other: OpenFlags) OpenFlags {
        return OpenFlags{
            .read = self.read or other.read,
            .write = self.write or other.write,
            .append = self.append or other.append,
            .create = self.create or other.create,
            .truncate = self.truncate or other.truncate,
            .exclusive = self.exclusive or other.exclusive,
            .nonblock = self.nonblock or other.nonblock,
            .sync = self.sync or other.sync,
            .directory = self.directory or other.directory,
        };
    }

    /// Check if readable
    pub fn canRead(self: OpenFlags) bool {
        return self.read;
    }

    /// Check if writable
    pub fn canWrite(self: OpenFlags) bool {
        return self.write;
    }

    /// Check if creating new file
    pub fn isCreate(self: OpenFlags) bool {
        return self.create;
    }
};

// =============================================================================
// Seek Whence
// =============================================================================

pub const SeekWhence = enum(u8) {
    /// Seek from beginning of file
    Set = 0,
    /// Seek from current position
    Cur = 1,
    /// Seek from end of file
    End = 2,

    pub fn toString(self: SeekWhence) []const u8 {
        return switch (self) {
            .Set => "SEEK_SET",
            .Cur => "SEEK_CUR",
            .End => "SEEK_END",
        };
    }
};

// =============================================================================
// File Operations
// =============================================================================

pub const FileOps = struct {
    /// Read data from file
    read: ?*const fn (file: *File, buf: []u8) i64 = null,

    /// Write data to file
    write: ?*const fn (file: *File, buf: []const u8) i64 = null,

    /// Seek to position
    seek: ?*const fn (file: *File, offset: i64, whence: SeekWhence) i64 = null,

    /// Close file
    close: ?*const fn (file: *File) void = null,

    /// Flush file buffers
    flush: ?*const fn (file: *File) bool = null,

    /// Get file status
    stat: ?*const fn (file: *File) ?*FileStat = null,

    /// I/O control
    ioctl: ?*const fn (file: *File, cmd: u32, arg: usize) i64 = null,

    /// Memory map
    mmap: ?*const fn (file: *File, offset: u64, length: usize) ?*anyopaque = null,

    /// Poll for events
    poll: ?*const fn (file: *File, events: u16) u16 = null,
};

// =============================================================================
// File Status
// =============================================================================

pub const FileStat = struct {
    dev: u64 = 0,
    ino: u64 = 0,
    mode: u16 = 0,
    nlink: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    rdev: u64 = 0,
    size: u64 = 0,
    blksize: u32 = 512,
    blocks: u64 = 0,
    atime: u64 = 0,
    mtime: u64 = 0,
    ctime: u64 = 0,
};

// =============================================================================
// File Structure
// =============================================================================

pub const File = struct {
    /// Associated inode
    inode: *Inode,

    /// Current file position
    position: u64 = 0,

    /// Open flags
    flags: OpenFlags = .{},

    /// Reference count
    ref_count: u32 = 1,

    /// File operations
    ops: ?*const FileOps = null,

    /// Private data for filesystem
    private_data: ?*anyopaque = null,

    // =========================================================================
    // Constructor
    // =========================================================================

    pub fn init(ino: *Inode, flg: OpenFlags) File {
        return File{
            .inode = ino,
            .position = 0,
            .flags = flg,
            .ref_count = 1,
            .ops = null,
            .private_data = null,
        };
    }

    // =========================================================================
    // Operations
    // =========================================================================

    /// Read data from file
    pub fn read(self: *File, buf: []u8) i64 {
        if (!self.flags.read) return -1;

        if (self.ops) |ops| {
            if (ops.read) |read_fn| {
                return read_fn(self, buf);
            }
        }
        return -1;
    }

    /// Write data to file
    pub fn write(self: *File, buf: []const u8) i64 {
        if (!self.flags.write) return -1;

        if (self.ops) |ops| {
            if (ops.write) |write_fn| {
                return write_fn(self, buf);
            }
        }
        return -1;
    }

    /// Seek to position
    pub fn seek(self: *File, offset: i64, whence: SeekWhence) i64 {
        if (self.ops) |ops| {
            if (ops.seek) |seek_fn| {
                return seek_fn(self, offset, whence);
            }
        }

        // Default seek implementation
        // FIX: Renamed from 'size' to 'file_size' to avoid shadowing
        const file_size: i64 = @intCast(self.inode.size);
        const pos: i64 = @intCast(self.position);

        const new_pos: i64 = switch (whence) {
            .Set => offset,
            .Cur => pos + offset,
            .End => file_size + offset,
        };

        if (new_pos < 0) return -1;

        self.position = @intCast(new_pos);
        return new_pos;
    }

    /// Close file
    pub fn close(self: *File) void {
        if (self.ops) |ops| {
            if (ops.close) |close_fn| {
                close_fn(self);
            }
        }
    }

    /// Flush file buffers
    pub fn flush(self: *File) bool {
        if (self.ops) |ops| {
            if (ops.flush) |flush_fn| {
                return flush_fn(self);
            }
        }
        return true;
    }

    /// Get current position
    pub fn tell(self: *const File) u64 {
        return self.position;
    }

    /// Check if at end of file
    pub fn eof(self: *const File) bool {
        return self.position >= self.inode.size;
    }

    /// Get file size
    pub fn getSize(self: *const File) u64 {
        return self.inode.size;
    }

    /// Increment reference count
    pub fn incRef(self: *File) void {
        self.ref_count += 1;
    }

    /// Decrement reference count, returns true if should be freed
    pub fn decRef(self: *File) bool {
        if (self.ref_count > 0) {
            self.ref_count -= 1;
            return self.ref_count == 0;
        }
        return true;
    }

    /// Rewind to beginning
    pub fn rewind(self: *File) void {
        self.position = 0;
    }

    /// Check if readable
    pub fn isReadable(self: *const File) bool {
        return self.flags.read;
    }

    /// Check if writable
    pub fn isWritable(self: *const File) bool {
        return self.flags.write;
    }

    /// Check if appendable
    pub fn isAppendable(self: *const File) bool {
        return self.flags.append;
    }
};

// =============================================================================
// File Descriptor Table
// =============================================================================

pub const FileDescriptor = struct {
    file: ?*File = null,
    flags: u32 = 0,
    in_use: bool = false,

    pub const FD_CLOEXEC: u32 = 1;
};

pub const FileDescriptorTable = struct {
    descriptors: [MAX_OPEN_FILES]FileDescriptor = [_]FileDescriptor{.{}} ** MAX_OPEN_FILES,
    count: usize = 0,

    /// Allocate new file descriptor
    pub fn alloc(self: *FileDescriptorTable, file: *File) ?i32 {
        var i: usize = 0;
        while (i < MAX_OPEN_FILES) : (i += 1) {
            if (!self.descriptors[i].in_use) {
                self.descriptors[i].file = file;
                self.descriptors[i].flags = 0;
                self.descriptors[i].in_use = true;
                self.count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Free file descriptor
    pub fn free(self: *FileDescriptorTable, fd: i32) bool {
        if (fd < 0 or fd >= MAX_OPEN_FILES) return false;

        const idx: usize = @intCast(fd);
        if (!self.descriptors[idx].in_use) return false;

        self.descriptors[idx].file = null;
        self.descriptors[idx].flags = 0;
        self.descriptors[idx].in_use = false;
        if (self.count > 0) self.count -= 1;

        return true;
    }

    /// Get file from descriptor
    pub fn get(self: *FileDescriptorTable, fd: i32) ?*File {
        if (fd < 0 or fd >= MAX_OPEN_FILES) return null;

        const idx: usize = @intCast(fd);
        if (!self.descriptors[idx].in_use) return null;

        return self.descriptors[idx].file;
    }

    /// Duplicate file descriptor
    pub fn dup(self: *FileDescriptorTable, fd: i32) ?i32 {
        const file = self.get(fd) orelse return null;
        file.incRef();
        return self.alloc(file);
    }

    /// Duplicate to specific fd
    pub fn dup2(self: *FileDescriptorTable, old_fd: i32, new_fd: i32) bool {
        if (new_fd < 0 or new_fd >= MAX_OPEN_FILES) return false;

        const file = self.get(old_fd) orelse return false;

        const new_idx: usize = @intCast(new_fd);

        // Close existing if open
        if (self.descriptors[new_idx].in_use) {
            if (self.descriptors[new_idx].file) |f| {
                if (f.decRef()) {
                    f.close();
                }
            }
        }

        file.incRef();
        self.descriptors[new_idx].file = file;
        self.descriptors[new_idx].flags = 0;
        self.descriptors[new_idx].in_use = true;

        return true;
    }
};

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test OpenFlags
    const flags = OpenFlags.O_RDWR.combine(OpenFlags.O_CREAT);
    if (flags.canRead() and flags.canWrite() and flags.isCreate()) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test FileDescriptorTable
    // FIX: Changed from 'var' to 'const' since it's not mutated
    const fdt = FileDescriptorTable{};
    if (fdt.count == 0) {
        passed += 1;
    } else {
        failed += 1;
    }

    return failed == 0;
}
