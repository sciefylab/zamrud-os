//! Zamrud OS - Virtual File System (VFS)
//! Main VFS interface with E3.2 Unveil + F3 Permission enforcement
//! B2.3: Rename, Truncate, Ftruncate operations

const serial = @import("../drivers/serial/serial.zig");
const heap = @import("../mm/heap.zig");
const path = @import("path.zig");
const process = @import("../proc/process.zig");
const unveil = @import("../security/unveil.zig");
const users = @import("../security/users.zig");

// Import modular components
pub const inode_mod = @import("inode.zig");
pub const file_mod = @import("file.zig");
pub const dirent_mod = @import("dirent.zig");

// Re-export commonly used types
pub const Inode = inode_mod.Inode;
pub const InodeOps = inode_mod.InodeOps;
pub const FileType = inode_mod.FileType;
pub const FileMode = inode_mod.FileMode;

pub const File = file_mod.File;
pub const FileOps = file_mod.FileOps;
pub const OpenFlags = file_mod.OpenFlags;
pub const SeekWhence = file_mod.SeekWhence;

pub const DirEntry = dirent_mod.DirEntry;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_PATH: usize = dirent_mod.MAX_PATH;
pub const MAX_FILENAME: usize = dirent_mod.MAX_FILENAME;
pub const MAX_OPEN_FILES: usize = file_mod.MAX_OPEN_FILES;
pub const MAX_MOUNT_POINTS: usize = 16;
const PTR_ALIGNMENT: u64 = 8;

// =============================================================================
// FileSystem
// =============================================================================

pub const FileSystem = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    root: ?*Inode = null,
    ops: ?*const FileSystemOps = null,
    file_ops: ?*const FileOps = null,
    fs_data: ?*anyopaque = null,

    pub fn getName(self: *const FileSystem) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *FileSystem, new_name: []const u8) void {
        const len = @min(new_name.len, 31);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = new_name[i];
        }
        self.name_len = @intCast(len);
    }
};

pub const FileSystemOps = struct {
    mount: ?*const fn (fs: *FileSystem) bool = null,
    unmount: ?*const fn (fs: *FileSystem) bool = null,
    sync: ?*const fn (fs: *FileSystem) void = null,
    statfs: ?*const fn (fs: *FileSystem) ?*StatFS = null,
};

pub const StatFS = struct {
    total_blocks: u64 = 0,
    free_blocks: u64 = 0,
    total_inodes: u64 = 0,
    free_inodes: u64 = 0,
    block_size: u32 = 0,
};

// =============================================================================
// Mount Point
// =============================================================================

pub const MountPoint = struct {
    path_buf: [MAX_PATH]u8 = [_]u8{0} ** MAX_PATH,
    path_len: u16 = 0,
    fs: ?*FileSystem = null,
    active: bool = false,

    pub fn getPath(self: *const MountPoint) []const u8 {
        return self.path_buf[0..self.path_len];
    }
};

// =============================================================================
// Global State
// =============================================================================

var mount_points: [MAX_MOUNT_POINTS]MountPoint = [_]MountPoint{.{}} ** MAX_MOUNT_POINTS;
var mount_count: usize = 0;
var open_files_raw: [MAX_OPEN_FILES]u64 = [_]u64{0} ** MAX_OPEN_FILES;
var open_files_alloc: [MAX_OPEN_FILES]u64 = [_]u64{0} ** MAX_OPEN_FILES;
var open_files_count: usize = 0;
var root_fs: ?*FileSystem = null;
var current_dir: [MAX_PATH]u8 = [_]u8{0} ** MAX_PATH;
var current_dir_len: usize = 0;
var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[VFS] Initializing...\n");

    mount_count = 0;
    open_files_count = 0;
    root_fs = null;
    current_dir_len = 0;

    var j: usize = 0;
    while (j < MAX_PATH) : (j += 1) {
        current_dir[j] = 0;
    }
    current_dir[0] = '/';
    current_dir_len = 1;

    var i: usize = 0;
    while (i < MAX_OPEN_FILES) : (i += 1) {
        open_files_raw[i] = 0;
        open_files_alloc[i] = 0;
    }

    i = 0;
    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        mount_points[i].active = false;
        mount_points[i].fs = null;
        mount_points[i].path_len = 0;
    }

    initialized = true;
    serial.writeString("[VFS] Initialized\n");
}

// =============================================================================
// E3.2: Unveil Check Helper
// =============================================================================

fn checkUnveil(file_path: []const u8, perm: u8) bool {
    if (!unveil.isInitialized()) return true;
    const pid = process.getCurrentPid();
    return unveil.checkAndEnforce(pid, file_path, perm);
}

fn checkUnveilRead(file_path: []const u8) bool {
    return checkUnveil(file_path, unveil.PERM_READ);
}

fn checkUnveilWrite(file_path: []const u8) bool {
    return checkUnveil(file_path, unveil.PERM_WRITE);
}

fn checkUnveilCreate(file_path: []const u8) bool {
    return checkUnveil(file_path, unveil.PERM_CREATE);
}

// =============================================================================
// F3: File Permission Check Helper
// =============================================================================

fn checkFilePerm(inode: *Inode, file_path: []const u8, perm: users.PermCheck) bool {
    if (!users.isInitialized()) return true;
    if (!users.isLoggedIn()) return true;
    return users.checkAndEnforceFilePermission(
        file_path,
        inode.uid,
        inode.gid,
        inode.mode,
        perm,
    );
}

fn setInodeOwner(inode: *Inode) void {
    if (users.isInitialized() and users.isLoggedIn()) {
        inode.uid = users.getCurrentUid();
        inode.gid = users.getCurrentGid();
    }
}

// =============================================================================
// Mount / Unmount
// =============================================================================

pub fn mount(mount_path: []const u8, fs: *FileSystem) bool {
    if (!initialized) return false;
    if (mount_count >= MAX_MOUNT_POINTS) return false;

    var i: usize = 0;
    var slot: usize = MAX_MOUNT_POINTS;

    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        if (!mount_points[i].active) {
            slot = i;
            break;
        }
    }

    if (slot >= MAX_MOUNT_POINTS) return false;

    const len = @min(mount_path.len, MAX_PATH);
    i = 0;
    while (i < len) : (i += 1) {
        mount_points[slot].path_buf[i] = mount_path[i];
    }

    mount_points[slot].path_len = @intCast(len);
    mount_points[slot].fs = fs;
    mount_points[slot].active = true;
    mount_count += 1;

    if (mount_path.len == 1 and mount_path[0] == '/') {
        root_fs = fs;
    }

    return true;
}

pub fn unmount(mount_path: []const u8) bool {
    if (!initialized) return false;

    var i: usize = 0;
    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        if (mount_points[i].active) {
            const mp_path = mount_points[i].getPath();
            if (strEqual(mp_path, mount_path)) {
                mount_points[i].active = false;
                mount_points[i].fs = null;
                mount_count -= 1;

                if (mount_path.len == 1 and mount_path[0] == '/') {
                    root_fs = null;
                }
                return true;
            }
        }
    }

    return false;
}

// =============================================================================
// Mount Point Helpers
// =============================================================================

fn getMountPointRoot(mp_path: []const u8) ?*Inode {
    var i: usize = 0;
    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        if (mount_points[i].active) {
            if (strEqual(mount_points[i].getPath(), mp_path)) {
                if (mount_points[i].fs) |fs| {
                    return fs.root;
                }
            }
        }
    }
    return null;
}

fn getMountPointFs(mp_path: []const u8) ?*FileSystem {
    var i: usize = 0;
    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        if (mount_points[i].active) {
            if (strEqual(mount_points[i].getPath(), mp_path)) {
                return mount_points[i].fs;
            }
        }
    }
    return null;
}

fn resolveInMountPoint(mp_path: []const u8, rel_path: []const u8) ?*Inode {
    var i: usize = 0;
    while (i < MAX_MOUNT_POINTS) : (i += 1) {
        if (mount_points[i].active) {
            if (strEqual(mount_points[i].getPath(), mp_path)) {
                if (mount_points[i].fs) |fs| {
                    if (fs.root) |root| {
                        if (root.ops) |ops| {
                            if (ops.lookup) |lookup_fn| {
                                return lookup_fn(root, rel_path);
                            }
                        }
                    }
                }
            }
        }
    }
    return null;
}

// =============================================================================
// File Operations (with E3.2 unveil + F3 permission checks)
// =============================================================================

pub fn open(file_path: []const u8, flags: OpenFlags) ?*File {
    if (!initialized) return null;
    if (root_fs == null) return null;

    if (flags.read and !checkUnveilRead(file_path)) return null;
    if (flags.write and !checkUnveilWrite(file_path)) return null;

    const inode = resolvePath(file_path) orelse {
        if (flags.create) {
            if (!checkUnveilCreate(file_path)) return null;
            const new_inode = createFileInternal(file_path) orelse return null;
            setInodeOwner(new_inode);
            return openInode(new_inode, file_path, flags);
        }
        return null;
    };

    if (flags.read and !checkFilePerm(inode, file_path, .read)) return null;
    if (flags.write and !checkFilePerm(inode, file_path, .write)) return null;

    return openInode(inode, file_path, flags);
}

fn openInode(inode: *Inode, file_path: []const u8, flags: OpenFlags) ?*File {
    if (open_files_count >= MAX_OPEN_FILES) return null;

    const alloc_size = @sizeOf(File) + PTR_ALIGNMENT;
    const raw_ptr = heap.kmalloc(alloc_size);
    if (raw_ptr == null) return null;

    const raw_addr = @intFromPtr(raw_ptr.?);
    const aligned_addr = (raw_addr + PTR_ALIGNMENT - 1) & ~(PTR_ALIGNMENT - 1);
    const file: *File = @ptrFromInt(aligned_addr);

    file.inode = inode;
    file.position = 0;
    file.flags = flags;
    file.ref_count = 1;
    file.ops = null;

    if (inode.file_type == .CharDevice or inode.file_type == .BlockDevice) {
        if (getMountPointFs("/dev")) |fs| {
            file.ops = fs.file_ops;
        }
    } else if (isPathUnderMount(file_path, "/dev")) {
        if (getMountPointFs("/dev")) |fs| {
            file.ops = fs.file_ops;
        }
    } else if (isPathUnderMount(file_path, "/disk")) {
        if (getMountPointFs("/disk")) |fs| {
            file.ops = fs.file_ops;
        }
    } else {
        if (root_fs) |fs| {
            file.ops = fs.file_ops;
        }
    }

    const slot = open_files_count;
    open_files_raw[slot] = aligned_addr;
    open_files_alloc[slot] = raw_addr;
    open_files_count += 1;

    return file;
}

pub fn isPathUnderMount(file_path: []const u8, mp: []const u8) bool {
    if (file_path.len < mp.len) return false;
    var i: usize = 0;
    while (i < mp.len) : (i += 1) {
        if (file_path[i] != mp[i]) return false;
    }
    if (file_path.len == mp.len) return true;
    if (file_path[mp.len] == '/') return true;
    return false;
}

pub fn close(file: *File) void {
    if (!initialized) return;

    if (file.ops) |ops| {
        if (ops.close) |close_fn| {
            close_fn(file);
        }
    }

    const file_addr = @intFromPtr(file);
    var i: usize = 0;
    while (i < MAX_OPEN_FILES) : (i += 1) {
        if (open_files_raw[i] == file_addr) {
            const alloc_addr = open_files_alloc[i];
            if (alloc_addr != 0) {
                heap.kfree(@ptrFromInt(alloc_addr));
            }
            open_files_raw[i] = 0;
            open_files_alloc[i] = 0;
            if (open_files_count > 0) {
                open_files_count -= 1;
            }
            break;
        }
    }
}

pub fn read(file: *File, buf: []u8) i64 {
    if (!file.flags.read) {
        return -1;
    }

    if (file.ops) |ops| {
        if (ops.read) |read_fn| {
            return read_fn(file, buf);
        }
    }

    return -1;
}

pub fn write(file: *File, buf: []const u8) i64 {
    if (!file.flags.write) {
        return -1;
    }

    if (file.ops) |ops| {
        if (ops.write) |write_fn| {
            return write_fn(file, buf);
        }
    }

    return -1;
}

pub fn seek(file: *File, offset: i64, whence: SeekWhence) i64 {
    const size: i64 = @intCast(file.inode.size);
    const pos: i64 = @intCast(file.position);

    const new_pos: i64 = switch (whence) {
        .Set => offset,
        .Cur => pos + offset,
        .End => size + offset,
    };

    if (new_pos < 0) return -1;

    file.position = @intCast(new_pos);
    return new_pos;
}

// =============================================================================
// Directory Operations (with E3.2 unveil + F3 permission checks)
// =============================================================================

pub fn readdir(dir_path: []const u8, index: usize) ?*DirEntry {
    if (!initialized) return null;

    if (!checkUnveilRead(dir_path)) return null;

    if (dir_path.len >= 5 and
        dir_path[0] == '/' and
        dir_path[1] == 'd' and
        dir_path[2] == 'i' and
        dir_path[3] == 's' and
        dir_path[4] == 'k')
    {
        if (getMountPointRoot("/disk")) |disk_root| {
            if (disk_root.ops) |ops| {
                if (ops.readdir) |readdir_fn| {
                    return readdir_fn(disk_root, index);
                }
            }
        }
        return null;
    }

    const inode = resolvePath(dir_path) orelse return null;
    if (inode.file_type != .Directory) return null;

    if (!checkFilePerm(inode, dir_path, .read)) return null;

    if (inode.ops) |ops| {
        if (ops.readdir) |readdir_fn| {
            return readdir_fn(inode, index);
        }
    }

    return null;
}

// =============================================================================
// Current Directory
// =============================================================================

pub fn getcwd() []const u8 {
    if (current_dir_len == 0) {
        return "/";
    }
    return current_dir[0..current_dir_len];
}

pub fn chdir(dir_path: []const u8) bool {
    if (!initialized) return false;
    if (dir_path.len == 0) return false;

    if (!checkUnveilRead(dir_path)) return false;

    if (dir_path.len == 1 and dir_path[0] == '/') {
        if (root_fs == null or root_fs.?.root == null) return false;
        current_dir[0] = '/';
        current_dir_len = 1;
        return true;
    }

    if (dir_path.len == 1 and dir_path[0] == '.') {
        return true;
    }

    if (dir_path.len == 2 and dir_path[0] == '.' and dir_path[1] == '.') {
        if (current_dir_len <= 1) {
            return true;
        }

        var new_len = current_dir_len;
        if (new_len > 1 and current_dir[new_len - 1] == '/') {
            new_len -= 1;
        }
        while (new_len > 1 and current_dir[new_len - 1] != '/') {
            new_len -= 1;
        }
        if (new_len == 0) new_len = 1;

        current_dir_len = new_len;
        return true;
    }

    // Allow cd to /disk
    if (dir_path.len == 5 and
        dir_path[0] == '/' and
        dir_path[1] == 'd' and
        dir_path[2] == 'i' and
        dir_path[3] == 's' and
        dir_path[4] == 'k')
    {
        if (getMountPointRoot("/disk") != null) {
            var k: usize = 0;
            while (k < dir_path.len and k < MAX_PATH) : (k += 1) {
                current_dir[k] = dir_path[k];
            }
            current_dir_len = dir_path.len;
            return true;
        }
        return false;
    }

    const inode = resolvePath(dir_path) orelse return false;
    if (inode.file_type != .Directory) return false;

    if (!checkFilePerm(inode, dir_path, .exec)) return false;

    if (dir_path[0] == '/') {
        var i: usize = 0;
        while (i < dir_path.len and i < MAX_PATH) : (i += 1) {
            current_dir[i] = dir_path[i];
        }
        current_dir_len = dir_path.len;
    } else {
        var new_len = current_dir_len;

        if (new_len > 0 and current_dir[new_len - 1] != '/') {
            if (new_len < MAX_PATH) {
                current_dir[new_len] = '/';
                new_len += 1;
            }
        }

        var i: usize = 0;
        while (i < dir_path.len and new_len < MAX_PATH) : (i += 1) {
            current_dir[new_len] = dir_path[i];
            new_len += 1;
        }

        current_dir_len = new_len;
    }

    return true;
}

// =============================================================================
// Path Resolution
// =============================================================================

pub fn resolvePath(file_path: []const u8) ?*Inode {
    if (root_fs == null) return null;
    if (root_fs.?.root == null) return null;

    if (file_path.len >= 5 and
        file_path[0] == '/' and
        file_path[1] == 'd' and
        file_path[2] == 'e' and
        file_path[3] == 'v' and
        file_path[4] == '/')
    {
        const dev_path = file_path[5..];
        return resolveInMountPoint("/dev", dev_path);
    }

    if (file_path.len == 4 and
        file_path[0] == '/' and
        file_path[1] == 'd' and
        file_path[2] == 'e' and
        file_path[3] == 'v')
    {
        return getMountPointRoot("/dev");
    }

    if (file_path.len >= 6 and
        file_path[0] == '/' and
        file_path[1] == 'd' and
        file_path[2] == 'i' and
        file_path[3] == 's' and
        file_path[4] == 'k' and
        file_path[5] == '/')
    {
        const disk_path = file_path[6..];
        return resolveInMountPoint("/disk", disk_path);
    }

    if (file_path.len == 5 and
        file_path[0] == '/' and
        file_path[1] == 'd' and
        file_path[2] == 'i' and
        file_path[3] == 's' and
        file_path[4] == 'k')
    {
        return getMountPointRoot("/disk");
    }

    var current = root_fs.?.root.?;

    if (file_path.len == 0) return current;
    if (file_path.len == 1 and file_path[0] == '.') return current;
    if (file_path.len == 1 and file_path[0] == '/') return current;

    var is_simple = true;
    var idx: usize = 0;
    while (idx < file_path.len) : (idx += 1) {
        if (file_path[idx] == '/') {
            is_simple = false;
            break;
        }
    }

    if (file_path.len > 0 and file_path[0] == '.') {
        is_simple = false;
    }

    if (is_simple) {
        if (current.ops) |ops| {
            if (ops.lookup) |lookup_fn| {
                return lookup_fn(current, file_path);
            }
        }
        return null;
    }

    var start: usize = 0;

    if (file_path[0] == '/') {
        start = 1;
    }

    var i = start;
    while (i < file_path.len) {
        while (i < file_path.len and file_path[i] == '/') {
            i += 1;
        }

        if (i >= file_path.len) break;

        var end = i;
        while (end < file_path.len and file_path[end] != '/') {
            end += 1;
        }

        if (end == i) {
            i += 1;
            continue;
        }

        const component = file_path[i..end];

        if (component.len == 1 and component[0] == '.') {
            i = end + 1;
            continue;
        }

        if (component.len == 2 and component[0] == '.' and component[1] == '.') {
            i = end + 1;
            continue;
        }

        if (component.len == 3 and component[0] == 'd' and component[1] == 'e' and component[2] == 'v') {
            if (getMountPointRoot("/dev")) |dev_root| {
                current = dev_root;
                i = end + 1;
                continue;
            }
        }

        if (component.len == 4 and component[0] == 'd' and component[1] == 'i' and component[2] == 's' and component[3] == 'k') {
            if (getMountPointRoot("/disk")) |disk_root| {
                current = disk_root;
                i = end + 1;
                continue;
            }
        }

        if (current.ops) |ops| {
            if (ops.lookup) |lookup_fn| {
                const result = lookup_fn(current, component);
                if (result) |found| {
                    current = found;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        } else {
            return null;
        }

        i = end + 1;
    }

    return current;
}

// =============================================================================
// Higher-Level File Operations (with E3.2 unveil + F3 permission checks)
// =============================================================================

fn getParentInode(file_path: []const u8) ?*Inode {
    if (root_fs == null) return null;
    if (root_fs.?.root == null) return null;

    const parent_path = path.dirname(file_path);

    if (parent_path.len == 1 and parent_path[0] == '.') {
        return root_fs.?.root;
    }

    if (parent_path.len == 1 and parent_path[0] == '/') {
        return root_fs.?.root;
    }

    return resolvePath(parent_path);
}

fn createFileInternal(file_path: []const u8) ?*Inode {
    if (root_fs == null) return null;

    const file_name = path.basename(file_path);
    if (file_name.len == 0) return null;

    const parent_inode = getParentInode(file_path) orelse return null;

    if (parent_inode.ops) |ops| {
        if (ops.create) |create_fn| {
            return create_fn(parent_inode, file_name, FileMode.regular());
        }
    }

    return null;
}

pub fn createFile(file_path: []const u8) ?*Inode {
    if (!checkUnveilCreate(file_path)) return null;

    const parent = getParentInode(file_path);
    if (parent != null) {
        const parent_path = path.dirname(file_path);
        if (!checkFilePerm(parent.?, parent_path, .write)) return null;
    }

    const inode = createFileInternal(file_path) orelse return null;
    setInodeOwner(inode);

    return inode;
}

pub fn createDir(dir_path: []const u8) ?*Inode {
    if (root_fs == null) return null;

    if (!checkUnveilCreate(dir_path)) return null;

    const dir_name = path.basename(dir_path);
    if (dir_name.len == 0) return null;

    const parent_inode = getParentInode(dir_path) orelse return null;

    const parent_path = path.dirname(dir_path);
    if (!checkFilePerm(parent_inode, parent_path, .write)) return null;

    if (parent_inode.ops) |ops| {
        if (ops.mkdir) |mkdir_fn| {
            const new_dir = mkdir_fn(parent_inode, dir_name, FileMode.directory()) orelse return null;
            setInodeOwner(new_dir);
            return new_dir;
        }
    }

    return null;
}

pub fn removeFile(file_path: []const u8) bool {
    if (root_fs == null) return false;

    if (!checkUnveilWrite(file_path)) return false;

    const inode = resolvePath(file_path) orelse return false;
    if (!checkFilePerm(inode, file_path, .write)) return false;

    const file_name = path.basename(file_path);
    if (file_name.len == 0) return false;

    const parent_inode = getParentInode(file_path) orelse return false;

    const parent_path = path.dirname(file_path);
    if (!checkFilePerm(parent_inode, parent_path, .write)) return false;

    if (parent_inode.ops) |ops| {
        if (ops.unlink) |unlink_fn| {
            return unlink_fn(parent_inode, file_name);
        }
    }

    return false;
}

pub fn removeDir(dir_path: []const u8) bool {
    if (root_fs == null) return false;

    if (!checkUnveilWrite(dir_path)) return false;

    const inode = resolvePath(dir_path) orelse return false;
    if (!checkFilePerm(inode, dir_path, .write)) return false;

    const dir_name = path.basename(dir_path);
    if (dir_name.len == 0) return false;

    const parent_inode = getParentInode(dir_path) orelse return false;

    const parent_path = path.dirname(dir_path);
    if (!checkFilePerm(parent_inode, parent_path, .write)) return false;

    if (parent_inode.ops) |ops| {
        if (ops.rmdir) |rmdir_fn| {
            return rmdir_fn(parent_inode, dir_name);
        }
    }

    return false;
}

// =============================================================================
// B2.3: Rename Operation (with E3.2 unveil + F3 permission checks)
// =============================================================================

pub fn rename(old_path: []const u8, new_path: []const u8) bool {
    if (root_fs == null) return false;
    if (!initialized) return false;

    // E3.2: Unveil check — need write on both paths
    if (!checkUnveilWrite(old_path)) return false;
    if (!checkUnveilCreate(new_path)) return false;

    // Check source exists
    const old_inode = resolvePath(old_path) orelse return false;

    // F3: Need write permission on source
    if (!checkFilePerm(old_inode, old_path, .write)) return false;

    // Check destination doesn't exist
    if (resolvePath(new_path) != null) return false;

    // Both paths must be on the same mount point
    const old_on_disk = isPathUnderMount(old_path, "/disk");
    const new_on_disk = isPathUnderMount(new_path, "/disk");

    if (old_on_disk and new_on_disk) {
        // FAT32 rename via direct driver
        const fat32 = @import("fat32.zig");
        const old_name = path.basename(old_path);
        const new_name = path.basename(new_path);
        if (old_name.len == 0 or new_name.len == 0) return false;
        return fat32.renameFile(old_name, new_name);
    }

    if (old_on_disk != new_on_disk) {
        return false; // Cross-mount rename not supported
    }

    // Check if cwd is /disk and paths are relative
    const cwd = getcwd();
    if (isPathUnderMount(cwd, "/disk") and old_path.len > 0 and old_path[0] != '/' and new_path.len > 0 and new_path[0] != '/') {
        const fat32 = @import("fat32.zig");
        return fat32.renameFile(old_path, new_path);
    }

    // Same filesystem — use InodeOps.rename if available
    const old_parent = getParentInode(old_path) orelse return false;
    const new_parent = getParentInode(new_path) orelse return false;

    // F3: Need write on parent directories
    const old_parent_path = path.dirname(old_path);
    if (!checkFilePerm(old_parent, old_parent_path, .write)) return false;
    const new_parent_path = path.dirname(new_path);
    if (!checkFilePerm(new_parent, new_parent_path, .write)) return false;

    const old_name = path.basename(old_path);
    const new_name = path.basename(new_path);
    if (old_name.len == 0 or new_name.len == 0) return false;

    if (old_parent.ops) |ops| {
        if (ops.rename) |rename_fn| {
            return rename_fn(old_parent, old_name, new_parent, new_name);
        }
    }

    return false;
}

// =============================================================================
// B2.3: Truncate Operation (with E3.2 unveil + F3 permission checks)
// =============================================================================

pub fn truncate(file_path: []const u8, length: u64) bool {
    if (root_fs == null) return false;
    if (!initialized) return false;

    // E3.2: Unveil check — need write permission
    if (!checkUnveilWrite(file_path)) return false;

    // FAT32 path — check absolute /disk path
    if (isPathUnderMount(file_path, "/disk")) {
        const fat32 = @import("fat32.zig");
        const fname = path.basename(file_path);
        if (fname.len == 0) return false;

        // F3: check via inode if resolvable
        const inode_check = resolvePath(file_path);
        if (inode_check) |ic| {
            if (ic.file_type != .Regular) return false;
            if (!checkFilePerm(ic, file_path, .write)) return false;
        }

        return fat32.truncateFile(fname, @intCast(@min(length, 0xFFFFFFFF)));
    }

    // Check if cwd is /disk and path is relative
    const cwd = getcwd();
    if (isPathUnderMount(cwd, "/disk") and file_path.len > 0 and file_path[0] != '/') {
        const fat32 = @import("fat32.zig");
        return fat32.truncateFile(file_path, @intCast(@min(length, 0xFFFFFFFF)));
    }

    // RAMFS path
    const inode_result = resolvePath(file_path) orelse return false;
    if (inode_result.file_type != .Regular) return false;

    // F3: Need write permission
    if (!checkFilePerm(inode_result, file_path, .write)) return false;

    // Use ramfs public helper
    const ramfs = @import("ramfs.zig");
    const entry = ramfs.getEntryFromInodePublic(inode_result);
    if (entry) |e| {
        return ramfsTruncateEntry(e, length);
    }

    return false;
}

/// Truncate by open file descriptor
pub fn ftruncate(file: *File, length: u64) bool {
    if (file.inode.file_type != .Regular) return false;
    if (!file.flags.write) return false;

    // Try RAMFS first
    const ramfs = @import("ramfs.zig");
    const entry = ramfs.getEntryFromInodePublic(file.inode);
    if (entry) |e| {
        if (ramfsTruncateEntry(e, length)) {
            if (file.position > length) {
                file.position = length;
            }
            return true;
        }
    }

    // Try FAT32
    const fat32 = @import("fat32.zig");
    const name = fat32.getInodeName(file.inode);
    if (name) |n| {
        if (fat32.truncateFile(n, @intCast(@min(length, 0xFFFFFFFF)))) {
            file.inode.size = length;
            if (file.position > length) {
                file.position = length;
            }
            return true;
        }
    }

    return false;
}

/// Internal helper: truncate a RAMFS entry to given length
fn ramfsTruncateEntry(e: *@import("ramfs.zig").RamfsEntry, length: u64) bool {
    const max_size: u64 = 1024 * 1024;
    const new_len = @min(length, max_size);
    const needed: usize = @intCast(new_len);

    if (new_len <= e.data_size) {
        // Shrink
        e.data_size = needed;
        e.inode.size = new_len;
        return true;
    }

    // Extend
    if (needed <= e.data_capacity) {
        // Zero fill from old size to new size
        if (e.data) |data| {
            var i: usize = e.data_size;
            while (i < needed) : (i += 1) {
                data[i] = 0;
            }
        }
        e.data_size = needed;
        e.inode.size = new_len;
        return true;
    }

    // Need realloc
    const BLOCK_SIZE: usize = 4096;
    const new_capacity = ((needed / BLOCK_SIZE) + 1) * BLOCK_SIZE;
    if (new_capacity > max_size) return false;

    const new_data = heap.kmalloc(new_capacity) orelse return false;
    const new_ptr: [*]u8 = @ptrCast(@alignCast(new_data));

    // Copy old data
    if (e.data) |old_data| {
        var i: usize = 0;
        while (i < e.data_size) : (i += 1) {
            new_ptr[i] = old_data[i];
        }
        heap.kfree(@ptrCast(old_data));
    }

    // Zero new space
    var j: usize = e.data_size;
    while (j < needed) : (j += 1) {
        new_ptr[j] = 0;
    }

    e.data = new_ptr;
    e.data_capacity = new_capacity;
    e.data_size = needed;
    e.inode.size = new_len;
    return true;
}

// =============================================================================
// Query Operations
// =============================================================================

pub fn exists(check_path: []const u8) bool {
    return resolvePath(check_path) != null;
}

pub fn isDirectory(check_path: []const u8) bool {
    const inode = resolvePath(check_path) orelse return false;
    return inode.file_type == .Directory;
}

pub fn isFile(check_path: []const u8) bool {
    const inode = resolvePath(check_path) orelse return false;
    return inode.file_type == .Regular;
}

pub fn getSize(file_path: []const u8) ?u64 {
    const inode = resolvePath(file_path) orelse return null;
    return inode.size;
}

// =============================================================================
// Utilities
// =============================================================================

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

pub fn printStatus() void {
    serial.writeString("[VFS] Status:\n");
    serial.writeString("  Initialized: ");
    serial.writeString(if (initialized) "yes" else "no");
    serial.writeString("\n");
}

pub fn setCwd(new_path: []const u8) void {
    const len = @min(new_path.len, MAX_PATH);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        current_dir[i] = new_path[i];
    }
    current_dir_len = len;
}

pub fn ensureDir(dir_path: []const u8) bool {
    if (resolvePath(dir_path) != null) return true;
    return createDir(dir_path) != null;
}

// =============================================================================
// Module Tests
// =============================================================================

pub fn runAllTests() bool {
    var all_passed = true;

    if (!inode_mod.runTests()) {
        serial.writeString("[VFS] Inode tests FAILED\n");
        all_passed = false;
    }

    if (!file_mod.runTests()) {
        serial.writeString("[VFS] File tests FAILED\n");
        all_passed = false;
    }

    if (!dirent_mod.runTests()) {
        serial.writeString("[VFS] DirEntry tests FAILED\n");
        all_passed = false;
    }

    if (all_passed) {
        serial.writeString("[VFS] All module tests PASSED\n");
    }

    return all_passed;
}
