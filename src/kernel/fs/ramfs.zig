//! Zamrud OS - RAM File System (RAMFS)
//! B2.3: Added rename support + public inode helper

const serial = @import("../drivers/serial/serial.zig");
const heap = @import("../mm/heap.zig");
const vfs = @import("vfs.zig");

const MAX_CHILDREN: usize = 32;
const MAX_FILE_SIZE: usize = 1024 * 1024;
const BLOCK_SIZE: usize = 4096;
const MAX_ENTRIES: usize = 128;

// =============================================================================
// RAMFS Entry
// =============================================================================

pub const RamfsEntry = struct {
    name: [vfs.MAX_FILENAME]u8,
    name_len: u8,
    inode: vfs.Inode,
    data: ?[*]u8,
    data_size: usize,
    data_capacity: usize,
    children: [MAX_CHILDREN]?*RamfsEntry,
    children_count: usize,
    parent: ?*RamfsEntry,
    in_use: bool,

    pub fn getName(self: *const RamfsEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn setName(self: *RamfsEntry, new_name: []const u8) void {
        const len = @min(new_name.len, vfs.MAX_FILENAME);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = new_name[i];
        }
        self.name_len = @intCast(len);
    }
};

// =============================================================================
// Entry Pool
// =============================================================================

var entry_pool: [MAX_ENTRIES]RamfsEntry = undefined;
var entry_pool_initialized: bool = false;

fn initEntryPool() void {
    serial.writeString("[RAMFS] Init pool\n");

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        entry_pool[i].in_use = false;
        entry_pool[i].name_len = 0;
        entry_pool[i].data = null;
        entry_pool[i].data_size = 0;
        entry_pool[i].data_capacity = 0;
        entry_pool[i].children_count = 0;
        entry_pool[i].parent = null;

        var j: usize = 0;
        while (j < MAX_CHILDREN) : (j += 1) {
            entry_pool[i].children[j] = null;
        }

        entry_pool[i].inode.id = 0;
        entry_pool[i].inode.file_type = .Regular;
        entry_pool[i].inode.mode = .{};
        entry_pool[i].inode.size = 0;
        entry_pool[i].inode.created = 0;
        entry_pool[i].inode.modified = 0;
        entry_pool[i].inode.accessed = 0;
        entry_pool[i].inode.link_count = 1;
        entry_pool[i].inode.uid = 0;
        entry_pool[i].inode.gid = 0;
        entry_pool[i].inode.dev_major = 0;
        entry_pool[i].inode.dev_minor = 0;
        entry_pool[i].inode.fs_data = null;
        entry_pool[i].inode.ops = null;
    }

    entry_pool_initialized = true;
    serial.writeString("[RAMFS] Pool done\n");
}

fn allocEntry() ?*RamfsEntry {
    if (!entry_pool_initialized) return null;

    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (!entry_pool[i].in_use) {
            entry_pool[i].in_use = true;
            return &entry_pool[i];
        }
    }
    return null;
}

fn freeEntry(entry: *RamfsEntry) void {
    if (entry.data) |data| {
        heap.kfree(@ptrCast(data));
    }

    entry.in_use = false;
    entry.data = null;
    entry.data_size = 0;
    entry.data_capacity = 0;
    entry.children_count = 0;
    entry.parent = null;
    entry.name_len = 0;

    var i: usize = 0;
    while (i < MAX_CHILDREN) : (i += 1) {
        entry.children[i] = null;
    }
}

// =============================================================================
// Global State
// =============================================================================

var root_entry: ?*RamfsEntry = null;
var filesystem: vfs.FileSystem = undefined;
var next_inode_id: u64 = 1;
var initialized: bool = false;

// =============================================================================
// Inode Operations
// =============================================================================

fn ramfsLookup(inode: *vfs.Inode, name: []const u8) ?*vfs.Inode {
    const entry = getEntryFromInode(inode) orelse return null;

    if (entry.inode.file_type != .Directory) return null;

    var i: usize = 0;
    while (i < entry.children_count) : (i += 1) {
        if (entry.children[i]) |child| {
            if (strEqual(child.getName(), name)) {
                return &child.inode;
            }
        }
    }

    return null;
}

fn ramfsCreate(parent: *vfs.Inode, name: []const u8, mode: vfs.FileMode) ?*vfs.Inode {
    const parent_entry = getEntryFromInode(parent) orelse return null;

    if (parent_entry.inode.file_type != .Directory) return null;
    if (parent_entry.children_count >= MAX_CHILDREN) return null;

    var i: usize = 0;
    while (i < parent_entry.children_count) : (i += 1) {
        if (parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), name)) {
                return null;
            }
        }
    }

    const new_entry = allocEntry() orelse return null;

    new_entry.setName(name);
    new_entry.inode.id = next_inode_id;
    next_inode_id += 1;
    new_entry.inode.file_type = .Regular;
    new_entry.inode.mode = mode;
    new_entry.inode.size = 0;
    new_entry.inode.link_count = 1;
    new_entry.inode.fs_data = @ptrCast(new_entry);
    new_entry.inode.ops = &ramfs_inode_ops;
    new_entry.parent = parent_entry;
    new_entry.data = null;
    new_entry.data_size = 0;
    new_entry.data_capacity = 0;
    new_entry.children_count = 0;

    parent_entry.children[parent_entry.children_count] = new_entry;
    parent_entry.children_count += 1;

    return &new_entry.inode;
}

fn ramfsMkdir(parent: *vfs.Inode, name: []const u8, mode: vfs.FileMode) ?*vfs.Inode {
    const parent_entry = getEntryFromInode(parent) orelse return null;

    if (parent_entry.inode.file_type != .Directory) return null;
    if (parent_entry.children_count >= MAX_CHILDREN) return null;

    var i: usize = 0;
    while (i < parent_entry.children_count) : (i += 1) {
        if (parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), name)) {
                return null;
            }
        }
    }

    const new_entry = allocEntry() orelse return null;

    new_entry.setName(name);
    new_entry.inode.id = next_inode_id;
    next_inode_id += 1;
    new_entry.inode.file_type = .Directory;
    new_entry.inode.mode = mode;
    new_entry.inode.size = 0;
    new_entry.inode.link_count = 2;
    new_entry.inode.fs_data = @ptrCast(new_entry);
    new_entry.inode.ops = &ramfs_inode_ops;
    new_entry.parent = parent_entry;
    new_entry.data = null;
    new_entry.data_size = 0;
    new_entry.data_capacity = 0;
    new_entry.children_count = 0;

    parent_entry.children[parent_entry.children_count] = new_entry;
    parent_entry.children_count += 1;

    return &new_entry.inode;
}

fn ramfsUnlink(parent: *vfs.Inode, name: []const u8) bool {
    const parent_entry = getEntryFromInode(parent) orelse return false;

    if (parent_entry.inode.file_type != .Directory) return false;

    var i: usize = 0;
    while (i < parent_entry.children_count) : (i += 1) {
        if (parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), name)) {
                if (child.inode.file_type == .Directory) return false;

                freeEntry(child);

                var j = i;
                while (j < parent_entry.children_count - 1) : (j += 1) {
                    parent_entry.children[j] = parent_entry.children[j + 1];
                }
                parent_entry.children[parent_entry.children_count - 1] = null;
                parent_entry.children_count -= 1;

                return true;
            }
        }
    }

    return false;
}

fn ramfsRmdir(parent: *vfs.Inode, name: []const u8) bool {
    const parent_entry = getEntryFromInode(parent) orelse return false;

    if (parent_entry.inode.file_type != .Directory) return false;

    var i: usize = 0;
    while (i < parent_entry.children_count) : (i += 1) {
        if (parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), name)) {
                if (child.inode.file_type != .Directory) return false;
                if (child.children_count > 0) return false;

                freeEntry(child);

                var j = i;
                while (j < parent_entry.children_count - 1) : (j += 1) {
                    parent_entry.children[j] = parent_entry.children[j + 1];
                }
                parent_entry.children[parent_entry.children_count - 1] = null;
                parent_entry.children_count -= 1;

                return true;
            }
        }
    }

    return false;
}

var static_dirent: vfs.DirEntry = undefined;
var static_dirent_init: bool = false;

fn ramfsReaddir(inode: *vfs.Inode, index: usize) ?*vfs.DirEntry {
    const entry = getEntryFromInode(inode) orelse return null;

    if (entry.inode.file_type != .Directory) return null;
    if (index >= entry.children_count) return null;

    if (entry.children[index]) |child| {
        if (!static_dirent_init) {
            var k: usize = 0;
            while (k < vfs.MAX_FILENAME) : (k += 1) {
                static_dirent.name[k] = 0;
            }
            static_dirent_init = true;
        }

        static_dirent.setName(child.getName());
        static_dirent.inode = &child.inode;
        static_dirent.file_type = child.inode.file_type;
        return &static_dirent;
    }

    return null;
}

// =============================================================================
// B2.3: Rename Operation
// =============================================================================

fn ramfsRename(old_parent: *vfs.Inode, old_name: []const u8, new_parent: *vfs.Inode, new_name: []const u8) bool {
    const old_parent_entry = getEntryFromInode(old_parent) orelse return false;
    const new_parent_entry = getEntryFromInode(new_parent) orelse return false;

    if (old_parent_entry.inode.file_type != .Directory) return false;
    if (new_parent_entry.inode.file_type != .Directory) return false;

    // Find source child
    var src_idx: ?usize = null;
    var src_child: ?*RamfsEntry = null;
    var i: usize = 0;
    while (i < old_parent_entry.children_count) : (i += 1) {
        if (old_parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), old_name)) {
                src_idx = i;
                src_child = child;
                break;
            }
        }
    }

    if (src_child == null or src_idx == null) return false;

    // Check destination name doesn't exist in new parent
    i = 0;
    while (i < new_parent_entry.children_count) : (i += 1) {
        if (new_parent_entry.children[i]) |child| {
            if (strEqual(child.getName(), new_name)) {
                return false; // Destination exists
            }
        }
    }

    const child = src_child.?;

    // Same parent — just rename in place
    if (old_parent_entry == new_parent_entry) {
        child.setName(new_name);
        return true;
    }

    // Different parent — move child
    if (new_parent_entry.children_count >= MAX_CHILDREN) return false;

    // Update child name and parent
    child.setName(new_name);
    child.parent = new_parent_entry;

    // Add to new parent
    new_parent_entry.children[new_parent_entry.children_count] = child;
    new_parent_entry.children_count += 1;

    // Remove from old parent
    const idx = src_idx.?;
    var j = idx;
    while (j < old_parent_entry.children_count - 1) : (j += 1) {
        old_parent_entry.children[j] = old_parent_entry.children[j + 1];
    }
    old_parent_entry.children[old_parent_entry.children_count - 1] = null;
    old_parent_entry.children_count -= 1;

    return true;
}

// =============================================================================
// Inode Ops Table (B2.3: added rename)
// =============================================================================

const ramfs_inode_ops = vfs.InodeOps{
    .lookup = &ramfsLookup,
    .create = &ramfsCreate,
    .mkdir = &ramfsMkdir,
    .unlink = &ramfsUnlink,
    .rmdir = &ramfsRmdir,
    .readdir = &ramfsReaddir,
    .rename = &ramfsRename,
};

// =============================================================================
// File Operations
// =============================================================================

fn ramfsRead(file: *vfs.File, buf: []u8) i64 {
    serial.writeString("[RAMFS] ramfsRead ENTER\n");

    const entry = getEntryFromInode(file.inode) orelse {
        serial.writeString("[RAMFS] getEntryFromInode FAILED\n");
        return -1;
    };

    if (entry.inode.file_type != .Regular) {
        serial.writeString("[RAMFS] not regular file\n");
        return -1;
    }

    if (entry.data == null) {
        serial.writeString("[RAMFS] data is null, returning 0\n");
        return 0;
    }

    const pos = file.position;
    if (pos >= entry.data_size) {
        serial.writeString("[RAMFS] pos >= data_size\n");
        return 0;
    }

    const available = entry.data_size - pos;
    const to_read = @min(buf.len, available);

    var i: usize = 0;
    while (i < to_read) : (i += 1) {
        buf[i] = entry.data.?[pos + i];
    }

    file.position += to_read;
    serial.writeString("[RAMFS] ramfsRead SUCCESS\n");
    return @intCast(to_read);
}

fn ramfsWrite(file: *vfs.File, buf: []const u8) i64 {
    serial.writeString("[RAMFS] ramfsWrite ENTER\n");

    const entry = getEntryFromInode(file.inode) orelse {
        serial.writeString("[RAMFS] getEntryFromInode FAILED\n");
        return -1;
    };

    serial.writeString("[RAMFS] got entry ok\n");

    if (entry.inode.file_type != .Regular) {
        serial.writeString("[RAMFS] not regular file\n");
        return -1;
    }

    serial.writeString("[RAMFS] file type ok, getting pos\n");

    const pos = if (file.flags.append) entry.data_size else file.position;

    serial.writeString("[RAMFS] pos calculated\n");

    const needed = pos + buf.len;

    serial.writeString("[RAMFS] checking capacity\n");

    if (needed > entry.data_capacity) {
        serial.writeString("[RAMFS] need to allocate new buffer\n");

        const new_capacity = ((needed / BLOCK_SIZE) + 1) * BLOCK_SIZE;
        if (new_capacity > MAX_FILE_SIZE) {
            serial.writeString("[RAMFS] exceeds max size\n");
            return -1;
        }

        serial.writeString("[RAMFS] calling kmalloc for data\n");
        const new_data = heap.kmalloc(new_capacity);
        if (new_data == null) {
            serial.writeString("[RAMFS] kmalloc FAILED\n");
            return -1;
        }

        serial.writeString("[RAMFS] kmalloc ok, casting\n");
        const new_ptr: [*]u8 = @ptrCast(@alignCast(new_data));

        if (entry.data) |old_data| {
            serial.writeString("[RAMFS] copying old data\n");
            var i: usize = 0;
            while (i < entry.data_size) : (i += 1) {
                new_ptr[i] = old_data[i];
            }
            serial.writeString("[RAMFS] freeing old data\n");
            heap.kfree(@ptrCast(old_data));
        }

        entry.data = new_ptr;
        entry.data_capacity = new_capacity;
        serial.writeString("[RAMFS] buffer ready\n");
    }

    serial.writeString("[RAMFS] writing data bytes\n");
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        entry.data.?[pos + i] = buf[i];
    }

    if (pos + buf.len > entry.data_size) {
        entry.data_size = pos + buf.len;
        entry.inode.size = entry.data_size;
    }

    file.position = pos + buf.len;

    serial.writeString("[RAMFS] ramfsWrite SUCCESS\n");
    return @intCast(buf.len);
}

fn ramfsSeek(file: *vfs.File, offset: i64, whence: vfs.SeekWhence) i64 {
    const entry = getEntryFromInode(file.inode) orelse return -1;

    const size: i64 = @intCast(entry.data_size);
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

fn ramfsClose(file: *vfs.File) void {
    _ = file;
}

const ramfs_file_ops = vfs.FileOps{
    .read = &ramfsRead,
    .write = &ramfsWrite,
    .seek = &ramfsSeek,
    .close = &ramfsClose,
};

// =============================================================================
// Helpers
// =============================================================================

fn getEntryFromInode(inode: *vfs.Inode) ?*RamfsEntry {
    if (inode.fs_data) |data| {
        const entry: *RamfsEntry = @ptrCast(@alignCast(data));
        if (entry.in_use) {
            return entry;
        }
    }
    return null;
}

/// B2.3: Public accessor for VFS truncate support
pub fn getEntryFromInodePublic(inode_ptr: *vfs.Inode) ?*RamfsEntry {
    return getEntryFromInode(inode_ptr);
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// =============================================================================
// Public API
// =============================================================================

pub fn init() bool {
    serial.writeString("[RAMFS] Initializing...\n");

    initEntryPool();

    root_entry = allocEntry();
    if (root_entry == null) {
        serial.writeString("[RAMFS] Failed root alloc\n");
        return false;
    }

    const root = root_entry.?;

    root.name[0] = '/';
    root.name_len = 1;
    root.inode.id = next_inode_id;
    next_inode_id += 1;
    root.inode.file_type = .Directory;
    root.inode.mode = vfs.FileMode.directory();
    root.inode.size = 0;
    root.inode.link_count = 2;
    root.inode.fs_data = @ptrCast(root);
    root.inode.ops = &ramfs_inode_ops;
    root.parent = null;
    root.children_count = 0;
    root.data = null;
    root.data_size = 0;
    root.data_capacity = 0;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        filesystem.name[i] = 0;
    }
    filesystem.name[0] = 'r';
    filesystem.name[1] = 'a';
    filesystem.name[2] = 'm';
    filesystem.name[3] = 'f';
    filesystem.name[4] = 's';
    filesystem.name_len = 5;
    filesystem.root = &root.inode;
    filesystem.ops = null;
    filesystem.file_ops = &ramfs_file_ops;
    filesystem.fs_data = null;

    serial.writeString("[RAMFS] filesystem.file_ops set to ramfs_file_ops\n");

    if (!vfs.mount("/", &filesystem)) {
        serial.writeString("[RAMFS] Mount failed\n");
        return false;
    }

    initialized = true;
    serial.writeString("[RAMFS] Initialized successfully\n");

    return true;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn getFileOps() *const vfs.FileOps {
    return &ramfs_file_ops;
}

pub fn getRoot() ?*RamfsEntry {
    return root_entry;
}

pub fn getEntryCount() usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_ENTRIES) : (i += 1) {
        if (entry_pool[i].in_use) count += 1;
    }
    return count;
}
