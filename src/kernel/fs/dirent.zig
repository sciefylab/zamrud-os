//! Zamrud OS - Directory Entry
//! Directory entry structure and operations

const inode_mod = @import("inode.zig");
const Inode = inode_mod.Inode;
const FileType = inode_mod.FileType;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_FILENAME: usize = 128;
pub const MAX_PATH: usize = 256;

// =============================================================================
// Directory Entry
// =============================================================================

pub const DirEntry = struct {
    /// File name
    name: [MAX_FILENAME]u8 = [_]u8{0} ** MAX_FILENAME,

    /// Name length
    name_len: u8 = 0,

    /// Pointer to inode
    inode: ?*Inode = null,

    /// File type (cached from inode)
    file_type: FileType = .Regular,

    /// Inode number (for persistent filesystems)
    ino: u64 = 0,

    /// Record length (for variable-length entries)
    rec_len: u16 = 0,

    // =========================================================================
    // Name Operations
    // =========================================================================

    /// Get the name as a slice
    pub fn getName(self: *const DirEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Set the name from a slice
    pub fn setName(self: *DirEntry, new_name: []const u8) void {
        const len = @min(new_name.len, MAX_FILENAME);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name[i] = new_name[i];
        }
        // Clear rest of buffer
        while (i < MAX_FILENAME) : (i += 1) {
            self.name[i] = 0;
        }
        self.name_len = @intCast(len);
    }

    /// Compare name with a string
    pub fn nameEquals(self: *const DirEntry, other: []const u8) bool {
        if (self.name_len != other.len) return false;
        var i: usize = 0;
        while (i < self.name_len) : (i += 1) {
            if (self.name[i] != other[i]) return false;
        }
        return true;
    }

    /// Check if name starts with a prefix
    pub fn nameStartsWith(self: *const DirEntry, prefix: []const u8) bool {
        if (self.name_len < prefix.len) return false;
        var i: usize = 0;
        while (i < prefix.len) : (i += 1) {
            if (self.name[i] != prefix[i]) return false;
        }
        return true;
    }

    // =========================================================================
    // Type Checks
    // =========================================================================

    /// Check if entry is a directory
    pub fn isDirectory(self: *const DirEntry) bool {
        return self.file_type == .Directory;
    }

    /// Check if entry is a regular file
    pub fn isRegular(self: *const DirEntry) bool {
        return self.file_type == .Regular;
    }

    /// Check if entry is a device
    pub fn isDevice(self: *const DirEntry) bool {
        return self.file_type == .CharDevice or self.file_type == .BlockDevice;
    }

    /// Check if entry is a symlink
    pub fn isSymlink(self: *const DirEntry) bool {
        return self.file_type == .Symlink;
    }

    /// Check if this is the "." entry
    pub fn isDot(self: *const DirEntry) bool {
        return self.name_len == 1 and self.name[0] == '.';
    }

    /// Check if this is the ".." entry
    pub fn isDotDot(self: *const DirEntry) bool {
        return self.name_len == 2 and self.name[0] == '.' and self.name[1] == '.';
    }

    /// Check if this is a hidden file (starts with .)
    pub fn isHidden(self: *const DirEntry) bool {
        return self.name_len > 0 and self.name[0] == '.';
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /// Initialize from inode
    pub fn initFromInode(self: *DirEntry, name: []const u8, ino: *Inode) void {
        self.setName(name);
        self.inode = ino;
        self.file_type = ino.file_type;
        self.ino = ino.id;
    }

    /// Create a new entry
    pub fn create(name: []const u8, ino: *Inode) DirEntry {
        var entry = DirEntry{};
        entry.initFromInode(name, ino);
        return entry;
    }

    /// Clear the entry
    pub fn clear(self: *DirEntry) void {
        self.name_len = 0;
        self.inode = null;
        self.file_type = .Regular;
        self.ino = 0;
        var i: usize = 0;
        while (i < MAX_FILENAME) : (i += 1) {
            self.name[i] = 0;
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /// Get file type as string
    pub fn getTypeString(self: *const DirEntry) []const u8 {
        return self.file_type.toString();
    }

    /// Get size (from inode if available)
    pub fn getSize(self: *const DirEntry) u64 {
        if (self.inode) |ino| {
            return ino.size;
        }
        return 0;
    }

    /// Copy entry to another
    pub fn copyTo(self: *const DirEntry, dest: *DirEntry) void {
        var i: usize = 0;
        while (i < MAX_FILENAME) : (i += 1) {
            dest.name[i] = self.name[i];
        }
        dest.name_len = self.name_len;
        dest.inode = self.inode;
        dest.file_type = self.file_type;
        dest.ino = self.ino;
        dest.rec_len = self.rec_len;
    }
};

// =============================================================================
// Directory Entry Buffer
// =============================================================================

pub const DirEntryBuffer = struct {
    entries: [64]DirEntry = [_]DirEntry{.{}} ** 64,
    count: usize = 0,
    position: usize = 0,

    /// Add an entry
    pub fn add(self: *DirEntryBuffer, entry: *const DirEntry) bool {
        if (self.count >= 64) return false;
        entry.copyTo(&self.entries[self.count]);
        self.count += 1;
        return true;
    }

    /// Get entry at index
    pub fn get(self: *DirEntryBuffer, index: usize) ?*DirEntry {
        if (index >= self.count) return null;
        return &self.entries[index];
    }

    /// Get next entry (iterator style)
    pub fn next(self: *DirEntryBuffer) ?*DirEntry {
        if (self.position >= self.count) return null;
        const entry = &self.entries[self.position];
        self.position += 1;
        return entry;
    }

    /// Reset iterator
    pub fn rewind(self: *DirEntryBuffer) void {
        self.position = 0;
    }

    /// Clear all entries
    pub fn clear(self: *DirEntryBuffer) void {
        self.count = 0;
        self.position = 0;
    }

    /// Find entry by name
    pub fn find(self: *DirEntryBuffer, name: []const u8) ?*DirEntry {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].nameEquals(name)) {
                return &self.entries[i];
            }
        }
        return null;
    }

    /// Sort entries by name (simple bubble sort)
    pub fn sortByName(self: *DirEntryBuffer) void {
        if (self.count < 2) return;

        var i: usize = 0;
        while (i < self.count - 1) : (i += 1) {
            var j: usize = 0;
            while (j < self.count - 1 - i) : (j += 1) {
                if (compareNames(&self.entries[j], &self.entries[j + 1]) > 0) {
                    // Swap
                    var temp: DirEntry = undefined;
                    self.entries[j].copyTo(&temp);
                    self.entries[j + 1].copyTo(&self.entries[j]);
                    temp.copyTo(&self.entries[j + 1]);
                }
            }
        }
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Compare two entry names
fn compareNames(a: *const DirEntry, b: *const DirEntry) i32 {
    const len = @min(a.name_len, b.name_len);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (a.name[i] < b.name[i]) return -1;
        if (a.name[i] > b.name[i]) return 1;
    }
    if (a.name_len < b.name_len) return -1;
    if (a.name_len > b.name_len) return 1;
    return 0;
}

/// Validate filename
pub fn isValidFilename(name: []const u8) bool {
    if (name.len == 0 or name.len > MAX_FILENAME) return false;

    // Check for invalid characters
    for (name) |c| {
        if (c == 0 or c == '/') return false;
    }

    // Check for reserved names
    if (name.len == 1 and name[0] == '.') return true; // . is ok
    if (name.len == 2 and name[0] == '.' and name[1] == '.') return true; // .. is ok

    return true;
}

/// Get file extension
pub fn getExtension(name: []const u8) ?[]const u8 {
    var last_dot: ?usize = null;
    var i: usize = 0;
    while (i < name.len) : (i += 1) {
        if (name[i] == '.') {
            last_dot = i;
        }
    }

    if (last_dot) |dot| {
        if (dot + 1 < name.len) {
            return name[dot + 1 ..];
        }
    }
    return null;
}

/// Get basename (filename without extension)
pub fn getBasename(name: []const u8) []const u8 {
    var last_dot: ?usize = null;
    var i: usize = 0;
    while (i < name.len) : (i += 1) {
        if (name[i] == '.') {
            last_dot = i;
        }
    }

    if (last_dot) |dot| {
        if (dot > 0) {
            return name[0..dot];
        }
    }
    return name;
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test DirEntry name operations
    var entry = DirEntry{};
    entry.setName("test.txt");

    if (entry.nameEquals("test.txt")) {
        passed += 1;
    } else {
        failed += 1;
    }

    if (entry.nameStartsWith("test")) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test filename validation
    if (isValidFilename("valid_file.txt")) {
        passed += 1;
    } else {
        failed += 1;
    }

    if (!isValidFilename("invalid/name")) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test extension
    const ext = getExtension("file.txt");
    if (ext != null and strEq(ext.?, "txt")) {
        passed += 1;
    } else {
        failed += 1;
    }

    return failed == 0;
}

fn strEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}
