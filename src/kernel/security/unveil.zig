//! Zamrud OS - Filesystem Sandbox / Unveil System (E3.2)
//! Per-process path visibility control
//! Inspired by OpenBSD unveil(2)
//!
//! Design:
//!   - Each process has up to MAX_UNVEIL_ENTRIES visible paths
//!   - Paths not in the table = BLOCKED
//!   - No table registered = FULL ACCESS (backward compat)
//!   - Once locked, no more paths can be added
//!   - ~O(n) check where n = entries per process (max 16)

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_UNVEIL_PROCESSES: usize = 32;
pub const MAX_UNVEIL_ENTRIES: usize = 16;
pub const MAX_UNVEIL_PATH: usize = 128;

// =============================================================================
// Permissions
// =============================================================================

pub const PERM_READ: u8 = 1 << 0;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_EXEC: u8 = 1 << 2;
pub const PERM_CREATE: u8 = 1 << 3;

pub const PERM_RW: u8 = PERM_READ | PERM_WRITE;
pub const PERM_ALL: u8 = PERM_READ | PERM_WRITE | PERM_EXEC | PERM_CREATE;
pub const PERM_NONE: u8 = 0;

// =============================================================================
// Unveil Entry - one allowed path for a process
// =============================================================================

pub const UnveilEntry = struct {
    path_buf: [MAX_UNVEIL_PATH]u8 = [_]u8{0} ** MAX_UNVEIL_PATH,
    path_len: u16 = 0,
    perms: u8 = PERM_NONE,
    active: bool = false,

    pub fn getPath(self: *const UnveilEntry) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    pub fn setPath(self: *UnveilEntry, p: []const u8) void {
        const len = @min(p.len, MAX_UNVEIL_PATH);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.path_buf[i] = p[i];
        }
        self.path_len = @intCast(len);
    }
};

// =============================================================================
// Per-Process Unveil Table
// =============================================================================

pub const UnveilTable = struct {
    pid: u32 = 0,
    entries: [MAX_UNVEIL_ENTRIES]UnveilEntry = [_]UnveilEntry{.{}} ** MAX_UNVEIL_ENTRIES,
    entry_count: u8 = 0,
    locked: bool = false,
    active: bool = false,
};

// =============================================================================
// Global State
// =============================================================================

var tables: [MAX_UNVEIL_PROCESSES]UnveilTable = [_]UnveilTable{.{}} ** MAX_UNVEIL_PROCESSES;
var violation_count: u64 = 0;
var initialized: bool = false;

// =============================================================================
// Init
// =============================================================================

pub fn init() void {
    serial.writeString("[UNVEIL] Initializing filesystem sandbox...\n");

    var i: usize = 0;
    while (i < MAX_UNVEIL_PROCESSES) : (i += 1) {
        tables[i] = .{};
    }

    violation_count = 0;
    initialized = true;
    serial.writeString("[UNVEIL] Filesystem sandbox ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Internal: Find table by PID
// =============================================================================

fn findTable(pid: u32) ?*UnveilTable {
    var i: usize = 0;
    while (i < MAX_UNVEIL_PROCESSES) : (i += 1) {
        if (tables[i].active and tables[i].pid == pid) {
            return &tables[i];
        }
    }
    return null;
}

fn findFreeTable() ?*UnveilTable {
    var i: usize = 0;
    while (i < MAX_UNVEIL_PROCESSES) : (i += 1) {
        if (!tables[i].active) {
            return &tables[i];
        }
    }
    return null;
}

// =============================================================================
// Table Management
// =============================================================================

/// Create unveil table for a process (starts empty = nothing visible)
pub fn createTable(pid: u32) bool {
    if (!initialized) return false;
    if (pid == 0) return false; // kernel never sandboxed

    // Already exists?
    if (findTable(pid) != null) return true;

    const table = findFreeTable() orelse return false;

    table.pid = pid;
    table.entry_count = 0;
    table.locked = false;
    table.active = true;

    var i: usize = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        table.entries[i] = .{};
    }

    serial.writeString("[UNVEIL] Created table for PID=");
    printDec32(pid);
    serial.writeString("\n");

    return true;
}

/// Remove unveil table (on process terminate)
pub fn destroyTable(pid: u32) void {
    if (findTable(pid)) |table| {
        table.active = false;
        table.pid = 0;
        table.entry_count = 0;
        table.locked = false;
    }
}

/// Add an allowed path with permissions
/// Returns false if table is locked or full
pub fn addEntry(pid: u32, file_path: []const u8, perms: u8) bool {
    if (!initialized) return false;
    if (pid == 0) return false;

    const table = findTable(pid) orelse return false;

    if (table.locked) {
        serial.writeString("[UNVEIL] DENIED: table locked for PID=");
        printDec32(pid);
        serial.writeString("\n");
        return false;
    }

    if (table.entry_count >= MAX_UNVEIL_ENTRIES) return false;

    // Check if path already exists - update perms
    var i: usize = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        if (table.entries[i].active) {
            if (pathEqual(table.entries[i].getPath(), file_path)) {
                table.entries[i].perms = perms;
                return true;
            }
        }
    }

    // Find free entry
    i = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        if (!table.entries[i].active) {
            table.entries[i].setPath(file_path);
            table.entries[i].perms = perms;
            table.entries[i].active = true;
            table.entry_count += 1;
            return true;
        }
    }

    return false;
}

/// Remove an allowed path
pub fn removeEntry(pid: u32, file_path: []const u8) bool {
    if (!initialized) return false;

    const table = findTable(pid) orelse return false;
    if (table.locked) return false;

    var i: usize = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        if (table.entries[i].active) {
            if (pathEqual(table.entries[i].getPath(), file_path)) {
                table.entries[i] = .{};
                if (table.entry_count > 0) table.entry_count -= 1;
                return true;
            }
        }
    }
    return false;
}

/// Lock the table - no more entries can be added
pub fn lock(pid: u32) bool {
    if (findTable(pid)) |table| {
        table.locked = true;
        serial.writeString("[UNVEIL] Locked table for PID=");
        printDec32(pid);
        serial.writeString("\n");
        return true;
    }
    return false;
}

/// Check if process has an unveil table
pub fn hasTable(pid: u32) bool {
    return findTable(pid) != null;
}

/// Check if table is locked
pub fn isLocked(pid: u32) bool {
    if (findTable(pid)) |table| {
        return table.locked;
    }
    return false;
}

// =============================================================================
// Permission Check (HOT PATH - called on every file operation)
// =============================================================================

/// Check if process is allowed to access path with given permission
/// Returns true if:
///   - PID is 0 (kernel)
///   - Process has no unveil table (backward compat = full access)
///   - Path matches an entry with required permission
pub inline fn checkAccess(pid: u32, file_path: []const u8, required_perm: u8) bool {
    // Kernel always allowed
    if (pid == 0) return true;

    // No unveil system
    if (!initialized) return true;

    // No table = full access (backward compat)
    const table = findTable(pid) orelse return true;

    // Check entries
    var i: usize = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        if (table.entries[i].active) {
            if (pathMatchesEntry(file_path, table.entries[i].getPath())) {
                // Path matches - check permission
                return (table.entries[i].perms & required_perm) == required_perm;
            }
        }
    }

    // No matching entry = DENIED
    return false;
}

/// Check and log violation
pub fn checkAndEnforce(pid: u32, file_path: []const u8, required_perm: u8) bool {
    if (checkAccess(pid, file_path, required_perm)) return true;

    // Record violation
    violation_count += 1;

    serial.writeString("[UNVEIL] VIOLATION: PID=");
    printDec32(pid);
    serial.writeString(" path=");
    serialPrintPath(file_path);
    serial.writeString(" perm=");
    printPermStr(required_perm);
    serial.writeString("\n");

    return false;
}

// =============================================================================
// Path Matching
// =============================================================================

/// Check if file_path falls under (or equals) an unveil entry path
/// "/home" matches "/home", "/home/user", "/home/user/file.txt"
/// "/" matches everything
fn pathMatchesEntry(file_path: []const u8, entry_path: []const u8) bool {
    // Root entry matches everything
    if (entry_path.len == 1 and entry_path[0] == '/') return true;

    // Exact match
    if (pathEqual(file_path, entry_path)) return true;

    // file_path starts with entry_path + "/"
    if (file_path.len > entry_path.len) {
        var i: usize = 0;
        while (i < entry_path.len) : (i += 1) {
            if (file_path[i] != entry_path[i]) return false;
        }
        // Next char must be '/' for directory prefix match
        if (file_path[entry_path.len] == '/') return true;
    }

    return false;
}

fn pathEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// =============================================================================
// Query Functions (for shell)
// =============================================================================

pub fn getViolationCount() u64 {
    return violation_count;
}

pub fn getEntryCount(pid: u32) u8 {
    if (findTable(pid)) |table| {
        return table.entry_count;
    }
    return 0;
}

pub fn getEntry(pid: u32, index: usize) ?struct {
    path: []const u8,
    perms: u8,
} {
    const table = findTable(pid) orelse return null;

    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_UNVEIL_ENTRIES) : (i += 1) {
        if (table.entries[i].active) {
            if (count == index) {
                return .{
                    .path = table.entries[i].getPath(),
                    .perms = table.entries[i].perms,
                };
            }
            count += 1;
        }
    }
    return null;
}

pub fn getTableCount() usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_UNVEIL_PROCESSES) : (i += 1) {
        if (tables[i].active) count += 1;
    }
    return count;
}

/// Format permission byte as string
pub fn formatPerms(perms: u8, buf: []u8) usize {
    var pos: usize = 0;
    if (perms == PERM_NONE) {
        if (buf.len >= 4) {
            buf[0] = 'N';
            buf[1] = 'O';
            buf[2] = 'N';
            buf[3] = 'E';
            return 4;
        }
        return 0;
    }
    if ((perms & PERM_READ) != 0 and pos < buf.len) {
        buf[pos] = 'r';
        pos += 1;
    }
    if ((perms & PERM_WRITE) != 0 and pos < buf.len) {
        buf[pos] = 'w';
        pos += 1;
    }
    if ((perms & PERM_EXEC) != 0 and pos < buf.len) {
        buf[pos] = 'x';
        pos += 1;
    }
    if ((perms & PERM_CREATE) != 0 and pos < buf.len) {
        buf[pos] = 'c';
        pos += 1;
    }
    return pos;
}

/// Parse permission string to byte
pub fn parsePerms(s: []const u8) u8 {
    var perms: u8 = 0;
    for (s) |c| {
        switch (c) {
            'r', 'R' => perms |= PERM_READ,
            'w', 'W' => perms |= PERM_WRITE,
            'x', 'X' => perms |= PERM_EXEC,
            'c', 'C' => perms |= PERM_CREATE,
            else => {},
        }
    }
    return perms;
}

// =============================================================================
// Print helpers
// =============================================================================

fn serialPrintPath(p: []const u8) void {
    const max_print: usize = 64;
    const len = @min(p.len, max_print);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        serial.writeChar(p[i]);
    }
    if (p.len > max_print) {
        serial.writeString("...");
    }
}

fn printPermStr(perms: u8) void {
    if ((perms & PERM_READ) != 0) serial.writeChar('r');
    if ((perms & PERM_WRITE) != 0) serial.writeChar('w');
    if ((perms & PERM_EXEC) != 0) serial.writeChar('x');
    if ((perms & PERM_CREATE) != 0) serial.writeChar('c');
    if (perms == PERM_NONE) serial.writeString("none");
}

fn printDec32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v: u32 = val;
    var started = false;
    const divs = [_]u32{ 1000000000, 100000000, 10000000, 1000000, 100000, 10000, 1000, 100, 10, 1 };
    for (divs) |d| {
        var digit: u8 = 0;
        while (v >= d) : (digit += 1) v -= d;
        if (digit > 0 or started) {
            serial.writeChar('0' + digit);
            started = true;
        }
    }
}
