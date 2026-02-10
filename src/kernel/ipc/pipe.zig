//! Zamrud OS - F1: IPC Pipes
//! Unidirectional byte streams between processes
//! Capability-gated: requires CAP_IPC

const serial = @import("../drivers/serial/serial.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PIPES = 32;
pub const PIPE_BUF_SIZE = 256;

// ============================================================================
// Types
// ============================================================================

pub const Pipe = struct {
    id: u16 = 0,
    active: bool = false,
    writer_pid: u16 = 0,
    reader_pid: u16 = 0,
    buf: [PIPE_BUF_SIZE]u8 = [_]u8{0} ** PIPE_BUF_SIZE,
    head: u16 = 0,
    tail: u16 = 0,
    count: u16 = 0,
    closed_write: bool = false,
    closed_read: bool = false,
    bytes_written: u64 = 0,
    bytes_read: u64 = 0,
};

pub const PipeResult = enum(u8) {
    ok = 0,
    no_cap = 1,
    pipe_full = 2,
    pipe_empty = 3,
    pipe_closed = 4,
    not_found = 5,
    not_owner = 6,
    table_full = 7,
};

pub const PipeStats = struct {
    total_created: u64 = 0,
    total_closed: u64 = 0,
    total_bytes_written: u64 = 0,
    total_bytes_read: u64 = 0,
    cap_violations: u64 = 0,
};

// ============================================================================
// Storage
// ============================================================================

var pipes: [MAX_PIPES]Pipe = undefined;
var next_pipe_id: u16 = 1;
pub var stats = PipeStats{};
var initialized: bool = false;

// ============================================================================
// Init
// ============================================================================

pub fn init() void {
    for (&pipes) |*p| {
        p.* = Pipe{};
    }
    next_pipe_id = 1;
    stats = PipeStats{};
    initialized = true;

    serial.writeString("[IPC-PIPE] Pipe system initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Pipe Creation
// ============================================================================

/// Create a pipe: writer_pid writes, reader_pid reads
pub fn create(writer_pid: u16, reader_pid: u16) ?u16 {
    if (!initialized) return null;

    // CAP_IPC check for non-kernel
    if (writer_pid != 0) {
        if (!capability.check(writer_pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportPipeViolation(writer_pid, "pipe create no CAP_IPC");
            return null;
        }
    }

    // Find free slot
    for (&pipes) |*p| {
        if (!p.active) {
            const id = next_pipe_id;
            next_pipe_id += 1;

            p.* = Pipe{};
            p.id = id;
            p.active = true;
            p.writer_pid = writer_pid;
            p.reader_pid = reader_pid;

            stats.total_created += 1;

            serial.writeString("[IPC-PIPE] Created pipe=");
            printNum(id);
            serial.writeString(" writer=");
            printNum(writer_pid);
            serial.writeString(" reader=");
            printNum(reader_pid);
            serial.writeString("\n");

            return id;
        }
    }
    return null; // table full
}

/// Close a pipe
pub fn close(pipe_id: u16) bool {
    const p = findPipe(pipe_id) orelse return false;
    p.active = false;
    stats.total_closed += 1;
    return true;
}

/// Close write end of pipe
pub fn closeWrite(pipe_id: u16, pid: u16) PipeResult {
    const p = findPipe(pipe_id) orelse return .not_found;
    if (p.writer_pid != pid and pid != 0) return .not_owner;
    p.closed_write = true;
    return .ok;
}

/// Close read end of pipe
pub fn closeRead(pipe_id: u16, pid: u16) PipeResult {
    const p = findPipe(pipe_id) orelse return .not_found;
    if (p.reader_pid != pid and pid != 0) return .not_owner;
    p.closed_read = true;
    return .ok;
}

// ============================================================================
// Write to Pipe
// ============================================================================

/// Write data to pipe (only writer_pid or kernel allowed)
pub fn write(pipe_id: u16, pid: u16, data: []const u8) struct { result: PipeResult, written: usize } {
    // CAP_IPC check
    if (pid != 0) {
        if (!capability.check(pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportPipeViolation(pid, "pipe write no CAP_IPC");
            return .{ .result = .no_cap, .written = 0 };
        }
    }

    const p = findPipe(pipe_id) orelse return .{ .result = .not_found, .written = 0 };

    // Check ownership
    if (p.writer_pid != pid and pid != 0) return .{ .result = .not_owner, .written = 0 };

    // Check closed
    if (p.closed_write) return .{ .result = .pipe_closed, .written = 0 };
    if (p.closed_read) return .{ .result = .pipe_closed, .written = 0 };

    // Write as much as fits
    var written: usize = 0;
    for (data) |byte| {
        if (p.count >= PIPE_BUF_SIZE) break;

        p.buf[p.tail] = byte;
        p.tail = (p.tail + 1) % PIPE_BUF_SIZE;
        p.count += 1;
        written += 1;
    }

    p.bytes_written += written;
    stats.total_bytes_written += written;

    return .{ .result = .ok, .written = written };
}

// ============================================================================
// Read from Pipe
// ============================================================================

/// Read data from pipe (only reader_pid or kernel allowed)
pub fn read(pipe_id: u16, pid: u16, buf: []u8) struct { result: PipeResult, bytes_read: usize } {
    // CAP_IPC check
    if (pid != 0) {
        if (!capability.check(pid, capability.CAP_IPC)) {
            stats.cap_violations += 1;
            reportPipeViolation(pid, "pipe read no CAP_IPC");
            return .{ .result = .no_cap, .bytes_read = 0 };
        }
    }

    const p = findPipe(pipe_id) orelse return .{ .result = .not_found, .bytes_read = 0 };

    // Check ownership
    if (p.reader_pid != pid and pid != 0) return .{ .result = .not_owner, .bytes_read = 0 };

    // Empty
    if (p.count == 0) {
        if (p.closed_write) return .{ .result = .pipe_closed, .bytes_read = 0 };
        return .{ .result = .pipe_empty, .bytes_read = 0 };
    }

    // Read as much as available
    var read_count: usize = 0;
    while (read_count < buf.len and p.count > 0) {
        buf[read_count] = p.buf[p.head];
        p.head = (p.head + 1) % PIPE_BUF_SIZE;
        p.count -= 1;
        read_count += 1;
    }

    p.bytes_read += read_count;
    stats.total_bytes_read += read_count;

    return .{ .result = .ok, .bytes_read = read_count };
}

/// Get available bytes in pipe
pub fn available(pipe_id: u16) u16 {
    const p = findPipe(pipe_id) orelse return 0;
    return p.count;
}

// ============================================================================
// Close all pipes for a PID (on process exit)
// ============================================================================

pub fn closeAllForPid(pid: u16) void {
    for (&pipes) |*p| {
        if (!p.active) continue;
        if (p.writer_pid == pid) p.closed_write = true;
        if (p.reader_pid == pid) p.closed_read = true;
        if (p.closed_write and p.closed_read) {
            p.active = false;
            stats.total_closed += 1;
        }
    }
}

// ============================================================================
// Lookup
// ============================================================================

fn findPipe(pipe_id: u16) ?*Pipe {
    for (&pipes) |*p| {
        if (p.active and p.id == pipe_id) return p;
    }
    return null;
}

// ============================================================================
// Query API
// ============================================================================

pub fn getStats() PipeStats {
    return stats;
}

pub fn getActivePipeCount() usize {
    var count: usize = 0;
    for (&pipes) |*p| {
        if (p.active) count += 1;
    }
    return count;
}

pub fn getPipeInfo(pipe_id: u16) ?struct {
    writer: u16,
    reader: u16,
    buffered: u16,
    bytes_written: u64,
    bytes_read: u64,
} {
    const p = findPipe(pipe_id) orelse return null;
    return .{
        .writer = p.writer_pid,
        .reader = p.reader_pid,
        .buffered = p.count,
        .bytes_written = p.bytes_written,
        .bytes_read = p.bytes_read,
    };
}

// ============================================================================
// Violation Reporting
// ============================================================================

fn reportPipeViolation(pid: u16, reason: []const u8) void {
    if (!violation.isInitialized()) return;

    _ = violation.reportViolation(.{
        .violation_type = .ipc_unauthorized,
        .severity = .medium,
        .pid = pid,
        .source_ip = 0,
        .detail = reason,
    });
}

// ============================================================================
// Display
// ============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== IPC PIPE STATUS ===\n");
    serial.writeString("  Active pipes: ");
    printNum(getActivePipeCount());
    serial.writeString("/");
    printNum(MAX_PIPES);
    serial.writeString("\n  Created:      ");
    printNum64(stats.total_created);
    serial.writeString("\n  Closed:       ");
    printNum64(stats.total_closed);
    serial.writeString("\n  Bytes written:");
    printNum64(stats.total_bytes_written);
    serial.writeString("\n  Bytes read:   ");
    printNum64(stats.total_bytes_read);
    serial.writeString("\n  CAP viols:    ");
    printNum64(stats.cap_violations);
    serial.writeString("\n");
}

// ============================================================================
// Helpers
// ============================================================================

fn printNum(n: anytype) void {
    const val: u32 = @intCast(n);
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf_arr: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf_arr[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf_arr[i]);
    }
}

fn printNum64(n: u64) void {
    if (n <= 0xFFFFFFFF) {
        printNum(@as(u32, @intCast(n)));
    } else {
        serial.writeString(">4G");
    }
}
