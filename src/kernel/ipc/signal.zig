//! Zamrud OS - F1: IPC Signals
//! Async notifications between processes
//! Lightweight: no data payload, just signal number

const serial = @import("../drivers/serial/serial.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");

// ============================================================================
// Signal Numbers
// ============================================================================

pub const SIG_KILL: u8 = 9;
pub const SIG_STOP: u8 = 19;
pub const SIG_CONT: u8 = 18;
pub const SIG_TERM: u8 = 15;
pub const SIG_USR1: u8 = 10;
pub const SIG_USR2: u8 = 12;
pub const SIG_ALARM: u8 = 14;
pub const SIG_PIPE: u8 = 13;
pub const SIG_CHILD: u8 = 17;
pub const SIG_INT: u8 = 2;
pub const SIG_HUP: u8 = 1;
pub const MAX_SIGNAL: u8 = 31;

// ============================================================================
// Types
// ============================================================================

pub const MAX_SIGNAL_QUEUE = 64;
pub const MAX_SIGNAL_PROCS = 64;

pub const PendingSignal = struct {
    sender_pid: u16 = 0,
    target_pid: u16 = 0,
    signal: u8 = 0,
    valid: bool = false,
};

pub const SignalEntry = struct {
    pid: u16 = 0,
    active: bool = false,
    pending: [MAX_SIGNAL + 1]bool = [_]bool{false} ** (MAX_SIGNAL + 1),
    pending_from: [MAX_SIGNAL + 1]u16 = [_]u16{0} ** (MAX_SIGNAL + 1),
    mask: u32 = 0, // bitmask of blocked signals
    signals_received: u64 = 0,
};

pub const SignalResult = enum(u8) {
    ok = 0,
    no_cap = 1,
    invalid_signal = 2,
    target_not_found = 3,
    signal_blocked = 4,
    self_signal = 5,
};

pub const SignalStats = struct {
    total_sent: u64 = 0,
    total_delivered: u64 = 0,
    total_blocked: u64 = 0,
    total_kills: u64 = 0,
    cap_violations: u64 = 0,
};

// ============================================================================
// Storage
// ============================================================================

var entries: [MAX_SIGNAL_PROCS]SignalEntry = undefined;
var entry_count: usize = 0;
pub var stats = SignalStats{};
var initialized: bool = false;

// ============================================================================
// Init
// ============================================================================

pub fn init() void {
    for (&entries) |*e| {
        e.* = SignalEntry{};
    }
    entry_count = 0;
    stats = SignalStats{};
    initialized = true;

    serial.writeString("[IPC-SIG] Signal system initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Process Registration
// ============================================================================

/// Register process for signal handling
pub fn registerProcess(pid: u16) bool {
    if (!initialized) return false;
    if (findEntry(pid) != null) return true;

    for (&entries) |*e| {
        if (!e.active) {
            e.* = SignalEntry{};
            e.pid = pid;
            e.active = true;
            entry_count += 1;
            return true;
        }
    }
    return false;
}

/// Unregister process
pub fn unregisterProcess(pid: u16) void {
    if (findEntry(pid)) |e| {
        e.active = false;
        if (entry_count > 0) entry_count -= 1;
    }
}

fn findEntry(pid: u16) ?*SignalEntry {
    for (&entries) |*e| {
        if (e.active and e.pid == pid) return e;
    }
    return null;
}

// ============================================================================
// Send Signal
// ============================================================================

/// Send signal to target process
pub fn sendSignal(sender_pid: u16, target_pid: u16, sig: u8) SignalResult {
    if (sig > MAX_SIGNAL) return .invalid_signal;

    // Kernel always allowed
    if (sender_pid != 0) {
        // SIG_KILL requires CAP_ADMIN, others require CAP_IPC
        const required = if (sig == SIG_KILL) capability.CAP_ADMIN else capability.CAP_IPC;
        if (!capability.check(sender_pid, required)) {
            stats.cap_violations += 1;
            reportSignalViolation(sender_pid, sig);
            return .no_cap;
        }
    }

    const entry = findEntry(target_pid) orelse return .target_not_found;

    // Check mask (SIG_KILL and SIG_STOP cannot be masked)
    if (sig != SIG_KILL and sig != SIG_STOP) {
        if ((entry.mask & (@as(u32, 1) << @intCast(sig))) != 0) {
            stats.total_blocked += 1;
            return .signal_blocked;
        }
    }

    // Set pending
    entry.pending[sig] = true;
    entry.pending_from[sig] = sender_pid;
    entry.signals_received += 1;
    stats.total_sent += 1;

    if (sig == SIG_KILL) stats.total_kills += 1;

    serial.writeString("[IPC-SIG] Signal ");
    printNum(sig);
    serial.writeString(" -> pid=");
    printNum(target_pid);
    serial.writeString(" from=");
    printNum(sender_pid);
    serial.writeString("\n");

    return .ok;
}

// ============================================================================
// Check & Consume Signals
// ============================================================================

/// Check if process has any pending signal
pub fn hasPending(pid: u16) bool {
    const entry = findEntry(pid) orelse return false;
    for (0..MAX_SIGNAL + 1) |i| {
        if (entry.pending[i]) return true;
    }
    return false;
}

/// Get next pending signal (and clear it)
pub fn consumeNext(pid: u16) ?struct { signal: u8, from: u16 } {
    const entry = findEntry(pid) orelse return null;

    // Priority: SIG_KILL first
    if (entry.pending[SIG_KILL]) {
        entry.pending[SIG_KILL] = false;
        stats.total_delivered += 1;
        return .{ .signal = SIG_KILL, .from = entry.pending_from[SIG_KILL] };
    }

    // Then SIG_STOP
    if (entry.pending[SIG_STOP]) {
        entry.pending[SIG_STOP] = false;
        stats.total_delivered += 1;
        return .{ .signal = SIG_STOP, .from = entry.pending_from[SIG_STOP] };
    }

    // Then others
    for (0..MAX_SIGNAL + 1) |i| {
        if (entry.pending[i]) {
            entry.pending[i] = false;
            stats.total_delivered += 1;
            return .{ .signal = @intCast(i), .from = entry.pending_from[i] };
        }
    }
    return null;
}

/// Check if specific signal is pending
pub fn isSignalPending(pid: u16, sig: u8) bool {
    if (sig > MAX_SIGNAL) return false;
    const entry = findEntry(pid) orelse return false;
    return entry.pending[sig];
}

// ============================================================================
// Signal Mask
// ============================================================================

/// Block a signal (cannot block SIGKILL/SIGSTOP)
pub fn blockSignal(pid: u16, sig: u8) bool {
    if (sig > MAX_SIGNAL) return false;
    if (sig == SIG_KILL or sig == SIG_STOP) return false; // cannot block

    const entry = findEntry(pid) orelse return false;
    entry.mask |= (@as(u32, 1) << @intCast(sig));
    return true;
}

/// Unblock a signal
pub fn unblockSignal(pid: u16, sig: u8) bool {
    if (sig > MAX_SIGNAL) return false;
    const entry = findEntry(pid) orelse return false;
    entry.mask &= ~(@as(u32, 1) << @intCast(sig));
    return true;
}

/// Get signal mask
pub fn getSignalMask(pid: u16) u32 {
    const entry = findEntry(pid) orelse return 0;
    return entry.mask;
}

// ============================================================================
// Query
// ============================================================================

pub fn getStats() SignalStats {
    return stats;
}

pub fn getRegisteredCount() usize {
    var count: usize = 0;
    for (&entries) |*e| {
        if (e.active) count += 1;
    }
    return count;
}

pub fn signalName(sig: u8) []const u8 {
    return switch (sig) {
        SIG_HUP => "SIGHUP",
        SIG_INT => "SIGINT",
        SIG_KILL => "SIGKILL",
        SIG_PIPE => "SIGPIPE",
        SIG_ALARM => "SIGALRM",
        SIG_TERM => "SIGTERM",
        SIG_USR1 => "SIGUSR1",
        SIG_USR2 => "SIGUSR2",
        SIG_CHILD => "SIGCHLD",
        SIG_CONT => "SIGCONT",
        SIG_STOP => "SIGSTOP",
        else => "SIG???",
    };
}

// ============================================================================
// Violation Reporting
// ============================================================================

fn reportSignalViolation(pid: u16, sig: u8) void {
    if (!violation.isInitialized()) return;

    var detail_buf: [32]u8 = [_]u8{0} ** 32;
    const prefix = "signal ";
    var pos: usize = 0;
    for (prefix) |c| {
        if (pos >= 32) break;
        detail_buf[pos] = c;
        pos += 1;
    }
    const sname = signalName(sig);
    for (sname) |c| {
        if (pos >= 32) break;
        detail_buf[pos] = c;
        pos += 1;
    }
    const suffix = " no cap";
    for (suffix) |c| {
        if (pos >= 32) break;
        detail_buf[pos] = c;
        pos += 1;
    }

    _ = violation.reportViolation(.{
        .violation_type = .ipc_unauthorized,
        .severity = if (sig == SIG_KILL) .high else .medium,
        .pid = pid,
        .source_ip = 0,
        .detail = detail_buf[0..pos],
    });
}

// ============================================================================
// Display
// ============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== IPC SIGNAL STATUS ===\n");
    serial.writeString("  Registered: ");
    printNum(getRegisteredCount());
    serial.writeString("\n  Sent:       ");
    printNum64(stats.total_sent);
    serial.writeString("\n  Delivered:  ");
    printNum64(stats.total_delivered);
    serial.writeString("\n  Blocked:    ");
    printNum64(stats.total_blocked);
    serial.writeString("\n  Kills:      ");
    printNum64(stats.total_kills);
    serial.writeString("\n  CAP viols:  ");
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

fn printNum64(n: u64) void {
    if (n <= 0xFFFFFFFF) {
        printNum(@as(u32, @intCast(n)));
    } else {
        serial.writeString(">4G");
    }
}
