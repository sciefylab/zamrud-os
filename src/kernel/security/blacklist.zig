// ============================================================================
// ZAMRUD OS - BLACKLIST SYSTEM
// ============================================================================

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// =============================================================================
// Types
// =============================================================================

pub const BlacklistEntry = struct {
    ip: u32,
    added_at: u64,
    expires_at: u64,
    permanent: bool,
    reason: [32]u8,
    reason_len: usize,
    hit_count: u64,
};

// =============================================================================
// Storage
// =============================================================================

const MAX_ENTRIES = 256;
var entries: [MAX_ENTRIES]BlacklistEntry = undefined;
var entry_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&entries) |*e| {
        e.* = emptyEntry();
    }
    entry_count = 0;

    serial.writeString("[BLACKLIST] Initialized\n");
}

fn emptyEntry() BlacklistEntry {
    return BlacklistEntry{
        .ip = 0,
        .added_at = 0,
        .expires_at = 0,
        .permanent = false,
        .reason = [_]u8{0} ** 32,
        .reason_len = 0,
        .hit_count = 0,
    };
}

// =============================================================================
// Management
// =============================================================================

pub fn addToBlacklist(ip: u32, duration_sec: u64, reason: []const u8) bool {
    const now = timer.getTicks();

    // Check if already exists
    for (entries[0..entry_count]) |*e| {
        if (e.ip == ip) {
            // Update expiry
            e.expires_at = now + (duration_sec * 1000);
            e.hit_count += 1;
            return true;
        }
    }

    if (entry_count >= MAX_ENTRIES) {
        // Remove oldest non-permanent
        removeOldest();
    }

    if (entry_count >= MAX_ENTRIES) {
        return false;
    }

    var entry = &entries[entry_count];
    entry.ip = ip;
    entry.added_at = now;
    entry.expires_at = now + (duration_sec * 1000);
    entry.permanent = false;
    entry.hit_count = 1;

    const reason_len = @min(reason.len, 32);
    @memcpy(entry.reason[0..reason_len], reason[0..reason_len]);
    entry.reason_len = reason_len;

    entry_count += 1;

    return true;
}

pub fn isBlacklisted(ip: u32) bool {
    const now = timer.getTicks();

    var i: usize = 0;
    while (i < entry_count) {
        if (entries[i].ip == ip) {
            // Check expiry
            if (!entries[i].permanent and entries[i].expires_at < now) {
                // Expired - remove
                removeAtIndex(i);
                return false;
            }

            entries[i].hit_count += 1;
            return true;
        }
        i += 1;
    }
    return false;
}

pub fn removeFromBlacklist(ip: u32) bool {
    for (0..entry_count) |i| {
        if (entries[i].ip == ip) {
            removeAtIndex(i);
            return true;
        }
    }
    return false;
}

fn removeAtIndex(index: usize) void {
    for (index..entry_count - 1) |j| {
        entries[j] = entries[j + 1];
    }
    entry_count -= 1;
}

fn removeOldest() void {
    var oldest_idx: usize = 0;
    var oldest_time: u64 = 0xFFFFFFFFFFFFFFFF;

    for (0..entry_count) |i| {
        if (!entries[i].permanent and entries[i].added_at < oldest_time) {
            oldest_time = entries[i].added_at;
            oldest_idx = i;
        }
    }

    if (!entries[oldest_idx].permanent) {
        removeAtIndex(oldest_idx);
    }
}

// =============================================================================
// Query
// =============================================================================

pub fn getActiveCount() u64 {
    return entry_count;
}

pub fn getEntry(index: usize) ?*const BlacklistEntry {
    if (index >= entry_count) return null;
    return &entries[index];
}
