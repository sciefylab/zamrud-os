//! Zamrud OS - F2: Shared Memory
//! F4.2: Optional encrypted shared memory regions
//! Zero-copy data sharing between processes
//! CAP_MEMORY enforced, owner-based access control

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const capability = @import("../security/capability.zig");
const violation = @import("../security/violation.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");
const aes = @import("../crypto/aes.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_REGIONS = 32;
pub const MAX_ATTACHMENTS_PER_REGION = 8;
pub const MAX_REGION_SIZE = 64 * 1024; // 64KB max
pub const MAX_REGIONS_PER_PROCESS = 4;
pub const MAX_NAME_LEN = 24;

// ============================================================================
// Types
// ============================================================================

pub const ShmPerm = enum(u8) {
    none = 0,
    read_only = 1,
    read_write = 2,
};

pub const Attachment = struct {
    pid: u16 = 0,
    perm: ShmPerm = .none,
    active: bool = false,
    attached_tick: u64 = 0,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
};

pub const SharedRegion = struct {
    id: u16 = 0,
    active: bool = false,
    owner_pid: u16 = 0,
    name: [MAX_NAME_LEN]u8 = [_]u8{0} ** MAX_NAME_LEN,
    name_len: u8 = 0,
    data: [MAX_REGION_SIZE]u8 = undefined,
    size: u32 = 0,
    used: u32 = 0,
    attachments: [MAX_ATTACHMENTS_PER_REGION]Attachment = [_]Attachment{.{}} ** MAX_ATTACHMENTS_PER_REGION,
    attachment_count: u8 = 0,
    created_tick: u64 = 0,
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    locked: bool = false,
    encrypted: bool = false, // F4.2

    pub fn getName(self: *const SharedRegion) []const u8 {
        return self.name[0..self.name_len];
    }

    fn setName(self: *SharedRegion, n: []const u8) void {
        const len = @min(n.len, MAX_NAME_LEN);
        for (0..len) |i| {
            self.name[i] = n[i];
        }
        self.name_len = @intCast(len);
    }
};

pub const ShmResult = enum(u8) {
    ok = 0,
    no_cap = 1,
    not_found = 2,
    already_exists = 3,
    table_full = 4,
    too_large = 5,
    not_owner = 6,
    not_attached = 7,
    already_attached = 8,
    attach_full = 9,
    permission_denied = 10,
    region_locked = 11,
    process_limit = 12,
    out_of_bounds = 13,
};

pub const ShmStats = struct {
    total_created: u64 = 0,
    total_destroyed: u64 = 0,
    total_attached: u64 = 0,
    total_detached: u64 = 0,
    total_reads: u64 = 0,
    total_writes: u64 = 0,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    cap_violations: u64 = 0,
    encrypted_regions: u64 = 0, // F4.2
};

// ============================================================================
// Return Types (named to avoid Zig anonymous struct mismatch)
// ============================================================================

pub const CreateResult = struct {
    result: ShmResult,
    id: u16,
};

pub const WriteResult = struct {
    result: ShmResult,
    written: usize,
};

pub const ReadResult = struct {
    result: ShmResult,
    bytes_read: usize,
};

// ============================================================================
// Storage
// ============================================================================

var regions: [MAX_REGIONS]SharedRegion = undefined;
var next_region_id: u16 = 1;
pub var stats = ShmStats{};
var initialized: bool = false;

// ============================================================================
// Init
// ============================================================================

pub fn init() void {
    for (&regions) |*r| {
        r.* = SharedRegion{};
        for (&r.data) |*b| {
            b.* = 0;
        }
    }
    next_region_id = 1;
    stats = ShmStats{};
    initialized = true;

    serial.writeString("[IPC-SHM] Shared memory initialized (max=");
    printNum(MAX_REGIONS);
    serial.writeString(" regions, ");
    printNum(MAX_REGION_SIZE / 1024);
    serial.writeString("KB/region)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Create Region
// ============================================================================

pub fn create(owner_pid: u16, name: []const u8, size: u32) CreateResult {
    return createInternal(owner_pid, name, size, false);
}

/// F4.2: Create encrypted shared memory region
pub fn createEncrypted(owner_pid: u16, name: []const u8, size: u32) CreateResult {
    if (!sys_encrypt.isInitialized() or !sys_encrypt.isMasterKeySet()) {
        return createInternal(owner_pid, name, size, false);
    }
    return createInternal(owner_pid, name, size, true);
}

fn createInternal(owner_pid: u16, name: []const u8, size: u32, encrypted: bool) CreateResult {
    if (!initialized) return .{ .result = .not_found, .id = 0 };

    if (owner_pid != 0) {
        if (!capability.check(owner_pid, capability.CAP_MEMORY)) {
            stats.cap_violations += 1;
            reportShmViolation(owner_pid, "create without CAP_MEMORY");
            return .{ .result = .no_cap, .id = 0 };
        }
    }

    if (size == 0 or size > MAX_REGION_SIZE) {
        return .{ .result = .too_large, .id = 0 };
    }

    if (findByName(name) != null) {
        return .{ .result = .already_exists, .id = 0 };
    }

    if (owner_pid != 0 and countRegionsForPid(owner_pid) >= MAX_REGIONS_PER_PROCESS) {
        return .{ .result = .process_limit, .id = 0 };
    }

    for (&regions) |*r| {
        if (!r.active) {
            const id = next_region_id;
            next_region_id += 1;

            r.* = SharedRegion{};
            r.id = id;
            r.active = true;
            r.owner_pid = owner_pid;
            r.setName(name);
            r.size = size;
            r.used = 0;
            r.created_tick = timer.getTicks();
            r.encrypted = encrypted;

            for (0..size) |i| {
                r.data[i] = 0;
            }

            r.attachments[0] = .{
                .pid = owner_pid,
                .perm = .read_write,
                .active = true,
                .attached_tick = timer.getTicks(),
                .bytes_read = 0,
                .bytes_written = 0,
            };
            r.attachment_count = 1;

            stats.total_created += 1;
            if (encrypted) stats.encrypted_regions += 1;

            serial.writeString("[IPC-SHM] Created '");
            serialPrintStr(name);
            serial.writeString("' id=");
            printNum(id);
            serial.writeString(" size=");
            printNum(size);
            if (encrypted) {
                serial.writeString(" [ENCRYPTED]");
            }
            serial.writeString("\n");

            return .{ .result = .ok, .id = id };
        }
    }

    return .{ .result = .table_full, .id = 0 };
}

// ============================================================================
// Destroy Region
// ============================================================================

pub fn destroy(pid: u16, region_id: u16) ShmResult {
    const r = findById(region_id) orelse return .not_found;

    if (pid != 0 and r.owner_pid != pid) {
        return .not_owner;
    }

    // F4.2: Secure wipe encrypted regions
    if (r.encrypted) {
        for (0..r.size) |i| {
            r.data[i] = 0;
        }
    }

    serial.writeString("[IPC-SHM] Destroyed '");
    serialPrintStr(r.getName());
    serial.writeString("'\n");

    r.active = false;
    r.attachment_count = 0;
    stats.total_destroyed += 1;

    return .ok;
}

// ============================================================================
// Attach / Detach
// ============================================================================

pub fn attach(pid: u16, region_id: u16, perm: ShmPerm) ShmResult {
    if (pid != 0) {
        if (!capability.check(pid, capability.CAP_MEMORY)) {
            stats.cap_violations += 1;
            reportShmViolation(pid, "attach without CAP_MEMORY");
            return .no_cap;
        }
    }

    const r = findById(region_id) orelse return .not_found;

    for (&r.attachments) |*a| {
        if (a.active and a.pid == pid) {
            return .already_attached;
        }
    }

    if (r.attachment_count >= MAX_ATTACHMENTS_PER_REGION) {
        return .attach_full;
    }

    if (pid != 0 and countAttachmentsForPid(pid) >= MAX_REGIONS_PER_PROCESS) {
        return .process_limit;
    }

    for (&r.attachments) |*a| {
        if (!a.active) {
            a.* = .{
                .pid = pid,
                .perm = perm,
                .active = true,
                .attached_tick = timer.getTicks(),
                .bytes_read = 0,
                .bytes_written = 0,
            };
            r.attachment_count += 1;
            stats.total_attached += 1;
            return .ok;
        }
    }

    return .attach_full;
}

pub fn detach(pid: u16, region_id: u16) ShmResult {
    const r = findById(region_id) orelse return .not_found;

    for (&r.attachments) |*a| {
        if (a.active and a.pid == pid) {
            a.active = false;
            if (r.attachment_count > 0) r.attachment_count -= 1;
            stats.total_detached += 1;

            if (r.attachment_count == 0 and r.owner_pid != 0) {
                // Secure wipe on auto-destroy
                if (r.encrypted) {
                    for (0..r.size) |i| {
                        r.data[i] = 0;
                    }
                }
                r.active = false;
                stats.total_destroyed += 1;
            }

            return .ok;
        }
    }

    return .not_attached;
}

pub fn detachAll(pid: u16) void {
    for (&regions) |*r| {
        if (!r.active) continue;

        for (&r.attachments) |*a| {
            if (a.active and a.pid == pid) {
                a.active = false;
                if (r.attachment_count > 0) r.attachment_count -= 1;
                stats.total_detached += 1;
            }
        }

        if (r.owner_pid == pid) {
            if (r.attachment_count == 0) {
                if (r.encrypted) {
                    for (0..r.size) |i| {
                        r.data[i] = 0;
                    }
                }
                r.active = false;
                stats.total_destroyed += 1;
            }
        }
    }
}

// ============================================================================
// Read / Write — F4.2: XOR encryption for encrypted regions
// ============================================================================

pub fn writeData(pid: u16, region_id: u16, offset: u32, data: []const u8) WriteResult {
    const r = findById(region_id) orelse return .{ .result = .not_found, .written = 0 };

    const att = findAttachment(r, pid) orelse {
        reportShmViolation(pid, "write not attached");
        return .{ .result = .not_attached, .written = 0 };
    };

    if (att.perm != .read_write) {
        reportShmViolation(pid, "write to read-only region");
        return .{ .result = .permission_denied, .written = 0 };
    }

    if (r.locked) return .{ .result = .region_locked, .written = 0 };
    if (offset >= r.size) return .{ .result = .out_of_bounds, .written = 0 };

    const max_write = r.size - offset;
    const write_len = @min(data.len, max_write);

    // F4.2: XOR encrypt for encrypted regions
    if (r.encrypted and sys_encrypt.isInitialized() and sys_encrypt.isMasterKeySet()) {
        if (sys_encrypt.getDomainKey(.ipc)) |ipc_key| {
            for (0..write_len) |i| {
                r.data[offset + i] = data[i] ^ ipc_key[(offset + i) % aes.KEY_SIZE];
            }
        } else {
            for (0..write_len) |i| {
                r.data[offset + i] = data[i];
            }
        }
    } else {
        for (0..write_len) |i| {
            r.data[offset + i] = data[i];
        }
    }

    const end_pos = offset + @as(u32, @intCast(write_len));
    if (end_pos > r.used) r.used = end_pos;

    att.bytes_written += write_len;
    r.total_writes += 1;
    stats.total_writes += 1;
    stats.bytes_written += write_len;

    return .{ .result = .ok, .written = write_len };
}

pub fn readData(pid: u16, region_id: u16, offset: u32, buf: []u8) ReadResult {
    const r = findById(region_id) orelse return .{ .result = .not_found, .bytes_read = 0 };

    const att = findAttachment(r, pid) orelse {
        reportShmViolation(pid, "read not attached");
        return .{ .result = .not_attached, .bytes_read = 0 };
    };

    if (att.perm == .none) {
        reportShmViolation(pid, "read with perm=none");
        return .{ .result = .permission_denied, .bytes_read = 0 };
    }

    if (offset >= r.size) return .{ .result = .out_of_bounds, .bytes_read = 0 };

    const max_read = r.size - offset;
    const read_len = @min(buf.len, max_read);

    // F4.2: XOR decrypt for encrypted regions
    if (r.encrypted and sys_encrypt.isInitialized() and sys_encrypt.isMasterKeySet()) {
        if (sys_encrypt.getDomainKey(.ipc)) |ipc_key| {
            for (0..read_len) |i| {
                buf[i] = r.data[offset + i] ^ ipc_key[(offset + i) % aes.KEY_SIZE];
            }
        } else {
            for (0..read_len) |i| {
                buf[i] = r.data[offset + i];
            }
        }
    } else {
        for (0..read_len) |i| {
            buf[i] = r.data[offset + i];
        }
    }

    att.bytes_read += read_len;
    r.total_reads += 1;
    stats.total_reads += 1;
    stats.bytes_read += read_len;

    return .{ .result = .ok, .bytes_read = read_len };
}

// ============================================================================
// Lock / Unlock
// ============================================================================

pub fn lockRegion(pid: u16, region_id: u16) ShmResult {
    const r = findById(region_id) orelse return .not_found;
    if (pid != 0 and r.owner_pid != pid) return .not_owner;
    r.locked = true;
    return .ok;
}

pub fn unlockRegion(pid: u16, region_id: u16) ShmResult {
    const r = findById(region_id) orelse return .not_found;
    if (pid != 0 and r.owner_pid != pid) return .not_owner;
    r.locked = false;
    return .ok;
}

// ============================================================================
// Query
// ============================================================================

/// F4.2: Check if region is encrypted
pub fn isRegionEncrypted(region_id: u16) bool {
    const r = findById(region_id) orelse return false;
    return r.encrypted;
}

fn findById(id: u16) ?*SharedRegion {
    for (&regions) |*r| {
        if (r.active and r.id == id) return r;
    }
    return null;
}

fn findByName(name: []const u8) ?*SharedRegion {
    for (&regions) |*r| {
        if (r.active and strEql(r.getName(), name)) return r;
    }
    return null;
}

fn findAttachment(r: *SharedRegion, pid: u16) ?*Attachment {
    if (pid == 0) return &r.attachments[0];
    for (&r.attachments) |*a| {
        if (a.active and a.pid == pid) return a;
    }
    return null;
}

fn countRegionsForPid(pid: u16) usize {
    var count: usize = 0;
    for (&regions) |*r| {
        if (r.active and r.owner_pid == pid) count += 1;
    }
    return count;
}

fn countAttachmentsForPid(pid: u16) usize {
    var count: usize = 0;
    for (&regions) |*r| {
        if (!r.active) continue;
        for (&r.attachments) |*a| {
            if (a.active and a.pid == pid) count += 1;
        }
    }
    return count;
}

pub fn getStats() ShmStats {
    return stats;
}

pub fn resetStats() void {
    stats = ShmStats{};
}

pub fn getActiveRegionCount() usize {
    var count: usize = 0;
    for (&regions) |*r| {
        if (r.active) count += 1;
    }
    return count;
}

pub fn getRegionById(id: u16) ?struct {
    name: []const u8,
    owner: u16,
    size: u32,
    used: u32,
    attachments: u8,
    locked: bool,
    encrypted: bool,
} {
    const r = findById(id) orelse return null;
    return .{
        .name = r.getName(),
        .owner = r.owner_pid,
        .size = r.size,
        .used = r.used,
        .attachments = r.attachment_count,
        .locked = r.locked,
        .encrypted = r.encrypted,
    };
}

pub fn findRegionByName(name: []const u8) ?u16 {
    const r = findByName(name) orelse return null;
    return r.id;
}

pub fn isAttached(pid: u16, region_id: u16) bool {
    const r = findById(region_id) orelse return false;
    return findAttachment(r, pid) != null;
}

pub fn getAttachmentPerm(pid: u16, region_id: u16) ShmPerm {
    const r = findById(region_id) orelse return .none;
    const att = findAttachment(r, pid) orelse return .none;
    return att.perm;
}

// ============================================================================
// Violation Reporting
// ============================================================================

fn reportShmViolation(pid: u16, reason: []const u8) void {
    if (!violation.isInitialized()) return;
    _ = violation.reportViolation(.{
        .violation_type = .memory_violation,
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
    serial.writeString("\n=== SHARED MEMORY STATUS ===\n");
    serial.writeString("  Active regions: ");
    printNum(getActiveRegionCount());
    serial.writeString("/");
    printNum(MAX_REGIONS);
    serial.writeString("\n  Created:        ");
    printNum64(stats.total_created);
    serial.writeString("\n  Destroyed:      ");
    printNum64(stats.total_destroyed);
    serial.writeString("\n  Encrypted:      ");
    printNum64(stats.encrypted_regions);
    serial.writeString("\n  Reads:          ");
    printNum64(stats.total_reads);
    serial.writeString("\n  Writes:         ");
    printNum64(stats.total_writes);
    serial.writeString("\n  Bytes read:     ");
    printNum64(stats.bytes_read);
    serial.writeString("\n  Bytes written:  ");
    printNum64(stats.bytes_written);
    serial.writeString("\n  CAP violations: ");
    printNum64(stats.cap_violations);
    serial.writeString("\n");

    var found = false;
    for (&regions) |*r| {
        if (!r.active) continue;
        if (!found) {
            serial.writeString("\n  ID   NAME                 OWNER  SIZE     USED     ATT  LOCK ENC\n");
            serial.writeString("  ---  -------------------  -----  -------  -------  ---  ---- ---\n");
            found = true;
        }
        serial.writeString("  ");
        printPadded(r.id, 3);
        serial.writeString("  ");
        serialPrintStr(r.getName());
        var pad: usize = 0;
        if (r.name_len < 19) pad = 19 - r.name_len;
        for (0..pad) |_| serial.writeChar(' ');
        serial.writeString("  ");
        printPadded(r.owner_pid, 5);
        serial.writeString("  ");
        printPadded(r.size, 7);
        serial.writeString("  ");
        printPadded(r.used, 7);
        serial.writeString("  ");
        printPadded(r.attachment_count, 3);
        serial.writeString("  ");
        serial.writeString(if (r.locked) "YES" else " NO");
        serial.writeString("  ");
        serial.writeString(if (r.encrypted) "YES" else " NO");
        serial.writeString("\n");
    }

    if (!found) {
        serial.writeString("  (no active regions)\n");
    }
    serial.writeString("\n");
}

// ============================================================================
// Name Helpers
// ============================================================================

pub fn permName(p: ShmPerm) []const u8 {
    return switch (p) {
        .none => "NONE",
        .read_only => "RO",
        .read_write => "RW",
    };
}

pub fn resultName(r: ShmResult) []const u8 {
    return switch (r) {
        .ok => "OK",
        .no_cap => "NO_CAP",
        .not_found => "NOT_FOUND",
        .already_exists => "EXISTS",
        .table_full => "TABLE_FULL",
        .too_large => "TOO_LARGE",
        .not_owner => "NOT_OWNER",
        .not_attached => "NOT_ATTACHED",
        .already_attached => "ATTACHED",
        .attach_full => "ATTACH_FULL",
        .permission_denied => "PERM_DENIED",
        .region_locked => "LOCKED",
        .process_limit => "PROC_LIMIT",
        .out_of_bounds => "OOB",
    };
}

// ============================================================================
// Helpers
// ============================================================================

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn serialPrintStr(s: []const u8) void {
    for (s) |c| serial.writeChar(c);
}

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

fn printPadded(n: anytype, width: usize) void {
    const val: u32 = @intCast(n);
    var d: usize = 1;
    var tmp = val;
    while (tmp >= 10) : (d += 1) tmp /= 10;
    if (d < width) {
        for (0..width - d) |_| serial.writeChar(' ');
    }
    printNum(val);
}
