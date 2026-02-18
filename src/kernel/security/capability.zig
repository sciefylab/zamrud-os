//! Zamrud OS - Process Capability System (E3.1)
//! Bitwise capability enforcement per-process
//! Design: ZERO-overhead when all caps granted (bitwise AND check)
//! E3.6: Wired to violation.zig unified pipeline
//! SC1: syscallRequiredCap updated to match numbers.zig

const serial = @import("../drivers/serial/serial.zig");
const violation = @import("violation.zig");
const numbers = @import("../syscall/numbers.zig");

// =============================================================================
// Capability Bits - Each bit = one permission
// =============================================================================

pub const CAP_NET: u32 = 1 << 0;
pub const CAP_FS_READ: u32 = 1 << 1;
pub const CAP_FS_WRITE: u32 = 1 << 2;
pub const CAP_IPC: u32 = 1 << 3;
pub const CAP_EXEC: u32 = 1 << 4;
pub const CAP_DEVICE: u32 = 1 << 5;
pub const CAP_GRAPHICS: u32 = 1 << 6;
pub const CAP_CRYPTO: u32 = 1 << 7;
pub const CAP_CHAIN: u32 = 1 << 8;
pub const CAP_ADMIN: u32 = 1 << 9;
pub const CAP_RAW_IO: u32 = 1 << 10;
pub const CAP_MEMORY: u32 = 1 << 11;

pub const CAP_ALL: u32 = 0xFFFFFFFF;
pub const CAP_USER_DEFAULT: u32 = CAP_FS_READ | CAP_FS_WRITE | CAP_IPC | CAP_GRAPHICS;
pub const CAP_MINIMAL: u32 = CAP_FS_READ;
pub const CAP_NONE: u32 = 0;

// =============================================================================
// Violation Tracking
// =============================================================================

pub const MAX_VIOLATIONS: usize = 64;
pub const KILL_THRESHOLD: u16 = 3;

pub const Violation = struct {
    pid: u32 = 0,
    attempted_cap: u32 = 0,
    syscall_num: u64 = 0,
    timestamp: u64 = 0,
    valid: bool = false,
};

var violations: [MAX_VIOLATIONS]Violation = [_]Violation{.{}} ** MAX_VIOLATIONS;
var violation_head: usize = 0;
var violation_count: u64 = 0;

// Per-process violation counters (indexed by cap_table slot, NOT by PID)
var pid_violation_count: [MAX_CAP_ENTRIES]u16 = [_]u16{0} ** MAX_CAP_ENTRIES;

var initialized: bool = false;

// =============================================================================
// Process Capability Storage
// =============================================================================

pub const MAX_CAP_ENTRIES: usize = 64;

pub const CapEntry = struct {
    pid: u32 = 0,
    caps: u32 = CAP_NONE,
    active: bool = false,
};

var cap_table: [MAX_CAP_ENTRIES]CapEntry = [_]CapEntry{.{}} ** MAX_CAP_ENTRIES;

// =============================================================================
// Init
// =============================================================================

pub fn init() void {
    serial.writeString("[CAP] Initializing capability system...\n");

    var i: usize = 0;
    while (i < MAX_CAP_ENTRIES) : (i += 1) {
        cap_table[i] = .{};
        pid_violation_count[i] = 0;
    }

    i = 0;
    while (i < MAX_VIOLATIONS) : (i += 1) {
        violations[i] = .{};
    }

    violation_head = 0;
    violation_count = 0;

    // PID 0 (idle/kernel) = ALL capabilities at slot 0
    cap_table[0] = .{
        .pid = 0,
        .caps = CAP_ALL,
        .active = true,
    };

    initialized = true;
    serial.writeString("[CAP] Capability system ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Internal: Find slot by PID
// =============================================================================

fn findSlotByPid(pid: u32) ?usize {
    var i: usize = 0;
    while (i < MAX_CAP_ENTRIES) : (i += 1) {
        if (cap_table[i].active and cap_table[i].pid == pid) {
            return i;
        }
    }
    return null;
}

// =============================================================================
// Capability Management
// =============================================================================

pub fn registerProcess(pid: u32, caps: u32) bool {
    var i: usize = 0;
    while (i < MAX_CAP_ENTRIES) : (i += 1) {
        if (!cap_table[i].active) {
            cap_table[i] = .{
                .pid = pid,
                .caps = caps,
                .active = true,
            };
            pid_violation_count[i] = 0;
            return true;
        }
    }
    return false;
}

pub fn unregisterProcess(pid: u32) void {
    if (findSlotByPid(pid)) |slot| {
        pid_violation_count[slot] = 0;
        cap_table[slot] = .{};
    }
}

pub fn getCaps(pid: u32) u32 {
    if (pid == 0) return CAP_ALL;

    if (findSlotByPid(pid)) |slot| {
        return cap_table[slot].caps;
    }
    // Unregistered = kernel process = ALL (backward compat)
    return CAP_ALL;
}

pub fn grantCap(pid: u32, cap: u32) bool {
    if (findSlotByPid(pid)) |slot| {
        cap_table[slot].caps |= cap;
        return true;
    }
    return false;
}

pub fn revokeCap(pid: u32, cap: u32) bool {
    if (findSlotByPid(pid)) |slot| {
        cap_table[slot].caps &= ~cap;
        return true;
    }
    return false;
}

pub fn setCaps(pid: u32, caps: u32) bool {
    if (findSlotByPid(pid)) |slot| {
        cap_table[slot].caps = caps;
        return true;
    }
    return false;
}

// =============================================================================
// Capability Check (HOT PATH - must be fast!)
// =============================================================================

pub inline fn check(pid: u32, required: u32) bool {
    if (pid == 0) return true;
    const caps = getCaps(pid);
    return (caps & required) == required;
}

pub fn checkAndEnforce(pid: u32, required: u32, syscall_num: u64, timestamp: u64) bool {
    if (check(pid, required)) return true;
    recordViolation(pid, required, syscall_num, timestamp);
    return false;
}

pub fn getViolationCount(pid: u32) u16 {
    if (findSlotByPid(pid)) |slot| {
        return pid_violation_count[slot];
    }
    return 0;
}

pub fn shouldKill(pid: u32) bool {
    return getViolationCount(pid) >= KILL_THRESHOLD;
}

// =============================================================================
// Violation Recording — E3.6: Now reports to unified pipeline
// =============================================================================

fn recordViolation(pid: u32, attempted_cap: u32, syscall_num: u64, timestamp: u64) void {
    // Store in local circular buffer
    violations[violation_head] = .{
        .pid = pid,
        .attempted_cap = attempted_cap,
        .syscall_num = syscall_num,
        .timestamp = timestamp,
        .valid = true,
    };

    violation_head += 1;
    if (violation_head >= MAX_VIOLATIONS) violation_head = 0;
    violation_count += 1;

    // Increment per-process counter
    if (findSlotByPid(pid)) |slot| {
        if (pid_violation_count[slot] < 65535) {
            pid_violation_count[slot] += 1;
        }
    }

    // Log to serial
    serial.writeString("[CAP] VIOLATION: PID=");
    printDec32(pid);
    serial.writeString(" cap=0x");
    printHex32(attempted_cap);
    serial.writeString(" syscall=");
    printDec64(syscall_num);
    serial.writeString(" count=");
    printDec16(getViolationCount(pid));
    serial.writeString("\n");

    // === E3.6: Report to unified violation handler ===
    if (violation.isInitialized()) {
        var detail_buf: [48]u8 = [_]u8{0} ** 48;
        const detail_str = buildCapDetail(&detail_buf, attempted_cap, syscall_num);

        const vcount = getViolationCount(pid);
        const severity: violation.ViolationSeverity = if (vcount >= KILL_THRESHOLD)
            .high
        else if (vcount >= 2)
            .medium
        else
            .low;

        _ = violation.reportViolation(.{
            .violation_type = .capability_violation,
            .severity = severity,
            .pid = @intCast(pid & 0xFFFF),
            .source_ip = 0,
            .detail = detail_str,
        });
    }
}

fn buildCapDetail(buf: []u8, cap: u32, syscall_num: u64) []const u8 {
    var pos: usize = 0;
    const prefix = "cap=0x";
    for (prefix) |c| {
        if (pos >= buf.len) break;
        buf[pos] = c;
        pos += 1;
    }
    const hex = "0123456789ABCDEF";
    if (pos + 4 <= buf.len) {
        buf[pos] = hex[@intCast((cap >> 12) & 0xF)];
        buf[pos + 1] = hex[@intCast((cap >> 8) & 0xF)];
        buf[pos + 2] = hex[@intCast((cap >> 4) & 0xF)];
        buf[pos + 3] = hex[@intCast(cap & 0xF)];
        pos += 4;
    }
    const mid = " sys=";
    for (mid) |c| {
        if (pos >= buf.len) break;
        buf[pos] = c;
        pos += 1;
    }
    if (syscall_num == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            pos += 1;
        }
    } else {
        var tmp: [20]u8 = undefined;
        var tlen: usize = 0;
        var v = syscall_num;
        while (v > 0) : (tlen += 1) {
            tmp[tlen] = @intCast((v % 10) + '0');
            v /= 10;
        }
        while (tlen > 0) {
            tlen -= 1;
            if (pos >= buf.len) break;
            buf[pos] = tmp[tlen];
            pos += 1;
        }
    }
    return buf[0..pos];
}

/// Public wrapper for table.zig
pub fn recordViolationPublic(pid: u32, attempted_cap: u32, syscall_num: u64, timestamp: u64) void {
    recordViolation(pid, attempted_cap, syscall_num, timestamp);
}

// =============================================================================
// Query Functions
// =============================================================================

pub fn getTotalViolations() u64 {
    return violation_count;
}

pub fn getRecentViolations(out: []Violation) usize {
    var count: usize = 0;

    if (violation_count == 0) return 0;

    var idx: usize = if (violation_head == 0) MAX_VIOLATIONS - 1 else violation_head - 1;
    var checked: usize = 0;

    while (count < out.len and checked < MAX_VIOLATIONS) {
        if (violations[idx].valid) {
            out[count] = violations[idx];
            count += 1;
        }
        checked += 1;
        if (idx == 0) {
            idx = MAX_VIOLATIONS - 1;
        } else {
            idx -= 1;
        }
    }

    return count;
}

pub fn getCapEntryByIndex(index: usize) ?CapEntry {
    if (index >= MAX_CAP_ENTRIES) return null;
    if (!cap_table[index].active) return null;
    return cap_table[index];
}

pub fn capName(cap: u32) []const u8 {
    if (cap == CAP_NET) return "NET";
    if (cap == CAP_FS_READ) return "FS_READ";
    if (cap == CAP_FS_WRITE) return "FS_WRITE";
    if (cap == CAP_IPC) return "IPC";
    if (cap == CAP_EXEC) return "EXEC";
    if (cap == CAP_DEVICE) return "DEVICE";
    if (cap == CAP_GRAPHICS) return "GRAPHICS";
    if (cap == CAP_CRYPTO) return "CRYPTO";
    if (cap == CAP_CHAIN) return "CHAIN";
    if (cap == CAP_ADMIN) return "ADMIN";
    if (cap == CAP_RAW_IO) return "RAW_IO";
    if (cap == CAP_MEMORY) return "MEMORY";
    return "UNKNOWN";
}

pub fn formatCaps(caps: u32, buf: []u8) usize {
    var pos: usize = 0;
    const cap_bits = [_]struct { bit: u32, name: []const u8 }{
        .{ .bit = CAP_NET, .name = "NET" },
        .{ .bit = CAP_FS_READ, .name = "R" },
        .{ .bit = CAP_FS_WRITE, .name = "W" },
        .{ .bit = CAP_IPC, .name = "IPC" },
        .{ .bit = CAP_EXEC, .name = "EXE" },
        .{ .bit = CAP_DEVICE, .name = "DEV" },
        .{ .bit = CAP_GRAPHICS, .name = "GFX" },
        .{ .bit = CAP_CRYPTO, .name = "CRY" },
        .{ .bit = CAP_CHAIN, .name = "CHN" },
        .{ .bit = CAP_ADMIN, .name = "ADM" },
        .{ .bit = CAP_RAW_IO, .name = "IO" },
        .{ .bit = CAP_MEMORY, .name = "MEM" },
    };

    if (caps == CAP_ALL) {
        const all_str = "ALL";
        for (all_str) |c| {
            if (pos >= buf.len) break;
            buf[pos] = c;
            pos += 1;
        }
        return pos;
    }

    var first = true;
    for (cap_bits) |cb| {
        if ((caps & cb.bit) != 0) {
            if (!first and pos < buf.len) {
                buf[pos] = '|';
                pos += 1;
            }
            for (cb.name) |c| {
                if (pos >= buf.len) break;
                buf[pos] = c;
                pos += 1;
            }
            first = false;
        }
    }

    if (pos == 0 and buf.len > 0) {
        const none_str = "NONE";
        for (none_str) |c| {
            if (pos >= buf.len) break;
            buf[pos] = c;
            pos += 1;
        }
    }

    return pos;
}

// =============================================================================
// Syscall-to-Capability Mapping — SC1: Updated to match numbers.zig
// =============================================================================

pub fn syscallRequiredCap(syscall_num: u64) u32 {
    return switch (syscall_num) {
        // --- Core FS read ---
        numbers.SYS_READ => CAP_FS_READ,
        numbers.SYS_OPEN => CAP_FS_READ, // open itself needs read; write checked separately
        numbers.SYS_STAT => CAP_FS_READ,
        numbers.SYS_FSTAT => CAP_FS_READ,
        numbers.SYS_LSEEK => CAP_FS_READ,
        numbers.SYS_GETCWD => CAP_FS_READ,

        // --- Core FS write ---
        numbers.SYS_WRITE => CAP_FS_WRITE, // special-cased in table.zig for stdout/stderr
        numbers.SYS_MKDIR => CAP_FS_WRITE,
        numbers.SYS_RMDIR => CAP_FS_WRITE,
        numbers.SYS_UNLINK => CAP_FS_WRITE,

        // --- FS Extended ---
        numbers.SYS_FSTAT_PATH => CAP_FS_READ,
        numbers.SYS_READDIR => CAP_FS_READ,
        numbers.SYS_RENAME => CAP_FS_WRITE,
        numbers.SYS_TRUNCATE => CAP_FS_WRITE,
        numbers.SYS_SEEK => CAP_FS_READ,

        // --- Process exec ---
        numbers.SYS_FORK => CAP_EXEC,
        numbers.SYS_EXEC => CAP_EXEC,
        numbers.SYS_SPAWN => CAP_EXEC,
        numbers.SYS_EXEC_ELF => CAP_EXEC,
        numbers.SYS_EXEC_ZAM => CAP_EXEC,

        // --- Network ---
        numbers.SYS_SOCKET => CAP_NET,
        numbers.SYS_BIND => CAP_NET,
        numbers.SYS_LISTEN => CAP_NET,
        numbers.SYS_ACCEPT => CAP_NET,
        numbers.SYS_CONNECT => CAP_NET,
        numbers.SYS_SENDTO => CAP_NET,
        numbers.SYS_RECVFROM => CAP_NET,

        // --- Graphics ---
        numbers.SYS_FB_GET_INFO => CAP_GRAPHICS,
        numbers.SYS_FB_MAP => CAP_GRAPHICS,
        numbers.SYS_FB_UNMAP => CAP_GRAPHICS,
        numbers.SYS_FB_FLUSH => CAP_GRAPHICS,
        numbers.SYS_CURSOR_SET_POS => CAP_GRAPHICS,
        numbers.SYS_CURSOR_SET_VISIBLE => CAP_GRAPHICS,
        numbers.SYS_CURSOR_SET_TYPE => CAP_GRAPHICS,
        numbers.SYS_SCREEN_GET_ORIENTATION => CAP_GRAPHICS,

        // --- Crypto ---
        numbers.SYS_CRYPTO_HASH => CAP_CRYPTO,
        numbers.SYS_CRYPTO_HMAC => CAP_CRYPTO,
        numbers.SYS_CRYPTO_RANDOM => CAP_CRYPTO,
        numbers.SYS_CRYPTO_SIGN => CAP_CRYPTO,
        numbers.SYS_CRYPTO_VERIFY => CAP_CRYPTO,
        numbers.SYS_CRYPTO_DERIVE_KEY => CAP_CRYPTO,

        // --- Chain ---
        numbers.SYS_CHAIN_STATUS => CAP_CHAIN,
        numbers.SYS_CHAIN_GET_HEIGHT => CAP_CHAIN,
        numbers.SYS_CHAIN_GET_BLOCK => CAP_CHAIN,
        numbers.SYS_CHAIN_SUBMIT_ENTRY => CAP_CHAIN,
        numbers.SYS_CHAIN_VERIFY_ENTRY => CAP_CHAIN,

        // --- IPC ---
        numbers.SYS_MSG_SEND => CAP_IPC,
        numbers.SYS_MSG_RECV => CAP_IPC,
        numbers.SYS_PIPE_CREATE => CAP_IPC,
        numbers.SYS_PIPE_WRITE => CAP_IPC,
        numbers.SYS_PIPE_READ => CAP_IPC,
        numbers.SYS_SIG_SEND => CAP_IPC,
        numbers.SYS_SIG_MASK => CAP_IPC,

        // --- Shared Memory ---
        numbers.SYS_SHM_CREATE => CAP_MEMORY,
        numbers.SYS_SHM_ATTACH => CAP_MEMORY,
        numbers.SYS_SHM_DETACH => CAP_MEMORY,
        numbers.SYS_SHM_DESTROY => CAP_MEMORY,
        numbers.SYS_SHM_WRITE => CAP_MEMORY,
        numbers.SYS_SHM_READ => CAP_MEMORY,

        // --- Encrypted FS ---
        numbers.SYS_ENC_WRITE => CAP_FS_WRITE | CAP_CRYPTO,
        numbers.SYS_ENC_READ => CAP_FS_READ | CAP_CRYPTO,
        numbers.SYS_ENC_SETKEY => CAP_CRYPTO | CAP_ADMIN,
        numbers.SYS_ENC_STATUS => CAP_CRYPTO,

        // --- User/Auth ---
        numbers.SYS_SETUID => CAP_ADMIN,
        numbers.SYS_SETGID => CAP_ADMIN,
        numbers.SYS_LOGIN => CAP_ADMIN,
        numbers.SYS_LOGOUT => CAP_ADMIN,

        // --- Capability management ---
        numbers.SYS_CAP_GET => CAP_NONE, // reading own caps is always allowed
        numbers.SYS_CAP_CHECK => CAP_NONE,
        numbers.SYS_CAP_DROP => CAP_NONE, // dropping own caps is always allowed

        // --- Boot (admin only) ---
        numbers.SYS_BOOT_SET_POLICY => CAP_ADMIN,

        // --- Raw IO ---
        numbers.SYS_MMAP => CAP_MEMORY,
        numbers.SYS_MUNMAP => CAP_MEMORY,
        numbers.SYS_IOCTL => CAP_RAW_IO,

        // --- Always allowed: EXIT, GETPID, GETPPID, GETUID, GETGID,
        //     GETEUID, GETEGID, SCHED_YIELD, NANOSLEEP, CLOSE,
        //     CHDIR, INPUT_*, DEBUG_*, GET_TICKS, GET_UPTIME,
        //     BOOT_STATUS, BOOT_VERIFY, BOOT_GET_HASH, BOOT_GET_POLICY,
        //     IDENTITY_*, INTEGRITY_*, QUARANTINE_*, MONITOR_*,
        //     GET_USERNAME, AUTHORITY_* ---
        else => CAP_NONE,
    };
}

pub fn checkWrite(pid: u32, fd: u64) bool {
    if (fd == 1 or fd == 2) return true;
    return check(pid, CAP_FS_WRITE);
}

// =============================================================================
// Print helpers
// =============================================================================

fn printDec16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v: u16 = val;
    var started = false;
    const divs = [_]u16{ 10000, 1000, 100, 10, 1 };
    for (divs) |d| {
        var digit: u8 = 0;
        while (v >= d) : (digit += 1) v -= d;
        if (digit > 0 or started) {
            serial.writeChar('0' + digit);
            started = true;
        }
    }
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

fn printDec64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v: u64 = val;
    var started = false;
    const divs = [_]u64{
        10000000000000000000, 1000000000000000000, 100000000000000000,
        10000000000000000,    1000000000000000,    100000000000000,
        10000000000000,       1000000000000,       100000000000,
        10000000000,          1000000000,          100000000,
        10000000,             1000000,             100000,
        10000,                1000,                100,
        10,                   1,
    };
    for (divs) |d| {
        var digit: u8 = 0;
        while (v >= d) : (digit += 1) v -= d;
        if (digit > 0 or started) {
            serial.writeChar('0' + digit);
            started = true;
        }
    }
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[@intCast((val >> 28) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 24) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 20) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 16) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 12) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 8) & 0xF)]);
    serial.writeChar(hex[@intCast((val >> 4) & 0xF)]);
    serial.writeChar(hex[@intCast(val & 0xF)]);
}
