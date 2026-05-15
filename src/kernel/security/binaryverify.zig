//! Zamrud OS - Binary Verification System (E3.3)
//! Hash-based binary whitelist enforcement via Registry
//! E3.6: Wired to violation.zig unified pipeline

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const violation = @import("violation.zig");
const registry = @import("../integrity/registry.zig"); // 🆕 Integrasi Registry Ledger

// =============================================================================
// Constants
// =============================================================================

pub const MAX_TRUSTED: usize = 64;
pub const HASH_SIZE: usize = 32;
pub const MAX_NAME: usize = 32;

// =============================================================================
// Trust Entry (Local Cache)
// =============================================================================

pub const TrustEntry = struct {
    hash_buf: [HASH_SIZE]u8 = [_]u8{0} ** HASH_SIZE,
    name_buf: [MAX_NAME]u8 = [_]u8{0} ** MAX_NAME,
    name_len: u8 = 0,
    trusted_by_pid: u32 = 0,
    timestamp: u64 = 0,
    active: bool = false,

    pub fn getName(self: *const TrustEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn setName(self: *TrustEntry, name: []const u8) void {
        const len = @min(name.len, MAX_NAME);
        var i: usize = 0;
        while (i < len) : (i += 1) {
            self.name_buf[i] = name[i];
        }
        self.name_len = @intCast(len);
    }

    pub fn getHash(self: *const TrustEntry) *const [HASH_SIZE]u8 {
        return &self.hash_buf;
    }
};

// =============================================================================
// Verification Result
// =============================================================================

pub const VerifyResult = enum(u8) {
    Trusted = 0,
    Untrusted = 1,
    NotFound = 2,
    Error = 3,
};

// =============================================================================
// Global State
// =============================================================================

var trust_table: [MAX_TRUSTED]TrustEntry = [_]TrustEntry{.{}} ** MAX_TRUSTED;
var trust_count: usize = 0;
var verify_count: u64 = 0;
var block_count: u64 = 0;
var allow_count: u64 = 0;
var enforce_mode: bool = false;
var initialized: bool = false;

// =============================================================================
// Init
// =============================================================================

pub fn init() void {
    serial.writeString("[BINVERIFY] Initializing binary verification...\n");

    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        trust_table[i] = .{};
    }

    trust_count = 0;
    verify_count = 0;
    block_count = 0;
    allow_count = 0;
    enforce_mode = false;
    initialized = true;

    serial.writeString("[BINVERIFY] Binary verification ready (warn mode)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

/// Set enforcement mode
pub fn setEnforce(enforce: bool) void {
    enforce_mode = enforce;
    if (enforce) {
        serial.writeString("[BINVERIFY] Mode: ENFORCING (unsigned/unregistered = blocked)\n");
    } else {
        serial.writeString("[BINVERIFY] Mode: WARN (unsigned/unregistered = allowed with warning)\n");
    }
}

pub fn isEnforcing() bool {
    return enforce_mode;
}

// =============================================================================
// Trust Management
// =============================================================================

/// Add a binary hash to the trust whitelist
pub fn trustHash(bin_hash: *const [HASH_SIZE]u8, name: []const u8, pid: u32, timestamp: u64) bool {
    if (!initialized) return false;

    // Check if already trusted
    if (findByHash(bin_hash) != null) return true;

    // Find free slot
    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        if (!trust_table[i].active) {
            var j: usize = 0;
            while (j < HASH_SIZE) : (j += 1) {
                trust_table[i].hash_buf[j] = bin_hash[j];
            }
            trust_table[i].setName(name);
            trust_table[i].trusted_by_pid = pid;
            trust_table[i].timestamp = timestamp;
            trust_table[i].active = true;
            trust_count += 1;

            serial.writeString("[BINVERIFY] Cached locally: ");
            serialPrintStr(name);
            serial.writeString(" hash=");
            printHashShort(bin_hash);
            serial.writeString("\n");

            return true;
        }
    }

    return false;
}

/// Trust a binary by computing its hash from data
pub fn trustBinary(data: []const u8, name: []const u8, pid: u32, timestamp: u64) bool {
    var bin_hash: [HASH_SIZE]u8 = undefined;
    hash.sha256Into(data, &bin_hash);
    return trustHash(&bin_hash, name, pid, timestamp);
}

/// Remove a hash from the trust whitelist
pub fn untrustHash(bin_hash: *const [HASH_SIZE]u8) bool {
    if (!initialized) return false;

    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        if (trust_table[i].active) {
            if (hash.hashEqual(&trust_table[i].hash_buf, bin_hash)) {
                serial.writeString("[BINVERIFY] Untrusted from cache: ");
                serialPrintStr(trust_table[i].getName());
                serial.writeString("\n");

                trust_table[i] = .{};
                if (trust_count > 0) trust_count -= 1;
                return true;
            }
        }
    }
    return false;
}

/// Remove by name
pub fn untrustByName(name: []const u8) bool {
    if (!initialized) return false;

    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        if (trust_table[i].active) {
            if (strEqual(trust_table[i].getName(), name)) {
                trust_table[i] = .{};
                if (trust_count > 0) trust_count -= 1;
                return true;
            }
        }
    }
    return false;
}

/// Remove by index
pub fn untrustByIndex(index: usize) bool {
    if (index >= MAX_TRUSTED) return false;
    if (!trust_table[index].active) return false;

    trust_table[index] = .{};
    if (trust_count > 0) trust_count -= 1;
    return true;
}

// =============================================================================
// Verification — E3.3 Check and E3.6 Reporting
// =============================================================================

/// Verify binary data against trust whitelist and Ledger
pub fn verifyBinary(data: []const u8) VerifyResult {
    if (!initialized) return .Error;

    verify_count += 1;

    var bin_hash: [HASH_SIZE]u8 = undefined;
    hash.sha256Into(data, &bin_hash);

    return verifyHash(&bin_hash);
}

/// Verify a pre-computed hash against Local Cache & Blockchain Registry
pub fn verifyHash(bin_hash: *const [HASH_SIZE]u8) VerifyResult {
    if (!initialized) return .Error;

    // 1. CEK CACHE LOKAL (Jalur Cepat - Fast Path)
    if (findByHash(bin_hash) != null) {
        allow_count += 1;
        return .Trusted;
    }

    // 2. CEK BLOCKCHAIN REGISTRY (Jalur Otoritas - Slow Path)
    serial.writeString("[BINVERIFY] Cache miss. Querying Blockchain Registry...\n");
    if (registry.isInitialized() and registry.isRegistered(bin_hash)) {
        // Jika sah di Blockchain, masukkan ke cache lokal agar eksekusi berikutnya instan
        _ = trustHash(bin_hash, "chain-approved", 0, 0);

        allow_count += 1;
        serial.writeString("[BINVERIFY] ALLOWED: Validated by Blockchain Ledger.\n");
        return .Trusted;
    }

    // 3. JIKA DITOLAK (Violation Gate)
    if (enforce_mode) {
        block_count += 1;
        serial.writeString("[BINVERIFY] BLOCKED: Unregistered binary hash=");
        printHashShort(bin_hash);
        serial.writeString("\n");
        reportBinaryViolation(bin_hash, true); // E3.6 Violation handler
    } else {
        serial.writeString("[BINVERIFY] WARN: Unregistered binary hash=");
        printHashShort(bin_hash);
        serial.writeString("\n");
        reportBinaryViolation(bin_hash, false);
    }

    return .Untrusted;
}

/// E3.6: Report untrusted binary to unified violation handler
fn reportBinaryViolation(bin_hash: *const [HASH_SIZE]u8, blocked: bool) void {
    if (!violation.isInitialized()) return;

    // Build detail: "hash=XXXXXXXX... blocked/warned"
    var detail_buf: [48]u8 = [_]u8{0} ** 48;
    const prefix = "hash=";
    var pos: usize = 0;
    for (prefix) |c| {
        if (pos >= 48) break;
        detail_buf[pos] = c;
        pos += 1;
    }

    // Copy first 8 bytes of hash as hex (16 chars)
    const hex = "0123456789abcdef";
    var hi: usize = 0;
    while (hi < 8 and pos + 1 < 48) : (hi += 1) {
        detail_buf[pos] = hex[bin_hash[hi] >> 4];
        detail_buf[pos + 1] = hex[bin_hash[hi] & 0xF];
        pos += 2;
    }

    const suffix = if (blocked) " BLOCKED" else " warned";
    for (suffix) |c| {
        if (pos >= 48) break;
        detail_buf[pos] = c;
        pos += 1;
    }

    const severity: violation.ViolationSeverity = if (blocked) .high else .medium;

    _ = violation.reportViolation(.{
        .violation_type = .binary_untrusted,
        .severity = severity,
        .pid = 0, // Binary verification is system-level
        .source_ip = 0,
        .detail = detail_buf[0..pos],
    });
}

/// Check and enforce - returns true if execution should be allowed
pub fn checkExec(data: []const u8) bool {
    const result = verifyBinary(data);

    return switch (result) {
        .Trusted => true,
        .Untrusted => !enforce_mode,
        .NotFound => !enforce_mode,
        .Error => false,
    };
}

/// Check pre-computed hash
pub fn checkExecHash(bin_hash: *const [HASH_SIZE]u8) bool {
    const result = verifyHash(bin_hash);

    return switch (result) {
        .Trusted => true,
        .Untrusted => !enforce_mode,
        .NotFound => !enforce_mode,
        .Error => false,
    };
}

// =============================================================================
// Lookup Helpers
// =============================================================================

fn findByHash(bin_hash: *const [HASH_SIZE]u8) ?*TrustEntry {
    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        if (trust_table[i].active) {
            if (hash.hashEqual(&trust_table[i].hash_buf, bin_hash)) {
                return &trust_table[i];
            }
        }
    }
    return null;
}

fn findByName(name: []const u8) ?*TrustEntry {
    _ = name;
    // Not used directly but kept for API completeness
    return null;
}

// =============================================================================
// Query Functions (for shell)
// =============================================================================

pub fn getTrustCount() usize {
    return trust_count;
}

pub fn getVerifyCount() u64 {
    return verify_count;
}

pub fn getBlockCount() u64 {
    return block_count;
}

pub fn getAllowCount() u64 {
    return allow_count;
}

pub fn getEntry(index: usize) ?struct {
    name: []const u8,
    hash_ptr: *const [HASH_SIZE]u8,
    trusted_by: u32,
    timestamp: u64,
} {
    var count: usize = 0;
    var i: usize = 0;
    while (i < MAX_TRUSTED) : (i += 1) {
        if (trust_table[i].active) {
            if (count == index) {
                return .{
                    .name = trust_table[i].getName(),
                    .hash_ptr = &trust_table[i].hash_buf,
                    .trusted_by = trust_table[i].trusted_by_pid,
                    .timestamp = trust_table[i].timestamp,
                };
            }
            count += 1;
        }
    }
    return null;
}

/// Compute hash of data and return it
pub fn computeHash(data: []const u8) [HASH_SIZE]u8 {
    return hash.sha256(data);
}

/// Format hash as hex string
pub fn formatHash(h: *const [HASH_SIZE]u8, buf: []u8) usize {
    const hex_c = "0123456789abcdef";
    const max_bytes = @min(HASH_SIZE, buf.len / 2);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < max_bytes) : (i += 1) {
        if (pos + 1 >= buf.len) break;
        buf[pos] = hex_c[h[i] >> 4];
        buf[pos + 1] = hex_c[h[i] & 0xF];
        pos += 2;
    }
    return pos;
}

/// Parse hex string to hash
pub fn parseHexHash(hex_str: []const u8, out: *[HASH_SIZE]u8) bool {
    if (hex_str.len != 64) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const hi = hexCharToNibble(hex_str[i * 2]) orelse return false;
        const lo = hexCharToNibble(hex_str[i * 2 + 1]) orelse return false;
        out[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return true;
}

fn hexCharToNibble(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    return null;
}

// =============================================================================
// Helpers
// =============================================================================

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn serialPrintStr(s: []const u8) void {
    for (s) |c| {
        serial.writeChar(c);
    }
}

fn printHashShort(h: *const [HASH_SIZE]u8) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        serial.writeChar(hex[h[i] >> 4]);
        serial.writeChar(hex[h[i] & 0xF]);
    }
    serial.writeString("...");
}
