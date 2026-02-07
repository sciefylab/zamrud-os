//! Zamrud OS - DNS Client
//! Domain Name System resolver (RFC 1035)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const udp = @import("udp.zig");

// =============================================================================
// Constants
// =============================================================================

pub const DNS_PORT: u16 = 53;
pub const MAX_DNS_SERVERS: usize = 4;
pub const MAX_NAME_LENGTH: usize = 255;
pub const MAX_CACHE_ENTRIES: usize = 32;

// DNS record types
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_NS: u16 = 2;
pub const TYPE_PTR: u16 = 12;

// DNS classes
pub const CLASS_IN: u16 = 1;

// DNS response codes
pub const RCODE_OK: u4 = 0;
pub const RCODE_FORMAT_ERROR: u4 = 1;
pub const RCODE_SERVER_FAILURE: u4 = 2;
pub const RCODE_NAME_ERROR: u4 = 3;
pub const RCODE_NOT_IMPLEMENTED: u4 = 4;
pub const RCODE_REFUSED: u4 = 5;

// =============================================================================
// Types
// =============================================================================

pub const CacheEntry = struct {
    name: [MAX_NAME_LENGTH]u8,
    name_len: usize,
    ip_addr: u32,
    ttl: u32,
    valid: bool,
    timestamp: u64,
};

// =============================================================================
// State
// =============================================================================

var dns_servers: [MAX_DNS_SERVERS]u32 = [_]u32{0} ** MAX_DNS_SERVERS;
var server_count: usize = 0;
var cache: [MAX_CACHE_ENTRIES]CacheEntry = undefined;
var initialized: bool = false;
var query_id: u16 = 1;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&cache) |*entry| {
        entry.* = .{
            .name = [_]u8{0} ** MAX_NAME_LENGTH,
            .name_len = 0,
            .ip_addr = 0,
            .ttl = 0,
            .valid = false,
            .timestamp = 0,
        };
    }

    // Set default DNS servers (Google DNS)
    _ = addServer(network.ipToU32(8, 8, 8, 8));
    _ = addServer(network.ipToU32(8, 8, 4, 4));

    initialized = true;
    serial.writeString("[DNS] DNS resolver initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Server Management
// =============================================================================

pub fn addServer(ip: u32) bool {
    if (server_count >= MAX_DNS_SERVERS) return false;

    for (dns_servers[0..server_count]) |server| {
        if (server == ip) return true;
    }

    dns_servers[server_count] = ip;
    server_count += 1;
    return true;
}

pub fn removeServer(ip: u32) bool {
    var i: usize = 0;
    while (i < server_count) {
        if (dns_servers[i] == ip) {
            var j = i;
            while (j + 1 < server_count) : (j += 1) {
                dns_servers[j] = dns_servers[j + 1];
            }
            server_count -= 1;
            return true;
        }
        i += 1;
    }
    return false;
}

pub fn clearServers() void {
    server_count = 0;
    for (&dns_servers) |*server| {
        server.* = 0;
    }
}

pub fn getServers() []const u32 {
    return dns_servers[0..server_count];
}

pub fn getServerCount() usize {
    return server_count;
}

// =============================================================================
// Resolution
// =============================================================================

pub fn resolve(name: []const u8) ?u32 {
    if (lookupCache(name)) |ip| {
        return ip;
    }
    return null;
}

pub fn resolveAsync(name: []const u8, callback: *const fn (?u32) void) void {
    const result = resolve(name);
    callback(result);
}

// =============================================================================
// Cache Management
// =============================================================================

fn lookupCache(name: []const u8) ?u32 {
    for (&cache) |*entry| {
        if (!entry.valid) continue;
        if (entry.name_len != name.len) continue;

        var match = true;
        for (name, 0..) |c, i| {
            if (entry.name[i] != c) {
                match = false;
                break;
            }
        }

        if (match) {
            return entry.ip_addr;
        }
    }
    return null;
}

pub fn addCacheEntry(name: []const u8, ip: u32, ttl: u32) void {
    var slot: ?*CacheEntry = null;
    var oldest_time: u64 = 0xFFFFFFFFFFFFFFFF;

    for (&cache) |*entry| {
        if (!entry.valid) {
            slot = entry;
            break;
        }
        if (entry.timestamp < oldest_time) {
            oldest_time = entry.timestamp;
            slot = entry;
        }
    }

    if (slot) |entry| {
        entry.valid = true;
        entry.ip_addr = ip;
        entry.ttl = ttl;
        entry.name_len = @min(name.len, MAX_NAME_LENGTH);
        for (name[0..entry.name_len], 0..) |c, i| {
            entry.name[i] = c;
        }
        entry.timestamp = 0;
    }
}

pub fn clearCache() void {
    for (&cache) |*entry| {
        entry.valid = false;
    }
}

pub fn getCacheEntries() []const CacheEntry {
    return &cache;
}

// =============================================================================
// Helpers
// =============================================================================

fn writeU16BE(data: []u8, val: u16) void {
    data[0] = @intCast((val >> 8) & 0xFF);
    data[1] = @intCast(val & 0xFF);
}

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}
