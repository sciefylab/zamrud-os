//! Zamrud OS - Network Checksum Utilities
//! Internet checksum (RFC 1071)

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    initialized = true;
    // Silent init - no log needed for utility module
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Checksum Calculation
// =============================================================================

/// Calculate Internet checksum (RFC 1071)
pub fn calculate(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum 16-bit words (big-endian)
    while (i + 1 < data.len) : (i += 2) {
        const word = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
        sum += word;
    }

    // Handle odd byte
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @intCast(~sum & 0xFFFF);
}

/// Verify checksum (result should be 0xFFFF for valid data with checksum)
pub fn verify(data: []const u8) bool {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < data.len) : (i += 2) {
        const word = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
        sum += word;
    }

    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (sum & 0xFFFF) == 0xFFFF;
}

/// Calculate pseudo-header sum for TCP/UDP checksum
pub fn pseudoHeader(src_ip: u32, dst_ip: u32, protocol: u8, length: u16) u32 {
    var sum: u32 = 0;

    // Source IP (split into two 16-bit words)
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;

    // Destination IP
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;

    // Protocol (zero-padded to 16 bits)
    sum += @as(u32, protocol);

    // Length
    sum += @as(u32, length);

    return sum;
}

/// Calculate checksum with pseudo-header (for TCP/UDP)
pub fn calculateWithPseudo(src_ip: u32, dst_ip: u32, protocol: u8, data: []const u8) u16 {
    var sum = pseudoHeader(src_ip, dst_ip, protocol, @intCast(data.len));

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        const word = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
        sum += word;
    }

    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @intCast(~sum & 0xFFFF);
}

/// Incremental checksum update (RFC 1624)
/// Used when modifying a single field in a packet
pub fn updateChecksum(old_checksum: u16, old_value: u16, new_value: u16) u16 {
    var sum: u32 = @as(u32, ~old_checksum & 0xFFFF);
    sum += @as(u32, ~old_value & 0xFFFF);
    sum += @as(u32, new_value);

    // Fold
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @intCast(sum & 0xFFFF));
}

/// Calculate checksum for IP header only
pub fn calculateIpHeader(header: []const u8) u16 {
    return calculate(header);
}

/// Verify IP header checksum
pub fn verifyIpHeader(header: []const u8) bool {
    return verify(header);
}
