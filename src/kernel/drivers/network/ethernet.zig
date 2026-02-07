//! Zamrud OS - Ethernet Frame Handler
//! IEEE 802.3 Ethernet frame parsing and creation

const network = @import("network.zig");

// =============================================================================
// Constants
// =============================================================================

pub const HEADER_SIZE: usize = 14;
pub const MIN_FRAME_SIZE: usize = 60;
pub const MAX_FRAME_SIZE: usize = 1514;
pub const CRC_SIZE: usize = 4;

// EtherTypes
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

// =============================================================================
// Types
// =============================================================================

pub const EthernetHeader = struct {
    dest_mac: network.MacAddress,
    src_mac: network.MacAddress,
    ethertype: u16,
};

pub const EthernetFrame = struct {
    header: EthernetHeader,
    payload: []const u8,

    pub fn getEtherType(self: *const EthernetFrame) u16 {
        return self.header.ethertype;
    }

    pub fn isIPv4(self: *const EthernetFrame) bool {
        return self.header.ethertype == ETHERTYPE_IPV4;
    }

    pub fn isARP(self: *const EthernetFrame) bool {
        return self.header.ethertype == ETHERTYPE_ARP;
    }
};

// =============================================================================
// Broadcast
// =============================================================================

pub const BROADCAST_MAC: network.MacAddress = [_]u8{0xFF} ** 6;

pub fn isBroadcast(mac: network.MacAddress) bool {
    for (mac) |b| {
        if (b != 0xFF) return false;
    }
    return true;
}

pub fn isMulticast(mac: network.MacAddress) bool {
    return (mac[0] & 0x01) != 0;
}

// =============================================================================
// Parsing
// =============================================================================

pub fn parse(data: []const u8) ?EthernetFrame {
    if (data.len < HEADER_SIZE) return null;

    var header: EthernetHeader = undefined;

    // Destination MAC
    for (data[0..6], 0..) |b, i| {
        header.dest_mac[i] = b;
    }

    // Source MAC
    for (data[6..12], 0..) |b, i| {
        header.src_mac[i] = b;
    }

    // EtherType (big endian)
    header.ethertype = (@as(u16, data[12]) << 8) | @as(u16, data[13]);

    return .{
        .header = header,
        .payload = data[HEADER_SIZE..],
    };
}

// =============================================================================
// Building
// =============================================================================

pub fn build(
    buffer: []u8,
    dest_mac: network.MacAddress,
    src_mac: network.MacAddress,
    ethertype: u16,
    payload: []const u8,
) ?usize {
    const total_len = HEADER_SIZE + payload.len;
    if (total_len > buffer.len) return null;
    if (total_len > MAX_FRAME_SIZE) return null;

    // Destination MAC
    for (dest_mac, 0..) |b, i| {
        buffer[i] = b;
    }

    // Source MAC
    for (src_mac, 0..) |b, i| {
        buffer[6 + i] = b;
    }

    // EtherType (big endian)
    buffer[12] = @intCast((ethertype >> 8) & 0xFF);
    buffer[13] = @intCast(ethertype & 0xFF);

    // Payload
    for (payload, 0..) |b, i| {
        buffer[HEADER_SIZE + i] = b;
    }

    // Pad if necessary
    var final_len = total_len;
    if (final_len < MIN_FRAME_SIZE) {
        while (final_len < MIN_FRAME_SIZE) : (final_len += 1) {
            buffer[final_len] = 0;
        }
    }

    return final_len;
}

// =============================================================================
// Initialization
// =============================================================================

var initialized: bool = true;

pub fn init() void {
    initialized = true;
}

pub fn isInitialized() bool {
    return initialized;
}
