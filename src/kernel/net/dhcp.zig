//! Zamrud OS - DHCP Client
//! Dynamic Host Configuration Protocol (RFC 2131)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const udp = @import("udp.zig");

// =============================================================================
// Constants
// =============================================================================

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

// DHCP message types
pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPDECLINE: u8 = 4;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;
pub const DHCPINFORM: u8 = 8;

// DHCP options
pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_DOMAIN: u8 = 15;
pub const OPT_BROADCAST: u8 = 28;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST: u8 = 55;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_END: u8 = 255;

// =============================================================================
// Types
// =============================================================================

pub const DhcpState = enum {
    init,
    selecting,
    requesting,
    bound,
    renewing,
    rebinding,
    released,
};

pub const DhcpLease = struct {
    ip_addr: u32,
    subnet_mask: u32,
    gateway: u32,
    dns_server: u32,
    server_id: u32,
    lease_time: u32,
    renewal_time: u32,
    rebinding_time: u32,
    obtained_at: u64,
    valid: bool,
};

// =============================================================================
// State
// =============================================================================

var state: DhcpState = .init;
var current_lease: DhcpLease = undefined;
var transaction_id: u32 = 0;
var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    state = .init;
    current_lease = .{
        .ip_addr = 0,
        .subnet_mask = 0,
        .gateway = 0,
        .dns_server = 0,
        .server_id = 0,
        .lease_time = 0,
        .renewal_time = 0,
        .rebinding_time = 0,
        .obtained_at = 0,
        .valid = false,
    };
    transaction_id = generateXid();
    initialized = true;
    serial.writeString("[DHCP] DHCP client initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// DHCP Operations
// =============================================================================

pub fn discover(iface: *network.NetworkInterface) bool {
    if (state != .init and state != .released) {
        return false;
    }

    var buffer: [576]u8 = [_]u8{0} ** 576;
    const len = buildDiscover(&buffer, iface) orelse return false;

    if (udp.send(iface, 0xFFFFFFFF, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, buffer[0..len])) {
        state = .selecting;
        return true;
    }
    return false;
}

pub fn request(iface: *network.NetworkInterface, offered_ip: u32, server_ip: u32) bool {
    if (state != .selecting) {
        return false;
    }

    var buffer: [576]u8 = [_]u8{0} ** 576;
    const len = buildRequest(&buffer, iface, offered_ip, server_ip) orelse return false;

    if (udp.send(iface, 0xFFFFFFFF, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, buffer[0..len])) {
        state = .requesting;
        return true;
    }
    return false;
}

pub fn release(iface: *network.NetworkInterface) bool {
    if (state != .bound) {
        return false;
    }

    var buffer: [576]u8 = [_]u8{0} ** 576;
    const len = buildRelease(&buffer, iface) orelse return false;

    if (udp.send(iface, current_lease.server_id, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, buffer[0..len])) {
        state = .released;
        current_lease.valid = false;
        return true;
    }
    return false;
}

pub fn renew(iface: *network.NetworkInterface) bool {
    if (state != .bound) {
        return false;
    }

    state = .renewing;
    return request(iface, current_lease.ip_addr, current_lease.server_id);
}

// =============================================================================
// State Query
// =============================================================================

pub fn getState() DhcpState {
    return state;
}

pub fn getLease() ?*const DhcpLease {
    if (current_lease.valid) {
        return &current_lease;
    }
    return null;
}

pub fn isBound() bool {
    return state == .bound and current_lease.valid;
}

// =============================================================================
// Message Building
// =============================================================================

fn buildDiscover(buffer: []u8, iface: *network.NetworkInterface) ?usize {
    return buildMessage(buffer, iface, DHCPDISCOVER, 0, 0);
}

fn buildRequest(buffer: []u8, iface: *network.NetworkInterface, requested_ip: u32, server_ip: u32) ?usize {
    return buildMessage(buffer, iface, DHCPREQUEST, requested_ip, server_ip);
}

fn buildRelease(buffer: []u8, iface: *network.NetworkInterface) ?usize {
    return buildMessage(buffer, iface, DHCPRELEASE, current_lease.ip_addr, current_lease.server_id);
}

fn buildMessage(buffer: []u8, iface: *network.NetworkInterface, msg_type: u8, requested_ip: u32, server_ip: u32) ?usize {
    if (buffer.len < 300) return null;

    for (buffer) |*b| b.* = 0;

    // BOOTP header
    buffer[0] = 1; // BOOTREQUEST
    buffer[1] = 1; // Ethernet
    buffer[2] = 6; // MAC length
    buffer[3] = 0; // Hops

    writeU32BE(buffer[4..8], transaction_id);
    buffer[10] = 0x80; // Broadcast flag

    for (0..6) |i| {
        buffer[28 + i] = iface.mac[i];
    }

    // Magic cookie
    var pos: usize = 236;
    writeU32BE(buffer[pos..][0..4], DHCP_MAGIC_COOKIE);
    pos += 4;

    // Message type option
    buffer[pos] = OPT_MESSAGE_TYPE;
    buffer[pos + 1] = 1;
    buffer[pos + 2] = msg_type;
    pos += 3;

    // Requested IP (for REQUEST)
    if (requested_ip != 0) {
        buffer[pos] = OPT_REQUESTED_IP;
        buffer[pos + 1] = 4;
        writeU32BE(buffer[pos + 2 ..][0..4], requested_ip);
        pos += 6;
    }

    // Server ID (for REQUEST/RELEASE)
    if (server_ip != 0) {
        buffer[pos] = OPT_SERVER_ID;
        buffer[pos + 1] = 4;
        writeU32BE(buffer[pos + 2 ..][0..4], server_ip);
        pos += 6;
    }

    // Parameter request list
    buffer[pos] = OPT_PARAM_REQUEST;
    buffer[pos + 1] = 4;
    buffer[pos + 2] = OPT_SUBNET_MASK;
    buffer[pos + 3] = OPT_ROUTER;
    buffer[pos + 4] = OPT_DNS;
    buffer[pos + 5] = OPT_LEASE_TIME;
    pos += 6;

    // End option
    buffer[pos] = OPT_END;
    pos += 1;

    return pos;
}

// =============================================================================
// Response Handling
// =============================================================================

pub fn handleResponse(data: []const u8) void {
    if (data.len < 240) return;

    const cookie = readU32BE(data[236..240]);
    if (cookie != DHCP_MAGIC_COOKIE) return;

    // Parse options
    var pos: usize = 240;
    var msg_type: u8 = 0;
    const offered_ip: u32 = readU32BE(data[16..20]); // yiaddr
    var subnet: u32 = 0;
    var gateway: u32 = 0;
    var dns: u32 = 0;
    var server_id: u32 = 0;
    var lease_time: u32 = 0;

    while (pos < data.len) {
        const opt = data[pos];
        if (opt == OPT_END) break;
        if (opt == OPT_PAD) {
            pos += 1;
            continue;
        }

        if (pos + 1 >= data.len) break;
        const len = data[pos + 1];
        if (pos + 2 + len > data.len) break;

        const opt_data = data[pos + 2 .. pos + 2 + len];

        switch (opt) {
            OPT_MESSAGE_TYPE => msg_type = opt_data[0],
            OPT_SUBNET_MASK => subnet = readU32BE(opt_data[0..4]),
            OPT_ROUTER => gateway = readU32BE(opt_data[0..4]),
            OPT_DNS => dns = readU32BE(opt_data[0..4]),
            OPT_SERVER_ID => server_id = readU32BE(opt_data[0..4]),
            OPT_LEASE_TIME => lease_time = readU32BE(opt_data[0..4]),
            else => {},
        }

        pos += 2 + len;
    }

    switch (msg_type) {
        DHCPOFFER => {
            if (state == .selecting) {
                current_lease.ip_addr = offered_ip;
                current_lease.subnet_mask = subnet;
                current_lease.gateway = gateway;
                current_lease.dns_server = dns;
                current_lease.server_id = server_id;
                current_lease.lease_time = lease_time;
            }
        },
        DHCPACK => {
            if (state == .requesting or state == .renewing) {
                current_lease.valid = true;
                current_lease.obtained_at = 0;
                state = .bound;
                serial.writeString("[DHCP] Lease obtained\n");
            }
        },
        DHCPNAK => {
            state = .init;
            current_lease.valid = false;
            serial.writeString("[DHCP] Lease rejected\n");
        },
        else => {},
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn generateXid() u32 {
    return 0x12345678;
}

fn writeU32BE(data: []u8, val: u32) void {
    data[0] = @intCast((val >> 24) & 0xFF);
    data[1] = @intCast((val >> 16) & 0xFF);
    data[2] = @intCast((val >> 8) & 0xFF);
    data[3] = @intCast(val & 0xFF);
}

fn readU32BE(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | @as(u32, data[3]);
}
