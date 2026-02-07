//! Zamrud OS - TCP Protocol (Stub)
//! Transmission Control Protocol (RFC 793)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ip = @import("ip.zig");

pub const HEADER_SIZE: usize = 20;
pub const MAX_CONNECTIONS: usize = 16;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;
pub const FLAG_URG: u8 = 0x20;

pub const TcpState = enum {
    closed,
    listen,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    closing,
    last_ack,
    time_wait,
};

pub const TcpConnection = struct {
    state: TcpState,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
    seq_num: u32,
    ack_num: u32,
    in_use: bool,
};

pub const TcpStats = struct {
    received: u64,
    sent: u64,
    errors: u64,
};

var connections: [MAX_CONNECTIONS]TcpConnection = undefined;
var stats: TcpStats = .{ .received = 0, .sent = 0, .errors = 0 };
var initialized: bool = false;

pub fn init() void {
    for (&connections) |*conn| {
        conn.* = .{
            .state = .closed,
            .local_addr = 0,
            .local_port = 0,
            .remote_addr = 0,
            .remote_port = 0,
            .seq_num = 0,
            .ack_num = 0,
            .in_use = false,
        };
    }
    stats = .{ .received = 0, .sent = 0, .errors = 0 };
    initialized = true;
    serial.writeString("[TCP] TCP initialized (stub)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn handlePacket(iface: *network.NetworkInterface, packet: *const ip.IpPacket) void {
    _ = iface;
    if (packet.payload.len < HEADER_SIZE) return;
    stats.received += 1;
    // TODO: Full TCP implementation
}

pub fn getStats() TcpStats {
    return stats;
}

pub fn getConnections() []const TcpConnection {
    return &connections;
}
