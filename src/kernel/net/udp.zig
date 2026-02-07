//! Zamrud OS - UDP Protocol
//! User Datagram Protocol (RFC 768)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ip = @import("ip.zig");
const checksum = @import("checksum.zig");

pub const HEADER_SIZE: usize = 8;
pub const MAX_SOCKETS: usize = 16;

pub const UdpSocket = struct {
    port: u16,
    bound: bool,
    callback: ?*const fn ([]const u8, u32, u16) void,

    pub fn bind(self: *UdpSocket, port: u16) bool {
        if (self.bound) return false;
        if (isPortBound(port)) return false;
        self.port = port;
        self.bound = true;
        return true;
    }

    pub fn unbind(self: *UdpSocket) void {
        self.bound = false;
        self.port = 0;
    }
};

var sockets: [MAX_SOCKETS]UdpSocket = undefined;
var initialized: bool = false;
var packets_received: u64 = 0;
var packets_sent: u64 = 0;

pub fn init() void {
    for (&sockets) |*sock| {
        sock.* = .{ .port = 0, .bound = false, .callback = null };
    }
    initialized = true;
    serial.writeString("[UDP] UDP initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn createSocket() ?*UdpSocket {
    for (&sockets) |*sock| {
        if (!sock.bound) {
            return sock;
        }
    }
    return null;
}

fn isPortBound(port: u16) bool {
    for (&sockets) |*sock| {
        if (sock.bound and sock.port == port) {
            return true;
        }
    }
    return false;
}

fn findSocket(port: u16) ?*UdpSocket {
    for (&sockets) |*sock| {
        if (sock.bound and sock.port == port) {
            return sock;
        }
    }
    return null;
}

pub fn handlePacket(iface: *network.NetworkInterface, packet: *const ip.IpPacket) void {
    _ = iface;

    if (packet.payload.len < HEADER_SIZE) return;

    const src_port = readU16BE(packet.payload[0..2]);
    const dst_port = readU16BE(packet.payload[2..4]);
    const length = readU16BE(packet.payload[4..6]);

    _ = length;
    packets_received += 1;

    if (findSocket(dst_port)) |sock| {
        if (sock.callback) |cb| {
            cb(packet.payload[HEADER_SIZE..], packet.header.src_ip, src_port);
        }
    }
}

pub fn send(iface: *network.NetworkInterface, dst_ip: u32, src_port: u16, dst_port: u16, data: []const u8) bool {
    var udp_packet: [1024]u8 = undefined;
    const total_len = HEADER_SIZE + data.len;

    if (total_len > udp_packet.len) return false;

    writeU16BE(udp_packet[0..2], src_port);
    writeU16BE(udp_packet[2..4], dst_port);
    writeU16BE(udp_packet[4..6], @intCast(total_len));
    writeU16BE(udp_packet[6..8], 0);

    for (data, 0..) |b, i| {
        udp_packet[HEADER_SIZE + i] = b;
    }

    const cksum = checksum.calculateWithPseudo(iface.ip_addr, dst_ip, ip.PROTO_UDP, udp_packet[0..total_len]);
    writeU16BE(udp_packet[6..8], if (cksum == 0) 0xFFFF else cksum);

    if (ip.send(iface, dst_ip, ip.PROTO_UDP, udp_packet[0..total_len])) {
        packets_sent += 1;
        return true;
    }
    return false;
}

pub fn getStats() struct { received: u64, sent: u64 } {
    return .{ .received = packets_received, .sent = packets_sent };
}

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn writeU16BE(data: []u8, val: u16) void {
    data[0] = @intCast((val >> 8) & 0xFF);
    data[1] = @intCast(val & 0xFF);
}
