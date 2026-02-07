//! Zamrud OS - Socket API
//! BSD-like socket interface

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const udp = @import("udp.zig");
const ip = @import("ip.zig");

pub const MAX_SOCKETS: usize = 32;

pub const SocketType = enum {
    tcp,
    udp,
    raw,
};

pub const SocketState = enum {
    closed,
    bound,
    listening,
    connecting,
    connected,
    closing,
};

pub const Socket = struct {
    sock_type: SocketType,
    state: SocketState,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    in_use: bool,

    rx_buffer: [4096]u8,
    rx_len: usize,

    pub fn hasData(self: *const Socket) bool {
        return self.rx_len > 0;
    }

    pub fn read(self: *Socket, buf: []u8) usize {
        const to_copy = @min(buf.len, self.rx_len);
        for (0..to_copy) |i| {
            buf[i] = self.rx_buffer[i];
        }

        if (to_copy < self.rx_len) {
            const remaining = self.rx_len - to_copy;
            for (0..remaining) |i| {
                self.rx_buffer[i] = self.rx_buffer[to_copy + i];
            }
            self.rx_len = remaining;
        } else {
            self.rx_len = 0;
        }

        return to_copy;
    }
};

/// UDP socket info for netstat display
pub const UdpSocketInfo = struct {
    local_addr: u32,
    local_port: u16,
    active: bool,
};

var sockets: [MAX_SOCKETS]Socket = undefined;
var initialized: bool = false;

pub fn init() void {
    for (&sockets) |*sock| {
        sock.* = Socket{
            .sock_type = .tcp,
            .state = .closed,
            .local_ip = 0,
            .local_port = 0,
            .remote_ip = 0,
            .remote_port = 0,
            .in_use = false,
            .rx_buffer = undefined,
            .rx_len = 0,
        };
    }
    initialized = true;
    serial.writeString("[SOCKET] Socket API initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn create(sock_type: SocketType) ?*Socket {
    for (&sockets) |*sock| {
        if (!sock.in_use) {
            sock.* = Socket{
                .sock_type = sock_type,
                .state = .closed,
                .local_ip = 0,
                .local_port = 0,
                .remote_ip = 0,
                .remote_port = 0,
                .in_use = true,
                .rx_buffer = undefined,
                .rx_len = 0,
            };
            return sock;
        }
    }
    return null;
}

pub fn bind(sock: *Socket, local_ip: u32, port: u16) bool {
    if (sock.state != .closed) return false;

    for (&sockets) |*s| {
        if (s.in_use and s != sock and s.local_port == port) {
            return false;
        }
    }

    sock.local_ip = local_ip;
    sock.local_port = port;
    sock.state = .bound;
    return true;
}

pub fn listen(sock: *Socket, backlog: usize) bool {
    _ = backlog;
    if (sock.sock_type != .tcp) return false;
    if (sock.state != .bound) return false;
    sock.state = .listening;
    return true;
}

pub fn connect(sock: *Socket, remote_ip: u32, port: u16) bool {
    if (sock.state != .closed and sock.state != .bound) return false;

    sock.remote_ip = remote_ip;
    sock.remote_port = port;
    sock.state = .connecting;

    if (sock.sock_type == .udp) {
        sock.state = .connected;
    }

    return true;
}

pub fn send(sock: *Socket, data: []const u8) isize {
    if (sock.state != .connected and sock.sock_type == .tcp) {
        return -1;
    }

    const iface = network.getDefaultInterface() orelse return -1;

    switch (sock.sock_type) {
        .udp => {
            if (udp.send(iface, sock.remote_ip, sock.local_port, sock.remote_port, data)) {
                return @intCast(data.len);
            }
            return -1;
        },
        .tcp => return -1,
        .raw => return -1,
    }
}

pub fn sendto(sock: *Socket, data: []const u8, remote_ip: u32, port: u16) isize {
    if (sock.sock_type != .udp) return -1;

    const iface = network.getDefaultInterface() orelse return -1;

    if (udp.send(iface, remote_ip, sock.local_port, port, data)) {
        return @intCast(data.len);
    }
    return -1;
}

pub fn recv(sock: *Socket, buf: []u8) isize {
    if (!sock.in_use) return -1;
    if (sock.rx_len == 0) return 0;
    return @intCast(sock.read(buf));
}

pub fn close(sock: *Socket) void {
    sock.state = .closed;
    sock.in_use = false;
    sock.rx_len = 0;
}

/// Close all sockets
pub fn closeAll() void {
    for (&sockets) |*sock| {
        if (sock.in_use) {
            sock.state = .closed;
            sock.in_use = false;
            sock.rx_len = 0;
        }
    }
}

pub fn getSocketCount() usize {
    var count: usize = 0;
    for (&sockets) |*sock| {
        if (sock.in_use) count += 1;
    }
    return count;
}

/// Get UDP sockets for netstat display
var udp_socket_info: [MAX_SOCKETS]UdpSocketInfo = undefined;

pub fn getUdpSockets() []const UdpSocketInfo {
    var count: usize = 0;
    for (&sockets) |*sock| {
        if (sock.in_use and sock.sock_type == .udp) {
            udp_socket_info[count] = .{
                .local_addr = sock.local_ip,
                .local_port = sock.local_port,
                .active = sock.state != .closed,
            };
            count += 1;
        }
    }
    return udp_socket_info[0..count];
}
