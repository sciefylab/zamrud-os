//! Zamrud OS - Socket API
//! BSD-like socket interface with PID ownership (E3.4)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const udp = @import("udp.zig");
const ip = @import("ip.zig");
const net_cap = @import("../security/net_capability.zig");

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
    owner_pid: u16, // E3.4: owning process

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
            .owner_pid = 0,
            .rx_buffer = undefined,
            .rx_len = 0,
        };
    }
    initialized = true;
    serial.writeString("[SOCKET] Socket API initialized (E3.4 PID-aware)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Socket Index Lookup
// ============================================================================

/// Get the array index of a socket pointer
fn getSocketIndex(sock: *Socket) ?u8 {
    const base = @intFromPtr(&sockets[0]);
    const ptr = @intFromPtr(sock);
    const size = @sizeOf(Socket);
    if (ptr < base) return null;
    const offset = ptr - base;
    if (offset % size != 0) return null;
    const idx = offset / size;
    if (idx >= MAX_SOCKETS) return null;
    return @intCast(idx);
}

// ============================================================================
// Create
// ============================================================================

/// Legacy: create socket as kernel (pid=0)
pub fn create(sock_type: SocketType) ?*Socket {
    return createForProcess(sock_type, 0);
}

/// E3.4: create socket owned by a process
pub fn createForProcess(sock_type: SocketType, pid: u16) ?*Socket {
    // Enforce network capability
    if (pid != 0 and net_cap.isInitialized()) {
        const result = net_cap.checkCreate(pid);
        if (result.action != .allowed) {
            serial.writeString("[SOCKET] BLOCKED create pid=");
            printNumber(pid);
            serial.writeString(": ");
            serial.writeString(result.reason);
            serial.writeString("\n");
            return null;
        }
    }

    for (&sockets, 0..) |*sock, idx| {
        if (!sock.in_use) {
            sock.* = Socket{
                .sock_type = sock_type,
                .state = .closed,
                .local_ip = 0,
                .local_port = 0,
                .remote_ip = 0,
                .remote_port = 0,
                .in_use = true,
                .owner_pid = pid,
                .rx_buffer = undefined,
                .rx_len = 0,
            };

            // Register ownership
            if (pid != 0 and net_cap.isInitialized()) {
                const st: u8 = switch (sock_type) {
                    .tcp => 0,
                    .udp => 1,
                    .raw => 2,
                };
                _ = net_cap.registerSocket(@intCast(idx), pid, st, 0);
            }

            return sock;
        }
    }
    return null;
}

// ============================================================================
// Bind
// ============================================================================

/// Legacy bind (uses socket's owner_pid)
pub fn bind(sock: *Socket, local_ip: u32, port: u16) bool {
    return bindForProcess(sock, local_ip, port, sock.owner_pid);
}

/// E3.4: bind with explicit PID enforcement
pub fn bindForProcess(sock: *Socket, local_ip: u32, port: u16, pid: u16) bool {
    if (sock.state != .closed) return false;

    // Enforce
    if (pid != 0 and net_cap.isInitialized()) {
        const result = net_cap.checkBind(pid, local_ip, port);
        if (result.action != .allowed) {
            serial.writeString("[SOCKET] BLOCKED bind pid=");
            printNumber(pid);
            serial.writeString(" port=");
            printNumber(port);
            serial.writeString(": ");
            serial.writeString(result.reason);
            serial.writeString("\n");
            return false;
        }
    }

    // Port conflict check
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

// ============================================================================
// Listen
// ============================================================================

pub fn listen(sock: *Socket, backlog: usize) bool {
    _ = backlog;
    if (sock.sock_type != .tcp) return false;
    if (sock.state != .bound) return false;
    sock.state = .listening;
    return true;
}

// ============================================================================
// Connect
// ============================================================================

/// Legacy connect
pub fn connect(sock: *Socket, remote_ip: u32, port: u16) bool {
    return connectForProcess(sock, remote_ip, port, sock.owner_pid);
}

/// E3.4: connect with PID enforcement
pub fn connectForProcess(sock: *Socket, remote_ip: u32, port: u16, pid: u16) bool {
    if (sock.state != .closed and sock.state != .bound) return false;

    // Enforce
    if (pid != 0 and net_cap.isInitialized()) {
        const result = net_cap.checkConnect(pid, remote_ip, port);
        if (result.action != .allowed) {
            serial.writeString("[SOCKET] BLOCKED connect pid=");
            printNumber(pid);
            serial.writeString(" -> ");
            printIP(remote_ip);
            serial.writeString(":");
            printNumber(port);
            serial.writeString("\n");
            return false;
        }
    }

    sock.remote_ip = remote_ip;
    sock.remote_port = port;
    sock.state = .connecting;

    if (sock.sock_type == .udp) {
        sock.state = .connected;
    }

    // Update ownership record
    if (getSocketIndex(sock)) |idx| {
        if (net_cap.isInitialized()) {
            net_cap.updateSocketRemote(idx, remote_ip, port);
        }
    }

    return true;
}

// ============================================================================
// Send
// ============================================================================

/// Legacy send
pub fn send(sock: *Socket, data: []const u8) isize {
    return sendForProcess(sock, data, sock.owner_pid);
}

/// E3.4: send with PID enforcement
pub fn sendForProcess(sock: *Socket, data: []const u8, pid: u16) isize {
    if (sock.state != .connected and sock.sock_type == .tcp) {
        return -1;
    }

    // Enforce
    if (pid != 0 and net_cap.isInitialized()) {
        const result = net_cap.checkSend(pid);
        if (result.action != .allowed) {
            serial.writeString("[SOCKET] BLOCKED send pid=");
            printNumber(pid);
            serial.writeString(": ");
            serial.writeString(result.reason);
            serial.writeString("\n");
            return -2; // permission denied
        }
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

/// Legacy sendto
pub fn sendto(sock: *Socket, data: []const u8, remote_ip: u32, port: u16) isize {
    return sendtoForProcess(sock, data, remote_ip, port, sock.owner_pid);
}

/// E3.4: sendto with PID enforcement
pub fn sendtoForProcess(sock: *Socket, data: []const u8, remote_ip: u32, port: u16, pid: u16) isize {
    if (sock.sock_type != .udp) return -1;

    if (pid != 0 and net_cap.isInitialized()) {
        const send_result = net_cap.checkSend(pid);
        if (send_result.action != .allowed) return -2;

        const conn_result = net_cap.checkConnect(pid, remote_ip, port);
        if (conn_result.action != .allowed) return -2;
    }

    const iface = network.getDefaultInterface() orelse return -1;

    if (udp.send(iface, remote_ip, sock.local_port, port, data)) {
        return @intCast(data.len);
    }
    return -1;
}

// ============================================================================
// Recv
// ============================================================================

pub fn recv(sock: *Socket, buf: []u8) isize {
    if (!sock.in_use) return -1;
    if (sock.rx_len == 0) return 0;
    return @intCast(sock.read(buf));
}

// ============================================================================
// Close
// ============================================================================

pub fn close(sock: *Socket) void {
    // E3.4: unregister ownership
    if (getSocketIndex(sock)) |idx| {
        if (net_cap.isInitialized()) {
            net_cap.unregisterSocket(idx);
        }
    }

    sock.state = .closed;
    sock.in_use = false;
    sock.owner_pid = 0;
    sock.rx_len = 0;
}

/// Close all sockets
pub fn closeAll() void {
    for (&sockets, 0..) |*sock, idx| {
        if (sock.in_use) {
            if (net_cap.isInitialized()) {
                net_cap.unregisterSocket(@intCast(idx));
            }
            sock.state = .closed;
            sock.in_use = false;
            sock.owner_pid = 0;
            sock.rx_len = 0;
        }
    }
}

/// E3.4: close all sockets belonging to a specific process
pub fn closeProcessSockets(pid: u16) void {
    for (&sockets, 0..) |*sock, idx| {
        if (sock.in_use and sock.owner_pid == pid) {
            if (net_cap.isInitialized()) {
                net_cap.unregisterSocket(@intCast(idx));
            }
            sock.state = .closed;
            sock.in_use = false;
            sock.owner_pid = 0;
            sock.rx_len = 0;
        }
    }
}

// ============================================================================
// Queries
// ============================================================================

pub fn getSocketCount() usize {
    var count: usize = 0;
    for (&sockets) |*sock| {
        if (sock.in_use) count += 1;
    }
    return count;
}

/// E3.4: count sockets for a specific process
pub fn getProcessSocketCount(pid: u16) usize {
    var count: usize = 0;
    for (&sockets) |*sock| {
        if (sock.in_use and sock.owner_pid == pid) count += 1;
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

// ============================================================================
// Helpers
// ============================================================================

fn printNumber(n: anytype) void {
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

fn printIP(ip_val: u32) void {
    printNumber((ip_val >> 24) & 0xFF);
    serial.writeChar('.');
    printNumber((ip_val >> 16) & 0xFF);
    serial.writeChar('.');
    printNumber((ip_val >> 8) & 0xFF);
    serial.writeChar('.');
    printNumber(ip_val & 0xFF);
}
