//! Zamrud OS - Network Syscalls (SC6)
//! SYS_SOCKET (250), SYS_BIND (251), SYS_LISTEN (252),
//! SYS_ACCEPT (253), SYS_CONNECT (254), SYS_SENDTO (255), SYS_RECVFROM (256)
//!
//! Socket Handle Table: maps integer handle → *Socket for userspace.
//! E3.4: All operations use PID-aware socket functions.

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const socket = @import("../net/socket.zig");
const net = @import("../net/net.zig");

// =============================================================================
// Socket Handle Table
// =============================================================================
// Userspace gets integer handles (1..MAX_HANDLES).
// Handle 0 is invalid/reserved.

const MAX_HANDLES: usize = 32;

const HandleEntry = struct {
    sock: ?*socket.Socket = null,
    pid: u16 = 0,
    active: bool = false,
};

var handles: [MAX_HANDLES]HandleEntry = [_]HandleEntry{.{}} ** MAX_HANDLES;
var handles_initialized: bool = false;

fn initHandles() void {
    for (&handles) |*h| {
        h.* = .{};
    }
    handles_initialized = true;
}

fn allocHandle(sock: *socket.Socket, pid: u16) ?u16 {
    if (!handles_initialized) initHandles();

    // Handle IDs start at 1 (0 = invalid)
    for (&handles, 0..) |*h, idx| {
        if (!h.active) {
            h.sock = sock;
            h.pid = pid;
            h.active = true;
            return @intCast(idx + 1); // handle = index + 1
        }
    }
    return null;
}

fn lookupHandle(handle: u16, pid: u16) ?*socket.Socket {
    if (handle == 0 or handle > MAX_HANDLES) return null;
    if (!handles_initialized) return null;

    const entry = &handles[handle - 1];
    if (!entry.active) return null;

    // E3.4: PID ownership check (pid=0 = kernel, bypasses)
    if (pid != 0 and entry.pid != pid) return null;

    return entry.sock;
}

fn freeHandle(handle: u16) void {
    if (handle == 0 or handle > MAX_HANDLES) return;
    if (!handles_initialized) return;

    handles[handle - 1] = .{};
}

/// Free all handles for a process (called on process exit)
pub fn freeProcessHandles(pid: u16) void {
    if (!handles_initialized) return;

    for (&handles) |*h| {
        if (h.active and h.pid == pid) {
            if (h.sock) |s| {
                socket.close(s);
            }
            h.* = .{};
        }
    }
}

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        numbers.SYS_SOCKET => sysSocket(a1),
        numbers.SYS_BIND => sysBind(a1, a2, a3),
        numbers.SYS_LISTEN => sysListen(a1, a2),
        numbers.SYS_ACCEPT => sysAccept(a1),
        numbers.SYS_CONNECT => sysConnect(a1, a2, a3),
        numbers.SYS_SENDTO => sysSendto(a1, a2, a3, a4),
        numbers.SYS_RECVFROM => sysRecvfrom(a1, a2, a3, a4),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Pointer Validation
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

fn currentPid16() u16 {
    return @truncate(process.getCurrentPid());
}

// =============================================================================
// SYS_SOCKET (250) — Create a socket
//   a1 = type: 0=TCP, 1=UDP, 2=RAW
//   Returns: socket handle (>0) on success, negative error
// =============================================================================

fn sysSocket(type_raw: u64) i64 {
    if (!socket.isInitialized()) {
        if (!net.isInitialized()) return numbers.ENODEV;
        socket.init();
    }

    const pid = currentPid16();

    const sock_type: socket.SocketType = switch (type_raw) {
        0 => .tcp,
        1 => .udp,
        2 => .raw,
        else => return numbers.EINVAL,
    };

    // E3.4: PID-aware creation with net_cap enforcement
    const sock = socket.createForProcess(sock_type, pid) orelse {
        return numbers.ENOMEM;
    };

    // Allocate handle for userspace
    const handle = allocHandle(sock, pid) orelse {
        socket.close(sock);
        return numbers.EMFILE;
    };

    return @intCast(handle);
}

// =============================================================================
// SYS_BIND (251) — Bind socket to address:port
//   a1 = socket handle
//   a2 = ip_addr (u32, network byte order: (a<<24)|(b<<16)|(c<<8)|d)
//        0 = INADDR_ANY
//   a3 = port
//   Returns: 0 on success, negative error
// =============================================================================

fn sysBind(handle_raw: u64, ip_raw: u64, port_raw: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);
    const ip_addr: u32 = @truncate(ip_raw);
    const port: u16 = @truncate(port_raw);

    if (port == 0) return numbers.EINVAL;

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    // E3.4: PID-aware bind with net_cap enforcement
    if (socket.bindForProcess(sock, ip_addr, port, pid)) {
        return numbers.SUCCESS;
    }

    return numbers.EACCES;
}

// =============================================================================
// SYS_LISTEN (252) — Listen for connections (TCP only)
//   a1 = socket handle
//   a2 = backlog
//   Returns: 0 on success, negative error
// =============================================================================

fn sysListen(handle_raw: u64, backlog_raw: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);
    const backlog = @min(backlog_raw, 128);

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    if (socket.listen(sock, backlog)) {
        return numbers.SUCCESS;
    }

    return numbers.EINVAL;
}

// =============================================================================
// SYS_ACCEPT (253) — Accept incoming connection (TCP only)
//   a1 = listening socket handle
//   Returns: new socket handle on success, negative error
//
//   Note: Currently returns ENOSYS (TCP accept not fully implemented).
//   When TCP is complete, this will create a new connected socket.
// =============================================================================

fn sysAccept(handle_raw: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    // Verify it's a listening TCP socket
    if (sock.sock_type != .tcp) return numbers.EINVAL;
    if (sock.state != .listening) return numbers.EINVAL;

    // TCP accept not yet fully implemented
    // When ready: create new socket, return handle
    return numbers.EAGAIN; // no pending connections
}

// =============================================================================
// SYS_CONNECT (254) — Connect to remote address:port
//   a1 = socket handle
//   a2 = remote_ip (u32)
//   a3 = remote_port
//   Returns: 0 on success, negative error
// =============================================================================

fn sysConnect(handle_raw: u64, ip_raw: u64, port_raw: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);
    const remote_ip: u32 = @truncate(ip_raw);
    const port: u16 = @truncate(port_raw);

    if (remote_ip == 0) return numbers.EINVAL;
    if (port == 0) return numbers.EINVAL;

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    // E3.4: PID-aware connect with net_cap enforcement
    if (socket.connectForProcess(sock, remote_ip, port, pid)) {
        return numbers.SUCCESS;
    }

    return numbers.EACCES;
}

// =============================================================================
// SYS_SENDTO (255) — Send data (optionally to specific address)
//   a1 = socket handle
//   a2 = data_ptr
//   a3 = data_len
//   a4 = flags_or_dest:
//        If 0: use connected remote (send)
//        If nonzero: packed as (remote_ip << 16) | remote_port
//        For simplicity: a4 = remote_port (use connected IP if a4 != 0
//                         but remote_ip was set via connect)
//
//   Simplified encoding for SC6:
//     a4 = 0        → send to connected peer
//     a4 = port     → sendto (uses sock's remote_ip + override port)
//
//   Returns: bytes sent on success, negative error
// =============================================================================

fn sysSendto(handle_raw: u64, data_ptr: u64, data_len: u64, dest_raw: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);
    const len = @min(data_len, 4096);

    if (data_ptr == 0 and len > 0) return numbers.EFAULT;
    if (len > 0 and !validatePtr(data_ptr, len)) return numbers.EFAULT;

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    const data: []const u8 = if (len > 0)
        @as([*]const u8, @ptrFromInt(data_ptr))[0..len]
    else
        &[_]u8{};

    if (dest_raw == 0) {
        // Send to connected peer
        const result = socket.sendForProcess(sock, data, pid);
        if (result >= 0) return result;
        if (result == -2) return numbers.EPERM; // net_cap blocked
        return numbers.EIO;
    } else {
        // Sendto with destination port (use sock's remote_ip)
        const dest_port: u16 = @truncate(dest_raw);
        const remote_ip = if (sock.remote_ip != 0) sock.remote_ip else return numbers.EINVAL;

        const result = socket.sendtoForProcess(sock, data, remote_ip, dest_port, pid);
        if (result >= 0) return result;
        if (result == -2) return numbers.EPERM;
        return numbers.EIO;
    }
}

// =============================================================================
// SYS_RECVFROM (256) — Receive data from socket
//   a1 = socket handle
//   a2 = buf_ptr
//   a3 = buf_len
//   a4 = info_ptr (optional, for sender info: u32 ip + u16 port = 8 bytes)
//   Returns: bytes received on success, 0 if no data, negative error
// =============================================================================

fn sysRecvfrom(handle_raw: u64, buf_ptr: u64, buf_len: u64, info_ptr: u64) i64 {
    const pid = currentPid16();
    const handle: u16 = @truncate(handle_raw);
    const len = @min(buf_len, 4096);

    if (buf_ptr == 0) return numbers.EFAULT;
    if (!validatePtr(buf_ptr, len)) return numbers.EFAULT;

    const sock = lookupHandle(handle, pid) orelse return numbers.EBADF;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const result = socket.recv(sock, buf[0..len]);

    if (result < 0) return numbers.EIO;

    // Fill sender info if requested
    if (info_ptr != 0 and validatePtr(info_ptr, 8) and result > 0) {
        const info: *RecvInfo = @ptrFromInt(info_ptr);
        info.sender_ip = sock.remote_ip;
        info.sender_port = sock.remote_port;
        info._pad = 0;
    }

    return result;
}

const RecvInfo = extern struct {
    sender_ip: u32 = 0,
    sender_port: u16 = 0,
    _pad: u16 = 0,
};

// =============================================================================
// Cleanup helper (called from process exit)
// =============================================================================

pub fn onProcessExit(pid: u16) void {
    freeProcessHandles(pid);
    socket.closeProcessSockets(pid);
}
