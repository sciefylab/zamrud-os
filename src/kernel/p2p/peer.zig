//! Zamrud OS - P2P Peer Management
//! Manages connected peers and their state

const serial = @import("../drivers/serial/serial.zig");
const socket = @import("../net/socket.zig");
const crypto = @import("../crypto/crypto.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_PEERS: usize = 64;
pub const PEER_TIMEOUT_MS: u64 = 120000;

// =============================================================================
// Types
// =============================================================================

pub const PeerStatus = enum {
    disconnected,
    connecting,
    connected,
    banned,
};

pub const Peer = struct {
    id: [32]u8,
    ip: u32,
    port: u16,
    status: PeerStatus,
    socket: ?*socket.Socket,
    public_key: [32]u8,

    // Stats
    connected_at: u64,
    last_seen: u64,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,

    // Sync state
    last_block: u64,
    capabilities: u32,

    // Reputation
    reputation: i32,

    pub fn isActive(self: *const Peer) bool {
        return self.status == .connected;
    }
};

// =============================================================================
// State
// =============================================================================

var peers: [MAX_PEERS]Peer = undefined;
var peer_count: usize = 0;
var initialized: bool = false;

// Banned peers (by ID hash)
var banned_ids: [64][32]u8 = undefined;
var banned_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    peer_count = 0;
    banned_count = 0;

    for (&peers) |*p| {
        p.* = emptyPeer();
    }

    for (&banned_ids) |*id| {
        id.* = [_]u8{0} ** 32;
    }

    initialized = true;
    serial.writeString("[PEER] Peer manager initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyPeer() Peer {
    return .{
        .id = [_]u8{0} ** 32,
        .ip = 0,
        .port = 0,
        .status = .disconnected,
        .socket = null,
        .public_key = [_]u8{0} ** 32,
        .connected_at = 0,
        .last_seen = 0,
        .messages_sent = 0,
        .messages_received = 0,
        .bytes_sent = 0,
        .bytes_received = 0,
        .last_block = 0,
        .capabilities = 0,
        .reputation = 0,
    };
}

// =============================================================================
// Peer Operations
// =============================================================================

pub fn add(id: [32]u8, ip: u32, port: u16, sock: *socket.Socket) ?*Peer {
    // Check if banned
    if (isBanned(id)) {
        serial.writeString("[PEER] Rejecting banned peer\n");
        return null;
    }

    // Check if already exists
    if (getById(id)) |existing| {
        // Update existing peer
        existing.ip = ip;
        existing.port = port;
        existing.socket = sock;
        existing.status = .connected;
        existing.last_seen = getTimestamp();
        return existing;
    }

    // Find empty slot
    for (&peers) |*p| {
        if (p.status == .disconnected) {
            p.* = .{
                .id = id,
                .ip = ip,
                .port = port,
                .status = .connected,
                .socket = sock,
                .public_key = [_]u8{0} ** 32,
                .connected_at = getTimestamp(),
                .last_seen = getTimestamp(),
                .messages_sent = 0,
                .messages_received = 0,
                .bytes_sent = 0,
                .bytes_received = 0,
                .last_block = 0,
                .capabilities = 0,
                .reputation = 50, // Start neutral
            };
            peer_count += 1;

            serial.writeString("[PEER] Added peer, total: ");
            printUsize(peer_count);
            serial.writeString("\n");

            return p;
        }
    }

    serial.writeString("[PEER] No slots available\n");
    return null;
}

pub fn remove(id: [32]u8) void {
    for (&peers) |*p| {
        if (eqlBytes(&p.id, &id)) {
            if (p.socket) |sock| {
                socket.close(sock);
            }
            p.* = emptyPeer();
            if (peer_count > 0) peer_count -= 1;

            serial.writeString("[PEER] Removed peer\n");
            return;
        }
    }
}

pub fn disconnect(p: *Peer) void {
    if (p.socket) |sock| {
        socket.close(sock);
        p.socket = null;
    }
    p.status = .disconnected;
}

pub fn disconnectAll() void {
    for (&peers) |*p| {
        if (p.status == .connected) {
            disconnect(p);
        }
    }
    peer_count = 0;
}

// =============================================================================
// Peer Lookup
// =============================================================================

pub fn getById(id: [32]u8) ?*Peer {
    for (&peers) |*p| {
        if (p.status != .disconnected and eqlBytes(&p.id, &id)) {
            return p;
        }
    }
    return null;
}

pub fn getByIp(ip: u32) ?*Peer {
    for (&peers) |*p| {
        if (p.status != .disconnected and p.ip == ip) {
            return p;
        }
    }
    return null;
}

pub fn getAll() []Peer {
    return peers[0..MAX_PEERS];
}

pub fn getConnected() []*Peer {
    var result: [MAX_PEERS]*Peer = undefined;
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected) {
            result[count] = p;
            count += 1;
        }
    }

    return result[0..count];
}

pub fn getConnectedCount() usize {
    var count: usize = 0;
    for (peers) |p| {
        if (p.status == .connected) count += 1;
    }
    return count;
}

pub fn getTotalCount() usize {
    return peer_count;
}

// =============================================================================
// Reputation System
// =============================================================================

pub fn increaseReputation(p: *Peer, amount: i32) void {
    p.reputation = @min(100, p.reputation + amount);
}

pub fn decreaseReputation(p: *Peer, amount: i32) void {
    p.reputation = @max(-100, p.reputation - amount);

    // Auto-ban if reputation too low
    if (p.reputation <= -50) {
        ban(p.id);
        disconnect(p);
    }
}

pub fn ban(id: [32]u8) void {
    if (banned_count >= banned_ids.len) return;

    banned_ids[banned_count] = id;
    banned_count += 1;

    serial.writeString("[PEER] Banned peer\n");
}

pub fn unban(id: [32]u8) void {
    for (0..banned_count) |i| {
        if (eqlBytes(&banned_ids[i], &id)) {
            // Shift remaining
            var j = i;
            while (j + 1 < banned_count) : (j += 1) {
                banned_ids[j] = banned_ids[j + 1];
            }
            banned_count -= 1;
            return;
        }
    }
}

pub fn isBanned(id: [32]u8) bool {
    for (banned_ids[0..banned_count]) |bid| {
        if (eqlBytes(&bid, &id)) return true;
    }
    return false;
}

// =============================================================================
// Maintenance
// =============================================================================

pub fn checkTimeouts() void {
    const now = getTimestamp();

    for (&peers) |*p| {
        if (p.status == .connected) {
            if (now > p.last_seen + PEER_TIMEOUT_MS / 1000) {
                serial.writeString("[PEER] Peer timed out\n");
                disconnect(p);
            }
        }
    }
}

pub fn updateLastSeen(p: *Peer) void {
    p.last_seen = getTimestamp();
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn printUsize(val: usize) void {
    if (val >= 10) printUsize(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}
