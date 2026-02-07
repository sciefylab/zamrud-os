//! Zamrud OS - P2P Peer Discovery
//! Finds and connects to new peers

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const socket = @import("../net/socket.zig");
const net = @import("../net/net.zig");

// =============================================================================
// Constants
// =============================================================================

pub const DISCOVERY_INTERVAL_MS: u64 = 60000;
pub const MAX_DISCOVERED: usize = 128;

// =============================================================================
// Types
// =============================================================================

pub const DiscoveredPeer = struct {
    ip: u32,
    port: u16,
    peer_id: [32]u8,
    discovered_at: u64,
    attempts: u8,
};

// Define a named struct type for bootstrap peers
pub const BootstrapPeer = struct {
    ip: u32,
    port: u16,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var running: bool = false;
var discovered: [MAX_DISCOVERED]DiscoveredPeer = undefined;
var discovered_count: usize = 0;

// Bootstrap peers (hardcoded for initial network)
var bootstrap_peers: [8]BootstrapPeer = undefined;
var bootstrap_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    discovered_count = 0;
    bootstrap_count = 0;
    running = false;

    for (&discovered) |*d| {
        d.* = .{
            .ip = 0,
            .port = 0,
            .peer_id = [_]u8{0} ** 32,
            .discovered_at = 0,
            .attempts = 0,
        };
    }

    for (&bootstrap_peers) |*bp| {
        bp.* = .{ .ip = 0, .port = 0 };
    }

    // Add default bootstrap peers (example IPs)
    // In real deployment, these would be well-known seed nodes
    addBootstrapPeer(net.ipToU32(127, 0, 0, 1), 31337); // Localhost for testing

    initialized = true;
    serial.writeString("[DISCOVERY] Peer discovery initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Bootstrap Peers
// =============================================================================

pub fn addBootstrapPeer(ip: u32, port: u16) void {
    if (bootstrap_count >= bootstrap_peers.len) return;

    bootstrap_peers[bootstrap_count] = .{ .ip = ip, .port = port };
    bootstrap_count += 1;
}

/// Returns bootstrap peers as slice
pub fn getBootstrapPeers() []const BootstrapPeer {
    return bootstrap_peers[0..bootstrap_count];
}

// =============================================================================
// Discovery Operations
// =============================================================================

pub fn start() void {
    if (running) return;

    running = true;
    serial.writeString("[DISCOVERY] Starting peer discovery\n");

    // Initial discovery from bootstrap
    discoverFromBootstrap();
}

pub fn stop() void {
    running = false;
    serial.writeString("[DISCOVERY] Stopped peer discovery\n");
}

pub fn isRunning() bool {
    return running;
}

fn discoverFromBootstrap() void {
    const peers = getBootstrapPeers();
    for (peers) |bp| {
        addDiscovered(bp.ip, bp.port, [_]u8{0} ** 32);
    }
}

/// Request peer list from connected peers
pub fn requestPeers() void {
    if (!running) return;

    const p2p = @import("p2p.zig");
    p2p.broadcast(.get_peers, &[_]u8{});
}

/// Handle received peer list
pub fn handlePeerList(data: []const u8) void {
    // Parse peer list
    // Format: [COUNT:2][IP:4][PORT:2][ID:32]...
    if (data.len < 2) return;

    const count = (@as(u16, data[0]) << 8) | @as(u16, data[1]);
    var pos: usize = 2;

    var i: u16 = 0;
    while (i < count and pos + 38 <= data.len) : (i += 1) {
        const ip = readU32(data[pos..]);
        const port = readU16(data[pos + 4 ..]);
        var peer_id: [32]u8 = undefined;
        @memcpy(&peer_id, data[pos + 6 ..][0..32]);
        pos += 38;

        addDiscovered(ip, port, peer_id);
    }
}

/// Encode peer list for sending
pub fn encodePeerList(buffer: []u8) usize {
    const connected = peer.getConnected();
    var pos: usize = 2;
    var count: u16 = 0;

    for (connected) |p| {
        if (pos + 38 > buffer.len) break;

        writeU32(buffer[pos..], p.ip);
        writeU16(buffer[pos + 4 ..], p.port);
        @memcpy(buffer[pos + 6 ..][0..32], &p.id);
        pos += 38;
        count += 1;
    }

    // Write count at beginning
    buffer[0] = @intCast((count >> 8) & 0xFF);
    buffer[1] = @intCast(count & 0xFF);

    return pos;
}

// =============================================================================
// Discovered Peer Management
// =============================================================================

pub fn addDiscovered(ip: u32, port: u16, peer_id: [32]u8) void {
    // Skip if already connected
    if (peer.getByIp(ip) != null) return;

    // Skip if already discovered
    for (discovered[0..discovered_count]) |d| {
        if (d.ip == ip and d.port == port) return;
    }

    // Add to list
    if (discovered_count < MAX_DISCOVERED) {
        discovered[discovered_count] = .{
            .ip = ip,
            .port = port,
            .peer_id = peer_id,
            .discovered_at = getTimestamp(),
            .attempts = 0,
        };
        discovered_count += 1;
    }
}

pub fn getDiscovered() []const DiscoveredPeer {
    return discovered[0..discovered_count];
}

pub fn getDiscoveredCount() usize {
    return discovered_count;
}

/// Try to connect to discovered peers
pub fn connectToDiscovered(max_connections: usize) usize {
    const p2p = @import("p2p.zig");
    var connected: usize = 0;

    // Use index-based iteration to allow modification
    for (0..discovered_count) |i| {
        if (connected >= max_connections) break;
        if (discovered[i].attempts >= 3) continue; // Skip failed peers

        discovered[i].attempts += 1;

        if (p2p.connectToPeer(discovered[i].ip, discovered[i].port)) {
            connected += 1;
            // Mark for removal
            discovered[i].ip = 0;
            discovered[i].port = 0;
        }
    }

    // Compact list
    compactDiscovered();

    return connected;
}

fn compactDiscovered() void {
    var write_idx: usize = 0;
    for (0..discovered_count) |read_idx| {
        if (discovered[read_idx].ip != 0) {
            if (write_idx != read_idx) {
                discovered[write_idx] = discovered[read_idx];
            }
            write_idx += 1;
        }
    }
    discovered_count = write_idx;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readU16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn writeU32(buf: []u8, val: u32) void {
    buf[0] = @intCast((val >> 24) & 0xFF);
    buf[1] = @intCast((val >> 16) & 0xFF);
    buf[2] = @intCast((val >> 8) & 0xFF);
    buf[3] = @intCast(val & 0xFF);
}

fn writeU16(buf: []u8, val: u16) void {
    buf[0] = @intCast((val >> 8) & 0xFF);
    buf[1] = @intCast(val & 0xFF);
}
