//! Zamrud OS - P2P Peer Discovery (P.3e Ready)
//! Finds and connects to new peers
//!
//! P.3e Ready:
//! - Skips banned peers during discovery
//! - Removes evicted peers from discovered cache
//! - Encodes peer list without using peer.getConnected() stack-slice bug
//! - Adds discovery hygiene helpers for eviction module

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const socket = @import("../net/socket.zig");
const net = @import("../net/net.zig");

// =============================================================================
// Constants
// =============================================================================

pub const DISCOVERY_INTERVAL_MS: u64 = 60000;
pub const MAX_DISCOVERED: usize = 128;
pub const MAX_CONNECT_ATTEMPTS: u8 = 3;

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

var bootstrap_peers: [8]BootstrapPeer = undefined;
var bootstrap_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    running = false;
    discovered_count = 0;
    bootstrap_count = 0;

    for (&discovered) |*d| {
        d.* = emptyDiscovered();
    }

    for (&bootstrap_peers) |*bp| {
        bp.* = .{
            .ip = 0,
            .port = 0,
        };
    }

    // Localhost bootstrap for test/dev
    addBootstrapPeer(net.ipToU32(127, 0, 0, 1), 31337);

    initialized = true;

    serial.writeString("[DISCOVERY] Peer discovery initialized (P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyDiscovered() DiscoveredPeer {
    return .{
        .ip = 0,
        .port = 0,
        .peer_id = [_]u8{0} ** 32,
        .discovered_at = 0,
        .attempts = 0,
    };
}

// =============================================================================
// Bootstrap Peers
// =============================================================================

pub fn addBootstrapPeer(ip: u32, port: u16) void {
    if (bootstrap_count >= bootstrap_peers.len) return;

    // Avoid duplicate bootstrap entries
    for (bootstrap_peers[0..bootstrap_count]) |bp| {
        if (bp.ip == ip and bp.port == port) {
            return;
        }
    }

    bootstrap_peers[bootstrap_count] = .{
        .ip = ip,
        .port = port,
    };

    bootstrap_count += 1;
}

pub fn getBootstrapPeers() []const BootstrapPeer {
    return bootstrap_peers[0..bootstrap_count];
}

pub fn getBootstrapCount() usize {
    return bootstrap_count;
}

// =============================================================================
// Discovery Operations
// =============================================================================

pub fn start() void {
    if (running) return;

    running = true;
    serial.writeString("[DISCOVERY] Starting peer discovery\n");

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

/// Request peer list from connected peers.
pub fn requestPeers() void {
    if (!running) return;

    const p2p = @import("p2p.zig");
    p2p.broadcast(.get_peers, &[_]u8{});
}

/// Handle received peer list.
/// Format:
/// [COUNT:2][IP:4][PORT:2][ID:32]...
pub fn handlePeerList(data: []const u8) void {
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

        if (!isZeroId(&peer_id) and peer.isBanned(peer_id)) {
            continue;
        }

        addDiscovered(ip, port, peer_id);
    }
}

/// Encode currently connected peers into peer list.
/// Important:
/// This avoids peer.getConnected() because current peer.zig implementation
/// returns a slice to a local stack array.
pub fn encodePeerList(buffer: []u8) usize {
    if (buffer.len < 2) return 0;

    const all = peer.getAll();

    var pos: usize = 2;
    var count: u16 = 0;

    for (all) |p| {
        if (pos + 38 > buffer.len) break;
        if (p.status != .connected) continue;
        if (peer.isBanned(p.id)) continue;

        writeU32(buffer[pos..], p.ip);
        writeU16(buffer[pos + 4 ..], p.port);
        @memcpy(buffer[pos + 6 ..][0..32], &p.id);

        pos += 38;
        count += 1;
    }

    buffer[0] = @intCast((count >> 8) & 0xFF);
    buffer[1] = @intCast(count & 0xFF);

    return pos;
}

// =============================================================================
// Discovered Peer Management
// =============================================================================

pub fn addDiscovered(ip: u32, port: u16, peer_id: [32]u8) void {
    if (ip == 0 or port == 0) return;

    // P.3e: do not add banned peer IDs
    if (!isZeroId(&peer_id) and peer.isBanned(peer_id)) {
        return;
    }

    // Skip if already connected by IP
    if (peer.getByIp(ip) != null) {
        return;
    }

    // Skip if already discovered
    for (discovered[0..discovered_count]) |d| {
        if (d.ip == ip and d.port == port) {
            return;
        }

        if (!isZeroId(&peer_id) and !isZeroId(&d.peer_id) and eqlBytes(&d.peer_id, &peer_id)) {
            return;
        }
    }

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

pub fn clearDiscovered() void {
    for (&discovered) |*d| {
        d.* = emptyDiscovered();
    }

    discovered_count = 0;
}

/// P.3e: remove discovered peer by ID.
pub fn removeDiscoveredById(peer_id: *const [32]u8) void {
    var write_idx: usize = 0;

    for (0..discovered_count) |read_idx| {
        if (!eqlBytes(&discovered[read_idx].peer_id, peer_id)) {
            if (write_idx != read_idx) {
                discovered[write_idx] = discovered[read_idx];
            }

            write_idx += 1;
        }
    }

    discovered_count = write_idx;
}

/// P.3e: remove discovered peer by IP.
pub fn removeDiscoveredByIp(ip: u32) void {
    var write_idx: usize = 0;

    for (0..discovered_count) |read_idx| {
        if (discovered[read_idx].ip != ip) {
            if (write_idx != read_idx) {
                discovered[write_idx] = discovered[read_idx];
            }

            write_idx += 1;
        }
    }

    discovered_count = write_idx;
}

/// P.3e: called after Twin-Node Eviction commit.
/// Cleans discovery cache so evicted node is not reconnected.
pub fn markPeerEvicted(peer_id: *const [32]u8) void {
    removeDiscoveredById(peer_id);

    serial.writeString("[DISCOVERY] Evicted peer removed from discovery cache\n");
}

/// Try to connect to discovered peers.
pub fn connectToDiscovered(max_connections: usize) usize {
    const p2p = @import("p2p.zig");

    var connected: usize = 0;

    for (0..discovered_count) |i| {
        if (connected >= max_connections) break;
        if (discovered[i].ip == 0 or discovered[i].port == 0) continue;
        if (discovered[i].attempts >= MAX_CONNECT_ATTEMPTS) continue;

        if (!isZeroId(&discovered[i].peer_id) and peer.isBanned(discovered[i].peer_id)) {
            discovered[i].ip = 0;
            discovered[i].port = 0;
            continue;
        }

        discovered[i].attempts += 1;

        if (p2p.connectToPeer(discovered[i].ip, discovered[i].port)) {
            connected += 1;

            // Mark for removal after successful connection
            discovered[i].ip = 0;
            discovered[i].port = 0;
        }
    }

    compactDiscovered();

    return connected;
}

fn compactDiscovered() void {
    var write_idx: usize = 0;

    for (0..discovered_count) |read_idx| {
        if (discovered[read_idx].ip != 0 and discovered[read_idx].port != 0) {
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

fn isZeroId(id: *const [32]u8) bool {
    for (id.*) |b| {
        if (b != 0) return false;
    }

    return true;
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    for (a, b) |x, y| {
        if (x != y) return false;
    }

    return true;
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  DISCOVERY TESTS P.3e READY\n");
    serial.writeString("========================================\n\n");

    if (!initialized) init();

    clearDiscovered();

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1] Add discovered........... ");
    {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xA1;

        addDiscovered(net.ipToU32(10, 0, 0, 1), 27777, id);

        if (getDiscoveredCount() == 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [2] Avoid duplicate.......... ");
    {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xA1;

        addDiscovered(net.ipToU32(10, 0, 0, 1), 27777, id);

        if (getDiscoveredCount() == 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [3] Remove by ID............. ");
    {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xA1;

        removeDiscoveredById(&id);

        if (getDiscoveredCount() == 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [4] Bootstrap count.......... ");
    {
        if (getBootstrapCount() > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  Discovery Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

fn printU32(val: u32) void {
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
