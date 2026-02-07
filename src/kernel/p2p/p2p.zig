//! Zamrud OS - P2P Network Protocol
//! Decentralized peer-to-peer communication layer

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const net = @import("../net/net.zig");
const udp = @import("../net/udp.zig");
const tcp = @import("../net/tcp.zig");
const socket = @import("../net/socket.zig");
const chain = @import("../chain/chain.zig");

const peer = @import("peer.zig");
const discovery = @import("discovery.zig");
const message = @import("message.zig");
const sync = @import("sync.zig");
const protocol = @import("protocol.zig");

// =============================================================================
// Constants
// =============================================================================

pub const VERSION: u8 = 1;
pub const DEFAULT_PORT: u16 = 31337;
pub const MAX_PEERS: usize = 64;
pub const MAX_MESSAGE_SIZE: usize = 65536;
pub const HEARTBEAT_INTERVAL_MS: u64 = 30000;
pub const PEER_TIMEOUT_MS: u64 = 120000;

// =============================================================================
// Types
// =============================================================================

pub const NodeStatus = enum {
    offline,
    connecting,
    online,
    syncing,
};

pub const NodeConfig = struct {
    port: u16 = DEFAULT_PORT,
    max_peers: usize = MAX_PEERS,
    enable_discovery: bool = true,
    enable_sync: bool = true,
    bootstrap_peers: []const PeerAddress = &[_]PeerAddress{},
};

pub const PeerAddress = struct {
    ip: u32,
    port: u16,
    peer_id: ?[32]u8 = null,
};

pub const NodeStats = struct {
    status: NodeStatus,
    peer_count: usize,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    uptime_seconds: u64,
    last_sync_block: u64,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var node_status: NodeStatus = .offline;
var config: NodeConfig = .{};

// Our identity
var node_id: [32]u8 = [_]u8{0} ** 32;
var node_private_key: [32]u8 = [_]u8{0} ** 32;
var node_public_key: [32]u8 = [_]u8{0} ** 32;

// Statistics
var messages_sent: u64 = 0;
var messages_received: u64 = 0;
var bytes_sent: u64 = 0;
var bytes_received: u64 = 0;
var start_time: u64 = 0;

// Listener socket
var listener_socket: ?*socket.Socket = null;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    initWithConfig(.{});
}

pub fn initWithConfig(cfg: NodeConfig) void {
    serial.writeString("[P2P] Initializing P2P network...\n");

    config = cfg;

    // Generate or load node identity
    generateNodeIdentity();

    // Initialize sub-modules
    peer.init();
    discovery.init();
    message.init();
    sync.init();
    protocol.init();

    initialized = true;
    node_status = .offline;

    serial.writeString("[P2P] Node ID: ");
    printHex(node_id[0..8]);
    serial.writeString("...\n");
    serial.writeString("[P2P] P2P network initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn generateNodeIdentity() void {
    // Generate keypair for this node
    crypto.KeyPair.generate();

    // getPublicKey() returns *[32]u8, need to dereference properly
    const pub_key_ptr = crypto.KeyPair.getPublicKey(); // *[32]u8
    @memcpy(&node_public_key, pub_key_ptr); // Copy from pointer

    // Hash public key to get shorter node ID
    const hash = crypto.sha256(&node_public_key);
    @memcpy(&node_id, &hash);

    // Store private key securely
    // getSecretKey returns *[64]u8, we only need first 32 bytes
    const secret_key_ptr = crypto.KeyPair.getSecretKey(); // *[64]u8
    @memcpy(&node_private_key, secret_key_ptr[0..32]);
}

// =============================================================================
// Node Operations
// =============================================================================

pub fn start() bool {
    if (!initialized) return false;
    if (node_status != .offline) return false;

    serial.writeString("[P2P] Starting P2P node...\n");

    node_status = .connecting;
    start_time = getTimestamp();

    // Start listening for incoming connections
    if (!startListener()) {
        serial.writeString("[P2P] Failed to start listener\n");
        node_status = .offline;
        return false;
    }

    // Connect to bootstrap peers
    if (config.enable_discovery) {
        connectToBootstrapPeers();
    }

    // Start discovery
    if (config.enable_discovery) {
        discovery.start();
    }

    node_status = .online;
    serial.writeString("[P2P] Node is online\n");

    // Start sync if enabled
    if (config.enable_sync) {
        node_status = .syncing;
        sync.start();
        node_status = .online;
    }

    return true;
}

pub fn stop() void {
    if (node_status == .offline) return;

    serial.writeString("[P2P] Stopping P2P node...\n");

    // Stop sync
    sync.stop();

    // Stop discovery
    discovery.stop();

    // Disconnect all peers
    peer.disconnectAll();

    // Close listener
    if (listener_socket) |sock| {
        socket.close(sock);
        listener_socket = null;
    }

    node_status = .offline;
    serial.writeString("[P2P] Node stopped\n");
}

fn startListener() bool {
    listener_socket = socket.create(.tcp) orelse return false;

    if (!socket.bind(listener_socket.?, 0, config.port)) {
        socket.close(listener_socket.?);
        listener_socket = null;
        return false;
    }

    if (!socket.listen(listener_socket.?, 16)) {
        socket.close(listener_socket.?);
        listener_socket = null;
        return false;
    }

    serial.writeString("[P2P] Listening on port ");
    printU16(config.port);
    serial.writeString("\n");

    return true;
}

fn connectToBootstrapPeers() void {
    for (config.bootstrap_peers) |addr| {
        _ = connectToPeer(addr.ip, addr.port);
    }
}

// =============================================================================
// Peer Connection
// =============================================================================

pub fn connectToPeer(ip: u32, port: u16) bool {
    serial.writeString("[P2P] Connecting to ");
    printIp(ip);
    serial.writeString(":");
    printU16(port);
    serial.writeString("\n");

    // Create socket
    const sock = socket.create(.tcp) orelse return false;

    // Connect
    if (!socket.connect(sock, ip, port)) {
        socket.close(sock);
        return false;
    }

    // Perform handshake
    if (!performHandshake(sock, ip, port)) {
        socket.close(sock);
        return false;
    }

    return true;
}

fn performHandshake(sock: *socket.Socket, ip: u32, port: u16) bool {
    // Build handshake message
    var handshake = message.Message{
        .msg_type = .handshake,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = undefined,
        .payload_len = 0,
        .signature = undefined,
    };

    // Add our info to payload
    const info = protocol.NodeInfo{
        .version = VERSION,
        .port = config.port,
        .public_key = node_public_key,
        .capabilities = protocol.CAP_FULL_NODE,
    };

    handshake.payload_len = protocol.encodeNodeInfo(&info, &handshake.payload);

    // Sign message
    message.sign(&handshake, &node_private_key);

    // Send handshake
    var buffer: [512]u8 = undefined;
    const len = message.encode(&handshake, &buffer);
    if (socket.send(sock, buffer[0..len]) < 0) {
        return false;
    }

    messages_sent += 1;
    bytes_sent += len;

    // Wait for response
    var recv_buf: [512]u8 = undefined;
    const recv_len = socket.recv(sock, &recv_buf);
    if (recv_len <= 0) {
        return false;
    }

    messages_received += 1;
    bytes_received += @intCast(recv_len);

    // Parse response
    const response = message.decode(recv_buf[0..@intCast(recv_len)]) orelse return false;

    if (response.msg_type != .handshake_ack) {
        return false;
    }

    // Verify signature
    if (!message.verify(&response)) {
        serial.writeString("[P2P] Invalid signature from peer\n");
        return false;
    }

    // Add peer
    _ = peer.add(response.sender_id, ip, port, sock);

    serial.writeString("[P2P] Handshake successful with ");
    printHex(response.sender_id[0..8]);
    serial.writeString("\n");

    return true;
}

// =============================================================================
// Message Sending
// =============================================================================

pub fn broadcast(msg_type: message.MessageType, payload: []const u8) void {
    var msg = message.Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = undefined,
        .payload_len = @intCast(payload.len),
        .signature = undefined,
    };

    // Copy payload
    const copy_len = @min(payload.len, msg.payload.len);
    @memcpy(msg.payload[0..copy_len], payload[0..copy_len]);

    // Sign message
    message.sign(&msg, &node_private_key);

    // Encode
    var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
    const len = message.encode(&msg, &buffer);

    // Send to all peers
    const peers = peer.getAll();
    for (peers) |p| {
        if (p.status == .connected) {
            if (p.socket) |s| {
                _ = socket.send(s, buffer[0..len]);
                messages_sent += 1;
                bytes_sent += len;
            }
        }
    }
}

pub fn sendToPeer(peer_id: [32]u8, msg_type: message.MessageType, payload: []const u8) bool {
    const p = peer.getById(peer_id) orelse return false;
    if (p.status != .connected) return false;

    var msg = message.Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = undefined,
        .payload_len = @intCast(payload.len),
        .signature = undefined,
    };

    const copy_len = @min(payload.len, msg.payload.len);
    @memcpy(msg.payload[0..copy_len], payload[0..copy_len]);

    message.sign(&msg, &node_private_key);

    var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
    const len = message.encode(&msg, &buffer);

    if (p.socket) |sock| {
        if (socket.send(sock, buffer[0..len]) >= 0) {
            messages_sent += 1;
            bytes_sent += len;
            return true;
        }
    }

    return false;
}

// =============================================================================
// Message Handling
// =============================================================================

pub fn handleIncomingMessage(p: *peer.Peer, data: []const u8) void {
    messages_received += 1;
    bytes_received += data.len;

    const msg = message.decode(data) orelse {
        serial.writeString("[P2P] Failed to decode message\n");
        return;
    };

    // Verify signature
    if (!message.verify(&msg)) {
        serial.writeString("[P2P] Invalid message signature\n");
        return;
    }

    // Check sender matches peer
    if (!eqlBytes(&msg.sender_id, &p.id)) {
        serial.writeString("[P2P] Sender ID mismatch\n");
        return;
    }

    // Update peer activity
    p.last_seen = getTimestamp();

    // Dispatch to protocol handler
    protocol.handleMessage(p, &msg);
}

// =============================================================================
// Status & Stats
// =============================================================================

pub fn getStatus() NodeStatus {
    return node_status;
}

pub fn getStats() NodeStats {
    const uptime = if (start_time > 0) getTimestamp() - start_time else 0;

    return .{
        .status = node_status,
        .peer_count = peer.getConnectedCount(),
        .messages_sent = messages_sent,
        .messages_received = messages_received,
        .bytes_sent = bytes_sent,
        .bytes_received = bytes_received,
        .uptime_seconds = uptime,
        .last_sync_block = sync.getLastBlock(),
    };
}

pub fn getNodeId() [32]u8 {
    return node_id;
}

pub fn getPublicKey() [32]u8 {
    return node_public_key;
}

pub fn getPeerCount() usize {
    return peer.getConnectedCount();
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

fn printHex(data: []const u8) void {
    const hex_chars = "0123456789abcdef";
    for (data) |b| {
        serial.writeChar(hex_chars[b >> 4]);
        serial.writeChar(hex_chars[b & 0xF]);
    }
}

fn printU16(val: u16) void {
    if (val >= 10000) serial.writeChar('0' + @as(u8, @intCast((val / 10000) % 10)));
    if (val >= 1000) serial.writeChar('0' + @as(u8, @intCast((val / 1000) % 10)));
    if (val >= 100) serial.writeChar('0' + @as(u8, @intCast((val / 100) % 10)));
    if (val >= 10) serial.writeChar('0' + @as(u8, @intCast((val / 10) % 10)));
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}

fn printIp(ip: u32) void {
    const parts = net.u32ToIp(ip);
    printU8(parts.a);
    serial.writeChar('.');
    printU8(parts.b);
    serial.writeChar('.');
    printU8(parts.c);
    serial.writeChar('.');
    printU8(parts.d);
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

// =============================================================================
// Test Support
// =============================================================================

pub fn runTests() bool {
    serial.writeString("[P2P] Running P2P tests...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Initialization
    if (initialized) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 2: Node ID generated
    var has_id = false;
    for (node_id) |b| {
        if (b != 0) {
            has_id = true;
            break;
        }
    }
    if (has_id) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 3: Sub-modules initialized
    if (peer.isInitialized() and discovery.isInitialized() and message.isInitialized()) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("[P2P] Tests: ");
    printU8(@intCast(passed));
    serial.writeString(" passed, ");
    printU8(@intCast(failed));
    serial.writeString(" failed\n");

    return failed == 0;
}
