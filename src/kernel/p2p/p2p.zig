//! Zamrud OS - P2P Network Protocol
//! Decentralized peer-to-peer communication layer
//! P.3c: TCP Listener & UDP Discovery Integration
//! P.3d: Onion Routing Ready
//! P.3e: Twin-Node Eviction Transport Ready

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const auth = @import("../identity/auth.zig");
const constant_time = @import("../crypto/constant_time.zig");
const net = @import("../net/net.zig");
const udp = @import("../net/udp.zig");
const tcp = @import("../net/tcp.zig");
const socket = @import("../net/socket.zig");
const chain = @import("../chain/chain.zig");
const timer = @import("../drivers/timer/timer.zig");

const peer = @import("peer.zig");
const discovery = @import("discovery.zig");
const message = @import("message.zig");
const sync = @import("sync.zig");
const protocol = @import("protocol.zig");
const node = @import("node.zig");

// =============================================================================
// Constants
// =============================================================================

pub const VERSION: u8 = 2;
pub const DEFAULT_PORT: u16 = 31337;
pub const P2P_SECURE_PORT: u16 = 27777;
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
    port: u16 = P2P_SECURE_PORT,
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

var node_id: [32]u8 = [_]u8{0} ** 32;
var node_public_key_bytes: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8 =
    [_]u8{0} ** gov_sign.PUBLIC_KEY_BLOB_BYTES;
var static_incoming_message: message.Message = undefined;
var static_handshake_message: message.Message = undefined;

var messages_sent: u64 = 0;
var messages_received: u64 = 0;
var bytes_sent: u64 = 0;
var bytes_received: u64 = 0;
var start_time: u64 = 0;

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

    generateNodeIdentity();

    peer.init();
    discovery.init();
    message.init();
    sync.init();

    if (@hasDecl(protocol, "init")) {
        protocol.init();
    }

    initialized = true;
    node_status = .offline;

    serial.writeString("[P2P] Node ID: ");
    printHex(node_id[0..8]);
    serial.writeString("...\n");

    serial.writeString("[P2P] P2P network initialized (P.3e transport ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn generateNodeIdentity() void {
    @memset(node_public_key_bytes[0..], 0);
    @memset(node_id[0..], 0);

    const public_key = auth.getGovernancePublicKey() orelse {
        serial.writeString("[P2P] Governance key unavailable; identity is fail-closed\n");
        return;
    };

    const serialized_len = gov_sign.serializePublicKey(
        public_key,
        &node_public_key_bytes,
    );
    if (serialized_len != gov_sign.PUBLIC_KEY_BLOB_BYTES) {
        serial.writeString("[P2P] Failed to serialize governance public key\n");
        constant_time.secureZero(&node_public_key_bytes);
        return;
    }

    crypto.sha256Into(&node_public_key_bytes, &node_id);
}

fn hasNodeIdentity() bool {
    return !constant_time.constantTimeIsZero32(&node_id);
}

/// Refresh the P2P identity after login/unlock. P2P initialization may run
/// before the user identity session is available at boot.
pub fn refreshIdentity() bool {
    if (hasNodeIdentity()) return true;
    generateNodeIdentity();
    return hasNodeIdentity();
}

// =============================================================================
// Node Operations
// =============================================================================

pub fn start() bool {
    if (!initialized) return false;
    if (!refreshIdentity()) {
        serial.writeString("[P2P] Cannot start without unlocked governance identity\n");
        return false;
    }
    if (node_status != .offline) return false;

    serial.writeString("[P2P] Starting P2P node...\n");

    node_status = .connecting;
    start_time = getTimestamp();

    if (@hasDecl(node, "startListener")) {
        if (!node.startListener()) {
            serial.writeString("[P2P] Failed to start secure P.3 listener\n");
            node_status = .offline;
            return false;
        }
    } else {
        if (!startListener()) {
            serial.writeString("[P2P] Failed to start legacy listener\n");
            node_status = .offline;
            return false;
        }
    }

    if (config.enable_discovery) {
        connectToBootstrapPeers();
    }

    if (config.enable_discovery) {
        discovery.start();

        if (@hasDecl(node, "broadcastPresence")) {
            _ = node.broadcastPresence();
        }
    }

    node_status = .online;
    serial.writeString("[P2P] Node is online\n");

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

    sync.stop();
    discovery.stop();
    peer.disconnectAll();

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

/// Main network polling function.
/// Should be called periodically from scheduler/timer.
pub fn pollNetwork() void {
    if (node_status == .offline) return;

    if (@hasDecl(node, "pollIncomingConnections")) {
        node.pollIncomingConnections();
    }

    // P.3e maintenance: cleanup stale eviction votes
    const eviction = @import("eviction.zig");
    if (@hasDecl(eviction, "pollMaintenance")) {
        eviction.pollMaintenance();
    }

    peer.checkTimeouts();
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

    const sock = socket.create(.tcp) orelse return false;

    if (!socket.connect(sock, ip, port)) {
        socket.close(sock);
        return false;
    }

    if (!performHandshake(sock, ip, port)) {
        socket.close(sock);
        return false;
    }

    return true;
}

fn performHandshake(sock: *socket.Socket, ip: u32, port: u16) bool {
    var handshake = message.Message{
        .msg_type = .handshake,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** message.MAX_PAYLOAD_SIZE,
        .payload_len = 0,
        .signature = [_]u8{0} ** message.SIGNATURE_SIZE,
    };

    const info = protocol.NodeInfo{
        .version = VERSION,
        .port = config.port,
        .public_key = node_public_key_bytes,
        .capabilities = protocol.CAP_FULL_NODE,
    };

    handshake.payload_len = protocol.encodeNodeInfo(&info, &handshake.payload);

    if (!message.signWithSession(&handshake)) return false;

    var buffer: [message.MAX_WIRE_SIZE]u8 = undefined;
    const len = message.encode(&handshake, &buffer);

    if (len == 0) {
        serial.writeString("[P2P] Failed to encode handshake\n");
        return false;
    }

    if (socket.send(sock, buffer[0..len]) < 0) {
        return false;
    }

    messages_sent += 1;
    bytes_sent += len;

    var recv_buf: [message.MAX_WIRE_SIZE]u8 = undefined;
    const recv_len = socket.recv(sock, &recv_buf);

    if (recv_len <= 0) {
        return false;
    }

    messages_received += 1;
    bytes_received += @intCast(recv_len);

    if (!message.decodeInto(recv_buf[0..@intCast(recv_len)], &static_handshake_message)) return false;
    const response = &static_handshake_message;
    if (response.msg_type != .handshake_ack) return false;
    if (peer.isBanned(response.sender_id)) {
        serial.writeString("[P2P] Refusing handshake with banned peer\n");
        return false;
    }
    var remote_info: protocol.NodeInfo = undefined;
    const response_payload_len: usize = @intCast(response.payload_len);
    if (!protocol.decodeNodeInfoInto(response.payload[0..response_payload_len], &remote_info)) return false;
    var remote_key = gov_sign.PublicKey{};
    defer gov_sign.clearPublicKey(&remote_key);
    if (!gov_sign.deserializePublicKey(&remote_info.public_key, &remote_key)) return false;
    if (!message.verifyWithPublicKey(response, &remote_key)) {
        serial.writeString("[P2P] Invalid signature from peer\n");
        return false;
    }
    const added = peer.add(response.sender_id, ip, port, sock) orelse return false;
    added.public_key = remote_info.public_key;

    serial.writeString("[P2P] Handshake successful with ");
    printHex(response.sender_id[0..8]);
    serial.writeString("\n");

    return true;
}

// =============================================================================
// Message Sending
// =============================================================================

pub fn broadcast(msg_type: message.MessageType, payload: []const u8) void {
    const copy_len = @min(payload.len, message.MAX_PAYLOAD_SIZE);

    var msg = message.Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** message.MAX_PAYLOAD_SIZE,
        .payload_len = @intCast(copy_len),
        .signature = [_]u8{0} ** message.SIGNATURE_SIZE,
    };

    if (copy_len > 0) {
        @memcpy(msg.payload[0..copy_len], payload[0..copy_len]);
    }

    if (!message.signWithSession(&msg)) {
        serial.writeString("[P2P] Message signing failed\n");
        return;
    }

    var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
    const len = message.encode(&msg, &buffer);

    if (len == 0) {
        serial.writeString("[P2P] Broadcast encode failed\n");
        return;
    }

    const peers = peer.getAll();

    for (peers) |p| {
        if (p.status == .connected) {
            if (peer.isBanned(p.id)) continue;

            if (p.socket) |s| {
                _ = socket.send(s, buffer[0..len]);
                messages_sent += 1;
                bytes_sent += len;
            }
        }
    }
}

/// P.3e helper:
/// Broadcast to all connected peers except a specific peer ID.
/// Used so eviction votes/commits are not sent directly to the target.
pub fn broadcastExcept(
    excluded_peer_id: [32]u8,
    msg_type: message.MessageType,
    payload: []const u8,
) void {
    const copy_len = @min(payload.len, message.MAX_PAYLOAD_SIZE);

    var msg = message.Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** message.MAX_PAYLOAD_SIZE,
        .payload_len = @intCast(copy_len),
        .signature = [_]u8{0} ** message.SIGNATURE_SIZE,
    };

    if (copy_len > 0) {
        @memcpy(msg.payload[0..copy_len], payload[0..copy_len]);
    }

    if (!message.signWithSession(&msg)) {
        serial.writeString("[P2P] Message signing failed\n");
        return;
    }

    var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
    const len = message.encode(&msg, &buffer);

    if (len == 0) {
        serial.writeString("[P2P] BroadcastExcept encode failed\n");
        return;
    }

    const peers = peer.getAll();

    for (peers) |p| {
        if (p.status != .connected) continue;
        if (peer.isBanned(p.id)) continue;

        if (eqlBytes(&p.id, &excluded_peer_id)) {
            continue;
        }

        if (p.socket) |s| {
            _ = socket.send(s, buffer[0..len]);
            messages_sent += 1;
            bytes_sent += len;
        }
    }
}

pub fn sendToPeer(peer_id: [32]u8, msg_type: message.MessageType, payload: []const u8) bool {
    if (peer.isBanned(peer_id)) {
        serial.writeString("[P2P] Refusing send to banned peer\n");
        return false;
    }

    const p = peer.getById(peer_id) orelse return false;

    if (p.status != .connected) return false;

    const copy_len = @min(payload.len, message.MAX_PAYLOAD_SIZE);

    var msg = message.Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** message.MAX_PAYLOAD_SIZE,
        .payload_len = @intCast(copy_len),
        .signature = [_]u8{0} ** message.SIGNATURE_SIZE,
    };

    if (copy_len > 0) {
        @memcpy(msg.payload[0..copy_len], payload[0..copy_len]);
    }

    if (!message.signWithSession(&msg)) {
        serial.writeString("[P2P] Message signing failed\n");
        return false;
    }

    var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
    const len = message.encode(&msg, &buffer);

    if (len == 0) {
        serial.writeString("[P2P] sendToPeer encode failed\n");
        return false;
    }

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

    if (!message.decodeInto(data, &static_incoming_message)) {
        serial.writeString("[P2P] Failed to decode message\n");
        return;
    }
    const msg = &static_incoming_message;

    if (peer.isBanned(msg.sender_id)) {
        serial.writeString("[P2P] Dropping message from banned peer\n");
        return;
    }

    var peer_key = gov_sign.PublicKey{};
    defer gov_sign.clearPublicKey(&peer_key);
    if (!gov_sign.deserializePublicKey(&p.public_key, &peer_key) or
        !message.verifyWithPublicKey(msg, &peer_key))
    {
        serial.writeString("[P2P] Invalid message signature\n");
        peer.decreaseReputation(p, 3);
        return;
    }

    if (!eqlBytes(&msg.sender_id, &p.id)) {
        serial.writeString("[P2P] Sender ID mismatch\n");
        peer.decreaseReputation(p, 5);
        return;
    }

    p.last_seen = getTimestamp();

    protocol.handleMessage(p, msg);
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

pub fn getPublicKeyBlob() [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8 {
    return node_public_key_bytes;
}

/// Shell/status compatibility alias. This returns the complete canonical
/// serialized ML-DSA-65 public-key blob, not the 32-byte node fingerprint.
pub fn getPublicKey() [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8 {
    return node_public_key_bytes;
}

pub fn getPeerCount() usize {
    return peer.getConnectedCount();
}

pub fn getMessagesSent() u64 {
    return messages_sent;
}

pub fn getMessagesReceived() u64 {
    return messages_received;
}

pub fn getBytesSent() u64 {
    return bytes_sent;
}

pub fn getBytesReceived() u64 {
    return bytes_received;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
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

    if (initialized) {
        passed += 1;
    } else {
        failed += 1;
    }

    // The governance key may become available only after shell login.
    _ = refreshIdentity();

    var has_id = false;

    for (node_id) |b| {
        if (b != 0) {
            has_id = true;
            break;
        }
    }

    if (has_id) {
        // Governance identity is available and the P2P node fingerprint was
        // derived successfully.
        passed += 1;
    } else if (!auth.isGovernanceSigningAvailable()) {
        // P2P can initialize before the dedicated governance-signing session
        // is unlocked. Remaining without an identity is the required
        // fail-closed state; no legacy or ephemeral fallback key is allowed.
        passed += 1;
    } else {
        // A signing session exists but identity derivation still failed.
        failed += 1;
    }

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
