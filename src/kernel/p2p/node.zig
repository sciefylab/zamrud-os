//! Zamrud OS - P2P Network Node Manager
//! P.3c: Socket Listener & Broadcaster
//! P.3e Ready: Listener Dispatch for Twin-Node Eviction
//! GOV.2a: Handshake public-key binding foundation
//!
//! Responsibilities:
//! - TCP listener for incoming P2P peers
//! - UDP broadcaster for local discovery
//! - Incoming handshake validation
//! - Dispatch received peer messages into p2p.handleIncomingMessage()
//!
//! P.3e note:
//! Eviction packets are not handled directly here.
//! They flow through:
//!   node.zig -> p2p.handleIncomingMessage() -> protocol.zig -> eviction.zig

const serial = @import("../drivers/serial/serial.zig");
const net = @import("../net/net.zig");
const socket = @import("../net/socket.zig");
const timer = @import("../drivers/timer/timer.zig");
const ahci = @import("../drivers/storage/ahci.zig");
const hash = @import("../crypto/hash.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const constant_time = @import("../crypto/constant_time.zig");

const peer = @import("peer.zig");
const message = @import("message.zig");
const protocol = @import("protocol.zig");

// =============================================================================
// Konfigurasi Port P2P Zamrud OS
// =============================================================================

pub const ZAMRUD_P2P_PORT: u16 = 27777;
pub const ZAMRUD_DISCOVERY_PORT: u16 = 27778;

pub const MAX_ACCEPT_PER_POLL: usize = 4;
pub const MAX_PEER_READ_PER_POLL: usize = 16;

// =============================================================================
// State
// =============================================================================

var is_listening: bool = false;
var tcp_listener_sock: ?*socket.Socket = null;

// Static buffers to reduce stack pressure
var incoming_buffer: [message.MAX_WIRE_SIZE]u8 = undefined;
var ack_buffer: [message.MAX_WIRE_SIZE]u8 = undefined;
var incoming_message: message.Message = undefined;
var incoming_node_info: protocol.NodeInfo = undefined;
var ack_message: message.Message = undefined;

// =============================================================================
// P2P Listener
// =============================================================================

/// Membuka socket TCP dan mendengarkan permintaan dari peer lain.
pub fn startListener() bool {
    if (is_listening) return true;

    serial.writeString("[P2P-NODE] Starting secure P2P Listener on TCP Port ");
    printU16(ZAMRUD_P2P_PORT);
    serial.writeString("...\n");

    tcp_listener_sock = socket.create(.tcp);

    if (tcp_listener_sock == null) {
        serial.writeString("[P2P-NODE] Error: Failed to create TCP socket.\n");
        return false;
    }

    if (!socket.bind(tcp_listener_sock.?, 0, ZAMRUD_P2P_PORT)) {
        serial.writeString("[P2P-NODE] Error: Failed to bind TCP socket.\n");
        socket.close(tcp_listener_sock.?);
        tcp_listener_sock = null;
        return false;
    }

    if (!socket.listen(tcp_listener_sock.?, 32)) {
        serial.writeString("[P2P-NODE] Error: Failed to start listening.\n");
        socket.close(tcp_listener_sock.?);
        tcp_listener_sock = null;
        return false;
    }

    is_listening = true;

    serial.writeString("[P2P-NODE] P2P Listener is now ACTIVE and waiting for peers.\n");
    return true;
}

/// Stop listener.
pub fn stopListener() void {
    if (!is_listening) return;

    if (tcp_listener_sock) |sock| {
        socket.close(sock);
        tcp_listener_sock = null;
    }

    is_listening = false;

    serial.writeString("[P2P-NODE] Listener stopped\n");
}

pub fn isListening() bool {
    return is_listening;
}

/// Fungsi yang dipanggil berkala dari scheduler/timer.
/// Tugas:
/// 1. Accept koneksi baru.
/// 2. Poll message dari peer connected.
pub fn pollIncomingConnections() void {
    if (!is_listening or tcp_listener_sock == null) return;

    acceptNewPeers();
    pollConnectedPeerMessages();
}

// =============================================================================
// Accept Incoming Peers
// =============================================================================

fn acceptNewPeers() void {
    if (!@hasDecl(socket, "accept")) return;

    var accepted: usize = 0;

    while (accepted < MAX_ACCEPT_PER_POLL) : (accepted += 1) {
        var peer_ip: u32 = 0;
        var peer_port: u16 = 0;

        if (socket.accept(tcp_listener_sock.?, &peer_ip, &peer_port)) |peer_sock| {
            serial.writeString("[P2P-NODE] Incoming connection from ");
            printIp(peer_ip);
            serial.writeString(":");
            printU16(peer_port);
            serial.writeString("\n");

            handlePeerHandshake(peer_sock, peer_ip, peer_port);
        } else {
            break;
        }
    }
}

// =============================================================================
// GOV.2a Security Gateway: Validasi Peer Masuk
// =============================================================================

fn validateNodeIdBinding(msg: *const message.Message, info: *const protocol.NodeInfo) bool {
    var expected_id: [32]u8 = [_]u8{0} ** 32;

    hash.sha256Into(&info.public_key, &expected_id);

    const ok = constant_time.constantTimeCompare32(&expected_id, &msg.sender_id);

    constant_time.secureZero32(&expected_id);

    return ok;
}

fn validateHandshakeMessage(msg: *const message.Message, info: *const protocol.NodeInfo) bool {
    var parsed_key = gov_sign.PublicKey{};
    defer gov_sign.clearPublicKey(&parsed_key);
    if (!gov_sign.deserializePublicKey(&info.public_key, &parsed_key)) {
        serial.writeString("[P2P-NODE] [DROP] Malformed public key in handshake\n");
        return false;
    }
    if (!validateNodeIdBinding(msg, info)) {
        serial.writeString("[P2P-NODE] [DROP] Handshake node_id != sha256(public_key)\n");
        return false;
    }
    if (!message.verifyWithPublicKey(msg, &parsed_key)) {
        serial.writeString("[P2P-NODE] [DROP] Invalid handshake signature\n");
        return false;
    }
    return true;
}
fn handlePeerHandshake(peer_sock: *socket.Socket, peer_ip: u32, peer_port: u16) void {
    const bytes_read = socket.recv(peer_sock, &incoming_buffer);

    if (bytes_read <= 0) {
        socket.close(peer_sock);
        return;
    }

    const n: usize = @intCast(bytes_read);

    if (!message.decodeInto(incoming_buffer[0..n], &incoming_message)) {
        serial.writeString("[P2P-NODE] [DROP] Failed to decode incoming handshake payload\n");
        socket.close(peer_sock);
        return;
    }
    const msg = &incoming_message;

    if (msg.msg_type != .handshake) {
        serial.writeString("[P2P-NODE] [DROP] First packet is not handshake\n");
        socket.close(peer_sock);
        return;
    }

    if (peer.isBanned(msg.sender_id)) {
        serial.writeString("[P2P-NODE] [DROP] Banned peer attempted handshake\n");
        socket.close(peer_sock);
        return;
    }

    const payload_len: usize = @intCast(msg.payload_len);

    if (!protocol.decodeNodeInfoInto(msg.payload[0..payload_len], &incoming_node_info)) {
        serial.writeString("[P2P-NODE] [DROP] Invalid NodeInfo in handshake\n");
        socket.close(peer_sock);
        return;
    }
    const info = &incoming_node_info;

    if (info.version != @import("p2p.zig").VERSION) {
        serial.writeString("[P2P-NODE] [DROP] Unsupported peer protocol version\n");
        socket.close(peer_sock);
        return;
    }

    // GOV.2a:
    // Verify public-key binding before accepting peer:
    // sender_id must equal sha256(NodeInfo.public_key).
    // message envelope must not be unsigned.
    // verifyWithPublicKey() is called here as the strict handshake path.
    if (!validateHandshakeMessage(msg, info)) {
        socket.close(peer_sock);
        return;
    }

    const added = peer.addInbound(msg.sender_id, peer_ip, peer_port, peer_sock);

    if (added == null) {
        serial.writeString("[P2P-NODE] [DROP] Failed to add inbound peer\n");
        socket.close(peer_sock);
        return;
    }

    const p = added.?;

    p.public_key = info.public_key;
    p.capabilities = info.capabilities;

    if (!sendHandshakeAck(peer_sock)) {
        serial.writeString("[P2P-NODE] Failed to send handshake ack\n");
        peer.remove(msg.sender_id);
        return;
    }

    serial.writeString("[P2P-NODE] Inbound handshake accepted from ");
    printIp(peer_ip);
    serial.writeString("\n");
}

fn sendHandshakeAck(peer_sock: *socket.Socket) bool {
    const p2p = @import("p2p.zig");
    ack_message = message.createEmpty(p2p.getNodeId(), .handshake_ack);
    const info = protocol.NodeInfo{
        .version = p2p.VERSION,
        .port = ZAMRUD_P2P_PORT,
        .public_key = p2p.getPublicKeyBlob(),
        .capabilities = protocol.CAP_FULL_NODE,
    };
    ack_message.payload_len = protocol.encodeNodeInfo(&info, &ack_message.payload);
    if (ack_message.payload_len == 0) return false;
    if (!message.signWithSession(&ack_message)) return false;
    const len = message.encode(&ack_message, &ack_buffer);
    if (len == 0) return false;
    return socket.send(peer_sock, ack_buffer[0..len]) >= 0;
}
// =============================================================================
// Poll Connected Peer Messages
// =============================================================================

fn pollConnectedPeerMessages() void {
    const p2p = @import("p2p.zig");

    const peers = peer.getAll();

    var reads: usize = 0;

    for (peers) |*p| {
        if (reads >= MAX_PEER_READ_PER_POLL) break;
        if (p.status != .connected) continue;
        if (peer.isBanned(p.id)) continue;

        if (p.socket) |sock| {
            const bytes_read = socket.recv(sock, &incoming_buffer);

            if (bytes_read > 0) {
                const n: usize = @intCast(bytes_read);

                p2p.handleIncomingMessage(p, incoming_buffer[0..n]);

                reads += 1;
            } else if (bytes_read < 0) {
                serial.writeString("[P2P-NODE] Peer socket read error, disconnecting\n");
                peer.disconnect(p);
                reads += 1;
            }
        }
    }
}

// =============================================================================
// P2P Broadcaster
// =============================================================================

/// Mengirimkan KTP jaringan / hardware hint ke jaringan lokal via UDP broadcast.
/// Catatan:
/// Ini bukan full handshake. Ini hanya discovery beacon.
pub fn broadcastPresence() bool {
    var hw_hash: [32]u8 = [_]u8{0} ** 32;

    if (ahci.isInitialized() and ahci.getDriveCount() > 0) {
        if (ahci.getDriveSerial(0)) |serial_str| {
            hash.sha256Into(serial_str, &hw_hash);
        }
    }

    const udp_sock = socket.create(.udp);

    if (udp_sock == null) {
        serial.writeString("[P2P-NODE] Failed to create UDP discovery socket\n");
        return false;
    }

    if (@hasDecl(socket, "setBroadcast")) {
        socket.setBroadcast(udp_sock.?, true);
    }

    const broadcast_ip: u32 = 0xFFFFFFFF;

    serial.writeString("[P2P-NODE] Broadcasting Node Identity to Network...\n");

    if (@hasDecl(socket, "sendTo")) {
        _ = socket.sendTo(
            udp_sock.?,
            &hw_hash,
            broadcast_ip,
            ZAMRUD_DISCOVERY_PORT,
        );
    }

    socket.close(udp_sock.?);
    return true;
}

// =============================================================================
// P.3e Helper: Local Detection Entry Point
// =============================================================================

/// Convenience helper.
/// Other subsystems may call this when node-level logic detects malicious peer behavior.
pub fn reportPeerForEviction(
    target_id: [32]u8,
    target_ip: u32,
    reason: @import("eviction.zig").EvictionReason,
    detail: []const u8,
) bool {
    const eviction = @import("eviction.zig");

    if (!@hasDecl(eviction, "reportLocalEvidence")) {
        return false;
    }

    return eviction.reportLocalEvidence(target_id, target_ip, reason, detail);
}

// =============================================================================
// Status
// =============================================================================

pub fn getListenerSocket() ?*socket.Socket {
    return tcp_listener_sock;
}

pub fn getPort() u16 {
    return ZAMRUD_P2P_PORT;
}

pub fn getDiscoveryPort() u16 {
    return ZAMRUD_DISCOVERY_PORT;
}

// =============================================================================
// Helpers untuk Mencetak Log
// =============================================================================

fn getTimestamp() u64 {
    return timer.getSeconds();
}

fn printU16(val: u16) void {
    var buf: [5]u8 = undefined;
    var i: usize = 0;
    var v = val;

    if (v == 0) {
        serial.writeChar('0');
        return;
    }

    while (v > 0) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn printIp(ip: u32) void {
    printU16(@intCast((ip >> 24) & 0xFF));
    serial.writeChar('.');
    printU16(@intCast((ip >> 16) & 0xFF));
    serial.writeChar('.');
    printU16(@intCast((ip >> 8) & 0xFF));
    serial.writeChar('.');
    printU16(@intCast(ip & 0xFF));
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  P2P NODE TESTS P.3c/P.3e/GOV.2a\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1] port constants........... ");
    if (ZAMRUD_P2P_PORT == 27777 and ZAMRUD_DISCOVERY_PORT == 27778) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [2] listener state query..... ");
    _ = isListening();
    serial.writeString("PASS\n");
    passed += 1;

    serial.writeString("  [3] get ports................ ");
    if (getPort() == ZAMRUD_P2P_PORT and getDiscoveryPort() == ZAMRUD_DISCOVERY_PORT) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [4] public key binding....... ");
    {
        var pk: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8 = [_]u8{0xA5} ** gov_sign.PUBLIC_KEY_BLOB_BYTES;
        var expected_id: [32]u8 = undefined;

        hash.sha256Into(&pk, &expected_id);

        var msg = message.createPing(expected_id);

        const info = protocol.NodeInfo{
            .version = @import("p2p.zig").VERSION,
            .port = ZAMRUD_P2P_PORT,
            .public_key = pk,
            .capabilities = protocol.CAP_FULL_NODE,
        };

        if (validateNodeIdBinding(&msg, &info)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  Node Results: ");
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
