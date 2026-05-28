//! Zamrud OS - P2P Protocol Handler
//! Message routing, state machine, and P.3 Hardware Attestation Handshake

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const discovery = @import("discovery.zig");
const sync = @import("sync.zig");

// Imports for P.3 Hardware Attestation
const crypto = @import("../crypto/crypto.zig");
const identity = @import("../identity/identity.zig");
const timer = @import("../drivers/timer/timer.zig");
const ahci = @import("../drivers/storage/ahci.zig");
const hash = @import("../crypto/hash.zig");
const signature_mod = @import("../crypto/signature.zig");

// =============================================================================
// Constants
// =============================================================================

pub const CAP_FULL_NODE: u32 = 0x01;
pub const CAP_LIGHT_NODE: u32 = 0x02;
pub const CAP_VALIDATOR: u32 = 0x04;
pub const CAP_RELAY: u32 = 0x08;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAGIC_BYTES = [_]u8{ 'Z', 'A', 'M', 'N', 'E', 'T', '0', '1' }; // ZAMNET01

pub const PacketType = enum(u8) {
    Handshake = 0x01,
    HandshakeAck = 0x02,
    Eviction = 0x03, // Paket Penggusuran Kloningan (Anti-Double Online)
    Ping = 0x04,
    Pong = 0x05,
    OnionRouted = 0x06, // Paket data terenkripsi berlapis
};

// =============================================================================
// Types
// =============================================================================

pub const NodeInfo = struct {
    version: u8,
    port: u16,
    public_key: [32]u8,
    capabilities: u32,
};

/// P.3: Struktur paket identitas saat pertama kali terhubung ke jaringan Bawang
pub const HandshakePayload = extern struct {
    magic: [8]u8,
    version: u32,
    packet_type: u8,
    timestamp: u64,
    public_key: [32]u8,
    hardware_hash: [32]u8,
    hw_signature: [64]u8, // Tanda tangan HardwareHash menggunakan Private Key
};

pub const ValidationResult = enum {
    Valid,
    InvalidMagic,
    UnsupportedVersion,
    SignatureMismatch,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    initialized = true;
    serial.writeString("[PROTO] Protocol handler initialized (P.3 Ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// P.3: Onion Routing Handshake Builders & Validators
// =============================================================================

/// Merakit paket salaman (KTP Jaringan) untuk dikirim ke peers
pub fn buildHandshake() ?HandshakePayload {
    var payload: HandshakePayload = undefined;

    // 1. Set Header & Identitas
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        payload.magic[i] = MAGIC_BYTES[i];
    }
    payload.version = PROTOCOL_VERSION;
    payload.packet_type = @intFromEnum(PacketType.Handshake);
    payload.timestamp = timer.getSeconds();

    // 2. Gunakan Kunci Publik dari Node P2P (Bukan User Identity yang terkunci)
    const node_pub = signature_mod.KeyPair.getPublicKey();
    i = 0;
    while (i < 32) : (i += 1) {
        payload.public_key[i] = node_pub[i];
    }

    // 3. Ekstrak DNA Hardware Langsung dari SSD
    var hw_hash: [32]u8 = [_]u8{0} ** 32;
    if (ahci.isInitialized() and ahci.getDriveCount() > 0) {
        if (ahci.getDriveSerial(0)) |serial_str| {
            hash.sha256Into(serial_str, &hw_hash);
        }
    }

    i = 0;
    while (i < 32) : (i += 1) {
        payload.hardware_hash[i] = hw_hash[i];
    }

    // 4. Tanda Tangani DNA Hardware menggunakan Node Secret Key yang aktif di RAM
    const active_sec_key = signature_mod.KeyPair.getSecretKey();
    const sig = crypto.signMessage(&payload.hardware_hash, active_sec_key);

    i = 0;
    while (i < 64) : (i += 1) {
        payload.hw_signature[i] = sig[i];
    }

    return payload;
}

/// Memvalidasi paket salaman dari node lain
pub fn validateHandshake(payload: *const HandshakePayload) ValidationResult {
    // 1. Verifikasi Magic Bytes
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (payload.magic[i] != MAGIC_BYTES[i]) return .InvalidMagic;
    }

    // 2. Verifikasi Versi Protokol
    if (payload.version != PROTOCOL_VERSION) return .UnsupportedVersion;

    // 3. Verifikasi Tanda Tangan Kriptografis
    const is_valid_sig = crypto.verifySignature(&payload.hardware_hash, &payload.hw_signature, &payload.public_key);

    if (!is_valid_sig) {
        return .SignatureMismatch;
    }

    return .Valid;
}

// =============================================================================
// Message Handling (Legacy/Main Protocol)
// =============================================================================

pub fn handleMessage(p: *peer.Peer, msg: *const message.Message) void {
    switch (msg.msg_type) {
        // Keepalive
        .ping => handlePing(p),
        .pong => handlePong(p),

        // Peer discovery
        .get_peers => handleGetPeers(p),
        .peers => handlePeers(p, msg.payload[0..msg.payload_len]),

        // Blockchain
        .get_blocks => handleGetBlocks(p, msg.payload[0..msg.payload_len]),
        .blocks => handleBlocks(p, msg.payload[0..msg.payload_len]),
        .new_block => handleNewBlock(p, msg.payload[0..msg.payload_len]),

        // Transactions
        .new_transaction => handleNewTransaction(p, msg.payload[0..msg.payload_len]),

        // Identity
        .identity_announce => handleIdentityAnnounce(p, msg.payload[0..msg.payload_len]),
        .identity_query => handleIdentityQuery(p, msg.payload[0..msg.payload_len]),

        // Consensus
        .vote => handleVote(p, msg.payload[0..msg.payload_len]),
        .proposal => handleProposal(p, msg.payload[0..msg.payload_len]),

        else => {},
    }
}

// =============================================================================
// Keepalive Handlers
// =============================================================================

fn handlePing(p: *peer.Peer) void {
    peer.updateLastSeen(p);

    // Send pong
    const p2p = @import("p2p.zig");
    _ = p2p.sendToPeer(p.id, .pong, &[_]u8{});
}

fn handlePong(p: *peer.Peer) void {
    peer.updateLastSeen(p);
    peer.increaseReputation(p, 1);
}

// =============================================================================
// Peer Discovery Handlers
// =============================================================================

fn handleGetPeers(p: *peer.Peer) void {
    peer.updateLastSeen(p);

    // Encode peer list
    var buffer: [4096]u8 = undefined;
    const len = discovery.encodePeerList(&buffer);

    // Send response
    const p2p = @import("p2p.zig");
    _ = p2p.sendToPeer(p.id, .peers, buffer[0..len]);
}

fn handlePeers(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    peer.increaseReputation(p, 2);

    // Process peer list
    discovery.handlePeerList(data);
}

// =============================================================================
// Blockchain Handlers
// =============================================================================

fn handleGetBlocks(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    if (data.len < 16) return;

    const from_block = readU64(data[0..8]);
    const count = readU64(data[8..16]);

    _ = from_block;
    _ = count;

    // TODO: Encode and send requested blocks
    // For now, just acknowledge
    serial.writeString("[PROTO] Blocks requested from peer\n");
}

fn handleBlocks(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    peer.increaseReputation(p, 5);

    sync.handleBlocks(data);
}

fn handleNewBlock(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    sync.handleNewBlock(p.id, data);

    // Relay to other peers (if not already seen)
    const p2p = @import("p2p.zig");
    p2p.broadcast(.new_block, data);
}

// =============================================================================
// Transaction Handlers
// =============================================================================

fn handleNewTransaction(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    // Validate transaction
    if (!validateTransaction(data)) {
        peer.decreaseReputation(p, 5);
        return;
    }

    peer.increaseReputation(p, 1);

    // Add to mempool
    // chain.addToMempool(data);

    // Relay to other peers
    const p2p = @import("p2p.zig");
    p2p.broadcast(.new_transaction, data);
}

fn validateTransaction(data: []const u8) bool {
    // Simplified validation
    // Real implementation would verify signature, balance, etc.
    return data.len > 0;
}

// =============================================================================
// Identity Handlers
// =============================================================================

fn handleIdentityAnnounce(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    // Parse identity announcement
    if (data.len < 64) return;

    // Verify and store identity
    serial.writeString("[PROTO] Identity announced from peer\n");
}

fn handleIdentityQuery(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    _ = data;

    // Look up and respond with identity
    serial.writeString("[PROTO] Identity queried by peer\n");
}

// =============================================================================
// Consensus Handlers
// =============================================================================

fn handleVote(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    _ = data;

    // Process vote for current proposal
    serial.writeString("[PROTO] Vote received from peer\n");
}

fn handleProposal(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);

    _ = data;

    // Process new block proposal
    serial.writeString("[PROTO] Proposal received from peer\n");
}

// =============================================================================
// Encoding Helpers
// =============================================================================

pub fn encodeNodeInfo(info: *const NodeInfo, buffer: []u8) u32 {
    if (buffer.len < 39) return 0;

    buffer[0] = info.version;
    buffer[1] = @intCast((info.port >> 8) & 0xFF);
    buffer[2] = @intCast(info.port & 0xFF);
    @memcpy(buffer[3..][0..32], &info.public_key);
    writeU32(buffer[35..], info.capabilities);

    return 39;
}

pub fn decodeNodeInfo(data: []const u8) ?NodeInfo {
    if (data.len < 39) return null;

    var public_key: [32]u8 = undefined;
    @memcpy(&public_key, data[3..][0..32]);

    return .{
        .version = data[0],
        .port = (@as(u16, data[1]) << 8) | @as(u16, data[2]),
        .public_key = public_key,
        .capabilities = readU32(data[35..]),
    };
}

// =============================================================================
// Utilities
// =============================================================================

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readU64(data: []const u8) u64 {
    return (@as(u64, data[0]) << 56) |
        (@as(u64, data[1]) << 48) |
        (@as(u64, data[2]) << 40) |
        (@as(u64, data[3]) << 32) |
        (@as(u64, data[4]) << 24) |
        (@as(u64, data[5]) << 16) |
        (@as(u64, data[6]) << 8) |
        @as(u64, data[7]);
}

fn writeU32(buf: []u8, val: u32) void {
    buf[0] = @intCast((val >> 24) & 0xFF);
    buf[1] = @intCast((val >> 16) & 0xFF);
    buf[2] = @intCast((val >> 8) & 0xFF);
    buf[3] = @intCast(val & 0xFF);
}
