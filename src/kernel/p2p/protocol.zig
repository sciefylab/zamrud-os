//! Zamrud OS - P2P Protocol Handler
//! Message routing and protocol state machine

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const discovery = @import("discovery.zig");
const sync = @import("sync.zig");

// =============================================================================
// Constants
// =============================================================================

pub const CAP_FULL_NODE: u32 = 0x01;
pub const CAP_LIGHT_NODE: u32 = 0x02;
pub const CAP_VALIDATOR: u32 = 0x04;
pub const CAP_RELAY: u32 = 0x08;

// =============================================================================
// Types
// =============================================================================

pub const NodeInfo = struct {
    version: u8,
    port: u16,
    public_key: [32]u8,
    capabilities: u32,
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
    serial.writeString("[PROTO] Protocol handler initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Message Handling
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
