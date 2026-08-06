//! Zamrud OS - P2P Protocol Handler V2
//! ML-DSA-65 authenticated hardware-attestation handshake.

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const discovery = @import("discovery.zig");
const sync = @import("sync.zig");
const eviction = @import("eviction.zig");
const identity = @import("../identity/identity.zig");
const auth = @import("../identity/auth.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const constant_time = @import("../crypto/constant_time.zig");
const timer = @import("../drivers/timer/timer.zig");
const ahci = @import("../drivers/storage/ahci.zig");
const hash = @import("../crypto/hash.zig");

pub const CAP_FULL_NODE: u32 = 0x01;
pub const CAP_LIGHT_NODE: u32 = 0x02;
pub const CAP_VALIDATOR: u32 = 0x04;
pub const CAP_RELAY: u32 = 0x08;
pub const PROTOCOL_VERSION: u32 = 2;
pub const MAGIC_BYTES = [_]u8{ 'Z', 'A', 'M', 'N', 'E', 'T', '0', '2' };
pub const HANDSHAKE_DOMAIN = "ZAMRUD:P2P:HANDSHAKE:V2";
pub const CHALLENGE_SIZE: usize = 32;
pub const HANDSHAKE_TRANSCRIPT_SIZE: usize =
    8 + 4 + 1 + 8 + CHALLENGE_SIZE + 32 + 32;

pub const PacketType = enum(u8) {
    Handshake = 0x01,
    HandshakeAck = 0x02,
    Eviction = 0x03,
    Ping = 0x04,
    Pong = 0x05,
    OnionRouted = 0x06,
};

pub const NodeInfo = struct {
    version: u8,
    port: u16,
    public_key: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8,
    capabilities: u32,
};

/// Wire V2. Public-key and signature fields contain canonical gov_sign bytes.
pub const HandshakePayload = extern struct {
    magic: [8]u8,
    version: u32,
    packet_type: u8,
    timestamp: u64,
    challenge: [CHALLENGE_SIZE]u8,
    public_key: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8,
    hardware_hash: [32]u8,
    hw_signature: [gov_sign.SIGNATURE_BLOB_BYTES]u8,
};

pub const ValidationResult = enum {
    Valid,
    InvalidMagic,
    UnsupportedVersion,
    SignatureMismatch,
    MissingChallenge,
    InvalidPublicKey,
};

var initialized: bool = false;
var static_handshake: HandshakePayload = undefined;
var static_transcript: [HANDSHAKE_TRANSCRIPT_SIZE]u8 =
    [_]u8{0} ** HANDSHAKE_TRANSCRIPT_SIZE;

pub fn init() void {
    if (@hasDecl(eviction, "init")) eviction.init();
    initialized = true;
    serial.writeString("[PROTO] Protocol V2 initialized (ML-DSA-65 handshake)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

/// Stack-safe handshake builder.
pub fn buildHandshakeInto(out: *HandshakePayload) bool {
    @memset(@as([*]u8, @ptrCast(out))[0..@sizeOf(HandshakePayload)], 0);

    @memcpy(&out.magic, &MAGIC_BYTES);
    out.version = PROTOCOL_VERSION;
    out.packet_type = @intFromEnum(PacketType.Handshake);
    out.timestamp = timer.getSeconds();

    // Bind a fresh challenge to this handshake.
    const crypto = @import("../crypto/crypto.zig");
    crypto.random.getBytes(&out.challenge);
    if (constant_time.constantTimeIsZero32(&out.challenge)) return false;

    const public_key = auth.getGovernancePublicKey() orelse return false;
    const public_key_len =
        gov_sign.serializePublicKey(public_key, &out.public_key);
    if (public_key_len != gov_sign.PUBLIC_KEY_BLOB_BYTES) return false;

    if (ahci.isInitialized() and ahci.getDriveCount() > 0) {
        if (ahci.getDriveSerial(0)) |serial_value| {
            hash.sha256Into(serial_value, &out.hardware_hash);
        }
    }

    const transcript_len = buildHandshakeTranscript(out, &static_transcript);
    if (transcript_len == 0) return false;
    defer constant_time.secureZero(static_transcript[0..transcript_len]);

    var signature = gov_sign.Signature{};
    defer gov_sign.clearSignature(&signature);
    if (!auth.signGovernancePayload(
        HANDSHAKE_DOMAIN,
        static_transcript[0..transcript_len],
        &signature,
    )) return false;

    const signature_len =
        gov_sign.serializeSignature(&signature, &out.hw_signature);
    return signature_len == gov_sign.SIGNATURE_BLOB_BYTES;
}

/// Compatibility wrapper. Prefer buildHandshakeInto() in production callers.
pub fn buildHandshake() ?HandshakePayload {
    if (!buildHandshakeInto(&static_handshake)) return null;
    return static_handshake;
}

pub fn validateHandshake(payload: *const HandshakePayload) ValidationResult {
    if (!bytesEqual(&payload.magic, &MAGIC_BYTES)) return .InvalidMagic;
    if (payload.version != PROTOCOL_VERSION) return .UnsupportedVersion;
    if (constant_time.constantTimeIsZero32(&payload.challenge)) return .MissingChallenge;

    var public_key = gov_sign.PublicKey{};
    defer gov_sign.clearPublicKey(&public_key);
    if (!gov_sign.deserializePublicKey(&payload.public_key, &public_key)) {
        return .InvalidPublicKey;
    }

    var signature = gov_sign.Signature{};
    defer gov_sign.clearSignature(&signature);
    if (!gov_sign.deserializeSignature(&payload.hw_signature, &signature)) {
        return .SignatureMismatch;
    }

    const transcript_len = buildHandshakeTranscript(payload, &static_transcript);
    if (transcript_len == 0) return .SignatureMismatch;
    defer constant_time.secureZero(static_transcript[0..transcript_len]);

    if (!auth.verifyGovernancePayloadBool(
        &public_key,
        HANDSHAKE_DOMAIN,
        static_transcript[0..transcript_len],
        &signature,
    )) return .SignatureMismatch;

    return .Valid;
}

fn buildHandshakeTranscript(payload: *const HandshakePayload, out: []u8) usize {
    if (out.len < HANDSHAKE_TRANSCRIPT_SIZE) return 0;
    var pos: usize = 0;
    @memcpy(out[pos..][0..8], &payload.magic);
    pos += 8;
    writeU32(out[pos..], payload.version);
    pos += 4;
    out[pos] = payload.packet_type;
    pos += 1;
    writeU64(out[pos..], payload.timestamp);
    pos += 8;
    @memcpy(out[pos..][0..CHALLENGE_SIZE], &payload.challenge);
    pos += CHALLENGE_SIZE;

    var public_fingerprint: [32]u8 = [_]u8{0} ** 32;
    hash.sha256Into(&payload.public_key, &public_fingerprint);
    @memcpy(out[pos..][0..32], &public_fingerprint);
    pos += 32;
    constant_time.secureZero32(&public_fingerprint);

    @memcpy(out[pos..][0..32], &payload.hardware_hash);
    pos += 32;
    return pos;
}

pub fn handleMessage(p: *peer.Peer, msg: *const message.Message) void {
    const payload_len: usize = @intCast(msg.payload_len);
    if (payload_len > message.MAX_PAYLOAD_SIZE) return;
    const data = msg.payload[0..payload_len];

    switch (msg.msg_type) {
        .ping => handlePing(p),
        .pong => handlePong(p),
        .get_peers => handleGetPeers(p),
        .peers => handlePeers(p, data),
        .get_blocks => handleGetBlocks(p, data),
        .blocks => handleBlocks(p, data),
        .new_block => handleNewBlock(p, data),
        .new_transaction => handleNewTransaction(p, data),
        .identity_announce => handleIdentityAnnounce(p, data),
        .identity_query => handleIdentityQuery(p, data),
        .vote => handleVote(p, data),
        .proposal => handleProposal(p, data),
        .onion_routed => handleOnionRouted(p, data),
        .eviction_vote => handleEvictionVote(p, data),
        .eviction_commit => handleEvictionCommit(p, data),
        .eviction_notice => handleEvictionNotice(p, data),
        else => {},
    }
}

fn handlePing(p: *peer.Peer) void {
    peer.updateLastSeen(p);
    const p2p = @import("p2p.zig");
    _ = p2p.sendToPeer(p.id, .pong, &[_]u8{});
}
fn handlePong(p: *peer.Peer) void {
    peer.updateLastSeen(p);
    peer.increaseReputation(p, 1);
}
fn handleGetPeers(p: *peer.Peer) void {
    peer.updateLastSeen(p);
    var buffer: [4096]u8 = undefined;
    const len = discovery.encodePeerList(&buffer);
    const p2p = @import("p2p.zig");
    _ = p2p.sendToPeer(p.id, .peers, buffer[0..len]);
}
fn handlePeers(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    peer.increaseReputation(p, 2);
    discovery.handlePeerList(data);
}
fn handleGetBlocks(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len < 16) return;
    _ = readU64(data[0..8]);
    _ = readU64(data[8..16]);
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
    const p2p = @import("p2p.zig");
    p2p.broadcast(.new_block, data);
}
fn handleNewTransaction(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len == 0) {
        peer.decreaseReputation(p, 5);
        return;
    }
    peer.increaseReputation(p, 1);
    const p2p = @import("p2p.zig");
    p2p.broadcast(.new_transaction, data);
}
fn handleIdentityAnnounce(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len >= 64) serial.writeString("[PROTO] Identity announced\n");
}
fn handleIdentityQuery(p: *peer.Peer, data: []const u8) void {
    _ = data;
    peer.updateLastSeen(p);
    serial.writeString("[PROTO] Identity queried\n");
}
fn handleVote(p: *peer.Peer, data: []const u8) void {
    _ = data;
    peer.updateLastSeen(p);
    serial.writeString("[PROTO] Vote received\n");
}
fn handleProposal(p: *peer.Peer, data: []const u8) void {
    _ = data;
    peer.updateLastSeen(p);
    serial.writeString("[PROTO] Proposal received\n");
}
fn handleOnionRouted(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len == 0) {
        peer.decreaseReputation(p, 1);
        return;
    }
    peer.increaseReputation(p, 1);
}
fn handleEvictionVote(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len == 0) {
        peer.decreaseReputation(p, 2);
        return;
    }
    eviction.handleVoteMessage(p, data);
}
fn handleEvictionCommit(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len == 0) {
        peer.decreaseReputation(p, 2);
        return;
    }
    eviction.handleCommitMessage(p, data);
}
fn handleEvictionNotice(p: *peer.Peer, data: []const u8) void {
    peer.updateLastSeen(p);
    if (data.len == 0) {
        peer.decreaseReputation(p, 1);
        return;
    }
    peer.increaseReputation(p, 1);
}

pub fn encodeNodeInfo(info: *const NodeInfo, buffer: []u8) u32 {
    if (buffer.len < NODE_INFO_WIRE_SIZE) return 0;
    buffer[0] = info.version;
    buffer[1] = @intCast(info.port >> 8);
    buffer[2] = @intCast(info.port);
    @memcpy(buffer[3..][0..gov_sign.PUBLIC_KEY_BLOB_BYTES], &info.public_key);
    writeU32(buffer[3 + gov_sign.PUBLIC_KEY_BLOB_BYTES ..], info.capabilities);
    return @intCast(NODE_INFO_WIRE_SIZE);
}

pub const NODE_INFO_WIRE_SIZE: usize = 1 + 2 + gov_sign.PUBLIC_KEY_BLOB_BYTES + 4;

pub fn decodeNodeInfoInto(data: []const u8, out: *NodeInfo) bool {
    if (data.len < NODE_INFO_WIRE_SIZE) return false;
    out.version = data[0];
    out.port = (@as(u16, data[1]) << 8) | data[2];
    @memcpy(&out.public_key, data[3..][0..gov_sign.PUBLIC_KEY_BLOB_BYTES]);
    out.capabilities = readU32(data[3 + gov_sign.PUBLIC_KEY_BLOB_BYTES ..]);
    return true;
}

fn bytesEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}
fn readU32(data: []const u8) u32 {
    if (data.len < 4) return 0;

    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readU64(data: []const u8) u64 {
    if (data.len < 8) return 0;

    var value: u64 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        value = (value << 8) | @as(u64, data[i]);
    }
    return value;
}

fn writeU32(buffer: []u8, value: u32) void {
    if (buffer.len < 4) return;
    buffer[0] = @truncate(value >> 24);
    buffer[1] = @truncate(value >> 16);
    buffer[2] = @truncate(value >> 8);
    buffer[3] = @truncate(value);
}

fn writeU64(buffer: []u8, value: u64) void {
    if (buffer.len < 8) return;

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast((7 - i) * 8);
        buffer[i] = @truncate(value >> shift);
    }
}
