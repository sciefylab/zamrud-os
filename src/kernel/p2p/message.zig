//! Zamrud OS - P2P Message Protocol
//! Message encoding, decoding, signing
//! P.3d: Multi-Layer Onion Wrapping (OTP & SLOR Integration)
//! P.3e: Twin-Node Eviction Message Types
//! GOV.2a: Message identity binding helpers

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");
const constant_time = @import("../crypto/constant_time.zig");

// =============================================================================
// Constants
// =============================================================================

// REDUCED from 65000 to 4096 to prevent stack overflow
pub const MAX_PAYLOAD_SIZE: usize = 4096;
pub const HEADER_SIZE: usize = 128;
pub const SIGNATURE_SIZE: usize = 64;
pub const MAGIC: u32 = 0x5A414D52; // "ZAMR"

// Canonical signing buffer:
// type(1) + sender(32) + timestamp(8) + payload_len(4) + payload(4096)
pub const MAX_SIGNING_INPUT_SIZE: usize = 1 + 32 + 8 + 4 + MAX_PAYLOAD_SIZE;

// =============================================================================
// Types
// =============================================================================

pub const MessageType = enum(u8) {
    // Handshake
    handshake = 0x01,
    handshake_ack = 0x02,

    // Onion Routing (P.3d)
    onion_routed = 0x06,

    // Keepalive
    ping = 0x10,
    pong = 0x11,

    // Peer discovery
    get_peers = 0x20,
    peers = 0x21,

    // Blockchain
    get_blocks = 0x30,
    blocks = 0x31,
    new_block = 0x32,

    // Transactions
    new_transaction = 0x40,
    get_transactions = 0x41,
    transactions = 0x42,

    // Identity
    identity_announce = 0x50,
    identity_query = 0x51,
    identity_response = 0x52,

    // Consensus
    vote = 0x60,
    proposal = 0x61,
    commit = 0x62,

    // P.3e: Twin-Node Eviction / Network Kill-Switch
    eviction_vote = 0x70,
    eviction_commit = 0x71,
    eviction_notice = 0x72,

    // Error
    error_msg = 0xFF,

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .handshake => "HANDSHAKE",
            .handshake_ack => "HANDSHAKE_ACK",

            .onion_routed => "ONION_ROUTED",

            .ping => "PING",
            .pong => "PONG",

            .get_peers => "GET_PEERS",
            .peers => "PEERS",

            .get_blocks => "GET_BLOCKS",
            .blocks => "BLOCKS",
            .new_block => "NEW_BLOCK",

            .new_transaction => "NEW_TX",
            .get_transactions => "GET_TXS",
            .transactions => "TXS",

            .identity_announce => "ID_ANNOUNCE",
            .identity_query => "ID_QUERY",
            .identity_response => "ID_RESPONSE",

            .vote => "VOTE",
            .proposal => "PROPOSAL",
            .commit => "COMMIT",

            .eviction_vote => "EVICTION_VOTE",
            .eviction_commit => "EVICTION_COMMIT",
            .eviction_notice => "EVICTION_NOTICE",

            .error_msg => "ERROR",
        };
    }
};

pub const Message = struct {
    msg_type: MessageType,
    sender_id: [32]u8,
    timestamp: u64,
    payload: [MAX_PAYLOAD_SIZE]u8,
    payload_len: u32,
    signature: [SIGNATURE_SIZE]u8,
};

// =============================================================================
// Static Buffers
// =============================================================================

var static_signing_input: [MAX_SIGNING_INPUT_SIZE]u8 = undefined;
var static_encode_buffer: [HEADER_SIZE + MAX_PAYLOAD_SIZE + SIGNATURE_SIZE]u8 = undefined;
var static_test_msg: Message = undefined;
var static_test_buffer: [512]u8 = undefined;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var messages_encoded: u64 = 0;
var messages_decoded: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    messages_encoded = 0;
    messages_decoded = 0;
    initialized = true;
    serial.writeString("[MSG] Message protocol initialized (P.3d Onion + P.3e Eviction + GOV.2a Ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Encoding
// =============================================================================

/// Encode message to wire format.
/// Format:
/// [MAGIC:4][TYPE:1][SENDER:32][TIMESTAMP:8][LEN:4][PAYLOAD:N][SIG:64]
pub fn encode(msg: *const Message, buffer: []u8) usize {
    var pos: usize = 0;

    const payload_len: usize = @intCast(msg.payload_len);

    if (payload_len > MAX_PAYLOAD_SIZE) {
        return 0;
    }

    const needed = 4 + 1 + 32 + 8 + 4 + payload_len + SIGNATURE_SIZE;
    if (buffer.len < needed) {
        return 0;
    }

    writeU32(buffer[pos..], MAGIC);
    pos += 4;

    buffer[pos] = @intFromEnum(msg.msg_type);
    pos += 1;

    @memcpy(buffer[pos..][0..32], &msg.sender_id);
    pos += 32;

    writeU64(buffer[pos..], msg.timestamp);
    pos += 8;

    writeU32(buffer[pos..], msg.payload_len);
    pos += 4;

    if (payload_len > 0) {
        @memcpy(buffer[pos..][0..payload_len], msg.payload[0..payload_len]);
        pos += payload_len;
    }

    @memcpy(buffer[pos..][0..SIGNATURE_SIZE], &msg.signature);
    pos += SIGNATURE_SIZE;

    messages_encoded += 1;
    return pos;
}

// =============================================================================
// Decoding
// =============================================================================

pub fn decode(data: []const u8) ?Message {
    if (data.len < 49 + SIGNATURE_SIZE) return null;

    var pos: usize = 0;

    const magic = readU32(data[pos..]);
    if (magic != MAGIC) return null;
    pos += 4;

    const msg_type_byte = data[pos];
    const msg_type: MessageType = @enumFromInt(msg_type_byte);
    pos += 1;

    var sender_id: [32]u8 = undefined;
    @memcpy(&sender_id, data[pos..][0..32]);
    pos += 32;

    const timestamp = readU64(data[pos..]);
    pos += 8;

    const payload_len = readU32(data[pos..]);
    pos += 4;

    if (payload_len > MAX_PAYLOAD_SIZE) return null;

    const plen: usize = @intCast(payload_len);

    if (pos + plen + SIGNATURE_SIZE > data.len) {
        return null;
    }

    var payload: [MAX_PAYLOAD_SIZE]u8 = [_]u8{0} ** MAX_PAYLOAD_SIZE;

    if (plen > 0) {
        @memcpy(payload[0..plen], data[pos..][0..plen]);
    }

    pos += plen;

    var signature: [SIGNATURE_SIZE]u8 = undefined;
    @memcpy(&signature, data[pos..][0..SIGNATURE_SIZE]);

    messages_decoded += 1;

    return .{
        .msg_type = msg_type,
        .sender_id = sender_id,
        .timestamp = timestamp,
        .payload = payload,
        .payload_len = payload_len,
        .signature = signature,
    };
}

// =============================================================================
// P.3d: Onion Wrapping
// =============================================================================

/// Encrypts the payload of a message in-place using OTP stream initialized by
/// SLOR shared secret. This wraps one onion layer.
pub fn encryptPayloadOtp(msg: *Message, shared_secret: *const [32]u8) void {
    if (msg.payload_len == 0) return;
    if (msg.payload_len > MAX_PAYLOAD_SIZE) return;

    var stream = crypto.OtpStream.init(shared_secret);

    const p_len: usize = @intCast(msg.payload_len);
    stream.process(msg.payload[0..p_len]);

    stream.destroy();
}

/// Decrypts the payload of an onion message in-place.
/// OTP XOR is symmetric.
pub fn decryptPayloadOtp(msg: *Message, shared_secret: *const [32]u8) void {
    encryptPayloadOtp(msg, shared_secret);
}

// =============================================================================
// GOV.2a Signing & Verification Helpers
// =============================================================================

/// Canonical bytes used for P2P message signing.
///
/// Domain is implicit by message type.
/// For GOV.2 final payload signatures, eviction.zig will add explicit
/// domain-separated SLOR governance payloads.
fn buildSigningInput(msg: *const Message, out: []u8) usize {
    const plen: usize = @intCast(msg.payload_len);

    if (plen > MAX_PAYLOAD_SIZE) return 0;
    if (out.len < 1 + 32 + 8 + 4 + plen) return 0;

    var pos: usize = 0;

    out[pos] = @intFromEnum(msg.msg_type);
    pos += 1;

    @memcpy(out[pos..][0..32], &msg.sender_id);
    pos += 32;

    writeU64(out[pos..], msg.timestamp);
    pos += 8;

    writeU32(out[pos..], msg.payload_len);
    pos += 4;

    if (plen > 0) {
        @memcpy(out[pos..][0..plen], msg.payload[0..plen]);
        pos += plen;
    }

    return pos;
}

pub fn isZeroSignature(sig: *const [SIGNATURE_SIZE]u8) bool {
    return constant_time.constantTimeIsZero64(sig);
}

pub fn deriveNodeIdFromPublicKey(public_key: *const [32]u8, out_node_id: *[32]u8) void {
    hash.sha256Into(public_key, out_node_id);
}

pub fn senderMatchesPublicKey(msg: *const Message, public_key: *const [32]u8) bool {
    var expected: [32]u8 = [_]u8{0} ** 32;
    deriveNodeIdFromPublicKey(public_key, &expected);

    const ok = constant_time.constantTimeCompare32(&expected, &msg.sender_id);

    constant_time.secureZero32(&expected);

    return ok;
}

/// Sign message envelope.
///
/// Existing P2P code passes the local 32-byte node private key.
/// This keeps compatibility. GOV.2 final authority-grade signing is done with
/// SLOR governance payload signature in eviction.zig.
pub fn sign(msg: *Message, private_key: *const [32]u8) void {
    const len = buildSigningInput(msg, &static_signing_input);
    if (len == 0) {
        msg.signature = [_]u8{0} ** SIGNATURE_SIZE;
        return;
    }

    const sig = crypto.signMessage(static_signing_input[0..len], private_key[0..]);
    @memcpy(&msg.signature, &sig);

    constant_time.secureZero(static_signing_input[0..len]);
}

/// Legacy verify path.
/// Kept for compatibility with p2p.zig until peer public-key verification is
/// fully routed through all inbound paths.
///
/// For production-grade peer verification use verifyWithPublicKey().
pub fn verify(msg: *const Message) bool {
    if (isZeroSignature(&msg.signature)) return false;

    const len = buildSigningInput(msg, &static_signing_input);
    if (len == 0) return false;

    // Legacy behavior: sender_id is used as verifier key material.
    // This is not public-verifiable identity proof.
    // It remains as compatibility plumbing until p2p.zig is moved fully to
    // verifyWithPublicKey(peer.public_key).
    const ok = crypto.verifySignature(
        static_signing_input[0..len],
        msg.signature[0..],
        msg.sender_id[0..],
    );

    constant_time.secureZero(static_signing_input[0..len]);

    return ok;
}

/// GOV.2a public-key-bound verification.
///
/// This performs:
/// 1. non-zero signature check
/// 2. sender_id == sha256(public_key)
/// 3. signature verification using the supplied public key
///
/// Note:
/// Current crypto.verifySignature() is still limited by the existing HMAC-style
/// signature layer. The production-grade anti-forgery final layer will be the
/// SLOR governance payload signature in eviction.zig.
pub fn verifyWithPublicKey(msg: *const Message, public_key: *const [32]u8) bool {
    if (isZeroSignature(&msg.signature)) return false;

    if (!senderMatchesPublicKey(msg, public_key)) {
        return false;
    }

    const len = buildSigningInput(msg, &static_signing_input);
    if (len == 0) return false;

    const ok = crypto.verifySignature(
        static_signing_input[0..len],
        msg.signature[0..],
        public_key[0..],
    );

    constant_time.secureZero(static_signing_input[0..len]);

    return ok;
}

// =============================================================================
// Helper Builders
// =============================================================================

pub fn createEmpty(
    node_id: [32]u8,
    msg_type: MessageType,
) Message {
    return .{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** MAX_PAYLOAD_SIZE,
        .payload_len = 0,
        .signature = [_]u8{0} ** SIGNATURE_SIZE,
    };
}

pub fn createWithPayload(
    node_id: [32]u8,
    msg_type: MessageType,
    raw_payload: []const u8,
) Message {
    var msg = Message{
        .msg_type = msg_type,
        .sender_id = node_id,
        .timestamp = getTimestamp(),
        .payload = [_]u8{0} ** MAX_PAYLOAD_SIZE,
        .payload_len = 0,
        .signature = [_]u8{0} ** SIGNATURE_SIZE,
    };

    const copy_len = @min(raw_payload.len, MAX_PAYLOAD_SIZE);

    if (copy_len > 0) {
        @memcpy(msg.payload[0..copy_len], raw_payload[0..copy_len]);
    }

    msg.payload_len = @intCast(copy_len);

    return msg;
}

pub fn createPing(node_id: [32]u8) Message {
    return createEmpty(node_id, .ping);
}

pub fn createPong(node_id: [32]u8) Message {
    return createEmpty(node_id, .pong);
}

pub fn createGetPeers(node_id: [32]u8) Message {
    return createEmpty(node_id, .get_peers);
}

// =============================================================================
// P.3d Onion Builder
// =============================================================================

pub fn createOnionRouted(node_id: [32]u8, raw_payload: []const u8) Message {
    return createWithPayload(node_id, .onion_routed, raw_payload);
}

// =============================================================================
// P.3e Eviction Builders
// =============================================================================

pub fn createEvictionVote(node_id: [32]u8, raw_payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_vote, raw_payload);
}

pub fn createEvictionCommit(node_id: [32]u8, raw_payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_commit, raw_payload);
}

pub fn createEvictionNotice(node_id: [32]u8, raw_payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_notice, raw_payload);
}

// =============================================================================
// Stats
// =============================================================================

pub fn getEncodedCount() u64 {
    return messages_encoded;
}

pub fn getDecodedCount() u64 {
    return messages_decoded;
}

// =============================================================================
// Test Functions
// =============================================================================

pub fn runTests() bool {
    serial.writeString("  Running message tests...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("    Create message........... ");
    static_test_msg = createPing([_]u8{0x42} ** 32);

    if (static_test_msg.msg_type == .ping) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Encode message........... ");
    const encoded_len = encode(&static_test_msg, &static_test_buffer);

    if (encoded_len > 0 and encoded_len < 512) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Decode message........... ");

    if (decode(static_test_buffer[0..encoded_len])) |decoded| {
        if (decoded.msg_type == .ping) {
            serial.writeString("[OK]\n");
            passed += 1;
        } else {
            serial.writeString("[FAIL]\n");
            failed += 1;
        }
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Magic validation......... ");
    var bad_buffer: [64]u8 = [_]u8{0} ** 64;

    if (decode(&bad_buffer) == null) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Eviction vote type....... ");
    var ev_payload: [16]u8 = [_]u8{0xEE} ** 16;
    const ev_msg = createEvictionVote([_]u8{0x11} ** 32, &ev_payload);

    if (ev_msg.msg_type == .eviction_vote and ev_msg.payload_len == 16) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Onion routed type........ ");
    var onion_payload: [8]u8 = [_]u8{0xAA} ** 8;
    const onion_msg = createOnionRouted([_]u8{0x22} ** 32, &onion_payload);

    if (onion_msg.msg_type == .onion_routed and onion_msg.payload_len == 8) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Signature zero check..... ");
    if (isZeroSignature(&static_test_msg.signature)) {
        serial.writeString("[OK]\n");
        passed += 1;
    } else {
        serial.writeString("[FAIL]\n");
        failed += 1;
    }

    serial.writeString("    Public key binding....... ");
    {
        var pubkey: [32]u8 = [_]u8{0xAB} ** 32;
        var expected_id: [32]u8 = undefined;

        deriveNodeIdFromPublicKey(&pubkey, &expected_id);

        var msg = createPing(expected_id);

        if (senderMatchesPublicKey(&msg, &pubkey)) {
            serial.writeString("[OK]\n");
            passed += 1;
        } else {
            serial.writeString("[FAIL]\n");
            failed += 1;
        }
    }

    serial.writeString("    Message tests: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");

    return failed == 0;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn writeU32(buf: []u8, val: u32) void {
    buf[0] = @intCast((val >> 24) & 0xFF);
    buf[1] = @intCast((val >> 16) & 0xFF);
    buf[2] = @intCast((val >> 8) & 0xFF);
    buf[3] = @intCast(val & 0xFF);
}

fn writeU64(buf: []u8, val: u64) void {
    buf[0] = @intCast((val >> 56) & 0xFF);
    buf[1] = @intCast((val >> 48) & 0xFF);
    buf[2] = @intCast((val >> 40) & 0xFF);
    buf[3] = @intCast((val >> 32) & 0xFF);
    buf[4] = @intCast((val >> 24) & 0xFF);
    buf[5] = @intCast((val >> 16) & 0xFF);
    buf[6] = @intCast((val >> 8) & 0xFF);
    buf[7] = @intCast(val & 0xFF);
}

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
