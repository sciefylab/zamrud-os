//! Zamrud OS - P2P Message Protocol V2
//! ML-DSA-65 message authentication through gov_sign.zig/auth.zig.
//! Legacy 32-byte/64-byte HMAC signatures are not accepted.

const serial = @import("../drivers/serial/serial.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");
const constant_time = @import("../crypto/constant_time.zig");
const gov_sign = @import("../crypto/gov_sign.zig");
const auth = @import("../identity/auth.zig");

pub const MAX_PAYLOAD_SIZE: usize = 4096;
pub const SIGNATURE_SIZE: usize = gov_sign.SIGNATURE_BLOB_BYTES;
pub const HEADER_SIZE: usize = 4 + 1 + 32 + 8 + 4;
pub const MAGIC: u32 = 0x5A414D52;
pub const WIRE_VERSION: u8 = 2;
pub const SIGNING_DOMAIN = "ZAMRUD:P2P:MESSAGE:V2";

pub const MAX_SIGNING_INPUT_SIZE: usize =
    1 + 1 + 32 + 8 + 4 + MAX_PAYLOAD_SIZE;
pub const MAX_WIRE_SIZE: usize =
    HEADER_SIZE + MAX_PAYLOAD_SIZE + SIGNATURE_SIZE;

pub const MessageType = enum(u8) {
    handshake = 0x01,
    handshake_ack = 0x02,
    onion_routed = 0x06,
    ping = 0x10,
    pong = 0x11,
    get_peers = 0x20,
    peers = 0x21,
    get_blocks = 0x30,
    blocks = 0x31,
    new_block = 0x32,
    new_transaction = 0x40,
    get_transactions = 0x41,
    transactions = 0x42,
    identity_announce = 0x50,
    identity_query = 0x51,
    identity_response = 0x52,
    vote = 0x60,
    proposal = 0x61,
    commit = 0x62,
    eviction_vote = 0x70,
    eviction_commit = 0x71,
    eviction_notice = 0x72,
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

var static_signing_input: [MAX_SIGNING_INPUT_SIZE]u8 =
    [_]u8{0} ** MAX_SIGNING_INPUT_SIZE;
var static_decode_message: Message = undefined;
var static_test_message: Message = undefined;
var static_test_buffer: [MAX_WIRE_SIZE]u8 = undefined;

var initialized: bool = false;
var messages_encoded: u64 = 0;
var messages_decoded: u64 = 0;

pub fn init() void {
    messages_encoded = 0;
    messages_decoded = 0;
    initialized = true;
    serial.writeString("[MSG] Protocol V2 initialized (ML-DSA-65 fail-closed)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn encode(msg: *const Message, buffer: []u8) usize {
    const payload_len: usize = @intCast(msg.payload_len);
    if (payload_len > MAX_PAYLOAD_SIZE) return 0;

    const needed = HEADER_SIZE + payload_len + SIGNATURE_SIZE;
    if (buffer.len < needed) return 0;

    var pos: usize = 0;
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

/// Stack-safe decoder. Callers provide storage for the large V2 message.
pub fn decodeInto(data: []const u8, out: *Message) bool {
    if (data.len < HEADER_SIZE + SIGNATURE_SIZE) return false;

    var pos: usize = 0;
    if (readU32(data[pos..]) != MAGIC) return false;
    pos += 4;

    const type_byte = data[pos];
    out.msg_type = messageTypeFromByte(type_byte) orelse return false;
    pos += 1;

    @memcpy(&out.sender_id, data[pos..][0..32]);
    pos += 32;
    out.timestamp = readU64(data[pos..]);
    pos += 8;
    out.payload_len = readU32(data[pos..]);
    pos += 4;

    const payload_len: usize = @intCast(out.payload_len);
    if (payload_len > MAX_PAYLOAD_SIZE) return false;
    if (payload_len > data.len - pos) return false;
    if (SIGNATURE_SIZE > data.len - pos - payload_len) return false;

    @memset(out.payload[0..], 0);
    if (payload_len > 0) {
        @memcpy(out.payload[0..payload_len], data[pos..][0..payload_len]);
        pos += payload_len;
    }
    @memcpy(&out.signature, data[pos..][0..SIGNATURE_SIZE]);

    messages_decoded += 1;
    return true;
}

/// Compatibility wrapper. New production callers should use decodeInto().
pub fn decode(data: []const u8) ?Message {
    if (!decodeInto(data, &static_decode_message)) return null;
    return static_decode_message;
}

pub fn encryptPayloadOtp(msg: *Message, shared_secret: *const [32]u8) void {
    if (msg.payload_len == 0 or msg.payload_len > MAX_PAYLOAD_SIZE) return;
    var stream = crypto.OtpStream.init(shared_secret);
    const length: usize = @intCast(msg.payload_len);
    stream.process(msg.payload[0..length]);
    stream.destroy();
}

pub fn decryptPayloadOtp(msg: *Message, shared_secret: *const [32]u8) void {
    encryptPayloadOtp(msg, shared_secret);
}

fn buildSigningInput(msg: *const Message, out: []u8) usize {
    const payload_len: usize = @intCast(msg.payload_len);
    if (payload_len > MAX_PAYLOAD_SIZE) return 0;
    const needed = 1 + 1 + 32 + 8 + 4 + payload_len;
    if (out.len < needed) return 0;

    var pos: usize = 0;
    out[pos] = WIRE_VERSION;
    pos += 1;
    out[pos] = @intFromEnum(msg.msg_type);
    pos += 1;
    @memcpy(out[pos..][0..32], &msg.sender_id);
    pos += 32;
    writeU64(out[pos..], msg.timestamp);
    pos += 8;
    writeU32(out[pos..], msg.payload_len);
    pos += 4;
    if (payload_len > 0) {
        @memcpy(out[pos..][0..payload_len], msg.payload[0..payload_len]);
        pos += payload_len;
    }
    return pos;
}

pub fn isZeroSignature(sig: *const [SIGNATURE_SIZE]u8) bool {
    var difference: u8 = 0;
    for (sig) |byte| difference |= byte;
    return difference == 0;
}

pub fn deriveNodeIdFromPublicKey(
    public_key: *const gov_sign.PublicKey,
    out_node_id: *[32]u8,
) bool {
    var serialized: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8 =
        [_]u8{0} ** gov_sign.PUBLIC_KEY_BLOB_BYTES;
    defer constant_time.secureZero(&serialized);

    if (gov_sign.serializePublicKey(public_key, &serialized) !=
        gov_sign.PUBLIC_KEY_BLOB_BYTES) return false;
    hash.sha256Into(&serialized, out_node_id);
    return true;
}

pub fn senderMatchesPublicKey(
    msg: *const Message,
    public_key: *const gov_sign.PublicKey,
) bool {
    var expected: [32]u8 = [_]u8{0} ** 32;
    defer constant_time.secureZero32(&expected);
    if (!deriveNodeIdFromPublicKey(public_key, &expected)) return false;
    return constant_time.constantTimeCompare32(&expected, &msg.sender_id);
}

/// Sign with the currently unlocked identity governance key.
pub fn signWithSession(msg: *Message) bool {
    @memset(msg.signature[0..], 0);
    if (!auth.isGovernanceSigningAvailable()) return false;

    const length = buildSigningInput(msg, &static_signing_input);
    if (length == 0) return false;
    defer constant_time.secureZero(static_signing_input[0..length]);

    var signature = gov_sign.Signature{};
    defer gov_sign.clearSignature(&signature);

    if (!auth.signGovernancePayload(
        SIGNING_DOMAIN,
        static_signing_input[0..length],
        &signature,
    )) return false;

    const serialized_len =
        gov_sign.serializeSignature(&signature, &msg.signature);
    return serialized_len == SIGNATURE_SIZE;
}

/// Verify against a supplied ML-DSA public key and sender fingerprint.
pub fn verifyWithPublicKey(
    msg: *const Message,
    public_key: *const gov_sign.PublicKey,
) bool {
    if (isZeroSignature(&msg.signature)) return false;
    if (!senderMatchesPublicKey(msg, public_key)) return false;

    const length = buildSigningInput(msg, &static_signing_input);
    if (length == 0) return false;
    defer constant_time.secureZero(static_signing_input[0..length]);

    var signature = gov_sign.Signature{};
    defer gov_sign.clearSignature(&signature);
    if (!gov_sign.deserializeSignature(&msg.signature, &signature)) return false;

    return auth.verifyGovernancePayloadBool(
        public_key,
        SIGNING_DOMAIN,
        static_signing_input[0..length],
        &signature,
    );
}

/// Legacy API intentionally fails closed. A 32-byte sender ID is a fingerprint,
/// not an ML-DSA public key.
pub fn verify(_: *const Message) bool {
    return false;
}

/// Compatibility API: the legacy private-key argument is ignored. Signing is
/// allowed only through the unlocked identity session.
pub fn sign(msg: *Message, private_key: *const [32]u8) void {
    _ = private_key;
    _ = signWithSession(msg);
}

pub fn createEmpty(node_id: [32]u8, msg_type: MessageType) Message {
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
    var msg = createEmpty(node_id, msg_type);
    const copy_len = @min(raw_payload.len, MAX_PAYLOAD_SIZE);
    if (copy_len > 0) @memcpy(msg.payload[0..copy_len], raw_payload[0..copy_len]);
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
pub fn createOnionRouted(node_id: [32]u8, payload: []const u8) Message {
    return createWithPayload(node_id, .onion_routed, payload);
}
pub fn createEvictionVote(node_id: [32]u8, payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_vote, payload);
}
pub fn createEvictionCommit(node_id: [32]u8, payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_commit, payload);
}
pub fn createEvictionNotice(node_id: [32]u8, payload: []const u8) Message {
    return createWithPayload(node_id, .eviction_notice, payload);
}

pub fn getEncodedCount() u64 {
    return messages_encoded;
}
pub fn getDecodedCount() u64 {
    return messages_decoded;
}

pub fn runTests() bool {
    serial.writeString("  Running P2P message V2 tests...\n");
    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("    [1] Create message............ ");
    static_test_message = createPing([_]u8{0x42} ** 32);
    if (static_test_message.msg_type == .ping and
        isZeroSignature(&static_test_message.signature))
    {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    [2] Encode message............ ");
    const encoded_len = encode(&static_test_message, &static_test_buffer);
    if (encoded_len > 0 and encoded_len <= static_test_buffer.len) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    [3] Decode message............ ");
    if (encoded_len > 0 and
        decodeInto(
            static_test_buffer[0..encoded_len],
            &static_decode_message,
        ) and
        static_decode_message.msg_type == .ping)
    {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    [4] Reject malformed.......... ");
    var bad: [64]u8 = [_]u8{0} ** 64;
    if (!decodeInto(&bad, &static_decode_message)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    [5] Legacy verify fail-closed. ");
    if (!verify(&static_test_message)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("    Message V2 tests: ");
    printU32(passed);
    serial.writeString(" passed, ");
    printU32(failed);
    serial.writeString(" failed\n");
    return failed == 0;
}

fn messageTypeFromByte(value: u8) ?MessageType {
    return switch (value) {
        0x01 => .handshake,
        0x02 => .handshake_ack,
        0x06 => .onion_routed,
        0x10 => .ping,
        0x11 => .pong,
        0x20 => .get_peers,
        0x21 => .peers,
        0x30 => .get_blocks,
        0x31 => .blocks,
        0x32 => .new_block,
        0x40 => .new_transaction,
        0x41 => .get_transactions,
        0x42 => .transactions,
        0x50 => .identity_announce,
        0x51 => .identity_query,
        0x52 => .identity_response,
        0x60 => .vote,
        0x61 => .proposal,
        0x62 => .commit,
        0x70 => .eviction_vote,
        0x71 => .eviction_commit,
        0x72 => .eviction_notice,
        0xFF => .error_msg,
        else => null,
    };
}

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
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

fn printU32(value: u32) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }

    var buffer: [10]u8 = [_]u8{0} ** 10;
    var index: usize = 0;
    var remaining = value;

    while (remaining > 0 and index < buffer.len) : (index += 1) {
        const digit: u8 = @intCast(remaining % 10);
        buffer[index] = digit + '0';
        remaining /= 10;
    }

    while (index > 0) {
        index -= 1;
        serial.writeChar(buffer[index]);
    }
}
