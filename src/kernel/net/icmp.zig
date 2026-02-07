//! Zamrud OS - ICMP Protocol
//! Internet Control Message Protocol (RFC 792)

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ip = @import("ip.zig");
const checksum = @import("checksum.zig");

// Hardware drivers for polling
const e1000 = @import("../drivers/network/e1000.zig");
const virtio_net = @import("../drivers/network/virtio_net.zig");

// =============================================================================
// Constants
// =============================================================================

const ICMP_HEADER_SIZE: usize = 8;
const PING_DATA_SIZE: usize = 56;
const MAX_ICMP_PACKET: usize = 1024;

// ICMP Types
pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_DEST_UNREACHABLE: u8 = 3;
pub const TYPE_SOURCE_QUENCH: u8 = 4;
pub const TYPE_REDIRECT: u8 = 5;
pub const TYPE_ECHO_REQUEST: u8 = 8;
pub const TYPE_TIME_EXCEEDED: u8 = 11;
pub const TYPE_PARAMETER_PROBLEM: u8 = 12;

// Destination Unreachable Codes
pub const CODE_NET_UNREACHABLE: u8 = 0;
pub const CODE_HOST_UNREACHABLE: u8 = 1;
pub const CODE_PROTOCOL_UNREACHABLE: u8 = 2;
pub const CODE_PORT_UNREACHABLE: u8 = 3;
pub const CODE_FRAGMENTATION_NEEDED: u8 = 4;
pub const CODE_SOURCE_ROUTE_FAILED: u8 = 5;

// Time Exceeded Codes
pub const CODE_TTL_EXCEEDED: u8 = 0;
pub const CODE_FRAGMENT_REASSEMBLY: u8 = 1;

// Ping timeout in polling iterations
const PING_TIMEOUT_ITERATIONS: u32 = 500;
const POLL_DELAY_CYCLES: u32 = 50000;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var echo_sequence: u16 = 0;
var echo_identifier: u16 = 0x1234;

// Statistics
var echo_requests_sent: u64 = 0;
var echo_replies_received: u64 = 0;
var echo_replies_sent: u64 = 0;
var errors_received: u64 = 0;
var checksum_errors: u64 = 0;

// Pending ping tracking
var pending_ping_id: u16 = 0;
var pending_ping_seq: u16 = 0;
var ping_pending: bool = false;
var ping_target_ip: u32 = 0;
var ping_reply_received: bool = false;
var last_ping_rtt: u32 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    echo_sequence = 0;
    echo_identifier = 0x1234;
    echo_requests_sent = 0;
    echo_replies_received = 0;
    echo_replies_sent = 0;
    errors_received = 0;
    checksum_errors = 0;
    ping_pending = false;
    ping_target_ip = 0;
    ping_reply_received = false;
    last_ping_rtt = 0;
    initialized = true;
    serial.writeString("[ICMP] ICMP initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Packet Handling
// =============================================================================

pub fn handlePacket(iface: *network.NetworkInterface, packet: *const ip.IpPacket) void {
    if (packet.payload.len < ICMP_HEADER_SIZE) {
        return;
    }

    const icmp_type = packet.payload[0];
    const icmp_code = packet.payload[1];
    const icmp_id = readU16BE(packet.payload[4..6]);
    const icmp_seq = readU16BE(packet.payload[6..8]);

    // Verify checksum
    if (!checksum.verify(packet.payload)) {
        checksum_errors += 1;
        serial.writeString("[ICMP] Checksum error\n");
        return;
    }

    switch (icmp_type) {
        TYPE_ECHO_REQUEST => {
            // Someone is pinging us - send reply
            sendEchoReply(
                iface,
                packet.header.src_ip,
                icmp_id,
                icmp_seq,
                packet.payload[ICMP_HEADER_SIZE..],
            );
        },
        TYPE_ECHO_REPLY => {
            // We received a ping reply
            echo_replies_received += 1;

            // Check if this matches our pending ping
            if (ping_pending and icmp_id == pending_ping_id) {
                ping_pending = false;
                ping_reply_received = true;
                serial.writeString("[ICMP] Reply from ");
                printIp(packet.header.src_ip);
                serial.writeString(" seq=");
                printU16(icmp_seq);
                serial.writeString("\n");
            } else {
                serial.writeString("[ICMP] Echo reply received (unexpected)\n");
            }
        },
        TYPE_DEST_UNREACHABLE => {
            errors_received += 1;
            ping_pending = false;
            serial.writeString("[ICMP] Destination unreachable (code ");
            printU8(icmp_code);
            serial.writeString(")\n");
        },
        TYPE_TIME_EXCEEDED => {
            errors_received += 1;
            ping_pending = false;
            serial.writeString("[ICMP] Time exceeded (TTL expired)\n");
        },
        TYPE_REDIRECT => {
            serial.writeString("[ICMP] Redirect received\n");
        },
        else => {
            // Unknown ICMP type
        },
    }
}

// =============================================================================
// Send Echo Reply (responding to ping)
// =============================================================================

fn sendEchoReply(
    iface: *network.NetworkInterface,
    dst_ip: u32,
    id: u16,
    seq: u16,
    data: []const u8,
) void {
    var icmp_packet: [MAX_ICMP_PACKET]u8 = undefined;
    const total_len = ICMP_HEADER_SIZE + data.len;

    if (total_len > icmp_packet.len) return;

    // Build ICMP Echo Reply header
    icmp_packet[0] = TYPE_ECHO_REPLY;
    icmp_packet[1] = 0; // Code = 0
    writeU16BE(icmp_packet[2..4], 0); // Checksum placeholder
    writeU16BE(icmp_packet[4..6], id); // Same ID as request
    writeU16BE(icmp_packet[6..8], seq); // Same sequence as request

    // Copy payload data (echo back the same data)
    @memcpy(icmp_packet[ICMP_HEADER_SIZE..][0..data.len], data);

    // Calculate and set checksum
    const cksum = checksum.calculate(icmp_packet[0..total_len]);
    writeU16BE(icmp_packet[2..4], cksum);

    // Send via IP layer
    if (ip.send(iface, dst_ip, ip.PROTO_ICMP, icmp_packet[0..total_len])) {
        echo_replies_sent += 1;
    }
}

// =============================================================================
// Send Echo Request (ping)
// =============================================================================

pub fn ping(iface: *network.NetworkInterface, dst_ip: u32) void {
    var icmp_packet: [ICMP_HEADER_SIZE + PING_DATA_SIZE]u8 = undefined;

    // Build ICMP Echo Request header
    icmp_packet[0] = TYPE_ECHO_REQUEST;
    icmp_packet[1] = 0; // Code = 0
    writeU16BE(icmp_packet[2..4], 0); // Checksum placeholder
    writeU16BE(icmp_packet[4..6], echo_identifier); // Identifier
    writeU16BE(icmp_packet[6..8], echo_sequence); // Sequence number

    // Track this ping
    pending_ping_id = echo_identifier;
    pending_ping_seq = echo_sequence;
    ping_pending = true;
    ping_reply_received = false;
    ping_target_ip = dst_ip;

    // Increment sequence for next ping
    echo_sequence +%= 1;

    // Fill payload with pattern (for debugging/verification)
    for (0..PING_DATA_SIZE) |i| {
        icmp_packet[ICMP_HEADER_SIZE + i] = @intCast((i + 0x10) & 0xFF);
    }

    // Calculate and set checksum
    const cksum = checksum.calculate(&icmp_packet);
    writeU16BE(icmp_packet[2..4], cksum);

    // Log the ping attempt
    serial.writeString("[ICMP] Ping ");
    printIp(dst_ip);
    serial.writeString(" seq=");
    printU16(pending_ping_seq);
    serial.writeString("\n");

    // Send via IP layer
    if (ip.send(iface, dst_ip, ip.PROTO_ICMP, &icmp_packet)) {
        echo_requests_sent += 1;
    } else {
        ping_pending = false;
        serial.writeString("[ICMP] Failed to send ping\n");
    }
}

/// Ping with active polling for reply - returns true if reply received
pub fn pingWithWait(iface: *network.NetworkInterface, dst_ip: u32) bool {
    // Reset reply flag
    ping_reply_received = false;

    // Send the ping
    ping(iface, dst_ip);

    // If send failed, return immediately
    if (!ping_pending) {
        return false;
    }

    // Poll for reply
    var iterations: u32 = 0;
    while (iterations < PING_TIMEOUT_ITERATIONS) : (iterations += 1) {
        // Poll hardware for received packets
        pollNetwork();

        // Check if reply was received
        if (ping_reply_received) {
            last_ping_rtt = iterations;
            return true;
        }

        // If ping is no longer pending (error received), stop
        if (!ping_pending) {
            return false;
        }

        // Small delay
        busyWait(POLL_DELAY_CYCLES);
    }

    // Timeout
    ping_pending = false;
    return false;
}

/// Poll network hardware for incoming packets
fn pollNetwork() void {
    if (e1000.isInitialized()) {
        e1000.poll();
    }
    if (virtio_net.isInitialized()) {
        virtio_net.poll();
    }
}

fn busyWait(cycles: u32) void {
    var i: u32 = 0;
    while (i < cycles) : (i += 1) {
        asm volatile ("pause");
    }
}

/// Ping with custom data size
pub fn pingWithSize(iface: *network.NetworkInterface, dst_ip: u32, data_size: usize) void {
    if (data_size > MAX_ICMP_PACKET - ICMP_HEADER_SIZE) {
        serial.writeString("[ICMP] Ping data too large\n");
        return;
    }

    var icmp_packet: [MAX_ICMP_PACKET]u8 = undefined;
    const total_len = ICMP_HEADER_SIZE + data_size;

    // Build header
    icmp_packet[0] = TYPE_ECHO_REQUEST;
    icmp_packet[1] = 0;
    writeU16BE(icmp_packet[2..4], 0);
    writeU16BE(icmp_packet[4..6], echo_identifier);
    writeU16BE(icmp_packet[6..8], echo_sequence);

    pending_ping_id = echo_identifier;
    pending_ping_seq = echo_sequence;
    ping_pending = true;
    ping_reply_received = false;
    ping_target_ip = dst_ip;
    echo_sequence +%= 1;

    // Fill payload
    for (0..data_size) |i| {
        icmp_packet[ICMP_HEADER_SIZE + i] = @intCast((i + 0x10) & 0xFF);
    }

    // Checksum
    const cksum = checksum.calculate(icmp_packet[0..total_len]);
    writeU16BE(icmp_packet[2..4], cksum);

    if (ip.send(iface, dst_ip, ip.PROTO_ICMP, icmp_packet[0..total_len])) {
        echo_requests_sent += 1;
    } else {
        ping_pending = false;
    }
}

// =============================================================================
// Send Error Messages
// =============================================================================

/// Send Destination Unreachable message
pub fn sendDestUnreachable(
    iface: *network.NetworkInterface,
    dst_ip: u32,
    code: u8,
    original_packet: []const u8,
) void {
    var icmp_packet: [MAX_ICMP_PACKET]u8 = undefined;

    // Include IP header + 8 bytes of original datagram
    const orig_len = @min(original_packet.len, 28); // IP header (20) + 8 bytes
    const total_len = ICMP_HEADER_SIZE + orig_len;

    icmp_packet[0] = TYPE_DEST_UNREACHABLE;
    icmp_packet[1] = code;
    writeU16BE(icmp_packet[2..4], 0); // Checksum placeholder
    writeU32BE(icmp_packet[4..8], 0); // Unused (must be zero)

    // Copy original packet data
    @memcpy(icmp_packet[ICMP_HEADER_SIZE..][0..orig_len], original_packet[0..orig_len]);

    // Checksum
    const cksum = checksum.calculate(icmp_packet[0..total_len]);
    writeU16BE(icmp_packet[2..4], cksum);

    _ = ip.send(iface, dst_ip, ip.PROTO_ICMP, icmp_packet[0..total_len]);
}

/// Send Time Exceeded message
pub fn sendTimeExceeded(
    iface: *network.NetworkInterface,
    dst_ip: u32,
    code: u8,
    original_packet: []const u8,
) void {
    var icmp_packet: [MAX_ICMP_PACKET]u8 = undefined;

    const orig_len = @min(original_packet.len, 28);
    const total_len = ICMP_HEADER_SIZE + orig_len;

    icmp_packet[0] = TYPE_TIME_EXCEEDED;
    icmp_packet[1] = code;
    writeU16BE(icmp_packet[2..4], 0);
    writeU32BE(icmp_packet[4..8], 0);

    @memcpy(icmp_packet[ICMP_HEADER_SIZE..][0..orig_len], original_packet[0..orig_len]);

    const cksum = checksum.calculate(icmp_packet[0..total_len]);
    writeU16BE(icmp_packet[2..4], cksum);

    _ = ip.send(iface, dst_ip, ip.PROTO_ICMP, icmp_packet[0..total_len]);
}

// =============================================================================
// Status & Statistics
// =============================================================================

pub fn isPingPending() bool {
    return ping_pending;
}

pub fn wasPingSuccessful() bool {
    return ping_reply_received;
}

pub fn getLastRtt() u32 {
    return last_ping_rtt;
}

pub fn cancelPing() void {
    ping_pending = false;
}

pub fn getPendingPingTarget() u32 {
    return ping_target_ip;
}

pub fn getStats() struct { sent: u64, received: u64 } {
    return .{
        .sent = echo_requests_sent,
        .received = echo_replies_received,
    };
}

pub fn getDetailedStats() struct { sent: u64, received: u64, replied: u64, errors: u64, checksum_errors: u64 } {
    return .{
        .sent = echo_requests_sent,
        .received = echo_replies_received,
        .replied = echo_replies_sent,
        .errors = errors_received,
        .checksum_errors = checksum_errors,
    };
}

pub fn resetStats() void {
    echo_requests_sent = 0;
    echo_replies_received = 0;
    echo_replies_sent = 0;
    errors_received = 0;
    checksum_errors = 0;
}

// =============================================================================
// Utility Functions
// =============================================================================

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn writeU16BE(data: []u8, val: u16) void {
    data[0] = @intCast((val >> 8) & 0xFF);
    data[1] = @intCast(val & 0xFF);
}

fn writeU32BE(data: []u8, val: u32) void {
    data[0] = @intCast((val >> 24) & 0xFF);
    data[1] = @intCast((val >> 16) & 0xFF);
    data[2] = @intCast((val >> 8) & 0xFF);
    data[3] = @intCast(val & 0xFF);
}

fn printIp(addr: u32) void {
    printU8(@intCast((addr >> 24) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast((addr >> 16) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast((addr >> 8) & 0xFF));
    serial.writeChar('.');
    printU8(@intCast(addr & 0xFF));
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printU16(val: u16) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [5]u8 = undefined;
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
