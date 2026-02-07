//! Zamrud OS - IPv4 Protocol with Firewall Integration
//! Internet Protocol version 4 (RFC 791) + Firewall

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ethernet = @import("../drivers/network/ethernet.zig");
const arp = @import("arp.zig");
const icmp = @import("icmp.zig");
const udp = @import("udp.zig");
const tcp = @import("tcp.zig");
const checksum = @import("checksum.zig");

// Security imports
const firewall = @import("firewall.zig");

// =============================================================================
// Constants
// =============================================================================

pub const HEADER_SIZE: usize = 20;
pub const MAX_PACKET_SIZE: usize = 65535;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FLAG_DF: u16 = 0x4000; // Don't Fragment
pub const FLAG_MF: u16 = 0x2000; // More Fragments

// =============================================================================
// Types
// =============================================================================

pub const IpHeader = struct {
    version: u4,
    ihl: u4,
    tos: u8,
    total_len: u16,
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_ip: u32,
    dst_ip: u32,

    pub fn headerLength(self: *const IpHeader) usize {
        return @as(usize, self.ihl) * 4;
    }

    pub fn payloadLength(self: *const IpHeader) usize {
        const hdr_len = self.headerLength();
        if (self.total_len < hdr_len) return 0;
        return self.total_len - hdr_len;
    }
};

pub const IpPacket = struct {
    header: IpHeader,
    payload: []const u8,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var packet_id: u16 = 0;

// Statistics
var packets_sent: u64 = 0;
var packets_received: u64 = 0;
var packets_dropped: u64 = 0;

// Security statistics
var firewall_blocked: u64 = 0;
var firewall_allowed: u64 = 0;

// Firewall enabled flag
var firewall_enabled: bool = true;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    packet_id = 1;
    packets_sent = 0;
    packets_received = 0;
    packets_dropped = 0;
    firewall_blocked = 0;
    firewall_allowed = 0;

    // Initialize firewall subsystem
    firewall.init();

    initialized = true;
    serial.writeString("[IP] IPv4 initialized with firewall\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Firewall Control
// =============================================================================

pub fn enableFirewall(enabled: bool) void {
    firewall_enabled = enabled;
    if (enabled) {
        firewall.setState(.enforcing);
    } else {
        firewall.setState(.disabled);
    }
    serial.writeString("[IP] Firewall ");
    serial.writeString(if (enabled) "ENABLED" else "DISABLED");
    serial.writeString("\n");
}

pub fn isFirewallEnabled() bool {
    return firewall_enabled;
}

pub fn getFirewall() type {
    return firewall;
}

// =============================================================================
// Packet Handling - WITH FIREWALL
// =============================================================================

pub fn handlePacket(iface: *network.NetworkInterface, data: []const u8) void {
    const packet = parse(data) orelse {
        packets_dropped += 1;
        return;
    };

    if (!verifyChecksum(data[0..packet.header.headerLength()])) {
        packets_dropped += 1;
        return;
    }

    // Accept packet if:
    // - Destination is our IP
    // - Destination is broadcast
    // - Destination is loopback range (127.x.x.x)
    const is_our_ip = packet.header.dst_ip == iface.ip_addr;
    const is_broadcast = packet.header.dst_ip == 0xFFFFFFFF;
    const is_loopback = (packet.header.dst_ip >> 24) == 127;
    const is_subnet_broadcast = (packet.header.dst_ip | ~iface.netmask) == 0xFFFFFFFF;

    if (!is_our_ip and !is_broadcast and !is_loopback and !is_subnet_broadcast) {
        return;
    }

    // =========================================================================
    // FIREWALL CHECK - Inbound Filtering
    // =========================================================================
    if (firewall_enabled and firewall.isInitialized()) {
        // Extract ports for TCP/UDP
        var src_port: u16 = 0;
        var dst_port: u16 = 0;

        if (packet.header.protocol == PROTO_TCP or packet.header.protocol == PROTO_UDP) {
            if (packet.payload.len >= 4) {
                src_port = (@as(u16, packet.payload[0]) << 8) | @as(u16, packet.payload[1]);
                dst_port = (@as(u16, packet.payload[2]) << 8) | @as(u16, packet.payload[3]);
            }
        }

        const filter_result = firewall.filterInbound(
            packet.header.src_ip,
            packet.header.dst_ip,
            packet.header.protocol,
            src_port,
            dst_port,
            null, // No P2P peer ID for raw packets
        );

        if (filter_result.action != .allow) {
            firewall_blocked += 1;

            // Log blocked packet (if configured)
            if (firewall.config.log_blocked) {
                serial.writeString("[IP] 🛡️ BLOCKED: ");
                printIpAddr(packet.header.src_ip);
                serial.writeString(":");
                printNumber(src_port);
                serial.writeString(" -> ");
                printIpAddr(packet.header.dst_ip);
                serial.writeString(":");
                printNumber(dst_port);
                serial.writeString(" proto=");
                printNumber(packet.header.protocol);
                serial.writeString(" (");
                serial.writeString(filter_result.reason);
                serial.writeString(")\n");
            }

            // Stealth mode - no response, just drop
            if (firewall.config.stealth_mode) {
                return; // Silent drop
            }

            // Send ICMP unreachable if reject mode
            if (filter_result.action == .reject) {
                // icmp.sendUnreachable(iface, &packet, icmp.UNREACHABLE_ADMIN);
            }

            return; // DROP PACKET
        }

        firewall_allowed += 1;

        // Port scan detection for TCP
        if (packet.header.protocol == PROTO_TCP) {
            _ = firewall.detectPortScan(packet.header.src_ip, dst_port);
        }
    }
    // =========================================================================

    packets_received += 1;

    // Route to appropriate protocol handler
    switch (packet.header.protocol) {
        PROTO_ICMP => {
            // ICMP might be blocked by firewall config
            if (firewall_enabled and firewall.config.block_icmp) {
                if (firewall.config.log_blocked) {
                    serial.writeString("[IP] ICMP blocked by config\n");
                }
                return;
            }
            icmp.handlePacket(iface, &packet);
        },
        PROTO_UDP => udp.handlePacket(iface, &packet),
        PROTO_TCP => tcp.handlePacket(iface, &packet),
        else => {
            // Unknown protocol - drop silently
        },
    }
}

pub fn parse(data: []const u8) ?IpPacket {
    if (data.len < HEADER_SIZE) return null;

    var header: IpHeader = undefined;

    header.version = @intCast((data[0] >> 4) & 0x0F);
    header.ihl = @intCast(data[0] & 0x0F);

    if (header.version != 4) return null;
    if (header.ihl < 5) return null;

    const hdr_len = header.headerLength();
    if (data.len < hdr_len) return null;

    header.tos = data[1];
    header.total_len = readU16BE(data[2..4]);
    header.id = readU16BE(data[4..6]);
    header.flags_fragment = readU16BE(data[6..8]);
    header.ttl = data[8];
    header.protocol = data[9];
    header.checksum = readU16BE(data[10..12]);
    header.src_ip = readU32BE(data[12..16]);
    header.dst_ip = readU32BE(data[16..20]);

    const total = @min(header.total_len, data.len);
    if (total < hdr_len) return null;

    return .{
        .header = header,
        .payload = data[hdr_len..total],
    };
}

// =============================================================================
// Packet Sending - WITH FIREWALL
// =============================================================================

pub fn send(iface: *network.NetworkInterface, dst_ip: u32, protocol: u8, payload: []const u8) bool {
    // =========================================================================
    // FIREWALL CHECK - Outbound Filtering
    // =========================================================================
    if (firewall_enabled and firewall.isInitialized()) {
        var src_port: u16 = 0;
        var dst_port: u16 = 0;

        if ((protocol == PROTO_TCP or protocol == PROTO_UDP) and payload.len >= 4) {
            src_port = (@as(u16, payload[0]) << 8) | @as(u16, payload[1]);
            dst_port = (@as(u16, payload[2]) << 8) | @as(u16, payload[3]);
        }

        const filter_result = firewall.filterOutbound(
            iface.ip_addr,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        );

        if (filter_result.action != .allow) {
            if (firewall.config.log_blocked) {
                serial.writeString("[IP] Outbound blocked: ");
                printIpAddr(dst_ip);
                serial.writeString(" (");
                serial.writeString(filter_result.reason);
                serial.writeString(")\n");
            }
            return false;
        }
    }
    // =========================================================================

    var ip_packet: [1500]u8 = undefined;

    const total_len = HEADER_SIZE + payload.len;
    if (total_len > ip_packet.len) return false;

    // Build IP header
    ip_packet[0] = 0x45; // Version 4, IHL 5
    ip_packet[1] = 0; // TOS
    writeU16BE(ip_packet[2..4], @intCast(total_len));
    writeU16BE(ip_packet[4..6], packet_id);
    packet_id +%= 1;
    writeU16BE(ip_packet[6..8], FLAG_DF); // Don't Fragment
    ip_packet[8] = 64; // TTL
    ip_packet[9] = protocol;
    writeU16BE(ip_packet[10..12], 0); // Checksum placeholder
    writeU32BE(ip_packet[12..16], iface.ip_addr);
    writeU32BE(ip_packet[16..20], dst_ip);

    // Copy payload
    @memcpy(ip_packet[HEADER_SIZE..][0..payload.len], payload);

    // Calculate IP header checksum
    const cksum = checksum.calculate(ip_packet[0..HEADER_SIZE]);
    writeU16BE(ip_packet[10..12], cksum);

    // For loopback interface, send IP packet directly
    if (network.isLoopback(iface)) {
        if (iface.send(ip_packet[0..total_len])) {
            packets_sent += 1;
            return true;
        }
        return false;
    }

    // For real interfaces, wrap in ethernet frame
    var buffer: [ethernet.MAX_FRAME_SIZE]u8 = undefined;

    const dst_mac = getDestinationMac(iface, dst_ip) orelse {
        serial.writeString("[IP] Cannot resolve MAC for ");
        network.printIp(dst_ip);
        serial.writeString("\n");
        return false;
    };

    const len = ethernet.build(&buffer, dst_mac, iface.mac, ethernet.ETHERTYPE_IPV4, ip_packet[0..total_len]) orelse return false;

    if (iface.send(buffer[0..len])) {
        packets_sent += 1;
        return true;
    }

    return false;
}

/// Build an IP packet without sending (for use by other protocols)
pub fn buildPacket(
    buffer: []u8,
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    payload: []const u8,
) ?usize {
    const total_len = HEADER_SIZE + payload.len;
    if (total_len > buffer.len or total_len > 65535) return null;

    // IP Header
    buffer[0] = 0x45; // Version 4, IHL 5
    buffer[1] = 0x00; // DSCP/ECN
    writeU16BE(buffer[2..4], @intCast(total_len));
    writeU16BE(buffer[4..6], packet_id);
    packet_id +%= 1;
    writeU16BE(buffer[6..8], FLAG_DF); // Don't Fragment
    buffer[8] = 64; // TTL
    buffer[9] = protocol;
    writeU16BE(buffer[10..12], 0); // Checksum placeholder
    writeU32BE(buffer[12..16], src_ip);
    writeU32BE(buffer[16..20], dst_ip);

    // Calculate header checksum
    const hdr_cksum = checksum.calculate(buffer[0..HEADER_SIZE]);
    writeU16BE(buffer[10..12], hdr_cksum);

    // Copy payload
    @memcpy(buffer[HEADER_SIZE..][0..payload.len], payload);

    return total_len;
}

// =============================================================================
// MAC Resolution
// =============================================================================

fn getDestinationMac(iface: *network.NetworkInterface, dst_ip: u32) ?network.MacAddress {
    // Broadcast address
    if (dst_ip == 0xFFFFFFFF) {
        return ethernet.BROADCAST_MAC;
    }

    // Check if destination is on same subnet
    const our_network = iface.ip_addr & iface.netmask;
    const dst_network = dst_ip & iface.netmask;

    var resolve_ip = dst_ip;

    // If not on same subnet, use gateway
    if (our_network != dst_network) {
        if (iface.gateway == 0) {
            serial.writeString("[IP] No gateway configured for ");
            network.printIp(dst_ip);
            serial.writeString("\n");
            return null;
        }
        resolve_ip = iface.gateway;
    }

    // Try ARP cache first
    if (arp.lookup(resolve_ip)) |mac| {
        return mac;
    }

    // Send ARP request and wait briefly
    arp.sendRequest(iface, resolve_ip);

    // Wait for ARP reply (simple busy wait)
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        // Small delay
        var i: u32 = 0;
        while (i < 10000) : (i += 1) {
            asm volatile ("pause");
        }

        // Check ARP cache again
        if (arp.lookup(resolve_ip)) |mac| {
            return mac;
        }
    }

    // For QEMU SLIRP, the gateway always responds
    if (resolve_ip == iface.gateway) {
        serial.writeString("[IP] ARP failed for gateway, using broadcast\n");
        return ethernet.BROADCAST_MAC;
    }

    return null;
}

// =============================================================================
// Statistics
// =============================================================================

pub const IpStats = struct {
    sent: u64,
    received: u64,
    dropped: u64,
    fw_blocked: u64,
    fw_allowed: u64,
};

pub fn getStats() IpStats {
    return .{
        .sent = packets_sent,
        .received = packets_received,
        .dropped = packets_dropped,
        .fw_blocked = firewall_blocked,
        .fw_allowed = firewall_allowed,
    };
}

pub fn getFirewallStats() firewall.FirewallStats {
    return firewall.getStats();
}

pub fn resetStats() void {
    packets_sent = 0;
    packets_received = 0;
    packets_dropped = 0;
    firewall_blocked = 0;
    firewall_allowed = 0;
}

// =============================================================================
// Utilities
// =============================================================================

fn verifyChecksum(header: []const u8) bool {
    return checksum.verify(header);
}

fn printIpAddr(addr: u32) void {
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

fn printNumber(n: anytype) void {
    const val = @as(u32, @intCast(n));
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

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn readU32BE(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | @as(u32, data[3]);
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
