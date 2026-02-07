//! Zamrud OS - ARP Protocol with Security Integration
//! Address Resolution Protocol (RFC 826) + ARP Defense

const serial = @import("../drivers/serial/serial.zig");
const network = @import("../drivers/network/network.zig");
const ethernet = @import("../drivers/network/ethernet.zig");

// Security imports
const arp_defense = @import("arp_defense.zig");
const threat_log = @import("../security/threat_log.zig");
const blacklist = @import("../security/blacklist.zig");

// =============================================================================
// Constants
// =============================================================================

const ARP_HEADER_SIZE: usize = 28;
const ARP_CACHE_SIZE: usize = 64;

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const HTYPE_ETHERNET: u16 = 1;

// =============================================================================
// Types
// =============================================================================

const ArpCacheEntry = struct {
    ip: u32,
    mac: network.MacAddress,
    valid: bool,
    timestamp: u64,
    verified: bool, // NEW: Cryptographically verified
    peer_id: ?[32]u8, // NEW: Associated P2P peer
};

/// Public ARP entry for shell commands
pub const ArpEntry = struct {
    ip_addr: u32,
    mac_addr: network.MacAddress,
    valid: bool,
    verified: bool, // NEW
};

// =============================================================================
// State
// =============================================================================

var arp_cache: [ARP_CACHE_SIZE]ArpCacheEntry = undefined;
var initialized: bool = false;

// Static buffer for getCache return
var cache_entries: [ARP_CACHE_SIZE]ArpEntry = undefined;

// Statistics
var requests_received: u64 = 0;
var replies_received: u64 = 0;
var requests_sent: u64 = 0;
var replies_sent: u64 = 0;

// NEW: Security statistics
var blocked_spoofs: u64 = 0;
var blocked_floods: u64 = 0;
var blocked_unknown: u64 = 0;

// NEW: Security enabled flag
var security_enabled: bool = true;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&arp_cache) |*entry| {
        entry.* = .{
            .ip = 0,
            .mac = [_]u8{0} ** 6,
            .valid = false,
            .timestamp = 0,
            .verified = false,
            .peer_id = null,
        };
    }

    for (&cache_entries) |*entry| {
        entry.* = .{
            .ip_addr = 0,
            .mac_addr = [_]u8{0} ** 6,
            .valid = false,
            .verified = false,
        };
    }

    requests_received = 0;
    replies_received = 0;
    requests_sent = 0;
    replies_sent = 0;
    blocked_spoofs = 0;
    blocked_floods = 0;
    blocked_unknown = 0;

    // Initialize ARP Defense subsystem
    arp_defense.init();

    initialized = true;
    serial.writeString("[ARP] ARP initialized with security\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Security Control
// =============================================================================

pub fn enableSecurity(enabled: bool) void {
    security_enabled = enabled;
    serial.writeString("[ARP] Security ");
    serial.writeString(if (enabled) "ENABLED" else "DISABLED");
    serial.writeString("\n");
}

pub fn isSecurityEnabled() bool {
    return security_enabled;
}

// =============================================================================
// Packet Handling - WITH SECURITY
// =============================================================================

pub fn handlePacket(iface: *network.NetworkInterface, data: []const u8) void {
    if (data.len < ARP_HEADER_SIZE) {
        serial.writeString("[ARP] Packet too small\n");
        return;
    }

    const htype = readU16BE(data[0..2]);
    const ptype = readU16BE(data[2..4]);
    const hlen = data[4];
    const plen = data[5];
    const oper = readU16BE(data[6..8]);

    // Debug: Print ARP packet info
    serial.writeString("[ARP] Received: op=");
    if (oper == ARP_REQUEST) {
        serial.writeString("REQUEST");
    } else if (oper == ARP_REPLY) {
        serial.writeString("REPLY");
    } else {
        serial.writeString("UNKNOWN(");
        printDec(oper);
        serial.writeString(")");
    }

    if (htype != HTYPE_ETHERNET) {
        serial.writeString(" [bad htype]\n");
        return;
    }
    if (ptype != ethernet.ETHERTYPE_IPV4) {
        serial.writeString(" [bad ptype]\n");
        return;
    }
    if (hlen != 6 or plen != 4) {
        serial.writeString(" [bad len]\n");
        return;
    }

    // Extract sender info
    var sha: network.MacAddress = undefined;
    for (0..6) |i| {
        sha[i] = data[8 + i];
    }
    const spa = readU32BE(data[14..18]);

    // Extract target info
    var tha: network.MacAddress = undefined;
    for (0..6) |i| {
        tha[i] = data[18 + i];
    }
    const tpa = readU32BE(data[24..28]);

    // Debug: Print addresses
    serial.writeString("\n[ARP]   Sender: ");
    printMac(sha);
    serial.writeString(" -> ");
    printIp(spa);
    serial.writeString("\n[ARP]   Target: ");
    printMac(tha);
    serial.writeString(" -> ");
    printIp(tpa);
    serial.writeString("\n[ARP]   Our IP: ");
    printIp(iface.ip_addr);
    serial.writeString(" Our MAC: ");
    printMac(iface.mac);
    serial.writeString("\n");

    // =========================================================================
    // SECURITY CHECK - ARP Defense Validation
    // =========================================================================
    if (security_enabled) {
        const validation = arp_defense.validateArpPacket(
            oper,
            sha,
            spa,
            tha,
            tpa,
            null, // No signature in standard ARP
        );

        if (!validation.allowed) {
            serial.writeString("[ARP] ⚠️ BLOCKED: ");
            serial.writeString(validation.reason);
            serial.writeString("\n");

            // Update security stats
            switch (validation.trust_level) {
                .unknown => blocked_unknown += 1,
                else => blocked_spoofs += 1,
            }

            return; // DROP PACKET
        }

        // Log if suspicious but allowed
        if (validation.trust_level == .unknown or validation.trust_level == .pending) {
            serial.writeString("[ARP] ⚡ Unverified source, proceeding cautiously\n");
        }
    }
    // =========================================================================

    // Update cache with sender info (we learned their MAC)
    updateCacheSecure(spa, sha, null);
    serial.writeString("[ARP] Updated cache: ");
    printIp(spa);
    serial.writeString(" -> ");
    printMac(sha);
    serial.writeString("\n");

    // Check if this is for us
    if (tpa != iface.ip_addr) {
        serial.writeString("[ARP] Not for us, ignoring\n");
        return;
    }

    if (oper == ARP_REQUEST) {
        requests_received += 1;
        serial.writeString("[ARP] REQUEST is for us! Sending REPLY...\n");
        sendReply(iface, sha, spa);
    } else if (oper == ARP_REPLY) {
        replies_received += 1;
        serial.writeString("[ARP] Got REPLY for us, cache updated\n");
    }
}

// =============================================================================
// Cache Management - WITH SECURITY
// =============================================================================

pub fn lookup(ip: u32) ?network.MacAddress {
    for (&arp_cache) |*entry| {
        if (entry.valid and entry.ip == ip) {
            return entry.mac;
        }
    }
    return null;
}

/// Lookup with verification status
pub fn lookupVerified(ip: u32) ?struct { mac: network.MacAddress, verified: bool } {
    for (&arp_cache) |*entry| {
        if (entry.valid and entry.ip == ip) {
            return .{
                .mac = entry.mac,
                .verified = entry.verified,
            };
        }
    }
    return null;
}

fn updateCache(ip: u32, mac: network.MacAddress) void {
    updateCacheSecure(ip, mac, null);
}

fn updateCacheSecure(ip: u32, mac: network.MacAddress, peer_id: ?[32]u8) void {
    // Skip if MAC is all zeros (invalid)
    var all_zero = true;
    for (mac) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return;

    // SECURITY: Check for IP-MAC binding changes (potential spoof)
    if (security_enabled) {
        for (&arp_cache) |*entry| {
            if (entry.valid and entry.ip == ip) {
                // Check if MAC changed
                var mac_changed = false;
                for (0..6) |i| {
                    if (entry.mac[i] != mac[i]) {
                        mac_changed = true;
                        break;
                    }
                }

                if (mac_changed) {
                    if (entry.verified) {
                        // Verified entry trying to change - SUSPICIOUS!
                        serial.writeString("[ARP] ⚠️ WARNING: Verified MAC changed for ");
                        printIp(ip);
                        serial.writeString("\n[ARP]   Old: ");
                        printMac(entry.mac);
                        serial.writeString(" (verified)\n[ARP]   New: ");
                        printMac(mac);
                        serial.writeString(" (unverified)\n");

                        _ = threat_log.logThreat(.{
                            .threat_type = .arp_spoof,
                            .severity = .high,
                            .source_ip = ip,
                            .description = "MAC address changed for verified entry",
                        });

                        // Don't update - keep verified entry
                        return;
                    } else {
                        // Unverified entry changed - log but allow
                        serial.writeString("[ARP] MAC changed for ");
                        printIp(ip);
                        serial.writeString(" (unverified)\n");
                    }
                }

                // Update existing entry
                entry.mac = mac;
                entry.timestamp = getTimestamp();
                if (peer_id) |pid| {
                    entry.peer_id = pid;
                    entry.verified = true;
                }
                return;
            }
        }
    }

    // First, check if entry exists (non-security path)
    for (&arp_cache) |*entry| {
        if (entry.ip == ip) {
            entry.mac = mac;
            entry.valid = true;
            entry.timestamp = getTimestamp();
            if (peer_id) |pid| {
                entry.peer_id = pid;
                entry.verified = true;
            }
            return;
        }
    }

    // Find empty slot
    for (&arp_cache) |*entry| {
        if (!entry.valid) {
            entry.ip = ip;
            entry.mac = mac;
            entry.valid = true;
            entry.timestamp = getTimestamp();
            entry.verified = peer_id != null;
            entry.peer_id = peer_id;
            return;
        }
    }

    // Cache full - replace oldest unverified entry
    var oldest_idx: usize = 0;
    var oldest_time: u64 = 0xFFFFFFFFFFFFFFFF;

    for (&arp_cache, 0..) |*entry, i| {
        if (!entry.verified and entry.timestamp < oldest_time) {
            oldest_time = entry.timestamp;
            oldest_idx = i;
        }
    }

    // Only replace if we found an unverified entry
    if (!arp_cache[oldest_idx].verified) {
        arp_cache[oldest_idx] = .{
            .ip = ip,
            .mac = mac,
            .valid = true,
            .timestamp = getTimestamp(),
            .verified = peer_id != null,
            .peer_id = peer_id,
        };
    } else {
        serial.writeString("[ARP] Cache full with verified entries\n");
    }
}

/// Add entry to cache (public API for shell commands)
pub fn addEntry(ip: u32, mac: network.MacAddress) void {
    updateCache(ip, mac);
}

/// Add verified entry (for trusted peers)
pub fn addVerifiedEntry(ip: u32, mac: network.MacAddress, peer_id: [32]u8) void {
    updateCacheSecure(ip, mac, peer_id);

    // Also add to ARP defense trusted bindings
    if (security_enabled) {
        _ = arp_defense.createBinding(mac, ip, peer_id, [_]u8{0} ** 32);
    }
}

/// Get all cache entries (public API for shell commands)
pub fn getCache() []const ArpEntry {
    for (&arp_cache, 0..) |*entry, i| {
        cache_entries[i] = .{
            .ip_addr = entry.ip,
            .mac_addr = entry.mac,
            .valid = entry.valid,
            .verified = entry.verified,
        };
    }
    return &cache_entries;
}

/// Clear entire cache (except verified entries)
pub fn clearCache() void {
    for (&arp_cache) |*entry| {
        if (!entry.verified) { // Keep verified entries
            entry.valid = false;
            entry.ip = 0;
            entry.mac = [_]u8{0} ** 6;
            entry.timestamp = 0;
        }
    }
}

/// Force clear all cache including verified
pub fn clearCacheForce() void {
    for (&arp_cache) |*entry| {
        entry.valid = false;
        entry.ip = 0;
        entry.mac = [_]u8{0} ** 6;
        entry.timestamp = 0;
        entry.verified = false;
        entry.peer_id = null;
    }
}

/// Get number of valid entries
pub fn getCacheCount() usize {
    var count: usize = 0;
    for (&arp_cache) |*entry| {
        if (entry.valid) count += 1;
    }
    return count;
}

/// Get number of verified entries
pub fn getVerifiedCount() usize {
    var count: usize = 0;
    for (&arp_cache) |*entry| {
        if (entry.valid and entry.verified) count += 1;
    }
    return count;
}

/// Remove specific entry
pub fn removeEntry(ip: u32) bool {
    for (&arp_cache) |*entry| {
        if (entry.valid and entry.ip == ip) {
            if (entry.verified) {
                serial.writeString("[ARP] WARNING: Removing verified entry\n");
            }
            entry.valid = false;
            entry.ip = 0;
            entry.mac = [_]u8{0} ** 6;
            entry.verified = false;
            entry.peer_id = null;
            return true;
        }
    }
    return false;
}

// =============================================================================
// ARP Request/Reply
// =============================================================================

pub fn sendRequest(iface: *network.NetworkInterface, target_ip: u32) void {
    serial.writeString("[ARP] Sending REQUEST for ");
    printIp(target_ip);
    serial.writeString("\n");

    var buffer: [ethernet.MAX_FRAME_SIZE]u8 = undefined;
    var arp_packet: [ARP_HEADER_SIZE]u8 = undefined;

    // Hardware type: Ethernet
    writeU16BE(arp_packet[0..2], HTYPE_ETHERNET);
    // Protocol type: IPv4
    writeU16BE(arp_packet[2..4], ethernet.ETHERTYPE_IPV4);
    // Hardware size: 6
    arp_packet[4] = 6;
    // Protocol size: 4
    arp_packet[5] = 4;
    // Operation: Request
    writeU16BE(arp_packet[6..8], ARP_REQUEST);

    // Sender hardware address (our MAC)
    for (0..6) |i| {
        arp_packet[8 + i] = iface.mac[i];
    }
    // Sender protocol address (our IP)
    writeU32BE(arp_packet[14..18], iface.ip_addr);

    // Target hardware address (unknown - zeros)
    for (0..6) |i| {
        arp_packet[18 + i] = 0;
    }
    // Target protocol address (IP we're looking for)
    writeU32BE(arp_packet[24..28], target_ip);

    // Build Ethernet frame
    const len = ethernet.build(
        &buffer,
        ethernet.BROADCAST_MAC,
        iface.mac,
        ethernet.ETHERTYPE_ARP,
        &arp_packet,
    ) orelse {
        serial.writeString("[ARP] Failed to build ethernet frame\n");
        return;
    };

    serial.writeString("[ARP] Sending ");
    printDec(@intCast(len));
    serial.writeString(" bytes\n");

    if (iface.send(buffer[0..len])) {
        requests_sent += 1;
        serial.writeString("[ARP] Request sent OK\n");
    } else {
        serial.writeString("[ARP] Request send FAILED\n");
    }
}

fn sendReply(iface: *network.NetworkInterface, target_mac: network.MacAddress, target_ip: u32) void {
    serial.writeString("[ARP] Sending REPLY to ");
    printIp(target_ip);
    serial.writeString(" (");
    printMac(target_mac);
    serial.writeString(")\n");

    var buffer: [ethernet.MAX_FRAME_SIZE]u8 = undefined;
    var arp_packet: [ARP_HEADER_SIZE]u8 = undefined;

    // Hardware type: Ethernet
    writeU16BE(arp_packet[0..2], HTYPE_ETHERNET);
    // Protocol type: IPv4
    writeU16BE(arp_packet[2..4], ethernet.ETHERTYPE_IPV4);
    // Hardware size: 6
    arp_packet[4] = 6;
    // Protocol size: 4
    arp_packet[5] = 4;
    // Operation: Reply
    writeU16BE(arp_packet[6..8], ARP_REPLY);

    // Sender hardware address (our MAC)
    for (0..6) |i| {
        arp_packet[8 + i] = iface.mac[i];
    }
    // Sender protocol address (our IP)
    writeU32BE(arp_packet[14..18], iface.ip_addr);

    // Target hardware address
    for (0..6) |i| {
        arp_packet[18 + i] = target_mac[i];
    }
    // Target protocol address
    writeU32BE(arp_packet[24..28], target_ip);

    // Debug: show what we're sending
    serial.writeString("[ARP] Reply content:\n");
    serial.writeString("[ARP]   SHA (us): ");
    printMac(iface.mac);
    serial.writeString(" SPA (us): ");
    printIp(iface.ip_addr);
    serial.writeString("\n[ARP]   THA: ");
    printMac(target_mac);
    serial.writeString(" TPA: ");
    printIp(target_ip);
    serial.writeString("\n");

    // Build Ethernet frame - send to specific MAC, not broadcast!
    const len = ethernet.build(
        &buffer,
        target_mac, // Destination is the requester
        iface.mac, // Source is us
        ethernet.ETHERTYPE_ARP,
        &arp_packet,
    ) orelse {
        serial.writeString("[ARP] Failed to build reply frame\n");
        return;
    };

    serial.writeString("[ARP] Sending reply frame: ");
    printDec(@intCast(len));
    serial.writeString(" bytes\n");

    if (iface.send(buffer[0..len])) {
        replies_sent += 1;
        serial.writeString("[ARP] Reply sent OK\n");
    } else {
        serial.writeString("[ARP] Reply send FAILED\n");
    }
}

// =============================================================================
// Resolution
// =============================================================================

/// Resolve IP to MAC - returns cached entry or sends request
pub fn resolve(iface: *network.NetworkInterface, ip: u32) ?network.MacAddress {
    // Check cache first
    if (lookup(ip)) |mac| {
        return mac;
    }

    // Not in cache - send ARP request
    sendRequest(iface, ip);

    // Return null - caller should retry later
    return null;
}

/// Resolve with wait (blocking) - tries multiple times with polling
pub fn resolveBlocking(iface: *network.NetworkInterface, ip: u32, max_attempts: u32) ?network.MacAddress {
    const e1000 = @import("../drivers/network/e1000.zig");

    var attempts: u32 = 0;

    while (attempts < max_attempts) : (attempts += 1) {
        // Check cache
        if (lookup(ip)) |mac| {
            serial.writeString("[ARP] Resolved ");
            printIp(ip);
            serial.writeString(" -> ");
            printMac(mac);
            serial.writeString("\n");
            return mac;
        }

        // Send request
        sendRequest(iface, ip);

        // Poll for response
        var poll_count: u32 = 0;
        while (poll_count < 1000) : (poll_count += 1) {
            // Poll hardware
            if (e1000.isInitialized()) {
                e1000.poll();
            }

            // Check if we got a response
            if (lookup(ip)) |mac| {
                return mac;
            }

            // Small delay
            var delay: u32 = 0;
            while (delay < 1000) : (delay += 1) {
                asm volatile ("pause");
            }
        }
    }

    serial.writeString("[ARP] Failed to resolve ");
    printIp(ip);
    serial.writeString(" after ");
    printDec(max_attempts);
    serial.writeString(" attempts\n");

    return lookup(ip);
}

// =============================================================================
// Statistics
// =============================================================================

pub fn getStats() struct {
    req_rx: u64,
    rep_rx: u64,
    req_tx: u64,
    rep_tx: u64,
    blocked_spoofs: u64,
    blocked_floods: u64,
    blocked_unknown: u64,
} {
    return .{
        .req_rx = requests_received,
        .rep_rx = replies_received,
        .req_tx = requests_sent,
        .rep_tx = replies_sent,
        .blocked_spoofs = blocked_spoofs,
        .blocked_floods = blocked_floods,
        .blocked_unknown = blocked_unknown,
    };
}

pub fn getSecurityStats() struct {
    spoofs_blocked: u64,
    floods_blocked: u64,
    unknown_blocked: u64,
    verified_entries: usize,
    total_entries: usize,
} {
    return .{
        .spoofs_blocked = blocked_spoofs,
        .floods_blocked = blocked_floods,
        .unknown_blocked = blocked_unknown,
        .verified_entries = getVerifiedCount(),
        .total_entries = getCacheCount(),
    };
}

// =============================================================================
// Utility Functions
// =============================================================================

fn getTimestamp() u64 {
    // Simple timestamp from timer
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getTicks();
}

fn readU16BE(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn readU32BE(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
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

fn printMac(mac: network.MacAddress) void {
    const hex = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        serial.writeChar(hex[b >> 4]);
        serial.writeChar(hex[b & 0xF]);
        if (i < 5) serial.writeChar(':');
    }
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printDec(val: u32) void {
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
