// ============================================================================
// ZAMRUD OS - ARP DEFENSE SYSTEM
// Cryptographic ARP protection dengan PeerID binding
// ============================================================================

const std = @import("std");
const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// Network driver (bukan net/network.zig)
const network = @import("../drivers/network/network.zig");

// Crypto untuk signature verification
const crypto = @import("../crypto/crypto.zig");

// Forward reference ke firewall (untuk blacklist)
const firewall = @import("firewall.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const ArpDefenseConfig = struct {
    // Enable cryptographic verification
    require_signature: bool = false, // Disabled by default for QEMU compatibility

    // Static ARP entries only (no dynamic learning)
    static_only: bool = false,

    // Bind MAC to PeerID
    require_peer_binding: bool = false, // Disabled by default for QEMU

    // Detect gratuitous ARP attacks
    detect_gratuitous: bool = true,

    // Rate limit ARP per IP
    arp_rate_limit: u32 = 30, // per second

    // Auto-blacklist attackers
    auto_blacklist: bool = true,
    blacklist_duration_sec: u64 = 7200, // 2 hours

    // Alert threshold
    alert_threshold: u32 = 5, // suspicious events before alert

    // Logging
    log_events: bool = true,
};

pub var config = ArpDefenseConfig{};

// =============================================================================
// MAC Address Type
// =============================================================================

pub const MacAddress = [6]u8;

// =============================================================================
// Trusted Binding - MAC to PeerID
// =============================================================================

pub const TrustLevel = enum(u8) {
    unknown = 0,
    pending = 1,
    verified = 2,
    trusted = 3,
    blockchain_verified = 4,
};

pub const TrustedBinding = struct {
    mac: MacAddress,
    ip: u32,
    peer_id: [32]u8,
    public_key: [32]u8,
    created_at: u64,
    last_verified: u64,
    trust_level: TrustLevel,
    verified: bool,
    description: [32]u8,
    desc_len: usize,
};

const MAX_TRUSTED_BINDINGS = 64;
var trusted_bindings: [MAX_TRUSTED_BINDINGS]TrustedBinding = undefined;
var binding_count: usize = 0;

// =============================================================================
// Secure ARP Cache
// =============================================================================

pub const EntryState = enum(u8) {
    empty = 0,
    pending = 1,
    verified = 2,
    suspicious = 3,
    blocked = 4,
};

pub const SecureArpEntry = struct {
    ip: u32,
    mac: MacAddress,
    peer_id: ?[32]u8,
    state: EntryState,
    created_at: u64,
    expires_at: u64,
    verified: bool,
    verification_failures: u32,
};

const MAX_ARP_ENTRIES = 128;
var arp_cache: [MAX_ARP_ENTRIES]SecureArpEntry = undefined;
var arp_cache_count: usize = 0;

// =============================================================================
// Rate Limiting
// =============================================================================

const ArpRateLimit = struct {
    ip: u32,
    mac: MacAddress,
    count_this_second: u32,
    last_reset: u64,
    violations: u32,
};

const MAX_RATE_LIMITS = 128;
var rate_limits: [MAX_RATE_LIMITS]ArpRateLimit = undefined;
var rate_limit_count: usize = 0;

// =============================================================================
// Event Logging
// =============================================================================

pub const ArpEventType = enum(u8) {
    request = 0,
    reply = 1,
    gratuitous = 2,
    probe = 3,
    announcement = 4,
    spoof_attempt = 5,
    flood = 6,
    binding_changed = 7,
};

pub const ArpEvent = struct {
    event_type: ArpEventType,
    src_ip: u32,
    src_mac: MacAddress,
    target_ip: u32,
    target_mac: MacAddress,
    timestamp: u64,
    is_suspicious: bool,
    reason: [64]u8,
    reason_len: usize,
};

const MAX_EVENTS = 64;
var event_log: [MAX_EVENTS]ArpEvent = undefined;
var event_count: usize = 0;

// =============================================================================
// Statistics
// =============================================================================

pub const ArpDefenseStats = struct {
    total_packets: u64 = 0,
    requests_received: u64 = 0,
    replies_received: u64 = 0,
    packets_allowed: u64 = 0,
    packets_blocked: u64 = 0,

    // Attack detection
    spoof_attempts: u64 = 0,
    gratuitous_blocked: u64 = 0,
    flood_detected: u64 = 0,
    unknown_source: u64 = 0,
    signature_failures: u64 = 0,

    // Bindings
    bindings_created: u64 = 0,
    bindings_verified: u64 = 0,
};

pub var stats = ArpDefenseStats{};

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[ARP-DEFENSE] Initializing...\n");

    // Clear trusted bindings
    for (&trusted_bindings) |*binding| {
        binding.* = emptyBinding();
    }
    binding_count = 0;

    // Clear ARP cache
    for (&arp_cache) |*entry| {
        entry.* = emptyArpEntry();
    }
    arp_cache_count = 0;

    // Clear rate limits
    for (&rate_limits) |*rl| {
        rl.* = emptyRateLimit();
    }
    rate_limit_count = 0;

    // Clear events
    for (&event_log) |*ev| {
        ev.* = emptyEvent();
    }
    event_count = 0;

    // Reset stats
    stats = ArpDefenseStats{};

    // Add QEMU gateway as trusted
    addQemuBindings();

    serial.writeString("[ARP-DEFENSE] Initialized\n");
    serial.writeString("[ARP-DEFENSE] Trusted bindings: ");
    printNumber(binding_count);
    serial.writeString("\n");
}

fn emptyBinding() TrustedBinding {
    return TrustedBinding{
        .mac = [_]u8{0} ** 6,
        .ip = 0,
        .peer_id = [_]u8{0} ** 32,
        .public_key = [_]u8{0} ** 32,
        .created_at = 0,
        .last_verified = 0,
        .trust_level = .unknown,
        .verified = false,
        .description = [_]u8{0} ** 32,
        .desc_len = 0,
    };
}

fn emptyArpEntry() SecureArpEntry {
    return SecureArpEntry{
        .ip = 0,
        .mac = [_]u8{0} ** 6,
        .peer_id = null,
        .state = .empty,
        .created_at = 0,
        .expires_at = 0,
        .verified = false,
        .verification_failures = 0,
    };
}

fn emptyRateLimit() ArpRateLimit {
    return ArpRateLimit{
        .ip = 0,
        .mac = [_]u8{0} ** 6,
        .count_this_second = 0,
        .last_reset = 0,
        .violations = 0,
    };
}

fn emptyEvent() ArpEvent {
    return ArpEvent{
        .event_type = .request,
        .src_ip = 0,
        .src_mac = [_]u8{0} ** 6,
        .target_ip = 0,
        .target_mac = [_]u8{0} ** 6,
        .timestamp = 0,
        .is_suspicious = false,
        .reason = [_]u8{0} ** 64,
        .reason_len = 0,
    };
}

fn addQemuBindings() void {
    // QEMU SLIRP gateway: 10.0.2.2 -> 52:55:0a:00:02:02
    const gateway_mac: MacAddress = .{ 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    const gateway_ip: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 2;
    _ = createStaticBinding(gateway_mac, gateway_ip, "QEMU Gateway");

    // QEMU SLIRP DNS: 10.0.2.3 -> 52:55:0a:00:02:03
    const dns_mac: MacAddress = .{ 0x52, 0x55, 0x0a, 0x00, 0x02, 0x03 };
    const dns_ip: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 3;
    _ = createStaticBinding(dns_mac, dns_ip, "QEMU DNS");
}

// =============================================================================
// Validation Result
// =============================================================================

pub const ValidationResult = struct {
    allowed: bool,
    reason: []const u8,
    trust_level: TrustLevel,
    peer_id: ?[32]u8,
};

// =============================================================================
// Main Validation Function
// =============================================================================

pub fn validateArpPacket(
    operation: u16,
    sender_mac: MacAddress,
    sender_ip: u32,
    target_mac: MacAddress,
    target_ip: u32,
    signature: ?[]const u8,
) ValidationResult {
    stats.total_packets += 1;

    if (operation == 1) {
        stats.requests_received += 1;
    } else {
        stats.replies_received += 1;
    }

    // 1. Rate limiting check
    if (!checkArpRateLimit(sender_ip, sender_mac)) {
        stats.packets_blocked += 1;
        stats.flood_detected += 1;

        logEvent(.flood, sender_ip, sender_mac, target_ip, target_mac, true, "ARP flood detected");

        if (config.auto_blacklist) {
            _ = firewall.addToBlacklist(sender_ip, config.blacklist_duration_sec, "ARP flood");
        }

        return .{
            .allowed = false,
            .reason = "ARP flood detected",
            .trust_level = .unknown,
            .peer_id = null,
        };
    }

    // 2. Detect gratuitous ARP (potential attack)
    if (config.detect_gratuitous and operation == 2) {
        if (sender_ip == target_ip) {
            // Gratuitous ARP - check if from known source
            if (!isKnownBinding(sender_ip, sender_mac)) {
                stats.packets_blocked += 1;
                stats.gratuitous_blocked += 1;

                logEvent(.gratuitous, sender_ip, sender_mac, target_ip, target_mac, true, "Unknown gratuitous ARP");

                return .{
                    .allowed = false,
                    .reason = "Gratuitous ARP from unknown source",
                    .trust_level = .unknown,
                    .peer_id = null,
                };
            }
        }
    }

    // 3. Check for ARP spoofing
    const spoof_check = detectArpSpoof(sender_ip, sender_mac);
    if (spoof_check.is_spoof) {
        stats.packets_blocked += 1;
        stats.spoof_attempts += 1;

        logEvent(.spoof_attempt, sender_ip, sender_mac, target_ip, target_mac, true, spoof_check.reason);

        if (config.auto_blacklist) {
            _ = firewall.addToBlacklist(sender_ip, config.blacklist_duration_sec, "ARP spoofing");
        }

        return .{
            .allowed = false,
            .reason = spoof_check.reason,
            .trust_level = .unknown,
            .peer_id = null,
        };
    }

    // 4. Signature verification (if required and provided)
    if (config.require_signature) {
        if (signature) |sig| {
            const binding = getTrustedBindingByMac(sender_mac);
            if (binding) |b| {
                if (!verifyArpSignature(operation, sender_mac, sender_ip, target_mac, target_ip, sig, &b.public_key)) {
                    stats.packets_blocked += 1;
                    stats.signature_failures += 1;

                    return .{
                        .allowed = false,
                        .reason = "Invalid ARP signature",
                        .trust_level = .unknown,
                        .peer_id = null,
                    };
                }
            }
        } else if (!isGatewayOrLocal(sender_ip)) {
            // No signature and not gateway - block if signature required
            stats.packets_blocked += 1;

            return .{
                .allowed = false,
                .reason = "ARP signature required",
                .trust_level = .unknown,
                .peer_id = null,
            };
        }
    }

    // 5. Update secure cache
    updateSecureCache(sender_ip, sender_mac);

    stats.packets_allowed += 1;

    // Get trust level
    const binding = getTrustedBinding(sender_ip, sender_mac);
    const event_type: ArpEventType = if (operation == 1) .request else .reply;
    logEvent(event_type, sender_ip, sender_mac, target_ip, target_mac, false, "Allowed");

    return .{
        .allowed = true,
        .reason = "Validated",
        .trust_level = if (binding) |b| b.trust_level else .unknown,
        .peer_id = if (binding) |b| b.peer_id else null,
    };
}

// =============================================================================
// Spoof Detection
// =============================================================================

const SpoofResult = struct {
    is_spoof: bool,
    reason: []const u8,
};

fn detectArpSpoof(ip: u32, mac: MacAddress) SpoofResult {
    // Check trusted bindings first
    for (trusted_bindings[0..binding_count]) |*binding| {
        if (binding.ip == ip) {
            // We have a binding for this IP
            if (!macEqual(binding.mac, mac)) {
                return .{
                    .is_spoof = true,
                    .reason = "MAC doesn't match trusted binding",
                };
            }
        }
    }

    // Check ARP cache for changes
    for (arp_cache[0..arp_cache_count]) |*entry| {
        if (entry.state != .empty and entry.ip == ip) {
            if (!macEqual(entry.mac, mac)) {
                if (entry.verified) {
                    return .{
                        .is_spoof = true,
                        .reason = "MAC changed for verified entry",
                    };
                }
                // Unverified entry - suspicious but allow
                entry.verification_failures += 1;
                entry.state = .suspicious;
            }
        }
    }

    return .{ .is_spoof = false, .reason = "" };
}

// =============================================================================
// Binding Management
// =============================================================================

pub fn createBinding(mac: MacAddress, ip: u32, peer_id: [32]u8, public_key: [32]u8) bool {
    // Check if binding exists
    for (trusted_bindings[0..binding_count]) |*binding| {
        if (binding.ip == ip) {
            // Update existing
            binding.mac = mac;
            binding.peer_id = peer_id;
            binding.public_key = public_key;
            binding.last_verified = getTimestamp();
            binding.verified = true;
            binding.trust_level = .verified;
            return true;
        }
    }

    if (binding_count >= MAX_TRUSTED_BINDINGS) {
        serial.writeString("[ARP-DEFENSE] Max bindings reached\n");
        return false;
    }

    trusted_bindings[binding_count] = TrustedBinding{
        .mac = mac,
        .ip = ip,
        .peer_id = peer_id,
        .public_key = public_key,
        .created_at = getTimestamp(),
        .last_verified = getTimestamp(),
        .trust_level = .verified,
        .verified = true,
        .description = [_]u8{0} ** 32,
        .desc_len = 0,
    };
    binding_count += 1;
    stats.bindings_created += 1;

    return true;
}

pub fn createStaticBinding(mac: MacAddress, ip: u32, description: []const u8) bool {
    if (binding_count >= MAX_TRUSTED_BINDINGS) {
        return false;
    }

    var binding = &trusted_bindings[binding_count];
    binding.* = emptyBinding();
    binding.mac = mac;
    binding.ip = ip;
    binding.created_at = getTimestamp();
    binding.last_verified = getTimestamp();
    binding.trust_level = .trusted;
    binding.verified = true;

    const desc_len = @min(description.len, 32);
    @memcpy(binding.description[0..desc_len], description[0..desc_len]);
    binding.desc_len = desc_len;

    binding_count += 1;
    stats.bindings_created += 1;

    return true;
}

pub fn removeBinding(ip: u32) bool {
    for (0..binding_count) |i| {
        if (trusted_bindings[i].ip == ip) {
            for (i..binding_count - 1) |j| {
                trusted_bindings[j] = trusted_bindings[j + 1];
            }
            binding_count -= 1;
            return true;
        }
    }
    return false;
}

fn getTrustedBinding(ip: u32, mac: MacAddress) ?*TrustedBinding {
    for (trusted_bindings[0..binding_count]) |*binding| {
        if (binding.ip == ip and macEqual(binding.mac, mac)) {
            return binding;
        }
    }
    return null;
}

fn getTrustedBindingByMac(mac: MacAddress) ?*TrustedBinding {
    for (trusted_bindings[0..binding_count]) |*binding| {
        if (macEqual(binding.mac, mac)) {
            return binding;
        }
    }
    return null;
}

fn isKnownBinding(ip: u32, mac: MacAddress) bool {
    return getTrustedBinding(ip, mac) != null;
}

// =============================================================================
// Secure Cache
// =============================================================================

fn updateSecureCache(ip: u32, mac: MacAddress) void {
    // Find existing entry
    for (arp_cache[0..arp_cache_count]) |*entry| {
        if (entry.ip == ip) {
            entry.mac = mac;
            entry.expires_at = getTimestamp() + 300000; // 5 minutes
            if (isKnownBinding(ip, mac)) {
                entry.verified = true;
                entry.state = .verified;
            }
            return;
        }
    }

    // Add new entry
    if (arp_cache_count >= MAX_ARP_ENTRIES) {
        // Evict oldest unverified
        for (0..arp_cache_count) |i| {
            if (!arp_cache[i].verified) {
                arp_cache[i] = emptyArpEntry();
                arp_cache[i].ip = ip;
                arp_cache[i].mac = mac;
                arp_cache[i].state = if (isKnownBinding(ip, mac)) .verified else .pending;
                arp_cache[i].created_at = getTimestamp();
                arp_cache[i].expires_at = getTimestamp() + 300000;
                arp_cache[i].verified = isKnownBinding(ip, mac);
                return;
            }
        }
        return; // Cache full with verified entries
    }

    arp_cache[arp_cache_count] = SecureArpEntry{
        .ip = ip,
        .mac = mac,
        .peer_id = null,
        .state = if (isKnownBinding(ip, mac)) .verified else .pending,
        .created_at = getTimestamp(),
        .expires_at = getTimestamp() + 300000,
        .verified = isKnownBinding(ip, mac),
        .verification_failures = 0,
    };
    arp_cache_count += 1;
}

pub fn lookupMac(ip: u32) ?MacAddress {
    for (arp_cache[0..arp_cache_count]) |*entry| {
        if (entry.ip == ip and entry.state != .empty and entry.state != .blocked) {
            return entry.mac;
        }
    }

    // Check trusted bindings
    for (trusted_bindings[0..binding_count]) |*binding| {
        if (binding.ip == ip) {
            return binding.mac;
        }
    }

    return null;
}

// =============================================================================
// Rate Limiting
// =============================================================================

fn checkArpRateLimit(ip: u32, mac: MacAddress) bool {
    const now = getTimestamp();

    // Find entry
    for (rate_limits[0..rate_limit_count]) |*entry| {
        if (entry.ip == ip) {
            // Reset counter every second
            if (now > entry.last_reset and now - entry.last_reset >= 1000) {
                entry.count_this_second = 0;
                entry.last_reset = now;
            }

            entry.count_this_second += 1;

            if (entry.count_this_second > config.arp_rate_limit) {
                entry.violations += 1;
                return false;
            }

            return true;
        }
    }

    // Create new entry
    if (rate_limit_count >= MAX_RATE_LIMITS) {
        return true; // Allow if can't track
    }

    rate_limits[rate_limit_count] = ArpRateLimit{
        .ip = ip,
        .mac = mac,
        .count_this_second = 1,
        .last_reset = now,
        .violations = 0,
    };
    rate_limit_count += 1;

    return true;
}

// =============================================================================
// Signature Verification
// =============================================================================

fn verifyArpSignature(
    operation: u16,
    sender_mac: MacAddress,
    sender_ip: u32,
    target_mac: MacAddress,
    target_ip: u32,
    signature: []const u8,
    public_key: *const [32]u8,
) bool {
    if (signature.len != 64) return false;

    var msg_buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Operation
    msg_buf[pos] = @intCast((operation >> 8) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast(operation & 0xFF);
    pos += 1;

    // Sender MAC
    @memcpy(msg_buf[pos .. pos + 6], &sender_mac);
    pos += 6;

    // Sender IP
    msg_buf[pos] = @intCast((sender_ip >> 24) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast((sender_ip >> 16) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast((sender_ip >> 8) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast(sender_ip & 0xFF);
    pos += 1;

    // Target MAC
    @memcpy(msg_buf[pos .. pos + 6], &target_mac);
    pos += 6;

    // Target IP
    msg_buf[pos] = @intCast((target_ip >> 24) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast((target_ip >> 16) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast((target_ip >> 8) & 0xFF);
    pos += 1;
    msg_buf[pos] = @intCast(target_ip & 0xFF);
    pos += 1;

    const hash = crypto.sha256(msg_buf[0..pos]);

    var sig_arr: [64]u8 = undefined;
    @memcpy(&sig_arr, signature[0..64]);

    return crypto.verify(public_key, &hash, &sig_arr);
}

// =============================================================================
// Helpers
// =============================================================================

fn isGatewayOrLocal(ip: u32) bool {
    // Loopback
    if ((ip >> 24) == 127) return true;

    // QEMU SLIRP network (10.0.2.0/24)
    if ((ip & 0xFFFFFF00) == 0x0A000200) return true;

    return false;
}

fn macEqual(a: MacAddress, b: MacAddress) bool {
    for (0..6) |i| {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn getTimestamp() u64 {
    return timer.getTicks();
}

// =============================================================================
// Event Logging
// =============================================================================

fn logEvent(
    event_type: ArpEventType,
    src_ip: u32,
    src_mac: MacAddress,
    target_ip: u32,
    target_mac: MacAddress,
    is_suspicious: bool,
    reason: []const u8,
) void {
    if (!config.log_events and !is_suspicious) return;

    if (event_count >= MAX_EVENTS) {
        // Shift events
        for (0..MAX_EVENTS - 1) |i| {
            event_log[i] = event_log[i + 1];
        }
        event_count = MAX_EVENTS - 1;
    }

    var ev = &event_log[event_count];
    ev.event_type = event_type;
    ev.src_ip = src_ip;
    ev.src_mac = src_mac;
    ev.target_ip = target_ip;
    ev.target_mac = target_mac;
    ev.timestamp = getTimestamp();
    ev.is_suspicious = is_suspicious;

    const reason_len = @min(reason.len, 64);
    @memcpy(ev.reason[0..reason_len], reason[0..reason_len]);
    ev.reason_len = reason_len;

    event_count += 1;

    // Log to serial if suspicious
    if (is_suspicious) {
        serial.writeString("[ARP-DEFENSE] ");
        serial.writeString(switch (event_type) {
            .request => "REQUEST",
            .reply => "REPLY",
            .gratuitous => "GRATUITOUS",
            .probe => "PROBE",
            .announcement => "ANNOUNCE",
            .spoof_attempt => "⚠️ SPOOF",
            .flood => "⚠️ FLOOD",
            .binding_changed => "BINDING",
        });
        serial.writeString(" from ");
        printIp(src_ip);
        serial.writeString(" - ");
        serial.writeString(reason);
        serial.writeString("\n");
    }
}

// =============================================================================
// Public API
// =============================================================================

pub fn getStats() ArpDefenseStats {
    return stats;
}

pub fn getBindingCount() usize {
    return binding_count;
}

pub fn getBinding(index: usize) ?*const TrustedBinding {
    if (index >= binding_count) return null;
    return &trusted_bindings[index];
}

pub fn getEventCount() usize {
    return event_count;
}

pub fn getEvent(index: usize) ?*const ArpEvent {
    if (index >= event_count) return null;
    return &event_log[index];
}

pub fn clearEvents() void {
    event_count = 0;
}

pub fn setRequireSignature(enabled: bool) void {
    config.require_signature = enabled;
}

pub fn setRequirePeerBinding(enabled: bool) void {
    config.require_peer_binding = enabled;
}

pub fn isInitialized() bool {
    return binding_count > 0 or stats.total_packets > 0;
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printIp(ip: u32) void {
    printNumber((ip >> 24) & 0xFF);
    serial.writeChar('.');
    printNumber((ip >> 16) & 0xFF);
    serial.writeChar('.');
    printNumber((ip >> 8) & 0xFF);
    serial.writeChar('.');
    printNumber(ip & 0xFF);
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
