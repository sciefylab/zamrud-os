//! Zamrud OS - Kernel Firewall
//! Stealth-mode firewall with Zero Trust architecture
//!
//! Features:
//! - Stealth mode (no ICMP responses)
//! - Connection tracking
//! - Rate limiting per IP/peer
//! - Port scan detection
//! - Auto-blacklist
//! - P2P-only mode

const std = @import("std");
const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// ============================================================================
// Configuration
// ============================================================================

pub const FirewallConfig = struct {
    stealth_mode: bool = true,
    block_icmp: bool = true,
    p2p_only_mode: bool = true,
    enable_rate_limit: bool = true,
    max_packets_per_second: u32 = 1000,
    max_connections_per_ip: u32 = 50,
    syn_flood_threshold: u32 = 100,
    syn_flood_window_ms: u64 = 1000,
    auto_blacklist: bool = true,
    blacklist_threshold: u32 = 10,
    blacklist_duration_sec: u64 = 3600,
    log_blocked: bool = false,
    log_allowed: bool = false,
    log_to_serial: bool = false,
};

pub var config = FirewallConfig{};

// ============================================================================
// Types
// ============================================================================

pub const FirewallState = enum(u8) {
    disabled = 0,
    permissive = 1,
    enforcing = 2,
    lockdown = 3,
};

pub var state: FirewallState = .enforcing;

pub const Protocol = enum(u8) {
    any = 0,
    icmp = 1,
    tcp = 6,
    udp = 17,
};

pub const Action = enum(u8) {
    allow = 0,
    drop = 1,
    reject = 2,
    log = 3,
    rate_limit = 4,
};

pub const Direction = enum(u8) {
    inbound = 0,
    outbound = 1,
    both = 2,
};

pub const Rule = struct {
    id: u32,
    priority: u16,
    enabled: bool,
    direction: Direction,
    protocol: Protocol,
    src_ip: u32,
    src_mask: u32,
    src_port_start: u16,
    src_port_end: u16,
    dst_ip: u32,
    dst_mask: u32,
    dst_port_start: u16,
    dst_port_end: u16,
    action: Action,
    require_peer_id: bool,
    peer_id: ?[32]u8,
    match_count: u64,
    last_match: u64,
    description: [64]u8,
};

pub const ConnectionState = enum(u8) {
    none = 0,
    syn_sent = 1,
    syn_received = 2,
    established = 3,
    fin_wait = 4,
    closed = 5,
};

pub const Connection = struct {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    protocol: Protocol,
    conn_state: ConnectionState,
    created_at: u64,
    last_activity: u64,
    packets_in: u64,
    packets_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    peer_id: ?[32]u8,
};

pub const RateLimitEntry = struct {
    ip: u32,
    packets_this_second: u32,
    connections_active: u32,
    syn_count: u32,
    last_reset: u64,
    violations: u32,
};

pub const BlacklistEntry = struct {
    ip: u32,
    added_at: u64,
    expires_at: u64,
    permanent: bool,
    reason: [64]u8,
    hit_count: u64,
};

pub const FirewallStats = struct {
    packets_total: u64 = 0,
    packets_allowed: u64 = 0,
    packets_dropped: u64 = 0,
    packets_rejected: u64 = 0,
    icmp_blocked: u64 = 0,
    tcp_blocked: u64 = 0,
    udp_blocked: u64 = 0,
    blocked_no_rule: u64 = 0,
    blocked_rate_limit: u64 = 0,
    blocked_blacklist: u64 = 0,
    blocked_no_peer: u64 = 0,
    blocked_syn_flood: u64 = 0,
    blocked_port_scan: u64 = 0,
    connections_total: u64 = 0,
    connections_active: u64 = 0,
    last_reset: u64 = 0,
};

pub var stats = FirewallStats{};

pub const FilterResult = struct {
    action: Action,
    rule_id: u32,
    reason: []const u8,
};

// ============================================================================
// Storage
// ============================================================================

const MAX_RULES = 256;
const MAX_CONNECTIONS = 1024;
const MAX_RATE_ENTRIES = 512;
const MAX_BLACKLIST = 512;
const MAX_SCAN_TRACKERS = 64;

var rules: [MAX_RULES]Rule = undefined;
var rule_count: usize = 0;
var rules_initialized: bool = false;

var connections: [MAX_CONNECTIONS]Connection = undefined;
var connection_count: usize = 0;

var rate_limits: [MAX_RATE_ENTRIES]RateLimitEntry = undefined;
var rate_limit_count: usize = 0;

var blacklist: [MAX_BLACKLIST]BlacklistEntry = undefined;
var blacklist_count: usize = 0;

const PortScanTracker = struct {
    ip: u32,
    ports_accessed: [64]u16,
    port_count: u8,
    first_seen: u64,
    last_seen: u64,
};

var scan_trackers: [MAX_SCAN_TRACKERS]PortScanTracker = undefined;
var scan_tracker_count: usize = 0;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("\n[FIREWALL] ");
    printLine(40);

    // Initialize rules
    for (&rules) |*rule| {
        rule.* = std.mem.zeroes(Rule);
    }
    rule_count = 0;

    // Initialize connections
    for (&connections) |*conn| {
        conn.* = std.mem.zeroes(Connection);
    }
    connection_count = 0;

    // Initialize rate limits
    for (&rate_limits) |*rl| {
        rl.* = std.mem.zeroes(RateLimitEntry);
    }
    rate_limit_count = 0;

    // Initialize blacklist
    for (&blacklist) |*bl| {
        bl.* = std.mem.zeroes(BlacklistEntry);
    }
    blacklist_count = 0;

    // Initialize scan trackers
    for (&scan_trackers) |*st| {
        st.* = std.mem.zeroes(PortScanTracker);
    }
    scan_tracker_count = 0;

    // Reset stats
    stats = FirewallStats{};

    // Add default rules
    addDefaultRules();
    rules_initialized = true;

    serial.writeString("[FIREWALL] Initialized with ");
    printNumber(rule_count);
    serial.writeString(" rules\n");

    serial.writeString("[FIREWALL] Mode: ");
    serial.writeString(switch (state) {
        .disabled => "DISABLED",
        .permissive => "PERMISSIVE",
        .enforcing => "ENFORCING",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString("\n");

    if (config.stealth_mode) {
        serial.writeString("[FIREWALL] Stealth mode: ENABLED\n");
    }
    if (config.p2p_only_mode) {
        serial.writeString("[FIREWALL] P2P-only mode: ENABLED\n");
    }
}

fn addDefaultRules() void {
    // =========================================================================
    // Rule 1: Allow loopback (127.0.0.0/8)
    // Priority: 0 (highest)
    // =========================================================================
    _ = addRule(.{
        .id = 1,
        .priority = 0,
        .enabled = true,
        .direction = .both,
        .protocol = .any,
        .src_ip = 0x7F000000, // 127.0.0.0
        .src_mask = 0xFF000000, // /8
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0x7F000000,
        .dst_mask = 0xFF000000,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("Allow loopback"),
    });

    // =========================================================================
    // Rule 2: Block ICMP (if configured)
    // Priority: 10
    // =========================================================================
    if (config.block_icmp) {
        _ = addRule(.{
            .id = 2,
            .priority = 10,
            .enabled = true,
            .direction = .inbound,
            .protocol = .icmp,
            .src_ip = 0,
            .src_mask = 0,
            .src_port_start = 0,
            .src_port_end = 0,
            .dst_ip = 0,
            .dst_mask = 0,
            .dst_port_start = 0,
            .dst_port_end = 0,
            .action = .drop,
            .require_peer_id = false,
            .peer_id = null,
            .match_count = 0,
            .last_match = 0,
            .description = makeDescription("Block ICMP"),
        });
    }

    // =========================================================================
    // Rule 3: DISABLED - Allow established
    // NOTE: Connection tracking is done BEFORE rule matching in filterInbound()
    //       so this rule is redundant and causes false positives
    // =========================================================================
    _ = addRule(.{
        .id = 3,
        .priority = 20,
        .enabled = false, // DISABLED - handled by connection tracking
        .direction = .inbound,
        .protocol = .tcp,
        .src_ip = 0,
        .src_mask = 0,
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("Allow established (disabled)"),
    });

    // =========================================================================
    // Rule 4: QEMU gateway (10.0.2.2)
    // Priority: 15
    // =========================================================================
    _ = addRule(.{
        .id = 4,
        .priority = 15,
        .enabled = true,
        .direction = .both,
        .protocol = .any,
        .src_ip = 0x0A000202, // 10.0.2.2
        .src_mask = 0xFFFFFFFF,
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("QEMU gateway"),
    });

    // =========================================================================
    // Rule 5: QEMU DNS (10.0.2.3:53)
    // Priority: 15
    // =========================================================================
    _ = addRule(.{
        .id = 5,
        .priority = 15,
        .enabled = true,
        .direction = .both,
        .protocol = .udp,
        .src_ip = 0x0A000203, // 10.0.2.3
        .src_mask = 0xFFFFFFFF,
        .src_port_start = 53,
        .src_port_end = 53,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("QEMU DNS"),
    });

    // =========================================================================
    // Rule 6: QEMU local subnet (10.0.2.0/24 <-> 10.0.2.0/24)
    // Priority: 25
    // NOTE: Both src AND dst must be in local subnet
    // =========================================================================
    _ = addRule(.{
        .id = 6,
        .priority = 25,
        .enabled = true,
        .direction = .both,
        .protocol = .any,
        .src_ip = 0x0A000200, // 10.0.2.0
        .src_mask = 0xFFFFFF00, // /24
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0x0A000200, // 10.0.2.0
        .dst_mask = 0xFFFFFF00, // /24
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("QEMU local subnet"),
    });

    // =========================================================================
    // Rule 100: Default deny inbound
    // Priority: 65534 (very low = last to match)
    // =========================================================================
    _ = addRule(.{
        .id = 100,
        .priority = 65534,
        .enabled = true,
        .direction = .inbound,
        .protocol = .any,
        .src_ip = 0,
        .src_mask = 0,
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .drop,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("Default deny inbound"),
    });

    // =========================================================================
    // Rule 101: Allow all outbound
    // Priority: 65535 (lowest)
    // =========================================================================
    _ = addRule(.{
        .id = 101,
        .priority = 65535,
        .enabled = true,
        .direction = .outbound,
        .protocol = .any,
        .src_ip = 0,
        .src_mask = 0,
        .src_port_start = 0,
        .src_port_end = 65535,
        .dst_ip = 0,
        .dst_mask = 0,
        .dst_port_start = 0,
        .dst_port_end = 65535,
        .action = .allow,
        .require_peer_id = false,
        .peer_id = null,
        .match_count = 0,
        .last_match = 0,
        .description = makeDescription("Allow outbound"),
    });
}

fn makeDescription(text: []const u8) [64]u8 {
    var desc: [64]u8 = [_]u8{0} ** 64;
    const len = @min(text.len, 63);
    for (0..len) |i| {
        desc[i] = text[i];
    }
    return desc;
}

// ============================================================================
// Rule Management
// ============================================================================

pub fn addRule(rule: Rule) bool {
    if (rule_count >= MAX_RULES) return false;

    // Find insertion position (sorted by priority)
    var insert_pos: usize = rule_count;
    for (0..rule_count) |i| {
        if (rule.priority < rules[i].priority) {
            insert_pos = i;
            break;
        }
    }

    // Shift rules to make room
    if (insert_pos < rule_count) {
        var i = rule_count;
        while (i > insert_pos) : (i -= 1) {
            rules[i] = rules[i - 1];
        }
    }

    rules[insert_pos] = rule;
    rule_count += 1;
    return true;
}

pub fn removeRule(id: u32) bool {
    for (0..rule_count) |i| {
        if (rules[i].id == id) {
            for (i..rule_count - 1) |j| {
                rules[j] = rules[j + 1];
            }
            rule_count -= 1;
            return true;
        }
    }
    return false;
}

pub fn enableRule(id: u32, enabled: bool) bool {
    for (0..rule_count) |i| {
        if (rules[i].id == id) {
            rules[i].enabled = enabled;
            return true;
        }
    }
    return false;
}

pub fn getRuleCount() usize {
    return rule_count;
}

pub fn getRule(index: usize) ?*const Rule {
    if (index >= rule_count) return null;
    return &rules[index];
}

// ============================================================================
// Blacklist Management
// ============================================================================

pub fn addToBlacklist(ip: u32, duration_sec: u64, reason: []const u8) bool {
    const now = getTimestamp();

    // Check if already exists - update expiry
    for (0..blacklist_count) |i| {
        if (blacklist[i].ip == ip) {
            blacklist[i].expires_at = now + (duration_sec * 1000);
            blacklist[i].hit_count += 1;
            return true;
        }
    }

    // Remove oldest if full
    if (blacklist_count >= MAX_BLACKLIST) {
        var oldest_idx: usize = 0;
        var oldest_time: u64 = 0xFFFFFFFFFFFFFFFF;

        for (0..blacklist_count) |i| {
            if (!blacklist[i].permanent and blacklist[i].added_at < oldest_time) {
                oldest_time = blacklist[i].added_at;
                oldest_idx = i;
            }
        }

        if (!blacklist[oldest_idx].permanent) {
            for (oldest_idx..blacklist_count - 1) |j| {
                blacklist[j] = blacklist[j + 1];
            }
            blacklist_count -= 1;
        } else {
            return false;
        }
    }

    // Create reason buffer
    var r: [64]u8 = [_]u8{0} ** 64;
    const len = @min(reason.len, 63);
    for (0..len) |i| {
        r[i] = reason[i];
    }

    // Add entry
    blacklist[blacklist_count] = BlacklistEntry{
        .ip = ip,
        .added_at = now,
        .expires_at = now + (duration_sec * 1000),
        .permanent = false,
        .reason = r,
        .hit_count = 1,
    };
    blacklist_count += 1;

    // Log only to serial if enabled
    if (config.log_to_serial) {
        serial.writeString("[FW] Blacklisted: ");
        printIP(ip);
        serial.writeString("\n");
    }

    return true;
}

pub fn isBlacklisted(ip: u32) bool {
    const now = getTimestamp();

    var i: usize = 0;
    while (i < blacklist_count) {
        if (blacklist[i].ip == ip) {
            // Check expiry
            if (!blacklist[i].permanent and blacklist[i].expires_at < now) {
                // Expired - remove
                for (i..blacklist_count - 1) |j| {
                    blacklist[j] = blacklist[j + 1];
                }
                blacklist_count -= 1;
                return false;
            }
            blacklist[i].hit_count += 1;
            return true;
        }
        i += 1;
    }
    return false;
}

pub fn removeFromBlacklist(ip: u32) bool {
    for (0..blacklist_count) |i| {
        if (blacklist[i].ip == ip) {
            for (i..blacklist_count - 1) |j| {
                blacklist[j] = blacklist[j + 1];
            }
            blacklist_count -= 1;
            return true;
        }
    }
    return false;
}

pub fn getBlacklistCount() usize {
    return blacklist_count;
}

pub fn getBlacklistEntry(index: usize) ?*const BlacklistEntry {
    if (index >= blacklist_count) return null;
    return &blacklist[index];
}

// ============================================================================
// Packet Filtering - Inbound
// ============================================================================

pub fn filterInbound(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    peer_id: ?[32]u8,
) FilterResult {
    stats.packets_total += 1;

    // =========================================
    // CHECK 1: Firewall disabled
    // =========================================
    if (state == .disabled) {
        stats.packets_allowed += 1;
        return .{ .action = .allow, .rule_id = 0, .reason = "Disabled" };
    }

    // =========================================
    // CHECK 2: Lockdown mode
    // =========================================
    if (state == .lockdown) {
        if (!isWhitelisted(src_ip)) {
            stats.packets_dropped += 1;
            return .{ .action = .drop, .rule_id = 0, .reason = "Lockdown" };
        }
    }

    // =========================================
    // CHECK 3: Blacklist
    // =========================================
    if (isBlacklisted(src_ip)) {
        stats.packets_dropped += 1;
        stats.blocked_blacklist += 1;
        return .{ .action = .drop, .rule_id = 0, .reason = "Blacklisted" };
    }

    // =========================================
    // CHECK 4: Rate limiting
    // =========================================
    if (config.enable_rate_limit) {
        const rate_result = checkRateLimit(src_ip, protocol);
        if (!rate_result.allowed) {
            stats.packets_dropped += 1;
            stats.blocked_rate_limit += 1;
            if (config.auto_blacklist) {
                recordViolation(src_ip);
            }
            return .{ .action = .drop, .rule_id = 0, .reason = rate_result.reason };
        }
    }

    // =========================================
    // CHECK 5: P2P-only mode
    // =========================================
    if (config.p2p_only_mode and peer_id == null) {
        const is_local = (src_ip & 0xFFFFFF00) == 0x0A000200; // 10.0.2.0/24
        const is_loopback = (src_ip >> 24) == 127;

        if (!is_local and !is_loopback) {
            if (!isRegisteredPeerIP(src_ip)) {
                stats.packets_dropped += 1;
                stats.blocked_no_peer += 1;
                return .{ .action = .drop, .rule_id = 0, .reason = "Unknown peer" };
            }
        }
    }

    // =========================================
    // CHECK 6: Established connection tracking (TCP only)
    // =========================================
    if (protocol == 6) { // TCP
        if (isEstablishedConnection(src_ip, src_port, dst_ip, dst_port)) {
            stats.packets_allowed += 1;
            return .{ .action = .allow, .rule_id = 3, .reason = "Established" };
        }
    }

    // =========================================
    // CHECK 7: Match against rules
    // =========================================
    const proto = protocolFromU8(protocol);

    for (0..rule_count) |i| {
        const rule = &rules[i];

        if (!rule.enabled) continue;
        if (rule.direction != .inbound and rule.direction != .both) continue;

        if (matchRule(rule, src_ip, dst_ip, proto, src_port, dst_port, peer_id)) {
            rule.match_count += 1;
            rule.last_match = getTimestamp();

            switch (rule.action) {
                .allow => {
                    stats.packets_allowed += 1;
                    return .{ .action = .allow, .rule_id = rule.id, .reason = "Rule" };
                },
                .drop => {
                    stats.packets_dropped += 1;
                    incrementBlockedByProtocol(proto);
                    return .{ .action = .drop, .rule_id = rule.id, .reason = "Rule drop" };
                },
                .reject => {
                    stats.packets_rejected += 1;
                    return .{ .action = .reject, .rule_id = rule.id, .reason = "Rule reject" };
                },
                .log => continue,
                .rate_limit => continue,
            }
        }
    }

    // =========================================
    // DEFAULT: Deny
    // =========================================
    stats.packets_dropped += 1;
    stats.blocked_no_rule += 1;
    return .{ .action = .drop, .rule_id = 0, .reason = "Default deny" };
}

// ============================================================================
// Packet Filtering - Outbound
// ============================================================================

pub fn filterOutbound(
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
) FilterResult {
    stats.packets_total += 1;

    if (state == .disabled) {
        stats.packets_allowed += 1;
        return .{ .action = .allow, .rule_id = 0, .reason = "Disabled" };
    }

    // Check if destination is blacklisted
    if (isBlacklisted(dst_ip)) {
        stats.packets_dropped += 1;
        return .{ .action = .drop, .rule_id = 0, .reason = "Dst blacklisted" };
    }

    const proto = protocolFromU8(protocol);

    // Match against rules
    for (0..rule_count) |i| {
        const rule = &rules[i];

        if (!rule.enabled) continue;
        if (rule.direction != .outbound and rule.direction != .both) continue;

        if (matchRule(rule, src_ip, dst_ip, proto, src_port, dst_port, null)) {
            rule.match_count += 1;
            rule.last_match = getTimestamp();

            if (rule.action == .allow) {
                stats.packets_allowed += 1;
                // Track outbound TCP for established connection detection
                if (protocol == 6) {
                    trackConnection(src_ip, src_port, dst_ip, dst_port, proto);
                }
                return .{ .action = .allow, .rule_id = rule.id, .reason = "Rule" };
            } else if (rule.action == .drop) {
                stats.packets_dropped += 1;
                return .{ .action = .drop, .rule_id = rule.id, .reason = "Rule drop" };
            }
        }
    }

    // Default allow outbound
    stats.packets_allowed += 1;
    return .{ .action = .allow, .rule_id = 0, .reason = "Default allow" };
}

// ============================================================================
// Rule Matching
// ============================================================================

fn matchRule(
    rule: *const Rule,
    src_ip: u32,
    dst_ip: u32,
    protocol: Protocol,
    src_port: u16,
    dst_port: u16,
    peer_id: ?[32]u8,
) bool {
    // Protocol check
    if (rule.protocol != .any and rule.protocol != protocol) return false;

    // Source IP check
    if (rule.src_ip != 0) {
        if ((src_ip & rule.src_mask) != (rule.src_ip & rule.src_mask)) return false;
    }

    // Destination IP check
    if (rule.dst_ip != 0) {
        if ((dst_ip & rule.dst_mask) != (rule.dst_ip & rule.dst_mask)) return false;
    }

    // Source port check
    if (rule.src_port_start != 0 or rule.src_port_end != 0) {
        if (src_port < rule.src_port_start or src_port > rule.src_port_end) return false;
    }

    // Destination port check
    if (rule.dst_port_start != 0 or rule.dst_port_end != 0) {
        if (dst_port < rule.dst_port_start or dst_port > rule.dst_port_end) return false;
    }

    // Peer ID check
    if (rule.require_peer_id) {
        if (peer_id == null) return false;
        if (rule.peer_id) |required_peer| {
            const pid = peer_id.?;
            for (0..32) |j| {
                if (pid[j] != required_peer[j]) return false;
            }
        }
    }

    return true;
}

// ============================================================================
// Rate Limiting
// ============================================================================

const RateLimitResult = struct {
    allowed: bool,
    reason: []const u8,
};

fn checkRateLimit(ip: u32, protocol: u8) RateLimitResult {
    const now = getTimestamp();
    var entry: ?*RateLimitEntry = null;

    // Find existing entry
    for (0..rate_limit_count) |i| {
        if (rate_limits[i].ip == ip) {
            entry = &rate_limits[i];
            break;
        }
    }

    // Create new entry if not found
    if (entry == null) {
        if (rate_limit_count >= MAX_RATE_ENTRIES) {
            // Remove first entry
            rate_limits[0] = rate_limits[rate_limit_count - 1];
            rate_limit_count -= 1;
        }

        rate_limits[rate_limit_count] = RateLimitEntry{
            .ip = ip,
            .packets_this_second = 0,
            .connections_active = 0,
            .syn_count = 0,
            .last_reset = now,
            .violations = 0,
        };
        entry = &rate_limits[rate_limit_count];
        rate_limit_count += 1;
    }

    var e = entry.?;

    // Reset counters if window passed
    if (now > e.last_reset and now - e.last_reset >= 1000) {
        e.packets_this_second = 0;
        e.syn_count = 0;
        e.last_reset = now;
    }

    e.packets_this_second += 1;

    // Check packet rate
    if (e.packets_this_second > config.max_packets_per_second) {
        e.violations += 1;
        return .{ .allowed = false, .reason = "Rate limit" };
    }

    // Check SYN flood for TCP
    if (protocol == 6) {
        e.syn_count += 1;
        if (e.syn_count > config.syn_flood_threshold) {
            stats.blocked_syn_flood += 1;
            e.violations += 1;
            return .{ .allowed = false, .reason = "SYN flood" };
        }
    }

    // Check connection limit
    if (e.connections_active > config.max_connections_per_ip) {
        e.violations += 1;
        return .{ .allowed = false, .reason = "Too many connections" };
    }

    return .{ .allowed = true, .reason = "" };
}

fn recordViolation(ip: u32) void {
    for (0..rate_limit_count) |i| {
        if (rate_limits[i].ip == ip) {
            rate_limits[i].violations += 1;
            if (rate_limits[i].violations >= config.blacklist_threshold) {
                _ = addToBlacklist(ip, config.blacklist_duration_sec, "Auto: violations");
            }
            break;
        }
    }
}

// ============================================================================
// Connection Tracking
// ============================================================================

fn trackConnection(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, protocol: Protocol) void {
    if (connection_count >= MAX_CONNECTIONS) {
        // Remove oldest
        for (0..MAX_CONNECTIONS - 1) |i| {
            connections[i] = connections[i + 1];
        }
        connection_count = MAX_CONNECTIONS - 1;
    }

    connections[connection_count] = Connection{
        .src_ip = src_ip,
        .src_port = src_port,
        .dst_ip = dst_ip,
        .dst_port = dst_port,
        .protocol = protocol,
        .conn_state = .syn_sent,
        .created_at = getTimestamp(),
        .last_activity = getTimestamp(),
        .packets_in = 0,
        .packets_out = 1,
        .bytes_in = 0,
        .bytes_out = 0,
        .peer_id = null,
    };
    connection_count += 1;
    stats.connections_total += 1;
    stats.connections_active += 1;
}

fn isEstablishedConnection(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) bool {
    for (0..connection_count) |i| {
        const conn = &connections[i];
        // Match reverse direction (response to our outbound)
        if (conn.dst_ip == src_ip and conn.dst_port == src_port and
            conn.src_ip == dst_ip and conn.src_port == dst_port)
        {
            if (conn.conn_state == .established or conn.conn_state == .syn_sent) {
                conn.last_activity = getTimestamp();
                conn.packets_in += 1;
                conn.conn_state = .established;
                return true;
            }
        }
    }
    return false;
}

pub fn getActiveConnections() usize {
    return connection_count;
}

// ============================================================================
// Port Scan Detection
// ============================================================================

pub fn detectPortScan(src_ip: u32, dst_port: u16) bool {
    const now = getTimestamp();
    const SCAN_WINDOW_MS: u64 = 5000;
    const SCAN_THRESHOLD: u8 = 10;

    var tracker: ?*PortScanTracker = null;

    // Find existing tracker
    for (0..scan_tracker_count) |i| {
        if (scan_trackers[i].ip == src_ip) {
            tracker = &scan_trackers[i];
            break;
        }
    }

    // Create new tracker
    if (tracker == null) {
        if (scan_tracker_count >= MAX_SCAN_TRACKERS) return false;
        scan_trackers[scan_tracker_count] = PortScanTracker{
            .ip = src_ip,
            .ports_accessed = [_]u16{0} ** 64,
            .port_count = 0,
            .first_seen = now,
            .last_seen = now,
        };
        tracker = &scan_trackers[scan_tracker_count];
        scan_tracker_count += 1;
    }

    var t = tracker.?;

    // Reset if window expired
    if (now > t.first_seen and now - t.first_seen > SCAN_WINDOW_MS) {
        t.port_count = 0;
        t.first_seen = now;
    }

    // Check if port already seen
    var port_exists = false;
    for (0..t.port_count) |i| {
        if (t.ports_accessed[i] == dst_port) {
            port_exists = true;
            break;
        }
    }

    // Add new port
    if (!port_exists and t.port_count < 64) {
        t.ports_accessed[t.port_count] = dst_port;
        t.port_count += 1;
    }

    t.last_seen = now;

    // Check threshold
    if (t.port_count >= SCAN_THRESHOLD) {
        stats.blocked_port_scan += 1;

        if (config.log_to_serial) {
            serial.writeString("[FW] Port scan: ");
            printIP(src_ip);
            serial.writeString("\n");
        }

        if (config.auto_blacklist) {
            _ = addToBlacklist(src_ip, config.blacklist_duration_sec, "Port scan");
        }
        t.port_count = 0;
        return true;
    }

    return false;
}

// ============================================================================
// Helpers
// ============================================================================

fn isWhitelisted(ip: u32) bool {
    // Loopback
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    // QEMU subnet
    if ((ip & 0xFFFFFF00) == 0x0A000200) return true;
    return false;
}

fn isRegisteredPeerIP(ip: u32) bool {
    // TODO: Integrate with P2P peer registry
    _ = ip;
    return true;
}

fn protocolFromU8(protocol: u8) Protocol {
    return switch (protocol) {
        1 => .icmp,
        6 => .tcp,
        17 => .udp,
        else => .any,
    };
}

fn incrementBlockedByProtocol(protocol: Protocol) void {
    switch (protocol) {
        .icmp => stats.icmp_blocked += 1,
        .tcp => stats.tcp_blocked += 1,
        .udp => stats.udp_blocked += 1,
        .any => {},
    }
}

fn getTimestamp() u64 {
    return timer.getTicks();
}

fn printIP(ip: u32) void {
    printNumber((ip >> 24) & 0xFF);
    serial.writeString(".");
    printNumber((ip >> 16) & 0xFF);
    serial.writeString(".");
    printNumber((ip >> 8) & 0xFF);
    serial.writeString(".");
    printNumber(ip & 0xFF);
}

fn printNumber(n: anytype) void {
    const val: u32 = @intCast(n);
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

fn printLine(len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        serial.writeChar('-');
    }
    serial.writeString("\n");
}

// ============================================================================
// Public API
// ============================================================================

pub fn isInitialized() bool {
    return rules_initialized;
}

pub fn setState(new_state: FirewallState) void {
    state = new_state;
    // Silent - no logging (for tests)
}

pub fn setStateWithLog(new_state: FirewallState) void {
    const old_state = state;
    state = new_state;
    serial.writeString("[FIREWALL] ");
    serial.writeString(switch (old_state) {
        .disabled => "DISABLED",
        .permissive => "PERMISSIVE",
        .enforcing => "ENFORCING",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString(" -> ");
    serial.writeString(switch (new_state) {
        .disabled => "DISABLED",
        .permissive => "PERMISSIVE",
        .enforcing => "ENFORCING",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString("\n");
}

pub fn setStealthMode(enabled: bool) void {
    config.stealth_mode = enabled;
}

pub fn setP2POnlyMode(enabled: bool) void {
    config.p2p_only_mode = enabled;
}

pub fn getStats() FirewallStats {
    return stats;
}

pub fn resetStats() void {
    stats = FirewallStats{};
    stats.last_reset = getTimestamp();
}

pub fn printStatus() void {
    serial.writeString("\n[FIREWALL STATUS] ");
    printLine(25);

    serial.writeString("  State:       ");
    serial.writeString(switch (state) {
        .disabled => "DISABLED",
        .permissive => "PERMISSIVE",
        .enforcing => "ENFORCING",
        .lockdown => "LOCKDOWN",
    });
    serial.writeString("\n");

    serial.writeString("  Stealth:     ");
    serial.writeString(if (config.stealth_mode) "ON" else "OFF");
    serial.writeString("\n");

    serial.writeString("  P2P-only:    ");
    serial.writeString(if (config.p2p_only_mode) "ON" else "OFF");
    serial.writeString("\n");

    serial.writeString("  Rules:       ");
    printNumber(rule_count);
    serial.writeString("\n");

    serial.writeString("  Blacklist:   ");
    printNumber(blacklist_count);
    serial.writeString("\n");

    printLine(45);

    serial.writeString("  Packets:     ");
    printNumber(stats.packets_total);
    serial.writeString("\n");

    serial.writeString("  Allowed:     ");
    printNumber(stats.packets_allowed);
    serial.writeString("\n");

    serial.writeString("  Dropped:     ");
    printNumber(stats.packets_dropped);
    serial.writeString("\n");

    serial.writeString("  Connections: ");
    printNumber(connection_count);
    serial.writeString("\n");

    printLine(45);
    serial.writeString("\n");
}
