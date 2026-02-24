//! Zamrud OS - DHCP Security Module (H.6)
//! Rogue DHCP detection, offer validation, trusted server pinning
//! Pattern follows arp_defense.zig

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const Config = struct {
    enabled: bool,
    trust_first_server: bool,
    validate_offers: bool,
    detect_rogue: bool,
    rate_limit_enabled: bool,
    require_gateway: bool,
    require_dns: bool,
    static_fallback_active: bool,
    max_offers_per_cycle: u8,
    max_packets_per_window: u16,
};

pub var config = Config{
    .enabled = true,
    .trust_first_server = true,
    .validate_offers = true,
    .detect_rogue = true,
    .rate_limit_enabled = true,
    .require_gateway = true,
    .require_dns = false,
    .static_fallback_active = false,
    .max_offers_per_cycle = 3,
    .max_packets_per_window = 50,
};

// =============================================================================
// Trusted Server
// =============================================================================

pub const TrustedServer = struct {
    ip: u32,
    pinned: bool,
    offers_seen: u32,
    acks_seen: u32,
};

var trusted_server: TrustedServer = .{
    .ip = 0,
    .pinned = false,
    .offers_seen = 0,
    .acks_seen = 0,
};

// =============================================================================
// Known Servers (for rogue detection)
// =============================================================================

const MAX_KNOWN_SERVERS: usize = 8;

var known_servers: [MAX_KNOWN_SERVERS]u32 = [_]u32{0} ** MAX_KNOWN_SERVERS;
var known_server_count: usize = 0;

// =============================================================================
// Static Fallback
// =============================================================================

pub const StaticConfig = struct {
    ip_addr: u32,
    subnet_mask: u32,
    gateway: u32,
    dns_server: u32,
    configured: bool,
};

var static_fallback: StaticConfig = .{
    .ip_addr = 0,
    .subnet_mask = 0,
    .gateway = 0,
    .dns_server = 0,
    .configured = false,
};

// =============================================================================
// Stats
// =============================================================================

pub const Stats = struct {
    offers_accepted: u32,
    offers_rejected: u32,
    rogue_detections: u32,
    rate_limit_hits: u32,
    packets_seen: u32,
    acks_verified: u32,
    acks_rejected: u32,
    servers_seen: u8,
};

var stats: Stats = .{
    .offers_accepted = 0,
    .offers_rejected = 0,
    .rogue_detections = 0,
    .rate_limit_hits = 0,
    .packets_seen = 0,
    .acks_verified = 0,
    .acks_rejected = 0,
    .servers_seen = 0,
};

// =============================================================================
// Event Log
// =============================================================================

pub const EventType = enum(u8) {
    offer_accepted = 0,
    offer_rejected = 1,
    rogue_detected = 2,
    rate_limited = 3,
    server_pinned = 4,
    fallback_activated = 5,
    ack_rejected = 6,
};

pub const Event = struct {
    event_type: EventType,
    server_ip: u32,
    valid: bool,
};

const MAX_EVENTS: usize = 16;
var events: [MAX_EVENTS]Event = undefined;
var event_count: usize = 0;

// =============================================================================
// Rate Limiting
// =============================================================================

var rate_window_count: u16 = 0;
var rate_window_offers: u8 = 0;

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    trusted_server = .{
        .ip = 0,
        .pinned = false,
        .offers_seen = 0,
        .acks_seen = 0,
    };

    known_server_count = 0;
    var i: usize = 0;
    while (i < MAX_KNOWN_SERVERS) : (i += 1) {
        known_servers[i] = 0;
    }

    static_fallback = .{
        .ip_addr = 0,
        .subnet_mask = 0,
        .gateway = 0,
        .dns_server = 0,
        .configured = false,
    };

    stats = .{
        .offers_accepted = 0,
        .offers_rejected = 0,
        .rogue_detections = 0,
        .rate_limit_hits = 0,
        .packets_seen = 0,
        .acks_verified = 0,
        .acks_rejected = 0,
        .servers_seen = 0,
    };

    event_count = 0;
    i = 0;
    while (i < MAX_EVENTS) : (i += 1) {
        events[i].valid = false;
        events[i].server_ip = 0;
        events[i].event_type = .offer_accepted;
    }

    rate_window_count = 0;
    rate_window_offers = 0;

    initialized = true;
    serial.writeString("[DHCP-SEC] Initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn isEnabled() bool {
    return initialized and config.enabled;
}

// =============================================================================
// Rate Limiting
// =============================================================================

/// Check if packet is within rate limit. Returns true if allowed.
pub fn checkRateLimit() bool {
    if (!config.rate_limit_enabled) return true;

    rate_window_count += 1;
    stats.packets_seen += 1;

    if (rate_window_count > config.max_packets_per_window) {
        stats.rate_limit_hits += 1;
        logEvent(.rate_limited, 0);
        serial.writeString("[DHCP-SEC] Rate limit exceeded\n");
        return false;
    }

    return true;
}

/// Reset rate limit window (call periodically)
pub fn resetRateWindow() void {
    rate_window_count = 0;
    rate_window_offers = 0;
}

pub fn getRateCount() u16 {
    return rate_window_count;
}

// =============================================================================
// Offer Validation
// =============================================================================

/// Validate a DHCP offer. Returns true if offer is sane.
pub fn validateOffer(offered_ip: u32, subnet: u32, gateway: u32, dns: u32) bool {
    if (!config.validate_offers) return true;

    // Reject 0.0.0.0
    if (offered_ip == 0) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: offered IP = 0.0.0.0\n");
        return false;
    }

    // Reject broadcast 255.255.255.255
    if (offered_ip == 0xFFFFFFFF) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: offered IP = broadcast\n");
        return false;
    }

    // Reject loopback 127.x.x.x
    if ((offered_ip >> 24) == 127) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: offered IP = loopback\n");
        return false;
    }

    // Reject multicast 224-239.x.x.x
    const first_octet = offered_ip >> 24;
    if (first_octet >= 224 and first_octet <= 239) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: offered IP = multicast\n");
        return false;
    }

    // Subnet must not be zero (if validating)
    if (subnet == 0) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: subnet = 0\n");
        return false;
    }

    // Gateway required?
    if (config.require_gateway and gateway == 0) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: no gateway\n");
        return false;
    }

    // DNS required?
    if (config.require_dns and dns == 0) {
        stats.offers_rejected += 1;
        logEvent(.offer_rejected, 0);
        serial.writeString("[DHCP-SEC] Rejected: no DNS\n");
        return false;
    }

    // Gateway in same subnet as offered IP?
    if (gateway != 0 and subnet != 0) {
        if ((offered_ip & subnet) != (gateway & subnet)) {
            stats.offers_rejected += 1;
            logEvent(.offer_rejected, 0);
            serial.writeString("[DHCP-SEC] Rejected: gateway not in subnet\n");
            return false;
        }
    }

    stats.offers_accepted += 1;
    logEvent(.offer_accepted, 0);
    return true;
}

// =============================================================================
// Server Trust & Rogue Detection
// =============================================================================

/// Check if a DHCP server is trusted. Pins on first use.
/// Returns true if server is allowed, false if rogue.
pub fn checkServer(server_ip: u32) bool {
    if (!config.detect_rogue) return true;
    if (server_ip == 0) return true;

    // Track offer count in this window
    rate_window_offers += 1;

    // Record this server
    recordServer(server_ip);

    // Trust-on-first-use: pin first server
    if (config.trust_first_server and !trusted_server.pinned) {
        pinServer(server_ip);
        return true;
    }

    // Check against trusted server
    if (trusted_server.pinned) {
        if (server_ip == trusted_server.ip) {
            trusted_server.offers_seen += 1;
            return true;
        } else {
            // Rogue detected!
            stats.rogue_detections += 1;
            logEvent(.rogue_detected, server_ip);
            serial.writeString("[DHCP-SEC] ROGUE SERVER DETECTED: ");
            printIp(server_ip);
            serial.writeString(" (trusted: ");
            printIp(trusted_server.ip);
            serial.writeString(")\n");
            return false;
        }
    }

    // Too many offers from different servers?
    if (rate_window_offers > config.max_offers_per_cycle) {
        stats.rogue_detections += 1;
        logEvent(.rogue_detected, server_ip);
        serial.writeString("[DHCP-SEC] Too many offers - rogue suspected\n");
        return false;
    }

    return true;
}

/// Verify ACK comes from trusted server
pub fn verifyAck(server_ip: u32) bool {
    if (!config.detect_rogue) return true;
    if (server_ip == 0) return true;

    if (trusted_server.pinned) {
        if (server_ip == trusted_server.ip) {
            trusted_server.acks_seen += 1;
            stats.acks_verified += 1;
            return true;
        } else {
            stats.acks_rejected += 1;
            logEvent(.ack_rejected, server_ip);
            serial.writeString("[DHCP-SEC] ACK from untrusted server!\n");
            return false;
        }
    }

    // No pinned server - accept but pin
    if (config.trust_first_server) {
        pinServer(server_ip);
    }
    stats.acks_verified += 1;
    return true;
}

/// Pin a server as trusted
pub fn pinServer(server_ip: u32) void {
    trusted_server.ip = server_ip;
    trusted_server.pinned = true;
    trusted_server.offers_seen = 1;
    trusted_server.acks_seen = 0;
    logEvent(.server_pinned, server_ip);
    serial.writeString("[DHCP-SEC] Pinned trusted server: ");
    printIp(server_ip);
    serial.writeString("\n");
}

/// Clear trusted server (for re-discovery)
pub fn clearTrustedServer() void {
    trusted_server.ip = 0;
    trusted_server.pinned = false;
    trusted_server.offers_seen = 0;
    trusted_server.acks_seen = 0;
}

/// Check if a specific server IP is trusted
pub fn isServerTrusted(server_ip: u32) bool {
    if (!trusted_server.pinned) return false;
    return trusted_server.ip == server_ip;
}

/// Get trusted server info
pub fn getTrustedServer() *const TrustedServer {
    return &trusted_server;
}

/// Track known server IPs (for rogue detection)
fn recordServer(server_ip: u32) void {
    // Check if already known
    var i: usize = 0;
    while (i < known_server_count) : (i += 1) {
        if (known_servers[i] == server_ip) return;
    }

    // Add new server
    if (known_server_count < MAX_KNOWN_SERVERS) {
        known_servers[known_server_count] = server_ip;
        known_server_count += 1;
        stats.servers_seen = @intCast(known_server_count);
    }
}

/// Get number of distinct DHCP servers seen
pub fn getServerCount() usize {
    return known_server_count;
}

// =============================================================================
// Static Fallback
// =============================================================================

/// Set static fallback configuration
pub fn setStaticFallback(ip: u32, subnet: u32, gateway: u32, dns: u32) void {
    static_fallback.ip_addr = ip;
    static_fallback.subnet_mask = subnet;
    static_fallback.gateway = gateway;
    static_fallback.dns_server = dns;
    static_fallback.configured = true;
}

/// Get static fallback config
pub fn getStaticFallback() *const StaticConfig {
    return &static_fallback;
}

/// Activate static fallback mode
pub fn activateFallback() bool {
    if (!static_fallback.configured) return false;
    config.static_fallback_active = true;
    logEvent(.fallback_activated, 0);
    serial.writeString("[DHCP-SEC] Static fallback ACTIVATED\n");
    return true;
}

/// Check if fallback is active
pub fn isFallbackActive() bool {
    return config.static_fallback_active;
}

/// Deactivate fallback
pub fn deactivateFallback() void {
    config.static_fallback_active = false;
}

// =============================================================================
// Event Log
// =============================================================================

fn logEvent(event_type: EventType, server_ip: u32) void {
    if (event_count >= MAX_EVENTS) return;

    events[event_count] = .{
        .event_type = event_type,
        .server_ip = server_ip,
        .valid = true,
    };
    event_count += 1;
}

pub fn getEventCount() usize {
    return event_count;
}

pub fn getEvent(index: usize) ?*const Event {
    if (index >= event_count) return null;
    if (!events[index].valid) return null;
    return &events[index];
}

pub fn clearEvents() void {
    event_count = 0;
    var i: usize = 0;
    while (i < MAX_EVENTS) : (i += 1) {
        events[i].valid = false;
    }
}

// =============================================================================
// Stats
// =============================================================================

pub fn getStats() *const Stats {
    return &stats;
}

pub fn resetStats() void {
    stats = .{
        .offers_accepted = 0,
        .offers_rejected = 0,
        .rogue_detections = 0,
        .rate_limit_hits = 0,
        .packets_seen = 0,
        .acks_verified = 0,
        .acks_rejected = 0,
        .servers_seen = 0,
    };
}

// =============================================================================
// Helpers
// =============================================================================

fn printIp(ip: u32) void {
    printDec(@intCast((ip >> 24) & 0xFF));
    serial.writeChar('.');
    printDec(@intCast((ip >> 16) & 0xFF));
    serial.writeChar('.');
    printDec(@intCast((ip >> 8) & 0xFF));
    serial.writeChar('.');
    printDec(@intCast(ip & 0xFF));
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

// =============================================================================
// Test Suite - 20 Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  H.6: DHCP SECURITY TESTS\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // -- Initialization (3 tests) --

    serial.writeString("  -- Initialization --\n");

    // Test 1: Module init
    serial.writeString("  [1]  Module initialized...... ");
    {
        init();
        if (initialized) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 2: Default config
    serial.writeString("  [2]  Default config.......... ");
    {
        if (config.enabled and config.trust_first_server and
            config.validate_offers and config.detect_rogue and
            config.require_gateway and !config.static_fallback_active)
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 3: Stats zeroed
    serial.writeString("  [3]  Stats zeroed............ ");
    {
        const s = getStats();
        if (s.offers_accepted == 0 and s.offers_rejected == 0 and
            s.rogue_detections == 0 and s.packets_seen == 0)
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // -- Trusted Server Pinning (4 tests) --

    serial.writeString("  -- Trusted Server Pinning --\n");

    // Test 4: Pin server
    serial.writeString("  [4]  Pin server.............. ");
    {
        init();
        pinServer(0xC0A80101); // 192.168.1.1
        if (trusted_server.pinned and trusted_server.ip == 0xC0A80101) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 5: Trusted server recognized
    serial.writeString("  [5]  Trusted server check.... ");
    {
        if (isServerTrusted(0xC0A80101)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 6: Unknown server not trusted
    serial.writeString("  [6]  Unknown not trusted..... ");
    {
        if (!isServerTrusted(0xC0A80102)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 7: Clear trusted
    serial.writeString("  [7]  Clear trusted........... ");
    {
        clearTrustedServer();
        if (!trusted_server.pinned and trusted_server.ip == 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // -- Rogue Detection (3 tests) --

    serial.writeString("  -- Rogue Detection --\n");

    // Test 8: First server OK
    serial.writeString("  [8]  First server OK......... ");
    {
        init();
        if (checkServer(0xC0A80101)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 9: Rogue detected
    serial.writeString("  [9]  Rogue detected.......... ");
    {
        // trusted_server should now be pinned to 0xC0A80101
        if (!checkServer(0xC0A80102)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 10: Rogue counter
    serial.writeString("  [10] Rogue counter........... ");
    {
        if (stats.rogue_detections >= 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // -- Offer Validation (4 tests) --

    serial.writeString("  -- Offer Validation --\n");

    // Test 11: Valid offer
    serial.writeString("  [11] Valid offer accepted.... ");
    {
        init();
        // 192.168.1.100, mask 255.255.255.0, gw 192.168.1.1, dns 8.8.8.8
        if (validateOffer(0xC0A80164, 0xFFFFFF00, 0xC0A80101, 0x08080808)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 12: Zero IP rejected
    serial.writeString("  [12] Zero IP rejected........ ");
    {
        if (!validateOffer(0, 0xFFFFFF00, 0xC0A80101, 0x08080808)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 13: Broadcast rejected
    serial.writeString("  [13] Broadcast rejected...... ");
    {
        if (!validateOffer(0xFFFFFFFF, 0xFFFFFF00, 0xC0A80101, 0x08080808)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 14: Zero subnet rejected
    serial.writeString("  [14] Zero subnet rejected.... ");
    {
        if (!validateOffer(0xC0A80164, 0, 0xC0A80101, 0x08080808)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // -- Rate Limit & Fallback (6 tests) --

    serial.writeString("  -- Rate Limit & Fallback --\n");

    // Test 15: Under limit OK
    serial.writeString("  [15] Under limit OK.......... ");
    {
        init();
        config.max_packets_per_window = 10;
        var ok = true;
        var i: u16 = 0;
        while (i < 5) : (i += 1) {
            if (!checkRateLimit()) {
                ok = false;
                break;
            }
        }
        if (ok) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 16: Over limit blocked
    serial.writeString("  [16] Over limit blocked...... ");
    {
        // Continue from test 15 - already at 5 packets with limit 10
        var i: u16 = 0;
        while (i < 6) : (i += 1) {
            _ = checkRateLimit();
        }
        // Now at 11, should be blocked
        if (!checkRateLimit()) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 17: Flood counter
    serial.writeString("  [17] Flood counter........... ");
    {
        if (stats.rate_limit_hits >= 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 18: Set static config
    serial.writeString("  [18] Set static config....... ");
    {
        init();
        // 10.0.0.50, mask 255.255.255.0, gw 10.0.0.1, dns 10.0.0.1
        setStaticFallback(0x0A000032, 0xFFFFFF00, 0x0A000001, 0x0A000001);
        if (static_fallback.configured and static_fallback.ip_addr == 0x0A000032) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 19: Get static config
    serial.writeString("  [19] Get static config....... ");
    {
        const fb = getStaticFallback();
        if (fb.configured and fb.gateway == 0x0A000001 and
            fb.subnet_mask == 0xFFFFFF00)
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 20: Fallback activation
    serial.writeString("  [20] Fallback activation..... ");
    {
        if (activateFallback() and isFallbackActive()) {
            deactivateFallback();
            if (!isFallbackActive()) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // -- Summary --

    serial.writeString("\n  --------------------------------\n");
    serial.writeString("  H.6 Results: ");
    printDec(passed);
    serial.writeString("/");
    printDec(passed + failed);
    serial.writeString(" passed");
    if (failed == 0) {
        serial.writeString(" OK\n");
    } else {
        serial.writeString(" FAIL\n");
    }
    serial.writeString("\n");

    return failed == 0;
}
