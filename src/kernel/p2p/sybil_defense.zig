//! Zamrud OS - Sybil Attack Defense System (H.3)
//! IP diversity enforcement, rate limiting, pattern detection
//!
//! Prevents:
//! - 1000 fake peers from same /24 subnet
//! - Rapid-fire peer registration floods
//! - Coordinated Sybil patterns

const serial = @import("../drivers/serial/serial.zig");
const reputation = @import("reputation.zig");
const ct = @import("../crypto/constant_time.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_SUBNETS: usize = 128;
pub const MAX_RATE_ENTRIES: usize = 64;
pub const MAX_PEERS_PER_SUBNET: u16 = 5; // Max peers from same /24
pub const MAX_NEW_PEERS_PER_MINUTE: usize = 10; // Rate limit
pub const RATE_WINDOW_SECONDS: u64 = 60; // 1 minute window
pub const ALERT_SUBNET_THRESHOLD: u16 = 3; // Alert after this many

// =============================================================================
// Types
// =============================================================================

pub const RegistrationResult = enum(u8) {
    allowed = 0,
    denied_no_pow = 1,
    denied_invalid_pow = 2,
    denied_rate_limit = 3,
    denied_subnet_limit = 4,
    denied_sybil_detected = 5,
};

pub const SubnetInfo = struct {
    subnet: u24, // First 3 bytes of IP (/24)
    peer_count: u16,
    last_added: u64,
};

pub const RateEntry = struct {
    timestamp: u64,
    ip: u32,
};

pub const SybilAlert = struct {
    alert_type: SybilAlertType,
    subnet: u24,
    peer_count: u16,
    timestamp: u64,
};

pub const SybilAlertType = enum(u8) {
    subnet_flood = 0, // Too many peers from same subnet
    rate_flood = 1, // Too many registrations too fast
    coordinated = 2, // Multiple subnets flooding simultaneously
};

// =============================================================================
// State
// =============================================================================

var subnets: [MAX_SUBNETS]SubnetInfo = undefined;
var subnet_count: usize = 0;

var rate_entries: [MAX_RATE_ENTRIES]RateEntry = undefined;
var rate_count: usize = 0;

var alerts: [16]SybilAlert = undefined;
var alert_count: usize = 0;

var total_registrations: u64 = 0;
var total_denials: u64 = 0;

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&subnets) |*s| {
        s.* = .{ .subnet = 0, .peer_count = 0, .last_added = 0 };
    }
    subnet_count = 0;

    for (&rate_entries) |*r| {
        r.* = .{ .timestamp = 0, .ip = 0 };
    }
    rate_count = 0;

    for (&alerts) |*a| {
        a.* = .{ .alert_type = .subnet_flood, .subnet = 0, .peer_count = 0, .timestamp = 0 };
    }
    alert_count = 0;

    total_registrations = 0;
    total_denials = 0;
    initialized = true;

    serial.writeString("[SYBIL] Defense system initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Registration Check (main entry point)
// =============================================================================

/// Comprehensive check before allowing a new peer
/// Returns allowed only if ALL checks pass
pub fn checkRegistration(
    ip: u32,
    peer_id: *const [32]u8,
    pow_nonce: u64,
    pow_difficulty: u8,
) RegistrationResult {
    // Check 1: PoW verification
    if (pow_difficulty == 0) {
        total_denials += 1;
        return .denied_no_pow;
    }

    if (!reputation.verifyPow(peer_id, pow_nonce, pow_difficulty)) {
        total_denials += 1;
        return .denied_invalid_pow;
    }

    // Check 2: Rate limiting
    if (isRateLimited()) {
        total_denials += 1;
        return .denied_rate_limit;
    }

    // Check 3: Subnet diversity
    const subnet = ipToSubnet(ip);
    const subnet_peers = getSubnetPeerCount(subnet);
    if (subnet_peers >= MAX_PEERS_PER_SUBNET) {
        total_denials += 1;
        addAlert(.subnet_flood, subnet, subnet_peers);
        return .denied_subnet_limit;
    }

    // Check 4: Sybil pattern detection
    if (detectSybilPattern()) {
        total_denials += 1;
        return .denied_sybil_detected;
    }

    // All checks passed
    total_registrations += 1;
    recordRegistration(ip);
    addSubnetPeer(subnet);
    return .allowed;
}

// =============================================================================
// IP Subnet Tracking
// =============================================================================

/// Extract /24 subnet from IP (first 3 bytes)
pub fn ipToSubnet(ip: u32) u24 {
    return @intCast(ip >> 8);
}

/// Get number of peers in a subnet
pub fn getSubnetPeerCount(subnet: u24) u16 {
    for (subnets[0..subnet_count]) |s| {
        if (s.subnet == subnet) return s.peer_count;
    }
    return 0;
}

/// Record a new peer in a subnet
pub fn addSubnetPeer(subnet: u24) void {
    // Find existing
    for (subnets[0..subnet_count]) |*s| {
        if (s.subnet == subnet) {
            s.peer_count +|= 1;
            s.last_added = getTimestamp();
            return;
        }
    }

    // Add new subnet entry
    if (subnet_count < MAX_SUBNETS) {
        subnets[subnet_count] = .{
            .subnet = subnet,
            .peer_count = 1,
            .last_added = getTimestamp(),
        };
        subnet_count += 1;
    }
}

/// Remove a peer from subnet tracking (when peer disconnects)
pub fn removeSubnetPeer(ip: u32) void {
    const subnet = ipToSubnet(ip);
    for (subnets[0..subnet_count]) |*s| {
        if (s.subnet == subnet and s.peer_count > 0) {
            s.peer_count -= 1;
            return;
        }
    }
}

/// Get total number of distinct subnets with peers
pub fn getDistinctSubnetCount() usize {
    var count: usize = 0;
    for (subnets[0..subnet_count]) |s| {
        if (s.peer_count > 0) count += 1;
    }
    return count;
}

/// Calculate diversity score (0-100)
/// Higher = more diverse = better
pub fn getDiversityScore() u8 {
    const distinct = getDistinctSubnetCount();
    const total = reputation.getTrackedCount();

    if (total == 0) return 100; // No peers = max diversity (vacuously)
    if (distinct == 0) return 0;

    // Ideal: each peer in different subnet
    // Score = (distinct_subnets / total_peers) * 100
    const score = (distinct * 100) / total;
    return @intCast(@min(score, 100));
}

// =============================================================================
// Rate Limiting
// =============================================================================

/// Check if rate limit is exceeded
fn isRateLimited() bool {
    cleanExpiredRateEntries();
    return rate_count >= MAX_NEW_PEERS_PER_MINUTE;
}

/// Record a registration for rate tracking
fn recordRegistration(ip: u32) void {
    cleanExpiredRateEntries();

    if (rate_count < MAX_RATE_ENTRIES) {
        rate_entries[rate_count] = .{
            .timestamp = getTimestamp(),
            .ip = ip,
        };
        rate_count += 1;
    }
}

/// Remove expired rate entries
fn cleanExpiredRateEntries() void {
    const now = getTimestamp();
    var write_idx: usize = 0;

    for (0..rate_count) |read_idx| {
        if (now - rate_entries[read_idx].timestamp < RATE_WINDOW_SECONDS) {
            if (write_idx != read_idx) {
                rate_entries[write_idx] = rate_entries[read_idx];
            }
            write_idx += 1;
        }
    }
    rate_count = write_idx;
}

/// Get number of registrations in the current window
pub fn getRecentRegistrationCount() usize {
    cleanExpiredRateEntries();
    return rate_count;
}

// =============================================================================
// Sybil Pattern Detection
// =============================================================================

/// Detect coordinated Sybil attack patterns
fn detectSybilPattern() bool {
    // Pattern 1: Multiple subnets near limit simultaneously
    var subnets_near_limit: usize = 0;
    for (subnets[0..subnet_count]) |s| {
        if (s.peer_count >= ALERT_SUBNET_THRESHOLD) {
            subnets_near_limit += 1;
        }
    }

    // If 3+ subnets are all near limit, likely coordinated
    if (subnets_near_limit >= 3) {
        addAlert(.coordinated, 0, @intCast(subnets_near_limit));
        return true;
    }

    // Pattern 2: Rate close to limit AND subnet pressure
    if (rate_count >= MAX_NEW_PEERS_PER_MINUTE / 2 and subnets_near_limit >= 2) {
        addAlert(.rate_flood, 0, @intCast(rate_count));
        return true;
    }

    return false;
}

// =============================================================================
// Alerts
// =============================================================================

fn addAlert(alert_type: SybilAlertType, subnet: u24, peer_count: u16) void {
    if (alert_count >= alerts.len) {
        // Shift out oldest
        for (0..alerts.len - 1) |i| {
            alerts[i] = alerts[i + 1];
        }
        alert_count = alerts.len - 1;
    }

    alerts[alert_count] = .{
        .alert_type = alert_type,
        .subnet = subnet,
        .peer_count = peer_count,
        .timestamp = getTimestamp(),
    };
    alert_count += 1;

    serial.writeString("[SYBIL] ALERT: ");
    switch (alert_type) {
        .subnet_flood => serial.writeString("Subnet flood detected\n"),
        .rate_flood => serial.writeString("Rate flood detected\n"),
        .coordinated => serial.writeString("Coordinated attack detected\n"),
    }
}

pub fn getAlertCount() usize {
    return alert_count;
}

pub fn getAlert(index: usize) ?*const SybilAlert {
    if (index >= alert_count) return null;
    return &alerts[index];
}

pub fn getTotalRegistrations() u64 {
    return total_registrations;
}

pub fn getTotalDenials() u64 {
    return total_denials;
}

// =============================================================================
// Reset (for testing)
// =============================================================================

pub fn resetForTest() void {
    for (&subnets) |*s| {
        s.* = .{ .subnet = 0, .peer_count = 0, .last_added = 0 };
    }
    subnet_count = 0;
    for (&rate_entries) |*r| {
        r.* = .{ .timestamp = 0, .ip = 0 };
    }
    rate_count = 0;
    for (&alerts) |*a| {
        a.* = .{ .alert_type = .subnet_flood, .subnet = 0, .peer_count = 0, .timestamp = 0 };
    }
    alert_count = 0;
    total_registrations = 0;
    total_denials = 0;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

// =============================================================================
// Tests — 15 tests
// =============================================================================

// Test peer IDs
var test_id: [32]u8 = [_]u8{0} ** 32;

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  SYBIL DEFENSE TESTS (H.3b)\n");
    serial.writeString("========================================\n\n");

    if (!initialized) init();
    resetForTest();

    // Also reset reputation for clean test
    reputation.init();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: IP to subnet
    serial.writeString("  [1]  IP to subnet............ ");
    {
        // 192.168.1.100 = 0xC0A80164
        const ip: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
        const subnet = ipToSubnet(ip);
        // subnet should be 192.168.1 = 0xC0A801
        const expected: u24 = (192 << 16) | (168 << 8) | 1;
        if (subnet == expected) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 2: Subnet tracking — add peer
    serial.writeString("  [2]  Subnet add peer......... ");
    {
        const subnet: u24 = (10 << 16) | (0 << 8) | 1; // 10.0.1.x
        addSubnetPeer(subnet);
        if (getSubnetPeerCount(subnet) == 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 3: Subnet limit enforcement
    serial.writeString("  [3]  Subnet limit (5 max).... ");
    {
        resetForTest();
        const subnet: u24 = (10 << 16) | (0 << 8) | 2;
        var i: usize = 0;
        while (i < MAX_PEERS_PER_SUBNET) : (i += 1) {
            addSubnetPeer(subnet);
        }
        if (getSubnetPeerCount(subnet) >= MAX_PEERS_PER_SUBNET) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 4: Registration allowed with valid PoW + unique subnet
    serial.writeString("  [4]  Registration allowed.... ");
    {
        resetForTest();
        test_id[0] = 0xD1;
        test_id[1] = 0x01;
        if (reputation.generatePow(&test_id, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const ip: u32 = (172 << 24) | (16 << 16) | (0 << 8) | 1;
            const result = checkRegistration(ip, &test_id, nonce, reputation.TEST_POW_DIFFICULTY);
            if (result == .allowed) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (denied)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (pow)\n");
            failed += 1;
        }
    }

    // Test 5: Denied without PoW
    serial.writeString("  [5]  Denied no PoW........... ");
    {
        test_id[0] = 0xD2;
        const ip: u32 = (172 << 24) | (16 << 16) | (1 << 8) | 1;
        const result = checkRegistration(ip, &test_id, 0, 0);
        if (result == .denied_no_pow) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 6: Denied invalid PoW
    serial.writeString("  [6]  Denied invalid PoW...... ");
    {
        test_id[0] = 0xD3;
        const ip: u32 = (172 << 24) | (16 << 16) | (2 << 8) | 1;
        const result = checkRegistration(ip, &test_id, 99999, reputation.TEST_POW_DIFFICULTY);
        if (result == .denied_invalid_pow) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 7: Denied subnet limit
    serial.writeString("  [7]  Denied subnet limit..... ");
    {
        resetForTest();
        // Fill up subnet 10.0.3.x
        const base_ip: u32 = (10 << 24) | (0 << 16) | (3 << 8);
        var i: u32 = 0;
        while (i < MAX_PEERS_PER_SUBNET) : (i += 1) {
            const subnet = ipToSubnet(base_ip | (i + 1));
            addSubnetPeer(subnet);
        }

        // Try one more from same subnet
        test_id[0] = 0xD4;
        test_id[1] = @intCast(i);
        if (reputation.generatePow(&test_id, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const result = checkRegistration(base_ip | 99, &test_id, nonce, reputation.TEST_POW_DIFFICULTY);
            if (result == .denied_subnet_limit) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (pow)\n");
            failed += 1;
        }
    }

    // Test 8: Rate limiting
    serial.writeString("  [8]  Rate limiting........... ");
    {
        resetForTest();
        // Fill up rate entries
        var i: usize = 0;
        while (i < MAX_NEW_PEERS_PER_MINUTE) : (i += 1) {
            recordRegistration(@intCast(i + 1));
        }
        if (isRateLimited()) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 9: Diversity score — single subnet
    serial.writeString("  [9]  Diversity (single sub).. ");
    {
        resetForTest();
        // All peers in one subnet → low diversity
        const subnet: u24 = (192 << 16) | (168 << 8) | 1;
        addSubnetPeer(subnet);
        addSubnetPeer(subnet);
        addSubnetPeer(subnet);

        // Register 3 fake reps for count
        var fake_id: [32]u8 = [_]u8{0} ** 32;
        var i: u8 = 0;
        while (i < 3) : (i += 1) {
            fake_id[0] = 0xF0 + i;
            if (reputation.generatePow(&fake_id, reputation.TEST_POW_DIFFICULTY, 10000)) |n| {
                _ = reputation.registerPeer(&fake_id, n, reputation.TEST_POW_DIFFICULTY);
            }
        }

        const score = getDiversityScore();
        // 1 subnet / 3 peers * 100 = 33
        if (score <= 50) {
            serial.writeString("PASS (score=");
            printU32(@as(u32, score));
            serial.writeString(")\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (score=");
            printU32(@as(u32, score));
            serial.writeString(")\n");
            failed += 1;
        }
    }

    // Test 10: Diversity score — multiple subnets
    serial.writeString("  [10] Diversity (multi sub)... ");
    {
        resetForTest();
        reputation.init();

        addSubnetPeer((10 << 16) | (0 << 8) | 1);
        addSubnetPeer((10 << 16) | (0 << 8) | 2);
        addSubnetPeer((10 << 16) | (0 << 8) | 3);

        var fake_id: [32]u8 = [_]u8{0} ** 32;
        var i: u8 = 0;
        while (i < 3) : (i += 1) {
            fake_id[0] = 0xE0 + i;
            if (reputation.generatePow(&fake_id, reputation.TEST_POW_DIFFICULTY, 10000)) |n| {
                _ = reputation.registerPeer(&fake_id, n, reputation.TEST_POW_DIFFICULTY);
            }
        }

        const score = getDiversityScore();
        if (score == 100) {
            serial.writeString("PASS (score=100)\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (score=");
            printU32(@as(u32, score));
            serial.writeString(")\n");
            failed += 1;
        }
    }

    // Test 11: Remove subnet peer
    serial.writeString("  [11] Remove subnet peer...... ");
    {
        resetForTest();
        const ip: u32 = (10 << 24) | (0 << 16) | (5 << 8) | 1;
        const subnet = ipToSubnet(ip);
        addSubnetPeer(subnet);
        addSubnetPeer(subnet);
        if (getSubnetPeerCount(subnet) != 2) {
            serial.writeString("FAIL (add)\n");
            failed += 1;
        } else {
            removeSubnetPeer(ip);
            if (getSubnetPeerCount(subnet) == 1) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        }
    }

    // Test 12: Alert generation
    serial.writeString("  [12] Alert generation........ ");
    {
        resetForTest();
        // Trigger subnet flood alert
        const subnet: u24 = (192 << 16) | (168 << 8) | 99;
        var i: u16 = 0;
        while (i < MAX_PEERS_PER_SUBNET + 1) : (i += 1) {
            addSubnetPeer(subnet);
        }
        // Try registration that should trigger alert
        test_id[0] = 0xAE;
        if (reputation.generatePow(&test_id, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const ip = (192 << 24) | (168 << 16) | (99 << 8) | 50;
            _ = checkRegistration(ip, &test_id, nonce, reputation.TEST_POW_DIFFICULTY);
        }
        if (alert_count > 0) {
            serial.writeString("PASS (");
            printU32(@intCast(alert_count));
            serial.writeString(" alerts)\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 13: Denial counter
    serial.writeString("  [13] Denial counter.......... ");
    {
        if (total_denials > 0) {
            serial.writeString("PASS (");
            printU64(total_denials);
            serial.writeString(" denials)\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 14: Distinct subnet count
    serial.writeString("  [14] Distinct subnets........ ");
    {
        resetForTest();
        addSubnetPeer((10 << 16) | (1 << 8) | 1);
        addSubnetPeer((10 << 16) | (2 << 8) | 1);
        addSubnetPeer((10 << 16) | (3 << 8) | 1);
        if (getDistinctSubnetCount() == 3) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 15: Registration count tracking
    serial.writeString("  [15] Registration tracking... ");
    {
        resetForTest();
        test_id[0] = 0xF9;
        if (reputation.generatePow(&test_id, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const ip = (172 << 24) | (20 << 16) | (0 << 8) | 1;
            _ = checkRegistration(ip, &test_id, nonce, reputation.TEST_POW_DIFFICULTY);
            if (total_registrations > 0) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (pow)\n");
            failed += 1;
        }
    }

    // Summary
    serial.writeString("\n  ────────────────────────────────\n");
    serial.writeString("  H.3b Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed");
    if (failed == 0) {
        serial.writeString(" ✓\n");
    } else {
        serial.writeString(" ✗\n");
    }

    return failed == 0;
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

fn printU64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
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
