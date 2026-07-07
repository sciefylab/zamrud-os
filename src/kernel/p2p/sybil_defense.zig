//! Zamrud OS - Sybil Attack Defense System (H.3 + P.3e Ready)
//! IP diversity enforcement, rate limiting, pattern detection
//!
//! H.3:
//! - Prevents 1000 fake peers from same /24 subnet
//! - Prevents rapid-fire registration floods
//! - Detects coordinated Sybil patterns
//!
//! P.3e Ready:
//! - Exposes Sybil alert status for Twin-Node Eviction evidence
//! - Records severe Sybil behavior into reputation
//! - Provides high-risk query for eviction trigger logic

const serial = @import("../drivers/serial/serial.zig");
const reputation = @import("reputation.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_SUBNETS: usize = 128;
pub const MAX_RATE_ENTRIES: usize = 64;

pub const MAX_PEERS_PER_SUBNET: u16 = 5;
pub const MAX_NEW_PEERS_PER_MINUTE: usize = 10;
pub const RATE_WINDOW_SECONDS: u64 = 60;
pub const ALERT_SUBNET_THRESHOLD: u16 = 3;

// P.3e thresholds
pub const SYBIL_HIGH_RISK_ALERTS: usize = 3;
pub const SYBIL_HIGH_RISK_DENIALS: u64 = 10;
pub const SYBIL_LOW_DIVERSITY_THRESHOLD: u8 = 35;

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
    subnet: u24,
    peer_count: u16,
    last_added: u64,
};

pub const RateEntry = struct {
    timestamp: u64,
    ip: u32,
};

pub const SybilAlertType = enum(u8) {
    subnet_flood = 0,
    rate_flood = 1,
    coordinated = 2,
};

pub const SybilAlert = struct {
    alert_type: SybilAlertType,
    subnet: u24,
    peer_count: u16,
    timestamp: u64,
};

pub const SybilStatus = struct {
    alert_count: usize,
    total_registrations: u64,
    total_denials: u64,
    recent_registrations: usize,
    distinct_subnets: usize,
    diversity_score: u8,
    high_risk: bool,
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
    resetInternal();
    initialized = true;

    serial.writeString("[SYBIL] Defense system initialized (P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn resetInternal() void {
    for (&subnets) |*s| {
        s.* = .{
            .subnet = 0,
            .peer_count = 0,
            .last_added = 0,
        };
    }

    subnet_count = 0;

    for (&rate_entries) |*r| {
        r.* = .{
            .timestamp = 0,
            .ip = 0,
        };
    }

    rate_count = 0;

    for (&alerts) |*a| {
        a.* = .{
            .alert_type = .subnet_flood,
            .subnet = 0,
            .peer_count = 0,
            .timestamp = 0,
        };
    }

    alert_count = 0;
    total_registrations = 0;
    total_denials = 0;
}

// =============================================================================
// Registration Check
// =============================================================================

/// Comprehensive check before allowing a new peer.
/// Returns `.allowed` only if all checks pass.
pub fn checkRegistration(
    ip: u32,
    peer_id: *const [32]u8,
    pow_nonce: u64,
    pow_difficulty: u8,
) RegistrationResult {
    // Check 1: PoW required
    if (pow_difficulty == 0) {
        total_denials += 1;
        return .denied_no_pow;
    }

    // Check 2: PoW verification
    if (!reputation.verifyPow(peer_id, pow_nonce, pow_difficulty)) {
        total_denials += 1;
        return .denied_invalid_pow;
    }

    // Check 3: Rate limiting
    if (isRateLimited()) {
        total_denials += 1;
        addAlert(.rate_flood, 0, @intCast(@min(rate_count, 65535)));

        if (@hasDecl(reputation, "recordSevereViolation")) {
            reputation.recordSevereViolation(peer_id);
        }

        return .denied_rate_limit;
    }

    // Check 4: Subnet diversity
    const subnet = ipToSubnet(ip);
    const subnet_peers = getSubnetPeerCount(subnet);

    if (subnet_peers >= MAX_PEERS_PER_SUBNET) {
        total_denials += 1;
        addAlert(.subnet_flood, subnet, subnet_peers);

        if (@hasDecl(reputation, "recordSevereViolation")) {
            reputation.recordSevereViolation(peer_id);
        }

        return .denied_subnet_limit;
    }

    // Check 5: Coordinated Sybil pattern
    if (detectSybilPattern()) {
        total_denials += 1;

        if (@hasDecl(reputation, "recordSevereViolation")) {
            reputation.recordSevereViolation(peer_id);
        }

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

/// Extract /24 subnet from IP.
/// Example: A.B.C.D -> A.B.C
pub fn ipToSubnet(ip: u32) u24 {
    return @intCast(ip >> 8);
}

pub fn getSubnetPeerCount(subnet: u24) u16 {
    for (subnets[0..subnet_count]) |s| {
        if (s.subnet == subnet) {
            return s.peer_count;
        }
    }

    return 0;
}

pub fn addSubnetPeer(subnet: u24) void {
    for (subnets[0..subnet_count]) |*s| {
        if (s.subnet == subnet) {
            s.peer_count +|= 1;
            s.last_added = getTimestamp();
            return;
        }
    }

    if (subnet_count < MAX_SUBNETS) {
        subnets[subnet_count] = .{
            .subnet = subnet,
            .peer_count = 1,
            .last_added = getTimestamp(),
        };

        subnet_count += 1;
    }
}

pub fn removeSubnetPeer(ip: u32) void {
    const subnet = ipToSubnet(ip);

    for (subnets[0..subnet_count]) |*s| {
        if (s.subnet == subnet and s.peer_count > 0) {
            s.peer_count -= 1;
            return;
        }
    }
}

pub fn getDistinctSubnetCount() usize {
    var count: usize = 0;

    for (subnets[0..subnet_count]) |s| {
        if (s.peer_count > 0) {
            count += 1;
        }
    }

    return count;
}

/// Calculate diversity score 0-100.
/// Higher = more diverse = safer.
pub fn getDiversityScore() u8 {
    const distinct = getDistinctSubnetCount();
    const total = reputation.getTrackedCount();

    if (total == 0) return 100;
    if (distinct == 0) return 0;

    const score = (distinct * 100) / total;
    return @intCast(@min(score, 100));
}

// =============================================================================
// Rate Limiting
// =============================================================================

fn isRateLimited() bool {
    cleanExpiredRateEntries();
    return rate_count >= MAX_NEW_PEERS_PER_MINUTE;
}

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

fn cleanExpiredRateEntries() void {
    const now = getTimestamp();
    var write_idx: usize = 0;

    for (0..rate_count) |read_idx| {
        if (now >= rate_entries[read_idx].timestamp and
            now - rate_entries[read_idx].timestamp < RATE_WINDOW_SECONDS)
        {
            if (write_idx != read_idx) {
                rate_entries[write_idx] = rate_entries[read_idx];
            }

            write_idx += 1;
        }
    }

    rate_count = write_idx;
}

pub fn getRecentRegistrationCount() usize {
    cleanExpiredRateEntries();
    return rate_count;
}

// =============================================================================
// Sybil Pattern Detection
// =============================================================================

fn detectSybilPattern() bool {
    var subnets_near_limit: usize = 0;

    for (subnets[0..subnet_count]) |s| {
        if (s.peer_count >= ALERT_SUBNET_THRESHOLD) {
            subnets_near_limit += 1;
        }
    }

    // Pattern 1: multiple subnets near limit together
    if (subnets_near_limit >= 3) {
        addAlert(.coordinated, 0, @intCast(@min(subnets_near_limit, 65535)));
        return true;
    }

    // Pattern 2: high rate + subnet pressure
    if (rate_count >= MAX_NEW_PEERS_PER_MINUTE / 2 and subnets_near_limit >= 2) {
        addAlert(.rate_flood, 0, @intCast(@min(rate_count, 65535)));
        return true;
    }

    return false;
}

// =============================================================================
// P.3e Risk Helpers
// =============================================================================

pub fn getStatus() SybilStatus {
    const diversity = getDiversityScore();
    const recent = getRecentRegistrationCount();

    return .{
        .alert_count = alert_count,
        .total_registrations = total_registrations,
        .total_denials = total_denials,
        .recent_registrations = recent,
        .distinct_subnets = getDistinctSubnetCount(),
        .diversity_score = diversity,
        .high_risk = isHighRisk(),
    };
}

/// P.3e: true if Sybil subsystem sees enough risk to become eviction evidence.
pub fn isHighRisk() bool {
    if (alert_count >= SYBIL_HIGH_RISK_ALERTS) return true;
    if (total_denials >= SYBIL_HIGH_RISK_DENIALS) return true;
    if (getDiversityScore() <= SYBIL_LOW_DIVERSITY_THRESHOLD and reputation.getTrackedCount() >= 4) return true;

    return false;
}

/// P.3e: alert types that can become evidence material.
pub fn hasEvictionRelevantAlert() bool {
    for (alerts[0..alert_count]) |a| {
        switch (a.alert_type) {
            .subnet_flood,
            .rate_flood,
            .coordinated,
            => return true,
        }
    }

    return false;
}

pub fn getLatestAlert() ?*const SybilAlert {
    if (alert_count == 0) return null;
    return &alerts[alert_count - 1];
}

pub fn clearAlerts() void {
    alert_count = 0;
}

// =============================================================================
// Alerts
// =============================================================================

fn addAlert(alert_type: SybilAlertType, subnet: u24, peer_count: u16) void {
    if (alert_count >= alerts.len) {
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
// Reset For Testing
// =============================================================================

pub fn resetForTest() void {
    resetInternal();
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

// =============================================================================
// Tests
// =============================================================================

var test_id: [32]u8 = [_]u8{0} ** 32;

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  SYBIL DEFENSE TESTS H.3 + P.3e\n");
    serial.writeString("========================================\n\n");

    if (!initialized) init();
    resetForTest();

    reputation.init();

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1] IP to subnet............. ");
    {
        const ip: u32 = (@as(u32, 192) << 24) |
            (@as(u32, 168) << 16) |
            (@as(u32, 1) << 8) |
            @as(u32, 100);

        const subnet = ipToSubnet(ip);
        const expected: u24 = (@as(u24, 192) << 16) |
            (@as(u24, 168) << 8) |
            @as(u24, 1);

        if (subnet == expected) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [2] Subnet add/remove........ ");
    {
        const ip: u32 = (@as(u32, 10) << 24) |
            (@as(u32, 0) << 16) |
            (@as(u32, 1) << 8) |
            @as(u32, 5);

        const subnet = ipToSubnet(ip);

        addSubnetPeer(subnet);
        addSubnetPeer(subnet);
        removeSubnetPeer(ip);

        if (getSubnetPeerCount(subnet) == 1) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [3] Registration allowed..... ");
    {
        resetForTest();

        test_id = [_]u8{0} ** 32;
        test_id[0] = 0xA1;

        if (reputation.generatePow(&test_id, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const ip: u32 = (@as(u32, 172) << 24) |
                (@as(u32, 16) << 16) |
                (@as(u32, 0) << 8) |
                @as(u32, 1);

            const result = checkRegistration(ip, &test_id, nonce, reputation.TEST_POW_DIFFICULTY);

            if (result == .allowed) {
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

    serial.writeString("  [4] Denied no PoW............ ");
    {
        test_id = [_]u8{0} ** 32;
        test_id[0] = 0xA2;

        const ip: u32 = (@as(u32, 172) << 24) |
            (@as(u32, 16) << 16) |
            (@as(u32, 1) << 8) |
            @as(u32, 1);

        const result = checkRegistration(ip, &test_id, 0, 0);

        if (result == .denied_no_pow) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [5] Subnet limit............. ");
    {
        resetForTest();

        const base_ip: u32 = (@as(u32, 10) << 24) |
            (@as(u32, 0) << 16) |
            (@as(u32, 3) << 8);

        const subnet = ipToSubnet(base_ip | 1);

        var i: u16 = 0;
        while (i < MAX_PEERS_PER_SUBNET) : (i += 1) {
            addSubnetPeer(subnet);
        }

        test_id = [_]u8{0} ** 32;
        test_id[0] = 0xA3;

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
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [6] P.3e high risk query..... ");
    {
        resetForTest();

        addAlert(.subnet_flood, 1, 5);
        addAlert(.rate_flood, 0, 10);
        addAlert(.coordinated, 0, 3);

        if (isHighRisk() and hasEvictionRelevantAlert()) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  Sybil Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

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
