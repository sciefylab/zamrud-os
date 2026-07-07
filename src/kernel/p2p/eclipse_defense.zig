//! Zamrud OS - Eclipse Attack Defense System (H.4 + P.3e Ready)
//!
//! Prevents attackers from isolating a node by controlling all connections.
//!
//! H.4:
//! 1. Outbound connection diversity
//! 2. Inbound/Outbound ratio limits
//! 3. Anchor peers
//! 4. Multi-path verification
//! 5. Connection bucketing
//!
//! P.3e Ready:
//! - Public risk query for eviction logic
//! - Alert severity helper
//! - Peer eviction cleanup path
//! - Eclipse evidence trigger helper

const serial = @import("../drivers/serial/serial.zig");
const peer_mod = @import("peer.zig");
const sybil = @import("sybil_defense.zig");
const reputation = @import("reputation.zig");
const discovery = @import("discovery.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_INBOUND: usize = 20;
pub const MAX_OUTBOUND: usize = 12;
pub const MIN_OUTBOUND: usize = 4;
pub const ANCHOR_PEER_COUNT: usize = 4;
pub const ANCHOR_MIN_AGE: u64 = 3600;
pub const ANCHOR_MIN_TRUST: reputation.TrustLevel = .member;
pub const ROTATION_INTERVAL: u64 = 1800;
pub const MIN_OUTBOUND_SUBNETS: usize = 3;
pub const MIN_BLOCK_CONFIRMATIONS: usize = 2;
pub const BUCKET_COUNT: usize = 16;
pub const MAX_PER_BUCKET: usize = 4;

// P.3e threshold
pub const ECLIPSE_EVICTION_RISK_THRESHOLD: u8 = 80;

// =============================================================================
// Types
// =============================================================================

pub const ConnectionType = enum(u8) {
    inbound = 0,
    outbound = 1,
    anchor = 2,
};

pub const ConnectionInfo = struct {
    peer_id: [32]u8,
    conn_type: ConnectionType,
    subnet: u24,
    bucket: u8,
    connected_at: u64,
    is_anchor: bool,
};

pub const BlockConfirmation = struct {
    block_height: u64,
    block_hash: [32]u8,
    confirmations: [8][32]u8,
    confirm_count: u8,
    first_seen: u64,
};

pub const EclipseAlertType = enum(u8) {
    low_outbound = 0,
    low_diversity = 1,
    inbound_flood = 2,
    anchor_lost = 3,
    block_conflict = 4,
    single_source_sync = 5,
};

pub const EclipseAlert = struct {
    alert_type: EclipseAlertType,
    timestamp: u64,
    details: u32,
};

pub const EclipseStatus = struct {
    is_safe: bool,
    risk_level: u8,
    outbound_count: usize,
    inbound_count: usize,
    anchor_count: usize,
    subnet_diversity: u8,
    alerts: usize,
};

// =============================================================================
// State
// =============================================================================

var connections: [peer_mod.MAX_PEERS]ConnectionInfo = undefined;
var connection_count: usize = 0;

var anchor_peers: [ANCHOR_PEER_COUNT][32]u8 = undefined;
var anchor_count: usize = 0;

var pending_blocks: [16]BlockConfirmation = undefined;
var pending_block_count: usize = 0;

var alerts: [32]EclipseAlert = undefined;
var alert_count: usize = 0;

var buckets: [BUCKET_COUNT]u8 = [_]u8{0} ** BUCKET_COUNT;

var last_rotation: u64 = 0;
var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    resetInternal();
    initialized = true;

    serial.writeString("[ECLIPSE] Defense system initialized (P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn resetInternal() void {
    for (&connections) |*c| {
        c.* = emptyConnection();
    }

    connection_count = 0;

    for (&anchor_peers) |*a| {
        a.* = [_]u8{0} ** 32;
    }

    anchor_count = 0;

    for (&pending_blocks) |*b| {
        b.* = emptyBlockConfirmation();
    }

    pending_block_count = 0;

    for (&alerts) |*a| {
        a.* = .{
            .alert_type = .low_outbound,
            .timestamp = 0,
            .details = 0,
        };
    }

    alert_count = 0;

    for (&buckets) |*b| {
        b.* = 0;
    }

    last_rotation = 0;
}

fn emptyConnection() ConnectionInfo {
    return .{
        .peer_id = [_]u8{0} ** 32,
        .conn_type = .inbound,
        .subnet = 0,
        .bucket = 0,
        .connected_at = 0,
        .is_anchor = false,
    };
}

fn emptyBlockConfirmation() BlockConfirmation {
    return .{
        .block_height = 0,
        .block_hash = [_]u8{0} ** 32,
        .confirmations = [_][32]u8{[_]u8{0} ** 32} ** 8,
        .confirm_count = 0,
        .first_seen = 0,
    };
}

// =============================================================================
// Connection Management
// =============================================================================

pub fn allowConnection(ip: u32, conn_type: ConnectionType) bool {
    const subnet = sybil.ipToSubnet(ip);
    const bucket = ipToBucket(ip);

    if (buckets[bucket] >= MAX_PER_BUCKET) {
        serial.writeString("[ECLIPSE] Bucket limit reached\n");
        return false;
    }

    if (conn_type == .inbound) {
        if (getInboundCount() >= MAX_INBOUND) {
            addAlert(.inbound_flood, getInboundCount());
            serial.writeString("[ECLIPSE] Inbound limit reached\n");
            return false;
        }
    } else {
        if (getOutboundCount() >= MAX_OUTBOUND) {
            serial.writeString("[ECLIPSE] Outbound limit reached\n");
            return false;
        }
    }

    if (conn_type == .outbound) {
        const subnet_count = getSubnetCount(subnet);

        if (subnet_count > 0 and getOutboundCount() >= MIN_OUTBOUND) {
            if (getDistinctOutboundSubnets() < MIN_OUTBOUND_SUBNETS) {
                serial.writeString("[ECLIPSE] Need more subnet diversity\n");
                return false;
            }
        }
    }

    return true;
}

pub fn registerConnection(peer_id: *const [32]u8, ip: u32, conn_type: ConnectionType) bool {
    if (!allowConnection(ip, conn_type)) {
        return false;
    }

    for (&connections) |*c| {
        if (isEmptyPeerId(&c.peer_id)) {
            const subnet = sybil.ipToSubnet(ip);
            const bucket = ipToBucket(ip);

            c.* = .{
                .peer_id = peer_id.*,
                .conn_type = conn_type,
                .subnet = subnet,
                .bucket = bucket,
                .connected_at = getTimestamp(),
                .is_anchor = conn_type == .anchor,
            };

            buckets[bucket] +|= 1;
            connection_count += 1;

            if (conn_type == .anchor and anchor_count < ANCHOR_PEER_COUNT) {
                anchor_peers[anchor_count] = peer_id.*;
                anchor_count += 1;
            }

            serial.writeString("[ECLIPSE] Registered ");

            switch (conn_type) {
                .inbound => serial.writeString("inbound"),
                .outbound => serial.writeString("outbound"),
                .anchor => serial.writeString("anchor"),
            }

            serial.writeString(" connection\n");

            return true;
        }
    }

    return false;
}

pub fn removeConnection(peer_id: *const [32]u8) void {
    for (&connections) |*c| {
        if (eqlBytes(&c.peer_id, peer_id)) {
            if (buckets[c.bucket] > 0) {
                buckets[c.bucket] -= 1;
            }

            if (c.is_anchor) {
                removeAnchor(peer_id);
                addAlert(.anchor_lost, 0);
            }

            c.* = emptyConnection();

            if (connection_count > 0) {
                connection_count -= 1;
            }

            checkHealth();
            return;
        }
    }
}

/// P.3e: called when target is evicted.
/// Intentional removal without anchor_lost alert noise.
pub fn removeEvictedConnection(peer_id: *const [32]u8) void {
    for (&connections) |*c| {
        if (eqlBytes(&c.peer_id, peer_id)) {
            if (buckets[c.bucket] > 0) {
                buckets[c.bucket] -= 1;
            }

            if (c.is_anchor) {
                removeAnchor(peer_id);
            }

            c.* = emptyConnection();

            if (connection_count > 0) {
                connection_count -= 1;
            }

            serial.writeString("[ECLIPSE] Evicted connection removed\n");
            return;
        }
    }
}

pub fn getConnection(peer_id: *const [32]u8) ?*ConnectionInfo {
    for (&connections) |*c| {
        if (eqlBytes(&c.peer_id, peer_id)) {
            return c;
        }
    }

    return null;
}

// =============================================================================
// Anchor Peer Management
// =============================================================================

pub fn promoteToAnchor(peer_id: *const [32]u8) bool {
    for (anchor_peers[0..anchor_count]) |*a| {
        if (eqlBytes(a, peer_id)) return true;
    }

    if (anchor_count >= ANCHOR_PEER_COUNT) {
        serial.writeString("[ECLIPSE] Anchor slots full\n");
        return false;
    }

    if (!isAnchorEligible(peer_id)) {
        serial.writeString("[ECLIPSE] Peer not eligible for anchor\n");
        return false;
    }

    anchor_peers[anchor_count] = peer_id.*;
    anchor_count += 1;

    if (getConnection(peer_id)) |conn| {
        conn.is_anchor = true;
        conn.conn_type = .anchor;
    }

    serial.writeString("[ECLIPSE] Promoted peer to anchor\n");
    return true;
}

pub fn isAnchorEligible(peer_id: *const [32]u8) bool {
    if (reputation.getReputation(peer_id)) |rep| {
        if (@intFromEnum(rep.trust_level) < @intFromEnum(ANCHOR_MIN_TRUST)) {
            return false;
        }

        const age = reputation.getAge(rep);
        if (age < ANCHOR_MIN_AGE) {
            return false;
        }

        return true;
    }

    return false;
}

fn removeAnchor(peer_id: *const [32]u8) void {
    for (0..anchor_count) |i| {
        if (eqlBytes(&anchor_peers[i], peer_id)) {
            var j = i;

            while (j + 1 < anchor_count) : (j += 1) {
                anchor_peers[j] = anchor_peers[j + 1];
            }

            anchor_peers[anchor_count - 1] = [_]u8{0} ** 32;
            anchor_count -= 1;
            return;
        }
    }
}

pub fn isAnchor(peer_id: *const [32]u8) bool {
    for (anchor_peers[0..anchor_count]) |*a| {
        if (eqlBytes(a, peer_id)) return true;
    }

    return false;
}

pub fn getAnchors() []const [32]u8 {
    return anchor_peers[0..anchor_count];
}

pub fn autoPromoteAnchors() void {
    if (anchor_count >= ANCHOR_PEER_COUNT) return;

    for (&connections) |*c| {
        if (isEmptyPeerId(&c.peer_id)) continue;
        if (c.is_anchor) continue;
        if (c.conn_type != .outbound) continue;

        if (isAnchorEligible(&c.peer_id)) {
            if (promoteToAnchor(&c.peer_id)) {
                if (anchor_count >= ANCHOR_PEER_COUNT) return;
            }
        }
    }
}

// =============================================================================
// Multi-Path Block Verification
// =============================================================================

pub fn addBlockConfirmation(
    peer_id: *const [32]u8,
    block_height: u64,
    block_hash: *const [32]u8,
) bool {
    for (&pending_blocks) |*b| {
        if (b.block_height == block_height) {
            if (eqlBytes(&b.block_hash, block_hash)) {
                return addConfirmation(b, peer_id);
            }

            addAlert(.block_conflict, @intCast(block_height & 0xFFFFFFFF));

            serial.writeString("[ECLIPSE] ALERT: Block hash conflict at height ");
            printU64(block_height);
            serial.writeString("\n");

            if (@hasDecl(reputation, "recordSevereViolation")) {
                reputation.recordSevereViolation(peer_id);
            } else {
                reputation.addViolation(peer_id);
            }

            return false;
        }
    }

    if (pending_block_count < pending_blocks.len) {
        pending_blocks[pending_block_count] = .{
            .block_height = block_height,
            .block_hash = block_hash.*,
            .confirmations = [_][32]u8{[_]u8{0} ** 32} ** 8,
            .confirm_count = 1,
            .first_seen = getTimestamp(),
        };

        pending_blocks[pending_block_count].confirmations[0] = peer_id.*;
        pending_block_count += 1;

        return true;
    }

    return false;
}

fn addConfirmation(block: *BlockConfirmation, peer_id: *const [32]u8) bool {
    for (block.confirmations[0..block.confirm_count]) |*c| {
        if (eqlBytes(c, peer_id)) return true;
    }

    if (block.confirm_count < 8) {
        block.confirmations[block.confirm_count] = peer_id.*;
        block.confirm_count += 1;
        return true;
    }

    return false;
}

pub fn isBlockConfirmed(block_height: u64) bool {
    for (pending_blocks[0..pending_block_count]) |*b| {
        if (b.block_height == block_height) {
            return b.confirm_count >= MIN_BLOCK_CONFIRMATIONS;
        }
    }

    return false;
}

pub fn getBlockConfirmations(block_height: u64) u8 {
    for (pending_blocks[0..pending_block_count]) |b| {
        if (b.block_height == block_height) {
            return b.confirm_count;
        }
    }

    return 0;
}

pub fn clearConfirmedBlocks(up_to_height: u64) void {
    var write_idx: usize = 0;

    for (0..pending_block_count) |read_idx| {
        if (pending_blocks[read_idx].block_height > up_to_height) {
            if (write_idx != read_idx) {
                pending_blocks[write_idx] = pending_blocks[read_idx];
            }

            write_idx += 1;
        }
    }

    pending_block_count = write_idx;
}

// =============================================================================
// Connection Rotation
// =============================================================================

pub fn rotateConnections() void {
    const now = getTimestamp();

    if (now < last_rotation + ROTATION_INTERVAL) {
        return;
    }

    last_rotation = now;

    var to_rotate: usize = 0;
    var oldest_idx: usize = 0;
    var oldest_time: u64 = now;

    for (connections, 0..) |c, i| {
        if (isEmptyPeerId(&c.peer_id)) continue;
        if (c.is_anchor) continue;
        if (c.conn_type == .anchor) continue;

        if (c.conn_type == .inbound and c.connected_at < oldest_time) {
            oldest_time = c.connected_at;
            oldest_idx = i;
            to_rotate += 1;
        }
    }

    if (to_rotate > 0 and getInboundCount() > MAX_INBOUND / 2) {
        const pid = connections[oldest_idx].peer_id;

        if (peer_mod.getById(pid)) |p| {
            serial.writeString("[ECLIPSE] Rotating old inbound connection\n");
            peer_mod.disconnect(p);
        }

        tryNewOutbound();
    }
}

fn tryNewOutbound() void {
    if (getOutboundCount() >= MAX_OUTBOUND) return;

    _ = discovery.connectToDiscovered(1);
}

// =============================================================================
// Health Monitoring
// =============================================================================

pub fn checkHealth() void {
    if (getOutboundCount() < MIN_OUTBOUND) {
        addAlert(.low_outbound, getOutboundCount());
    }

    if (getDistinctOutboundSubnets() < MIN_OUTBOUND_SUBNETS) {
        addAlert(.low_diversity, getDistinctOutboundSubnets());
    }

    const inbound = getInboundCount();
    const outbound = getOutboundCount();

    if (outbound > 0 and inbound > outbound * 3) {
        addAlert(.inbound_flood, inbound);
    }

    if (anchor_count == 0 and connection_count > 4) {
        autoPromoteAnchors();
    }
}

pub fn getStatus() EclipseStatus {
    const outbound = getOutboundCount();
    const inbound = getInboundCount();
    const diversity = getDistinctOutboundSubnets();

    var risk: u32 = 0;

    if (outbound < MIN_OUTBOUND) {
        risk += 30;
    } else if (outbound < MIN_OUTBOUND + 2) {
        risk += 15;
    }

    if (diversity < MIN_OUTBOUND_SUBNETS) {
        risk += 25;
    } else if (diversity < MIN_OUTBOUND_SUBNETS + 2) {
        risk += 10;
    }

    if (outbound > 0 and inbound > outbound * 2) {
        risk += 20;
    }

    if (anchor_count == 0) {
        risk += 15;
    }

    if (alert_count > 0) {
        risk += @min(alert_count * 5, 20);
    }

    return .{
        .is_safe = risk < 50,
        .risk_level = @intCast(@min(risk, 100)),
        .outbound_count = outbound,
        .inbound_count = inbound,
        .anchor_count = anchor_count,
        .subnet_diversity = @intCast(diversity),
        .alerts = alert_count,
    };
}

pub fn isHighRisk() bool {
    return getStatus().risk_level >= ECLIPSE_EVICTION_RISK_THRESHOLD;
}

pub fn hasEvictionRelevantAlert() bool {
    for (alerts[0..alert_count]) |a| {
        switch (a.alert_type) {
            .inbound_flood,
            .block_conflict,
            .single_source_sync,
            .low_diversity,
            => return true,

            else => {},
        }
    }

    return false;
}

// =============================================================================
// Statistics
// =============================================================================

pub fn getInboundCount() usize {
    var count: usize = 0;

    for (connections[0..connection_count]) |c| {
        if (c.conn_type == .inbound and !isEmptyPeerId(&c.peer_id)) {
            count += 1;
        }
    }

    return count;
}

pub fn getOutboundCount() usize {
    var count: usize = 0;

    for (connections[0..connection_count]) |c| {
        if ((c.conn_type == .outbound or c.conn_type == .anchor) and !isEmptyPeerId(&c.peer_id)) {
            count += 1;
        }
    }

    return count;
}

pub fn getAnchorCount() usize {
    return anchor_count;
}

pub fn getDistinctOutboundSubnets() usize {
    var subnets: [MAX_OUTBOUND]u24 = undefined;
    var subnet_count: usize = 0;

    for (connections[0..connection_count]) |c| {
        if (c.conn_type != .outbound and c.conn_type != .anchor) continue;
        if (isEmptyPeerId(&c.peer_id)) continue;

        var found = false;

        for (subnets[0..subnet_count]) |s| {
            if (s == c.subnet) {
                found = true;
                break;
            }
        }

        if (!found and subnet_count < MAX_OUTBOUND) {
            subnets[subnet_count] = c.subnet;
            subnet_count += 1;
        }
    }

    return subnet_count;
}

fn getSubnetCount(subnet: u24) usize {
    var count: usize = 0;

    for (connections[0..connection_count]) |c| {
        if (c.subnet == subnet and !isEmptyPeerId(&c.peer_id)) {
            count += 1;
        }
    }

    return count;
}

// =============================================================================
// Alerts
// =============================================================================

fn addAlert(alert_type: EclipseAlertType, details: usize) void {
    const now = getTimestamp();

    for (alerts[0..alert_count]) |a| {
        if (a.alert_type == alert_type and now >= a.timestamp and now - a.timestamp < 60) {
            return;
        }
    }

    if (alert_count >= alerts.len) {
        for (0..alerts.len - 1) |i| {
            alerts[i] = alerts[i + 1];
        }

        alert_count = alerts.len - 1;
    }

    alerts[alert_count] = .{
        .alert_type = alert_type,
        .timestamp = now,
        .details = @intCast(details & 0xFFFFFFFF),
    };

    alert_count += 1;

    serial.writeString("[ECLIPSE] ALERT: ");

    switch (alert_type) {
        .low_outbound => serial.writeString("Low outbound connections"),
        .low_diversity => serial.writeString("Low subnet diversity"),
        .inbound_flood => serial.writeString("Inbound connection flood"),
        .anchor_lost => serial.writeString("Anchor peer lost"),
        .block_conflict => serial.writeString("Block hash conflict"),
        .single_source_sync => serial.writeString("Single source sync"),
    }

    serial.writeString("\n");
}

pub fn getAlertCount() usize {
    return alert_count;
}

pub fn getAlert(index: usize) ?*const EclipseAlert {
    if (index >= alert_count) return null;
    return &alerts[index];
}

pub fn getLatestAlert() ?*const EclipseAlert {
    if (alert_count == 0) return null;
    return &alerts[alert_count - 1];
}

pub fn clearAlerts() void {
    alert_count = 0;
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

fn ipToBucket(ip: u32) u8 {
    const high_byte: u8 = @intCast((ip >> 24) & 0xFF);
    return @intCast(high_byte % BUCKET_COUNT);
}

fn isEmptyPeerId(id: *const [32]u8) bool {
    for (id.*) |b| {
        if (b != 0) return false;
    }

    return true;
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    for (a, b) |x, y| {
        if (x != y) return false;
    }

    return true;
}

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn printU64(val: u64) void {
    if (val >= 10) printU64(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
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

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  ECLIPSE DEFENSE TESTS H.4 + P.3e\n");
    serial.writeString("========================================\n\n");

    if (!initialized) init();
    resetForTest();

    var passed: u32 = 0;
    var failed: u32 = 0;

    var peer_a: [32]u8 = [_]u8{0} ** 32;
    peer_a[0] = 0xAA;

    serial.writeString("  [1] Allow inbound............ ");
    if (allowConnection(0x01020304, .inbound)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [2] Register inbound......... ");
    if (registerConnection(&peer_a, 0x01020304, .inbound)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [3] Count inbound............ ");
    if (getInboundCount() == 1) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [4] Remove evicted........... ");
    removeEvictedConnection(&peer_a);
    if (getInboundCount() == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [5] Status query............. ");
    const status = getStatus();
    if (status.risk_level <= 100) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("\n  Eclipse Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
