//! Zamrud OS - Eclipse Attack Defense System (H.4)
//!
//! Prevents attackers from isolating a node by controlling all its connections.
//!
//! Defense Mechanisms:
//! 1. Outbound connection diversity - Force connections to different subnets
//! 2. Inbound/Outbound ratio limits - Prevent attacker flooding inbound
//! 3. Anchor peers - Long-term trusted connections that resist rotation
//! 4. Multi-path verification - Verify blocks from multiple independent peers
//! 5. Connection bucketing - Limit connections per subnet bucket

const serial = @import("../drivers/serial/serial.zig");
const peer_mod = @import("peer.zig");
const sybil = @import("sybil_defense.zig");
const reputation = @import("reputation.zig");
const discovery = @import("discovery.zig");

// =============================================================================
// Configuration
// =============================================================================

/// Maximum inbound connections (attacker-controlled risk)
pub const MAX_INBOUND: usize = 20;

/// Maximum outbound connections (we control these)
pub const MAX_OUTBOUND: usize = 12;

/// Minimum outbound connections for security
pub const MIN_OUTBOUND: usize = 4;

/// Number of anchor peers to maintain
pub const ANCHOR_PEER_COUNT: usize = 4;

/// Anchor peer minimum age (seconds) before eligible
pub const ANCHOR_MIN_AGE: u64 = 3600; // 1 hour

/// Anchor peer minimum trust level
pub const ANCHOR_MIN_TRUST: reputation.TrustLevel = .member;

/// Connection rotation interval (seconds)
pub const ROTATION_INTERVAL: u64 = 1800; // 30 minutes

/// Minimum distinct subnets for outbound connections
pub const MIN_OUTBOUND_SUBNETS: usize = 3;

/// Multi-path verification: minimum confirmations needed
pub const MIN_BLOCK_CONFIRMATIONS: usize = 2;

/// Bucket count for connection distribution (by IP prefix)
pub const BUCKET_COUNT: usize = 16;

/// Max connections per bucket
pub const MAX_PER_BUCKET: usize = 4;

// =============================================================================
// Types
// =============================================================================

pub const ConnectionType = enum(u8) {
    inbound = 0, // Peer connected to us
    outbound = 1, // We connected to peer
    anchor = 2, // Long-term trusted peer
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
    confirmations: [8][32]u8, // Peer IDs that confirmed
    confirm_count: u8,
    first_seen: u64,
};

pub const EclipseAlert = struct {
    alert_type: EclipseAlertType,
    timestamp: u64,
    details: u32,
};

pub const EclipseAlertType = enum(u8) {
    low_outbound = 0, // Too few outbound connections
    low_diversity = 1, // Connections from few subnets
    inbound_flood = 2, // Too many inbound vs outbound
    anchor_lost = 3, // Lost anchor peer connection
    block_conflict = 4, // Different blocks at same height
    single_source_sync = 5, // Syncing from single peer (dangerous)
};

pub const EclipseStatus = struct {
    is_safe: bool,
    risk_level: u8, // 0-100, higher = more risk
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
        a.* = .{ .alert_type = .low_outbound, .timestamp = 0, .details = 0 };
    }
    alert_count = 0;

    for (&buckets) |*b| {
        b.* = 0;
    }

    last_rotation = 0;
    initialized = true;

    serial.writeString("[ECLIPSE] Defense system initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
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

/// Check if a new connection should be allowed
pub fn allowConnection(ip: u32, conn_type: ConnectionType) bool {
    const subnet = sybil.ipToSubnet(ip);
    const bucket = ipToBucket(ip);

    // Check bucket limit
    if (buckets[bucket] >= MAX_PER_BUCKET) {
        serial.writeString("[ECLIPSE] Bucket limit reached\n");
        return false;
    }

    // Check type limits
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

    // For outbound: prefer diverse subnets
    if (conn_type == .outbound) {
        const subnet_count = getSubnetCount(subnet);
        // Allow if this adds diversity or we need more connections
        if (subnet_count > 0 and getOutboundCount() >= MIN_OUTBOUND) {
            // Already have peers from this subnet and have enough outbound
            // Prefer a different subnet
            if (getDistinctOutboundSubnets() < MIN_OUTBOUND_SUBNETS) {
                serial.writeString("[ECLIPSE] Need more subnet diversity\n");
                return false;
            }
        }
    }

    return true;
}

/// Register a new connection
pub fn registerConnection(peer_id: *const [32]u8, ip: u32, conn_type: ConnectionType) bool {
    if (!allowConnection(ip, conn_type)) {
        return false;
    }

    // Find empty slot
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
                .is_anchor = false,
            };

            buckets[bucket] +|= 1;
            connection_count += 1;

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

/// Remove a connection
pub fn removeConnection(peer_id: *const [32]u8) void {
    for (&connections) |*c| {
        if (eqlBytes(&c.peer_id, peer_id)) {
            // Update bucket count
            if (buckets[c.bucket] > 0) {
                buckets[c.bucket] -= 1;
            }

            // Check if was anchor
            if (c.is_anchor) {
                removeAnchor(peer_id);
                addAlert(.anchor_lost, 0);
            }

            c.* = emptyConnection();
            if (connection_count > 0) connection_count -= 1;

            // Check health after removal
            checkHealth();
            return;
        }
    }
}

/// Get connection info for a peer
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

/// Promote a peer to anchor status
pub fn promoteToAnchor(peer_id: *const [32]u8) bool {
    // Check if already an anchor
    for (anchor_peers[0..anchor_count]) |*a| {
        if (eqlBytes(a, peer_id)) return true;
    }

    // Check anchor count limit
    if (anchor_count >= ANCHOR_PEER_COUNT) {
        serial.writeString("[ECLIPSE] Anchor slots full\n");
        return false;
    }

    // Check eligibility
    if (!isAnchorEligible(peer_id)) {
        serial.writeString("[ECLIPSE] Peer not eligible for anchor\n");
        return false;
    }

    // Add to anchors
    anchor_peers[anchor_count] = peer_id.*;
    anchor_count += 1;

    // Update connection info
    if (getConnection(peer_id)) |conn| {
        conn.is_anchor = true;
        conn.conn_type = .anchor;
    }

    serial.writeString("[ECLIPSE] Promoted peer to anchor\n");
    return true;
}

/// Check if peer is eligible to become anchor
pub fn isAnchorEligible(peer_id: *const [32]u8) bool {
    // Check reputation
    if (reputation.getReputation(peer_id)) |rep| {
        // Must be member or higher
        if (@intFromEnum(rep.trust_level) < @intFromEnum(ANCHOR_MIN_TRUST)) {
            return false;
        }

        // Must be old enough
        const age = reputation.getAge(rep);
        if (age < ANCHOR_MIN_AGE) {
            return false;
        }

        return true;
    }

    return false;
}

/// Remove anchor status
fn removeAnchor(peer_id: *const [32]u8) void {
    for (0..anchor_count) |i| {
        if (eqlBytes(&anchor_peers[i], peer_id)) {
            // Shift remaining
            var j = i;
            while (j + 1 < anchor_count) : (j += 1) {
                anchor_peers[j] = anchor_peers[j + 1];
            }
            anchor_count -= 1;
            return;
        }
    }
}

/// Check if peer is an anchor
pub fn isAnchor(peer_id: *const [32]u8) bool {
    for (anchor_peers[0..anchor_count]) |*a| {
        if (eqlBytes(a, peer_id)) return true;
    }
    return false;
}

/// Get anchor peers
pub fn getAnchors() []const [32]u8 {
    return anchor_peers[0..anchor_count];
}

/// Auto-promote eligible peers to anchors
pub fn autoPromoteAnchors() void {
    if (anchor_count >= ANCHOR_PEER_COUNT) return;

    // Find eligible peers
    for (&connections) |*c| {
        if (isEmptyPeerId(&c.peer_id)) continue;
        if (c.is_anchor) continue;
        if (c.conn_type != .outbound) continue; // Prefer outbound for anchors

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

/// Add a block confirmation from a peer
pub fn addBlockConfirmation(
    peer_id: *const [32]u8,
    block_height: u64,
    block_hash: *const [32]u8,
) bool {
    // Find existing pending block
    for (&pending_blocks) |*b| {
        if (b.block_height == block_height) {
            // Check if same hash
            if (eqlBytes(&b.block_hash, block_hash)) {
                // Add confirmation
                return addConfirmation(b, peer_id);
            } else {
                // CONFLICT! Different hashes for same height
                addAlert(.block_conflict, @intCast(block_height & 0xFFFFFFFF));
                serial.writeString("[ECLIPSE] ALERT: Block hash conflict at height ");
                printU64(block_height);
                serial.writeString("\n");
                return false;
            }
        }
    }

    // New block - add to pending
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
    // Check if already confirmed by this peer
    for (block.confirmations[0..block.confirm_count]) |*c| {
        if (eqlBytes(c, peer_id)) return true; // Already confirmed
    }

    // Add new confirmation
    if (block.confirm_count < 8) {
        block.confirmations[block.confirm_count] = peer_id.*;
        block.confirm_count += 1;
        return true;
    }

    return false;
}

/// Check if block has enough confirmations
pub fn isBlockConfirmed(block_height: u64) bool {
    for (pending_blocks[0..pending_block_count]) |*b| {
        if (b.block_height == block_height) {
            return b.confirm_count >= MIN_BLOCK_CONFIRMATIONS;
        }
    }
    return false;
}

/// Get confirmation count for a block
pub fn getBlockConfirmations(block_height: u64) u8 {
    for (pending_blocks[0..pending_block_count]) |b| {
        if (b.block_height == block_height) {
            return b.confirm_count;
        }
    }
    return 0;
}

/// Clear confirmed blocks (after they're accepted)
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

/// Rotate non-anchor connections periodically
pub fn rotateConnections() void {
    const now = getTimestamp();

    if (now < last_rotation + ROTATION_INTERVAL) {
        return; // Not time yet
    }

    last_rotation = now;

    // Count connections to rotate
    var to_rotate: usize = 0;
    var oldest_idx: usize = 0;
    var oldest_time: u64 = now;

    for (connections, 0..) |c, i| {
        if (isEmptyPeerId(&c.peer_id)) continue;
        if (c.is_anchor) continue; // Never rotate anchors
        if (c.conn_type == .anchor) continue;

        // Find oldest non-anchor inbound connection
        if (c.conn_type == .inbound and c.connected_at < oldest_time) {
            oldest_time = c.connected_at;
            oldest_idx = i;
            to_rotate += 1;
        }
    }

    // Rotate one connection if we have excess inbound
    if (to_rotate > 0 and getInboundCount() > MAX_INBOUND / 2) {
        const peer_id = connections[oldest_idx].peer_id;

        // Disconnect (peer module will call removeConnection)
        if (peer_mod.getById(peer_id)) |p| {
            serial.writeString("[ECLIPSE] Rotating old inbound connection\n");
            peer_mod.disconnect(p);
        }

        // Try to establish new outbound connection
        tryNewOutbound();
    }
}

/// Try to establish a new outbound connection
fn tryNewOutbound() void {
    if (getOutboundCount() >= MAX_OUTBOUND) return;

    // Get discovered peers and try to connect
    _ = discovery.connectToDiscovered(1);
}

// =============================================================================
// Health Monitoring
// =============================================================================

/// Check overall eclipse defense health
pub fn checkHealth() void {
    // Check outbound count
    if (getOutboundCount() < MIN_OUTBOUND) {
        addAlert(.low_outbound, getOutboundCount());
    }

    // Check diversity
    if (getDistinctOutboundSubnets() < MIN_OUTBOUND_SUBNETS) {
        addAlert(.low_diversity, getDistinctOutboundSubnets());
    }

    // Check inbound/outbound ratio
    const inbound = getInboundCount();
    const outbound = getOutboundCount();
    if (outbound > 0 and inbound > outbound * 3) {
        addAlert(.inbound_flood, inbound);
    }

    // Check anchor count
    if (anchor_count == 0 and connection_count > 4) {
        autoPromoteAnchors();
    }
}

/// Get current eclipse defense status
pub fn getStatus() EclipseStatus {
    const outbound = getOutboundCount();
    const inbound = getInboundCount();
    const diversity = getDistinctOutboundSubnets();

    // Calculate risk level (0-100)
    var risk: u32 = 0;

    // Low outbound = high risk
    if (outbound < MIN_OUTBOUND) {
        risk += 30;
    } else if (outbound < MIN_OUTBOUND + 2) {
        risk += 15;
    }

    // Low diversity = high risk
    if (diversity < MIN_OUTBOUND_SUBNETS) {
        risk += 25;
    } else if (diversity < MIN_OUTBOUND_SUBNETS + 2) {
        risk += 10;
    }

    // High inbound ratio = medium risk
    if (outbound > 0 and inbound > outbound * 2) {
        risk += 20;
    }

    // No anchors = some risk
    if (anchor_count == 0) {
        risk += 15;
    }

    // Recent alerts = some risk
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

        // Check if subnet already counted
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
    // Avoid duplicate recent alerts
    const now = getTimestamp();
    for (alerts[0..alert_count]) |a| {
        if (a.alert_type == alert_type and now - a.timestamp < 60) {
            return; // Recent duplicate
        }
    }

    if (alert_count >= alerts.len) {
        // Shift out oldest
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

pub fn clearAlerts() void {
    alert_count = 0;
}

// =============================================================================
// Reset (for testing)
// =============================================================================

pub fn resetForTest() void {
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
        a.* = .{ .alert_type = .low_outbound, .timestamp = 0, .details = 0 };
    }
    alert_count = 0;

    for (&buckets) |*b| {
        b.* = 0;
    }

    last_rotation = 0;
}

// =============================================================================
// Utilities
// =============================================================================

fn ipToBucket(ip: u32) u8 {
    // Use high byte of IP for bucketing (simple approach)
    const high_byte: u8 = @intCast((ip >> 24) & 0xFF);
    return @intCast(high_byte % BUCKET_COUNT);
}

fn isEmptyPeerId(id: *const [32]u8) bool {
    for (id) |b| {
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
