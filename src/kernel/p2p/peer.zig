//! Zamrud OS - P2P Peer Management (H.3 + H.4 + P.3e READY)
//! Manages connected peers with Sybil + Eclipse defense integration
//!
//! H.3:
//! - Proof-of-Work verification
//! - Reputation integration
//! - Subnet tracking
//!
//! H.4:
//! - Eclipse defense integration
//! - Connection type tracking
//! - Anchor peer support
//!
//! P.3e:
//! - Twin-Node Eviction support
//! - Safer static cached peer list slices
//! - Evicted/banned peer handling
//! - Compatible with eviction.zig

const serial = @import("../drivers/serial/serial.zig");
const socket = @import("../net/socket.zig");

const reputation_mod = @import("reputation.zig");
const sybil = @import("sybil_defense.zig");
const eclipse = @import("eclipse_defense.zig");
const gov_sign = @import("../crypto/gov_sign.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_PEERS: usize = 64;
pub const PEER_TIMEOUT_MS: u64 = 120000;

pub const MAX_BANNED_IDS: usize = 64;

// =============================================================================
// Types
// =============================================================================

pub const PeerStatus = enum {
    disconnected,
    connecting,
    connected,
    banned,
};

pub const Peer = struct {
    id: [32]u8,
    ip: u32,
    port: u16,
    status: PeerStatus,
    socket: ?*socket.Socket,
    public_key: [gov_sign.PUBLIC_KEY_BLOB_BYTES]u8,

    // Stats
    connected_at: u64,
    last_seen: u64,
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,

    // Sync state
    last_block: u64,
    capabilities: u32,

    // H.3: Reputation
    reputation: i32,
    proof_of_work: u64,
    first_seen: u64,
    trust_level: reputation_mod.TrustLevel,

    // H.4: Eclipse defense
    conn_type: eclipse.ConnectionType,

    pub fn isActive(self: *const Peer) bool {
        return self.status == .connected;
    }

    pub fn isAnchor(self: *const Peer) bool {
        return self.conn_type == .anchor;
    }

    pub fn isOutbound(self: *const Peer) bool {
        return self.conn_type == .outbound or self.conn_type == .anchor;
    }
};

// =============================================================================
// State
// =============================================================================

var peers: [MAX_PEERS]Peer = undefined;
var peer_count: usize = 0;
var initialized: bool = false;

// Banned peers by ID hash
var banned_ids: [MAX_BANNED_IDS][32]u8 = undefined;
var banned_count: usize = 0;

// Static result caches.
// Important: do not return slices pointing to local stack arrays.
var connected_cache: [MAX_PEERS]*Peer = undefined;
var inbound_cache: [MAX_PEERS]*Peer = undefined;
var outbound_cache: [MAX_PEERS]*Peer = undefined;
var anchor_cache: [MAX_PEERS]*Peer = undefined;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    peer_count = 0;
    banned_count = 0;

    for (&peers) |*p| {
        p.* = emptyPeer();
    }

    for (&banned_ids) |*id| {
        id.* = [_]u8{0} ** 32;
    }

    reputation_mod.init();
    sybil.init();
    eclipse.init();

    initialized = true;

    serial.writeString("[PEER] Peer manager initialized (H.3 + H.4 + P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyPeer() Peer {
    return .{
        .id = [_]u8{0} ** 32,
        .ip = 0,
        .port = 0,
        .status = .disconnected,
        .socket = null,
        .public_key = [_]u8{0} ** gov_sign.PUBLIC_KEY_BLOB_BYTES,

        .connected_at = 0,
        .last_seen = 0,
        .messages_sent = 0,
        .messages_received = 0,
        .bytes_sent = 0,
        .bytes_received = 0,

        .last_block = 0,
        .capabilities = 0,

        .reputation = 0,
        .proof_of_work = 0,
        .first_seen = 0,
        .trust_level = .untrusted,

        .conn_type = .inbound,
    };
}

// =============================================================================
// Peer Operations
// =============================================================================

/// Backward-compatible add function.
/// Internal/trusted connections are treated as outbound.
pub fn add(id: [32]u8, ip: u32, port: u16, sock: *socket.Socket) ?*Peer {
    return addWithType(id, ip, port, sock, .outbound);
}

pub fn addWithType(
    id: [32]u8,
    ip: u32,
    port: u16,
    sock: *socket.Socket,
    conn_type: eclipse.ConnectionType,
) ?*Peer {
    if (isBanned(id)) {
        serial.writeString("[PEER] Rejecting banned peer\n");
        return null;
    }

    if (!eclipse.allowConnection(ip, conn_type)) {
        serial.writeString("[PEER] Rejected by eclipse defense\n");
        return null;
    }

    if (getById(id)) |existing| {
        existing.ip = ip;
        existing.port = port;
        existing.socket = sock;
        existing.status = .connected;
        existing.last_seen = getTimestamp();
        existing.conn_type = conn_type;
        return existing;
    }

    return addToSlot(id, ip, port, sock, 0, .provisional, conn_type);
}

pub fn addInbound(id: [32]u8, ip: u32, port: u16, sock: *socket.Socket) ?*Peer {
    return addWithType(id, ip, port, sock, .inbound);
}

pub fn addOutbound(id: [32]u8, ip: u32, port: u16, sock: *socket.Socket) ?*Peer {
    return addWithType(id, ip, port, sock, .outbound);
}

/// H.3: Add peer with full Sybil defense verification.
pub fn addWithVerification(
    id: [32]u8,
    ip: u32,
    port: u16,
    sock: *socket.Socket,
    pow_nonce: u64,
    pow_difficulty: u8,
    conn_type: eclipse.ConnectionType,
) ?*Peer {
    if (isBanned(id)) {
        serial.writeString("[PEER] Rejecting banned peer\n");
        return null;
    }

    if (!eclipse.allowConnection(ip, conn_type)) {
        serial.writeString("[PEER] Rejected by eclipse defense\n");
        return null;
    }

    if (getById(id)) |existing| {
        existing.ip = ip;
        existing.port = port;
        existing.socket = sock;
        existing.status = .connected;
        existing.last_seen = getTimestamp();
        existing.conn_type = conn_type;
        return existing;
    }

    const result = sybil.checkRegistration(ip, &id, pow_nonce, pow_difficulty);

    switch (result) {
        .allowed => {},

        .denied_no_pow => {
            serial.writeString("[PEER] DENIED: No Proof-of-Work\n");
            return null;
        },

        .denied_invalid_pow => {
            serial.writeString("[PEER] DENIED: Invalid Proof-of-Work\n");
            return null;
        },

        .denied_rate_limit => {
            serial.writeString("[PEER] DENIED: Rate limit exceeded\n");
            return null;
        },

        .denied_subnet_limit => {
            serial.writeString("[PEER] DENIED: Too many peers from subnet\n");
            return null;
        },

        .denied_sybil_detected => {
            serial.writeString("[PEER] DENIED: Sybil attack pattern detected\n");
            ban(id);
            return null;
        },
    }

    const rep = reputation_mod.registerPeer(&id, pow_nonce, pow_difficulty);
    const trust = if (rep) |r| r.trust_level else reputation_mod.TrustLevel.provisional;

    return addToSlot(id, ip, port, sock, pow_nonce, trust, conn_type);
}

fn addToSlot(
    id: [32]u8,
    ip: u32,
    port: u16,
    sock: *socket.Socket,
    pow_nonce: u64,
    trust: reputation_mod.TrustLevel,
    conn_type: eclipse.ConnectionType,
) ?*Peer {
    for (&peers) |*p| {
        if (p.status == .disconnected) {
            const now = getTimestamp();

            p.* = .{
                .id = id,
                .ip = ip,
                .port = port,
                .status = .connected,
                .socket = sock,
                .public_key = [_]u8{0} ** gov_sign.PUBLIC_KEY_BLOB_BYTES,

                .connected_at = now,
                .last_seen = now,
                .messages_sent = 0,
                .messages_received = 0,
                .bytes_sent = 0,
                .bytes_received = 0,

                .last_block = 0,
                .capabilities = 0,

                .reputation = 50,
                .proof_of_work = pow_nonce,
                .first_seen = now,
                .trust_level = trust,

                .conn_type = conn_type,
            };

            peer_count += 1;

            _ = eclipse.registerConnection(&id, ip, conn_type);

            serial.writeString("[PEER] Added peer (");

            switch (conn_type) {
                .inbound => serial.writeString("inbound"),
                .outbound => serial.writeString("outbound"),
                .anchor => serial.writeString("anchor"),
            }

            serial.writeString(", trust=");

            switch (trust) {
                .untrusted => serial.writeString("untrusted"),
                .provisional => serial.writeString("provisional"),
                .member => serial.writeString("member"),
                .trusted => serial.writeString("trusted"),
            }

            serial.writeString("), total: ");
            printUsize(peer_count);
            serial.writeString("\n");

            return p;
        }
    }

    serial.writeString("[PEER] No slots available\n");
    return null;
}

/// Remove peer from active table.
/// If peer is already banned, keep reputation entry so P.3e ban score remains auditable.
pub fn remove(id: [32]u8) void {
    for (&peers) |*p| {
        if (p.status != .disconnected and eqlBytes(p.id[0..], id[0..])) {
            const was_banned = isBanned(id);

            if (p.socket) |sock| {
                socket.close(sock);
            }

            sybil.removeSubnetPeer(p.ip);

            if (!was_banned) {
                reputation_mod.removePeer(&p.id);
            }

            if (@hasDecl(eclipse, "removeEvictedConnection") and was_banned) {
                eclipse.removeEvictedConnection(&p.id);
            } else {
                eclipse.removeConnection(&p.id);
            }

            p.* = emptyPeer();

            if (peer_count > 0) {
                peer_count -= 1;
            }

            serial.writeString("[PEER] Removed peer\n");
            return;
        }
    }
}

pub fn disconnect(p: *Peer) void {
    if (p.socket) |sock| {
        socket.close(sock);
        p.socket = null;
    }

    sybil.removeSubnetPeer(p.ip);
    eclipse.removeConnection(&p.id);

    p.status = .disconnected;

    if (peer_count > 0) {
        peer_count -= 1;
    }
}

pub fn disconnectAll() void {
    for (&peers) |*p| {
        if (p.status == .connected or p.status == .connecting) {
            if (p.socket) |sock| {
                socket.close(sock);
            }

            sybil.removeSubnetPeer(p.ip);
            eclipse.removeConnection(&p.id);

            p.* = emptyPeer();
        }
    }

    peer_count = 0;
}

// =============================================================================
// P.3e Eviction Helpers
// =============================================================================

/// Execute local peer-level eviction.
/// This is a convenience helper. The full Twin-Node logic lives in eviction.zig.
pub fn evict(id: [32]u8) void {
    ban(id);
    remove(id);
}

pub fn isEvicted(id: [32]u8) bool {
    return isBanned(id);
}

// =============================================================================
// Peer Lookup
// =============================================================================

pub fn getById(id: [32]u8) ?*Peer {
    for (&peers) |*p| {
        if (p.status != .disconnected and eqlBytes(p.id[0..], id[0..])) {
            return p;
        }
    }

    return null;
}

pub fn getByIp(ip: u32) ?*Peer {
    for (&peers) |*p| {
        if (p.status != .disconnected and p.ip == ip) {
            return p;
        }
    }

    return null;
}

/// Returns full peer storage slice.
/// Caller should check status.
pub fn getAll() []Peer {
    return peers[0..MAX_PEERS];
}

pub fn getPeerByIndex(index: usize) ?*Peer {
    if (index >= MAX_PEERS) return null;
    return &peers[index];
}

/// Safe static-cache list of connected peers.
pub fn getConnected() []*Peer {
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected) {
            connected_cache[count] = p;
            count += 1;
        }
    }

    return connected_cache[0..count];
}

pub fn getConnectedCount() usize {
    var count: usize = 0;

    for (peers) |p| {
        if (p.status == .connected) {
            count += 1;
        }
    }

    return count;
}

pub fn getTotalCount() usize {
    return peer_count;
}

// =============================================================================
// H.4: Connection Type Queries
// =============================================================================

pub fn getOutbound() []*Peer {
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected and p.isOutbound()) {
            outbound_cache[count] = p;
            count += 1;
        }
    }

    return outbound_cache[0..count];
}

pub fn getInbound() []*Peer {
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected and p.conn_type == .inbound) {
            inbound_cache[count] = p;
            count += 1;
        }
    }

    return inbound_cache[0..count];
}

pub fn getAnchors() []*Peer {
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected and p.conn_type == .anchor) {
            anchor_cache[count] = p;
            count += 1;
        }
    }

    return anchor_cache[0..count];
}

pub fn getOutboundCount() usize {
    return eclipse.getOutboundCount();
}

pub fn getInboundCount() usize {
    return eclipse.getInboundCount();
}

pub fn getAnchorCount() usize {
    return eclipse.getAnchorCount();
}

pub fn promoteToAnchor(p: *Peer) bool {
    if (eclipse.promoteToAnchor(&p.id)) {
        p.conn_type = .anchor;
        serial.writeString("[PEER] Promoted to anchor\n");
        return true;
    }

    return false;
}

// =============================================================================
// Reputation System
// =============================================================================

pub fn increaseReputation(p: *Peer, amount: i32) void {
    _ = amount;

    reputation_mod.addGoodAction(&p.id);

    if (reputation_mod.getReputation(&p.id)) |rep| {
        p.reputation = rep.score;
        p.trust_level = rep.trust_level;
    }
}

pub fn decreaseReputation(p: *Peer, amount: i32) void {
    _ = amount;

    reputation_mod.addViolation(&p.id);

    if (reputation_mod.getReputation(&p.id)) |rep| {
        p.reputation = rep.score;
        p.trust_level = rep.trust_level;

        if (rep.score <= reputation_mod.SCORE_BAN) {
            ban(p.id);
            disconnect(p);
        }
    }
}

pub fn recordSevereViolation(p: *Peer) void {
    if (@hasDecl(reputation_mod, "recordSevereViolation")) {
        reputation_mod.recordSevereViolation(&p.id);
    } else {
        reputation_mod.addViolation(&p.id);
        reputation_mod.addViolation(&p.id);
        reputation_mod.addViolation(&p.id);
    }

    if (reputation_mod.getReputation(&p.id)) |rep| {
        p.reputation = rep.score;
        p.trust_level = rep.trust_level;

        if (rep.score <= reputation_mod.SCORE_BAN) {
            ban(p.id);
            disconnect(p);
        }
    }
}

pub fn getTrustLevel(p: *const Peer) reputation_mod.TrustLevel {
    return p.trust_level;
}

pub fn getReputationScore(p: *const Peer) i32 {
    return p.reputation;
}

// =============================================================================
// Ban List
// =============================================================================

pub fn ban(id: [32]u8) void {
    if (isBanned(id)) {
        return;
    }

    if (banned_count >= banned_ids.len) {
        serial.writeString("[PEER] Ban list full\n");
        return;
    }

    banned_ids[banned_count] = id;
    banned_count += 1;

    // Mark active peer as banned and close socket if present.
    if (getById(id)) |p| {
        if (p.socket) |sock| {
            socket.close(sock);
            p.socket = null;
        }

        p.status = .banned;
    }

    serial.writeString("[PEER] Banned peer\n");
}

pub fn unban(id: [32]u8) void {
    for (0..banned_count) |i| {
        if (eqlBytes(banned_ids[i][0..], id[0..])) {
            var j = i;

            while (j + 1 < banned_count) : (j += 1) {
                banned_ids[j] = banned_ids[j + 1];
            }

            banned_ids[banned_count - 1] = [_]u8{0} ** 32;
            banned_count -= 1;

            serial.writeString("[PEER] Unbanned peer\n");
            return;
        }
    }
}

pub fn isBanned(id: [32]u8) bool {
    for (banned_ids[0..banned_count]) |bid| {
        if (eqlBytes(bid[0..], id[0..])) {
            return true;
        }
    }

    return false;
}

pub fn getBannedCount() usize {
    return banned_count;
}

pub fn getBannedId(index: usize) ?[32]u8 {
    if (index >= banned_count) return null;
    return banned_ids[index];
}

// =============================================================================
// H.3: Sybil Defense Accessors
// =============================================================================

pub fn getDiversityScore() u8 {
    return sybil.getDiversityScore();
}

pub fn getSybilAlertCount() usize {
    return sybil.getAlertCount();
}

pub fn getDeniedCount() u64 {
    return sybil.getTotalDenials();
}

// =============================================================================
// H.4: Eclipse Defense Accessors
// =============================================================================

pub fn getEclipseStatus() eclipse.EclipseStatus {
    return eclipse.getStatus();
}

pub fn getEclipseAlertCount() usize {
    return eclipse.getAlertCount();
}

pub fn isEclipseSafe() bool {
    return eclipse.getStatus().is_safe;
}

pub fn getEclipseRisk() u8 {
    return eclipse.getStatus().risk_level;
}

// =============================================================================
// Maintenance
// =============================================================================

pub fn checkTimeouts() void {
    const now = getTimestamp();

    for (&peers) |*p| {
        if (p.status == .connected) {
            if (now > p.last_seen + PEER_TIMEOUT_MS / 1000) {
                serial.writeString("[PEER] Peer timed out\n");
                disconnect(p);
            }
        }
    }

    eclipse.checkHealth();
    eclipse.rotateConnections();
    eclipse.autoPromoteAnchors();
}

pub fn updateLastSeen(p: *Peer) void {
    p.last_seen = getTimestamp();
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    for (a, b) |x, y| {
        if (x != y) return false;
    }

    return true;
}

fn printUsize(val: usize) void {
    if (val >= 10) {
        printUsize(val / 10);
    }

    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  PEER MANAGER TESTS H.3/H.4/P.3e\n");
    serial.writeString("========================================\n\n");

    if (!initialized) {
        init();
    }

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1] initialized.............. ");
    if (initialized) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [2] ban/unban................ ");
    {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xAA;

        ban(id);

        if (isBanned(id)) {
            unban(id);

            if (!isBanned(id)) {
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

    serial.writeString("  [3] static connected cache... ");
    {
        const list = getConnected();

        if (list.len <= MAX_PEERS) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [4] ban duplicate safe....... ");
    {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xBB;

        const before = getBannedCount();

        ban(id);
        ban(id);

        const after = getBannedCount();

        if (after == before + 1 or isBanned(id)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }

        unban(id);
    }

    serial.writeString("\n  Peer Results: ");
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
