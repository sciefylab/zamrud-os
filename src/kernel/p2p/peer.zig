//! Zamrud OS - P2P Peer Management (H.3 HARDENED)
//! Manages connected peers with Sybil defense integration
//!
//! H.3 CHANGES:
//! ✅ Added proof_of_work field to Peer struct
//! ✅ Added first_seen field for age tracking
//! ✅ Added trust_level from reputation system
//! ✅ New addWithVerification() with full Sybil checks
//! ✅ Reputation delegates to reputation module
//! ✅ Disconnect removes from subnet tracking

const serial = @import("../drivers/serial/serial.zig");
const socket = @import("../net/socket.zig");
const crypto = @import("../crypto/crypto.zig");
const ct = @import("../crypto/constant_time.zig");
const reputation_mod = @import("reputation.zig");
const sybil = @import("sybil_defense.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_PEERS: usize = 64;
pub const PEER_TIMEOUT_MS: u64 = 120000;

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
    public_key: [32]u8,

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

    // H.3: Enhanced reputation
    reputation: i32,
    proof_of_work: u64, // PoW nonce (verified)
    first_seen: u64, // For age tracking
    trust_level: reputation_mod.TrustLevel, // From reputation system

    pub fn isActive(self: *const Peer) bool {
        return self.status == .connected;
    }
};

// =============================================================================
// State
// =============================================================================

var peers: [MAX_PEERS]Peer = undefined;
var peer_count: usize = 0;
var initialized: bool = false;

// Banned peers (by ID hash)
var banned_ids: [64][32]u8 = undefined;
var banned_count: usize = 0;

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

    // Initialize H.3 subsystems
    reputation_mod.init();
    sybil.init();

    initialized = true;
    serial.writeString("[PEER] Peer manager initialized (H.3 hardened)\n");
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
        .public_key = [_]u8{0} ** 32,
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
    };
}

// =============================================================================
// Peer Operations
// =============================================================================

/// Original add function — backward compatible (no PoW required)
/// Used for internal/trusted connections
pub fn add(id: [32]u8, ip: u32, port: u16, sock: *socket.Socket) ?*Peer {
    // Check if banned
    if (isBanned(id)) {
        serial.writeString("[PEER] Rejecting banned peer\n");
        return null;
    }

    // Check if already exists
    if (getById(id)) |existing| {
        existing.ip = ip;
        existing.port = port;
        existing.socket = sock;
        existing.status = .connected;
        existing.last_seen = getTimestamp();
        return existing;
    }

    return addToSlot(id, ip, port, sock, 0, .provisional);
}

/// H.3: Add peer with full Sybil defense verification
/// Used for incoming P2P connections
pub fn addWithVerification(
    id: [32]u8,
    ip: u32,
    port: u16,
    sock: *socket.Socket,
    pow_nonce: u64,
    pow_difficulty: u8,
) ?*Peer {
    // Check if banned
    if (isBanned(id)) {
        serial.writeString("[PEER] Rejecting banned peer\n");
        return null;
    }

    // Check if already exists
    if (getById(id)) |existing| {
        existing.ip = ip;
        existing.port = port;
        existing.socket = sock;
        existing.status = .connected;
        existing.last_seen = getTimestamp();
        return existing;
    }

    // H.3: Full Sybil defense check
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

    // Register in reputation system
    const rep = reputation_mod.registerPeer(&id, pow_nonce, pow_difficulty);
    const trust = if (rep) |r| r.trust_level else reputation_mod.TrustLevel.provisional;

    return addToSlot(id, ip, port, sock, pow_nonce, trust);
}

/// Internal: add peer to a slot
fn addToSlot(
    id: [32]u8,
    ip: u32,
    port: u16,
    sock: *socket.Socket,
    pow_nonce: u64,
    trust: reputation_mod.TrustLevel,
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
                .public_key = [_]u8{0} ** 32,
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
            };
            peer_count += 1;

            serial.writeString("[PEER] Added peer (trust=");
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

pub fn remove(id: [32]u8) void {
    for (&peers) |*p| {
        if (eqlBytes(&p.id, &id)) {
            if (p.socket) |sock| {
                socket.close(sock);
            }
            // H.3: Remove from subnet tracking
            sybil.removeSubnetPeer(p.ip);
            // H.3: Remove from reputation
            reputation_mod.removePeer(&p.id);
            p.* = emptyPeer();
            if (peer_count > 0) peer_count -= 1;
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
    // H.3: Remove from subnet tracking on disconnect
    sybil.removeSubnetPeer(p.ip);
    p.status = .disconnected;
}

pub fn disconnectAll() void {
    for (&peers) |*p| {
        if (p.status == .connected) {
            disconnect(p);
        }
    }
    peer_count = 0;
}

// =============================================================================
// Peer Lookup
// =============================================================================

pub fn getById(id: [32]u8) ?*Peer {
    for (&peers) |*p| {
        if (p.status != .disconnected and eqlBytes(&p.id, &id)) {
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

pub fn getAll() []Peer {
    return peers[0..MAX_PEERS];
}

pub fn getConnected() []*Peer {
    var result: [MAX_PEERS]*Peer = undefined;
    var count: usize = 0;

    for (&peers) |*p| {
        if (p.status == .connected) {
            result[count] = p;
            count += 1;
        }
    }

    return result[0..count];
}

pub fn getConnectedCount() usize {
    var count: usize = 0;
    for (peers) |p| {
        if (p.status == .connected) count += 1;
    }
    return count;
}

pub fn getTotalCount() usize {
    return peer_count;
}

// =============================================================================
// Reputation System (H.3: delegates to reputation module)
// =============================================================================

/// Record good behavior — delegates to reputation module
pub fn increaseReputation(p: *Peer, amount: i32) void {
    _ = amount;
    reputation_mod.addGoodAction(&p.id);

    // Sync cached values
    if (reputation_mod.getReputation(&p.id)) |rep| {
        p.reputation = rep.score;
        p.trust_level = rep.trust_level;
    }
}

/// Record bad behavior — delegates to reputation module
pub fn decreaseReputation(p: *Peer, amount: i32) void {
    _ = amount;
    reputation_mod.addViolation(&p.id);

    // Sync cached values
    if (reputation_mod.getReputation(&p.id)) |rep| {
        p.reputation = rep.score;
        p.trust_level = rep.trust_level;

        // Auto-ban if score drops below threshold
        if (rep.score <= reputation_mod.SCORE_BAN) {
            ban(p.id);
            disconnect(p);
        }
    }
}

/// Get trust level for a peer
pub fn getTrustLevel(p: *const Peer) reputation_mod.TrustLevel {
    return p.trust_level;
}

pub fn ban(id: [32]u8) void {
    if (banned_count >= banned_ids.len) return;

    banned_ids[banned_count] = id;
    banned_count += 1;

    serial.writeString("[PEER] Banned peer\n");
}

pub fn unban(id: [32]u8) void {
    for (0..banned_count) |i| {
        if (eqlBytes(&banned_ids[i], &id)) {
            var j = i;
            while (j + 1 < banned_count) : (j += 1) {
                banned_ids[j] = banned_ids[j + 1];
            }
            banned_count -= 1;
            return;
        }
    }
}

pub fn isBanned(id: [32]u8) bool {
    for (banned_ids[0..banned_count]) |bid| {
        if (eqlBytes(&bid, &id)) return true;
    }
    return false;
}

// =============================================================================
// H.3: Sybil Defense Accessors
// =============================================================================

/// Get peer diversity score (0-100)
pub fn getDiversityScore() u8 {
    return sybil.getDiversityScore();
}

/// Get Sybil alert count
pub fn getSybilAlertCount() usize {
    return sybil.getAlertCount();
}

/// Get total denied registrations
pub fn getDeniedCount() u64 {
    return sybil.getTotalDenials();
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
    if (val >= 10) printUsize(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}
