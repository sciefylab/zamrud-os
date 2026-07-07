//! Zamrud OS - P.3e Twin-Node Eviction Engine
//! Network Kill-Switch for malicious P2P nodes
//!
//! Security Model:
//! - Single node cannot evict alone.
//! - Requires two independent voters.
//! - Voters must be different from target and from each other.
//! - Evidence hash must match.
//! - Voters must be authorized by security/authority.zig.
//! - Voters must also be behaviorally healthy by p2p/reputation.zig.
//!
//! Final enforcement:
//! 1. peer.ban(target)
//! 2. peer.remove(target)
//! 3. reputation.forceBanScore(target)
//! 4. eclipse.removeEvictedConnection(target)
//! 5. discovery.markPeerEvicted(target)
//! 6. firewall.blockEvictedPeerIp(target_ip)
//! 7. firewall.dropExistingFlows(target_ip)
//! 8. broadcast eviction_commit

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

const hash_mod = @import("../crypto/hash.zig");

const peer = @import("peer.zig");
const p2p = @import("p2p.zig");
const reputation = @import("reputation.zig");
const eclipse = @import("eclipse_defense.zig");
const discovery = @import("discovery.zig");

const authority = @import("../security/authority.zig");
const threat_score = @import("../security/threat_score.zig");
const violation = @import("../security/violation.zig");
const firewall = @import("../net/firewall.zig");

// =============================================================================
// Constants
// =============================================================================

pub const EVICTION_MAGIC = [_]u8{ 'Z', 'M', 'E', 'V', 'I', 'C', 'T', '1' };
pub const EVICTION_VERSION: u32 = 1;

pub const MAX_PENDING_RECORDS: usize = 32;
pub const MAX_EXECUTED_RECORDS: usize = 32;

pub const VOTE_TTL_SECONDS: u64 = 300;
pub const MIN_TWIN_VOTES: u8 = 2;

pub const VOTE_PAYLOAD_SIZE: usize = 130;
pub const COMMIT_PAYLOAD_SIZE: usize = 154;

// =============================================================================
// Types
// =============================================================================

pub const EvictionReason = enum(u8) {
    duplicate_identity = 1,
    invalid_signature = 2,
    malicious_onion_route = 3,
    sybil_confirmed = 4,
    eclipse_attack = 5,
    hardware_mismatch = 6,
    protocol_violation = 7,
    eviction_vote_spam = 8,
    peer_impersonation = 9,
};

pub const PayloadKind = enum(u8) {
    vote = 1,
    commit = 2,
    notice = 3,
};

pub const VoteValidationResult = enum {
    valid,
    invalid_size,
    invalid_magic,
    invalid_version,
    invalid_kind,
    stale,
    self_target,
    voter_is_target,
    sender_mismatch,
    unauthorized_voter,
    unhealthy_voter,
    duplicate,
};

pub const EvictionVote = struct {
    reason: EvictionReason,
    target_id: [32]u8,
    voter_id: [32]u8,
    target_ip: u32,
    evidence_hash: [32]u8,
    timestamp: u64,
    nonce: u64,
};

pub const EvictionCommit = struct {
    reason: EvictionReason,
    target_id: [32]u8,
    voter_a: [32]u8,
    voter_b: [32]u8,
    target_ip: u32,
    evidence_hash: [32]u8,
    timestamp: u64,
};

pub const EvictionRecord = struct {
    active: bool,
    executed: bool,

    reason: EvictionReason,
    target_id: [32]u8,
    target_ip: u32,
    evidence_hash: [32]u8,

    voter_a: [32]u8,
    voter_b: [32]u8,
    vote_count: u8,

    created_at: u64,
    executed_at: u64,
};

pub const EvictionStats = struct {
    votes_received: u64 = 0,
    votes_accepted: u64 = 0,
    votes_rejected: u64 = 0,
    duplicate_votes: u64 = 0,
    unauthorized_votes: u64 = 0,
    unhealthy_votes: u64 = 0,

    commits_received: u64 = 0,
    commits_executed: u64 = 0,
    commits_rejected: u64 = 0,

    local_evidence_reports: u64 = 0,
    evictions_executed: u64 = 0,

    firewall_blocks: u64 = 0,
    firewall_flow_drops: u64 = 0,
};

// =============================================================================
// State
// =============================================================================

var pending_records: [MAX_PENDING_RECORDS]EvictionRecord = undefined;
var executed_records: [MAX_EXECUTED_RECORDS]EvictionRecord = undefined;

var executed_count: usize = 0;
var initialized: bool = false;

/// Test flag.
/// When enabled, executeEviction() skips security evidence scoring to prevent
/// tests from escalating into global lockdown.
var test_mode: bool = false;

pub var stats = EvictionStats{};

var evidence_input: [256]u8 = [_]u8{0} ** 256;
var encode_buffer: [COMMIT_PAYLOAD_SIZE]u8 = [_]u8{0} ** COMMIT_PAYLOAD_SIZE;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&pending_records) |*r| {
        r.* = emptyRecord();
    }

    for (&executed_records) |*r| {
        r.* = emptyRecord();
    }

    executed_count = 0;
    stats = EvictionStats{};
    test_mode = false;
    initialized = true;

    if (!authority.isInitialized()) authority.init();

    serial.writeString("[EVICTION] P.3e Twin-Node Eviction Engine initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyRecord() EvictionRecord {
    return .{
        .active = false,
        .executed = false,
        .reason = .protocol_violation,
        .target_id = [_]u8{0} ** 32,
        .target_ip = 0,
        .evidence_hash = [_]u8{0} ** 32,
        .voter_a = [_]u8{0} ** 32,
        .voter_b = [_]u8{0} ** 32,
        .vote_count = 0,
        .created_at = 0,
        .executed_at = 0,
    };
}

// =============================================================================
// Local Evidence Reporting
// =============================================================================

pub fn reportLocalEvidence(
    target_id: [32]u8,
    target_ip: u32,
    reason: EvictionReason,
    detail: []const u8,
) bool {
    if (!initialized) init();

    const local_id = p2p.getNodeId();

    if (eqlBytes(&target_id, &local_id)) {
        serial.writeString("[EVICTION] Refusing to generate self-eviction vote\n");
        return false;
    }

    var evidence_hash: [32]u8 = [_]u8{0} ** 32;
    buildEvidenceHash(&target_id, target_ip, reason, detail, &evidence_hash);

    recordSecurityEvidence(target_ip, reason, detail);

    if (@hasDecl(reputation, "recordEvictionEvidence")) {
        reputation.recordEvictionEvidence(&target_id, &evidence_hash);
    } else {
        reputation.addViolation(&target_id);
        reputation.addViolation(&target_id);
    }

    const vote = EvictionVote{
        .reason = reason,
        .target_id = target_id,
        .voter_id = local_id,
        .target_ip = target_ip,
        .evidence_hash = evidence_hash,
        .timestamp = getTimestamp(),
        .nonce = makeNonce(target_id, local_id, evidence_hash),
    };

    const add_result = addVote(vote);

    if (add_result == .duplicate) {
        stats.duplicate_votes += 1;
    }

    const len = encodeVote(&vote, &encode_buffer);
    if (len == 0) return false;

    broadcastVote(target_id, encode_buffer[0..len]);

    stats.local_evidence_reports += 1;

    serial.writeString("[EVICTION] Local eviction evidence reported and vote broadcast\n");
    return true;
}

// =============================================================================
// Inbound Vote / Commit Handlers
// =============================================================================

pub fn handleVoteMessage(sender: *peer.Peer, payload: []const u8) void {
    if (!initialized) init();

    stats.votes_received += 1;

    const vote = decodeVote(payload) orelse {
        stats.votes_rejected += 1;
        punishBadVoter(sender, .p2p_eviction_vote_invalid, "bad eviction vote payload");
        return;
    };

    const validation = validateVote(sender, &vote);

    if (validation != .valid) {
        stats.votes_rejected += 1;

        switch (validation) {
            .duplicate => {
                stats.duplicate_votes += 1;
            },
            .unauthorized_voter => {
                stats.unauthorized_votes += 1;
                punishBadVoter(sender, .p2p_eviction_vote_invalid, "unauthorized eviction voter");
            },
            .unhealthy_voter => {
                stats.unhealthy_votes += 1;
                punishBadVoter(sender, .p2p_eviction_vote_invalid, "unhealthy eviction voter");
            },
            else => {
                punishBadVoter(sender, .p2p_eviction_vote_invalid, "invalid eviction vote");
            },
        }

        return;
    }

    const result = addVote(vote);

    switch (result) {
        .valid => {
            stats.votes_accepted += 1;
            serial.writeString("[EVICTION] Eviction vote accepted\n");
        },
        .duplicate => {
            stats.duplicate_votes += 1;
            serial.writeString("[EVICTION] Duplicate eviction vote ignored\n");
        },
        else => {
            stats.votes_rejected += 1;
            punishBadVoter(sender, .p2p_eviction_vote_invalid, "rejected eviction vote");
        },
    }
}

pub fn handleCommitMessage(sender: *peer.Peer, payload: []const u8) void {
    if (!initialized) init();

    stats.commits_received += 1;

    const commit = decodeCommit(payload) orelse {
        stats.commits_rejected += 1;
        punishBadVoter(sender, .p2p_eviction_vote_invalid, "bad eviction commit payload");
        return;
    };

    if (!validateCommit(&commit)) {
        stats.commits_rejected += 1;
        punishBadVoter(sender, .p2p_eviction_vote_invalid, "invalid or unauthorized eviction commit");
        return;
    }

    executeEviction(
        commit.target_id,
        commit.target_ip,
        commit.reason,
        commit.evidence_hash,
        commit.voter_a,
        commit.voter_b,
        false,
    );

    stats.commits_executed += 1;
}

// =============================================================================
// Vote State Machine
// =============================================================================

fn addVote(vote: EvictionVote) VoteValidationResult {
    cleanupExpiredVotes();

    if (isEvicted(vote.target_id)) {
        return .duplicate;
    }

    for (&pending_records) |*r| {
        if (!r.active) continue;
        if (r.executed) continue;

        if (eqlBytes(&r.target_id, &vote.target_id) and
            r.reason == vote.reason and
            eqlBytes(&r.evidence_hash, &vote.evidence_hash))
        {
            if (eqlBytes(&r.voter_a, &vote.voter_id)) {
                return .duplicate;
            }

            if (r.vote_count >= 2 and eqlBytes(&r.voter_b, &vote.voter_id)) {
                return .duplicate;
            }

            if (r.vote_count == 1) {
                r.voter_b = vote.voter_id;
                r.vote_count = 2;

                serial.writeString("[EVICTION] Twin vote confirmed. Executing eviction.\n");

                executeEviction(
                    r.target_id,
                    r.target_ip,
                    r.reason,
                    r.evidence_hash,
                    r.voter_a,
                    r.voter_b,
                    true,
                );

                r.executed = true;
                r.executed_at = getTimestamp();

                return .valid;
            }

            return .duplicate;
        }
    }

    for (&pending_records) |*r| {
        if (!r.active) {
            r.* = .{
                .active = true,
                .executed = false,
                .reason = vote.reason,
                .target_id = vote.target_id,
                .target_ip = vote.target_ip,
                .evidence_hash = vote.evidence_hash,
                .voter_a = vote.voter_id,
                .voter_b = [_]u8{0} ** 32,
                .vote_count = 1,
                .created_at = getTimestamp(),
                .executed_at = 0,
            };

            return .valid;
        }
    }

    serial.writeString("[EVICTION] No pending record slots available\n");
    return .invalid_size;
}

fn validateVote(sender: *peer.Peer, vote: *const EvictionVote) VoteValidationResult {
    const now = getTimestamp();

    if (!eqlBytes(&sender.id, &vote.voter_id)) {
        return .sender_mismatch;
    }

    if (vote.timestamp + VOTE_TTL_SECONDS < now) {
        return .stale;
    }

    const local_id = p2p.getNodeId();

    if (eqlBytes(&vote.target_id, &local_id)) {
        return .self_target;
    }

    if (eqlBytes(&vote.target_id, &vote.voter_id)) {
        return .voter_is_target;
    }

    // Source-of-truth authority check.
    if (!authority.canVoteForEviction(&vote.voter_id)) {
        return .unauthorized_voter;
    }

    // Behavior health check.
    if (@hasDecl(reputation, "isPeerHealthyForEviction")) {
        if (!reputation.isPeerHealthyForEviction(&vote.voter_id)) {
            return .unhealthy_voter;
        }
    }

    return .valid;
}

fn validateCommit(commit: *const EvictionCommit) bool {
    const local_id = p2p.getNodeId();

    if (eqlBytes(&commit.target_id, &local_id)) {
        serial.writeString("[EVICTION] Refusing commit targeting local node\n");
        return false;
    }

    if (eqlBytes(&commit.target_id, &commit.voter_a)) return false;
    if (eqlBytes(&commit.target_id, &commit.voter_b)) return false;
    if (eqlBytes(&commit.voter_a, &commit.voter_b)) return false;

    if (commit.timestamp + VOTE_TTL_SECONDS < getTimestamp()) {
        return false;
    }

    if (!authority.canCommitEviction(&commit.voter_a)) return false;
    if (!authority.canCommitEviction(&commit.voter_b)) return false;

    if (@hasDecl(reputation, "isPeerHealthyForEviction")) {
        if (!reputation.isPeerHealthyForEviction(&commit.voter_a)) return false;
        if (!reputation.isPeerHealthyForEviction(&commit.voter_b)) return false;
    }

    return true;
}

// =============================================================================
// Eviction Execution
// =============================================================================

fn executeEviction(
    target_id: [32]u8,
    target_ip: u32,
    reason: EvictionReason,
    evidence_hash: [32]u8,
    voter_a: [32]u8,
    voter_b: [32]u8,
    should_broadcast_commit: bool,
) void {
    if (isEvicted(target_id)) {
        return;
    }

    serial.writeString("[EVICTION] EXECUTING NETWORK KILL-SWITCH for peer\n");

    if (@hasDecl(reputation, "forceBanScore")) {
        reputation.forceBanScore(&target_id);
    }

    peer.ban(target_id);
    peer.remove(target_id);

    if (@hasDecl(eclipse, "removeEvictedConnection")) {
        eclipse.removeEvictedConnection(&target_id);
    } else {
        eclipse.removeConnection(&target_id);
    }

    if (@hasDecl(discovery, "markPeerEvicted")) {
        discovery.markPeerEvicted(&target_id);
    }

    if (target_ip != 0) {
        if (!test_mode) {
            recordSecurityEvidence(target_ip, reason, "twin-node eviction executed");
        }

        if (@hasDecl(firewall, "blockEvictedPeerIp")) {
            if (firewall.blockEvictedPeerIp(target_ip, "P.3e twin-node eviction")) {
                stats.firewall_blocks += 1;
            }
        }

        if (@hasDecl(firewall, "dropExistingFlows")) {
            firewall.dropExistingFlows(target_ip);
            stats.firewall_flow_drops += 1;
        }
    }

    storeExecutedRecord(target_id, target_ip, reason, evidence_hash, voter_a, voter_b);

    stats.evictions_executed += 1;

    if (should_broadcast_commit) {
        const commit = EvictionCommit{
            .reason = reason,
            .target_id = target_id,
            .voter_a = voter_a,
            .voter_b = voter_b,
            .target_ip = target_ip,
            .evidence_hash = evidence_hash,
            .timestamp = getTimestamp(),
        };

        const len = encodeCommit(&commit, &encode_buffer);

        if (len > 0) {
            broadcastCommit(target_id, encode_buffer[0..len]);
        }
    }
}

fn storeExecutedRecord(
    target_id: [32]u8,
    target_ip: u32,
    reason: EvictionReason,
    evidence_hash: [32]u8,
    voter_a: [32]u8,
    voter_b: [32]u8,
) void {
    const idx = executed_count % MAX_EXECUTED_RECORDS;

    executed_records[idx] = .{
        .active = true,
        .executed = true,
        .reason = reason,
        .target_id = target_id,
        .target_ip = target_ip,
        .evidence_hash = evidence_hash,
        .voter_a = voter_a,
        .voter_b = voter_b,
        .vote_count = 2,
        .created_at = getTimestamp(),
        .executed_at = getTimestamp(),
    };

    executed_count += 1;
}

pub fn isEvicted(target_id: [32]u8) bool {
    if (peer.isBanned(target_id)) return true;

    for (&executed_records) |*r| {
        if (!r.active) continue;
        if (!r.executed) continue;

        if (eqlBytes(&r.target_id, &target_id)) {
            return true;
        }
    }

    return false;
}

// =============================================================================
// Security Evidence Hooks
// =============================================================================

fn recordSecurityEvidence(
    target_ip: u32,
    reason: EvictionReason,
    detail: []const u8,
) void {
    if (target_ip == 0) return;

    const event_type = reasonToThreatEvent(reason);
    const violation_type = reasonToViolation(reason);

    _ = threat_score.recordP2PThreat(target_ip, event_type, .high);

    _ = violation.reportP2PViolation(
        target_ip,
        violation_type,
        .high,
        detail,
    );
}

fn punishBadVoter(
    sender: *peer.Peer,
    vtype: violation.ViolationType,
    detail: []const u8,
) void {
    serial.writeString("[EVICTION] Bad eviction voter punished\n");

    peer.decreaseReputation(sender, 10);

    _ = threat_score.recordP2PThreat(
        sender.ip,
        .p2p_eviction_spam,
        .medium,
    );

    _ = violation.reportP2PViolation(
        sender.ip,
        vtype,
        .medium,
        detail,
    );
}

fn reasonToThreatEvent(reason: EvictionReason) threat_score.EventType {
    return switch (reason) {
        .duplicate_identity => .p2p_duplicate_identity,
        .invalid_signature => .signature_invalid,
        .malicious_onion_route => .p2p_onion_abuse,
        .sybil_confirmed => .p2p_eviction_evidence,
        .eclipse_attack => .p2p_eviction_evidence,
        .hardware_mismatch => .p2p_peer_impersonation,
        .protocol_violation => .protocol_error,
        .eviction_vote_spam => .p2p_eviction_spam,
        .peer_impersonation => .p2p_peer_impersonation,
    };
}

fn reasonToViolation(reason: EvictionReason) violation.ViolationType {
    return switch (reason) {
        .duplicate_identity => .p2p_duplicate_identity,
        .invalid_signature => .p2p_peer_impersonation,
        .malicious_onion_route => .p2p_invalid_onion_route,
        .sybil_confirmed => .p2p_peer_impersonation,
        .eclipse_attack => .network_violation,
        .hardware_mismatch => .p2p_hardware_attestation_failed,
        .protocol_violation => .network_violation,
        .eviction_vote_spam => .p2p_eviction_spam,
        .peer_impersonation => .p2p_peer_impersonation,
    };
}

// =============================================================================
// Encoding / Decoding
// =============================================================================

pub fn encodeVote(vote: *const EvictionVote, buffer: []u8) usize {
    if (buffer.len < VOTE_PAYLOAD_SIZE) return 0;

    var pos: usize = 0;

    @memcpy(buffer[pos..][0..8], &EVICTION_MAGIC);
    pos += 8;

    writeU32(buffer[pos..], EVICTION_VERSION);
    pos += 4;

    buffer[pos] = @intFromEnum(PayloadKind.vote);
    pos += 1;

    buffer[pos] = @intFromEnum(vote.reason);
    pos += 1;

    @memcpy(buffer[pos..][0..32], &vote.target_id);
    pos += 32;

    @memcpy(buffer[pos..][0..32], &vote.voter_id);
    pos += 32;

    writeU32(buffer[pos..], vote.target_ip);
    pos += 4;

    @memcpy(buffer[pos..][0..32], &vote.evidence_hash);
    pos += 32;

    writeU64(buffer[pos..], vote.timestamp);
    pos += 8;

    writeU64(buffer[pos..], vote.nonce);
    pos += 8;

    return pos;
}

pub fn decodeVote(data: []const u8) ?EvictionVote {
    if (data.len < VOTE_PAYLOAD_SIZE) return null;

    var pos: usize = 0;

    if (!checkMagic(data[pos..][0..8])) return null;
    pos += 8;

    const version = readU32(data[pos..]);
    pos += 4;

    if (version != EVICTION_VERSION) return null;

    const kind_int = data[pos];
    pos += 1;

    if (kind_int != @intFromEnum(PayloadKind.vote)) return null;

    const reason: EvictionReason = @enumFromInt(data[pos]);
    pos += 1;

    var target_id: [32]u8 = undefined;
    @memcpy(&target_id, data[pos..][0..32]);
    pos += 32;

    var voter_id: [32]u8 = undefined;
    @memcpy(&voter_id, data[pos..][0..32]);
    pos += 32;

    const target_ip = readU32(data[pos..]);
    pos += 4;

    var evidence_hash: [32]u8 = undefined;
    @memcpy(&evidence_hash, data[pos..][0..32]);
    pos += 32;

    const timestamp = readU64(data[pos..]);
    pos += 8;

    const nonce = readU64(data[pos..]);
    pos += 8;

    return .{
        .reason = reason,
        .target_id = target_id,
        .voter_id = voter_id,
        .target_ip = target_ip,
        .evidence_hash = evidence_hash,
        .timestamp = timestamp,
        .nonce = nonce,
    };
}

pub fn encodeCommit(commit: *const EvictionCommit, buffer: []u8) usize {
    if (buffer.len < COMMIT_PAYLOAD_SIZE) return 0;

    var pos: usize = 0;

    @memcpy(buffer[pos..][0..8], &EVICTION_MAGIC);
    pos += 8;

    writeU32(buffer[pos..], EVICTION_VERSION);
    pos += 4;

    buffer[pos] = @intFromEnum(PayloadKind.commit);
    pos += 1;

    buffer[pos] = @intFromEnum(commit.reason);
    pos += 1;

    @memcpy(buffer[pos..][0..32], &commit.target_id);
    pos += 32;

    @memcpy(buffer[pos..][0..32], &commit.voter_a);
    pos += 32;

    @memcpy(buffer[pos..][0..32], &commit.voter_b);
    pos += 32;

    writeU32(buffer[pos..], commit.target_ip);
    pos += 4;

    @memcpy(buffer[pos..][0..32], &commit.evidence_hash);
    pos += 32;

    writeU64(buffer[pos..], commit.timestamp);
    pos += 8;

    return pos;
}

pub fn decodeCommit(data: []const u8) ?EvictionCommit {
    if (data.len < COMMIT_PAYLOAD_SIZE) return null;

    var pos: usize = 0;

    if (!checkMagic(data[pos..][0..8])) return null;
    pos += 8;

    const version = readU32(data[pos..]);
    pos += 4;

    if (version != EVICTION_VERSION) return null;

    const kind_int = data[pos];
    pos += 1;

    if (kind_int != @intFromEnum(PayloadKind.commit)) return null;

    const reason: EvictionReason = @enumFromInt(data[pos]);
    pos += 1;

    var target_id: [32]u8 = undefined;
    @memcpy(&target_id, data[pos..][0..32]);
    pos += 32;

    var voter_a: [32]u8 = undefined;
    @memcpy(&voter_a, data[pos..][0..32]);
    pos += 32;

    var voter_b: [32]u8 = undefined;
    @memcpy(&voter_b, data[pos..][0..32]);
    pos += 32;

    const target_ip = readU32(data[pos..]);
    pos += 4;

    var evidence_hash: [32]u8 = undefined;
    @memcpy(&evidence_hash, data[pos..][0..32]);
    pos += 32;

    const timestamp = readU64(data[pos..]);
    pos += 8;

    return .{
        .reason = reason,
        .target_id = target_id,
        .voter_a = voter_a,
        .voter_b = voter_b,
        .target_ip = target_ip,
        .evidence_hash = evidence_hash,
        .timestamp = timestamp,
    };
}

// =============================================================================
// Broadcast Helpers
// =============================================================================

fn broadcastVote(target_id: [32]u8, payload: []const u8) void {
    if (@hasDecl(p2p, "broadcastExcept")) {
        p2p.broadcastExcept(target_id, .eviction_vote, payload);
    } else {
        p2p.broadcast(.eviction_vote, payload);
    }
}

fn broadcastCommit(target_id: [32]u8, payload: []const u8) void {
    if (@hasDecl(p2p, "broadcastExcept")) {
        p2p.broadcastExcept(target_id, .eviction_commit, payload);
    } else {
        p2p.broadcast(.eviction_commit, payload);
    }
}

// =============================================================================
// Evidence Hash
// =============================================================================

pub fn buildEvidenceHash(
    target_id: *const [32]u8,
    target_ip: u32,
    reason: EvictionReason,
    detail: []const u8,
    out_hash: *[32]u8,
) void {
    var pos: usize = 0;

    @memcpy(evidence_input[pos..][0..32], target_id);
    pos += 32;

    writeU32(evidence_input[pos..], target_ip);
    pos += 4;

    evidence_input[pos] = @intFromEnum(reason);
    pos += 1;

    const dlen = @min(detail.len, evidence_input.len - pos);

    if (dlen > 0) {
        @memcpy(evidence_input[pos..][0..dlen], detail[0..dlen]);
        pos += dlen;
    }

    hash_mod.sha256Into(evidence_input[0..pos], out_hash);
}

fn makeNonce(target_id: [32]u8, voter_id: [32]u8, evidence_hash: [32]u8) u64 {
    var input: [96]u8 = undefined;
    var out: [32]u8 = undefined;

    @memcpy(input[0..32], &target_id);
    @memcpy(input[32..64], &voter_id);
    @memcpy(input[64..96], &evidence_hash);

    hash_mod.sha256Into(&input, &out);

    return readU64(out[0..8]);
}

// =============================================================================
// Maintenance
// =============================================================================

pub fn pollMaintenance() void {
    cleanupExpiredVotes();
}

fn cleanupExpiredVotes() void {
    const now = getTimestamp();

    for (&pending_records) |*r| {
        if (!r.active) continue;
        if (r.executed) continue;

        if (r.created_at + VOTE_TTL_SECONDS < now) {
            r.* = emptyRecord();
        }
    }
}

// =============================================================================
// Query API
// =============================================================================

pub fn getStats() EvictionStats {
    return stats;
}

pub fn getPendingCount() usize {
    var count: usize = 0;

    for (&pending_records) |*r| {
        if (r.active and !r.executed) {
            count += 1;
        }
    }

    return count;
}

pub fn getExecutedCount() usize {
    return @min(executed_count, MAX_EXECUTED_RECORDS);
}

pub fn getPendingRecord(index: usize) ?*const EvictionRecord {
    var count: usize = 0;

    for (&pending_records) |*r| {
        if (r.active and !r.executed) {
            if (count == index) return r;
            count += 1;
        }
    }

    return null;
}

pub fn getExecutedRecord(index: usize) ?*const EvictionRecord {
    if (index >= getExecutedCount()) return null;
    return &executed_records[index];
}

// =============================================================================
// Utilities
// =============================================================================

fn checkMagic(data: []const u8) bool {
    if (data.len < 8) return false;

    var i: usize = 0;

    while (i < 8) : (i += 1) {
        if (data[i] != EVICTION_MAGIC[i]) return false;
    }

    return true;
}

fn getTimestamp() u64 {
    return timer.getSeconds();
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    for (a, b) |x, y| {
        if (x != y) return false;
    }

    return true;
}

fn writeU32(buf: []u8, val: u32) void {
    buf[0] = @intCast((val >> 24) & 0xFF);
    buf[1] = @intCast((val >> 16) & 0xFF);
    buf[2] = @intCast((val >> 8) & 0xFF);
    buf[3] = @intCast(val & 0xFF);
}

fn writeU64(buf: []u8, val: u64) void {
    buf[0] = @intCast((val >> 56) & 0xFF);
    buf[1] = @intCast((val >> 48) & 0xFF);
    buf[2] = @intCast((val >> 40) & 0xFF);
    buf[3] = @intCast((val >> 32) & 0xFF);
    buf[4] = @intCast((val >> 24) & 0xFF);
    buf[5] = @intCast((val >> 16) & 0xFF);
    buf[6] = @intCast((val >> 8) & 0xFF);
    buf[7] = @intCast(val & 0xFF);
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readU64(data: []const u8) u64 {
    return (@as(u64, data[0]) << 56) |
        (@as(u64, data[1]) << 48) |
        (@as(u64, data[2]) << 40) |
        (@as(u64, data[3]) << 32) |
        (@as(u64, data[4]) << 24) |
        (@as(u64, data[5]) << 16) |
        (@as(u64, data[6]) << 8) |
        @as(u64, data[7]);
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
    serial.writeString("  P.3e TWIN-NODE EVICTION TESTS\n");
    serial.writeString("========================================\n\n");

    init();

    var passed: u32 = 0;
    var failed: u32 = 0;

    var target: [32]u8 = [_]u8{0} ** 32;
    var voter: [32]u8 = [_]u8{0} ** 32;
    var evidence: [32]u8 = [_]u8{0} ** 32;

    target[0] = 0xAA;
    voter[0] = 0xBB;
    evidence[0] = 0xEE;

    serial.writeString("  [1] encode/decode vote....... ");
    {
        const vote = EvictionVote{
            .reason = .protocol_violation,
            .target_id = target,
            .voter_id = voter,
            .target_ip = 0xC0A80101,
            .evidence_hash = evidence,
            .timestamp = getTimestamp(),
            .nonce = 12345,
        };

        var buf: [VOTE_PAYLOAD_SIZE]u8 = undefined;
        const len = encodeVote(&vote, &buf);

        if (len == VOTE_PAYLOAD_SIZE) {
            if (decodeVote(&buf)) |decoded| {
                if (decoded.reason == .protocol_violation and
                    eqlBytes(&decoded.target_id, &target) and
                    eqlBytes(&decoded.voter_id, &voter))
                {
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
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [2] encode/decode commit..... ");
    {
        var voter_b: [32]u8 = [_]u8{0} ** 32;
        voter_b[0] = 0xCC;

        const commit = EvictionCommit{
            .reason = .duplicate_identity,
            .target_id = target,
            .voter_a = voter,
            .voter_b = voter_b,
            .target_ip = 0xC0A80102,
            .evidence_hash = evidence,
            .timestamp = getTimestamp(),
        };

        var buf: [COMMIT_PAYLOAD_SIZE]u8 = undefined;
        const len = encodeCommit(&commit, &buf);

        if (len == COMMIT_PAYLOAD_SIZE) {
            if (decodeCommit(&buf)) |decoded| {
                if (decoded.reason == .duplicate_identity and
                    eqlBytes(&decoded.voter_a, &voter) and
                    eqlBytes(&decoded.voter_b, &voter_b))
                {
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
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [3] evidence hash............ ");
    {
        var out: [32]u8 = [_]u8{0} ** 32;

        buildEvidenceHash(
            &target,
            0xC0A80101,
            .protocol_violation,
            "test evidence",
            &out,
        );

        var nonzero = false;

        for (out) |b| {
            if (b != 0) {
                nonzero = true;
                break;
            }
        }

        if (nonzero) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [4] firewall integration..... ");
    {
        var voter_a: [32]u8 = [_]u8{0} ** 32;
        var voter_b: [32]u8 = [_]u8{0} ** 32;
        var target2: [32]u8 = [_]u8{0} ** 32;
        var evidence2: [32]u8 = [_]u8{0} ** 32;

        voter_a[0] = 0xA1;
        voter_b[0] = 0xB2;
        target2[0] = 0xD1;
        evidence2[0] = 0xE1;

        const target_ip: u32 = 0xC0A8FA77; // 192.168.250.119

        if (!firewall.isInitialized()) {
            firewall.init();
        }

        test_mode = true;

        if (@hasDecl(firewall, "setP3eTestMode")) {
            firewall.setP3eTestMode(true);
        }

        executeEviction(
            target2,
            target_ip,
            .protocol_violation,
            evidence2,
            voter_a,
            voter_b,
            false,
        );

        const blocked = firewall.isBlockedByFirewall(target_ip);
        const stat_ok = stats.firewall_blocks > 0;

        _ = firewall.removeFromBlacklist(target_ip);

        if (@hasDecl(threat_score, "resetScore")) {
            _ = threat_score.resetScore(target_ip);
        }

        peer.unban(target2);

        if (@hasDecl(firewall, "setP3eTestMode")) {
            firewall.setP3eTestMode(false);
        }

        test_mode = false;

        if (blocked and stat_ok) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [5] authority voter gate..... ");
    {
        if (@hasDecl(authority, "resetForTest")) {
            authority.resetForTest();
        }

        var root: [32]u8 = [_]u8{0} ** 32;
        var validator: [32]u8 = [_]u8{0} ** 32;
        var guest: [32]u8 = [_]u8{0} ** 32;
        var hw: [32]u8 = [_]u8{0} ** 32;

        root[0] = 0xF0;
        validator[0] = 0xA5;
        guest[0] = 0xC5;
        hw[0] = 0x44;

        _ = authority.registerRootAuthority(&root, "root");
        _ = authority.registerValidator(&validator, &root, &hw, true, true, "validator");
        _ = authority.registerGuest(&guest, "guest");

        const good = authority.canVoteForEviction(&validator);
        const bad = authority.canVoteForEviction(&guest);

        if (good and !bad) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  P.3e Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
