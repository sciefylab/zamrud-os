//! Zamrud OS - P2P Peer Reputation System
//! H.3 Reputation Layer with Security Authority as Source-of-Truth
//!
//! security/authority.zig is the global authority source-of-truth.
//! p2p/reputation.zig tracks behavior score, violations, vouches,
//! eviction evidence, forced ban state, and legacy anti-spam PoW compatibility.

const serial = @import("../drivers/serial/serial.zig");
const hash_mod = @import("../crypto/hash.zig");
const ct = @import("../crypto/constant_time.zig");
const authority = @import("../security/authority.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_TRACKED: usize = 64;
pub const MAX_VOUCHERS: usize = 4;

// Legacy anti-spam PoW compatibility.
// Not primary trust.
pub const DEFAULT_POW_DIFFICULTY: u8 = 16;
pub const TEST_POW_DIFFICULTY: u8 = 8;

// Score thresholds
pub const SCORE_UNTRUSTED: i32 = 0;
pub const SCORE_PROVISIONAL: i32 = 50;
pub const SCORE_MEMBER: i32 = 200;
pub const SCORE_TRUSTED: i32 = 500;
pub const SCORE_BAN: i32 = -100;
pub const SCORE_MAX: i32 = 1000;
pub const SCORE_MIN: i32 = -500;

// Authority score mirror.
// Authority source-of-truth remains security/authority.zig.
pub const AUTH_UNKNOWN_SCORE: i32 = 0;
pub const AUTH_GUEST_SCORE: i32 = 25;
pub const AUTH_MEMBER_SCORE: i32 = 100;
pub const AUTH_VALIDATOR_SCORE: i32 = 250;
pub const AUTH_ROOT_SCORE: i32 = 500;

// Attestation score mirror
pub const HARDWARE_ATTEST_BONUS: i32 = 100;
pub const CHAIN_REGISTERED_BONUS: i32 = 100;
pub const AUTHORITY_SIGNATURE_BONUS: i32 = 150;

// Legacy PoW anti-spam score
pub const POW_BASE_SCORE: i32 = 10;
pub const POW_EXTRA_PER_BIT: i32 = 1;

// Behavior scoring
pub const GOOD_ACTION_SCORE: i32 = 2;
pub const VIOLATION_PENALTY: i32 = 10;
pub const SEVERE_VIOLATION_PENALTY: i32 = 50;
pub const EVICTION_EVIDENCE_PENALTY: i32 = 75;
pub const VOUCH_BONUS: i32 = 25;
pub const AGE_BONUS_PER_HOUR: i32 = 1;
pub const AGE_BONUS_MAX: i32 = 100;

// =============================================================================
// Type aliases from global authority
// =============================================================================

pub const AuthorityLevel = authority.AuthorityLevel;
pub const AttestationState = authority.AttestationState;

pub const TrustLevel = enum(u8) {
    untrusted = 0,
    provisional = 1,
    member = 2,
    trusted = 3,
};

pub const PeerReputation = struct {
    peer_id: [32]u8,
    active: bool,

    // Composite P2P behavior score
    score: i32,

    // Permanent behavior ban flag.
    // When true, recalculateScore() must not lift the peer score again.
    force_banned: bool,

    // Timing
    first_seen: u64,
    last_active: u64,

    // Behavior
    good_actions: u32,
    violations: u32,
    severe_violations: u32,
    eviction_evidence_count: u32,
    last_evidence_hash: [32]u8,

    // Mirrored authority metadata for scoring/display only.
    // Source-of-truth is security/authority.zig.
    authority_level: AuthorityLevel,
    attestation_state: AttestationState,
    attestation_verified: bool,
    chain_verified: bool,
    authority_signature_verified: bool,
    hardware_hash: [32]u8,
    authority_id: [32]u8,

    // Legacy optional anti-spam PoW
    pow_difficulty: u8,
    pow_verified: bool,
    proof_of_work: u64,

    // Vouching
    voucher_count: u8,
    vouchers: [MAX_VOUCHERS][32]u8,

    // Derived
    trust_level: TrustLevel,
};

// =============================================================================
// State
// =============================================================================

var reputations: [MAX_TRACKED]PeerReputation = undefined;
var rep_count: usize = 0;
var initialized: bool = false;

// Legacy PoW static buffers
var pow_input: [40]u8 = [_]u8{0} ** 40;
var pow_hash: [32]u8 = [_]u8{0} ** 32;
const leading_masks = [8]u8{ 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE };

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&reputations) |*r| {
        r.* = emptyReputation();
    }

    rep_count = 0;
    initialized = true;

    if (!authority.isInitialized()) {
        authority.init();
    }

    serial.writeString("[REPUTATION] P2P reputation layer initialized (authority-backed)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyReputation() PeerReputation {
    return .{
        .peer_id = [_]u8{0} ** 32,
        .active = false,

        .score = 0,
        .force_banned = false,

        .first_seen = 0,
        .last_active = 0,

        .good_actions = 0,
        .violations = 0,
        .severe_violations = 0,
        .eviction_evidence_count = 0,
        .last_evidence_hash = [_]u8{0} ** 32,

        .authority_level = .unknown,
        .attestation_state = .none,
        .attestation_verified = false,
        .chain_verified = false,
        .authority_signature_verified = false,
        .hardware_hash = [_]u8{0} ** 32,
        .authority_id = [_]u8{0} ** 32,

        .pow_difficulty = 0,
        .pow_verified = false,
        .proof_of_work = 0,

        .voucher_count = 0,
        .vouchers = [_][32]u8{[_]u8{0} ** 32} ** MAX_VOUCHERS,

        .trust_level = .untrusted,
    };
}

// =============================================================================
// Authority-backed registration
// =============================================================================

pub fn registerAuthorityPeer(
    peer_id: *const [32]u8,
    authority_level: AuthorityLevel,
    authority_id: *const [32]u8,
) ?*PeerReputation {
    if (!authority.isInitialized()) authority.init();

    switch (authority_level) {
        .root_authority => {
            _ = authority.registerRootAuthority(peer_id, "p2p-root");
        },
        .validator => {
            var empty_hw: [32]u8 = [_]u8{0} ** 32;
            _ = authority.registerValidator(peer_id, authority_id, &empty_hw, true, true, "p2p-validator");
        },
        .member => {
            var empty_hw: [32]u8 = [_]u8{0} ** 32;
            _ = authority.registerMember(peer_id, authority_id, &empty_hw, true, true, "p2p-member");
        },
        .guest => {
            _ = authority.registerGuest(peer_id, "p2p-guest");
        },
        .unknown => {},
    }

    const r = getOrCreateReputation(peer_id) orelse return null;

    syncFromAuthority(r);
    r.last_active = getTimestamp();

    recalculateScore(r);

    serial.writeString("[REPUTATION] Authority mirror registered\n");
    return r;
}

pub fn registerAttestedPeer(
    peer_id: *const [32]u8,
    authority_level: AuthorityLevel,
    hardware_hash: *const [32]u8,
    chain_verified: bool,
    authority_signature_verified: bool,
    authority_id: *const [32]u8,
) ?*PeerReputation {
    if (!authority.isInitialized()) authority.init();

    switch (authority_level) {
        .root_authority => {
            _ = authority.registerRootAuthority(peer_id, "p2p-root");
            _ = authority.updateAttestation(
                peer_id,
                hardware_hash,
                true,
                chain_verified,
                authority_signature_verified,
            );
        },
        .validator => {
            _ = authority.registerValidator(
                peer_id,
                authority_id,
                hardware_hash,
                chain_verified,
                authority_signature_verified,
                "p2p-validator",
            );
        },
        .member => {
            _ = authority.registerMember(
                peer_id,
                authority_id,
                hardware_hash,
                chain_verified,
                authority_signature_verified,
                "p2p-member",
            );
        },
        .guest => {
            _ = authority.registerGuest(peer_id, "p2p-guest");
            _ = authority.updateAttestation(
                peer_id,
                hardware_hash,
                true,
                chain_verified,
                authority_signature_verified,
            );
        },
        .unknown => {},
    }

    const r = getOrCreateReputation(peer_id) orelse return null;

    syncFromAuthority(r);
    r.last_active = getTimestamp();

    recalculateScore(r);

    serial.writeString("[REPUTATION] Attested authority mirror registered\n");
    return r;
}

/// Legacy registration path.
/// Kept so sybil_defense.zig and old tests still compile.
/// This is optional anti-spam registration, not primary trust.
pub fn registerPeer(peer_id: *const [32]u8, pow_nonce: u64, difficulty: u8) ?*PeerReputation {
    if (!verifyPow(peer_id, pow_nonce, difficulty)) {
        serial.writeString("[REPUTATION] Legacy PoW verification failed\n");
        return null;
    }

    if (!authority.isInitialized()) authority.init();

    if (!authority.isKnownAuthority(peer_id)) {
        _ = authority.registerGuest(peer_id, "legacy-pow-guest");
    }

    const r = getOrCreateReputation(peer_id) orelse return null;

    r.pow_difficulty = difficulty;
    r.pow_verified = true;
    r.proof_of_work = pow_nonce;

    syncFromAuthority(r);
    r.last_active = getTimestamp();

    recalculateScore(r);

    serial.writeString("[REPUTATION] Legacy PoW peer registered as guest\n");
    return r;
}

fn getOrCreateReputation(peer_id: *const [32]u8) ?*PeerReputation {
    if (getReputation(peer_id)) |existing| {
        existing.last_active = getTimestamp();
        return existing;
    }

    for (&reputations) |*r| {
        if (!r.active) {
            r.* = emptyReputation();

            @memcpy(&r.peer_id, peer_id);

            r.active = true;
            r.first_seen = getTimestamp();
            r.last_active = r.first_seen;

            rep_count += 1;

            return r;
        }
    }

    serial.writeString("[REPUTATION] No slots available\n");
    return null;
}

pub fn syncFromAuthority(r: *PeerReputation) void {
    if (!authority.isInitialized()) authority.init();

    if (authority.getEntryConst(&r.peer_id)) |entry| {
        r.authority_level = entry.level;
        r.attestation_state = entry.attestation_state;
        r.attestation_verified = entry.hardware_attested;
        r.chain_verified = entry.chain_verified;
        r.authority_signature_verified = entry.authority_signature_verified;
        r.hardware_hash = entry.hardware_hash;
        r.authority_id = entry.authority_id;
    } else {
        r.authority_level = .unknown;
        r.attestation_state = .none;
        r.attestation_verified = false;
        r.chain_verified = false;
        r.authority_signature_verified = false;
        r.hardware_hash = [_]u8{0} ** 32;
        r.authority_id = [_]u8{0} ** 32;
    }
}

pub fn syncPeerFromAuthority(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        syncFromAuthority(r);
        recalculateScore(r);
    }
}

// =============================================================================
// Lookup / Removal
// =============================================================================

pub fn getReputation(peer_id: *const [32]u8) ?*PeerReputation {
    for (&reputations) |*r| {
        if (r.active and ct.constantTimeCompare32(&r.peer_id, peer_id)) {
            return r;
        }
    }

    return null;
}

pub fn removePeer(peer_id: *const [32]u8) void {
    for (&reputations) |*r| {
        if (r.active and ct.constantTimeCompare32(&r.peer_id, peer_id)) {
            ct.secureZero(&r.peer_id);
            r.* = emptyReputation();

            if (rep_count > 0) {
                rep_count -= 1;
            }

            return;
        }
    }
}

pub fn getTrackedCount() usize {
    return rep_count;
}

pub fn getAuthorityCount() usize {
    if (!authority.isInitialized()) return 0;
    return authority.getAuthorityCount();
}

pub fn isSmallNetwork() bool {
    if (!authority.isInitialized()) return true;
    return authority.isSmallNetwork();
}

// =============================================================================
// Reputation scoring
// =============================================================================

pub fn addGoodAction(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.good_actions +|= 1;
        r.last_active = getTimestamp();
        syncFromAuthority(r);
        recalculateScore(r);
    }
}

pub fn addViolation(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.violations +|= 1;
        r.last_active = getTimestamp();

        if (authority.isInitialized()) {
            authority.recordAuthorityViolation(peer_id);
        }

        syncFromAuthority(r);
        recalculateScore(r);
    }
}

pub fn recordSevereViolation(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.severe_violations +|= 1;
        r.last_active = getTimestamp();

        if (authority.isInitialized()) {
            authority.recordAuthorityViolation(peer_id);
        }

        syncFromAuthority(r);
        recalculateScore(r);

        serial.writeString("[REPUTATION] Severe violation recorded\n");
    }
}

pub fn recordEvictionEvidence(peer_id: *const [32]u8, evidence_hash: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.eviction_evidence_count +|= 1;
        r.last_evidence_hash = evidence_hash.*;
        r.last_active = getTimestamp();

        syncFromAuthority(r);
        recalculateScore(r);

        serial.writeString("[REPUTATION] Eviction evidence recorded\n");
    }
}

pub fn forceBanScore(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.force_banned = true;
        r.score = SCORE_BAN;
        r.trust_level = .untrusted;
        r.last_active = getTimestamp();

        serial.writeString("[REPUTATION] Peer score forced to ban threshold\n");
    }
}

pub fn clearForceBan(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.force_banned = false;
        r.last_active = getTimestamp();
        recalculateScore(r);
    }
}

pub fn recalculateScore(r: *PeerReputation) void {
    if (r.force_banned) {
        r.score = SCORE_BAN;
        r.trust_level = .untrusted;
        return;
    }

    syncFromAuthority(r);

    var score: i32 = 0;

    score += authorityScore(r.authority_level);

    if (r.attestation_verified) {
        score += HARDWARE_ATTEST_BONUS;
    }

    if (r.chain_verified) {
        score += CHAIN_REGISTERED_BONUS;
    }

    if (r.authority_signature_verified) {
        score += AUTHORITY_SIGNATURE_BONUS;
    }

    if (r.pow_verified) {
        score += POW_BASE_SCORE;
        score += @as(i32, @intCast(r.pow_difficulty)) * POW_EXTRA_PER_BIT;
    }

    score += @min(@as(i32, @intCast(r.good_actions)) * GOOD_ACTION_SCORE, 200);
    score -= @as(i32, @intCast(r.violations)) * VIOLATION_PENALTY;
    score -= @as(i32, @intCast(r.severe_violations)) * SEVERE_VIOLATION_PENALTY;
    score -= @as(i32, @intCast(r.eviction_evidence_count)) * EVICTION_EVIDENCE_PENALTY;
    score += @as(i32, @intCast(r.voucher_count)) * VOUCH_BONUS;

    const now = getTimestamp();
    if (now > r.first_seen) {
        const age_hours: i32 = @intCast(@min((now - r.first_seen) / 3600, 1000));
        score += @min(age_hours * AGE_BONUS_PER_HOUR, AGE_BONUS_MAX);
    }

    if (score > SCORE_MAX) score = SCORE_MAX;
    if (score < SCORE_MIN) score = SCORE_MIN;

    r.score = score;
    r.trust_level = calculateTrustLevel(r);
}

fn authorityScore(level: AuthorityLevel) i32 {
    return switch (level) {
        .unknown => AUTH_UNKNOWN_SCORE,
        .guest => AUTH_GUEST_SCORE,
        .member => AUTH_MEMBER_SCORE,
        .validator => AUTH_VALIDATOR_SCORE,
        .root_authority => AUTH_ROOT_SCORE,
    };
}

pub fn calculateTrustLevel(r: *const PeerReputation) TrustLevel {
    if (r.score >= SCORE_TRUSTED) return .trusted;
    if (r.score >= SCORE_MEMBER) return .member;
    if (r.score >= SCORE_PROVISIONAL) return .provisional;
    return .untrusted;
}

pub fn getAge(r: *const PeerReputation) u64 {
    const now = getTimestamp();
    if (now > r.first_seen) return now - r.first_seen;
    return 0;
}

pub fn getScore(peer_id: *const [32]u8) i32 {
    if (getReputation(peer_id)) |r| {
        return r.score;
    }

    return SCORE_UNTRUSTED;
}

pub fn getTrustLevelById(peer_id: *const [32]u8) TrustLevel {
    if (getReputation(peer_id)) |r| {
        return r.trust_level;
    }

    return .untrusted;
}

// =============================================================================
// Eviction eligibility
// =============================================================================

pub fn isPeerHealthyForEviction(peer_id: *const [32]u8) bool {
    if (getReputation(peer_id)) |r| {
        if (r.force_banned) return false;
        if (r.score <= SCORE_BAN) return false;

        syncFromAuthority(r);
        recalculateScore(r);

        return r.active and !r.force_banned and r.score > SCORE_BAN;
    }

    return true;
}

pub fn canVoteForEviction(peer_id: *const [32]u8) bool {
    if (!authority.isInitialized()) authority.init();

    if (!authority.canVoteForEviction(peer_id)) {
        return false;
    }

    return isPeerHealthyForEviction(peer_id);
}

pub fn canCommitEviction(peer_id: *const [32]u8) bool {
    if (!authority.isInitialized()) authority.init();

    if (!authority.canCommitEviction(peer_id)) {
        return false;
    }

    return isPeerHealthyForEviction(peer_id);
}

pub fn canEmergencyQuarantine(peer_id: *const [32]u8) bool {
    if (!authority.isInitialized()) authority.init();

    if (!authority.canEmergencyQuarantine(peer_id)) {
        return false;
    }

    return isPeerHealthyForEviction(peer_id);
}

// =============================================================================
// Vouching
// =============================================================================

pub fn addVouch(peer_id: *const [32]u8, voucher_id: *const [32]u8) bool {
    const voucher = getReputation(voucher_id) orelse return false;

    if (@intFromEnum(voucher.trust_level) < @intFromEnum(TrustLevel.member)) {
        return false;
    }

    const target = getReputation(peer_id) orelse return false;

    var i: usize = 0;
    while (i < target.voucher_count) : (i += 1) {
        if (ct.constantTimeCompare32(&target.vouchers[i], voucher_id)) {
            return false;
        }
    }

    if (target.voucher_count >= MAX_VOUCHERS) return false;

    @memcpy(&target.vouchers[target.voucher_count], voucher_id);
    target.voucher_count += 1;

    recalculateScore(target);
    return true;
}

pub fn getVouchCount(peer_id: *const [32]u8) u8 {
    const rep = getReputation(peer_id) orelse return 0;
    return rep.voucher_count;
}

// =============================================================================
// Legacy PoW compatibility
// =============================================================================

pub fn hasLeadingZeroBits(h: *const [32]u8, bits: u8) bool {
    if (bits == 0) return true;
    if (bits > 255) return false;

    const full_bytes: usize = @as(usize, bits) / 8;
    const remaining: u8 = bits % 8;

    var i: usize = 0;
    while (i < full_bytes) : (i += 1) {
        if (i >= 32) return true;
        if (h[i] != 0) return false;
    }

    if (remaining > 0 and full_bytes < 32) {
        if (h[full_bytes] & leading_masks[remaining] != 0) return false;
    }

    return true;
}

pub fn verifyPow(peer_id: *const [32]u8, nonce: u64, difficulty: u8) bool {
    @memcpy(pow_input[0..32], peer_id);

    pow_input[32] = @truncate(nonce);
    pow_input[33] = @truncate(nonce >> 8);
    pow_input[34] = @truncate(nonce >> 16);
    pow_input[35] = @truncate(nonce >> 24);
    pow_input[36] = @truncate(nonce >> 32);
    pow_input[37] = @truncate(nonce >> 40);
    pow_input[38] = @truncate(nonce >> 48);
    pow_input[39] = @truncate(nonce >> 56);

    hash_mod.sha256Into(&pow_input, &pow_hash);

    return hasLeadingZeroBits(&pow_hash, difficulty);
}

pub fn generatePow(peer_id: *const [32]u8, difficulty: u8, max_iterations: u64) ?u64 {
    @memcpy(pow_input[0..32], peer_id);

    var nonce: u64 = 0;
    while (nonce < max_iterations) : (nonce += 1) {
        pow_input[32] = @truncate(nonce);
        pow_input[33] = @truncate(nonce >> 8);
        pow_input[34] = @truncate(nonce >> 16);
        pow_input[35] = @truncate(nonce >> 24);
        pow_input[36] = @truncate(nonce >> 32);
        pow_input[37] = @truncate(nonce >> 40);
        pow_input[38] = @truncate(nonce >> 48);
        pow_input[39] = @truncate(nonce >> 56);

        hash_mod.sha256Into(&pow_input, &pow_hash);

        if (hasLeadingZeroBits(&pow_hash, difficulty)) {
            return nonce;
        }
    }

    return null;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const t = @import("../drivers/timer/timer.zig");
    return t.getSeconds();
}

// =============================================================================
// Tests
// =============================================================================

var test_peer_a: [32]u8 = [_]u8{0} ** 32;
var test_peer_b: [32]u8 = [_]u8{0} ** 32;
var test_peer_c: [32]u8 = [_]u8{0} ** 32;
var test_root: [32]u8 = [_]u8{0} ** 32;
var test_hw: [32]u8 = [_]u8{0} ** 32;

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  REPUTATION AUTHORITY-BACKED TESTS\n");
    serial.writeString("========================================\n\n");

    if (!initialized) init();

    for (&reputations) |*r| {
        r.* = emptyReputation();
    }

    rep_count = 0;

    if (@hasDecl(authority, "resetForTest")) {
        authority.resetForTest();
    } else if (!authority.isInitialized()) {
        authority.init();
    }

    test_peer_a = [_]u8{0} ** 32;
    test_peer_b = [_]u8{0} ** 32;
    test_peer_c = [_]u8{0} ** 32;
    test_root = [_]u8{0} ** 32;
    test_hw = [_]u8{0} ** 32;

    test_peer_a[0] = 0xAA;
    test_peer_b[0] = 0xBB;
    test_peer_c[0] = 0xCC;
    test_root[0] = 0xF0;
    test_hw[0] = 0x44;

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1]  Register root authority. ");
    {
        if (registerAuthorityPeer(&test_root, .root_authority, &test_root)) |rep| {
            if (authority.isRootAuthority(&test_root) and rep.score >= SCORE_TRUSTED) {
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

    serial.writeString("  [2]  Register validator...... ");
    {
        if (registerAttestedPeer(
            &test_peer_a,
            .validator,
            &test_hw,
            true,
            true,
            &test_root,
        )) |rep| {
            if (authority.isValidator(&test_peer_a) and rep.attestation_verified) {
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

    serial.writeString("  [3]  Trust level calc........ ");
    {
        var mock: PeerReputation = emptyReputation();

        mock.score = SCORE_PROVISIONAL - 1;
        const tl1 = calculateTrustLevel(&mock);

        mock.score = SCORE_PROVISIONAL;
        const tl2 = calculateTrustLevel(&mock);

        mock.score = SCORE_MEMBER;
        const tl3 = calculateTrustLevel(&mock);

        mock.score = SCORE_TRUSTED;
        const tl4 = calculateTrustLevel(&mock);

        if (tl1 == .untrusted and
            tl2 == .provisional and
            tl3 == .member and
            tl4 == .trusted)
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [4]  Good action +score...... ");
    {
        if (getReputation(&test_peer_a)) |rep| {
            const before = rep.score;
            addGoodAction(&test_peer_a);

            if (rep.score >= before) {
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

    serial.writeString("  [5]  Violation -score........ ");
    {
        if (getReputation(&test_peer_a)) |rep| {
            const before = rep.score;
            addViolation(&test_peer_a);

            if (rep.score <= before) {
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

    serial.writeString("  [6]  Severe violation........ ");
    {
        if (getReputation(&test_peer_a)) |rep| {
            const before = rep.score;
            recordSevereViolation(&test_peer_a);

            if (rep.score < before) {
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

    serial.writeString("  [7]  Eviction evidence....... ");
    {
        var evhash: [32]u8 = [_]u8{0xEE} ** 32;

        if (getReputation(&test_peer_a)) |rep| {
            recordEvictionEvidence(&test_peer_a, &evhash);

            if (rep.eviction_evidence_count > 0) {
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

    serial.writeString("  [8]  Vouching system......... ");
    {
        _ = registerAttestedPeer(
            &test_peer_b,
            .member,
            &test_hw,
            true,
            true,
            &test_root,
        );

        if (getReputation(&test_peer_a)) |rep_a| {
            rep_a.score = SCORE_MEMBER;
            rep_a.trust_level = .member;
        }

        if (addVouch(&test_peer_b, &test_peer_a)) {
            if (getVouchCount(&test_peer_b) == 1) {
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

    serial.writeString("  [9]  Vote eligibility........ ");
    {
        if (canVoteForEviction(&test_peer_a)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [10] Commit eligibility...... ");
    {
        if (canCommitEviction(&test_peer_a)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [11] Legacy PoW compatibility ");
    {
        if (generatePow(&test_peer_c, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (verifyPow(&test_peer_c, nonce, TEST_POW_DIFFICULTY)) {
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

    serial.writeString("  [12] Legacy register peer.... ");
    {
        if (generatePow(&test_peer_c, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (registerPeer(&test_peer_c, nonce, TEST_POW_DIFFICULTY)) |rep| {
                if (rep.pow_verified and authority.getAuthorityLevel(&test_peer_c) == .guest) {
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

    serial.writeString("  [13] Authority source truth... ");
    {
        if (authority.isValidator(&test_peer_a) and getAuthorityCount() >= 3) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [14] Force ban score......... ");
    {
        forceBanScore(&test_peer_b);

        if (getScore(&test_peer_b) <= SCORE_BAN and !isPeerHealthyForEviction(&test_peer_b)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [15] Tracked count........... ");
    {
        if (getTrackedCount() >= 3) {
            serial.writeString("PASS (");
            printU64(@as(u64, getTrackedCount()));
            serial.writeString(" peers)\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  --------------------------------\n");
    serial.writeString("  Reputation Results: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed");

    if (failed == 0) {
        serial.writeString(" OK\n");
    } else {
        serial.writeString(" FAILED\n");
    }

    return failed == 0;
}

// =============================================================================
// Print Helpers
// =============================================================================

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
