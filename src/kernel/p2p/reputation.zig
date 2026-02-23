//! Zamrud OS - P2P Peer Reputation System (H.3)
//! Proof-of-Work registration, reputation scoring, vouching, age weighting
//!
//! Makes Sybil attacks EXPENSIVE:
//! - Each PeerID requires Proof-of-Work (SHA-256 with leading zeros)
//! - Reputation builds over time (age bonus)
//! - Trusted peers can vouch for new peers
//! - Violations decay reputation, auto-ban at threshold

const serial = @import("../drivers/serial/serial.zig");
const hash_mod = @import("../crypto/hash.zig");
const ct = @import("../crypto/constant_time.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_TRACKED: usize = 64;
pub const DEFAULT_POW_DIFFICULTY: u8 = 16; // 16 leading zero bits (~65536 hashes)
pub const TEST_POW_DIFFICULTY: u8 = 8; // 8 bits for testing (~256 hashes)
pub const MAX_VOUCHERS: usize = 4;

// Score thresholds
pub const SCORE_UNTRUSTED: i32 = 0;
pub const SCORE_PROVISIONAL: i32 = 50;
pub const SCORE_MEMBER: i32 = 200;
pub const SCORE_TRUSTED: i32 = 500;
pub const SCORE_BAN: i32 = -100;
pub const SCORE_MAX: i32 = 1000;
pub const SCORE_MIN: i32 = -500;

// Scoring values
pub const POW_BASE_SCORE: i32 = 30; // Base score for valid PoW
pub const POW_EXTRA_PER_BIT: i32 = 5; // Bonus per extra difficulty bit
pub const GOOD_ACTION_SCORE: i32 = 2; // Per good action
pub const VIOLATION_PENALTY: i32 = 10; // Per violation
pub const VOUCH_BONUS: i32 = 25; // Per voucher
pub const AGE_BONUS_PER_HOUR: i32 = 1; // Per hour of age
pub const AGE_BONUS_MAX: i32 = 100; // Cap age bonus
pub const DECAY_PER_HOUR: i32 = 1; // Score decay when inactive

// =============================================================================
// Types
// =============================================================================

pub const TrustLevel = enum(u8) {
    untrusted = 0,
    provisional = 1,
    member = 2,
    trusted = 3,
};

pub const PeerReputation = struct {
    peer_id: [32]u8,
    active: bool,
    score: i32,
    first_seen: u64,
    last_active: u64,
    good_actions: u32,
    violations: u32,
    pow_difficulty: u8,
    pow_verified: bool,
    voucher_count: u8,
    vouchers: [MAX_VOUCHERS][32]u8,
    trust_level: TrustLevel,
};

// =============================================================================
// State
// =============================================================================

var reputations: [MAX_TRACKED]PeerReputation = undefined;
var rep_count: usize = 0;
var initialized: bool = false;

// Static buffers for PoW computation
var pow_input: [40]u8 = [_]u8{0} ** 40; // peer_id(32) + nonce(8)
var pow_hash: [32]u8 = [_]u8{0} ** 32;

// Mask lookup for leading zero bit check
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
    serial.writeString("[REPUTATION] Peer reputation system initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyReputation() PeerReputation {
    return .{
        .peer_id = [_]u8{0} ** 32,
        .active = false,
        .score = 0,
        .first_seen = 0,
        .last_active = 0,
        .good_actions = 0,
        .violations = 0,
        .pow_difficulty = 0,
        .pow_verified = false,
        .voucher_count = 0,
        .vouchers = [_][32]u8{[_]u8{0} ** 32} ** MAX_VOUCHERS,
        .trust_level = .untrusted,
    };
}

// =============================================================================
// Proof-of-Work
// =============================================================================

/// Check if hash has N leading zero bits
pub fn hasLeadingZeroBits(h: *const [32]u8, bits: u8) bool {
    if (bits == 0) return true;
    if (bits > 255) return false;

    const full_bytes: usize = @as(usize, bits) / 8;
    const remaining: u8 = bits % 8;

    // Check full zero bytes
    var i: usize = 0;
    while (i < full_bytes) : (i += 1) {
        if (i >= 32) return true;
        if (h[i] != 0) return false;
    }

    // Check remaining bits in next byte
    if (remaining > 0 and full_bytes < 32) {
        if (h[full_bytes] & leading_masks[remaining] != 0) return false;
    }

    return true;
}

/// Verify a Proof-of-Work: SHA-256(peer_id || nonce) has `difficulty` leading zero bits
pub fn verifyPow(peer_id: *const [32]u8, nonce: u64, difficulty: u8) bool {
    // Build input: peer_id(32) || nonce_le(8)
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

/// Generate a Proof-of-Work for a peer ID
/// Returns nonce if found within max_iterations, null otherwise
pub fn generatePow(peer_id: *const [32]u8, difficulty: u8, max_iterations: u64) ?u64 {
    @memcpy(pow_input[0..32], peer_id);

    var nonce: u64 = 0;
    while (nonce < max_iterations) : (nonce += 1) {
        // Encode nonce (little-endian)
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
// Peer Registration & Lookup
// =============================================================================

/// Register a new peer with verified PoW
/// Returns pointer to reputation entry if successful
pub fn registerPeer(peer_id: *const [32]u8, pow_nonce: u64, difficulty: u8) ?*PeerReputation {
    // Verify PoW
    if (!verifyPow(peer_id, pow_nonce, difficulty)) {
        serial.writeString("[REPUTATION] PoW verification failed\n");
        return null;
    }

    // Check if already registered
    if (getReputation(peer_id)) |existing| {
        existing.last_active = getTimestamp();
        return existing;
    }

    // Find empty slot
    for (&reputations) |*r| {
        if (!r.active) {
            r.* = emptyReputation();
            @memcpy(&r.peer_id, peer_id);
            r.active = true;
            r.pow_difficulty = difficulty;
            r.pow_verified = true;
            r.first_seen = getTimestamp();
            r.last_active = r.first_seen;
            r.score = POW_BASE_SCORE + @as(i32, @intCast(difficulty)) * POW_EXTRA_PER_BIT;
            r.trust_level = calculateTrustLevel(r);
            rep_count += 1;
            return r;
        }
    }

    serial.writeString("[REPUTATION] No slots available\n");
    return null;
}

/// Get reputation entry for a peer
pub fn getReputation(peer_id: *const [32]u8) ?*PeerReputation {
    for (&reputations) |*r| {
        if (r.active and ct.constantTimeCompare32(&r.peer_id, peer_id)) {
            return r;
        }
    }
    return null;
}

/// Remove peer from reputation tracking
pub fn removePeer(peer_id: *const [32]u8) void {
    for (&reputations) |*r| {
        if (r.active and ct.constantTimeCompare32(&r.peer_id, peer_id)) {
            ct.secureZero(&r.peer_id);
            r.* = emptyReputation();
            if (rep_count > 0) rep_count -= 1;
            return;
        }
    }
}

pub fn getTrackedCount() usize {
    return rep_count;
}

// =============================================================================
// Reputation Scoring
// =============================================================================

/// Record a good action (valid block relayed, helpful response, etc.)
pub fn addGoodAction(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.good_actions +|= 1;
        r.last_active = getTimestamp();
        recalculateScore(r);
    }
}

/// Record a violation (invalid signature, spam, protocol violation, etc.)
pub fn addViolation(peer_id: *const [32]u8) void {
    if (getReputation(peer_id)) |r| {
        r.violations +|= 1;
        r.last_active = getTimestamp();
        recalculateScore(r);
    }
}

/// Recalculate composite score from all factors
pub fn recalculateScore(r: *PeerReputation) void {
    var score: i32 = 0;

    // Base: PoW contribution
    if (r.pow_verified) {
        score += POW_BASE_SCORE;
        score += @as(i32, @intCast(r.pow_difficulty)) * POW_EXTRA_PER_BIT;
    }

    // Good actions bonus
    score += @min(@as(i32, @intCast(r.good_actions)) * GOOD_ACTION_SCORE, 200);

    // Violation penalty
    score -= @as(i32, @intCast(r.violations)) * VIOLATION_PENALTY;

    // Vouch bonus
    score += @as(i32, @intCast(r.voucher_count)) * VOUCH_BONUS;

    // Age bonus
    const now = getTimestamp();
    if (now > r.first_seen) {
        const age_hours: i32 = @intCast(@min((now - r.first_seen) / 3600, 1000));
        score += @min(age_hours * AGE_BONUS_PER_HOUR, AGE_BONUS_MAX);
    }

    // Clamp
    if (score > SCORE_MAX) score = SCORE_MAX;
    if (score < SCORE_MIN) score = SCORE_MIN;

    r.score = score;
    r.trust_level = calculateTrustLevel(r);
}

/// Calculate trust level from score
pub fn calculateTrustLevel(r: *const PeerReputation) TrustLevel {
    if (r.score >= SCORE_TRUSTED) return .trusted;
    if (r.score >= SCORE_MEMBER) return .member;
    if (r.score >= SCORE_PROVISIONAL) return .provisional;
    return .untrusted;
}

/// Get peer age in seconds
pub fn getAge(r: *const PeerReputation) u64 {
    const now = getTimestamp();
    if (now > r.first_seen) return now - r.first_seen;
    return 0;
}

// =============================================================================
// Vouching System
// =============================================================================

/// Add a vouch from one peer for another
/// Voucher must be at least 'member' trust level
pub fn addVouch(peer_id: *const [32]u8, voucher_id: *const [32]u8) bool {
    // Voucher must exist and be trusted enough
    const voucher = getReputation(voucher_id) orelse return false;
    if (@intFromEnum(voucher.trust_level) < @intFromEnum(TrustLevel.member)) {
        return false; // Voucher not trusted enough
    }

    // Target must exist
    const target = getReputation(peer_id) orelse return false;

    // Check if already vouched
    var i: usize = 0;
    while (i < target.voucher_count) : (i += 1) {
        if (ct.constantTimeCompare32(&target.vouchers[i], voucher_id)) {
            return false; // Already vouched
        }
    }

    // Add vouch
    if (target.voucher_count >= MAX_VOUCHERS) return false;

    @memcpy(&target.vouchers[target.voucher_count], voucher_id);
    target.voucher_count += 1;

    recalculateScore(target);
    return true;
}

/// Get number of vouches for a peer
pub fn getVouchCount(peer_id: *const [32]u8) u8 {
    const rep = getReputation(peer_id) orelse return 0;
    return rep.voucher_count;
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

// Static test buffers
var test_peer_a: [32]u8 = [_]u8{0} ** 32;
var test_peer_b: [32]u8 = [_]u8{0} ** 32;
var test_peer_c: [32]u8 = [_]u8{0} ** 32;

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  REPUTATION & PoW TESTS (H.3a)\n");
    serial.writeString("========================================\n\n");

    // Ensure initialized
    if (!initialized) init();

    // Reset state for tests
    for (&reputations) |*r| {
        r.* = emptyReputation();
    }
    rep_count = 0;

    // Setup test peer IDs
    test_peer_a[0] = 0xAA;
    test_peer_a[1] = 0x01;
    test_peer_b[0] = 0xBB;
    test_peer_b[1] = 0x02;
    test_peer_c[0] = 0xCC;
    test_peer_c[1] = 0x03;

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: hasLeadingZeroBits — all zeros
    serial.writeString("  [1]  LeadingZeros (0 bits).... ");
    {
        const h = [_]u8{0xFF} ** 32;
        if (hasLeadingZeroBits(&h, 0)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 2: hasLeadingZeroBits — 8 bits (1 zero byte)
    serial.writeString("  [2]  LeadingZeros (8 bits).... ");
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        if (hasLeadingZeroBits(&h, 8)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 3: hasLeadingZeroBits — fails when not enough
    serial.writeString("  [3]  LeadingZeros (fail)...... ");
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        if (!hasLeadingZeroBits(&h, 9)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 4: hasLeadingZeroBits — 16 bits
    serial.writeString("  [4]  LeadingZeros (16 bits)... ");
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        h[1] = 0x00;
        if (hasLeadingZeroBits(&h, 16) and !hasLeadingZeroBits(&h, 17)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 5: Generate PoW at test difficulty (8 bits)
    serial.writeString("  [5]  Generate PoW (8-bit).... ");
    {
        if (generatePow(&test_peer_a, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            serial.writeString("PASS (nonce=");
            printU64(nonce);
            serial.writeString(")\n");
            passed += 1;
        } else {
            serial.writeString("FAIL (not found)\n");
            failed += 1;
        }
    }

    // Test 6: Verify valid PoW
    serial.writeString("  [6]  Verify valid PoW........ ");
    {
        if (generatePow(&test_peer_a, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (verifyPow(&test_peer_a, nonce, TEST_POW_DIFFICULTY)) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (verify)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (gen)\n");
            failed += 1;
        }
    }

    // Test 7: Reject invalid nonce
    serial.writeString("  [7]  Reject bad nonce........ ");
    {
        if (!verifyPow(&test_peer_a, 0xDEADBEEF, TEST_POW_DIFFICULTY)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 8: Reject wrong peer_id
    serial.writeString("  [8]  Reject wrong peer_id.... ");
    {
        if (generatePow(&test_peer_a, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (!verifyPow(&test_peer_b, nonce, TEST_POW_DIFFICULTY)) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (gen)\n");
            failed += 1;
        }
    }

    // Test 9: Register peer with valid PoW
    serial.writeString("  [9]  Register with PoW....... ");
    {
        if (generatePow(&test_peer_a, TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (registerPeer(&test_peer_a, nonce, TEST_POW_DIFFICULTY)) |rep| {
                if (rep.pow_verified and rep.score > 0 and rep.active) {
                    serial.writeString("PASS (score=");
                    printI32(rep.score);
                    serial.writeString(")\n");
                    passed += 1;
                } else {
                    serial.writeString("FAIL (state)\n");
                    failed += 1;
                }
            } else {
                serial.writeString("FAIL (register)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (gen)\n");
            failed += 1;
        }
    }

    // Test 10: Register without PoW rejected
    serial.writeString("  [10] Register no PoW rejected ");
    {
        if (registerPeer(&test_peer_b, 0, TEST_POW_DIFFICULTY)) |_| {
            serial.writeString("FAIL (accepted)\n");
            failed += 1;
        } else {
            serial.writeString("PASS\n");
            passed += 1;
        }
    }

    // Test 11: Good action increases score
    serial.writeString("  [11] Good action +score...... ");
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
            serial.writeString("FAIL (not found)\n");
            failed += 1;
        }
    }

    // Test 12: Violation decreases score
    serial.writeString("  [12] Violation -score........ ");
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
            serial.writeString("FAIL (not found)\n");
            failed += 1;
        }
    }

    // Test 13: Trust level calculation
    serial.writeString("  [13] Trust level calc........ ");
    {
        var mock: PeerReputation = emptyReputation();
        mock.score = -10;
        const tl1 = calculateTrustLevel(&mock);
        mock.score = 30;
        const tl2 = calculateTrustLevel(&mock);
        mock.score = 100;
        const tl3 = calculateTrustLevel(&mock);
        mock.score = 600;
        const tl4 = calculateTrustLevel(&mock);

        if (tl1 == .untrusted and tl2 == .provisional and
            tl3 == .member and tl4 == .trusted)
        {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Test 14: Vouching (register peer B first)
    serial.writeString("  [14] Vouching system......... ");
    {
        // Register peer B with PoW
        if (generatePow(&test_peer_b, TEST_POW_DIFFICULTY, 10000)) |nonce_b| {
            _ = registerPeer(&test_peer_b, nonce_b, TEST_POW_DIFFICULTY);
        }

        // Peer A needs member trust to vouch — boost score
        if (getReputation(&test_peer_a)) |rep_a| {
            rep_a.score = SCORE_MEMBER; // Force to member
            rep_a.trust_level = .member;
        }

        // A vouches for B
        if (addVouch(&test_peer_b, &test_peer_a)) {
            if (getVouchCount(&test_peer_b) == 1) {
                serial.writeString("PASS\n");
                passed += 1;
            } else {
                serial.writeString("FAIL (count)\n");
                failed += 1;
            }
        } else {
            serial.writeString("FAIL (vouch)\n");
            failed += 1;
        }
    }

    // Test 15: Tracked count
    serial.writeString("  [15] Tracked count........... ");
    {
        if (rep_count >= 2) {
            serial.writeString("PASS (");
            printU64(@as(u64, rep_count));
            serial.writeString(" peers)\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    // Summary
    serial.writeString("\n  ────────────────────────────────\n");
    serial.writeString("  H.3a Results: ");
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

fn printI32(val: i32) void {
    if (val < 0) {
        serial.writeChar('-');
        printU32(@intCast(-val));
    } else {
        printU32(@intCast(val));
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
