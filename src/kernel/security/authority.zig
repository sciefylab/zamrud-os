//! Zamrud OS - Security Authority Registry
//! Global OS-wide authority source-of-truth
//!
//! Purpose:
//! - Stores trusted authority identities.
//! - Tracks root authority, validators, members, and guests.
//! - Tracks hardware attestation / chain verification state.
//! - Provides policy checks used by P2P reputation and eviction.
//!
//! Important:
//! - This file is the authority source-of-truth.
//! - P2P modules should NOT keep a separate authority database.
//! - p2p/reputation.zig may mirror score/trust, but authority status belongs here.
//!
//! Trust Model:
//!   Security = Identity x Integrity x Isolation x Blockchain
//!
//! Authority hierarchy:
//!   unknown        -> no authority
//!   guest          -> known but weak
//!   member         -> trusted member
//!   validator      -> may participate in consensus / eviction voting
//!   root_authority -> bootstrap/root authority

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const MAX_AUTHORITIES: usize = 64;
pub const MAX_REVOKED: usize = 64;

pub const SMALL_NETWORK_THRESHOLD: usize = 3;

pub const AUTHORITY_VERSION: u32 = 1;

// =============================================================================
// Types
// =============================================================================

pub const AuthorityLevel = enum(u8) {
    unknown = 0,
    guest = 1,
    member = 2,
    validator = 3,
    root_authority = 4,
};

pub const AttestationState = enum(u8) {
    none = 0,
    hardware_attested = 1,
    chain_registered = 2,
    authority_signed = 3,
    full = 4,
};

pub const AuthorityStatus = enum(u8) {
    inactive = 0,
    active = 1,
    revoked = 2,
    quarantined = 3,
};

pub const AuthorityDecision = enum(u8) {
    deny = 0,
    allow = 1,
    allow_small_network = 2,
    allow_emergency = 3,
};

pub const AuthorityEntry = struct {
    id: [32]u8,
    active: bool,

    level: AuthorityLevel,
    status: AuthorityStatus,

    hardware_hash: [32]u8,
    authority_id: [32]u8,

    attestation_state: AttestationState,
    hardware_attested: bool,
    chain_verified: bool,
    authority_signature_verified: bool,

    created_at: u64,
    last_seen: u64,
    revoked_at: u64,

    vote_count: u64,
    commit_count: u64,
    violation_count: u64,

    label: [32]u8,
};

pub const AuthorityStats = struct {
    registrations: u64 = 0,
    root_count: u64 = 0,
    validator_count: u64 = 0,
    member_count: u64 = 0,
    guest_count: u64 = 0,

    attestations: u64 = 0,
    chain_verified: u64 = 0,
    signature_verified: u64 = 0,

    revocations: u64 = 0,
    quarantines: u64 = 0,

    vote_allows: u64 = 0,
    vote_denies: u64 = 0,
    commit_allows: u64 = 0,
    commit_denies: u64 = 0,
};

// =============================================================================
// Storage
// =============================================================================

var authorities: [MAX_AUTHORITIES]AuthorityEntry = undefined;
var authority_count: usize = 0;

var revoked_ids: [MAX_REVOKED][32]u8 = undefined;
var revoked_count: usize = 0;

pub var stats = AuthorityStats{};

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&authorities) |*a| {
        a.* = emptyAuthority();
    }

    for (&revoked_ids) |*id| {
        id.* = [_]u8{0} ** 32;
    }

    authority_count = 0;
    revoked_count = 0;
    stats = AuthorityStats{};
    initialized = true;

    serial.writeString("[AUTHORITY] Security authority registry initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyAuthority() AuthorityEntry {
    return .{
        .id = [_]u8{0} ** 32,
        .active = false,

        .level = .unknown,
        .status = .inactive,

        .hardware_hash = [_]u8{0} ** 32,
        .authority_id = [_]u8{0} ** 32,

        .attestation_state = .none,
        .hardware_attested = false,
        .chain_verified = false,
        .authority_signature_verified = false,

        .created_at = 0,
        .last_seen = 0,
        .revoked_at = 0,

        .vote_count = 0,
        .commit_count = 0,
        .violation_count = 0,

        .label = [_]u8{0} ** 32,
    };
}

// =============================================================================
// Registration API
// =============================================================================

pub fn registerRootAuthority(
    id: *const [32]u8,
    label: []const u8,
) bool {
    return registerAuthority(
        id,
        .root_authority,
        null,
        null,
        true,
        true,
        true,
        label,
    );
}

pub fn registerValidator(
    id: *const [32]u8,
    authority_id: *const [32]u8,
    hardware_hash: *const [32]u8,
    chain_verified: bool,
    authority_signature_verified: bool,
    label: []const u8,
) bool {
    return registerAuthority(
        id,
        .validator,
        hardware_hash,
        authority_id,
        true,
        chain_verified,
        authority_signature_verified,
        label,
    );
}

pub fn registerMember(
    id: *const [32]u8,
    authority_id: *const [32]u8,
    hardware_hash: *const [32]u8,
    chain_verified: bool,
    authority_signature_verified: bool,
    label: []const u8,
) bool {
    return registerAuthority(
        id,
        .member,
        hardware_hash,
        authority_id,
        true,
        chain_verified,
        authority_signature_verified,
        label,
    );
}

pub fn registerGuest(
    id: *const [32]u8,
    label: []const u8,
) bool {
    return registerAuthority(
        id,
        .guest,
        null,
        null,
        false,
        false,
        false,
        label,
    );
}

/// Generic authority registration.
/// This accepts verification results from identity/chain/signature subsystems.
/// It does NOT perform cryptographic signature verification internally.
pub fn registerAuthority(
    id: *const [32]u8,
    level: AuthorityLevel,
    hardware_hash: ?*const [32]u8,
    authority_id: ?*const [32]u8,
    hardware_attested: bool,
    chain_verified: bool,
    authority_signature_verified: bool,
    label: []const u8,
) bool {
    if (!initialized) init();

    if (isRevoked(id)) {
        serial.writeString("[AUTHORITY] Refusing to register revoked authority\n");
        return false;
    }

    const entry = getOrCreateEntry(id) orelse return false;

    const was_new = !entry.active;

    entry.id = id.*;
    entry.active = true;
    entry.level = level;
    entry.status = .active;

    if (hardware_hash) |hh| {
        entry.hardware_hash = hh.*;
    }

    if (authority_id) |aid| {
        entry.authority_id = aid.*;
    }

    entry.hardware_attested = hardware_attested;
    entry.chain_verified = chain_verified;
    entry.authority_signature_verified = authority_signature_verified;

    entry.attestation_state = calculateAttestationState(
        hardware_attested,
        chain_verified,
        authority_signature_verified,
    );

    const now = getTimestamp();

    if (entry.created_at == 0) {
        entry.created_at = now;
    }

    entry.last_seen = now;
    entry.label = makeLabel(label);

    if (was_new) {
        authority_count += 1;
    }

    stats.registrations += 1;
    incrementLevelStats(level);

    if (hardware_attested) stats.attestations += 1;
    if (chain_verified) stats.chain_verified += 1;
    if (authority_signature_verified) stats.signature_verified += 1;

    serial.writeString("[AUTHORITY] Registered ");
    serial.writeString(levelName(level));
    serial.writeString("\n");

    return true;
}

fn getOrCreateEntry(id: *const [32]u8) ?*AuthorityEntry {
    if (getEntry(id)) |entry| {
        return entry;
    }

    for (&authorities) |*entry| {
        if (!entry.active) {
            return entry;
        }
    }

    serial.writeString("[AUTHORITY] Registry full\n");
    return null;
}

fn incrementLevelStats(level: AuthorityLevel) void {
    switch (level) {
        .root_authority => stats.root_count += 1,
        .validator => stats.validator_count += 1,
        .member => stats.member_count += 1,
        .guest => stats.guest_count += 1,
        .unknown => {},
    }
}

fn calculateAttestationState(
    hardware_ok: bool,
    chain_ok: bool,
    authority_sig_ok: bool,
) AttestationState {
    if (hardware_ok and chain_ok and authority_sig_ok) {
        return .full;
    }

    if (authority_sig_ok) {
        return .authority_signed;
    }

    if (chain_ok) {
        return .chain_registered;
    }

    if (hardware_ok) {
        return .hardware_attested;
    }

    return .none;
}

// =============================================================================
// Query API
// =============================================================================

pub fn getEntry(id: *const [32]u8) ?*AuthorityEntry {
    for (&authorities) |*entry| {
        if (entry.active and eqlId(&entry.id, id)) {
            return entry;
        }
    }

    return null;
}

pub fn getEntryConst(id: *const [32]u8) ?*const AuthorityEntry {
    for (&authorities) |*entry| {
        if (entry.active and eqlId(&entry.id, id)) {
            return entry;
        }
    }

    return null;
}

pub fn getEntryByIndex(index: usize) ?*const AuthorityEntry {
    if (index >= authority_count) return null;

    var count: usize = 0;

    for (&authorities) |*entry| {
        if (entry.active) {
            if (count == index) return entry;
            count += 1;
        }
    }

    return null;
}

pub fn getAuthorityCount() usize {
    return authority_count;
}

pub fn getStats() AuthorityStats {
    return stats;
}

pub fn isKnownAuthority(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active;
    }

    return false;
}

pub fn isRootAuthority(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active and entry.level == .root_authority;
    }

    return false;
}

pub fn isValidator(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active and entry.level == .validator;
    }

    return false;
}

pub fn isMemberOrHigher(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        if (entry.status != .active) return false;

        return @intFromEnum(entry.level) >= @intFromEnum(AuthorityLevel.member);
    }

    return false;
}

pub fn getAuthorityLevel(id: *const [32]u8) AuthorityLevel {
    if (getEntryConst(id)) |entry| {
        if (entry.status == .active) return entry.level;
    }

    return .unknown;
}

pub fn getAttestationState(id: *const [32]u8) AttestationState {
    if (getEntryConst(id)) |entry| {
        if (entry.status == .active) return entry.attestation_state;
    }

    return .none;
}

pub fn isHardwareAttested(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active and entry.hardware_attested;
    }

    return false;
}

pub fn isChainVerified(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active and entry.chain_verified;
    }

    return false;
}

pub fn isAuthoritySignatureVerified(id: *const [32]u8) bool {
    if (getEntryConst(id)) |entry| {
        return entry.status == .active and entry.authority_signature_verified;
    }

    return false;
}

pub fn isSmallNetwork() bool {
    return authority_count < SMALL_NETWORK_THRESHOLD;
}

// =============================================================================
// Policy API
// =============================================================================

/// Whether this identity can participate in eviction vote creation.
pub fn canVoteForEviction(id: *const [32]u8) bool {
    const entry = getEntry(id) orelse {
        stats.vote_denies += 1;
        return false;
    };

    if (entry.status != .active) {
        stats.vote_denies += 1;
        return false;
    }

    if (isRevoked(id)) {
        stats.vote_denies += 1;
        return false;
    }

    const allowed = canVoteEntry(entry);

    if (allowed) {
        entry.vote_count += 1;
        entry.last_seen = getTimestamp();
        stats.vote_allows += 1;
    } else {
        stats.vote_denies += 1;
    }

    return allowed;
}

/// Whether this identity can participate in eviction commit validation.
pub fn canCommitEviction(id: *const [32]u8) bool {
    const entry = getEntry(id) orelse {
        stats.commit_denies += 1;
        return false;
    };

    if (entry.status != .active) {
        stats.commit_denies += 1;
        return false;
    }

    if (isRevoked(id)) {
        stats.commit_denies += 1;
        return false;
    }

    const allowed = canCommitEntry(entry);

    if (allowed) {
        entry.commit_count += 1;
        entry.last_seen = getTimestamp();
        stats.commit_allows += 1;
    } else {
        stats.commit_denies += 1;
    }

    return allowed;
}

fn canVoteEntry(entry: *const AuthorityEntry) bool {
    if (!isEntryTrustedEnough(entry)) return false;

    if (!isSmallNetwork()) {
        return @intFromEnum(entry.level) >= @intFromEnum(AuthorityLevel.member) and
            entry.hardware_attested;
    }

    // Small network bootstrap:
    // Validators/root may vote if they are attested OR authority-signed.
    switch (entry.level) {
        .root_authority, .validator => {
            return entry.hardware_attested or entry.authority_signature_verified;
        },
        .member => {
            return entry.hardware_attested and entry.chain_verified;
        },
        else => return false,
    }
}

fn canCommitEntry(entry: *const AuthorityEntry) bool {
    if (!isEntryTrustedEnough(entry)) return false;

    switch (entry.level) {
        .root_authority => {
            return entry.authority_signature_verified or entry.hardware_attested;
        },
        .validator => {
            return entry.hardware_attested and entry.chain_verified;
        },
        .member => {
            return !isSmallNetwork() and entry.hardware_attested and entry.chain_verified;
        },
        else => return false,
    }
}

pub fn canEmergencyQuarantine(id: *const [32]u8) bool {
    const entry = getEntryConst(id) orelse return false;

    if (entry.status != .active) return false;
    if (isRevoked(id)) return false;

    switch (entry.level) {
        .root_authority => return entry.authority_signature_verified or entry.hardware_attested,
        .validator => return entry.hardware_attested and entry.chain_verified,
        else => return false,
    }
}

fn isEntryTrustedEnough(entry: *const AuthorityEntry) bool {
    if (entry.status != .active) return false;

    switch (entry.level) {
        .unknown, .guest => return false,
        .member, .validator, .root_authority => return true,
    }
}

// =============================================================================
// Attestation / Verification Updates
// =============================================================================

pub fn updateAttestation(
    id: *const [32]u8,
    hardware_hash: *const [32]u8,
    hardware_attested: bool,
    chain_verified: bool,
    authority_signature_verified: bool,
) bool {
    const entry = getEntry(id) orelse return false;

    entry.hardware_hash = hardware_hash.*;
    entry.hardware_attested = hardware_attested;
    entry.chain_verified = chain_verified;
    entry.authority_signature_verified = authority_signature_verified;

    entry.attestation_state = calculateAttestationState(
        hardware_attested,
        chain_verified,
        authority_signature_verified,
    );

    entry.last_seen = getTimestamp();

    if (hardware_attested) stats.attestations += 1;
    if (chain_verified) stats.chain_verified += 1;
    if (authority_signature_verified) stats.signature_verified += 1;

    return true;
}

pub fn markSeen(id: *const [32]u8) void {
    if (getEntry(id)) |entry| {
        entry.last_seen = getTimestamp();
    }
}

pub fn recordAuthorityViolation(id: *const [32]u8) void {
    if (getEntry(id)) |entry| {
        entry.violation_count += 1;
        entry.last_seen = getTimestamp();
    }
}

// =============================================================================
// Revocation / Quarantine
// =============================================================================

pub fn revokeAuthority(id: *const [32]u8) bool {
    const now = getTimestamp();

    if (getEntry(id)) |entry| {
        entry.status = .revoked;
        entry.active = false;
        entry.revoked_at = now;
    }

    if (!isRevoked(id)) {
        if (revoked_count < MAX_REVOKED) {
            revoked_ids[revoked_count] = id.*;
            revoked_count += 1;
        }
    }

    if (authority_count > 0) {
        authority_count -= 1;
    }

    stats.revocations += 1;

    serial.writeString("[AUTHORITY] Revoked authority\n");
    return true;
}

pub fn quarantineAuthority(id: *const [32]u8) bool {
    if (getEntry(id)) |entry| {
        entry.status = .quarantined;
        entry.last_seen = getTimestamp();
        stats.quarantines += 1;

        serial.writeString("[AUTHORITY] Quarantined authority\n");
        return true;
    }

    return false;
}

pub fn restoreAuthority(id: *const [32]u8) bool {
    if (isRevoked(id)) return false;

    if (getEntry(id)) |entry| {
        if (entry.status == .quarantined) {
            entry.status = .active;
            entry.last_seen = getTimestamp();
            return true;
        }
    }

    return false;
}

pub fn isRevoked(id: *const [32]u8) bool {
    for (revoked_ids[0..revoked_count]) |rid| {
        if (eqlId(&rid, id)) return true;
    }

    return false;
}

pub fn getRevokedCount() usize {
    return revoked_count;
}

pub fn getRevokedId(index: usize) ?[32]u8 {
    if (index >= revoked_count) return null;
    return revoked_ids[index];
}

// =============================================================================
// Display
// =============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== SECURITY AUTHORITY REGISTRY ===\n");

    serial.writeString("  Authorities: ");
    printU64(@as(u64, authority_count));
    serial.writeString("\n");

    serial.writeString("  Revoked:     ");
    printU64(@as(u64, revoked_count));
    serial.writeString("\n");

    serial.writeString("  Root:        ");
    printU64(stats.root_count);
    serial.writeString("\n");

    serial.writeString("  Validators:  ");
    printU64(stats.validator_count);
    serial.writeString("\n");

    serial.writeString("  Members:     ");
    printU64(stats.member_count);
    serial.writeString("\n");

    serial.writeString("  Guests:      ");
    printU64(stats.guest_count);
    serial.writeString("\n");

    serial.writeString("  Vote Allow:  ");
    printU64(stats.vote_allows);
    serial.writeString("\n");

    serial.writeString("  Vote Deny:   ");
    printU64(stats.vote_denies);
    serial.writeString("\n");

    serial.writeString("  Commit Allow:");
    printU64(stats.commit_allows);
    serial.writeString("\n");

    serial.writeString("  Commit Deny: ");
    printU64(stats.commit_denies);
    serial.writeString("\n");
}

pub fn levelName(level: AuthorityLevel) []const u8 {
    return switch (level) {
        .unknown => "UNKNOWN",
        .guest => "GUEST",
        .member => "MEMBER",
        .validator => "VALIDATOR",
        .root_authority => "ROOT",
    };
}

pub fn statusName(status: AuthorityStatus) []const u8 {
    return switch (status) {
        .inactive => "INACTIVE",
        .active => "ACTIVE",
        .revoked => "REVOKED",
        .quarantined => "QUARANTINED",
    };
}

pub fn attestationName(state: AttestationState) []const u8 {
    return switch (state) {
        .none => "NONE",
        .hardware_attested => "HARDWARE",
        .chain_registered => "CHAIN",
        .authority_signed => "SIGNED",
        .full => "FULL",
    };
}

// =============================================================================
// Test Support
// =============================================================================

pub fn resetForTest() void {
    for (&authorities) |*a| {
        a.* = emptyAuthority();
    }

    for (&revoked_ids) |*id| {
        id.* = [_]u8{0} ** 32;
    }

    authority_count = 0;
    revoked_count = 0;
    stats = AuthorityStats{};
    initialized = true;
}

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  SECURITY AUTHORITY TESTS\n");
    serial.writeString("========================================\n\n");

    resetForTest();

    var passed: u32 = 0;
    var failed: u32 = 0;

    var root: [32]u8 = [_]u8{0} ** 32;
    var validator: [32]u8 = [_]u8{0} ** 32;
    var member: [32]u8 = [_]u8{0} ** 32;
    var guest: [32]u8 = [_]u8{0} ** 32;
    var hw: [32]u8 = [_]u8{0} ** 32;

    root[0] = 0xF0;
    validator[0] = 0xA1;
    member[0] = 0xB2;
    guest[0] = 0xC3;
    hw[0] = 0x44;

    serial.writeString("  [1] register root............ ");
    if (registerRootAuthority(&root, "root")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [2] register validator....... ");
    if (registerValidator(&validator, &root, &hw, true, true, "validator")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [3] register member.......... ");
    if (registerMember(&member, &root, &hw, true, true, "member")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [4] register guest........... ");
    if (registerGuest(&guest, "guest")) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [5] root check............... ");
    if (isRootAuthority(&root)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [6] validator vote........... ");
    if (canVoteForEviction(&validator)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [7] validator commit......... ");
    if (canCommitEviction(&validator)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [8] guest denied vote........ ");
    if (!canVoteForEviction(&guest)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [9] quarantine member........ ");
    if (quarantineAuthority(&member) and !canVoteForEviction(&member)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [10] revoke validator........ ");
    if (revokeAuthority(&validator) and isRevoked(&validator) and !canCommitEviction(&validator)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("\n  Authority Results: ");
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
// Utility
// =============================================================================

fn makeLabel(label: []const u8) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    const len = @min(label.len, 31);

    for (0..len) |i| {
        out[i] = label[i];
    }

    return out;
}

fn eqlId(a: *const [32]u8, b: *const [32]u8) bool {
    for (0..32) |i| {
        if (a.*[i] != b.*[i]) return false;
    }

    return true;
}

fn getTimestamp() u64 {
    return timer.getSeconds();
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
