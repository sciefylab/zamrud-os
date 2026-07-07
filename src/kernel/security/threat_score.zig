//! Zamrud OS - H.8 Threat Scoring & Auto-Response Engine
//! P.3e Ready: P2P Eviction Evidence Provider

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

const blacklist = @import("blacklist.zig");
const threat_log = @import("threat_log.zig");
const security = @import("security.zig");

// =============================================================================
// Constants & Thresholds
// =============================================================================

const MAX_TRACKED_IPS: usize = 256;

pub const THRESHOLD_ELEVATED: u16 = 20;
pub const THRESHOLD_WARNING: u16 = 40;
pub const THRESHOLD_HIGH: u16 = 60;
pub const THRESHOLD_CRITICAL: u16 = 80;
pub const THRESHOLD_MAXIMUM: u16 = 100;

const TEMP_BLACKLIST_DURATION: u64 = 3600;
const PERM_BLACKLIST_DURATION: u64 = 86400 * 7;

const DECAY_INTERVAL_MS: u64 = 60_000;
const DECAY_AMOUNT: u16 = 1;
const DECAY_MIN_AGE_MS: u64 = 300_000;

const WEIGHT_PORT_SCAN: u16 = 25;
const WEIGHT_RATE_LIMIT: u16 = 10;
const WEIGHT_AUTH_FAILURE: u16 = 15;
const WEIGHT_ARP_SPOOF: u16 = 30;
const WEIGHT_PROTOCOL_ERROR: u16 = 5;
const WEIGHT_BRUTE_FORCE: u16 = 20;
const WEIGHT_DOS_ATTACK: u16 = 35;
const WEIGHT_MALFORMED_PACKET: u16 = 8;
const WEIGHT_UNKNOWN_PEER: u16 = 12;
const WEIGHT_SIGNATURE_INVALID: u16 = 20;

const WEIGHT_P2P_EVICTION_EVIDENCE: u16 = 30;
const WEIGHT_P2P_DUPLICATE_IDENTITY: u16 = 40;
const WEIGHT_P2P_ONION_ABUSE: u16 = 35;
const WEIGHT_P2P_PEER_IMPERSONATION: u16 = 45;
const WEIGHT_P2P_EVICTION_SPAM: u16 = 25;

const SEVERITY_LOW_MULT: u16 = 1;
const SEVERITY_MEDIUM_MULT: u16 = 2;
const SEVERITY_HIGH_MULT: u16 = 3;
const SEVERITY_CRITICAL_MULT: u16 = 5;

// =============================================================================
// Types
// =============================================================================

pub const ThreatLevel = enum(u8) {
    normal = 0,
    elevated = 1,
    warning = 2,
    high = 3,
    critical = 4,
    maximum = 5,
};

pub const EventType = enum(u8) {
    port_scan = 0,
    rate_limit_exceeded = 1,
    auth_failure = 2,
    arp_spoof = 3,
    protocol_error = 4,
    brute_force = 5,
    dos_attack = 6,
    malformed_packet = 7,
    unknown_peer = 8,
    signature_invalid = 9,
    generic_threat = 10,

    // P.3e
    p2p_eviction_evidence = 11,
    p2p_duplicate_identity = 12,
    p2p_onion_abuse = 13,
    p2p_peer_impersonation = 14,
    p2p_eviction_spam = 15,
};

pub const AutoAction = enum(u8) {
    none = 0,
    log_only = 1,
    rate_limit = 2,
    temp_blacklist = 3,
    perm_blacklist = 4,
    lockdown = 5,
};

/// Named return type.
pub const RecordResult = struct {
    score: u16,
    action: AutoAction,
};

pub const ThreatSummary = struct {
    ip: u32,
    score: u16,
};

pub const ThreatEntry = struct {
    ip: u32,
    active: bool,

    score: u16,

    port_scans: u16,
    rate_violations: u16,
    auth_failures: u16,
    arp_spoofs: u16,
    protocol_errors: u16,
    brute_force_attempts: u16,
    dos_events: u16,
    malformed_packets: u16,
    unknown_peer_attempts: u16,
    signature_failures: u16,
    generic_events: u16,

    // P.3e counters
    p2p_eviction_events: u16,
    p2p_duplicate_identity_events: u16,
    p2p_onion_abuse_events: u16,
    p2p_impersonation_events: u16,
    p2p_eviction_spam_events: u16,

    first_seen: u64,
    last_event: u64,
    last_decay: u64,

    current_level: ThreatLevel,
    warned: bool,
    rate_limited: bool,
    temp_blacklisted: bool,
    perm_blacklisted: bool,
    lockdown_triggered: bool,

    associated_pids: [8]u16,
    pid_count: u8,
};

pub const ThreatStats = struct {
    total_events: u64 = 0,
    total_ips_tracked: u64 = 0,
    current_ips_active: u32 = 0,

    port_scan_events: u64 = 0,
    rate_limit_events: u64 = 0,
    auth_failure_events: u64 = 0,
    arp_spoof_events: u64 = 0,
    dos_events: u64 = 0,
    other_events: u64 = 0,

    p2p_events: u64 = 0,
    eviction_evidence_events: u64 = 0,

    warnings_issued: u64 = 0,
    rate_limits_applied: u64 = 0,
    temp_blacklists: u64 = 0,
    perm_blacklists: u64 = 0,
    lockdowns_triggered: u64 = 0,

    decay_cycles: u64 = 0,
    points_decayed: u64 = 0,

    highest_score_seen: u16 = 0,
    highest_score_ip: u32 = 0,
};

// =============================================================================
// Storage
// =============================================================================

var entries: [MAX_TRACKED_IPS]ThreatEntry = undefined;
var entry_count: usize = 0;

pub var stats = ThreatStats{};
var initialized: bool = false;
var last_decay_time: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&entries) |*e| {
        e.* = emptyEntry();
    }

    entry_count = 0;
    stats = ThreatStats{};
    last_decay_time = getTick();
    initialized = true;

    serial.writeString("[THREAT_SCORE] H.8 Threat Scoring Engine initialized (P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyEntry() ThreatEntry {
    return .{
        .ip = 0,
        .active = false,
        .score = 0,

        .port_scans = 0,
        .rate_violations = 0,
        .auth_failures = 0,
        .arp_spoofs = 0,
        .protocol_errors = 0,
        .brute_force_attempts = 0,
        .dos_events = 0,
        .malformed_packets = 0,
        .unknown_peer_attempts = 0,
        .signature_failures = 0,
        .generic_events = 0,

        .p2p_eviction_events = 0,
        .p2p_duplicate_identity_events = 0,
        .p2p_onion_abuse_events = 0,
        .p2p_impersonation_events = 0,
        .p2p_eviction_spam_events = 0,

        .first_seen = 0,
        .last_event = 0,
        .last_decay = 0,

        .current_level = .normal,
        .warned = false,
        .rate_limited = false,
        .temp_blacklisted = false,
        .perm_blacklisted = false,
        .lockdown_triggered = false,

        .associated_pids = [_]u16{0} ** 8,
        .pid_count = 0,
    };
}

// =============================================================================
// Main API
// =============================================================================

pub fn recordEvent(
    ip: u32,
    event_type: EventType,
    severity: threat_log.ThreatSeverity,
) RecordResult {
    if (!initialized) init();

    const now = getTick();
    stats.total_events += 1;

    maybeDecayScores(now);

    const entry_opt = getOrCreateEntry(ip);
    if (entry_opt == null) {
        logToThreatLog(ip, event_type, severity);
        return .{ .score = 0, .action = .none };
    }

    const e = entry_opt.?;

    if (e.first_seen == 0) e.first_seen = now;
    e.last_event = now;

    const weight = incrementEventCounter(e, event_type);
    const multiplier = getSeverityMultiplier(severity);
    const points: u16 = weight * multiplier;

    e.score = @min(e.score + points, 100);

    categorizeEvent(event_type);

    if (e.score > stats.highest_score_seen) {
        stats.highest_score_seen = e.score;
        stats.highest_score_ip = ip;
    }

    e.current_level = scoreToLevel(e.score);

    logToThreatLog(ip, event_type, severity);

    const action = determineAutoResponse(e, severity);
    executeAutoResponse(e, action);

    if (e.score >= THRESHOLD_HIGH) {
        serial.writeString("[THREAT_SCORE] ");
        printIP(ip);
        serial.writeString(" score=");
        printNum(e.score);
        serial.writeString(" action=");
        serial.writeString(actionName(action));
        serial.writeString("\n");
    }

    return .{ .score = e.score, .action = action };
}

pub fn recordEventWithPid(
    ip: u32,
    event_type: EventType,
    severity: threat_log.ThreatSeverity,
    pid: u16,
) RecordResult {
    const result = recordEvent(ip, event_type, severity);

    if (getEntry(ip)) |e| {
        associatePid(e, pid);
    }

    return result;
}

// =============================================================================
// P.3e Helpers
// =============================================================================

pub fn recordP2PThreat(
    ip: u32,
    event_type: EventType,
    severity: threat_log.ThreatSeverity,
) RecordResult {
    return recordEvent(ip, event_type, severity);
}

pub fn isEvictionEvidenceCandidate(ip: u32) bool {
    return isAtLevel(ip, .high);
}

pub fn isKillSwitchCandidate(ip: u32) bool {
    return isAtLevel(ip, .critical);
}

pub fn isMaximumThreat(ip: u32) bool {
    return getLevel(ip) == .maximum;
}

// =============================================================================
// Score Management
// =============================================================================

pub fn getScore(ip: u32) u16 {
    if (getEntry(ip)) |e| return e.score;
    return 0;
}

pub fn getLevel(ip: u32) ThreatLevel {
    if (getEntry(ip)) |e| return e.current_level;
    return .normal;
}

pub fn isAtLevel(ip: u32, level: ThreatLevel) bool {
    return @intFromEnum(getLevel(ip)) >= @intFromEnum(level);
}

pub fn adjustScore(ip: u32, delta: i16) void {
    if (getEntry(ip)) |e| {
        if (delta > 0) {
            e.score = @min(e.score + @as(u16, @intCast(delta)), 100);
        } else {
            const sub: u16 = @intCast(-delta);
            e.score = if (e.score > sub) e.score - sub else 0;
        }

        e.current_level = scoreToLevel(e.score);
    }
}

pub fn resetScore(ip: u32) bool {
    if (getEntry(ip)) |e| {
        e.score = 0;
        e.current_level = .normal;
        e.warned = false;
        e.rate_limited = false;
        return true;
    }

    return false;
}

pub fn removeEntry(ip: u32) bool {
    for (0..entry_count) |i| {
        if (entries[i].ip == ip and entries[i].active) {
            entries[i] = emptyEntry();

            if (i < entry_count - 1) {
                entries[i] = entries[entry_count - 1];
                entries[entry_count - 1] = emptyEntry();
            }

            entry_count -= 1;

            if (stats.current_ips_active > 0) {
                stats.current_ips_active -= 1;
            }

            return true;
        }
    }

    return false;
}

// =============================================================================
// Decay
// =============================================================================

fn maybeDecayScores(now: u64) void {
    if (now < last_decay_time + DECAY_INTERVAL_MS) return;

    last_decay_time = now;
    stats.decay_cycles += 1;

    for (&entries) |*e| {
        if (!e.active) continue;
        if (e.score == 0) continue;

        if (now < e.last_event + DECAY_MIN_AGE_MS) continue;

        if (e.score >= DECAY_AMOUNT) {
            e.score -= DECAY_AMOUNT;
            stats.points_decayed += DECAY_AMOUNT;
        } else {
            stats.points_decayed += e.score;
            e.score = 0;
        }

        e.current_level = scoreToLevel(e.score);
        e.last_decay = now;

        if (e.score < THRESHOLD_WARNING) {
            e.rate_limited = false;
        }

        if (e.score < THRESHOLD_ELEVATED) {
            e.warned = false;
        }
    }
}

pub fn forceDecay() void {
    maybeDecayScores(getTick() + DECAY_INTERVAL_MS + 1);
}

// =============================================================================
// Auto Response
// =============================================================================

fn determineAutoResponse(entry: *ThreatEntry, severity: threat_log.ThreatSeverity) AutoAction {
    if (entry.lockdown_triggered) return .none;
    if (entry.perm_blacklisted) return .none;

    if (severity == .critical) {
        if (!entry.perm_blacklisted) return .perm_blacklist;
    }

    if (entry.score >= THRESHOLD_MAXIMUM) return .lockdown;

    if (entry.score >= THRESHOLD_CRITICAL) {
        if (!entry.perm_blacklisted) return .perm_blacklist;
    }

    if (entry.score >= THRESHOLD_HIGH) {
        if (!entry.temp_blacklisted) return .temp_blacklist;
    }

    if (entry.score >= THRESHOLD_WARNING) {
        if (!entry.rate_limited) return .rate_limit;
    }

    if (entry.score >= THRESHOLD_ELEVATED) {
        if (!entry.warned) return .log_only;
    }

    return .none;
}

fn executeAutoResponse(entry: *ThreatEntry, action: AutoAction) void {
    switch (action) {
        .none => {},

        .log_only => {
            entry.warned = true;
            stats.warnings_issued += 1;
            serial.writeString("[THREAT_SCORE] WARNING: ");
            printIP(entry.ip);
            serial.writeString("\n");
        },

        .rate_limit => {
            entry.rate_limited = true;
            stats.rate_limits_applied += 1;
            serial.writeString("[THREAT_SCORE] RATE_LIMIT: ");
            printIP(entry.ip);
            serial.writeString("\n");
        },

        .temp_blacklist => {
            entry.temp_blacklisted = true;
            stats.temp_blacklists += 1;
            _ = blacklist.addToBlacklist(entry.ip, TEMP_BLACKLIST_DURATION, "Auto: High threat score");
            serial.writeString("[THREAT_SCORE] TEMP_BLACKLIST: ");
            printIP(entry.ip);
            serial.writeString("\n");
        },

        .perm_blacklist => {
            entry.perm_blacklisted = true;
            stats.perm_blacklists += 1;
            _ = blacklist.addToBlacklist(entry.ip, PERM_BLACKLIST_DURATION, "Auto: Critical threat");
            serial.writeString("[THREAT_SCORE] PERM_BLACKLIST: ");
            printIP(entry.ip);
            serial.writeString("\n");
        },

        .lockdown => {
            entry.lockdown_triggered = true;
            stats.lockdowns_triggered += 1;
            security.respondToThreat(.critical);
            serial.writeString("[THREAT_SCORE] LOCKDOWN triggered by ");
            printIP(entry.ip);
            serial.writeString("\n");
        },
    }
}

// =============================================================================
// Entry Management
// =============================================================================

fn getEntry(ip: u32) ?*ThreatEntry {
    for (&entries) |*e| {
        if (e.ip == ip and e.active) return e;
    }

    return null;
}

fn getOrCreateEntry(ip: u32) ?*ThreatEntry {
    if (getEntry(ip)) |e| return e;

    if (entry_count >= MAX_TRACKED_IPS) {
        evictLowestScore();
    }

    if (entry_count >= MAX_TRACKED_IPS) return null;

    for (&entries) |*e| {
        if (!e.active) {
            e.* = emptyEntry();
            e.ip = ip;
            e.active = true;

            entry_count += 1;
            stats.total_ips_tracked += 1;
            stats.current_ips_active += 1;

            return e;
        }
    }

    return null;
}

fn evictLowestScore() void {
    var lowest_idx: usize = 0;
    var lowest_score: u16 = 0xFFFF;
    var found = false;

    for (0..MAX_TRACKED_IPS) |i| {
        if (entries[i].active and entries[i].score < lowest_score) {
            if (entries[i].temp_blacklisted or entries[i].perm_blacklisted) continue;

            lowest_score = entries[i].score;
            lowest_idx = i;
            found = true;
        }
    }

    if (found) {
        entries[lowest_idx] = emptyEntry();
        if (entry_count > 0) entry_count -= 1;
        if (stats.current_ips_active > 0) stats.current_ips_active -= 1;
    }
}

fn associatePid(entry: *ThreatEntry, pid: u16) void {
    if (pid == 0) return;

    for (0..entry.pid_count) |i| {
        if (entry.associated_pids[i] == pid) return;
    }

    if (entry.pid_count < 8) {
        entry.associated_pids[entry.pid_count] = pid;
        entry.pid_count += 1;
    }
}

// =============================================================================
// Event Helpers
// =============================================================================

fn incrementEventCounter(entry: *ThreatEntry, event_type: EventType) u16 {
    return switch (event_type) {
        .port_scan => blk: {
            entry.port_scans += 1;
            break :blk WEIGHT_PORT_SCAN;
        },
        .rate_limit_exceeded => blk: {
            entry.rate_violations += 1;
            break :blk WEIGHT_RATE_LIMIT;
        },
        .auth_failure => blk: {
            entry.auth_failures += 1;
            break :blk WEIGHT_AUTH_FAILURE;
        },
        .arp_spoof => blk: {
            entry.arp_spoofs += 1;
            break :blk WEIGHT_ARP_SPOOF;
        },
        .protocol_error => blk: {
            entry.protocol_errors += 1;
            break :blk WEIGHT_PROTOCOL_ERROR;
        },
        .brute_force => blk: {
            entry.brute_force_attempts += 1;
            break :blk WEIGHT_BRUTE_FORCE;
        },
        .dos_attack => blk: {
            entry.dos_events += 1;
            break :blk WEIGHT_DOS_ATTACK;
        },
        .malformed_packet => blk: {
            entry.malformed_packets += 1;
            break :blk WEIGHT_MALFORMED_PACKET;
        },
        .unknown_peer => blk: {
            entry.unknown_peer_attempts += 1;
            break :blk WEIGHT_UNKNOWN_PEER;
        },
        .signature_invalid => blk: {
            entry.signature_failures += 1;
            break :blk WEIGHT_SIGNATURE_INVALID;
        },
        .generic_threat => blk: {
            entry.generic_events += 1;
            break :blk 10;
        },

        .p2p_eviction_evidence => blk: {
            entry.p2p_eviction_events += 1;
            break :blk WEIGHT_P2P_EVICTION_EVIDENCE;
        },
        .p2p_duplicate_identity => blk: {
            entry.p2p_duplicate_identity_events += 1;
            break :blk WEIGHT_P2P_DUPLICATE_IDENTITY;
        },
        .p2p_onion_abuse => blk: {
            entry.p2p_onion_abuse_events += 1;
            break :blk WEIGHT_P2P_ONION_ABUSE;
        },
        .p2p_peer_impersonation => blk: {
            entry.p2p_impersonation_events += 1;
            break :blk WEIGHT_P2P_PEER_IMPERSONATION;
        },
        .p2p_eviction_spam => blk: {
            entry.p2p_eviction_spam_events += 1;
            break :blk WEIGHT_P2P_EVICTION_SPAM;
        },
    };
}

fn getSeverityMultiplier(severity: threat_log.ThreatSeverity) u16 {
    return switch (severity) {
        .low => SEVERITY_LOW_MULT,
        .medium => SEVERITY_MEDIUM_MULT,
        .high => SEVERITY_HIGH_MULT,
        .critical => SEVERITY_CRITICAL_MULT,
    };
}

fn scoreToLevel(score: u16) ThreatLevel {
    if (score >= THRESHOLD_MAXIMUM) return .maximum;
    if (score >= THRESHOLD_CRITICAL) return .critical;
    if (score >= THRESHOLD_HIGH) return .high;
    if (score >= THRESHOLD_WARNING) return .warning;
    if (score >= THRESHOLD_ELEVATED) return .elevated;
    return .normal;
}

fn categorizeEvent(event_type: EventType) void {
    switch (event_type) {
        .port_scan => stats.port_scan_events += 1,
        .rate_limit_exceeded => stats.rate_limit_events += 1,
        .auth_failure => stats.auth_failure_events += 1,
        .arp_spoof => stats.arp_spoof_events += 1,
        .dos_attack => stats.dos_events += 1,

        .p2p_eviction_evidence,
        .p2p_duplicate_identity,
        .p2p_onion_abuse,
        .p2p_peer_impersonation,
        .p2p_eviction_spam,
        => {
            stats.p2p_events += 1;
            stats.eviction_evidence_events += 1;
        },

        else => stats.other_events += 1,
    }
}

fn logToThreatLog(ip: u32, event_type: EventType, severity: threat_log.ThreatSeverity) void {
    const tt: threat_log.ThreatType = switch (event_type) {
        .port_scan => .port_scan,
        .rate_limit_exceeded => .rate_limit_abuse,
        .auth_failure => .authentication_failure,
        .arp_spoof => .arp_spoof,
        .protocol_error => .protocol_violation,
        .brute_force => .brute_force,
        .dos_attack => .dos_attack,
        .malformed_packet => .malformed_packet,
        .unknown_peer => .unknown_peer,
        .signature_invalid => .signature_invalid,
        .generic_threat => .system_event,

        .p2p_eviction_evidence => .protocol_violation,
        .p2p_duplicate_identity => .authentication_failure,
        .p2p_onion_abuse => .protocol_violation,
        .p2p_peer_impersonation => .authentication_failure,
        .p2p_eviction_spam => .rate_limit_abuse,
    };

    _ = threat_log.logThreat(.{
        .threat_type = tt,
        .severity = severity,
        .source_ip = ip,
        .description = "Threat score event",
    });
}

// =============================================================================
// Query API
// =============================================================================

pub fn getStats() ThreatStats {
    return stats;
}

pub fn resetStats() void {
    stats = ThreatStats{};
    stats.current_ips_active = @intCast(entry_count);
}

pub fn getActiveCount() u32 {
    return stats.current_ips_active;
}

pub fn getEntryByIndex(index: usize) ?*const ThreatEntry {
    var count: usize = 0;

    for (&entries) |*e| {
        if (e.active) {
            if (count == index) return e;
            count += 1;
        }
    }

    return null;
}

pub fn getIPsAtLevel(level: ThreatLevel, out_ips: []u32) usize {
    var count: usize = 0;

    for (&entries) |*e| {
        if (!e.active) continue;

        if (@intFromEnum(e.current_level) >= @intFromEnum(level)) {
            if (count < out_ips.len) {
                out_ips[count] = e.ip;
                count += 1;
            }
        }
    }

    return count;
}

pub fn getTopThreats(out: []ThreatSummary) usize {
    var temp: [MAX_TRACKED_IPS]ThreatSummary = undefined;
    var temp_count: usize = 0;

    for (&entries) |*e| {
        if (e.active and e.score > 0) {
            temp[temp_count] = .{
                .ip = e.ip,
                .score = e.score,
            };
            temp_count += 1;
        }
    }

    var i: usize = 0;
    while (i < temp_count) : (i += 1) {
        var j: usize = i + 1;

        while (j < temp_count) : (j += 1) {
            if (temp[j].score > temp[i].score) {
                const t = temp[i];
                temp[i] = temp[j];
                temp[j] = t;
            }
        }
    }

    const copy_count = @min(temp_count, out.len);

    for (0..copy_count) |k| {
        out[k] = temp[k];
    }

    return copy_count;
}

pub fn getPidThreatInfo(pid: u16) struct { max_score: u16, total_ips: u8 } {
    var max_score: u16 = 0;
    var ip_count: u8 = 0;

    for (&entries) |*e| {
        if (!e.active) continue;

        for (0..e.pid_count) |i| {
            if (e.associated_pids[i] == pid) {
                ip_count += 1;
                if (e.score > max_score) max_score = e.score;
                break;
            }
        }
    }

    return .{
        .max_score = max_score,
        .total_ips = ip_count,
    };
}

// =============================================================================
// Display / Name Helpers
// =============================================================================

pub fn levelName(level: ThreatLevel) []const u8 {
    return switch (level) {
        .normal => "NORMAL",
        .elevated => "ELEVATED",
        .warning => "WARNING",
        .high => "HIGH",
        .critical => "CRITICAL",
        .maximum => "MAXIMUM",
    };
}

pub fn actionName(action: AutoAction) []const u8 {
    return switch (action) {
        .none => "NONE",
        .log_only => "LOG",
        .rate_limit => "RATE_LIMIT",
        .temp_blacklist => "TEMP_BAN",
        .perm_blacklist => "PERM_BAN",
        .lockdown => "LOCKDOWN",
    };
}

pub fn eventTypeName(et: EventType) []const u8 {
    return switch (et) {
        .port_scan => "port_scan",
        .rate_limit_exceeded => "rate_limit",
        .auth_failure => "auth_fail",
        .arp_spoof => "arp_spoof",
        .protocol_error => "protocol",
        .brute_force => "brute_force",
        .dos_attack => "dos",
        .malformed_packet => "malformed",
        .unknown_peer => "unknown_peer",
        .signature_invalid => "bad_sig",
        .generic_threat => "generic",

        .p2p_eviction_evidence => "p2p_evict_evidence",
        .p2p_duplicate_identity => "p2p_dup_identity",
        .p2p_onion_abuse => "p2p_onion_abuse",
        .p2p_peer_impersonation => "p2p_impersonate",
        .p2p_eviction_spam => "p2p_evict_spam",
    };
}

pub fn printStatus() void {
    serial.writeString("\n=== H.8 THREAT SCORING ENGINE ===\n");
    serial.writeString("Active IPs: ");
    printNum(stats.current_ips_active);
    serial.writeString("\nTotal Events: ");
    printNum64(stats.total_events);
    serial.writeString("\nP2P Events: ");
    printNum64(stats.p2p_events);
    serial.writeString("\nHighest Score: ");
    printNum(stats.highest_score_seen);
    serial.writeString("\n");
}

pub fn printTopThreats() void {
    serial.writeString("\n=== TOP THREATS ===\n");

    var top: [10]ThreatSummary = undefined;
    const count = getTopThreats(&top);

    if (count == 0) {
        serial.writeString("(no active threats)\n");
        return;
    }

    for (0..count) |i| {
        printIP(top[i].ip);
        serial.writeString(" score=");
        printNum(top[i].score);
        serial.writeString("\n");
    }
}

pub fn printThresholds() void {
    serial.writeString("\n=== THREAT THRESHOLDS ===\n");
    serial.writeString("NORMAL: 0-19\n");
    serial.writeString("ELEVATED: 20-39\n");
    serial.writeString("WARNING: 40-59\n");
    serial.writeString("HIGH: 60-79\n");
    serial.writeString("CRITICAL: 80-99\n");
    serial.writeString("MAXIMUM: 100\n");
}

// =============================================================================
// Print Helpers
// =============================================================================

fn getTick() u64 {
    return timer.getTicks();
}

fn printNum(n: anytype) void {
    const val: u32 = @intCast(n);

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

fn printNum64(n: u64) void {
    if (n <= 0xFFFFFFFF) {
        printNum(@as(u32, @intCast(n)));
        return;
    }

    printNum(@as(u32, @intCast(n % 1_000_000_000)));
}

fn printIP(ip: u32) void {
    printNum((ip >> 24) & 0xFF);
    serial.writeChar('.');
    printNum((ip >> 16) & 0xFF);
    serial.writeChar('.');
    printNum((ip >> 8) & 0xFF);
    serial.writeChar('.');
    printNum(ip & 0xFF);
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  H.8 THREAT SCORE TESTS P.3e READY\n");
    serial.writeString("========================================\n\n");

    init();

    var passed: u32 = 0;
    var failed: u32 = 0;

    const test_ip: u32 = 0xC0A80101;

    serial.writeString("  [1] record event............. ");
    const r1 = recordEvent(test_ip, .port_scan, .medium);
    if (r1.score > 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [2] P2P threat event......... ");
    _ = recordP2PThreat(test_ip, .p2p_duplicate_identity, .high);
    if (getScore(test_ip) >= THRESHOLD_HIGH) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [3] eviction candidate....... ");
    if (isEvictionEvidenceCandidate(test_ip)) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("  [4] reset score.............. ");
    _ = resetScore(test_ip);
    if (getScore(test_ip) == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    serial.writeString("\n  H.8 Results: ");
    printNum(passed);
    serial.writeString("/");
    printNum(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
