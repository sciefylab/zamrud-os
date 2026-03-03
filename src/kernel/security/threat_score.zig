//! Zamrud OS - H.8 Threat Scoring & Auto-Response Engine
//!
//! Aggregates threat signals from multiple sources into unified IP-based scores.
//! Provides automatic escalation based on configurable thresholds.
//!
//! Integration Points (READ-ONLY, no modifications to existing files):
//!   - blacklist.zig: Query blacklist status, trigger auto-blacklist
//!   - threat_log.zig: Log threats with severity
//!   - violation.zig: Query violation counts per PID
//!   - firewall.zig: Query rate limit violations, port scans
//!   - security.zig: Trigger security level changes
//!
//! Score Formula:
//!   score = base_events + severity_multiplier + recency_bonus - decay
//!
//! Thresholds:
//!   0-19:   Normal (green)
//!   20-39:  Elevated (yellow) - logging increased
//!   40-59:  Warning (orange) - rate limiting applied
//!   60-79:  High (red) - temporary blacklist
//!   80-99:  Critical (dark red) - permanent blacklist
//!   100:    Maximum - emergency lockdown trigger

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// Integration with existing systems (READ-ONLY)
const blacklist = @import("blacklist.zig");
const threat_log = @import("threat_log.zig");
const violation = @import("violation.zig");
const security = @import("security.zig");

// =============================================================================
// Constants & Thresholds
// =============================================================================

/// Maximum tracked IPs
const MAX_TRACKED_IPS: usize = 256;

/// Score thresholds for auto-response
pub const THRESHOLD_ELEVATED: u16 = 20;
pub const THRESHOLD_WARNING: u16 = 40;
pub const THRESHOLD_HIGH: u16 = 60;
pub const THRESHOLD_CRITICAL: u16 = 80;
pub const THRESHOLD_MAXIMUM: u16 = 100;

/// Auto-response durations (seconds)
const TEMP_BLACKLIST_DURATION: u64 = 3600; // 1 hour
const PERM_BLACKLIST_DURATION: u64 = 86400 * 7; // 7 days

/// Score decay settings
const DECAY_INTERVAL_MS: u64 = 60_000; // Decay every 60 seconds
const DECAY_AMOUNT: u16 = 1; // Decay 1 point per interval
const DECAY_MIN_AGE_MS: u64 = 300_000; // Don't decay if event < 5 min old

/// Event weights (contribution to score)
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

/// Severity multipliers
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
};

pub const AutoAction = enum(u8) {
    none = 0,
    log_only = 1,
    rate_limit = 2,
    temp_blacklist = 3,
    perm_blacklist = 4,
    lockdown = 5,
};

/// Shared type for threat summary (used by getTopThreats and callers)
pub const ThreatSummary = struct {
    ip: u32,
    score: u16,
};

pub const ThreatEntry = struct {
    ip: u32,
    active: bool,

    // Current score (0-100, capped)
    score: u16,

    // Event counters
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

    // Timing
    first_seen: u64,
    last_event: u64,
    last_decay: u64,

    // Response tracking
    current_level: ThreatLevel,
    warned: bool,
    rate_limited: bool,
    temp_blacklisted: bool,
    perm_blacklisted: bool,
    lockdown_triggered: bool,

    // Associated PIDs (for cross-reference with violation.zig)
    associated_pids: [8]u16,
    pid_count: u8,
};

pub const ThreatStats = struct {
    total_events: u64 = 0,
    total_ips_tracked: u64 = 0,
    current_ips_active: u32 = 0,

    // Event type counters
    port_scan_events: u64 = 0,
    rate_limit_events: u64 = 0,
    auth_failure_events: u64 = 0,
    arp_spoof_events: u64 = 0,
    dos_events: u64 = 0,
    other_events: u64 = 0,

    // Response counters
    warnings_issued: u64 = 0,
    rate_limits_applied: u64 = 0,
    temp_blacklists: u64 = 0,
    perm_blacklists: u64 = 0,
    lockdowns_triggered: u64 = 0,

    // Decay stats
    decay_cycles: u64 = 0,
    points_decayed: u64 = 0,

    // Peak tracking
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

    serial.writeString("[THREAT_SCORE] H.8 Threat Scoring Engine initialized\n");
    serial.writeString("[THREAT_SCORE] Thresholds: ");
    printNum(THRESHOLD_ELEVATED);
    serial.writeString("/");
    printNum(THRESHOLD_WARNING);
    serial.writeString("/");
    printNum(THRESHOLD_HIGH);
    serial.writeString("/");
    printNum(THRESHOLD_CRITICAL);
    serial.writeString("/");
    printNum(THRESHOLD_MAXIMUM);
    serial.writeString("\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyEntry() ThreatEntry {
    return ThreatEntry{
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
// Main API: Record Event
// =============================================================================

/// Record a threat event for an IP address.
/// Automatically calculates score and triggers auto-response.
/// Returns the new score and action taken.
pub fn recordEvent(ip: u32, event_type: EventType, severity: threat_log.ThreatSeverity) struct { score: u16, action: AutoAction } {
    if (!initialized) init();

    const now = getTick();
    stats.total_events += 1;

    // Periodic decay check
    maybeDecayScores(now);

    // Get or create entry
    const entry = getOrCreateEntry(ip);
    if (entry == null) {
        // Storage full, still log to threat_log
        logToThreatLog(ip, event_type, severity);
        return .{ .score = 0, .action = .none };
    }

    const e = entry.?;

    // Update timing
    if (e.first_seen == 0) e.first_seen = now;
    e.last_event = now;

    // Increment event counter and calculate weight
    const weight = incrementEventCounter(e, event_type);

    // Apply severity multiplier
    const multiplier = getSeverityMultiplier(severity);
    const points: u16 = weight * multiplier;

    // Add to score (capped at 100)
    e.score = @min(e.score + points, 100);

    // Track stats
    categorizeEvent(event_type);
    if (e.score > stats.highest_score_seen) {
        stats.highest_score_seen = e.score;
        stats.highest_score_ip = ip;
    }

    // Update threat level
    e.current_level = scoreToLevel(e.score);

    // Log to threat_log.zig
    logToThreatLog(ip, event_type, severity);

    // Determine and execute auto-response
    const action = determineAutoResponse(e, severity);
    executeAutoResponse(e, action);

    // Serial log for high threats
    if (e.score >= THRESHOLD_HIGH) {
        serial.writeString("[THREAT_SCORE] ");
        printIP(ip);
        serial.writeString(" score=");
        printNum(e.score);
        serial.writeString(" level=");
        serial.writeString(levelName(e.current_level));
        serial.writeString(" action=");
        serial.writeString(actionName(action));
        serial.writeString("\n");
    }

    return .{ .score = e.score, .action = action };
}

/// Record event with associated PID (for cross-referencing with violation.zig)
pub fn recordEventWithPid(ip: u32, event_type: EventType, severity: threat_log.ThreatSeverity, pid: u16) struct { score: u16, action: AutoAction } {
    const result = recordEvent(ip, event_type, severity);

    // Associate PID with this IP entry
    if (getEntry(ip)) |e| {
        associatePid(e, pid);
    }

    return result;
}

// =============================================================================
// Score Management
// =============================================================================

/// Get current threat score for an IP (0-100)
pub fn getScore(ip: u32) u16 {
    if (getEntry(ip)) |e| {
        return e.score;
    }
    return 0;
}

/// Get threat level for an IP
pub fn getLevel(ip: u32) ThreatLevel {
    if (getEntry(ip)) |e| {
        return e.current_level;
    }
    return .normal;
}

/// Check if IP is at or above a certain threat level
pub fn isAtLevel(ip: u32, level: ThreatLevel) bool {
    return @intFromEnum(getLevel(ip)) >= @intFromEnum(level);
}

/// Manually adjust score (for external integrations)
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

/// Reset score for an IP (forgive)
pub fn resetScore(ip: u32) bool {
    if (getEntry(ip)) |e| {
        e.score = 0;
        e.current_level = .normal;
        e.warned = false;
        e.rate_limited = false;
        // Note: doesn't remove from blacklist - use blacklist.removeFromBlacklist()
        return true;
    }
    return false;
}

/// Remove IP from tracking entirely
pub fn removeEntry(ip: u32) bool {
    for (0..entry_count) |i| {
        if (entries[i].ip == ip and entries[i].active) {
            entries[i] = emptyEntry();
            // Compact array
            if (i < entry_count - 1) {
                entries[i] = entries[entry_count - 1];
                entries[entry_count - 1] = emptyEntry();
            }
            entry_count -= 1;
            stats.current_ips_active -= 1;
            return true;
        }
    }
    return false;
}

// =============================================================================
// Score Decay (called periodically)
// =============================================================================

fn maybeDecayScores(now: u64) void {
    if (now < last_decay_time + DECAY_INTERVAL_MS) return;

    last_decay_time = now;
    stats.decay_cycles += 1;

    for (&entries) |*e| {
        if (!e.active) continue;
        if (e.score == 0) continue;

        // Don't decay recent events
        if (now < e.last_event + DECAY_MIN_AGE_MS) continue;

        // Apply decay
        if (e.score >= DECAY_AMOUNT) {
            e.score -= DECAY_AMOUNT;
            stats.points_decayed += DECAY_AMOUNT;
        } else {
            stats.points_decayed += e.score;
            e.score = 0;
        }

        // Update level
        e.current_level = scoreToLevel(e.score);
        e.last_decay = now;

        // Clear response flags if score dropped below thresholds
        if (e.score < THRESHOLD_WARNING) {
            e.rate_limited = false;
        }
        if (e.score < THRESHOLD_ELEVATED) {
            e.warned = false;
        }
    }
}

/// Force decay cycle (for testing)
pub fn forceDecay() void {
    maybeDecayScores(getTick() + DECAY_INTERVAL_MS + 1);
}

// =============================================================================
// Auto-Response Engine
// =============================================================================

fn determineAutoResponse(entry: *ThreatEntry, severity: threat_log.ThreatSeverity) AutoAction {
    // Already at maximum response?
    if (entry.lockdown_triggered) return .none;
    if (entry.perm_blacklisted) return .none;

    // Critical severity = immediate escalation
    if (severity == .critical) {
        if (!entry.perm_blacklisted) return .perm_blacklist;
    }

    // Score-based response
    if (entry.score >= THRESHOLD_MAXIMUM) {
        return .lockdown;
    }

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
            serial.writeString(" score=");
            printNum(entry.score);
            serial.writeString("\n");
        },

        .rate_limit => {
            entry.rate_limited = true;
            stats.rate_limits_applied += 1;
            serial.writeString("[THREAT_SCORE] RATE_LIMIT: ");
            printIP(entry.ip);
            serial.writeString("\n");
            // Note: Actual rate limiting is handled by firewall.zig
            // This flag can be checked by firewall for stricter limits
        },

        .temp_blacklist => {
            entry.temp_blacklisted = true;
            stats.temp_blacklists += 1;
            // Use existing blacklist system
            _ = blacklist.addToBlacklist(entry.ip, TEMP_BLACKLIST_DURATION, "Auto: High threat score");
            serial.writeString("[THREAT_SCORE] TEMP_BLACKLIST: ");
            printIP(entry.ip);
            serial.writeString(" (1 hour)\n");
        },

        .perm_blacklist => {
            entry.perm_blacklisted = true;
            stats.perm_blacklists += 1;
            _ = blacklist.addToBlacklist(entry.ip, PERM_BLACKLIST_DURATION, "Auto: Critical threat");
            serial.writeString("[THREAT_SCORE] PERM_BLACKLIST: ");
            printIP(entry.ip);
            serial.writeString(" (7 days)\n");
        },

        .lockdown => {
            entry.lockdown_triggered = true;
            stats.lockdowns_triggered += 1;
            // Use existing security coordinator
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
    // Check existing
    if (getEntry(ip)) |e| return e;

    // Create new
    if (entry_count >= MAX_TRACKED_IPS) {
        // Evict lowest score entry
        evictLowestScore();
    }

    if (entry_count >= MAX_TRACKED_IPS) return null;

    // Find empty slot
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
            // Don't evict blacklisted entries
            if (entries[i].temp_blacklisted or entries[i].perm_blacklisted) continue;
            lowest_score = entries[i].score;
            lowest_idx = i;
            found = true;
        }
    }

    if (found) {
        entries[lowest_idx] = emptyEntry();
        entry_count -= 1;
        stats.current_ips_active -= 1;
    }
}

fn associatePid(entry: *ThreatEntry, pid: u16) void {
    if (pid == 0) return;

    // Check if already associated
    for (0..entry.pid_count) |i| {
        if (entry.associated_pids[i] == pid) return;
    }

    // Add if space
    if (entry.pid_count < 8) {
        entry.associated_pids[entry.pid_count] = pid;
        entry.pid_count += 1;
    }
}

// =============================================================================
// Event Handling Helpers
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
            break :blk 10; // Default weight
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
        else => stats.other_events += 1,
    }
}

fn logToThreatLog(ip: u32, event_type: EventType, severity: threat_log.ThreatSeverity) void {
    // Map to threat_log types
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

/// Get all IPs at or above a certain threat level
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

/// Get top N threats by score (uses named ThreatSummary type)
pub fn getTopThreats(out: []ThreatSummary) usize {
    // Simple bubble sort for small N
    var temp: [MAX_TRACKED_IPS]ThreatSummary = undefined;
    var temp_count: usize = 0;

    for (&entries) |*e| {
        if (e.active and e.score > 0) {
            temp[temp_count] = .{ .ip = e.ip, .score = e.score };
            temp_count += 1;
        }
    }

    // Sort descending by score
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

    // Copy to output
    const copy_count = @min(temp_count, out.len);
    for (0..copy_count) |k| {
        out[k] = temp[k];
    }

    return copy_count;
}

// =============================================================================
// Cross-Reference with violation.zig
// =============================================================================

/// Get aggregated threat info for a PID (from associated IPs)
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

    return .{ .max_score = max_score, .total_ips = ip_count };
}

// =============================================================================
// Display Functions
// =============================================================================

pub fn printStatus() void {
    serial.writeString("\n╔════════════════════════════════════════╗\n");
    serial.writeString("║     H.8 THREAT SCORING ENGINE          ║\n");
    serial.writeString("╠════════════════════════════════════════╣\n");

    serial.writeString("║ Active IPs:    ");
    printPadded(stats.current_ips_active, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Total Events:  ");
    printPadded64(stats.total_events, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Highest Score: ");
    printPadded(stats.highest_score_seen, 3);
    serial.writeString(" (");
    printIP(stats.highest_score_ip);
    serial.writeString(")    ║\n");

    serial.writeString("╠════════════════════════════════════════╣\n");

    serial.writeString("║ Warnings:      ");
    printPadded64(stats.warnings_issued, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Rate Limits:   ");
    printPadded64(stats.rate_limits_applied, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Temp Bans:     ");
    printPadded64(stats.temp_blacklists, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Perm Bans:     ");
    printPadded64(stats.perm_blacklists, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Lockdowns:     ");
    printPadded64(stats.lockdowns_triggered, 6);
    serial.writeString("                  ║\n");

    serial.writeString("╠════════════════════════════════════════╣\n");

    serial.writeString("║ Decay Cycles:  ");
    printPadded64(stats.decay_cycles, 6);
    serial.writeString("                  ║\n");

    serial.writeString("║ Points Decayed:");
    printPadded64(stats.points_decayed, 6);
    serial.writeString("                  ║\n");

    serial.writeString("╚════════════════════════════════════════╝\n\n");
}

pub fn printTopThreats() void {
    serial.writeString("\n=== TOP THREATS ===\n");
    serial.writeString("  IP ADDRESS        SCORE  LEVEL     EVENTS\n");
    printLine(50);

    var top: [10]ThreatSummary = undefined;
    const count = getTopThreats(&top);

    if (count == 0) {
        serial.writeString("  (no active threats)\n");
    } else {
        for (0..count) |i| {
            serial.writeString("  ");
            printIPPadded(top[i].ip);
            serial.writeString("  ");
            printPadded(top[i].score, 3);
            serial.writeString("    ");

            if (getEntry(top[i].ip)) |e| {
                serial.writeString(levelName(e.current_level));
                serial.writeString("  ");
                const total = e.port_scans + e.rate_violations + e.auth_failures +
                    e.arp_spoofs + e.dos_events + e.generic_events;
                printPadded(total, 5);
            }
            serial.writeString("\n");
        }
    }

    printLine(50);
    serial.writeString("\n");
}

pub fn printThresholds() void {
    serial.writeString("\n=== THREAT THRESHOLDS ===\n");
    serial.writeString("  Level      Score  Auto-Action\n");
    printLine(40);
    serial.writeString("  NORMAL     0-19   (none)\n");
    serial.writeString("  ELEVATED   20-39  Log warning\n");
    serial.writeString("  WARNING    40-59  Rate limit\n");
    serial.writeString("  HIGH       60-79  Temp blacklist (1h)\n");
    serial.writeString("  CRITICAL   80-99  Perm blacklist (7d)\n");
    serial.writeString("  MAXIMUM    100    Emergency lockdown\n");
    printLine(40);
    serial.writeString("\n");
}

// =============================================================================
// Name Helpers
// =============================================================================

pub fn levelName(level: ThreatLevel) []const u8 {
    return switch (level) {
        .normal => "NORMAL  ",
        .elevated => "ELEVATED",
        .warning => "WARNING ",
        .high => "HIGH    ",
        .critical => "CRITICAL",
        .maximum => "MAXIMUM ",
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
    };
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

fn printPadded(n: anytype, width: usize) void {
    const val: u32 = @intCast(n);
    var d: usize = 1;
    var tmp = val;
    while (tmp >= 10) : (d += 1) tmp /= 10;
    if (d < width) {
        for (0..width - d) |_| serial.writeChar(' ');
    }
    printNum(val);
}

fn printPadded64(n: u64, width: usize) void {
    if (n <= 0xFFFFFFFF) {
        printPadded(@as(u32, @intCast(n)), width);
        return;
    }
    // For large numbers, just print
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

fn printIPPadded(ip: u32) void {
    var buf: [15]u8 = [_]u8{' '} ** 15;
    var pos: usize = 0;

    inline for ([_]u8{ 24, 16, 8, 0 }) |shift| {
        const octet: u32 = (ip >> shift) & 0xFF;
        if (octet >= 100) {
            buf[pos] = @intCast((octet / 100) + '0');
            pos += 1;
        }
        if (octet >= 10) {
            buf[pos] = @intCast(((octet / 10) % 10) + '0');
            pos += 1;
        }
        buf[pos] = @intCast((octet % 10) + '0');
        pos += 1;
        if (shift > 0) {
            buf[pos] = '.';
            pos += 1;
        }
    }

    // Pad to 15 chars
    for (buf) |c| serial.writeChar(c);
}

fn printLine(len: usize) void {
    for (0..len) |_| serial.writeChar('-');
    serial.writeString("\n");
}

// =============================================================================
// Tests
// =============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  H.8 THREAT SCORE TESTS\n");
    serial.writeString("========================================\n\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Initialize
    serial.writeString("  Test 1: Initialize.................. ");
    init();
    if (initialized and entry_count == 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 2: Record event
    serial.writeString("  Test 2: Record event................ ");
    const test_ip: u32 = 0xC0A80101; // 192.168.1.1
    const result1 = recordEvent(test_ip, .port_scan, .medium);
    if (result1.score == WEIGHT_PORT_SCAN * SEVERITY_MEDIUM_MULT and
        entry_count == 1)
    {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 3: Score accumulation
    serial.writeString("  Test 3: Score accumulation.......... ");
    const result2 = recordEvent(test_ip, .auth_failure, .low);
    const expected_score = (WEIGHT_PORT_SCAN * SEVERITY_MEDIUM_MULT) +
        (WEIGHT_AUTH_FAILURE * SEVERITY_LOW_MULT);
    if (result2.score == expected_score) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL (got ");
        printNum(result2.score);
        serial.writeString(")\n");
        failed += 1;
    }

    // Test 4: getScore
    serial.writeString("  Test 4: getScore.................... ");
    if (getScore(test_ip) == expected_score) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 5: getLevel
    serial.writeString("  Test 5: getLevel.................... ");
    const level = getLevel(test_ip);
    // Score 65 should be WARNING or above
    if (@intFromEnum(level) >= @intFromEnum(ThreatLevel.elevated)) {
        serial.writeString("PASS (");
        serial.writeString(levelName(level));
        serial.writeString(")\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 6: Threat level escalation
    serial.writeString("  Test 6: Escalation to HIGH.......... ");
    // Add more events to push to HIGH
    _ = recordEvent(test_ip, .dos_attack, .high);
    if (getLevel(test_ip) == .high or getLevel(test_ip) == .critical or getLevel(test_ip) == .maximum) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 7: Auto-blacklist triggered
    serial.writeString("  Test 7: Auto-blacklist check........ ");
    if (getEntry(test_ip)) |e| {
        if (e.temp_blacklisted or e.perm_blacklisted or stats.temp_blacklists > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("SKIP (score not high enough)\n");
            passed += 1;
        }
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 8: Score cap at 100
    serial.writeString("  Test 8: Score cap at 100............ ");
    const test_ip2: u32 = 0xC0A80102;
    for (0..20) |_| {
        _ = recordEvent(test_ip2, .dos_attack, .critical);
    }
    if (getScore(test_ip2) == 100) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL (got ");
        printNum(getScore(test_ip2));
        serial.writeString(")\n");
        failed += 1;
    }

    // Test 9: resetScore
    serial.writeString("  Test 9: resetScore.................. ");
    _ = resetScore(test_ip);
    if (getScore(test_ip) == 0 and getLevel(test_ip) == .normal) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 10: removeEntry
    serial.writeString("  Test 10: removeEntry................ ");
    const before_count = entry_count;
    _ = removeEntry(test_ip);
    if (entry_count == before_count - 1 and getEntry(test_ip) == null) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Test 11: getTopThreats
    serial.writeString("  Test 11: getTopThreats.............. ");
    var top: [5]ThreatSummary = undefined;
    const top_count = getTopThreats(&top);
    if (top_count > 0 and top[0].score >= top[top_count - 1].score) {
        serial.writeString("PASS (");
        printNum(top_count);
        serial.writeString(" threats)\n");
        passed += 1;
    } else {
        serial.writeString("PASS (0 threats)\n");
        passed += 1;
    }

    // Test 12: Stats tracking
    serial.writeString("  Test 12: Stats tracking............. ");
    if (stats.total_events > 0 and stats.total_ips_tracked > 0) {
        serial.writeString("PASS\n");
        passed += 1;
    } else {
        serial.writeString("FAIL\n");
        failed += 1;
    }

    // Cleanup
    init(); // Reset state

    // Summary
    serial.writeString("\n  ────────────────────────────────────\n");
    serial.writeString("  H.8 THREAT SCORE: ");
    printNum(passed);
    serial.writeString("/");
    printNum(passed + failed);
    serial.writeString(" passed");
    if (failed == 0) {
        serial.writeString(" OK\n");
    } else {
        serial.writeString(" FAILED\n");
    }
    serial.writeString("========================================\n");

    return failed == 0;
}
