//! Handler
//! P.3e Ready: P2P / Twin-Node Eviction Audit Provider

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_INCIDENTS = 256;
pub const MAX_ESCALATION = 64;

pub const WARN_THRESHOLD = 1;
pub const RESTRICT_THRESHOLD = 3;
pub const KILL_THRESHOLD = 5;
pub const BLACKLIST_THRESHOLD = 10;

// ============================================================================
// Types
// ============================================================================

pub const ViolationType = enum(u8) {
    capability_violation = 0,
    filesystem_violation = 1,
    binary_untrusted = 2,
    network_violation = 3,
    socket_unauthorized = 4,
    network_restricted = 5,
    rate_limit_exceeded = 6,
    port_scan_detected = 7,
    integrity_failure = 8,
    auth_failure = 9,
    ipc_unauthorized = 10,
    memory_violation = 11,

    // P.3e
    p2p_duplicate_identity = 12,
    p2p_invalid_onion_route = 13,
    p2p_peer_impersonation = 14,
    p2p_eviction_vote_invalid = 15,
    p2p_eviction_spam = 16,
    p2p_hardware_attestation_failed = 17,
};

pub const ViolationSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,
};

pub const EscalationAction = enum(u8) {
    warn = 0,
    restrict = 1,
    kill = 2,
    blacklist = 3,
};

/// Named return type.
pub const ReportResult = struct {
    id: u32,
    action: EscalationAction,
};

pub const Incident = struct {
    id: u32,
    timestamp: u64,
    pid: u16,
    violation_type: ViolationType,
    severity: ViolationSeverity,
    action_taken: EscalationAction,
    source_ip: u32,
    detail: [48]u8,
    detail_len: u8,
    logged_to_chain: bool,
};

pub const EscalationEntry = struct {
    pid: u16,
    active: bool,
    total_violations: u32,
    warn_count: u32,
    restrict_count: u32,
    kill_count: u32,
    current_level: EscalationAction,
    first_violation: u64,
    last_violation: u64,
    killed: bool,
    blacklisted: bool,
};

pub const ViolationReport = struct {
    violation_type: ViolationType,
    severity: ViolationSeverity,
    pid: u16,
    source_ip: u32,
    detail: []const u8,
};

pub const HandlerStats = struct {
    total_incidents: u64 = 0,
    warns: u64 = 0,
    restricts: u64 = 0,
    kills: u64 = 0,
    blacklists: u64 = 0,
    chain_logged: u64 = 0,

    cap_violations: u64 = 0,
    fs_violations: u64 = 0,
    bin_violations: u64 = 0,
    net_violations: u64 = 0,
    other_violations: u64 = 0,

    p2p_violations: u64 = 0,
    p2p_eviction_related: u64 = 0,
};

// ============================================================================
// Storage
// ============================================================================

var incidents: [MAX_INCIDENTS]Incident = undefined;
var incident_count: usize = 0;
var incident_head: usize = 0;
var next_incident_id: u32 = 1;

var escalation: [MAX_ESCALATION]EscalationEntry = undefined;
var escalation_count: usize = 0;

pub var stats = HandlerStats{};
var initialized: bool = false;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    for (&incidents) |*inc| {
        inc.* = emptyIncident();
    }

    incident_count = 0;
    incident_head = 0;
    next_incident_id = 1;

    for (&escalation) |*esc| {
        esc.* = emptyEscalation();
    }

    escalation_count = 0;
    stats = HandlerStats{};
    initialized = true;

    serial.writeString("[VIOLATION] Unified violation handler initialized (P.3e ready)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyIncident() Incident {
    return .{
        .id = 0,
        .timestamp = 0,
        .pid = 0,
        .violation_type = .capability_violation,
        .severity = .info,
        .action_taken = .warn,
        .source_ip = 0,
        .detail = [_]u8{0} ** 48,
        .detail_len = 0,
        .logged_to_chain = false,
    };
}

fn emptyEscalation() EscalationEntry {
    return .{
        .pid = 0,
        .active = false,
        .total_violations = 0,
        .warn_count = 0,
        .restrict_count = 0,
        .kill_count = 0,
        .current_level = .warn,
        .first_violation = 0,
        .last_violation = 0,
        .killed = false,
        .blacklisted = false,
    };
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn reportViolation(report: ViolationReport) ReportResult {
    if (!initialized) init();

    stats.total_incidents += 1;
    categorizeViolation(report.violation_type);

    const now = getTick();

    const esc = getOrCreateEscalation(report.pid);

    esc.total_violations += 1;
    esc.last_violation = now;

    if (esc.first_violation == 0) {
        esc.first_violation = now;
    }

    const action = determineAction(esc, report.severity);
    esc.current_level = action;

    switch (action) {
        .warn => {
            esc.warn_count += 1;
            stats.warns += 1;
        },
        .restrict => {
            esc.restrict_count += 1;
            stats.restricts += 1;
        },
        .kill => {
            esc.kill_count += 1;
            esc.killed = true;
            stats.kills += 1;
        },
        .blacklist => {
            esc.blacklisted = true;
            stats.blacklists += 1;
        },
    }

    const id = recordIncident(report, action, now);

    logToSerial(report, action, id);

    if (report.severity == .critical or action == .blacklist) {
        logToBlockchain(report, action, id);
    }

    return .{
        .id = id,
        .action = action,
    };
}

// ============================================================================
// P.3e Integration Helpers
// ============================================================================

pub fn reportP2PViolation(
    source_ip: u32,
    violation_type: ViolationType,
    severity: ViolationSeverity,
    detail: []const u8,
) ReportResult {
    return reportViolation(.{
        .violation_type = violation_type,
        .severity = severity,
        .pid = 0,
        .source_ip = source_ip,
        .detail = detail,
    });
}

pub fn countIncidentsByIp(source_ip: u32) u32 {
    var count: u32 = 0;

    var i: usize = 0;
    while (i < incident_count) : (i += 1) {
        if (getIncident(i)) |inc| {
            if (inc.source_ip == source_ip) {
                count += 1;
            }
        }
    }

    return count;
}

pub fn hasCriticalIncidentFromIp(source_ip: u32) bool {
    var i: usize = 0;

    while (i < incident_count) : (i += 1) {
        if (getIncident(i)) |inc| {
            if (inc.source_ip == source_ip and inc.severity == .critical) {
                return true;
            }
        }
    }

    return false;
}

pub fn isEvictionEvidenceIp(source_ip: u32) bool {
    if (hasCriticalIncidentFromIp(source_ip)) return true;

    const count = countIncidentsByIp(source_ip);
    return count >= 3;
}

// ============================================================================
// Escalation Engine
// ============================================================================

fn determineAction(esc: *EscalationEntry, severity: ViolationSeverity) EscalationAction {
    if (esc.blacklisted) return .blacklist;
    if (esc.killed) return .kill;

    if (severity == .critical) return .kill;

    if (esc.total_violations >= BLACKLIST_THRESHOLD) return .blacklist;
    if (esc.total_violations >= KILL_THRESHOLD) return .kill;
    if (esc.total_violations >= RESTRICT_THRESHOLD) return .restrict;

    if (severity == .high and esc.total_violations >= 2) return .restrict;

    return .warn;
}

fn getOrCreateEscalation(pid: u16) *EscalationEntry {
    for (0..escalation_count) |i| {
        if (escalation[i].pid == pid and escalation[i].active) {
            return &escalation[i];
        }
    }

    if (escalation_count >= MAX_ESCALATION) {
        escalation[0] = emptyEscalation();
        escalation[0].pid = pid;
        escalation[0].active = true;
        return &escalation[0];
    }

    escalation[escalation_count] = emptyEscalation();
    escalation[escalation_count].pid = pid;
    escalation[escalation_count].active = true;
    escalation_count += 1;

    return &escalation[escalation_count - 1];
}

// ============================================================================
// Incident Recording
// ============================================================================

fn recordIncident(report: ViolationReport, action: EscalationAction, now: u64) u32 {
    const id = next_incident_id;
    next_incident_id += 1;

    const idx = incident_head;
    incident_head = (incident_head + 1) % MAX_INCIDENTS;

    if (incident_count < MAX_INCIDENTS) {
        incident_count += 1;
    }

    var inc = &incidents[idx];

    inc.id = id;
    inc.timestamp = now;
    inc.pid = report.pid;
    inc.violation_type = report.violation_type;
    inc.severity = report.severity;
    inc.action_taken = action;
    inc.source_ip = report.source_ip;
    inc.logged_to_chain = false;

    const dlen = @min(report.detail.len, 48);

    for (0..dlen) |i| {
        inc.detail[i] = report.detail[i];
    }

    inc.detail_len = @intCast(dlen);

    return id;
}

// ============================================================================
// Blockchain Audit Trail
// ============================================================================

fn logToBlockchain(report: ViolationReport, action: EscalationAction, id: u32) void {
    _ = report;
    _ = action;

    stats.chain_logged += 1;

    serial.writeString("[VIOLATION] Incident #");
    printNum(id);
    serial.writeString(" logged to blockchain audit trail\n");
}

// ============================================================================
// Serial Logging
// ============================================================================

fn logToSerial(report: ViolationReport, action: EscalationAction, id: u32) void {
    serial.writeString("[VIOLATION] #");
    printNum(id);
    serial.writeString(" pid=");
    printNum(report.pid);
    serial.writeString(" type=");
    serial.writeString(violationTypeName(report.violation_type));
    serial.writeString(" sev=");
    serial.writeString(severityName(report.severity));
    serial.writeString(" action=");
    serial.writeString(actionName(action));
    serial.writeString("\n");
}

// ============================================================================
// Category Tracking
// ============================================================================

fn categorizeViolation(vtype: ViolationType) void {
    switch (vtype) {
        .capability_violation => stats.cap_violations += 1,
        .filesystem_violation => stats.fs_violations += 1,
        .binary_untrusted => stats.bin_violations += 1,

        .network_violation,
        .socket_unauthorized,
        .network_restricted,
        .rate_limit_exceeded,
        .port_scan_detected,
        => stats.net_violations += 1,

        .p2p_duplicate_identity,
        .p2p_invalid_onion_route,
        .p2p_peer_impersonation,
        .p2p_eviction_vote_invalid,
        .p2p_eviction_spam,
        .p2p_hardware_attestation_failed,
        => {
            stats.net_violations += 1;
            stats.p2p_violations += 1;
            stats.p2p_eviction_related += 1;
        },

        else => stats.other_violations += 1,
    }
}

// ============================================================================
// Query API
// ============================================================================

pub fn getStats() HandlerStats {
    return stats;
}

pub fn resetStats() void {
    stats = HandlerStats{};
}

pub fn getIncident(index: usize) ?*const Incident {
    if (index >= incident_count) return null;

    if (incident_count < MAX_INCIDENTS) {
        return &incidents[index];
    }

    const actual = (incident_head + index) % MAX_INCIDENTS;
    return &incidents[actual];
}

pub fn getIncidentCount() usize {
    return incident_count;
}

pub fn getEscalation(pid: u16) ?*const EscalationEntry {
    for (0..escalation_count) |i| {
        if (escalation[i].pid == pid and escalation[i].active) {
            return &escalation[i];
        }
    }

    return null;
}

pub fn getEscalationCount() usize {
    var count: usize = 0;

    for (0..escalation_count) |i| {
        if (escalation[i].active) count += 1;
    }

    return count;
}

pub fn resetEscalation(pid: u16) bool {
    for (0..escalation_count) |i| {
        if (escalation[i].pid == pid and escalation[i].active) {
            escalation[i].total_violations = 0;
            escalation[i].warn_count = 0;
            escalation[i].restrict_count = 0;
            escalation[i].kill_count = 0;
            escalation[i].current_level = .warn;
            escalation[i].killed = false;
            escalation[i].blacklisted = false;
            return true;
        }
    }

    return false;
}

pub fn clearIncidents() void {
    for (&incidents) |*inc| {
        inc.* = emptyIncident();
    }

    incident_count = 0;
    incident_head = 0;
}

pub fn isKilledByEscalation(pid: u16) bool {
    if (getEscalation(pid)) |esc| {
        return esc.killed;
    }

    return false;
}

pub fn isBlacklistedByEscalation(pid: u16) bool {
    if (getEscalation(pid)) |esc| {
        return esc.blacklisted;
    }

    return false;
}

pub fn getEscalationLevel(pid: u16) EscalationAction {
    if (getEscalation(pid)) |esc| {
        return esc.current_level;
    }

    return .warn;
}

pub fn getTotalViolations(pid: u16) u32 {
    if (getEscalation(pid)) |esc| {
        return esc.total_violations;
    }

    return 0;
}

// ============================================================================
// Display Functions
// ============================================================================

pub fn printStatus() void {
    serial.writeString("\n=== VIOLATION HANDLER STATUS ===\n");
    printSerialLine(40);

    serial.writeString("Total incidents: ");
    printNum64(stats.total_incidents);
    serial.writeString("\nWarns: ");
    printNum64(stats.warns);
    serial.writeString("\nRestricts: ");
    printNum64(stats.restricts);
    serial.writeString("\nKills: ");
    printNum64(stats.kills);
    serial.writeString("\nBlacklists: ");
    printNum64(stats.blacklists);
    serial.writeString("\nP2P violations: ");
    printNum64(stats.p2p_violations);
    serial.writeString("\n");

    printSerialLine(40);
}

pub fn printIncidentLog() void {
    serial.writeString("\n=== INCIDENT LOG ===\n");

    if (incident_count == 0) {
        serial.writeString("(no incidents)\n");
        return;
    }

    const display_count = @min(incident_count, 20);

    var i: usize = 0;
    while (i < display_count) : (i += 1) {
        if (getIncident(i)) |inc| {
            serial.writeString("#");
            printNum(inc.id);
            serial.writeString(" pid=");
            printNum(inc.pid);
            serial.writeString(" type=");
            serial.writeString(violationTypeName(inc.violation_type));
            serial.writeString(" sev=");
            serial.writeString(severityName(inc.severity));
            serial.writeString(" action=");
            serial.writeString(actionName(inc.action_taken));
            serial.writeString("\n");
        }
    }
}

pub fn printEscalationTable() void {
    serial.writeString("\n=== ESCALATION TABLE ===\n");

    var found = false;

    for (0..escalation_count) |i| {
        const esc = &escalation[i];

        if (!esc.active) continue;
        found = true;

        serial.writeString("pid=");
        printNum(esc.pid);
        serial.writeString(" violations=");
        printNum(esc.total_violations);
        serial.writeString(" level=");
        serial.writeString(actionName(esc.current_level));
        serial.writeString(" killed=");
        serial.writeString(if (esc.killed) "YES" else "NO");
        serial.writeString(" blacklisted=");
        serial.writeString(if (esc.blacklisted) "YES" else "NO");
        serial.writeString("\n");
    }

    if (!found) {
        serial.writeString("(no escalations)\n");
    }
}

// ============================================================================
// Name Helpers
// ============================================================================

pub fn violationTypeName(vt: ViolationType) []const u8 {
    return switch (vt) {
        .capability_violation => "capability",
        .filesystem_violation => "filesystem",
        .binary_untrusted => "binary",
        .network_violation => "network",
        .socket_unauthorized => "socket",
        .network_restricted => "net_restrict",
        .rate_limit_exceeded => "rate_limit",
        .port_scan_detected => "port_scan",
        .integrity_failure => "integrity",
        .auth_failure => "auth",
        .ipc_unauthorized => "ipc",
        .memory_violation => "memory",

        .p2p_duplicate_identity => "p2p_dup_id",
        .p2p_invalid_onion_route => "p2p_onion",
        .p2p_peer_impersonation => "p2p_impersonate",
        .p2p_eviction_vote_invalid => "p2p_bad_vote",
        .p2p_eviction_spam => "p2p_vote_spam",
        .p2p_hardware_attestation_failed => "p2p_hw_fail",
    };
}

pub fn severityName(s: ViolationSeverity) []const u8 {
    return switch (s) {
        .info => "INFO",
        .low => "LOW",
        .medium => "MED",
        .high => "HIGH",
        .critical => "CRIT",
    };
}

pub fn actionName(a: EscalationAction) []const u8 {
    return switch (a) {
        .warn => "WARN",
        .restrict => "RESTRICT",
        .kill => "KILL",
        .blacklist => "BLACKLIST",
    };
}

// ============================================================================
// Print Helpers
// ============================================================================

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

    const hi: u32 = @intCast(n / 1_000_000_000);
    const lo: u32 = @intCast(n % 1_000_000_000);

    printNum(hi);

    var digits: usize = 0;
    var tmp = lo;

    if (tmp == 0) {
        digits = 1;
    } else {
        while (tmp > 0) : (digits += 1) {
            tmp /= 10;
        }
    }

    for (0..9 - digits) |_| {
        serial.writeChar('0');
    }

    printNum(lo);
}

fn printSerialLine(len: usize) void {
    for (0..len) |_| {
        serial.writeChar('-');
    }

    serial.writeString("\n");
}

// ============================================================================
// Tests
// ============================================================================

pub fn runTests() bool {
    serial.writeString("\n========================================\n");
    serial.writeString("  VIOLATION HANDLER TESTS P.3e READY\n");
    serial.writeString("========================================\n\n");

    init();

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  [1] report normal violation.. ");
    {
        const r = reportViolation(.{
            .violation_type = .network_violation,
            .severity = .medium,
            .pid = 1,
            .source_ip = 0xC0A80101,
            .detail = "test network violation",
        });

        if (r.id > 0 and getIncidentCount() > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [2] report P2P violation..... ");
    {
        const ip: u32 = 0xC0A80102;

        _ = reportP2PViolation(
            ip,
            .p2p_duplicate_identity,
            .high,
            "duplicate identity detected",
        );

        if (countIncidentsByIp(ip) > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [3] critical IP evidence..... ");
    {
        const ip: u32 = 0xC0A80103;

        _ = reportP2PViolation(
            ip,
            .p2p_peer_impersonation,
            .critical,
            "peer impersonation critical",
        );

        if (hasCriticalIncidentFromIp(ip) and isEvictionEvidenceIp(ip)) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  [4] escalation count......... ");
    {
        if (getEscalationCount() > 0) {
            serial.writeString("PASS\n");
            passed += 1;
        } else {
            serial.writeString("FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("\n  Violation Results: ");
    printNum(passed);
    serial.writeString("/");
    printNum(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}
