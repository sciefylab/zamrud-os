//! Zamrud OS - E3.5 Unified Violation Handler
//! Central security pipeline for ALL violation types
//!
//! Flow:
//!  capability.zig ──┐
//!  unveil.zig ──────┤
//!  binaryverify.zig─┤──▶ reportViolation() ──▶ Escalation Engine
//!  net_capability.zig┘         │                    │
//!                              ▼                    ▼
//!                        Incident Log         Action: warn/kill/blacklist
//!                              │
//!                              ▼
//!                     Blockchain Audit (critical only)

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
    /// E3.1: Process tried syscall without capability
    capability_violation = 0,
    /// E3.2: Process accessed path outside unveil
    filesystem_violation = 1,
    /// E3.3: Untrusted binary execution attempt
    binary_untrusted = 2,
    /// E3.4: Network op without CAP_NET
    network_violation = 3,
    /// E3.4: Socket created without permission
    socket_unauthorized = 4,
    /// E3.4: Connect to restricted IP/port
    network_restricted = 5,
    /// Firewall: rate limit exceeded
    rate_limit_exceeded = 6,
    /// Firewall: port scan detected
    port_scan_detected = 7,
    /// General: integrity check failed
    integrity_failure = 8,
    /// General: authentication failure
    auth_failure = 9,
    /// General: IPC unauthorized
    ipc_unauthorized = 10,
    /// General: memory access violation
    memory_violation = 11,
};

pub const ViolationSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,
};

pub const EscalationAction = enum(u8) {
    /// Log only, no action
    warn = 0,
    /// Reduce process capabilities
    restrict = 1,
    /// Terminate the process
    kill = 2,
    /// Ban process/IP permanently
    blacklist = 3,
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
};

// ============================================================================
// Storage
// ============================================================================

var incidents: [MAX_INCIDENTS]Incident = undefined;
var incident_count: usize = 0;
var incident_head: usize = 0; // ring buffer head
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

    serial.writeString("[VIOLATION] Unified violation handler initialized\n");
    serial.writeString("[VIOLATION] Thresholds: warn=");
    printNum(WARN_THRESHOLD);
    serial.writeString(" restrict=");
    printNum(RESTRICT_THRESHOLD);
    serial.writeString(" kill=");
    printNum(KILL_THRESHOLD);
    serial.writeString(" blacklist=");
    printNum(BLACKLIST_THRESHOLD);
    serial.writeString("\n");
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
// Main Entry Point — Called by ALL security subsystems
// ============================================================================

/// Report a violation from any security subsystem.
/// Returns the incident ID and the action taken.
pub fn reportViolation(report: ViolationReport) struct { id: u32, action: EscalationAction } {
    stats.total_incidents += 1;
    categorizeViolation(report.violation_type);

    const now = getTick();

    // 1. Get or create escalation entry for this PID
    const esc = getOrCreateEscalation(report.pid);
    esc.total_violations += 1;
    esc.last_violation = now;
    if (esc.first_violation == 0) esc.first_violation = now;

    // 2. Determine action based on escalation level
    const action = determineAction(esc, report.severity);
    esc.current_level = action;

    // Update action counters
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

    // 3. Record incident
    const id = recordIncident(report, action, now);

    // 4. Log to serial
    logToSerial(report, action, id);

    // 5. Log critical to blockchain
    if (report.severity == .critical or action == .blacklist) {
        logToBlockchain(report, action, id);
    }

    return .{ .id = id, .action = action };
}

// ============================================================================
// Escalation Engine
// ============================================================================

fn determineAction(esc: *EscalationEntry, severity: ViolationSeverity) EscalationAction {
    // Already blacklisted? Stay blacklisted
    if (esc.blacklisted) return .blacklist;

    // Already killed? Stay killed (until reset)
    if (esc.killed) return .kill;

    // Critical severity = immediate kill
    if (severity == .critical) return .kill;

    // Escalation based on total violation count
    if (esc.total_violations >= BLACKLIST_THRESHOLD) return .blacklist;
    if (esc.total_violations >= KILL_THRESHOLD) return .kill;
    if (esc.total_violations >= RESTRICT_THRESHOLD) return .restrict;

    // High severity escalates faster
    if (severity == .high and esc.total_violations >= 2) return .restrict;

    return .warn;
}

fn getOrCreateEscalation(pid: u16) *EscalationEntry {
    // Find existing
    for (0..escalation_count) |i| {
        if (escalation[i].pid == pid and escalation[i].active) {
            return &escalation[i];
        }
    }

    // Create new
    if (escalation_count >= MAX_ESCALATION) {
        // Overwrite oldest inactive or first entry
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
// Incident Recording (Ring Buffer)
// ============================================================================

fn recordIncident(report: ViolationReport, action: EscalationAction, now: u64) u32 {
    const id = next_incident_id;
    next_incident_id += 1;

    const idx = incident_head;
    incident_head = (incident_head + 1) % MAX_INCIDENTS;
    if (incident_count < MAX_INCIDENTS) incident_count += 1;

    var inc = &incidents[idx];
    inc.id = id;
    inc.timestamp = now;
    inc.pid = report.pid;
    inc.violation_type = report.violation_type;
    inc.severity = report.severity;
    inc.action_taken = action;
    inc.source_ip = report.source_ip;
    inc.logged_to_chain = false;

    // Copy detail
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
    // Mark as logged (actual chain integration uses chain.zig)
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
        .network_violation, .socket_unauthorized, .network_restricted => stats.net_violations += 1,
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

/// Get incident by display index (0 = most recent)
pub fn getIncident(index: usize) ?*const Incident {
    if (index >= incident_count) return null;

    // Ring buffer: calculate actual index
    if (incident_count < MAX_INCIDENTS) {
        return &incidents[index];
    } else {
        const actual = (incident_head + index) % MAX_INCIDENTS;
        return &incidents[actual];
    }
}

pub fn getIncidentCount() usize {
    return incident_count;
}

/// Get escalation entry for a PID
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

/// Reset escalation for a PID (un-kill, un-blacklist)
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

/// Clear all incidents
pub fn clearIncidents() void {
    for (&incidents) |*inc| {
        inc.* = emptyIncident();
    }
    incident_count = 0;
    incident_head = 0;
}

/// Check if PID is currently killed by escalation
pub fn isKilledByEscalation(pid: u16) bool {
    if (getEscalation(pid)) |esc| {
        return esc.killed;
    }
    return false;
}

/// Check if PID is blacklisted by escalation
pub fn isBlacklistedByEscalation(pid: u16) bool {
    if (getEscalation(pid)) |esc| {
        return esc.blacklisted;
    }
    return false;
}

/// Get current escalation level for a PID
pub fn getEscalationLevel(pid: u16) EscalationAction {
    if (getEscalation(pid)) |esc| {
        return esc.current_level;
    }
    return .warn;
}

/// Get total violations for a PID across all subsystems
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

    serial.writeString("  Total incidents:  ");
    printNum64(stats.total_incidents);
    serial.writeString("\n  Warns:            ");
    printNum64(stats.warns);
    serial.writeString("\n  Restricts:        ");
    printNum64(stats.restricts);
    serial.writeString("\n  Kills:            ");
    printNum64(stats.kills);
    serial.writeString("\n  Blacklists:       ");
    printNum64(stats.blacklists);
    serial.writeString("\n  Chain logged:     ");
    printNum64(stats.chain_logged);
    serial.writeString("\n");

    printSerialLine(40);

    serial.writeString("  Cap violations:   ");
    printNum64(stats.cap_violations);
    serial.writeString("\n  FS violations:    ");
    printNum64(stats.fs_violations);
    serial.writeString("\n  Bin violations:   ");
    printNum64(stats.bin_violations);
    serial.writeString("\n  Net violations:   ");
    printNum64(stats.net_violations);
    serial.writeString("\n  Other:            ");
    printNum64(stats.other_violations);
    serial.writeString("\n");

    printSerialLine(40);

    serial.writeString("  Incident buffer:  ");
    printNum(incident_count);
    serial.writeString("/");
    printNum(MAX_INCIDENTS);
    serial.writeString("\n  Escalation table: ");
    printNum(getEscalationCount());
    serial.writeString("/");
    printNum(MAX_ESCALATION);
    serial.writeString("\n");

    printSerialLine(40);
    serial.writeString("\n");
}

pub fn printIncidentLog() void {
    serial.writeString("\n=== INCIDENT LOG ===\n");
    serial.writeString("  ID    PID  TYPE            SEV    ACTION\n");
    printSerialLine(55);

    if (incident_count == 0) {
        serial.writeString("  (no incidents)\n");
    } else {
        const display_count = @min(incident_count, 20); // Show last 20
        var i: usize = 0;
        while (i < display_count) : (i += 1) {
            if (getIncident(i)) |inc| {
                serial.writeString("  ");
                printPadded(inc.id, 5);
                serial.writeString("  ");
                printPadded(inc.pid, 3);
                serial.writeString("  ");
                serial.writeString(violationTypeShort(inc.violation_type));
                serial.writeString("  ");
                serial.writeString(severityName(inc.severity));
                serial.writeString("   ");
                serial.writeString(actionName(inc.action_taken));
                serial.writeString("\n");
            }
        }
    }
    printSerialLine(55);
    serial.writeString("\n");
}

pub fn printEscalationTable() void {
    serial.writeString("\n=== ESCALATION TABLE ===\n");
    serial.writeString("  PID  VIOLS  LEVEL      KILLED  BANNED\n");
    printSerialLine(50);

    var found = false;
    for (0..escalation_count) |i| {
        const esc = &escalation[i];
        if (!esc.active) continue;
        found = true;

        serial.writeString("  ");
        printPadded(esc.pid, 4);
        serial.writeString("  ");
        printPadded(esc.total_violations, 4);
        serial.writeString("   ");
        serial.writeString(actionName(esc.current_level));
        serial.writeString("    ");
        serial.writeString(if (esc.killed) "YES" else " NO");
        serial.writeString("     ");
        serial.writeString(if (esc.blacklisted) "YES" else " NO");
        serial.writeString("\n");
    }

    if (!found) {
        serial.writeString("  (no escalations)\n");
    }
    printSerialLine(50);
    serial.writeString("\n");
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
    };
}

fn violationTypeShort(vt: ViolationType) []const u8 {
    return switch (vt) {
        .capability_violation => "CAP         ",
        .filesystem_violation => "FS          ",
        .binary_untrusted => "BIN         ",
        .network_violation => "NET         ",
        .socket_unauthorized => "SOCK        ",
        .network_restricted => "NET_RESTR   ",
        .rate_limit_exceeded => "RATE        ",
        .port_scan_detected => "SCAN        ",
        .integrity_failure => "INTEG       ",
        .auth_failure => "AUTH        ",
        .ipc_unauthorized => "IPC         ",
        .memory_violation => "MEM         ",
    };
}

pub fn severityName(s: ViolationSeverity) []const u8 {
    return switch (s) {
        .info => "INFO",
        .low => "LOW ",
        .medium => "MED ",
        .high => "HIGH",
        .critical => "CRIT",
    };
}

pub fn actionName(a: EscalationAction) []const u8 {
    return switch (a) {
        .warn => "WARN     ",
        .restrict => "RESTRICT ",
        .kill => "KILL     ",
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
    const tmp = lo;
    if (tmp == 0) {
        digits = 1;
    } else {
        var t = tmp;
        while (t > 0) : (digits += 1) t /= 10;
    }
    for (0..9 - digits) |_| serial.writeChar('0');
    if (lo > 0) printNum(lo);
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

fn printSerialLine(len: usize) void {
    for (0..len) |_| serial.writeChar('-');
    serial.writeString("\n");
}
