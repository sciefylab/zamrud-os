// ============================================================================
// ZAMRUD OS - THREAT LOGGING SYSTEM
// ============================================================================

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");

// =============================================================================
// Types
// =============================================================================

pub const ThreatType = enum(u8) {
    port_scan = 0,
    arp_spoof = 1,
    rate_limit_abuse = 2,
    authentication_failure = 3,
    signature_invalid = 4,
    unknown_peer = 5,
    malformed_packet = 6,
    protocol_violation = 7,
    brute_force = 8,
    dos_attack = 9,
    system_event = 10,
};

pub const ThreatSeverity = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,
    critical = 3,
};

pub const ThreatEntry = struct {
    id: u64,
    threat_type: ThreatType,
    severity: ThreatSeverity,
    source_ip: u32,
    timestamp: u64,
    description: [64]u8,
    desc_len: usize,
    handled: bool,
};

// =============================================================================
// Storage
// =============================================================================

const MAX_THREATS = 128;
var threats: [MAX_THREATS]ThreatEntry = undefined;
var threat_count: usize = 0;
var threat_id_counter: u64 = 0;
var total_threats: u64 = 0;
var last_threat_time: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    for (&threats) |*t| {
        t.* = emptyThreat();
    }
    threat_count = 0;
    threat_id_counter = 0;
    total_threats = 0;
    last_threat_time = 0;

    serial.writeString("[THREAT-LOG] Initialized\n");
}

fn emptyThreat() ThreatEntry {
    return ThreatEntry{
        .id = 0,
        .threat_type = .system_event,
        .severity = .low,
        .source_ip = 0,
        .timestamp = 0,
        .description = [_]u8{0} ** 64,
        .desc_len = 0,
        .handled = false,
    };
}

// =============================================================================
// Logging
// =============================================================================

pub const ThreatInfo = struct {
    threat_type: ThreatType,
    severity: ThreatSeverity,
    source_ip: u32,
    description: []const u8,
};

pub fn logThreat(info: ThreatInfo) u64 {
    const now = timer.getTicks();

    threat_id_counter += 1;
    total_threats += 1;
    last_threat_time = now;

    // Store threat
    if (threat_count >= MAX_THREATS) {
        // Shift old threats
        for (0..MAX_THREATS - 1) |i| {
            threats[i] = threats[i + 1];
        }
        threat_count = MAX_THREATS - 1;
    }

    var entry = &threats[threat_count];
    entry.id = threat_id_counter;
    entry.threat_type = info.threat_type;
    entry.severity = info.severity;
    entry.source_ip = info.source_ip;
    entry.timestamp = now;
    entry.handled = false;

    const desc_len = @min(info.description.len, 64);
    @memcpy(entry.description[0..desc_len], info.description[0..desc_len]);
    entry.desc_len = desc_len;

    threat_count += 1;

    // Log to serial
    serial.writeString("[THREAT] ");
    serial.writeString(switch (info.severity) {
        .low => "LOW",
        .medium => "MED",
        .high => "HIGH",
        .critical => "CRIT",
    });
    serial.writeString(" - ");
    serial.writeString(switch (info.threat_type) {
        .port_scan => "Port Scan",
        .arp_spoof => "ARP Spoof",
        .rate_limit_abuse => "Rate Limit",
        .authentication_failure => "Auth Fail",
        .signature_invalid => "Bad Signature",
        .unknown_peer => "Unknown Peer",
        .malformed_packet => "Bad Packet",
        .protocol_violation => "Protocol Error",
        .brute_force => "Brute Force",
        .dos_attack => "DoS Attack",
        .system_event => "System Event",
    });
    serial.writeString("\n");

    return threat_id_counter;
}

// =============================================================================
// Query
// =============================================================================

pub fn getTotalThreats() u64 {
    return total_threats;
}

pub fn getLastThreatTime() u64 {
    return last_threat_time;
}

pub fn getThreatCount() usize {
    return threat_count;
}

pub fn getThreat(index: usize) ?*const ThreatEntry {
    if (index >= threat_count) return null;
    return &threats[index];
}
