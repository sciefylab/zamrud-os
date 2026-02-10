//! Zamrud OS - E3.4 Network Capability Enforcement
//! Per-process network access control with socket ownership
//! E3.6: Wired to violation.zig unified pipeline

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const violation = @import("violation.zig");

// ============================================================================
// Constants
// ============================================================================

pub const CAP_NET: u32 = 0x0008;

pub const MAX_PROCESSES = 64;
pub const MAX_SOCKET_OWNERS = 32;
pub const MAX_ALLOWED_IPS = 16;
pub const MAX_ALLOWED_PORTS = 16;
pub const MAX_VIOLATIONS_BEFORE_KILL = 3;
pub const MAX_NET_RULES = 128;

// ============================================================================
// Types
// ============================================================================

pub const NetMode = enum(u8) {
    inherit = 0,
    allow_all = 1,
    restricted = 2,
    deny_all = 3,
};

pub const NetAction = enum(u8) {
    allowed = 0,
    blocked_no_cap = 1,
    blocked_restricted = 2,
    blocked_deny_all = 3,
    blocked_no_policy = 4,
    blocked_socket_limit = 5,
    blocked_killed = 6,
};

pub const NetProcessEntry = struct {
    pid: u16,
    active: bool,
    capabilities: u32,
    mode: NetMode,
    allowed_ips: [MAX_ALLOWED_IPS]u32,
    allowed_ports: [MAX_ALLOWED_PORTS]u16,
    ip_count: u8,
    port_count: u8,
    max_sockets: u8,
    current_sockets: u8,
    violations: u32,
    killed: bool,
    last_violation_tick: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    packets_blocked: u64,
};

pub const SocketOwner = struct {
    socket_idx: u8,
    pid: u16,
    active: bool,
    sock_type: u8,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    created_tick: u64,
};

pub const NetCheckResult = struct {
    action: NetAction,
    reason: []const u8,
};

pub const NetRule = struct {
    id: u32,
    pid: u16,
    remote_ip: u32,
    remote_mask: u32,
    remote_port_start: u16,
    remote_port_end: u16,
    allow: bool,
    enabled: bool,
    match_count: u64,
};

pub const NetStats = struct {
    checks_total: u64 = 0,
    checks_allowed: u64 = 0,
    checks_blocked: u64 = 0,
    violations_total: u64 = 0,
    processes_killed: u64 = 0,
    sockets_created: u64 = 0,
    sockets_closed: u64 = 0,
};

// ============================================================================
// Storage
// ============================================================================

var processes: [MAX_PROCESSES]NetProcessEntry = undefined;
var process_count: usize = 0;

var owners: [MAX_SOCKET_OWNERS]SocketOwner = undefined;

var net_rules: [MAX_NET_RULES]NetRule = undefined;
var net_rule_count: usize = 0;
var next_rule_id: u32 = 1;

pub var stats = NetStats{};
var initialized: bool = false;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    for (&processes) |*p| {
        p.* = emptyProcess();
    }
    process_count = 0;

    for (&owners) |*o| {
        o.* = emptyOwner();
    }

    for (&net_rules) |*r| {
        r.* = emptyRule();
    }
    net_rule_count = 0;
    next_rule_id = 1;

    stats = NetStats{};
    initialized = true;

    serial.writeString("[NET-CAP] Network capability enforcement initialized\n");
    serial.writeString("[NET-CAP] Max processes=");
    printNumber(MAX_PROCESSES);
    serial.writeString(" max_sockets=");
    printNumber(MAX_SOCKET_OWNERS);
    serial.writeString(" kill_threshold=");
    printNumber(MAX_VIOLATIONS_BEFORE_KILL);
    serial.writeString("\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptyProcess() NetProcessEntry {
    return .{
        .pid = 0,
        .active = false,
        .capabilities = 0,
        .mode = .inherit,
        .allowed_ips = [_]u32{0} ** MAX_ALLOWED_IPS,
        .allowed_ports = [_]u16{0} ** MAX_ALLOWED_PORTS,
        .ip_count = 0,
        .port_count = 0,
        .max_sockets = 8,
        .current_sockets = 0,
        .violations = 0,
        .killed = false,
        .last_violation_tick = 0,
        .bytes_sent = 0,
        .bytes_recv = 0,
        .packets_blocked = 0,
    };
}

fn emptyOwner() SocketOwner {
    return .{
        .socket_idx = 0,
        .pid = 0,
        .active = false,
        .sock_type = 0,
        .local_port = 0,
        .remote_ip = 0,
        .remote_port = 0,
        .created_tick = 0,
    };
}

fn emptyRule() NetRule {
    return .{
        .id = 0,
        .pid = 0,
        .remote_ip = 0,
        .remote_mask = 0,
        .remote_port_start = 0,
        .remote_port_end = 0,
        .allow = false,
        .enabled = false,
        .match_count = 0,
    };
}

// ============================================================================
// Process Registration
// ============================================================================

pub fn registerProcess(pid: u16, capabilities: u32) bool {
    if (findProcess(pid)) |entry| {
        entry.capabilities = capabilities;
        entry.active = true;
        entry.killed = false;
        return true;
    }

    if (process_count >= MAX_PROCESSES) return false;

    var entry = emptyProcess();
    entry.pid = pid;
    entry.active = true;
    entry.capabilities = capabilities;

    processes[process_count] = entry;
    process_count += 1;

    serial.writeString("[NET-CAP] Registered pid=");
    printNumber(pid);
    serial.writeString(" cap_net=");
    serial.writeString(if ((capabilities & CAP_NET) != 0) "YES" else "NO");
    serial.writeString("\n");

    return true;
}

pub fn unregisterProcess(pid: u16) void {
    closeProcessSockets(pid);
    if (findProcess(pid)) |entry| {
        entry.active = false;
    }
}

pub fn updateCapabilities(pid: u16, capabilities: u32) void {
    if (findProcess(pid)) |entry| {
        const had_net = (entry.capabilities & CAP_NET) != 0;
        const has_net = (capabilities & CAP_NET) != 0;
        entry.capabilities = capabilities;

        if (had_net and !has_net) {
            serial.writeString("[NET-CAP] CAP_NET revoked pid=");
            printNumber(pid);
            serial.writeString(" - closing sockets\n");
            closeProcessSockets(pid);
        }
    }
}

pub fn setNetMode(pid: u16, mode: NetMode) bool {
    if (findProcess(pid)) |entry| {
        entry.mode = mode;
        serial.writeString("[NET-CAP] pid=");
        printNumber(pid);
        serial.writeString(" mode=");
        serial.writeString(switch (mode) {
            .inherit => "inherit",
            .allow_all => "allow_all",
            .restricted => "restricted",
            .deny_all => "deny_all",
        });
        serial.writeString("\n");
        return true;
    }
    return false;
}

pub fn setMaxSockets(pid: u16, max: u8) bool {
    if (findProcess(pid)) |entry| {
        entry.max_sockets = max;
        return true;
    }
    return false;
}

fn findProcess(pid: u16) ?*NetProcessEntry {
    for (0..process_count) |i| {
        if (processes[i].pid == pid and processes[i].active) {
            return &processes[i];
        }
    }
    return null;
}

pub fn getProcess(pid: u16) ?*const NetProcessEntry {
    for (0..process_count) |i| {
        if (processes[i].pid == pid and processes[i].active) {
            return &processes[i];
        }
    }
    return null;
}

pub fn getProcessCount() usize {
    var count: usize = 0;
    for (0..process_count) |i| {
        if (processes[i].active) count += 1;
    }
    return count;
}

// ============================================================================
// Permission Enforcement — E3.6: Reports to unified pipeline
// ============================================================================

/// Determine violation type for unified handler
fn netActionToViolationType(action: NetAction) violation.ViolationType {
    return switch (action) {
        .blocked_no_cap => .network_violation,
        .blocked_restricted => .network_restricted,
        .blocked_deny_all => .network_violation,
        .blocked_no_policy => .network_violation,
        .blocked_socket_limit => .socket_unauthorized,
        .blocked_killed => .network_violation,
        .allowed => .network_violation,
    };
}

/// Report a network violation to the unified handler
fn reportNetViolation(pid: u16, action: NetAction, reason: []const u8, remote_ip: u32) void {
    if (!violation.isInitialized()) return;

    const vtype = netActionToViolationType(action);

    // Determine severity
    const severity: violation.ViolationSeverity = switch (action) {
        .blocked_killed => .critical,
        .blocked_deny_all => .high,
        .blocked_no_cap => .medium,
        .blocked_restricted => .medium,
        .blocked_socket_limit => .low,
        .blocked_no_policy => .low,
        .allowed => .info,
    };

    _ = violation.reportViolation(.{
        .violation_type = vtype,
        .severity = severity,
        .pid = pid,
        .source_ip = remote_ip,
        .detail = reason,
    });
}

pub fn checkCreate(pid: u16) NetCheckResult {
    stats.checks_total += 1;

    if (pid == 0) {
        stats.checks_allowed += 1;
        return .{ .action = .allowed, .reason = "Kernel" };
    }

    const entry = findProcess(pid) orelse {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_policy, .reason = "Unregistered process" };
    };

    if (entry.killed) {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_killed, .reason = "Process killed" };
    }

    if (entry.mode == .deny_all) {
        recordViolation(entry, "socket create in deny_all");
        reportNetViolation(pid, .blocked_deny_all, "socket create deny_all", 0);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_deny_all, .reason = "Mode: deny_all" };
    }

    if ((entry.capabilities & CAP_NET) == 0) {
        recordViolation(entry, "socket create without CAP_NET");
        reportNetViolation(pid, .blocked_no_cap, "create without CAP_NET", 0);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_cap, .reason = "No CAP_NET" };
    }

    if (entry.current_sockets >= entry.max_sockets) {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_socket_limit, .reason = "Socket limit reached" };
    }

    stats.checks_allowed += 1;
    return .{ .action = .allowed, .reason = "OK" };
}

pub fn checkBind(pid: u16, bind_ip: u32, port: u16) NetCheckResult {
    stats.checks_total += 1;

    if (pid == 0) {
        stats.checks_allowed += 1;
        return .{ .action = .allowed, .reason = "Kernel" };
    }

    const entry = findProcess(pid) orelse {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_policy, .reason = "Unregistered process" };
    };

    if (entry.killed) {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_killed, .reason = "Process killed" };
    }

    if ((entry.capabilities & CAP_NET) == 0) {
        recordViolation(entry, "bind without CAP_NET");
        reportNetViolation(pid, .blocked_no_cap, "bind without CAP_NET", bind_ip);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_cap, .reason = "No CAP_NET" };
    }

    if (entry.mode == .restricted) {
        if (!isPortAllowed(entry, port)) {
            recordViolation(entry, "bind to restricted port");
            reportNetViolation(pid, .blocked_restricted, "bind restricted port", 0);
            stats.checks_blocked += 1;
            return .{ .action = .blocked_restricted, .reason = "Port not in allowlist" };
        }
    }

    stats.checks_allowed += 1;
    return .{ .action = .allowed, .reason = "OK" };
}

pub fn checkConnect(pid: u16, remote_ip: u32, remote_port: u16) NetCheckResult {
    stats.checks_total += 1;

    if (pid == 0) {
        stats.checks_allowed += 1;
        return .{ .action = .allowed, .reason = "Kernel" };
    }

    const entry = findProcess(pid) orelse {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_policy, .reason = "Unregistered process" };
    };

    if (entry.killed) {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_killed, .reason = "Process killed" };
    }

    if (entry.mode == .deny_all) {
        recordViolation(entry, "connect in deny_all");
        reportNetViolation(pid, .blocked_deny_all, "connect deny_all", remote_ip);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_deny_all, .reason = "Mode: deny_all" };
    }

    if ((entry.capabilities & CAP_NET) == 0) {
        recordViolation(entry, "connect without CAP_NET");
        reportNetViolation(pid, .blocked_no_cap, "connect no CAP_NET", remote_ip);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_cap, .reason = "No CAP_NET" };
    }

    if (entry.mode == .restricted) {
        if (!isIPAllowed(entry, remote_ip)) {
            recordViolation(entry, "connect to restricted IP");
            reportNetViolation(pid, .blocked_restricted, "connect restricted IP", remote_ip);
            stats.checks_blocked += 1;
            return .{ .action = .blocked_restricted, .reason = "IP not in allowlist" };
        }
        if (!isPortAllowed(entry, remote_port)) {
            recordViolation(entry, "connect to restricted port");
            reportNetViolation(pid, .blocked_restricted, "connect restricted port", remote_ip);
            stats.checks_blocked += 1;
            return .{ .action = .blocked_restricted, .reason = "Port not in allowlist" };
        }
    }

    if (checkNetRules(pid, remote_ip, remote_port)) |rule| {
        if (!rule.allow) {
            recordViolation(entry, "denied by net rule");
            reportNetViolation(pid, .blocked_restricted, "denied by rule", remote_ip);
            stats.checks_blocked += 1;
            return .{ .action = .blocked_restricted, .reason = "Rule denied" };
        }
    }

    stats.checks_allowed += 1;
    return .{ .action = .allowed, .reason = "OK" };
}

pub fn checkSend(pid: u16) NetCheckResult {
    stats.checks_total += 1;

    if (pid == 0) {
        stats.checks_allowed += 1;
        return .{ .action = .allowed, .reason = "Kernel" };
    }

    const entry = findProcess(pid) orelse {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_policy, .reason = "Unregistered process" };
    };

    if (entry.killed) {
        stats.checks_blocked += 1;
        return .{ .action = .blocked_killed, .reason = "Process killed" };
    }

    if (entry.mode == .deny_all) {
        recordViolation(entry, "send in deny_all");
        reportNetViolation(pid, .blocked_deny_all, "send deny_all", 0);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_deny_all, .reason = "Mode: deny_all" };
    }

    if ((entry.capabilities & CAP_NET) == 0) {
        recordViolation(entry, "send without CAP_NET");
        reportNetViolation(pid, .blocked_no_cap, "send no CAP_NET", 0);
        stats.checks_blocked += 1;
        return .{ .action = .blocked_no_cap, .reason = "No CAP_NET" };
    }

    stats.checks_allowed += 1;
    return .{ .action = .allowed, .reason = "OK" };
}

// ============================================================================
// IP / Port Allowlists
// ============================================================================

pub fn addAllowedIP(pid: u16, ip: u32) bool {
    const entry = findProcess(pid) orelse return false;
    if (entry.ip_count >= MAX_ALLOWED_IPS) return false;

    for (0..entry.ip_count) |i| {
        if (entry.allowed_ips[i] == ip) return true;
    }

    entry.allowed_ips[entry.ip_count] = ip;
    entry.ip_count += 1;
    return true;
}

pub fn removeAllowedIP(pid: u16, ip: u32) bool {
    const entry = findProcess(pid) orelse return false;
    for (0..entry.ip_count) |i| {
        if (entry.allowed_ips[i] == ip) {
            var j = i;
            while (j + 1 < entry.ip_count) : (j += 1) {
                entry.allowed_ips[j] = entry.allowed_ips[j + 1];
            }
            entry.ip_count -= 1;
            return true;
        }
    }
    return false;
}

pub fn addAllowedPort(pid: u16, port: u16) bool {
    const entry = findProcess(pid) orelse return false;
    if (entry.port_count >= MAX_ALLOWED_PORTS) return false;

    for (0..entry.port_count) |i| {
        if (entry.allowed_ports[i] == port) return true;
    }

    entry.allowed_ports[entry.port_count] = port;
    entry.port_count += 1;
    return true;
}

pub fn removeAllowedPort(pid: u16, port: u16) bool {
    const entry = findProcess(pid) orelse return false;
    for (0..entry.port_count) |i| {
        if (entry.allowed_ports[i] == port) {
            var j = i;
            while (j + 1 < entry.port_count) : (j += 1) {
                entry.allowed_ports[j] = entry.allowed_ports[j + 1];
            }
            entry.port_count -= 1;
            return true;
        }
    }
    return false;
}

fn isIPAllowed(entry: *const NetProcessEntry, ip: u32) bool {
    if (entry.ip_count == 0) return true;
    for (0..entry.ip_count) |i| {
        if (entry.allowed_ips[i] == ip) return true;
    }
    return false;
}

fn isPortAllowed(entry: *const NetProcessEntry, port: u16) bool {
    if (entry.port_count == 0) return true;
    for (0..entry.port_count) |i| {
        if (entry.allowed_ports[i] == port) return true;
    }
    return false;
}

// ============================================================================
// Per-Process Network Rules
// ============================================================================

pub fn addNetRule(
    pid: u16,
    remote_ip: u32,
    remote_mask: u32,
    port_start: u16,
    port_end: u16,
    allow: bool,
) ?u32 {
    if (net_rule_count >= MAX_NET_RULES) return null;

    const id = next_rule_id;
    next_rule_id += 1;

    net_rules[net_rule_count] = .{
        .id = id,
        .pid = pid,
        .remote_ip = remote_ip,
        .remote_mask = remote_mask,
        .remote_port_start = port_start,
        .remote_port_end = port_end,
        .allow = allow,
        .enabled = true,
        .match_count = 0,
    };
    net_rule_count += 1;
    return id;
}

pub fn removeNetRule(id: u32) bool {
    for (0..net_rule_count) |i| {
        if (net_rules[i].id == id) {
            var j = i;
            while (j + 1 < net_rule_count) : (j += 1) {
                net_rules[j] = net_rules[j + 1];
            }
            net_rule_count -= 1;
            return true;
        }
    }
    return false;
}

pub fn getNetRuleCount() usize {
    return net_rule_count;
}

fn checkNetRules(pid: u16, remote_ip: u32, remote_port: u16) ?*NetRule {
    for (0..net_rule_count) |i| {
        const rule = &net_rules[i];
        if (!rule.enabled or rule.pid != pid) continue;

        if (rule.remote_ip != 0) {
            if ((remote_ip & rule.remote_mask) != (rule.remote_ip & rule.remote_mask)) continue;
        }

        if (rule.remote_port_start != 0 or rule.remote_port_end != 0) {
            if (remote_port < rule.remote_port_start or remote_port > rule.remote_port_end) continue;
        }

        rule.match_count += 1;
        return rule;
    }
    return null;
}

// ============================================================================
// Socket Ownership
// ============================================================================

pub fn registerSocket(socket_idx: u8, pid: u16, sock_type: u8, local_port: u16) bool {
    if (findProcess(pid)) |entry| {
        entry.current_sockets += 1;
    }

    for (&owners) |*o| {
        if (!o.active) {
            o.* = .{
                .socket_idx = socket_idx,
                .pid = pid,
                .active = true,
                .sock_type = sock_type,
                .local_port = local_port,
                .remote_ip = 0,
                .remote_port = 0,
                .created_tick = getTick(),
            };
            stats.sockets_created += 1;
            return true;
        }
    }
    return false;
}

pub fn unregisterSocket(socket_idx: u8) void {
    for (&owners) |*o| {
        if (o.active and o.socket_idx == socket_idx) {
            if (findProcess(o.pid)) |entry| {
                if (entry.current_sockets > 0) entry.current_sockets -= 1;
            }
            o.active = false;
            stats.sockets_closed += 1;
            return;
        }
    }
}

pub fn updateSocketRemote(socket_idx: u8, remote_ip: u32, remote_port: u16) void {
    for (&owners) |*o| {
        if (o.active and o.socket_idx == socket_idx) {
            o.remote_ip = remote_ip;
            o.remote_port = remote_port;
            return;
        }
    }
}

pub fn getSocketOwner(socket_idx: u8) ?u16 {
    for (&owners) |*o| {
        if (o.active and o.socket_idx == socket_idx) return o.pid;
    }
    return null;
}

pub fn getActiveSocketCount() usize {
    var count: usize = 0;
    for (&owners) |*o| {
        if (o.active) count += 1;
    }
    return count;
}

pub fn closeProcessSockets(pid: u16) void {
    for (&owners) |*o| {
        if (o.active and o.pid == pid) {
            o.active = false;
            stats.sockets_closed += 1;
        }
    }
    if (findProcess(pid)) |entry| {
        entry.current_sockets = 0;
    }
}

pub fn getSocketOwnerEntry(index: usize) ?*const SocketOwner {
    var count: usize = 0;
    for (&owners) |*o| {
        if (o.active) {
            if (count == index) return o;
            count += 1;
        }
    }
    return null;
}

// ============================================================================
// Violation Tracking & Auto-Kill — E3.6: Also reports to unified pipeline
// ============================================================================

fn recordViolation(entry: *NetProcessEntry, reason: []const u8) void {
    entry.violations += 1;
    entry.packets_blocked += 1;
    entry.last_violation_tick = getTick();
    stats.violations_total += 1;

    serial.writeString("[NET-CAP] VIOLATION pid=");
    printNumber(entry.pid);
    serial.writeString(" #");
    printNumber(entry.violations);
    serial.writeString("/");
    printNumber(MAX_VIOLATIONS_BEFORE_KILL);
    serial.writeString(" reason=\"");
    serial.writeString(reason);
    serial.writeString("\"\n");

    // Auto-kill threshold reached
    if (entry.violations >= MAX_VIOLATIONS_BEFORE_KILL and !entry.killed) {
        entry.killed = true;
        stats.processes_killed += 1;
        closeProcessSockets(entry.pid);

        serial.writeString("[NET-CAP] *** AUTO-KILL pid=");
        printNumber(entry.pid);
        serial.writeString(" *** (");
        printNumber(entry.violations);
        serial.writeString(" violations)\n");

        // E3.6: Report kill event to unified handler
        if (violation.isInitialized()) {
            _ = violation.reportViolation(.{
                .violation_type = .network_violation,
                .severity = .critical,
                .pid = entry.pid,
                .source_ip = 0,
                .detail = "auto-killed: max violations",
            });
        }
    }
}

pub fn getViolations(pid: u16) u32 {
    if (findProcess(pid)) |entry| return entry.violations;
    return 0;
}

pub fn isKilled(pid: u16) bool {
    if (findProcess(pid)) |entry| return entry.killed;
    return false;
}

pub fn resetViolations(pid: u16) void {
    if (findProcess(pid)) |entry| {
        entry.violations = 0;
        entry.killed = false;
    }
}

// ============================================================================
// Capability Bridge
// ============================================================================

pub fn grantNetCapability(pid: u16) bool {
    if (findProcess(pid)) |entry| {
        entry.capabilities |= CAP_NET;
        return true;
    }
    return false;
}

pub fn revokeNetCapability(pid: u16) bool {
    if (findProcess(pid)) |entry| {
        entry.capabilities &= ~CAP_NET;
        closeProcessSockets(pid);
        return true;
    }
    return false;
}

pub fn hasNetCapability(pid: u16) bool {
    if (pid == 0) return true;
    if (findProcess(pid)) |entry| return (entry.capabilities & CAP_NET) != 0;
    return false;
}

// ============================================================================
// Statistics & Display
// ============================================================================

pub fn getStats() NetStats {
    return stats;
}

pub fn resetStats() void {
    stats = NetStats{};
}

pub fn printStatus() void {
    serial.writeString("\n=== NET-CAP STATUS ===\n");
    printSerialLine(40);

    serial.writeString("  Registered processes: ");
    printNumber(getProcessCount());
    serial.writeString("\n  Active sockets:       ");
    printNumber(getActiveSocketCount());
    serial.writeString("\n  Per-process rules:    ");
    printNumber(net_rule_count);
    serial.writeString("\n");

    printSerialLine(40);

    serial.writeString("  Checks total:     ");
    printNumber64(stats.checks_total);
    serial.writeString("\n  Checks allowed:   ");
    printNumber64(stats.checks_allowed);
    serial.writeString("\n  Checks blocked:   ");
    printNumber64(stats.checks_blocked);
    serial.writeString("\n  Violations total: ");
    printNumber64(stats.violations_total);
    serial.writeString("\n  Processes killed: ");
    printNumber64(stats.processes_killed);
    serial.writeString("\n  Sockets created:  ");
    printNumber64(stats.sockets_created);
    serial.writeString("\n  Sockets closed:   ");
    printNumber64(stats.sockets_closed);
    serial.writeString("\n");

    printSerialLine(40);
    serial.writeString("\n");
}

pub fn printProcessTable() void {
    serial.writeString("\n=== NET-CAP PROCESS TABLE ===\n");
    serial.writeString("  PID  NET  MODE        SOCKS  VIOLS  STATUS\n");
    printSerialLine(55);

    for (0..process_count) |i| {
        const p = &processes[i];
        if (!p.active) continue;

        serial.writeString("  ");
        printPadded(p.pid, 4);
        serial.writeString("  ");

        if ((p.capabilities & CAP_NET) != 0) {
            serial.writeString("YES");
        } else {
            serial.writeString(" NO");
        }
        serial.writeString("  ");

        switch (p.mode) {
            .inherit => serial.writeString("inherit   "),
            .allow_all => serial.writeString("allow_all "),
            .restricted => serial.writeString("restrict  "),
            .deny_all => serial.writeString("deny_all  "),
        }

        serial.writeString("  ");
        printPadded(p.current_sockets, 2);
        serial.writeString("/");
        printNumber(p.max_sockets);

        serial.writeString("  ");
        printPadded(p.violations, 4);

        serial.writeString("  ");
        if (p.killed) {
            serial.writeString("KILLED");
        } else {
            serial.writeString("active");
        }

        serial.writeString("\n");
    }
    printSerialLine(55);
    serial.writeString("\n");
}

pub fn printSocketOwners() void {
    serial.writeString("\n=== SOCKET OWNERSHIP ===\n");
    serial.writeString("  IDX  PID  TYPE  LOCAL  REMOTE\n");
    printSerialLine(50);

    var found = false;
    for (&owners) |*o| {
        if (!o.active) continue;
        found = true;

        serial.writeString("  ");
        printPadded(o.socket_idx, 3);
        serial.writeString("  ");
        printPadded(o.pid, 3);
        serial.writeString("  ");

        switch (o.sock_type) {
            0 => serial.writeString("TCP"),
            1 => serial.writeString("UDP"),
            2 => serial.writeString("RAW"),
            else => serial.writeString("???"),
        }
        serial.writeString("   ");
        printPadded(o.local_port, 5);
        serial.writeString("  ");

        if (o.remote_ip != 0) {
            printIP(o.remote_ip);
            serial.writeString(":");
            printNumber(o.remote_port);
        } else {
            serial.writeString("*:*");
        }
        serial.writeString("\n");
    }

    if (!found) {
        serial.writeString("  (no active sockets)\n");
    }
    printSerialLine(50);
    serial.writeString("\n");
}

// ============================================================================
// Helpers
// ============================================================================

fn getTick() u64 {
    return timer.getTicks();
}

fn printNumber(n: anytype) void {
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

fn printNumber64(n: u64) void {
    if (n <= 0xFFFFFFFF) {
        printNumber(@as(u32, @intCast(n)));
        return;
    }
    const hi: u32 = @intCast(n / 1_000_000_000);
    const lo: u32 = @intCast(n % 1_000_000_000);
    printNumber(hi);
    var digits: usize = 0;
    const tmp = lo;
    if (tmp == 0) {
        digits = 1;
    } else {
        var t = tmp;
        while (t > 0) : (digits += 1) t /= 10;
    }
    for (0..9 - digits) |_| serial.writeChar('0');
    if (lo > 0) printNumber(lo);
}

fn printPadded(n: anytype, width: usize) void {
    const val: u32 = @intCast(n);
    var d: usize = 1;
    var tmp = val;
    while (tmp >= 10) : (d += 1) tmp /= 10;
    if (d < width) {
        for (0..width - d) |_| serial.writeChar(' ');
    }
    printNumber(val);
}

fn printIP(ip_val: u32) void {
    printNumber((ip_val >> 24) & 0xFF);
    serial.writeChar('.');
    printNumber((ip_val >> 16) & 0xFF);
    serial.writeChar('.');
    printNumber((ip_val >> 8) & 0xFF);
    serial.writeChar('.');
    printNumber(ip_val & 0xFF);
}

fn printSerialLine(len: usize) void {
    for (0..len) |_| serial.writeChar('-');
    serial.writeString("\n");
}
