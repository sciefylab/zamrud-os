// ============================================================================
// ZAMRUD OS - SECURITY COORDINATOR
// Central security management
// ============================================================================

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const firewall = @import("../net/firewall.zig");
const blacklist = @import("blacklist.zig");
const threat_log = @import("threat_log.zig");

// =============================================================================
// Security Level
// =============================================================================

pub const SecurityLevel = enum(u8) {
    minimal = 0, // Basic protection
    standard = 1, // Normal operation
    elevated = 2, // Heightened security
    maximum = 3, // Full lockdown
    paranoid = 4, // Everything blocked except whitelist
};

var current_level: SecurityLevel = .standard;
var initialized: bool = false;

// Test-state transaction storage. Static backups avoid large kernel-stack copies.
var test_isolation_active: bool = false;
var test_backup_current_level: @TypeOf(current_level) = undefined;
var test_backup_initialized: @TypeOf(initialized) = undefined;

pub fn beginTestIsolation() bool {
    if (test_isolation_active) return false;
    test_backup_current_level = current_level;
    test_backup_initialized = initialized;
    test_isolation_active = true;
    return true;
}

pub fn endTestIsolation(owner: bool) void {
    if (!owner or !test_isolation_active) return;
    current_level = test_backup_current_level;
    initialized = test_backup_initialized;
    test_isolation_active = false;
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[SECURITY] Initializing security coordinator...\n");

    // Initialize subsystems
    threat_log.init();
    blacklist.init();

    // Firewall is initialized by ip.zig

    initialized = true;
    serial.writeString("[SECURITY] Security coordinator ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Security Level Management
// =============================================================================

pub fn setSecurityLevel(level: SecurityLevel) void {
    current_level = level;

    switch (level) {
        .minimal => {
            firewall.setState(.permissive);
            firewall.setStealthMode(false);
            firewall.setP2POnlyMode(false);
        },
        .standard => {
            firewall.setState(.enforcing);
            firewall.setStealthMode(true);
            firewall.setP2POnlyMode(false);
        },
        .elevated => {
            firewall.setState(.enforcing);
            firewall.setStealthMode(true);
            firewall.setP2POnlyMode(true);
        },
        .maximum => {
            firewall.setState(.lockdown);
            firewall.setStealthMode(true);
            firewall.setP2POnlyMode(true);
        },
        .paranoid => {
            firewall.setState(.lockdown);
            firewall.setStealthMode(true);
            firewall.setP2POnlyMode(true);
        },
    }

    serial.writeString("[SECURITY] Level: ");
    serial.writeString(switch (level) {
        .minimal => "MINIMAL",
        .standard => "STANDARD",
        .elevated => "ELEVATED",
        .maximum => "MAXIMUM",
        .paranoid => "PARANOID",
    });
    serial.writeString("\n");
}

pub fn getSecurityLevel() SecurityLevel {
    return current_level;
}

// =============================================================================
// Emergency Controls
// =============================================================================

pub fn emergencyLockdown() void {
    serial.writeString("\n");
    serial.writeString("╔═══════════════════════════════════════╗\n");
    serial.writeString("║   🔴 EMERGENCY LOCKDOWN ACTIVE 🔴     ║\n");
    serial.writeString("╚═══════════════════════════════════════╝\n");

    setSecurityLevel(.paranoid);
}

pub fn disarmLockdown() void {
    serial.writeString("[SECURITY] Lockdown disarmed\n");
    setSecurityLevel(.standard);
}

// =============================================================================
// Threat Response
// =============================================================================

pub fn respondToThreat(severity: threat_log.ThreatSeverity) void {
    switch (severity) {
        .low => {
            // Just log
        },
        .medium => {
            serial.writeString("[SECURITY] ⚠️ Medium threat detected\n");
        },
        .high => {
            serial.writeString("[SECURITY] 🚨 High threat! Elevating security\n");
            if (current_level == .standard) {
                setSecurityLevel(.elevated);
            }
        },
        .critical => {
            serial.writeString("[SECURITY] 🔴 CRITICAL THREAT!\n");
            setSecurityLevel(.maximum);
        },
    }
}

// =============================================================================
// Status
// =============================================================================

pub const SecurityStatus = struct {
    level: SecurityLevel,
    firewall_state: firewall.FirewallState,
    threats_detected: u64,
    active_blocks: u64,
};

pub fn getStatus() SecurityStatus {
    return SecurityStatus{
        .level = current_level,
        .firewall_state = firewall.state,
        .threats_detected = threat_log.getTotalThreats(),
        .active_blocks = blacklist.getActiveCount(),
    };
}

pub fn printStatus() void {
    const status = getStatus();

    serial.writeString("\n╔═══════════════════════════════════════╗\n");
    serial.writeString("║       SECURITY STATUS                 ║\n");
    serial.writeString("╠═══════════════════════════════════════╣\n");

    serial.writeString("║ Level: ");
    serial.writeString(switch (status.level) {
        .minimal => "MINIMAL                         ",
        .standard => "STANDARD                        ",
        .elevated => "ELEVATED                        ",
        .maximum => "MAXIMUM                         ",
        .paranoid => "PARANOID                        ",
    });
    serial.writeString("║\n");

    serial.writeString("║ Firewall: ");
    serial.writeString(switch (status.firewall_state) {
        .disabled => "DISABLED                      ",
        .permissive => "PERMISSIVE                    ",
        .enforcing => "ENFORCING ✓                   ",
        .lockdown => "LOCKDOWN 🔒                   ",
    });
    serial.writeString("║\n");

    serial.writeString("╚═══════════════════════════════════════╝\n\n");
}
