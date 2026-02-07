//! Zamrud OS - Build Configuration
//! Central configuration for kernel and subsystems
//!
//! Configuration Profiles:
//!   - PRODUCTION:  Optimized for performance, minimal debug output
//!   - DEVELOPMENT: Full debug output, all tests visible
//!   - TESTING:     Maximum validation, verbose output
//!
//! Change PROFILE constant to switch between modes

const build_options = @import("config");

// =============================================================================
// MASTER CONFIGURATION PROFILE
// =============================================================================

/// Configuration profile selector
pub const Profile = enum {
    production, // Clean, fast, silent
    development, // Debug enabled, verbose
    testing, // All tests, maximum verbosity
};

/// 🔧 CHANGE THIS TO SWITCH PROFILE
pub const PROFILE: Profile = .development;

// =============================================================================
// Profile-Based Settings (Automatic based on PROFILE)
// =============================================================================

/// Smoke test display mode
pub const SmokeTestDisplay = enum {
    always, // Always show test results
    on_failure, // Only show if tests fail
    never, // Never show, completely silent
    verbose, // Show detailed test info
};

pub const SMOKE_TEST_DISPLAY: SmokeTestDisplay = switch (PROFILE) {
    .production => .on_failure,
    .development => .always,
    .testing => .verbose,
};

pub const ENABLE_SMOKE_TEST: bool = switch (PROFILE) {
    .production => true, // Yes, but silent if pass
    .development => true, // Yes, with output
    .testing => true, // Yes, verbose
};

pub const VERBOSE_BOOT: bool = switch (PROFILE) {
    .production => false,
    .development => true,
    .testing => true,
};

pub const SERIAL_DEBUG: bool = switch (PROFILE) {
    .production => false, // No debug spam in production
    .development => true,
    .testing => true,
};

pub const HEAP_DEBUG: bool = switch (PROFILE) {
    .production => false,
    .development => false, // Usually too verbose even for dev
    .testing => true,
};

pub const NETWORK_DEBUG: bool = switch (PROFILE) {
    .production => false,
    .development => false,
    .testing => true,
};

pub const FS_DEBUG: bool = switch (PROFILE) {
    .production => false,
    .development => false,
    .testing => true,
};

// =============================================================================
// Build Options (from build.zig)
// =============================================================================

/// UI Engine enabled (QuickJS, Yoga, Svelte apps)
/// Jika false, kernel console tetap jalan di framebuffer
pub const enable_ui: bool = build_options.enable_ui;

// =============================================================================
// Version Info
// =============================================================================

pub const version = "0.1.0";
pub const VERSION_MAJOR: u8 = 0;
pub const VERSION_MINOR: u8 = 1;
pub const VERSION_PATCH: u8 = 0;

/// Get build mode string
pub fn getBuildMode() []const u8 {
    return if (enable_ui) "Desktop" else "Server";
}

/// Get profile string
pub fn getProfileString() []const u8 {
    return switch (PROFILE) {
        .production => "PRODUCTION",
        .development => "DEVELOPMENT",
        .testing => "TESTING",
    };
}

// =============================================================================
// PRODUCTION SETTINGS
// =============================================================================

pub const ProductionConfig = struct {
    // Security - Maximum
    pub const SECURITY_LOCKDOWN: bool = false;
    pub const FIREWALL_ENFORCING: bool = true;
    pub const P2P_ONLY_MODE: bool = true;
    pub const STEALTH_MODE: bool = true;
    pub const AUTO_BLACKLIST: bool = true;

    // Memory - Optimized
    pub const HEAP_INITIAL_PAGES: u64 = 16; // 64 KB
    pub const HEAP_MAX_PAGES: u64 = 256; // 1 MB
    pub const HEAP_CANARY: bool = true;
    pub const HEAP_ZERO_ON_FREE: bool = true;

    // Network - Conservative
    pub const MAX_PACKETS_PER_SECOND: u32 = 1000;
    pub const SYN_FLOOD_THRESHOLD: u32 = 100;
    pub const MAX_CONNECTIONS: usize = 1024;
    pub const CONNECTION_TIMEOUT_MS: u64 = 300000; // 5 min

    // Performance
    pub const ENABLE_PROFILING: bool = false;
    pub const ENABLE_STATS: bool = false;

    // Testing
    pub const ENABLE_TEST_COMMANDS: bool = false;
    pub const ENABLE_TESTALL: bool = false;

    // Logging
    pub const LOG_LEVEL = LogLevel.err;
    pub const LOG_TO_SERIAL: bool = false;
    pub const LOG_DROPPED_PACKETS: bool = false;
};

// =============================================================================
// DEVELOPMENT SETTINGS
// =============================================================================

pub const DevelopmentConfig = struct {
    // Security - Relaxed for testing
    pub const SECURITY_LOCKDOWN: bool = false;
    pub const FIREWALL_ENFORCING: bool = true;
    pub const P2P_ONLY_MODE: bool = false; // Allow non-P2P for testing
    pub const STEALTH_MODE: bool = false; // Respond to ICMP for debug
    pub const AUTO_BLACKLIST: bool = false; // Don't auto-block during dev

    // Memory - Generous
    pub const HEAP_INITIAL_PAGES: u64 = 32; // 128 KB
    pub const HEAP_MAX_PAGES: u64 = 512; // 2 MB
    pub const HEAP_CANARY: bool = true;
    pub const HEAP_ZERO_ON_FREE: bool = true;

    // Network - Permissive
    pub const MAX_PACKETS_PER_SECOND: u32 = 10000;
    pub const SYN_FLOOD_THRESHOLD: u32 = 1000;
    pub const MAX_CONNECTIONS: usize = 2048;
    pub const CONNECTION_TIMEOUT_MS: u64 = 600000; // 10 min

    // Performance
    pub const ENABLE_PROFILING: bool = true;
    pub const ENABLE_STATS: bool = true;

    // Testing
    pub const ENABLE_TEST_COMMANDS: bool = true;
    pub const ENABLE_TESTALL: bool = true;

    // Logging
    pub const LOG_LEVEL = LogLevel.info;
    pub const LOG_TO_SERIAL: bool = true;
    pub const LOG_DROPPED_PACKETS: bool = false;
};

// =============================================================================
// TESTING SETTINGS
// =============================================================================

pub const TestingConfig = struct {
    // Security - Mixed for testing scenarios
    pub const SECURITY_LOCKDOWN: bool = false;
    pub const FIREWALL_ENFORCING: bool = true;
    pub const P2P_ONLY_MODE: bool = false;
    pub const STEALTH_MODE: bool = false;
    pub const AUTO_BLACKLIST: bool = true;

    // Memory - Maximum for stress testing
    pub const HEAP_INITIAL_PAGES: u64 = 64; // 256 KB
    pub const HEAP_MAX_PAGES: u64 = 1024; // 4 MB
    pub const HEAP_CANARY: bool = true;
    pub const HEAP_ZERO_ON_FREE: bool = true;

    // Network - Wide open for testing
    pub const MAX_PACKETS_PER_SECOND: u32 = 100000;
    pub const SYN_FLOOD_THRESHOLD: u32 = 10000;
    pub const MAX_CONNECTIONS: usize = 4096;
    pub const CONNECTION_TIMEOUT_MS: u64 = 3600000; // 1 hour

    // Performance
    pub const ENABLE_PROFILING: bool = true;
    pub const ENABLE_STATS: bool = true;

    // Testing
    pub const ENABLE_TEST_COMMANDS: bool = true;
    pub const ENABLE_TESTALL: bool = true;

    // Logging
    pub const LOG_LEVEL = LogLevel.debug;
    pub const LOG_TO_SERIAL: bool = true;
    pub const LOG_DROPPED_PACKETS: bool = true;
};

// =============================================================================
// ACTIVE CONFIGURATION (Based on selected PROFILE)
// =============================================================================

// Security
pub const SECURITY_LOCKDOWN: bool = switch (PROFILE) {
    .production => ProductionConfig.SECURITY_LOCKDOWN,
    .development => DevelopmentConfig.SECURITY_LOCKDOWN,
    .testing => TestingConfig.SECURITY_LOCKDOWN,
};

pub const FIREWALL_ENFORCING: bool = switch (PROFILE) {
    .production => ProductionConfig.FIREWALL_ENFORCING,
    .development => DevelopmentConfig.FIREWALL_ENFORCING,
    .testing => TestingConfig.FIREWALL_ENFORCING,
};

pub const P2P_ONLY_MODE: bool = switch (PROFILE) {
    .production => ProductionConfig.P2P_ONLY_MODE,
    .development => DevelopmentConfig.P2P_ONLY_MODE,
    .testing => TestingConfig.P2P_ONLY_MODE,
};

pub const STEALTH_MODE: bool = switch (PROFILE) {
    .production => ProductionConfig.STEALTH_MODE,
    .development => DevelopmentConfig.STEALTH_MODE,
    .testing => TestingConfig.STEALTH_MODE,
};

pub const AUTO_BLACKLIST: bool = switch (PROFILE) {
    .production => ProductionConfig.AUTO_BLACKLIST,
    .development => DevelopmentConfig.AUTO_BLACKLIST,
    .testing => TestingConfig.AUTO_BLACKLIST,
};

// Memory
pub const HEAP_INITIAL_PAGES: u64 = switch (PROFILE) {
    .production => ProductionConfig.HEAP_INITIAL_PAGES,
    .development => DevelopmentConfig.HEAP_INITIAL_PAGES,
    .testing => TestingConfig.HEAP_INITIAL_PAGES,
};

pub const HEAP_MAX_PAGES: u64 = switch (PROFILE) {
    .production => ProductionConfig.HEAP_MAX_PAGES,
    .development => DevelopmentConfig.HEAP_MAX_PAGES,
    .testing => TestingConfig.HEAP_MAX_PAGES,
};

pub const HEAP_CANARY: bool = switch (PROFILE) {
    .production => ProductionConfig.HEAP_CANARY,
    .development => DevelopmentConfig.HEAP_CANARY,
    .testing => TestingConfig.HEAP_CANARY,
};

pub const HEAP_ZERO_ON_FREE: bool = switch (PROFILE) {
    .production => ProductionConfig.HEAP_ZERO_ON_FREE,
    .development => DevelopmentConfig.HEAP_ZERO_ON_FREE,
    .testing => TestingConfig.HEAP_ZERO_ON_FREE,
};

// Network
pub const MAX_PACKETS_PER_SECOND: u32 = switch (PROFILE) {
    .production => ProductionConfig.MAX_PACKETS_PER_SECOND,
    .development => DevelopmentConfig.MAX_PACKETS_PER_SECOND,
    .testing => TestingConfig.MAX_PACKETS_PER_SECOND,
};

pub const SYN_FLOOD_THRESHOLD: u32 = switch (PROFILE) {
    .production => ProductionConfig.SYN_FLOOD_THRESHOLD,
    .development => DevelopmentConfig.SYN_FLOOD_THRESHOLD,
    .testing => TestingConfig.SYN_FLOOD_THRESHOLD,
};

pub const MAX_CONNECTIONS: usize = switch (PROFILE) {
    .production => ProductionConfig.MAX_CONNECTIONS,
    .development => DevelopmentConfig.MAX_CONNECTIONS,
    .testing => TestingConfig.MAX_CONNECTIONS,
};

pub const CONNECTION_TIMEOUT_MS: u64 = switch (PROFILE) {
    .production => ProductionConfig.CONNECTION_TIMEOUT_MS,
    .development => DevelopmentConfig.CONNECTION_TIMEOUT_MS,
    .testing => TestingConfig.CONNECTION_TIMEOUT_MS,
};

// Performance
pub const ENABLE_PROFILING: bool = switch (PROFILE) {
    .production => ProductionConfig.ENABLE_PROFILING,
    .development => DevelopmentConfig.ENABLE_PROFILING,
    .testing => TestingConfig.ENABLE_PROFILING,
};

pub const ENABLE_STATS: bool = switch (PROFILE) {
    .production => ProductionConfig.ENABLE_STATS,
    .development => DevelopmentConfig.ENABLE_STATS,
    .testing => TestingConfig.ENABLE_STATS,
};

// Testing
pub const ENABLE_TEST_COMMANDS: bool = switch (PROFILE) {
    .production => ProductionConfig.ENABLE_TEST_COMMANDS,
    .development => DevelopmentConfig.ENABLE_TEST_COMMANDS,
    .testing => TestingConfig.ENABLE_TEST_COMMANDS,
};

pub const ENABLE_TESTALL: bool = switch (PROFILE) {
    .production => ProductionConfig.ENABLE_TESTALL,
    .development => DevelopmentConfig.ENABLE_TESTALL,
    .testing => TestingConfig.ENABLE_TESTALL,
};

// Logging
pub const LogLevel = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
    critical = 4,
    none = 255,
};

pub const LOG_LEVEL: LogLevel = switch (PROFILE) {
    .production => ProductionConfig.LOG_LEVEL,
    .development => DevelopmentConfig.LOG_LEVEL,
    .testing => TestingConfig.LOG_LEVEL,
};

pub const LOG_TO_SERIAL: bool = switch (PROFILE) {
    .production => ProductionConfig.LOG_TO_SERIAL,
    .development => DevelopmentConfig.LOG_TO_SERIAL,
    .testing => TestingConfig.LOG_TO_SERIAL,
};

pub const LOG_DROPPED_PACKETS: bool = switch (PROFILE) {
    .production => ProductionConfig.LOG_DROPPED_PACKETS,
    .development => DevelopmentConfig.LOG_DROPPED_PACKETS,
    .testing => TestingConfig.LOG_DROPPED_PACKETS,
};

// =============================================================================
// FIXED CONSTANTS (Same for all profiles)
// =============================================================================

// Process
pub const MAX_PROCESSES: usize = 64;
pub const DEFAULT_TIME_SLICE: u32 = 10;
pub const KERNEL_STACK_SIZE: u64 = 16 * 1024;

// Filesystem
pub const MAX_OPEN_FILES: usize = 128;
pub const MAX_PATH_LENGTH: usize = 256;
pub const MAX_FILENAME_LENGTH: usize = 255;
pub const MAX_MOUNT_POINTS: usize = 16;

// Gateway
pub const MAX_GATEWAY_SERVICES: usize = 32;
pub const MAX_GATEWAY_CONNECTIONS: usize = 128;
pub const MAX_ALLOWED_PEERS: usize = 16;
pub const MAX_REQUEST_AGE_MS: u64 = 30000;

// P2P
pub const MAX_PEERS: usize = 256;
pub const MAX_PENDING_MESSAGES: usize = 512;
pub const PEER_TIMEOUT_MS: u64 = 60000;
pub const DISCOVERY_INTERVAL_MS: u64 = 30000;

// Blockchain
pub const MAX_BLOCKS: usize = 10000;
pub const MAX_ENTRIES_PER_BLOCK: usize = 100;
pub const MINING_DIFFICULTY: u8 = 2;

// Identity
pub const MAX_IDENTITIES: usize = 100;
pub const MAX_KEYS_PER_IDENTITY: usize = 10;
pub const SESSION_TIMEOUT_MS: u64 = 1800000;

// Shell
pub const SHELL_HISTORY_SIZE: usize = 100;
pub const MAX_COMMAND_LENGTH: usize = 256;
pub const SHELL_PROMPT: []const u8 = "zamrud> ";

// Hardware
pub const TIMER_FREQ_HZ: u32 = 100;
pub const SERIAL_PORT: u16 = 0x3F8;
pub const SERIAL_BAUD: u32 = 115200;

// Limits
pub const MAX_SOCKETS: usize = 128;
pub const MAX_FIREWALL_RULES: usize = 256;
pub const MAX_BLACKLIST_ENTRIES: usize = 512;
pub const MAX_RATE_ENTRIES: usize = 512;
pub const MAX_SCAN_TRACKERS: usize = 64;

// Panic
pub const PanicMode = enum {
    halt,
    reboot,
    debug,
};

pub const PANIC_MODE: PanicMode = switch (PROFILE) {
    .production => .reboot,
    .development => .halt,
    .testing => .debug,
};

pub const PANIC_DUMP_REGISTERS: bool = switch (PROFILE) {
    .production => false,
    .development => true,
    .testing => true,
};

pub const PANIC_DUMP_STACK: bool = switch (PROFILE) {
    .production => false,
    .development => true,
    .testing => true,
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if we should log at a given level
pub fn shouldLog(level: LogLevel) bool {
    return @intFromEnum(level) >= @intFromEnum(LOG_LEVEL);
}

/// Get a human-readable config summary
pub fn printConfigSummary() void {
    const serial = @import("drivers/serial/serial.zig");

    serial.writeString("\n[CONFIG] Profile: ");
    serial.writeString(getProfileString());
    serial.writeString("\n");

    serial.writeString("[CONFIG] Mode: ");
    serial.writeString(getBuildMode());
    serial.writeString("\n");

    serial.writeString("[CONFIG] Version: ");
    serial.writeString(version);
    serial.writeString("\n");

    serial.writeString("[CONFIG] Security: ");
    if (P2P_ONLY_MODE) serial.writeString("P2P-ONLY ");
    if (STEALTH_MODE) serial.writeString("STEALTH ");
    if (FIREWALL_ENFORCING) serial.writeString("FW-ON ");
    serial.writeString("\n");

    serial.writeString("[CONFIG] Debug: ");
    if (VERBOSE_BOOT) serial.writeString("VERBOSE ");
    if (SERIAL_DEBUG) serial.writeString("SERIAL ");
    if (HEAP_DEBUG) serial.writeString("HEAP ");
    if (NETWORK_DEBUG) serial.writeString("NET ");
    serial.writeString("\n");
}
