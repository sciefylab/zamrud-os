//! Zamrud OS - Name Service (ZNS)
//! Blockchain-based name registration and lookup

const serial = @import("../drivers/serial/serial.zig");
const keyring = @import("keyring.zig");

// =============================================================================
// Constants
// =============================================================================

pub const MAX_REGISTERED_NAMES: usize = 32;

// Reserved names that cannot be registered
const RESERVED_NAMES = [_][]const u8{
    "admin",
    "root",
    "system",
    "zamrud",
    "official",
    "support",
    "help",
};

// =============================================================================
// Types
// =============================================================================

pub const NameEntry = struct {
    name: [32]u8,
    name_len: u8,
    address: [50]u8,
    address_len: u8,
    registered_at: u32,
    active: bool,
};

// =============================================================================
// State
// =============================================================================

var name_registry: [MAX_REGISTERED_NAMES]NameEntry = undefined;
var name_count: usize = 0;
var initialized: bool = false;

// =============================================================================
// Functions
// =============================================================================

pub fn init() void {
    serial.writeString("[NAMES] Initializing...\n");

    var i: usize = 0;
    while (i < MAX_REGISTERED_NAMES) : (i += 1) {
        name_registry[i].name_len = 0;
        name_registry[i].address_len = 0;
        name_registry[i].registered_at = 0;
        name_registry[i].active = false;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            name_registry[i].name[j] = 0;
        }
        j = 0;
        while (j < 50) : (j += 1) {
            name_registry[i].address[j] = 0;
        }
    }

    name_count = 0;
    initialized = true;
    serial.writeString("[NAMES] Initialized\n");
}

/// Check if name is available for registration
pub fn isAvailable(name: []const u8) bool {
    // Check reserved names
    if (isReserved(name)) return false;

    // Check if already registered
    if (lookup(name) != null) return false;

    return true;
}

/// Check if name is reserved
fn isReserved(name: []const u8) bool {
    // Strip @ prefix if present
    var check_name = name;
    if (name.len > 0 and name[0] == '@') {
        check_name = name[1..];
    }

    for (RESERVED_NAMES) |reserved| {
        if (stringsEqual(check_name, reserved)) return true;
    }
    return false;
}

fn stringsEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

/// Register name for current identity
pub fn registerName(name: []const u8) bool {
    if (!initialized) return false;
    if (name_count >= MAX_REGISTERED_NAMES) return false;
    if (!isAvailable(name)) return false;

    const current = keyring.getCurrentIdentity();
    if (current == null) return false;
    if (!current.?.unlocked) return false; // Must be unlocked to register

    var entry = &name_registry[name_count];

    // Copy name (with @ prefix)
    var dest: usize = 0;
    if (name.len > 0 and name[0] != '@') {
        entry.name[0] = '@';
        dest = 1;
    }
    var i: usize = 0;
    while (i < name.len and dest < 32) : (i += 1) {
        entry.name[dest] = name[i];
        dest += 1;
    }
    entry.name_len = @intCast(dest);

    // Copy address
    const addr = current.?.getAddress();
    i = 0;
    while (i < addr.len and i < 50) : (i += 1) {
        entry.address[i] = addr[i];
    }
    entry.address_len = @intCast(i);

    entry.registered_at = 1700000000; // TODO: real timestamp
    entry.active = true;

    // Update identity to have this name
    current.?.has_name = true;
    i = 0;
    while (i < entry.name_len and i < 32) : (i += 1) {
        current.?.name[i] = entry.name[i];
    }
    current.?.name_len = entry.name_len;

    name_count += 1;

    return true;
}

/// Lookup address by name
pub fn lookup(name: []const u8) ?*const [50]u8 {
    var i: usize = 0;
    while (i < name_count) : (i += 1) {
        if (!name_registry[i].active) continue;

        const entry_name = name_registry[i].name[0..name_registry[i].name_len];
        if (namesMatch(entry_name, name)) {
            return &name_registry[i].address;
        }
    }
    return null;
}

fn namesMatch(a: []const u8, b: []const u8) bool {
    var a_start: usize = 0;
    var b_start: usize = 0;

    if (a.len > 0 and a[0] == '@') a_start = 1;
    if (b.len > 0 and b[0] == '@') b_start = 1;

    const a_name = a[a_start..];
    const b_name = b[b_start..];

    if (a_name.len != b_name.len) return false;

    var i: usize = 0;
    while (i < a_name.len) : (i += 1) {
        if (a_name[i] != b_name[i]) return false;
    }
    return true;
}

/// Get registered name count
pub fn getNameCount() usize {
    return name_count;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_names() bool {
    serial.writeString("[NAMES] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Setup: create and unlock identity
    keyring.init();
    _ = keyring.createIdentity("testuser", "1234");
    const auth = @import("auth.zig");
    auth.init();
    _ = auth.unlock("testuser", "1234");

    // Test 1: Init
    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized and name_count == 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Reserved names blocked
    serial.writeString("  Test 2: Reserved blocked\n");
    if (!isAvailable("admin") and !isAvailable("@root")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Register name
    serial.writeString("  Test 3: Register name\n");
    if (registerName("budi_hutan")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Lookup registered name
    serial.writeString("  Test 4: Lookup name\n");
    const addr = lookup("@budi_hutan");
    if (addr != null) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Duplicate blocked
    serial.writeString("  Test 5: Duplicate blocked\n");
    if (!isAvailable("budi_hutan")) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  NAMES: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = [_]u8{0} ** 10;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
