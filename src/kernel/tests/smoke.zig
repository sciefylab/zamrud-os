//! Zamrud OS - Quick Smoke Tests
//! Minimal validation for critical subsystems at boot
//! Designed to run in <500ms with minimal impact on boot time

const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const crypto = @import("../crypto/crypto.zig");
const firewall = @import("../net/firewall.zig");
const gateway = @import("../gateway/gateway.zig");
const vfs = @import("../fs/vfs.zig");
const process = @import("../proc/process.zig");
const heap = @import("../mm/heap.zig");

// =============================================================================
// Test Results Tracking
// =============================================================================

var tests_run: u32 = 0;
var tests_passed: u32 = 0;
var tests_failed: u32 = 0;

// =============================================================================
// Main Entry Point - Smoke Tests
// =============================================================================

pub fn runSmokeTests() void {
    const start_time = timer.getTicks();

    // Reset counters
    tests_run = 0;
    tests_passed = 0;
    tests_failed = 0;

    serial.writeString("\n");
    serial.writeString("+-------------------------------------+\n");
    serial.writeString("|   SMOKE TEST - Quick Validation    |\n");
    serial.writeString("+-------------------------------------+\n");

    // Run individual smoke tests
    testCrypto();
    testMemory();
    testFirewall();
    testFilesystem();
    testProcess();
    testGateway();

    // Calculate elapsed time
    const end_time = timer.getTicks();
    const elapsed_ms = if (end_time > start_time) (end_time - start_time) else 0;

    // Print summary
    serial.writeString("+-------------------------------------+\n");

    if (tests_failed == 0) {
        serial.writeString("| [OK] ALL TESTS PASSED              |\n");
    } else {
        serial.writeString("| [!!] SOME TESTS FAILED             |\n");
    }

    serial.writeString("| Tests: ");
    printNumber(tests_passed);
    serial.writeString("/");
    printNumber(tests_run);
    serial.writeString(" passed                  |\n");

    serial.writeString("| Time:  ");
    printNumber(elapsed_ms);
    serial.writeString(" ms                       |\n");

    serial.writeString("+-------------------------------------+\n");
    serial.writeString("\n");

    // If any test failed, print warning
    if (tests_failed > 0) {
        serial.writeString("[WARN] System may be unstable!\n");
        serial.writeString("[WARN] Run 'testall' for diagnostics\n\n");
    }
}

// =============================================================================
// Individual Smoke Tests
// =============================================================================

fn testCrypto() void {
    tests_run += 1;
    serial.writeString("| Crypto              : ");

    var passed = true;

    // Test 1: SHA256 known vector
    const test_data = "test";
    const hash = crypto.sha256(test_data);

    // Known SHA256 hash for "test" starts with 0x9f, 0x86, 0xd0
    if (hash[0] != 0x9f or hash[1] != 0x86 or hash[2] != 0xd0) {
        passed = false;
    }

    // Test 2: Random number generation
    if (passed) {
        const rand1 = crypto.random.getU32();
        const rand2 = crypto.random.getU32();

        // Should not be equal (with very high probability)
        if (rand1 == rand2 and rand1 == 0) {
            passed = false;
        }
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

fn testMemory() void {
    tests_run += 1;
    serial.writeString("| Memory              : ");

    var passed = true;

    // Test heap allocation using kmalloc
    const ptr = heap.kmalloc(256);
    if (ptr == null) {
        passed = false;
    } else {
        // Write simple test pattern
        const bytes = ptr.?;
        const test_pattern: u8 = 0xAA;

        // Write pattern
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            bytes[i] = test_pattern;
        }

        // Verify pattern
        i = 0;
        while (i < 256) : (i += 1) {
            if (bytes[i] != test_pattern) {
                passed = false;
                break;
            }
        }

        // Free memory using kfree
        heap.kfree(ptr.?);
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

fn testFirewall() void {
    tests_run += 1;
    serial.writeString("| Firewall            : ");

    var passed = true;

    // Test 1: Firewall is initialized
    if (!firewall.isInitialized()) {
        passed = false;
    }

    // Test 2: Has default rules (at least 5)
    if (passed) {
        if (firewall.getRuleCount() < 5) {
            passed = false;
        }
    }

    // Test 3: Config is accessible (public var)
    if (passed) {
        const cfg = firewall.config;
        _ = cfg.stealth_mode;
        _ = cfg.p2p_only_mode;
    }

    // Test 4: State is valid (public var)
    if (passed) {
        const current_state = firewall.state;
        if (current_state != .enforcing and
            current_state != .permissive and
            current_state != .disabled and
            current_state != .lockdown)
        {
            passed = false;
        }
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

fn testFilesystem() void {
    tests_run += 1;
    serial.writeString("| Filesystem          : ");

    var passed = true;

    // Test 1: Can resolve root path
    const root_inode = vfs.resolvePath("/");
    if (root_inode == null) {
        passed = false;
    }

    // Test 2: Root should be a directory
    if (passed) {
        if (root_inode) |inode| {
            if (inode.file_type != .Directory) {
                passed = false;
            }
        }
    }

    // Test 3: Can check if /dev exists
    if (passed) {
        if (!vfs.exists("/dev")) {
            passed = false;
        }
    }

    // Test 4: /dev/null should exist
    if (passed) {
        if (!vfs.exists("/dev/null")) {
            passed = false;
        }
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

fn testProcess() void {
    tests_run += 1;
    serial.writeString("| Process             : ");

    var passed = true;

    // Test 1: Process manager initialized
    if (!process.isInitialized()) {
        passed = false;
    }

    // Test 2: Can get process count
    if (passed) {
        const count = process.getCount();
        _ = count;
    }

    // Test 3: Can get current PID
    if (passed) {
        const pid = process.getCurrentPid();
        _ = pid;
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

fn testGateway() void {
    tests_run += 1;
    serial.writeString("| Gateway             : ");

    var passed = true;

    // Test 1: Gateway initialized
    if (!gateway.isInitialized()) {
        passed = false;
    }

    // Test 2: Has valid node ID (not all zeros)
    if (passed) {
        const node_id = gateway.getGatewayId();
        var all_zero = true;
        for (node_id) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            passed = false;
        }
    }

    // Test 3: Can get stats without crash
    if (passed) {
        const gw_stats = gateway.getStats();
        _ = gw_stats.state;
    }

    if (passed) {
        serial.writeString("PASS    |\n");
        tests_passed += 1;
    } else {
        serial.writeString("FAIL    |\n");
        tests_failed += 1;
    }
}

// =============================================================================
// Full Test Suite (via shell command 'test all')
// =============================================================================

pub fn runFullTests() void {
    serial.writeString("\n");
    serial.writeString("+=========================================+\n");
    serial.writeString("|      FULL TEST SUITE - All Tests        |\n");
    serial.writeString("+=========================================+\n");
    serial.writeString("\n");

    // Step 1: Run smoke tests first
    serial.writeString("[1/4] Running smoke tests...\n");
    runSmokeTests();

    // Step 2: Crypto full test
    serial.writeString("[2/4] Running crypto tests...\n");
    if (crypto.random.test_random()) {
        serial.writeString("  Crypto: PASS\n");
    } else {
        serial.writeString("  Crypto: FAIL\n");
    }

    // Step 3: Heap test
    serial.writeString("[3/4] Running heap tests...\n");
    heap.test_heap();

    // Step 4: Gateway status
    serial.writeString("[4/4] Running gateway tests...\n");
    gateway.printStatus();

    serial.writeString("\n");
    serial.writeString("+=========================================+\n");
    serial.writeString("|       Full test suite completed         |\n");
    serial.writeString("+=========================================+\n");
    serial.writeString("\n");
}

// =============================================================================
// Get Test Results
// =============================================================================

pub fn getTestsPassed() u32 {
    return tests_passed;
}

pub fn getTestsFailed() u32 {
    return tests_failed;
}

pub fn getTestsRun() u32 {
    return tests_run;
}

pub fn allTestsPassed() bool {
    return tests_failed == 0 and tests_run > 0;
}

// =============================================================================
// Utilities
// =============================================================================

fn printNumber(n: anytype) void {
    const val: u64 = @intCast(n);
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
