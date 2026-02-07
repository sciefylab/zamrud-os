//! Zamrud OS - Boot Verification
//! Verifies system integrity at boot time

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const measure = @import("measure.zig");
const policy = @import("policy.zig");

// =============================================================================
// Types
// =============================================================================

pub const VerifyError = enum {
    none,
    kernel_hash_mismatch,
    memory_layout_invalid,
    boot_params_invalid,
    critical_module_tampered,
    policy_violation,
};

pub const VerifyResult = struct {
    success: bool,
    error_code: VerifyError,
    kernel_hash: [32]u8,
    boot_time: u64,
    verified_at: u64,
    checks_passed: u8,
    checks_total: u8,
    kernel_hash_ok: bool,
    memory_ok: bool,
    cpu_ok: bool,
    security_ok: bool,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var last_result: VerifyResult = .{
    .success = false,
    .error_code = .none,
    .kernel_hash = [_]u8{0} ** 32,
    .boot_time = 0,
    .verified_at = 0,
    .checks_passed = 0,
    .checks_total = 0,
    .kernel_hash_ok = false,
    .memory_ok = false,
    .cpu_ok = false,
    .security_ok = false,
};

var trusted_kernel_hash: [32]u8 = [_]u8{0} ** 32;
var trust_on_first_boot: bool = true;

// =============================================================================
// Public API
// =============================================================================

pub fn init() void {
    serial.writeString("[BOOT_VERIFY] Initializing...\n");

    initialized = false;
    trust_on_first_boot = true;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        trusted_kernel_hash[i] = 0;
        last_result.kernel_hash[i] = 0;
    }

    last_result.success = false;
    last_result.error_code = .none;
    last_result.verified_at = 0;
    last_result.checks_passed = 0;
    last_result.checks_total = 0;
    last_result.kernel_hash_ok = false;
    last_result.memory_ok = false;
    last_result.cpu_ok = false;
    last_result.security_ok = false;

    initialized = true;
    serial.writeString("[BOOT_VERIFY] Initialized\n");
}

pub fn verify() VerifyResult {
    serial.writeString("[BOOT_VERIFY] Starting verification...\n");

    var result = VerifyResult{
        .success = true,
        .error_code = .none,
        .kernel_hash = [_]u8{0} ** 32,
        .boot_time = 0,
        .verified_at = 0,
        .checks_passed = 0,
        .checks_total = 5,
        .kernel_hash_ok = false,
        .memory_ok = false,
        .cpu_ok = false,
        .security_ok = false,
    };

    // Check 1: Measure kernel
    serial.writeString("[BOOT_VERIFY] Check 1/5: Measuring kernel...\n");
    if (measure.measureKernel(&result.kernel_hash)) {
        result.checks_passed += 1;
        result.kernel_hash_ok = true;
    } else {
        result.success = false;
        result.error_code = .kernel_hash_mismatch;
        result.kernel_hash_ok = false;
    }

    // Check 2: Verify kernel hash
    serial.writeString("[BOOT_VERIFY] Check 2/5: Verifying kernel hash...\n");
    if (verifyKernelHash(&result.kernel_hash)) {
        result.checks_passed += 1;
    } else if (trust_on_first_boot) {
        result.checks_passed += 1;
        storeKernelHash(&result.kernel_hash);
    } else {
        result.success = false;
        result.error_code = .kernel_hash_mismatch;
        result.kernel_hash_ok = false;
    }

    // Check 3: Validate memory layout
    serial.writeString("[BOOT_VERIFY] Check 3/5: Validating memory layout...\n");
    if (measure.validateMemoryLayout()) {
        result.checks_passed += 1;
        result.memory_ok = true;
    } else {
        result.success = false;
        result.error_code = .memory_layout_invalid;
        result.memory_ok = false;
    }

    // Check 4: Check boot parameters (CPU)
    serial.writeString("[BOOT_VERIFY] Check 4/5: Checking boot parameters...\n");
    if (measure.validateBootParams()) {
        result.checks_passed += 1;
        result.cpu_ok = true;
    } else {
        result.success = false;
        result.error_code = .boot_params_invalid;
        result.cpu_ok = false;
    }

    // Check 5: Verify security policy
    serial.writeString("[BOOT_VERIFY] Check 5/5: Checking security policy...\n");
    if (policy.check()) {
        result.checks_passed += 1;
        result.security_ok = true;
    } else {
        result.success = false;
        result.error_code = .policy_violation;
        result.security_ok = false;
    }

    // Set verified_at (simple counter for now)
    result.verified_at = result.checks_passed;

    last_result = result;

    if (result.success) {
        serial.writeString("[BOOT_VERIFY] Verification PASSED\n");
    } else {
        serial.writeString("[BOOT_VERIFY] Verification FAILED!\n");
    }

    return result;
}

pub fn quickVerify() bool {
    if (!initialized) return false;

    var current_hash: [32]u8 = [_]u8{0} ** 32;
    if (!measure.measureKernel(&current_hash)) return false;

    return verifyKernelHash(&current_hash);
}

pub fn getLastResult() *const VerifyResult {
    return &last_result;
}

pub fn isVerified() bool {
    return initialized and last_result.success;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn getKernelHash() *const [32]u8 {
    return &last_result.kernel_hash;
}

pub fn getTrustedHash() *const [32]u8 {
    return &trusted_kernel_hash;
}

// =============================================================================
// Internal Functions
// =============================================================================

fn verifyKernelHash(current: *const [32]u8) bool {
    var has_trusted = false;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (trusted_kernel_hash[i] != 0) {
            has_trusted = true;
            break;
        }
    }

    if (!has_trusted) {
        return false;
    }

    return hash.hashEqual(&trusted_kernel_hash, current);
}

fn storeKernelHash(h: *const [32]u8) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        trusted_kernel_hash[i] = h[i];
    }
    trust_on_first_boot = false;
}

// =============================================================================
// Test
// =============================================================================

pub fn test_verify() bool {
    serial.writeString("\n=== Boot Verify Test ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  Test 1: Initialize\n");
    init();
    if (initialized) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 2: First boot verify\n");
    const result = verify();
    if (result.success) {
        passed += 1;
    } else {
        failed += 1;
    }

    serial.writeString("  Test 3: isVerified\n");
    if (isVerified()) {
        passed += 1;
    } else {
        failed += 1;
    }

    return failed == 0;
}
