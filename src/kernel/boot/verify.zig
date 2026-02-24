//! Zamrud OS - Boot Verification (H.5 Enhanced)
//! Verifies system integrity at boot time
//! H.5: PCR chain verification, CT comparison, runtime re-measurement

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const ct = @import("../crypto/constant_time.zig");
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
    chain_incomplete,
    runtime_tamper_detected,
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
    chain_ok: bool, // H.5: boot chain measured
    chain_verified: bool, // H.5: chain integrity verified
};

pub const TamperStatus = struct {
    text_ok: bool,
    rodata_ok: bool,
    checked: bool,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var last_result: VerifyResult = makeEmptyResult();
var trusted_kernel_hash: [32]u8 = [_]u8{0} ** 32;
var trust_on_first_boot: bool = true;

// H.5: Tamper detection state
var last_tamper: TamperStatus = .{
    .text_ok = false,
    .rodata_ok = false,
    .checked = false,
};

// Temporary hash buffers for verification
var verify_tmp_hash: [32]u8 = [_]u8{0} ** 32;

fn makeEmptyResult() VerifyResult {
    return VerifyResult{
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
        .chain_ok = false,
        .chain_verified = false,
    };
}

// =============================================================================
// Public API
// =============================================================================

pub fn init() void {
    serial.writeString("[BOOT_VERIFY] Initializing...\n");

    initialized = false;
    trust_on_first_boot = true;

    ct.secureZero32(&trusted_kernel_hash);
    last_result = makeEmptyResult();
    last_tamper = .{ .text_ok = false, .rodata_ok = false, .checked = false };

    initialized = true;
    serial.writeString("[BOOT_VERIFY] Initialized\n");
}

pub fn verify() VerifyResult {
    serial.writeString("[BOOT_VERIFY] Starting verification...\n");

    var result = makeEmptyResult();
    result.success = true;
    result.checks_total = 7; // H.5: 5 original + 2 new

    // Check 1: Measure kernel
    serial.writeString("[BOOT_VERIFY] Check 1/7: Measuring kernel...\n");
    if (measure.measureKernel(&result.kernel_hash)) {
        result.checks_passed += 1;
        result.kernel_hash_ok = true;
    } else {
        result.success = false;
        result.error_code = .kernel_hash_mismatch;
        result.kernel_hash_ok = false;
    }

    // Check 2: Verify kernel hash (using constant-time comparison)
    serial.writeString("[BOOT_VERIFY] Check 2/7: Verifying kernel hash...\n");
    if (verifyKernelHash(&result.kernel_hash)) {
        result.checks_passed += 1;
    } else if (trust_on_first_boot) {
        result.checks_passed += 1;
        storeKernelHash(&result.kernel_hash);
        serial.writeString("[BOOT_VERIFY] First boot — trusted hash stored\n");
    } else {
        result.success = false;
        result.error_code = .kernel_hash_mismatch;
        result.kernel_hash_ok = false;
    }

    // Check 3: Validate memory layout
    serial.writeString("[BOOT_VERIFY] Check 3/7: Validating memory layout...\n");
    if (measure.validateMemoryLayout()) {
        result.checks_passed += 1;
        result.memory_ok = true;
    } else {
        result.success = false;
        result.error_code = .memory_layout_invalid;
        result.memory_ok = false;
    }

    // Check 4: Check boot parameters
    serial.writeString("[BOOT_VERIFY] Check 4/7: Checking boot parameters...\n");
    if (measure.validateBootParams()) {
        result.checks_passed += 1;
        result.cpu_ok = true;
    } else {
        result.success = false;
        result.error_code = .boot_params_invalid;
        result.cpu_ok = false;
    }

    // Check 5: Verify security policy
    serial.writeString("[BOOT_VERIFY] Check 5/7: Checking security policy...\n");
    if (policy.check()) {
        result.checks_passed += 1;
        result.security_ok = true;
    } else {
        result.success = false;
        result.error_code = .policy_violation;
        result.security_ok = false;
    }

    // Check 6 (H.5): Run boot measurement chain
    serial.writeString("[BOOT_VERIFY] Check 6/7: Boot measurement chain...\n");
    if (measure.runBootChain()) {
        result.checks_passed += 1;
        result.chain_ok = true;
    } else {
        // Chain failure is a warning in standard mode, error in strict+
        const level = policy.getLevel();
        if (level == .strict or level == .paranoid) {
            result.success = false;
            result.error_code = .chain_incomplete;
        }
        result.chain_ok = false;
    }

    // Check 7 (H.5): Verify chain integrity
    serial.writeString("[BOOT_VERIFY] Check 7/7: Chain integrity verification...\n");
    if (verifyChainIntegrity()) {
        result.checks_passed += 1;
        result.chain_verified = true;
    } else {
        const level = policy.getLevel();
        if (level == .strict or level == .paranoid) {
            result.success = false;
        }
        result.chain_verified = false;
    }

    result.verified_at = result.checks_passed;
    last_result = result;

    if (result.success) {
        serial.writeString("[BOOT_VERIFY] Verification PASSED (");
        printDecSerial(result.checks_passed);
        serial.writeString("/");
        printDecSerial(result.checks_total);
        serial.writeString(")\n");
    } else {
        serial.writeString("[BOOT_VERIFY] Verification FAILED!\n");
    }

    return result;
}

/// Quick verification (kernel hash only, using CT compare)
pub fn quickVerify() bool {
    if (!initialized) return false;

    if (!measure.measureKernel(&verify_tmp_hash)) return false;
    const result = ct.constantTimeCompare32(&verify_tmp_hash, &trusted_kernel_hash);
    ct.secureZero32(&verify_tmp_hash);
    return result;
}

// =============================================================================
// Runtime Re-measurement (H.5 — detect runtime tampering)
// =============================================================================

/// Re-measure .text and .rodata sections, compare with boot-time values
/// These sections should be IMMUTABLE — any change = tampering
pub fn runtimeVerify() TamperStatus {
    var status = TamperStatus{
        .text_ok = false,
        .rodata_ok = false,
        .checked = true,
    };

    if (!measure.hasBootHashes()) {
        serial.writeString("[VERIFY] No boot hashes stored — skipping\n");
        status.checked = false;
        last_tamper = status;
        return status;
    }

    // Re-measure .text
    if (measure.measureTextSection(&verify_tmp_hash)) {
        status.text_ok = ct.constantTimeCompare32(
            &verify_tmp_hash,
            measure.getBootTextHash(),
        );
        if (!status.text_ok) {
            serial.writeString("[VERIFY] TAMPER: .text section MODIFIED!\n");
        }
    }

    // Re-measure .rodata
    if (measure.measureRodataSection(&verify_tmp_hash)) {
        status.rodata_ok = ct.constantTimeCompare32(
            &verify_tmp_hash,
            measure.getBootRodataHash(),
        );
        if (!status.rodata_ok) {
            serial.writeString("[VERIFY] TAMPER: .rodata section MODIFIED!\n");
        }
    }

    ct.secureZero32(&verify_tmp_hash);
    last_tamper = status;
    return status;
}

/// Check if tampering has been detected
pub fn isTampered() bool {
    if (!last_tamper.checked) return false;
    return !last_tamper.text_ok or !last_tamper.rodata_ok;
}

/// Get last tamper check status
pub fn getTamperStatus() TamperStatus {
    return last_tamper;
}

// =============================================================================
// Accessors
// =============================================================================

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

/// Constant-time kernel hash verification (H.5: uses CT module)
fn verifyKernelHash(current: *const [32]u8) bool {
    // Check if we have a trusted hash stored
    if (ct.constantTimeIsZero32(&trusted_kernel_hash)) {
        return false; // No trusted hash yet
    }

    return ct.constantTimeCompare32(&trusted_kernel_hash, current);
}

fn storeKernelHash(h: *const [32]u8) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        trusted_kernel_hash[i] = h[i];
    }
    trust_on_first_boot = false;
}

/// Verify boot chain integrity
fn verifyChainIntegrity() bool {
    // Check 1: Chain must be complete
    if (!measure.isChainComplete()) return false;

    // Check 2: Critical PCRs must be extended
    if (!measure.isPcrExtended(measure.PCR_TEXT)) return false;
    if (!measure.isPcrExtended(measure.PCR_RODATA)) return false;
    if (!measure.isPcrExtended(measure.PCR_KERNEL)) return false;
    if (!measure.isPcrExtended(measure.PCR_AGGREGATE)) return false;

    // Check 3: PCR values must not be zero (would indicate failed measurement)
    const agg = measure.getPcr(measure.PCR_AGGREGATE);
    if (agg) |pcr_val| {
        if (ct.constantTimeIsZero32(pcr_val)) return false;
    } else {
        return false;
    }

    // Check 4: Event log should have entries
    if (measure.getEventCount() == 0) return false;

    return true;
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

fn printDecSerial(val: u64) void {
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
