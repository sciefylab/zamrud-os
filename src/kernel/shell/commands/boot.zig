//! Zamrud OS - Boot Commands (H.5 Enhanced)
//! Boot verification, PCR display, event log, runtime re-measurement
//! H.5: Added pcr, events, remeasure, test subcommands (25 tests)

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const boot_verify = @import("../../boot/verify.zig");
const policy_mod = @import("../../boot/policy.zig");
const measure = @import("../../boot/measure.zig");
const hash = @import("../../crypto/hash.zig");
const ct = @import("../../crypto/constant_time.zig");

// =============================================================================
// Command Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const trimmed = helpers.trim(args);

    var end: usize = 0;
    while (end < trimmed.len and trimmed[end] != ' ') {
        end += 1;
    }

    const subcommand = if (end > 0) trimmed[0..end] else "";
    var subargs_start = end;
    while (subargs_start < trimmed.len and trimmed[subargs_start] == ' ') {
        subargs_start += 1;
    }
    const subargs = if (subargs_start < trimmed.len) trimmed[subargs_start..] else "";

    if (subcommand.len == 0 or helpers.strEql(subcommand, "help")) {
        showHelp();
    } else if (helpers.strEql(subcommand, "status")) {
        showStatus();
    } else if (helpers.strEql(subcommand, "verify")) {
        runVerify();
    } else if (helpers.strEql(subcommand, "hash")) {
        showHash();
    } else if (helpers.strEql(subcommand, "policy")) {
        showPolicy();
    } else if (helpers.strEql(subcommand, "set-policy")) {
        setPolicy(subargs);
    } else if (helpers.strEql(subcommand, "trusted")) {
        showTrusted();
    } else if (helpers.strEql(subcommand, "violations")) {
        showViolations();
    } else if (helpers.strEql(subcommand, "pcr")) {
        showPcr();
    } else if (helpers.strEql(subcommand, "events")) {
        showEvents();
    } else if (helpers.strEql(subcommand, "remeasure")) {
        runRemeasure();
    } else if (helpers.strEql(subcommand, "test")) {
        runBootTests();
    } else {
        shell.printError("boot: unknown subcommand '");
        shell.print(subcommand);
        shell.println("'");
        shell.println("  Type 'boot help' for usage");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BOOT - Boot Integrity System (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: boot <subcommand> [args]");
    shell.newLine();

    shell.println("Subcommands:");
    shell.println("  help           Show this help");
    shell.println("  status         Show boot verification status");
    shell.println("  verify         Re-run boot verification");
    shell.println("  hash           Show kernel hash details");
    shell.println("  policy         Show current security policy");
    shell.println("  set-policy <l> Set security policy level");
    shell.println("  trusted        Show trusted hashes");
    shell.println("  violations     Show policy violations");
    shell.println("  pcr            Show PCR measurement values");
    shell.println("  events         Show boot event log");
    shell.println("  remeasure      Runtime re-measurement");
    shell.println("  test           Run H.5 test suite (25)");
    shell.newLine();

    shell.println("Security Policy Levels:");
    shell.println("  permissive  standard  strict  paranoid");
    shell.newLine();
}

// =============================================================================
// Status
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BOOT VERIFICATION STATUS (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Boot Verified:     ");
    if (boot_verify.isVerified()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }

    const result = boot_verify.getLastResult();

    shell.print("  Checks Passed:     ");
    helpers.printU32(@intCast(result.checks_passed));
    shell.print("/");
    helpers.printU32(@intCast(result.checks_total));
    if (result.checks_passed == result.checks_total) {
        shell.printSuccessLine(" ALL PASS");
    } else {
        shell.printErrorLine(" (some failed)");
    }

    shell.print("  Security Policy:   ");
    shell.println(policy_mod.getLevelName(policy_mod.getLevel()));

    shell.print("  Policy Violations: ");
    const violations = policy_mod.getViolationCount();
    if (violations == 0) {
        shell.printSuccessLine("0");
    } else {
        helpers.printU32(violations);
        shell.printErrorLine(" detected");
    }

    // H.5: Chain status
    const chain = measure.getChainStatus();

    shell.print("  Boot Chain:        ");
    if (chain.complete) {
        shell.printSuccessLine("COMPLETE");
    } else {
        shell.printWarningLine("INCOMPLETE");
    }

    shell.print("  Chain Sealed:      ");
    if (chain.sealed) {
        shell.printSuccessLine("YES");
    } else {
        shell.println("No");
    }

    shell.print("  PCRs Extended:     ");
    helpers.printU32(@intCast(chain.pcrs_extended));
    shell.print("/");
    helpers.printU32(measure.NUM_PCRS);
    shell.newLine();

    shell.print("  Event Log:         ");
    helpers.printU32(@intCast(chain.event_count));
    shell.println(" entries");

    // Kernel hash (abbreviated)
    shell.print("  Kernel Hash:       ");
    const h = boot_verify.getKernelHash();
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        helpers.printHexByte(h[i]);
    }
    shell.println("...");

    shell.newLine();

    if (result.success and violations == 0 and chain.complete) {
        shell.printSuccessLine("  System integrity: FULLY VERIFIED");
    } else if (result.success) {
        shell.printWarningLine("  System integrity: VERIFIED (with warnings)");
    } else {
        shell.printErrorLine("  System integrity: UNVERIFIED");
    }
    shell.newLine();
}

// =============================================================================
// Verify (enhanced for H.5)
// =============================================================================

fn runVerify() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  RUNNING BOOT VERIFICATION (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    const result = boot_verify.verify();

    shell.println("  Verification Results:");
    shell.println("  ----------------------------------------");

    shell.print("    Kernel hash:        ");
    printCheckResult(result.kernel_hash_ok);

    shell.print("    Memory layout:      ");
    printCheckResult(result.memory_ok);

    shell.print("    CPU features:       ");
    printCheckResult(result.cpu_ok);

    shell.print("    Security config:    ");
    printCheckResult(result.security_ok);

    shell.print("    Boot chain (H.5):   ");
    printCheckResult(result.chain_ok);

    shell.print("    Chain verify (H.5): ");
    printCheckResult(result.chain_verified);

    shell.println("  ----------------------------------------");
    shell.print("  Total: ");
    helpers.printU32(@intCast(result.checks_passed));
    shell.print("/");
    helpers.printU32(@intCast(result.checks_total));
    shell.println(" checks passed");
    shell.newLine();

    if (result.success) {
        shell.printSuccessLine("  Boot verification: PASSED");
    } else {
        shell.printErrorLine("  Boot verification: FAILED");
        shell.println("  WARNING: System may have been tampered with!");
    }
    shell.newLine();
}

fn printCheckResult(ok: bool) void {
    if (ok) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
    }
}

// =============================================================================
// Hash Display
// =============================================================================

fn showHash() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  KERNEL HASH INFORMATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Algorithm: SHA-256");
    shell.println("  Comparison: Constant-time (H.1)");
    shell.newLine();

    shell.println("  Current Kernel Hash:");
    shell.print("    ");
    const h = boot_verify.getKernelHash();
    printFullHash(h);
    shell.newLine();

    shell.println("  Trusted Hash:");
    shell.print("    ");
    const trusted = boot_verify.getTrustedHash();
    printFullHash(trusted);
    shell.newLine();

    shell.print("  Match: ");
    if (ct.constantTimeCompare32(h, trusted)) {
        shell.printSuccessLine("YES - Kernel is authentic");
    } else {
        shell.printErrorLine("NO - Hash mismatch!");
    }
    shell.newLine();
}

fn printFullHash(h: *const [32]u8) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        helpers.printHexByte(h[i]);
        if (i == 15) {
            shell.newLine();
            shell.print("    ");
        }
    }
    shell.newLine();
}

// =============================================================================
// PCR Display (H.5)
// =============================================================================

fn showPcr() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  PCR MEASUREMENT REGISTERS (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  PCR = SHA256(PCR_old || measurement)");
    shell.println("  Like TPM PCRs - tamper-evident chain");
    shell.newLine();

    var i: usize = 0;
    while (i < measure.NUM_PCRS) : (i += 1) {
        shell.print("  PCR[");
        helpers.printU32(@intCast(i));
        shell.print("] ");

        // Right-pad name
        const name = measure.getPcrName(i);
        shell.print(name);
        var pad: usize = 0;
        while (pad + name.len < 10) : (pad += 1) {
            shell.print(" ");
        }

        if (measure.isPcrExtended(i)) {
            const pcr = measure.getPcr(i).?;
            var j: usize = 0;
            while (j < 16) : (j += 1) {
                helpers.printHexByte(pcr[j]);
            }
            shell.print("... (x");
            helpers.printU32(@intCast(measure.getPcrExtendCount(i)));
            shell.println(")");
        } else {
            shell.println("<not extended>");
        }
    }

    shell.newLine();
    shell.print("  Extended: ");
    helpers.printU32(@intCast(measure.getExtendedPcrCount()));
    shell.print("/");
    helpers.printU32(measure.NUM_PCRS);
    shell.newLine();
    shell.newLine();
}

// =============================================================================
// Event Log Display (H.5)
// =============================================================================

fn showEvents() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BOOT EVENT LOG (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    const count = measure.getEventCount();

    shell.print("  Total Events: ");
    helpers.printU32(@intCast(count));
    shell.newLine();
    shell.newLine();

    if (count == 0) {
        shell.println("  No events recorded.");
        shell.println("  Run 'boot verify' to populate.");
        shell.newLine();
        return;
    }

    shell.println("  Seq  PCR  Description          Hash (first 8)");
    shell.println("  ---------------------------------------------");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (measure.getEvent(i)) |ev| {
            shell.print("  ");
            // Sequence
            if (ev.sequence < 10) shell.print(" ");
            helpers.printU32(@intCast(ev.sequence));
            shell.print("   ");

            // PCR index
            helpers.printU32(@intCast(ev.pcr_index));
            shell.print("    ");

            // Description
            const desc = ev.getDesc();
            shell.print(desc);
            var pad: usize = 0;
            while (pad + desc.len < 20) : (pad += 1) {
                shell.print(" ");
            }
            shell.print(" ");

            // Hash (first 8 bytes)
            var j: usize = 0;
            while (j < 8) : (j += 1) {
                helpers.printHexByte(ev.measurement[j]);
            }
            shell.newLine();
        }
    }
    shell.newLine();
}

// =============================================================================
// Runtime Re-measurement (H.5)
// =============================================================================

fn runRemeasure() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  RUNTIME RE-MEASUREMENT (H.5)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Checking immutable sections for tampering...");
    shell.newLine();

    const status = boot_verify.runtimeVerify();

    if (!status.checked) {
        shell.printWarningLine("  No boot hashes available.");
        shell.println("  Run 'boot verify' first.");
        shell.newLine();
        return;
    }

    shell.print("    .text  section: ");
    if (status.text_ok) {
        shell.printSuccessLine("INTACT");
    } else {
        shell.printErrorLine("TAMPERED!");
    }

    shell.print("    .rodata section: ");
    if (status.rodata_ok) {
        shell.printSuccessLine("INTACT");
    } else {
        shell.printErrorLine("TAMPERED!");
    }

    shell.newLine();
    if (status.text_ok and status.rodata_ok) {
        shell.printSuccessLine("  Runtime integrity: OK");
    } else {
        shell.printErrorLine("  ALERT: Code tampering detected!");
        shell.println("  Kernel code or data has been modified.");
        shell.println("  Consider rebooting from trusted media.");
    }
    shell.newLine();
}

// =============================================================================
// Policy Display
// =============================================================================

fn showPolicy() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  SECURITY POLICY CONFIGURATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    const level = policy_mod.getLevel();
    const flags = policy_mod.getFlags();

    shell.print("  Current Level: ");
    shell.println(policy_mod.getLevelName(level));
    shell.newLine();

    shell.println("  Policy Flags:");
    printFlag("    Require kernel hash:     ", flags.require_kernel_hash);
    printFlag("    Require module hashes:   ", flags.require_module_hashes);
    printFlag("    Require boot chain (H.5):", flags.require_boot_chain);
    printFlag("    Memory isolation:        ", flags.require_memory_isolation);
    printFlag("    Stack protection:        ", flags.require_stack_protection);
    printFlag("    NX bit:                  ", flags.require_nx);
    printFlag("    Allow debug:             ", flags.allow_debug);
    printFlag("    Allow unsigned:          ", flags.allow_unsigned);
    shell.newLine();

    shell.print("  Violations: ");
    helpers.printU32(policy_mod.getViolationCount());
    shell.newLine();
    shell.newLine();
}

fn printFlag(label: []const u8, val: bool) void {
    shell.print(label);
    if (val) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }
}

fn setPolicy(args: []const u8) void {
    const level_str = helpers.trim(args);

    if (level_str.len == 0) {
        shell.printErrorLine("Usage: boot set-policy <level>");
        shell.println("  Levels: permissive, standard, strict, paranoid");
        return;
    }

    var new_level: policy_mod.SecurityLevel = undefined;
    var valid = false;

    if (helpers.strEql(level_str, "permissive")) {
        new_level = .permissive;
        valid = true;
    } else if (helpers.strEql(level_str, "standard")) {
        new_level = .standard;
        valid = true;
    } else if (helpers.strEql(level_str, "strict")) {
        new_level = .strict;
        valid = true;
    } else if (helpers.strEql(level_str, "paranoid")) {
        new_level = .paranoid;
        valid = true;
    }

    if (!valid) {
        shell.printError("Unknown level: '");
        shell.print(level_str);
        shell.println("'");
        return;
    }

    policy_mod.setLevel(new_level);
    shell.printSuccess("Policy set to: ");
    shell.println(level_str);
    shell.newLine();
}

fn showTrusted() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  TRUSTED BOOT COMPONENTS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Trusted Kernel Hash:");
    shell.print("    ");
    printFullHash(boot_verify.getTrustedHash());
    shell.newLine();

    if (measure.hasBootHashes()) {
        shell.println("  Boot-time Section Hashes:");
        shell.print("    .text:   ");
        const th = measure.getBootTextHash();
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            helpers.printHexByte(th[i]);
        }
        shell.println("...");

        shell.print("    .rodata: ");
        const rh = measure.getBootRodataHash();
        i = 0;
        while (i < 16) : (i += 1) {
            helpers.printHexByte(rh[i]);
        }
        shell.println("...");
    } else {
        shell.println("  No boot-time hashes stored.");
    }
    shell.newLine();
}

fn showViolations() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  POLICY VIOLATIONS");
    shell.printInfoLine("========================================");
    shell.newLine();

    const count = policy_mod.getViolationCount();
    shell.print("  Total: ");
    if (count == 0) {
        shell.printSuccessLine("0 - No violations");
    } else {
        helpers.printU32(count);
        shell.printErrorLine(" detected");
        shell.println("  Run 'boot verify' to re-check");
    }
    shell.newLine();
}

// =============================================================================
// H.5 TEST SUITE - 25 Tests
// =============================================================================

fn runBootTests() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  H.5: BOOT INTEGRITY CHAIN TESTS");
    shell.printInfoLine("========================================");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // -- PCR Operations (7 tests) --

    shell.println("  -- PCR Operations --");

    // Test 1: PCR init - all zeros
    shell.print("  [1]  PCR init all zeros...... ");
    {
        measure.initPcr();
        var all_zero = true;
        var i: usize = 0;
        while (i < measure.NUM_PCRS) : (i += 1) {
            if (measure.getPcr(i)) |pcr| {
                if (!ct.constantTimeIsZero32(pcr)) {
                    all_zero = false;
                    break;
                }
            }
        }
        if (all_zero) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 2: PCR extend - non-zero result
    shell.print("  [2]  PCR extend non-zero..... ");
    {
        measure.initPcr();
        var test_data: [32]u8 = [_]u8{0} ** 32;
        test_data[0] = 0xAB;
        test_data[1] = 0xCD;
        _ = measure.extendPcr(0, &test_data, "test");
        if (measure.getPcr(0)) |pcr| {
            if (!ct.constantTimeIsZero32(pcr)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 3: PCR extend deterministic
    shell.print("  [3]  PCR extend deterministic ");
    {
        var test_data: [32]u8 = [_]u8{0} ** 32;
        test_data[0] = 0x42;

        // First run
        measure.initPcr();
        _ = measure.extendPcr(0, &test_data, "det");
        var result1: [32]u8 = undefined;
        if (measure.getPcr(0)) |pcr| {
            var i: usize = 0;
            while (i < 32) : (i += 1) result1[i] = pcr[i];
        }

        // Second run (same input)
        measure.initPcr();
        _ = measure.extendPcr(0, &test_data, "det");
        if (measure.getPcr(0)) |pcr| {
            if (ct.constantTimeCompare32(&result1, pcr)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 4: PCR extend order matters (A->B != B->A)
    shell.print("  [4]  PCR extend order matters ");
    {
        var data_a: [32]u8 = [_]u8{0} ** 32;
        var data_b: [32]u8 = [_]u8{0} ** 32;
        data_a[0] = 0x11;
        data_b[0] = 0x22;

        // Order: A then B
        measure.initPcr();
        _ = measure.extendPcr(0, &data_a, "a");
        _ = measure.extendPcr(0, &data_b, "b");
        var result_ab: [32]u8 = undefined;
        if (measure.getPcr(0)) |pcr| {
            var i: usize = 0;
            while (i < 32) : (i += 1) result_ab[i] = pcr[i];
        }

        // Order: B then A
        measure.initPcr();
        _ = measure.extendPcr(0, &data_b, "b");
        _ = measure.extendPcr(0, &data_a, "a");
        if (measure.getPcr(0)) |pcr| {
            if (!ct.constantTimeCompare32(&result_ab, pcr)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 5: PCR read valid index
    shell.print("  [5]  PCR read valid index.... ");
    {
        if (measure.getPcr(0) != null and
            measure.getPcr(measure.NUM_PCRS - 1) != null)
        {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 6: PCR read invalid index
    shell.print("  [6]  PCR read invalid index.. ");
    {
        if (measure.getPcr(measure.NUM_PCRS) == null and
            measure.getPcr(99) == null)
        {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 7: PCR extended tracking
    shell.print("  [7]  PCR extended tracking... ");
    {
        measure.initPcr();
        if (!measure.isPcrExtended(0)) {
            var td: [32]u8 = [_]u8{0xAA} ** 32;
            _ = measure.extendPcr(0, &td, "track");
            if (measure.isPcrExtended(0) and !measure.isPcrExtended(1)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // -- Section Measurement (5 tests) --

    shell.println("  -- Section Measurement --");

    // Test 8: Measure .text section
    shell.print("  [8]  Measure .text........... ");
    {
        var h: [32]u8 = undefined;
        if (measure.measureTextSection(&h)) {
            if (!ct.constantTimeIsZero32(&h)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL (zero)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (err)");
            failed += 1;
        }
    }

    // Test 9: Measure .rodata section
    shell.print("  [9]  Measure .rodata......... ");
    {
        var h: [32]u8 = undefined;
        if (measure.measureRodataSection(&h)) {
            if (!ct.constantTimeIsZero32(&h)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL (zero)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (err)");
            failed += 1;
        }
    }

    // Test 10: .text and .rodata hashes differ
    shell.print("  [10] .text != .rodata........ ");
    {
        var h_text: [32]u8 = undefined;
        var h_rodata: [32]u8 = undefined;
        const t_ok = measure.measureTextSection(&h_text);
        const r_ok = measure.measureRodataSection(&h_rodata);
        if (t_ok and r_ok) {
            if (!ct.constantTimeCompare32(&h_text, &h_rodata)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL (same)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (err)");
            failed += 1;
        }
    }

    // Test 11: Measure .data section
    shell.print("  [11] Measure .data........... ");
    {
        var h: [32]u8 = undefined;
        if (measure.measureDataSection(&h)) {
            if (!ct.constantTimeIsZero32(&h)) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL (zero)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (err)");
            failed += 1;
        }
    }

    // Test 12: BSS validation
    shell.print("  [12] BSS validation.......... ");
    {
        if (measure.validateBssSection()) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // -- Event Log (4 tests) --

    shell.println("  -- Event Log --");

    // Test 13: Event log starts empty
    shell.print("  [13] Event log empty......... ");
    {
        measure.initPcr();
        if (measure.getEventCount() == 0) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 14: Event recorded after extend
    shell.print("  [14] Event recorded.......... ");
    {
        measure.initPcr();
        var td: [32]u8 = [_]u8{0x55} ** 32;
        _ = measure.extendPcr(2, &td, "test event");
        if (measure.getEventCount() == 1) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 15: Event count increments
    shell.print("  [15] Event count incr........ ");
    {
        measure.initPcr();
        var td: [32]u8 = [_]u8{0x77} ** 32;
        _ = measure.extendPcr(0, &td, "ev1");
        _ = measure.extendPcr(1, &td, "ev2");
        _ = measure.extendPcr(2, &td, "ev3");
        if (measure.getEventCount() == 3) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 16: Event stores correct PCR index
    shell.print("  [16] Event PCR index stored.. ");
    {
        measure.initPcr();
        var td: [32]u8 = [_]u8{0x88} ** 32;
        _ = measure.extendPcr(3, &td, "pcr3 test");
        if (measure.getEvent(0)) |ev| {
            if (ev.pcr_index == 3) {
                shell.printSuccessLine("PASS");
                passed += 1;
            } else {
                shell.printErrorLine("FAIL (idx)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (null)");
            failed += 1;
        }
    }

    // -- Boot Chain (5 tests) --

    shell.println("  -- Boot Chain --");

    // Test 17: Chain initially incomplete
    shell.print("  [17] Chain init incomplete... ");
    {
        measure.initPcr();
        if (!measure.isChainComplete()) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 18: Chain runs successfully
    shell.print("  [18] Chain runs OK........... ");
    {
        measure.init();
        if (measure.runBootChain()) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 19: Chain complete after run
    shell.print("  [19] Chain complete.......... ");
    {
        if (measure.isChainComplete()) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 20: Multiple PCRs extended
    shell.print("  [20] Multiple PCRs extended.. ");
    {
        const count = measure.getExtendedPcrCount();
        if (count >= 5) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 21: Aggregate PCR populated
    shell.print("  [21] Aggregate PCR populated. ");
    {
        if (measure.isPcrExtended(measure.PCR_AGGREGATE)) {
            if (measure.getPcr(measure.PCR_AGGREGATE)) |pcr| {
                if (!ct.constantTimeIsZero32(pcr)) {
                    shell.printSuccessLine("PASS");
                    passed += 1;
                } else {
                    shell.printErrorLine("FAIL (zero)");
                    failed += 1;
                }
            } else {
                shell.printErrorLine("FAIL (null)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (not ext)");
            failed += 1;
        }
    }

    // -- Runtime & CT Verification (4 tests) --

    shell.println("  -- Runtime & CT Verification --");

    // Test 22: .text re-measurement matches boot
    shell.print("  [22] .text re-measure match.. ");
    {
        if (measure.hasBootHashes()) {
            var current: [32]u8 = undefined;
            if (measure.measureTextSection(&current)) {
                if (ct.constantTimeCompare32(&current, measure.getBootTextHash())) {
                    shell.printSuccessLine("PASS");
                    passed += 1;
                } else {
                    shell.printErrorLine("FAIL (mismatch)");
                    failed += 1;
                }
            } else {
                shell.printErrorLine("FAIL (err)");
                failed += 1;
            }
        } else {
            // No boot hashes - run chain first, then check
            _ = measure.runBootChain();
            var current: [32]u8 = undefined;
            if (measure.measureTextSection(&current)) {
                if (ct.constantTimeCompare32(&current, measure.getBootTextHash())) {
                    shell.printSuccessLine("PASS");
                    passed += 1;
                } else {
                    shell.printErrorLine("FAIL");
                    failed += 1;
                }
            } else {
                shell.printErrorLine("FAIL (err)");
                failed += 1;
            }
        }
    }

    // Test 23: .rodata re-measurement matches boot
    shell.print("  [23] .rodata re-measure match ");
    {
        if (measure.hasBootHashes()) {
            var current: [32]u8 = undefined;
            if (measure.measureRodataSection(&current)) {
                if (ct.constantTimeCompare32(&current, measure.getBootRodataHash())) {
                    shell.printSuccessLine("PASS");
                    passed += 1;
                } else {
                    shell.printErrorLine("FAIL");
                    failed += 1;
                }
            } else {
                shell.printErrorLine("FAIL (err)");
                failed += 1;
            }
        } else {
            shell.printErrorLine("FAIL (no ref)");
            failed += 1;
        }
    }

    // Test 24: CT compare equal
    shell.print("  [24] CT hash compare equal... ");
    {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            a[i] = @intCast(i *% 7 +% 3);
            b[i] = @intCast(i *% 7 +% 3);
        }
        if (ct.constantTimeCompare32(&a, &b)) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // Test 25: CT compare differ
    shell.print("  [25] CT hash compare differ.. ");
    {
        var a: [32]u8 = [_]u8{0xAA} ** 32;
        var b: [32]u8 = [_]u8{0xAA} ** 32;
        b[31] = 0xBB;
        if (!ct.constantTimeCompare32(&a, &b)) {
            shell.printSuccessLine("PASS");
            passed += 1;
        } else {
            shell.printErrorLine("FAIL");
            failed += 1;
        }
    }

    // -- Summary --

    shell.newLine();
    shell.println("  --------------------------------");
    shell.print("  H.5 Results: ");
    helpers.printU32(passed);
    shell.print("/");
    helpers.printU32(passed + failed);
    shell.print(" passed");
    if (failed == 0) {
        shell.printSuccessLine(" OK");
    } else {
        shell.printErrorLine(" FAIL");
    }
    shell.newLine();

    // Re-run boot chain to restore state after tests
    _ = measure.runBootChain();
}
