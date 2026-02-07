//! Zamrud OS - Boot Commands
//! Boot verification and security policy management

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const boot_verify = @import("../../boot/verify.zig");
const policy_mod = @import("../../boot/policy.zig");

// =============================================================================
// Command Entry Point
// =============================================================================

/// Main boot command dispatcher
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
    } else {
        shell.printError("boot: unknown subcommand '");
        shell.print(subcommand);
        shell.println("'");
        shell.println("  Type 'boot help' for usage");
    }
}

// =============================================================================
// Subcommand Implementations
// =============================================================================

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BOOT - Boot Verification System");
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
    shell.newLine();

    shell.println("Security Policy Levels:");
    shell.println("  permissive     Minimal checks (development)");
    shell.println("  standard       Default security level");
    shell.println("  strict         Enhanced security");
    shell.println("  paranoid       Maximum security");
    shell.newLine();

    shell.println("Examples:");
    shell.println("  boot status");
    shell.println("  boot verify");
    shell.println("  boot set-policy strict");
    shell.newLine();
}

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BOOT VERIFICATION STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    // Verification status
    shell.print("  Boot Verified:     ");
    if (boot_verify.isVerified()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }

    const result = boot_verify.getLastResult();

    // Checks summary
    shell.print("  Verification Checks: ");
    helpers.printU32(@intCast(result.checks_passed));
    shell.print("/");
    helpers.printU32(@intCast(result.checks_total));
    if (result.checks_passed == result.checks_total) {
        shell.printSuccessLine(" passed");
    } else {
        shell.printErrorLine(" (some failed)");
    }

    // Security policy
    shell.print("  Security Policy:   ");
    const level = policy_mod.getLevel();
    switch (level) {
        .permissive => shell.printWarningLine("Permissive"),
        .standard => shell.println("Standard"),
        .strict => shell.printSuccessLine("Strict"),
        .paranoid => shell.printSuccessLine("Paranoid"),
    }

    // Policy violations
    const violations = policy_mod.getViolationCount();
    shell.print("  Policy Violations: ");
    if (violations == 0) {
        shell.printSuccessLine("0");
    } else {
        helpers.printU32(violations);
        shell.printErrorLine(" (security concern!)");
    }

    // Kernel hash (abbreviated)
    shell.print("  Kernel Hash:       ");
    const h = boot_verify.getKernelHash();
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        helpers.printHexByte(h[i]);
    }
    shell.println("...");

    // Boot time
    shell.print("  Verified At:       ");
    helpers.printU32(@intCast(result.verified_at));
    shell.println(" ticks");

    shell.newLine();

    // Overall assessment
    if (result.success and violations == 0) {
        shell.printSuccessLine("  System integrity: VERIFIED");
    } else if (result.success) {
        shell.printWarningLine("  System integrity: VERIFIED (with warnings)");
    } else {
        shell.printErrorLine("  System integrity: UNVERIFIED");
        shell.println("  Run 'boot verify' for details");
    }
    shell.newLine();
}

fn runVerify() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  RUNNING BOOT VERIFICATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Checking kernel integrity...");

    const result = boot_verify.verify();

    shell.newLine();
    shell.println("  Verification Results:");
    shell.println("  ----------------------------------------");

    // Individual checks
    shell.print("    Kernel hash:        ");
    if (result.kernel_hash_ok) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("MISMATCH");
    }

    shell.print("    Memory layout:      ");
    if (result.memory_ok) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("INVALID");
    }

    shell.print("    CPU features:       ");
    if (result.cpu_ok) {
        shell.printSuccessLine("OK");
    } else {
        shell.printWarningLine("LIMITED");
    }

    shell.print("    Security config:    ");
    if (result.security_ok) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("WEAK");
    }

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
        shell.newLine();
        shell.println("  WARNING: System may have been tampered with!");
        shell.println("  Consider rebooting from trusted media.");
    }
    shell.newLine();
}

fn showHash() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  KERNEL HASH INFORMATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Algorithm: SHA-256");
    shell.newLine();

    // Current hash
    shell.println("  Current Kernel Hash:");
    shell.print("    ");
    const h = boot_verify.getKernelHash();
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        helpers.printHexByte(h[i]);
        if (i == 15) {
            shell.newLine();
            shell.print("    ");
        }
    }
    shell.newLine();
    shell.newLine();

    // Trusted hash
    shell.println("  Trusted Hash (expected):");
    shell.print("    ");
    const trusted = boot_verify.getTrustedHash();
    i = 0;
    while (i < 32) : (i += 1) {
        helpers.printHexByte(trusted[i]);
        if (i == 15) {
            shell.newLine();
            shell.print("    ");
        }
    }
    shell.newLine();
    shell.newLine();

    // Comparison
    shell.print("  Match: ");
    var match = true;
    i = 0;
    while (i < 32) : (i += 1) {
        if (h[i] != trusted[i]) {
            match = false;
            break;
        }
    }

    if (match) {
        shell.printSuccessLine("YES - Kernel is authentic");
    } else {
        shell.printErrorLine("NO - Hash mismatch detected!");
        shell.newLine();
        shell.printWarningLine("  WARNING: Kernel may have been modified!");
    }
    shell.newLine();
}

fn showPolicy() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  SECURITY POLICY CONFIGURATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    const level = policy_mod.getLevel();
    const flags = policy_mod.getFlags();

    // Current level
    shell.print("  Current Level:         ");
    switch (level) {
        .permissive => {
            shell.printWarningLine("PERMISSIVE");
            shell.println("    Minimal security - for development only");
        },
        .standard => {
            shell.println("STANDARD");
            shell.println("    Balanced security and usability");
        },
        .strict => {
            shell.printSuccessLine("STRICT");
            shell.println("    Enhanced security for production");
        },
        .paranoid => {
            shell.printSuccessLine("PARANOID");
            shell.println("    Maximum security - may limit functionality");
        },
    }

    shell.newLine();
    shell.println("  Policy Flags:");

    shell.print("    Require kernel hash:     ");
    if (flags.require_kernel_hash) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No");
    }

    shell.print("    Require module hashes:   ");
    if (flags.require_module_hashes) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }

    shell.print("    Memory isolation:        ");
    if (flags.require_memory_isolation) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }

    shell.print("    Stack protection:        ");
    if (flags.require_stack_protection) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }

    shell.print("    NX (No-Execute) bit:     ");
    if (flags.require_nx) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }

    shell.print("    Allow debug mode:        ");
    if (flags.allow_debug) {
        shell.printWarningLine("Yes (security risk)");
    } else {
        shell.printSuccessLine("No");
    }

    shell.print("    Allow unsigned modules:  ");
    if (flags.allow_unsigned) {
        shell.printWarningLine("Yes (security risk)");
    } else {
        shell.printSuccessLine("No");
    }

    shell.newLine();

    // Violation count
    shell.print("  Policy Violations:     ");
    const violations = policy_mod.getViolationCount();
    if (violations == 0) {
        shell.printSuccessLine("0");
    } else {
        helpers.printU32(violations);
        shell.printErrorLine(" detected");
    }

    shell.newLine();
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
        shell.printError("Unknown policy level: '");
        shell.print(level_str);
        shell.println("'");
        shell.println("  Valid levels: permissive, standard, strict, paranoid");
        return;
    }

    policy_mod.setLevel(new_level);

    shell.printSuccess("Security policy set to: ");
    shell.println(level_str);

    if (new_level == .permissive) {
        shell.newLine();
        shell.printWarningLine("  WARNING: Permissive mode reduces security!");
        shell.println("  Only use for development.");
    } else if (new_level == .paranoid) {
        shell.newLine();
        shell.printInfoLine("  Note: Paranoid mode may limit some features.");
    }
    shell.newLine();
}

fn showTrusted() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  TRUSTED BOOT COMPONENTS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Trusted Kernel Hash:");
    shell.print("    ");
    const trusted = boot_verify.getTrustedHash();
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        helpers.printHexByte(trusted[i]);
    }
    shell.newLine();
    shell.newLine();

    shell.println("  Trusted Components:");
    shell.println("    - Kernel image");
    shell.println("    - Boot configuration");
    shell.println("    - Initial ramdisk (if present)");
    shell.newLine();

    shell.println("  Hash Algorithm: SHA-256");
    shell.println("  Verification: At boot and on-demand");
    shell.newLine();
}

fn showViolations() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  POLICY VIOLATIONS");
    shell.printInfoLine("========================================");
    shell.newLine();

    const count = policy_mod.getViolationCount();

    shell.print("  Total Violations: ");
    if (count == 0) {
        shell.printSuccessLine("0");
        shell.newLine();
        shell.println("  No security policy violations detected.");
        shell.println("  System is operating within policy.");
    } else {
        helpers.printU32(count);
        shell.printErrorLine(" detected");
        shell.newLine();
        shell.printWarningLine("  WARNING: Security policy has been violated!");
        shell.println("  Review system logs for details.");
        shell.newLine();
        shell.println("  Recommended actions:");
        shell.println("    1. Review recent changes");
        shell.println("    2. Run 'boot verify'");
        shell.println("    3. Consider rebooting from trusted media");
    }
    shell.newLine();
}
