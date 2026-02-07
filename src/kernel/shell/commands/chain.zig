//! Zamrud OS - Chain/Blockchain Commands

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const serial = @import("../../drivers/serial/serial.zig");
const chain = @import("../../chain/chain.zig");
const crypto = @import("../../crypto/crypto.zig");

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        chainHelp();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        chainTest();
    } else if (helpers.strEql(parsed.cmd, "init")) {
        chainInit();
    } else if (helpers.strEql(parsed.cmd, "info")) {
        chainInfo();
    } else {
        shell.printError("chain: unknown subcommand '");
        shell.print(parsed.cmd);
        shell.println("'");
    }
}

fn chainHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CHAIN - Blockchain Module");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: chain <subcommand>");
    shell.newLine();

    shell.println("Subcommands:");
    shell.println("  help     Show this help");
    shell.println("  info     Show chain status");
    shell.println("  init     Initialize with genesis");
    shell.println("  test     Run chain tests");
    shell.newLine();
}

fn chainInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BLOCKCHAIN STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized: ");
    if (chain.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    shell.newLine();
}

fn chainInit() void {
    shell.printInfoLine("Initializing blockchain...");

    crypto.KeyPair.generate();
    var miner_key: [32]u8 = [_]u8{0} ** 32;
    const pub_key = crypto.KeyPair.getPublicKey();

    // Copy pub_key to miner_key
    for (pub_key, 0..) |b, i| {
        miner_key[i] = b;
    }

    if (chain.initWithGenesis(&miner_key)) {
        shell.printSuccessLine("Blockchain initialized!");
        shell.print("  Miner pubkey: ");
        for (miner_key[0..16]) |b| helpers.printHexByte(b);
        shell.println("...");
    } else {
        shell.printErrorLine("Failed to initialize!");
    }
}

pub fn chainTest() void {
    const block_mod = @import("../../chain/block.zig");
    const entry_mod = @import("../../chain/entry.zig");
    const authority_mod = @import("../../chain/authority.zig");
    const ledger_mod = @import("../../chain/ledger.zig");

    helpers.printTestHeader("BLOCKCHAIN TEST SUITE");

    var passed: u32 = 0;
    var failed: u32 = 0;

    shell.println("[1/4] Block Structure...");
    if (block_mod.test_blockchain()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[2/4] Block Entries...");
    if (entry_mod.test_entry()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[3/4] PoA Authority...");
    if (authority_mod.test_authority()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    shell.println("[4/4] Ledger...");
    if (ledger_mod.test_ledger()) {
        shell.printSuccessLine("      PASSED");
        passed += 1;
    } else {
        shell.printErrorLine("      FAILED");
        failed += 1;
    }

    helpers.printTestResults(passed, failed);
}
