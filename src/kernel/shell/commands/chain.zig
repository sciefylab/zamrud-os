//! Zamrud OS - Chain/Blockchain Commands

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const serial = @import("../../drivers/serial/serial.zig");
const chain = @import("../../chain/chain.zig");
const crypto = @import("../../crypto/crypto.zig");
const fat32 = @import("../../fs/fat32.zig");

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
    } else if (helpers.strEql(parsed.cmd, "save")) {
        chainSave();
    } else if (helpers.strEql(parsed.cmd, "load")) {
        chainLoad();
    } else if (helpers.strEql(parsed.cmd, "add")) {
        chainAddBlock(parsed.rest);
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
    shell.println("  add      Add a test block");
    shell.println("  save     Save chain to disk");
    shell.println("  load     Load chain from disk");
    shell.println("  test     Run chain tests");
    shell.newLine();
}

fn chainInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  BLOCKCHAIN STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized:  ");
    if (chain.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
        shell.newLine();
        return;
    }

    const ledger = @import("../../chain/ledger.zig");

    shell.print("  Height:       ");
    helpers.printU32(chain.getHeight());
    shell.newLine();

    shell.print("  Blocks:       ");
    helpers.printU32(chain.getBlockCount());
    shell.newLine();

    shell.print("  Auto-save:    ");
    if (ledger.isAutoSaveEnabled()) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  Last saved:   height ");
    helpers.printU32(chain.getLastSaveHeight());
    shell.newLine();

    shell.print("  Saved on disk:");
    if (chain.hasSavedChain()) {
        shell.printSuccessLine(" YES");
    } else {
        shell.printWarningLine(" NO");
    }

    // Show tip hash
    shell.print("  Tip hash:     ");
    const tip = chain.getTipHash();
    for (tip[0..8]) |b| helpers.printHexByte(b);
    shell.println("...");

    // Show genesis hash
    const genesis = ledger.getGenesisHash();
    shell.print("  Genesis hash: ");
    for (genesis[0..8]) |b| helpers.printHexByte(b);
    shell.println("...");

    shell.newLine();
}

fn chainInit() void {
    shell.printInfoLine("Initializing blockchain...");

    crypto.KeyPair.generate();
    var miner_key: [32]u8 = [_]u8{0} ** 32;
    const pub_key = crypto.KeyPair.getPublicKey();

    for (pub_key, 0..) |b, i| {
        miner_key[i] = b;
    }

    if (chain.initWithGenesis(&miner_key)) {
        shell.printSuccessLine("Blockchain initialized!");
        shell.print("  Authority: ");
        for (miner_key[0..16]) |b| helpers.printHexByte(b);
        shell.println("...");

        shell.print("  Height:    ");
        helpers.printU32(chain.getHeight());
        shell.newLine();

        if (chain.hasSavedChain()) {
            shell.printSuccessLine("  Saved to disk automatically");
        }
    } else {
        shell.printErrorLine("Failed to initialize!");
    }
}

fn chainSave() void {
    if (!chain.isInitialized()) {
        shell.printErrorLine("Chain not initialized! Run 'chain init' first.");
        return;
    }

    if (!fat32.isMounted()) {
        shell.printErrorLine("Disk not mounted! Cannot save.");
        return;
    }

    shell.print("  Saving chain to /disk/CHAIN.DAT...");

    if (chain.saveChain()) {
        shell.printSuccessLine(" OK");
        shell.print("  Height: ");
        helpers.printU32(chain.getHeight());
        shell.print(", Blocks: ");
        helpers.printU32(chain.getBlockCount());
        shell.newLine();
    } else {
        shell.printErrorLine(" FAILED");
    }
}

fn chainLoad() void {
    if (!fat32.isMounted()) {
        shell.printErrorLine("Disk not mounted! Cannot load.");
        return;
    }

    shell.print("  Loading chain from /disk/CHAIN.DAT...");

    if (chain.loadChain()) {
        shell.printSuccessLine(" OK");
        shell.print("  Height: ");
        helpers.printU32(chain.getHeight());
        shell.print(", Blocks: ");
        helpers.printU32(chain.getBlockCount());
        shell.newLine();

        const tip = chain.getTipHash();
        shell.print("  Tip: ");
        for (tip[0..8]) |b| helpers.printHexByte(b);
        shell.println("...");
    } else {
        shell.printErrorLine(" FAILED");
        shell.println("  No saved chain found or file corrupt.");
    }
}

fn chainAddBlock(args: []const u8) void {
    _ = args;

    if (!chain.isInitialized()) {
        shell.printErrorLine("Chain not initialized! Run 'chain init' first.");
        return;
    }

    const ledger = @import("../../chain/ledger.zig");

    var auth_key: [32]u8 = [_]u8{0} ** 32;
    auth_key[0] = 0x01;

    const blk = chain.createBlockTemplate(&auth_key);

    const entry = @import("../../chain/entry.zig");
    var test_entry: entry.Entry = undefined;
    entry.Entry.initInto(&test_entry);
    test_entry.entry_type = .system_update;
    test_entry.timestamp = 1700000000 + (chain.getBlockCount() * 10);

    if (!blk.addEntry(&test_entry)) {
        shell.printErrorLine("Failed to add entry to block!");
        return;
    }

    const prev_height = chain.getHeight();

    if (chain.addBlock(blk)) {
        shell.printSuccessLine("Block added!");
        shell.print("  Height: ");
        helpers.printU32(prev_height);
        shell.print(" -> ");
        helpers.printU32(chain.getHeight());
        shell.newLine();

        if (ledger.isAutoSaveEnabled() and chain.hasSavedChain()) {
            shell.printSuccessLine("  Auto-saved to disk");
        }
    } else {
        shell.printErrorLine("Failed to add block!");
        shell.println("  Chain may be full or block invalid.");
    }
}

// =============================================================================
// Test Suite
// =============================================================================

pub fn chainTest() void {
    const block_mod = @import("../../chain/block.zig");
    const entry_mod = @import("../../chain/entry.zig");
    const authority_mod = @import("../../chain/authority.zig");
    const ledger_mod = @import("../../chain/ledger.zig");

    helpers.printTestHeader("BLOCKCHAIN TEST SUITE (D2)");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // =========================================================================
    // Test 1: Block Structure
    // =========================================================================
    shell.println("[1/6] Block Structure");
    passed += helpers.doTest("Block creation", blk: {
        const blk = block_mod.Block.initStatic();
        break :blk (blk.entry_count == 0 and blk.header.version == block_mod.BLOCK_VERSION);
    }, &failed);

    passed += helpers.doTest("Add entry", blk: {
        _ = block_mod.Block.initStatic();
        var e: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e);
        e.entry_type = .file_register;
        e.target_hash[0] = 0xAB;
        const s = &block_mod.static_block;
        break :blk (s.addEntry(&e) and s.entry_count == 1);
    }, &failed);

    passed += helpers.doTest("Genesis block", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        const g = block_mod.Block.createGenesis(&k);
        break :blk (g.header.height == 0 and g.entry_count == 1 and g.validate());
    }, &failed);

    passed += helpers.doTest("Block hash non-zero", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        const g = block_mod.Block.createGenesis(&k);
        const h = g.getHash();
        var has: bool = false;
        for (h) |b| {
            if (b != 0) has = true;
        }
        break :blk has;
    }, &failed);

    // =========================================================================
    // Test 2: Block Entries
    // =========================================================================
    shell.newLine();
    shell.println("[2/6] Block Entries");

    passed += helpers.doTest("File register entry", blk: {
        var e: entry_mod.Entry = undefined;
        var th: [32]u8 = [_]u8{0} ** 32;
        th[0] = 0xAB;
        entry_mod.Entry.fileRegisterInto(&e, &th, 1);
        break :blk (e.entry_type == .file_register and e.target_hash[0] == 0xAB);
    }, &failed);

    passed += helpers.doTest("Quarantine entry", blk: {
        var e: entry_mod.Entry = undefined;
        var th: [32]u8 = [_]u8{0} ** 32;
        th[0] = 0xCD;
        entry_mod.Entry.quarantineFileInto(&e, &th, 1);
        break :blk (e.entry_type == .quarantine and e.data[0] == 1);
    }, &failed);

    passed += helpers.doTest("Entry serialize", blk: {
        var e: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e);
        e.entry_type = .system_update;
        var out: [128]u8 = [_]u8{0} ** 128;
        const sz = e.serialize(&out);
        break :blk (sz == 66 and out[0] == @intFromEnum(entry_mod.EntryType.system_update));
    }, &failed);

    // =========================================================================
    // Test 3: PoA Authority
    // =========================================================================
    shell.newLine();
    shell.println("[3/6] PoA Authority");

    passed += helpers.doTest("Authority init", blk: {
        authority_mod.init();
        break :blk true;
    }, &failed);

    passed += helpers.doTest("Add authority", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x42;
        break :blk authority_mod.addAuthority(&k, "test");
    }, &failed);

    passed += helpers.doTest("Verify authority", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x42;
        break :blk authority_mod.isAuthority(&k);
    }, &failed);

    passed += helpers.doTest("Reject unknown", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0xFF;
        break :blk !authority_mod.isAuthority(&k);
    }, &failed);

    // =========================================================================
    // Test 4: Ledger
    // =========================================================================
    shell.newLine();
    shell.println("[4/6] Ledger");

    // Disable auto-save during tests
    const prev_auto = ledger_mod.isAutoSaveEnabled();
    ledger_mod.setAutoSave(false);

    passed += helpers.doTest("Ledger init", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        break :blk (ledger_mod.init(&k) and ledger_mod.isInitialized());
    }, &failed);

    passed += helpers.doTest("Genesis state", blk: {
        break :blk (ledger_mod.getHeight() == 0 and ledger_mod.getBlockCount() == 1);
    }, &failed);

    passed += helpers.doTest("Add block", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        const b = ledger_mod.createBlockTemplate(&k);
        var e: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e);
        e.entry_type = .file_register;
        _ = b.addEntry(&e);
        break :blk (ledger_mod.addBlock(b) and ledger_mod.getHeight() == 1);
    }, &failed);

    passed += helpers.doTest("Reject bad height", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        // Create block with wrong height (template gives height+1, but let's manually break it)
        const b = block_mod.Block.initStatic();
        b.header.height = 999;
        var e: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e);
        _ = b.addEntry(&e);
        break :blk !ledger_mod.addBlock(b);
    }, &failed);

    passed += helpers.doTest("Chain grows", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x01;
        const b = ledger_mod.createBlockTemplate(&k);
        var e: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e);
        e.entry_type = .system_update;
        _ = b.addEntry(&e);
        const h_before = ledger_mod.getHeight();
        const ok = ledger_mod.addBlock(b);
        break :blk (ok and ledger_mod.getHeight() == h_before + 1);
    }, &failed);

    // =========================================================================
    // Test 5: Persistence - Serialize/Deserialize
    // =========================================================================
    shell.newLine();
    shell.println("[5/6] Persistence (Serialize)");

    if (fat32.isMounted()) {
        // Setup: init fresh chain with known state
        var test_key: [32]u8 = [_]u8{0} ** 32;
        test_key[0] = 0xAA;
        test_key[1] = 0xBB;
        _ = ledger_mod.init(&test_key);

        // Add 2 blocks
        var bi: usize = 0;
        while (bi < 2) : (bi += 1) {
            const b = ledger_mod.createBlockTemplate(&test_key);
            var e: entry_mod.Entry = undefined;
            entry_mod.Entry.initInto(&e);
            e.entry_type = .system_update;
            _ = b.addEntry(&e);
            _ = ledger_mod.addBlock(b);
        }

        const saved_height = ledger_mod.getHeight();
        const saved_blocks = ledger_mod.getBlockCount();

        // Save tip hash for later comparison
        var saved_tip: [32]u8 = [_]u8{0} ** 32;
        const tip_ptr = ledger_mod.getTipHash();
        for (tip_ptr, 0..) |b, idx| {
            saved_tip[idx] = b;
        }

        // Save genesis hash
        var saved_genesis: [32]u8 = [_]u8{0} ** 32;
        const gen_ptr = ledger_mod.getGenesisHash();
        for (gen_ptr, 0..) |b, idx| {
            saved_genesis[idx] = b;
        }

        // Test: save to disk
        const save_ok = ledger_mod.saveToDisk();
        passed += helpers.doTest("Save to disk", save_ok, &failed);

        // Test: file created
        const file_exists = fat32.findInRoot("CHAIN.DAT") != null;
        passed += helpers.doTest("CHAIN.DAT created", file_exists, &failed);

        // Test: file size reasonable
        if (fat32.findInRoot("CHAIN.DAT")) |fi| {
            const size_ok = (fi.size >= 80 and fi.size <= 1024);
            passed += helpers.doTest("File size valid", size_ok, &failed);
        } else {
            passed += helpers.doTest("File size valid", false, &failed);
        }

        // =====================================================================
        // Test 6: Persistence - Load & Verify
        // =====================================================================
        shell.newLine();
        shell.println("[6/6] Persistence (Restore)");

        // Reset ledger completely
        _ = ledger_mod.init(&test_key);

        // Verify it's reset
        const reset_ok = (ledger_mod.getHeight() == 0 and ledger_mod.getBlockCount() == 1);
        passed += helpers.doTest("Reset verified", reset_ok, &failed);

        // Load from disk
        const load_ok = ledger_mod.loadFromDisk();
        passed += helpers.doTest("Load from disk", load_ok, &failed);

        // Verify height restored
        const height_ok = (ledger_mod.getHeight() == saved_height);
        passed += helpers.doTest("Height restored", height_ok, &failed);

        // Verify block count restored
        const blocks_ok = (ledger_mod.getBlockCount() == saved_blocks);
        passed += helpers.doTest("Block count restored", blocks_ok, &failed);

        // Verify tip hash matches
        const restored_tip = ledger_mod.getTipHash();
        var tip_match = true;
        for (restored_tip, 0..) |b, idx| {
            if (b != saved_tip[idx]) {
                tip_match = false;
                break;
            }
        }
        passed += helpers.doTest("Tip hash matches", tip_match, &failed);

        // Verify genesis hash matches
        const restored_gen = ledger_mod.getGenesisHash();
        var gen_match = true;
        for (restored_gen, 0..) |b, idx| {
            if (b != saved_genesis[idx]) {
                gen_match = false;
                break;
            }
        }
        passed += helpers.doTest("Genesis hash matches", gen_match, &failed);

        // Verify can still add blocks after restore
        const b2 = ledger_mod.createBlockTemplate(&test_key);
        var e2: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e2);
        e2.entry_type = .file_register;
        _ = b2.addEntry(&e2);
        const add_after_load = ledger_mod.addBlock(b2);
        passed += helpers.doTest("Add block after load", add_after_load, &failed);

        const height_grew = (ledger_mod.getHeight() == saved_height + 1);
        passed += helpers.doTest("Height grew after add", height_grew, &failed);

        // Cleanup test file
        _ = fat32.deleteFile("CHAIN.DAT");

        // Verify cleanup
        const cleaned = fat32.findInRoot("CHAIN.DAT") == null;
        passed += helpers.doTest("Cleanup CHAIN.DAT", cleaned, &failed);
    } else {
        // Disk not available - skip persistence tests
        shell.newLine();
        shell.println("[5/6] Persistence (Serialize)");
        helpers.doSkip("Save to disk");
        helpers.doSkip("CHAIN.DAT created");
        helpers.doSkip("File size valid");

        shell.newLine();
        shell.println("[6/6] Persistence (Restore)");
        helpers.doSkip("Reset verified");
        helpers.doSkip("Load from disk");
        helpers.doSkip("Height restored");
        helpers.doSkip("Block count restored");
        helpers.doSkip("Tip hash matches");
        helpers.doSkip("Genesis hash matches");
        helpers.doSkip("Add block after load");
        helpers.doSkip("Height grew after add");
        helpers.doSkip("Cleanup CHAIN.DAT");
    }

    // Restore auto-save
    ledger_mod.setAutoSave(prev_auto);

    // Summary
    helpers.printTestResults(passed, failed);
}
