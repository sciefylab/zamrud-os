//! Zamrud OS - Chain/Blockchain Commands
//! Updated: GOV.1a runtime governance audit visibility
//! Updated: GOV.1b bounded persistent audit ring visibility

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const chain = @import("../../chain/chain.zig");
const crypto = @import("../../crypto/crypto.zig");
const gov_sign = @import("../../crypto/gov_sign.zig");
const auth = @import("../../identity/auth.zig");
const constant_time = @import("../../crypto/constant_time.zig");
const fat32 = @import("../../fs/fat32.zig");

var chain_identity_public_key: [gov_sign.PUBLIC_KEY_BYTES]u8 =
    [_]u8{0} ** gov_sign.PUBLIC_KEY_BYTES;

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
    } else if (helpers.strEql(parsed.cmd, "audit")) {
        chainAudit(parsed.rest);
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

// =============================================================================
// Help
// =============================================================================

fn chainHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  CHAIN - Blockchain Module");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: chain <subcommand>");
    shell.newLine();

    shell.println("Subcommands:");
    shell.println("  help                  Show this help");
    shell.println("  info                  Show chain status");
    shell.println("  audit                 Show governance audit status");
    shell.println("  audit status          Show governance audit status");
    shell.println("  audit latest          Show latest audit records");
    shell.println("  audit records         Show latest audit records");
    shell.println("  audit autosave        Show audit auto-save state");
    shell.println("  audit autosave on     Enable audit auto-save");
    shell.println("  audit autosave off    Disable audit auto-save");
    shell.println("  audit checkpoint      Save current audit checkpoint");
    shell.println("  init                  Initialize with genesis");
    shell.println("  add                   Add a test block");
    shell.println("  save                  Save chain to disk");
    shell.println("  load                  Load chain from disk");
    shell.println("  test                  Run chain tests");
    shell.newLine();

    shell.println("Lightweight GOV Audit:");
    shell.println("  - GOV.1a: audit events are hash-committed.");
    shell.println("  - GOV.1b: small bounded persistent audit ring.");
    shell.println("  - Audit auto-save is OFF by default for lightweight operation.");
    shell.println("  - Use 'chain audit checkpoint' to manually persist current state.");
    shell.newLine();
}

// =============================================================================
// Info
// =============================================================================

fn chainInfo() void {
    const ledger = @import("../../chain/ledger.zig");

    shell.printInfoLine("========================================");
    shell.printInfoLine("  BLOCKCHAIN STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Chain initialized: ");
    if (chain.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    shell.print("  Ledger initialized:");
    if (chain.isLedgerInitialized()) {
        shell.printSuccessLine(" YES");
    } else {
        shell.printWarningLine(" NO");
        shell.newLine();
        return;
    }

    shell.print("  Height:            ");
    helpers.printU32(chain.getHeight());
    shell.newLine();

    shell.print("  Blocks:            ");
    helpers.printU32(chain.getBlockCount());
    shell.newLine();

    shell.print("  Normal auto-save:  ");
    if (chain.isAutoSaveEnabled()) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  Audit auto-save:   ");
    if (chain.isAuditAutoSaveEnabled()) {
        shell.printWarningLine("ON");
    } else {
        shell.printSuccessLine("OFF");
    }

    shell.print("  Last saved:        height ");
    helpers.printU32(chain.getLastSaveHeight());
    shell.newLine();

    shell.print("  Saved on disk:     ");
    if (chain.hasSavedChain()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    shell.print("  Audit stage:       ");
    shell.printSuccessLine("GOV.1b");

    shell.print("  Audit mode:        ");
    shell.printSuccessLine("Bounded persistent ring + hash-commit");

    shell.print("  Audit capacity:    ");
    helpers.printU32(ledger.getAuditCapacity());
    shell.println(" records");

    shell.print("  Audit records:     ");
    helpers.printU32(ledger.getAuditRecordCount());
    shell.print("/");
    helpers.printU32(ledger.getAuditCapacity());
    shell.newLine();

    shell.print("  Audit total:       ");
    helpers.printU32(ledger.getAuditTotal());
    shell.newLine();

    shell.print("  Tip hash:          ");
    const tip = chain.getTipHash();
    for (tip[0..8]) |b| helpers.printHexByte(b);
    shell.println("...");

    shell.print("  Genesis hash:      ");
    const genesis = chain.getGenesisHash();
    for (genesis[0..8]) |b| helpers.printHexByte(b);
    shell.println("...");

    shell.newLine();
}

// =============================================================================
// GOV.1b Audit Commands
// =============================================================================

fn chainAudit(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "status")) {
        chainAuditStatus();
    } else if (helpers.strEql(parsed.cmd, "latest")) {
        chainAuditRecords();
    } else if (helpers.strEql(parsed.cmd, "records")) {
        chainAuditRecords();
    } else if (helpers.strEql(parsed.cmd, "autosave")) {
        chainAuditAutosave(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "checkpoint")) {
        chainAuditCheckpoint();
    } else if (helpers.strEql(parsed.cmd, "help")) {
        chainAuditHelp();
    } else {
        chainAuditHelp();
    }
}

fn chainAuditHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  GOVERNANCE AUDIT COMMANDS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: chain audit <subcommand>");
    shell.newLine();

    shell.println("Subcommands:");
    shell.println("  status             Show audit status");
    shell.println("  latest             Show bounded audit records");
    shell.println("  records            Show bounded audit records");
    shell.println("  autosave           Show audit auto-save status");
    shell.println("  autosave on        Enable audit auto-save");
    shell.println("  autosave off       Disable audit auto-save");
    shell.println("  checkpoint         Save current hash/audit checkpoint to disk");
    shell.println("  help               Show this help");
    shell.newLine();

    shell.println("Notes:");
    shell.println("  GOV.1b keeps audit detail small using a fixed ring buffer.");
    shell.println("  Old audit entries are overwritten when the ring is full.");
    shell.println("  This keeps Zamrud OS lightweight and bounded.");
    shell.newLine();
}

fn chainAuditStatus() void {
    const ledger = @import("../../chain/ledger.zig");

    shell.printInfoLine("========================================");
    shell.printInfoLine("  GOVERNANCE AUDIT STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Chain initialized: ");
    if (chain.isInitialized()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    shell.print("  Ledger initialized:");
    if (chain.isLedgerInitialized()) {
        shell.printSuccessLine(" YES");
    } else {
        shell.printWarningLine(" NO");
    }

    shell.print("  Audit stage:       ");
    shell.printSuccessLine("GOV.1b");

    shell.print("  Audit mode:        ");
    shell.printSuccessLine("Bounded persistent ring + hash-committed");

    shell.print("  Entry types:       ");
    shell.println("authority_audit, eviction_audit, firewall_audit");

    shell.print("  Chain growth:      ");
    shell.printSuccessLine("Bounded by MAX_BLOCKS + tip folding");

    shell.print("  Audit detail:      ");
    if (ledger.isAuditDetailPersistent()) {
        shell.printSuccessLine("Bounded persistent ring");
    } else {
        shell.printWarningLine("Runtime only");
    }

    shell.print("  Audit capacity:    ");
    helpers.printU32(ledger.getAuditCapacity());
    shell.println(" records");

    shell.print("  Audit records:     ");
    helpers.printU32(ledger.getAuditRecordCount());
    shell.print("/");
    helpers.printU32(ledger.getAuditCapacity());
    shell.newLine();

    shell.print("  Audit total:       ");
    helpers.printU32(ledger.getAuditTotal());
    shell.newLine();

    shell.print("  Audit write index: ");
    helpers.printU32(ledger.getAuditWriteIndex());
    shell.newLine();

    shell.print("  Normal auto-save:  ");
    if (chain.isAutoSaveEnabled()) {
        shell.printSuccessLine("ON");
    } else {
        shell.printWarningLine("OFF");
    }

    shell.print("  Audit auto-save:   ");
    if (chain.isAuditAutoSaveEnabled()) {
        shell.printWarningLine("ON");
    } else {
        shell.printSuccessLine("OFF");
    }

    shell.print("  Current height:    ");
    helpers.printU32(chain.getHeight());
    shell.newLine();

    shell.print("  Current blocks:    ");
    helpers.printU32(chain.getBlockCount());
    shell.newLine();

    shell.print("  Last saved height: ");
    helpers.printU32(chain.getLastSaveHeight());
    shell.newLine();

    shell.print("  Saved on disk:     ");
    if (chain.hasSavedChain()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printWarningLine("NO");
    }

    shell.newLine();
    shell.println("  GOV.1b behavior:");
    shell.println("  - Authority, eviction, and firewall audit events are committed.");
    shell.println("  - Audit detail is stored in a small bounded ring buffer.");
    shell.println("  - Audit events do not spam disk writes by default.");
    shell.println("  - If block capacity is full, audit is folded into tip hash.");
    shell.println("  - Use 'chain audit checkpoint' to persist current checkpoint.");
    shell.newLine();
}

fn chainAuditRecords() void {
    const ledger = @import("../../chain/ledger.zig");

    shell.printInfoLine("========================================");
    shell.printInfoLine("  GOVERNANCE AUDIT RECORDS");
    shell.printInfoLine("========================================");
    shell.newLine();

    if (!chain.isLedgerInitialized()) {
        shell.printWarningLine("Ledger not initialized. No audit records.");
        shell.newLine();
        return;
    }

    const count = ledger.getAuditRecordCount();

    shell.print("  Records: ");
    helpers.printU32(count);
    shell.print("/");
    helpers.printU32(ledger.getAuditCapacity());
    shell.newLine();

    shell.print("  Total:   ");
    helpers.printU32(ledger.getAuditTotal());
    shell.newLine();

    shell.newLine();

    if (count == 0) {
        shell.printWarningLine("  No audit records.");
        shell.newLine();
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (ledger.getAuditRecord(i)) |rec| {
            shell.print("  [");
            helpers.printU32(@intCast(i));
            shell.print("] ");

            printAuditEntryType(rec.entry_type);
            shell.print(" action=");
            printAuditAction(rec.entry_type, rec.action);

            shell.print(" ts=");
            helpers.printU32(rec.timestamp);

            shell.print(" aux=");
            helpers.printU32(rec.aux);

            shell.print(" target=");
            printHexPrefix8(&rec.target_prefix);

            shell.print(" data=");
            printHexPrefix8(&rec.data_prefix);

            shell.print(" tip=");
            printHexPrefix8(&rec.tip_prefix);

            shell.newLine();
        }
    }

    shell.newLine();
}

fn chainAuditAutosave(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "status")) {
        shell.print("  Audit auto-save: ");
        if (chain.isAuditAutoSaveEnabled()) {
            shell.printWarningLine("ON");
            shell.println("  Warning: audit events may write CHAIN.DAT more often.");
        } else {
            shell.printSuccessLine("OFF");
            shell.println("  Lightweight mode active: audit does not auto-save per event.");
        }
        return;
    }

    if (helpers.strEql(opt, "on")) {
        chain.setAuditAutoSave(true);
        shell.printWarningLine("[!] Audit auto-save ENABLED");
        shell.println("    Useful for experiments, but heavier for disk I/O.");
    } else if (helpers.strEql(opt, "off")) {
        chain.setAuditAutoSave(false);
        shell.printSuccessLine("[+] Audit auto-save DISABLED");
        shell.println("    Lightweight mode restored.");
    } else {
        shell.println("Usage: chain audit autosave [on|off]");
    }
}

fn chainAuditCheckpoint() void {
    if (!chain.isLedgerInitialized()) {
        shell.printErrorLine("Ledger not initialized. Nothing to checkpoint.");
        return;
    }

    if (!fat32.isMounted()) {
        shell.printErrorLine("Disk not mounted! Cannot save audit checkpoint.");
        return;
    }

    shell.print("  Saving GOV.1b audit checkpoint...");

    if (chain.saveAuditCheckpoint()) {
        shell.printSuccessLine(" OK");

        shell.print("  Height: ");
        helpers.printU32(chain.getHeight());
        shell.print(", Blocks: ");
        helpers.printU32(chain.getBlockCount());
        shell.newLine();

        shell.print("  Tip: ");
        const tip = chain.getTipHash();
        for (tip[0..8]) |b| helpers.printHexByte(b);
        shell.println("...");
    } else {
        shell.printErrorLine(" FAILED");
    }
}

// =============================================================================
// Init / Save / Load
// =============================================================================

fn chainInit() void {
    shell.printInfoLine("Initializing blockchain...");

    var miner_key: [32]u8 = [_]u8{0} ** 32;
    defer constant_time.secureZero32(&miner_key);
    defer constant_time.secureZero(&chain_identity_public_key);

    const public_key = auth.getGovernancePublicKey() orelse {
        shell.printErrorLine("No active governance identity key.");
        shell.println("Login/unlock an identity before initializing the chain.");
        return;
    };

    const serialized_len = gov_sign.serializePublicKey(
        public_key,
        &chain_identity_public_key,
    );
    if (serialized_len != gov_sign.PUBLIC_KEY_BYTES) {
        shell.printErrorLine("Failed to serialize governance public key.");
        return;
    }

    crypto.sha256Into(&chain_identity_public_key, &miner_key);

    if (chain.initWithGenesis(&miner_key)) {
        shell.printSuccessLine("Blockchain initialized!");
        shell.print("  Authority: ");
        for (miner_key[0..16]) |byte| helpers.printHexByte(byte);
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
    if (!chain.isLedgerInitialized()) {
        shell.printErrorLine("Ledger not initialized! Run 'chain init' first.");
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

    if (!chain.isLedgerInitialized()) {
        shell.printErrorLine("Ledger not initialized! Run 'chain init' first.");
        return;
    }

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

        if (chain.isAutoSaveEnabled() and chain.hasSavedChain()) {
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

    passed += helpers.doTest("Authority audit entry", blk: {
        var e: entry_mod.Entry = undefined;
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xA7;

        entry_mod.Entry.authorityAuditInto(
            &e,
            &id,
            entry_mod.AUDIT_AUTH_REGISTER,
            3,
            1,
            1700000001,
        );

        break :blk (e.entry_type == .authority_audit and
            e.target_hash[0] == 0xA7 and
            e.data[0] == entry_mod.AUDIT_AUTH_REGISTER);
    }, &failed);

    passed += helpers.doTest("Eviction audit entry", blk: {
        var e: entry_mod.Entry = undefined;
        var id: [32]u8 = [_]u8{0} ** 32;
        var ev: [32]u8 = [_]u8{0} ** 32;

        id[0] = 0xE7;
        ev[0] = 0xEE;

        entry_mod.Entry.evictionAuditInto(
            &e,
            &id,
            0xC0A80101,
            7,
            &ev,
            1700000002,
        );

        break :blk (e.entry_type == .eviction_audit and
            e.data[0] == entry_mod.AUDIT_EVICTION_EXECUTED and
            e.data[2] == 0xC0 and
            e.data[5] == 0x01);
    }, &failed);

    passed += helpers.doTest("Firewall audit entry", blk: {
        var e: entry_mod.Entry = undefined;

        entry_mod.Entry.firewallAuditInto(
            &e,
            0xC0A8FA77,
            entry_mod.AUDIT_FIREWALL_KILLSWITCH,
            1,
            1700000003,
        );

        break :blk (e.entry_type == .firewall_audit and
            e.target_hash[0] == 0xC0 and
            e.target_hash[3] == 0x77 and
            e.data[0] == entry_mod.AUDIT_FIREWALL_KILLSWITCH);
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

    passed += helpers.doTest("Add/retain authority", blk: {
        var k: [32]u8 = [_]u8{0} ** 32;
        k[0] = 0x42;

        // The authority registry is persistent/idempotent across repeated
        // shell test runs. addAuthority() may correctly return false when
        // the same authority already exists, so test the required
        // postcondition instead of requiring a fresh insertion.
        _ = authority_mod.addAuthority(&k, "test");
        break :blk authority_mod.isAuthority(&k);
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

    const prev_auto = ledger_mod.isAutoSaveEnabled();
    const prev_audit_auto = ledger_mod.isAuditAutoSaveEnabled();

    ledger_mod.setAutoSave(false);
    ledger_mod.setAuditAutoSave(false);

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

    passed += helpers.doTest("Authority audit append", blk: {
        var id: [32]u8 = [_]u8{0} ** 32;
        id[0] = 0xA1;

        const before = ledger_mod.getHeight();

        const ok = ledger_mod.appendAuthorityAudit(
            &id,
            entry_mod.AUDIT_AUTH_REGISTER,
            3,
            1,
        );

        break :blk (ok and ledger_mod.getHeight() == before + 1 and
            ledger_mod.getAuditRecordCount() > 0);
    }, &failed);

    passed += helpers.doTest("Eviction audit append", blk: {
        var id: [32]u8 = [_]u8{0} ** 32;
        var ev: [32]u8 = [_]u8{0} ** 32;

        id[0] = 0xE1;
        ev[0] = 0xEE;

        const before = ledger_mod.getHeight();

        const ok = ledger_mod.appendEvictionAudit(
            &id,
            0xC0A80101,
            7,
            &ev,
        );

        break :blk (ok and ledger_mod.getHeight() == before + 1 and
            ledger_mod.getAuditRecordCount() > 1);
    }, &failed);

    passed += helpers.doTest("Firewall audit append", blk: {
        const before = ledger_mod.getHeight();

        const ok = ledger_mod.appendFirewallAudit(
            0xC0A8FA77,
            entry_mod.AUDIT_FIREWALL_KILLSWITCH,
            1,
        );

        break :blk (ok and ledger_mod.getHeight() == before + 1 and
            ledger_mod.getAuditRecordCount() > 2);
    }, &failed);

    passed += helpers.doTest("Audit ring bounded", blk: {
        var n: usize = 0;
        while (n < 20) : (n += 1) {
            var id: [32]u8 = [_]u8{0} ** 32;
            id[0] = @intCast(n & 0xFF);

            _ = ledger_mod.appendAuthorityAudit(
                &id,
                entry_mod.AUDIT_AUTH_REGISTER,
                3,
                1,
            );
        }

        break :blk (ledger_mod.getAuditRecordCount() == ledger_mod.getAuditCapacity() and
            ledger_mod.getAuditTotal() >= 20);
    }, &failed);

    // =========================================================================
    // Test 5: Persistence - Serialize/Deserialize
    // =========================================================================
    shell.newLine();
    shell.println("[5/6] Persistence (Serialize)");

    if (fat32.isMounted()) {
        var test_key: [32]u8 = [_]u8{0} ** 32;
        test_key[0] = 0xAA;
        test_key[1] = 0xBB;

        _ = ledger_mod.init(&test_key);

        var bi: usize = 0;
        while (bi < 2) : (bi += 1) {
            const b = ledger_mod.createBlockTemplate(&test_key);

            var e: entry_mod.Entry = undefined;
            entry_mod.Entry.initInto(&e);
            e.entry_type = .system_update;

            _ = b.addEntry(&e);
            _ = ledger_mod.addBlock(b);
        }

        var aid: [32]u8 = [_]u8{0} ** 32;
        aid[0] = 0xA9;
        _ = ledger_mod.appendAuthorityAudit(
            &aid,
            entry_mod.AUDIT_AUTH_REGISTER,
            3,
            1,
        );

        const saved_height = ledger_mod.getHeight();
        const saved_blocks = ledger_mod.getBlockCount();
        const saved_audit_count = ledger_mod.getAuditRecordCount();

        var saved_tip: [32]u8 = [_]u8{0} ** 32;
        const tip_ptr = ledger_mod.getTipHash();
        for (tip_ptr, 0..) |b, idx| {
            saved_tip[idx] = b;
        }

        var saved_genesis: [32]u8 = [_]u8{0} ** 32;
        const gen_ptr = ledger_mod.getGenesisHash();
        for (gen_ptr, 0..) |b, idx| {
            saved_genesis[idx] = b;
        }

        const save_ok = ledger_mod.saveToDisk();
        passed += helpers.doTest("Save to disk", save_ok, &failed);

        const file_exists = fat32.findInRoot("CHAIN.DAT") != null;
        passed += helpers.doTest("CHAIN.DAT created", file_exists, &failed);

        if (fat32.findInRoot("CHAIN.DAT")) |fi| {
            const size_ok = (fi.size >= 80 and fi.size <= 2048);
            passed += helpers.doTest("File size valid", size_ok, &failed);
        } else {
            passed += helpers.doTest("File size valid", false, &failed);
        }

        // =====================================================================
        // Test 6: Persistence - Load & Verify
        // =====================================================================
        shell.newLine();
        shell.println("[6/6] Persistence (Restore)");

        _ = ledger_mod.init(&test_key);

        const reset_ok = (ledger_mod.getHeight() == 0 and ledger_mod.getBlockCount() == 1);
        passed += helpers.doTest("Reset verified", reset_ok, &failed);

        const load_ok = ledger_mod.loadFromDisk();
        passed += helpers.doTest("Load from disk", load_ok, &failed);

        const height_ok = (ledger_mod.getHeight() == saved_height);
        passed += helpers.doTest("Height restored", height_ok, &failed);

        const blocks_ok = (ledger_mod.getBlockCount() == saved_blocks);
        passed += helpers.doTest("Block count restored", blocks_ok, &failed);

        const audit_ok = (ledger_mod.getAuditRecordCount() == saved_audit_count);
        passed += helpers.doTest("Audit count restored", audit_ok, &failed);

        const restored_tip = ledger_mod.getTipHash();
        var tip_match = true;
        for (restored_tip, 0..) |b, idx| {
            if (b != saved_tip[idx]) {
                tip_match = false;
                break;
            }
        }
        passed += helpers.doTest("Tip hash matches", tip_match, &failed);

        const restored_gen = ledger_mod.getGenesisHash();
        var gen_match = true;
        for (restored_gen, 0..) |b, idx| {
            if (b != saved_genesis[idx]) {
                gen_match = false;
                break;
            }
        }
        passed += helpers.doTest("Genesis hash matches", gen_match, &failed);

        const b2 = ledger_mod.createBlockTemplate(&test_key);

        var e2: entry_mod.Entry = undefined;
        entry_mod.Entry.initInto(&e2);
        e2.entry_type = .file_register;

        _ = b2.addEntry(&e2);

        const add_after_load = ledger_mod.addBlock(b2);
        passed += helpers.doTest("Add block after load", add_after_load, &failed);

        const height_grew = (ledger_mod.getHeight() == saved_height + 1);
        passed += helpers.doTest("Height grew after add", height_grew, &failed);

        _ = fat32.deleteFile("CHAIN.DAT");

        const cleaned = fat32.findInRoot("CHAIN.DAT") == null;
        passed += helpers.doTest("Cleanup CHAIN.DAT", cleaned, &failed);
    } else {
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
        helpers.doSkip("Audit count restored");
        helpers.doSkip("Tip hash matches");
        helpers.doSkip("Genesis hash matches");
        helpers.doSkip("Add block after load");
        helpers.doSkip("Height grew after add");
        helpers.doSkip("Cleanup CHAIN.DAT");
    }

    ledger_mod.setAutoSave(prev_auto);
    ledger_mod.setAuditAutoSave(prev_audit_auto);

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Audit Printing Helpers
// =============================================================================

fn printAuditEntryType(t: anytype) void {
    const entry_mod = @import("../../chain/entry.zig");

    switch (t) {
        entry_mod.EntryType.authority_audit => shell.print("authority"),
        entry_mod.EntryType.eviction_audit => shell.print("eviction"),
        entry_mod.EntryType.firewall_audit => shell.print("firewall"),
        else => shell.print("other"),
    }
}

fn printAuditAction(t: anytype, action: u8) void {
    const entry_mod = @import("../../chain/entry.zig");

    switch (t) {
        entry_mod.EntryType.authority_audit => {
            switch (action) {
                entry_mod.AUDIT_AUTH_REGISTER => shell.print("register"),
                entry_mod.AUDIT_AUTH_REVOKE => shell.print("revoke"),
                entry_mod.AUDIT_AUTH_QUARANTINE => shell.print("quarantine"),
                entry_mod.AUDIT_AUTH_RESTORE => shell.print("restore"),
                else => {
                    shell.print("unknown(");
                    helpers.printU32(action);
                    shell.print(")");
                },
            }
        },
        entry_mod.EntryType.eviction_audit => {
            switch (action) {
                entry_mod.AUDIT_EVICTION_EXECUTED => shell.print("executed"),
                else => {
                    shell.print("unknown(");
                    helpers.printU32(action);
                    shell.print(")");
                },
            }
        },
        entry_mod.EntryType.firewall_audit => {
            switch (action) {
                entry_mod.AUDIT_FIREWALL_KILLSWITCH => shell.print("killswitch"),
                entry_mod.AUDIT_FIREWALL_QUARANTINE => shell.print("quarantine"),
                else => {
                    shell.print("unknown(");
                    helpers.printU32(action);
                    shell.print(")");
                },
            }
        },
        else => {
            shell.print("unknown(");
            helpers.printU32(action);
            shell.print(")");
        },
    }
}

fn printHexPrefix8(prefix: *const [8]u8) void {
    for (prefix) |b| {
        helpers.printHexByte(b);
    }
}
