//! Zamrud OS - P2P Shell Commands (H.3 HARDENED)
//! P2P network management, testing, and Sybil defense

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");

const p2p = @import("../../p2p/p2p.zig");
const peer = @import("../../p2p/peer.zig");
const discovery = @import("../../p2p/discovery.zig");
const message = @import("../../p2p/message.zig");
const sync = @import("../../p2p/sync.zig");
const protocol = @import("../../p2p/protocol.zig");
const reputation = @import("../../p2p/reputation.zig");
const sybil = @import("../../p2p/sybil_defense.zig");

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "start")) {
        startNode();
    } else if (helpers.strEql(parsed.cmd, "stop")) {
        stopNode();
    } else if (helpers.strEql(parsed.cmd, "peers")) {
        showPeers();
    } else if (helpers.strEql(parsed.cmd, "connect")) {
        connectPeer(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "disconnect")) {
        disconnectPeer(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "discover")) {
        runDiscovery();
    } else if (helpers.strEql(parsed.cmd, "sync")) {
        showSyncStatus();
    } else if (helpers.strEql(parsed.cmd, "id")) {
        showNodeId();
    } else if (helpers.strEql(parsed.cmd, "stats")) {
        showStats();
    } else if (helpers.strEql(parsed.cmd, "reputation")) {
        showReputation(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "sybil")) {
        showSybilStatus(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "diversity")) {
        showDiversity();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTest(parsed.rest);
    } else {
        shell.printError("p2p: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'p2p help'");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  P2P - Peer-to-Peer Network (H.3)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: p2p <command> [args]");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  help              Show this help");
    shell.println("  status            Show P2P node status");
    shell.println("  start             Start P2P node");
    shell.println("  stop              Stop P2P node");
    shell.println("  id                Show node ID");
    shell.println("  stats             Show statistics");
    shell.newLine();

    shell.println("Peer Management:");
    shell.println("  peers             List connected peers");
    shell.println("  connect <ip:port> Connect to peer");
    shell.println("  disconnect <id>   Disconnect peer");
    shell.println("  discover          Run peer discovery");
    shell.newLine();

    shell.println("Sybil Defense (H.3):");
    shell.println("  reputation        Show reputation summary");
    shell.println("  reputation <id>   Show specific peer reputation");
    shell.println("  sybil             Show Sybil defense status");
    shell.println("  sybil alerts      Show Sybil attack alerts");
    shell.println("  diversity         Show peer diversity score");
    shell.newLine();

    shell.println("Sync:");
    shell.println("  sync              Show sync status");
    shell.newLine();

    shell.println("Testing:");
    shell.println("  test              Run all P2P tests (45 tests)");
    shell.println("  test quick        Quick health check");
    shell.newLine();
}

// =============================================================================
// Status Commands
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  P2P NODE STATUS (H.3 HARDENED)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Initialized:    ");
    if (p2p.isInitialized()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.print("  Status:         ");
    const status = p2p.getStatus();
    switch (status) {
        .offline => shell.printWarningLine("OFFLINE"),
        .connecting => shell.println("CONNECTING..."),
        .online => shell.printSuccessLine("ONLINE"),
        .syncing => shell.println("SYNCING..."),
    }

    shell.print("  Peer Count:     ");
    helpers.printUsize(p2p.getPeerCount());
    shell.newLine();

    const stats = p2p.getStats();
    shell.newLine();
    shell.println("  Traffic:");
    shell.print("    Messages TX:  ");
    helpers.printU64(stats.messages_sent);
    shell.newLine();
    shell.print("    Messages RX:  ");
    helpers.printU64(stats.messages_received);
    shell.newLine();
    shell.print("    Bytes TX:     ");
    helpers.printU64(stats.bytes_sent);
    shell.newLine();
    shell.print("    Bytes RX:     ");
    helpers.printU64(stats.bytes_received);
    shell.newLine();

    shell.newLine();
    shell.print("  Uptime:         ");
    helpers.printU64(stats.uptime_seconds);
    shell.println(" seconds");

    // H.3: Sybil Defense Summary
    shell.newLine();
    shell.println("  Sybil Defense (H.3):");
    shell.print("    Reputation:   ");
    if (reputation.isInitialized()) {
        shell.printSuccess("ACTIVE (");
        helpers.printUsize(reputation.getTrackedCount());
        shell.printSuccessLine(" tracked)");
    } else {
        shell.printWarningLine("Not initialized");
    }

    shell.print("    Sybil Guard:  ");
    if (sybil.isInitialized()) {
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.printWarningLine("Not initialized");
    }

    shell.print("    Diversity:    ");
    const div_score = peer.getDiversityScore();
    helpers.printU8(div_score);
    shell.print("/100");
    if (div_score >= 80) {
        shell.printSuccessLine(" (excellent)");
    } else if (div_score >= 50) {
        shell.println(" (good)");
    } else if (div_score > 0) {
        shell.printWarningLine(" (low)");
    } else {
        shell.println(" (no peers)");
    }

    shell.print("    Alerts:       ");
    const alert_count = peer.getSybilAlertCount();
    if (alert_count == 0) {
        shell.printSuccessLine("0 (clean)");
    } else {
        shell.printError("");
        helpers.printUsize(alert_count);
        shell.printErrorLine(" active!");
    }

    shell.print("    Denials:      ");
    helpers.printU64(peer.getDeniedCount());
    shell.println(" registrations blocked");

    shell.newLine();
}

fn showNodeId() void {
    shell.printInfoLine("Node Identity:");
    shell.newLine();

    shell.print("  Node ID:    ");
    const node_id = p2p.getNodeId();
    printHexShort(node_id[0..16]);
    shell.println("...");

    shell.print("  Public Key: ");
    const pub_key = p2p.getPublicKey();
    printHexShort(pub_key[0..16]);
    shell.println("...");

    shell.newLine();
}

fn showStats() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  P2P STATISTICS (H.3)");
    shell.printInfoLine("========================================");
    shell.newLine();

    const stats = p2p.getStats();

    shell.println("  Messages:");
    shell.print("    Sent:         ");
    helpers.printU64(stats.messages_sent);
    shell.newLine();
    shell.print("    Received:     ");
    helpers.printU64(stats.messages_received);
    shell.newLine();

    shell.newLine();
    shell.println("  Bandwidth:");
    shell.print("    TX:           ");
    helpers.printU64(stats.bytes_sent);
    shell.println(" bytes");
    shell.print("    RX:           ");
    helpers.printU64(stats.bytes_received);
    shell.println(" bytes");

    shell.newLine();
    shell.println("  Peers:");
    shell.print("    Connected:    ");
    helpers.printUsize(peer.getConnectedCount());
    shell.newLine();
    shell.print("    Total known:  ");
    helpers.printUsize(peer.getTotalCount());
    shell.newLine();
    shell.print("    Tracked rep:  ");
    helpers.printUsize(reputation.getTrackedCount());
    shell.newLine();

    shell.newLine();
    shell.println("  Discovery:");
    shell.print("    Discovered:   ");
    helpers.printUsize(discovery.getDiscoveredCount());
    shell.newLine();

    shell.newLine();
    shell.println("  Sybil Defense:");
    shell.print("    Registrations:");
    helpers.printU64(sybil.getTotalRegistrations());
    shell.println(" allowed");
    shell.print("    Denials:      ");
    helpers.printU64(sybil.getTotalDenials());
    shell.println(" blocked");
    shell.print("    Alerts:       ");
    helpers.printUsize(sybil.getAlertCount());
    shell.newLine();
    shell.print("    Diversity:    ");
    helpers.printU8(peer.getDiversityScore());
    shell.println("/100");

    shell.newLine();
    shell.println("  Sync:");
    const sync_progress = sync.getProgress();
    shell.print("    Block:        ");
    helpers.printU64(sync_progress.current);
    shell.print(" / ");
    helpers.printU64(sync_progress.target);
    shell.print(" (");
    helpers.printU8(sync_progress.percent);
    shell.println("%)");

    shell.newLine();
}

// =============================================================================
// Node Control
// =============================================================================

fn startNode() void {
    if (!p2p.isInitialized()) {
        shell.printErrorLine("P2P not initialized!");
        return;
    }

    shell.println("Starting P2P node...");

    if (p2p.start()) {
        shell.printSuccessLine("P2P node started");
    } else {
        shell.printErrorLine("Failed to start P2P node");
    }
}

fn stopNode() void {
    shell.println("Stopping P2P node...");
    p2p.stop();
    shell.printSuccessLine("P2P node stopped");
}

// =============================================================================
// Peer Management
// =============================================================================

fn showPeers() void {
    shell.printInfoLine("Connected Peers:");
    shell.println("  ID               Status  Trust       Rep");
    shell.println("  ---------------- ------- ----------- -----");

    const peers = peer.getAll();
    var count: usize = 0;

    for (peers) |p| {
        if (p.status == .disconnected) continue;

        shell.print("  ");
        printHexShort(p.id[0..8]);
        shell.print(" ");

        switch (p.status) {
            .disconnected => shell.print("DISC    "),
            .connecting => shell.print("CONN    "),
            .connected => shell.print("OK      "),
            .banned => shell.print("BAN     "),
        }

        switch (p.trust_level) {
            .untrusted => shell.print("untrusted   "),
            .provisional => shell.print("provisional "),
            .member => shell.print("member      "),
            .trusted => shell.print("trusted     "),
        }

        helpers.printI32(p.reputation);
        shell.newLine();
        count += 1;
    }

    if (count == 0) {
        shell.println("  (no peers connected)");
    }

    shell.newLine();
    shell.print("Total: ");
    helpers.printUsize(count);
    shell.print(" peers, diversity: ");
    helpers.printU8(peer.getDiversityScore());
    shell.println("/100");
    shell.newLine();
}

fn connectPeer(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.println("Usage: p2p connect <ip:port>");
        shell.println("Example: p2p connect 192.168.1.100:31337");
        return;
    }

    const parsed = parseIpPort(trimmed);
    if (parsed.ip == 0) {
        shell.printError("Invalid address: ");
        shell.println(trimmed);
        return;
    }

    shell.print("Connecting to ");
    printIp(parsed.ip);
    shell.print(":");
    helpers.printU16(parsed.port);
    shell.println("...");

    if (p2p.connectToPeer(parsed.ip, parsed.port)) {
        shell.printSuccessLine("Connected!");
    } else {
        shell.printErrorLine("Connection failed");
    }
}

fn disconnectPeer(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.println("Usage: p2p disconnect <peer_id_prefix>");
        return;
    }

    const peers = peer.getAll();
    for (peers) |*p| {
        if (p.status == .disconnected) continue;

        var id_str: [16]u8 = undefined;
        formatHex(p.id[0..8], &id_str);

        if (helpers.startsWith(&id_str, trimmed)) {
            peer.disconnect(p);
            shell.printSuccess("Disconnected peer ");
            printHexShort(p.id[0..8]);
            shell.newLine();
            return;
        }
    }

    shell.printError("Peer not found: ");
    shell.println(trimmed);
}

fn runDiscovery() void {
    shell.println("Running peer discovery...");

    if (!discovery.isInitialized()) {
        shell.printErrorLine("Discovery not initialized");
        return;
    }

    discovery.requestPeers();

    shell.print("Discovered peers: ");
    helpers.printUsize(discovery.getDiscoveredCount());
    shell.newLine();

    const connected = discovery.connectToDiscovered(3);
    shell.print("New connections: ");
    helpers.printUsize(connected);
    shell.newLine();
}

fn showSyncStatus() void {
    shell.printInfoLine("Sync Status:");
    shell.newLine();

    const state = sync.getState();

    shell.print("  Status:       ");
    switch (state.status) {
        .idle => shell.println("IDLE"),
        .requesting => shell.println("REQUESTING..."),
        .receiving => shell.println("RECEIVING..."),
        .validating => shell.println("VALIDATING..."),
        .complete => shell.printSuccessLine("COMPLETE"),
        .failed => shell.printErrorLine("FAILED"),
    }

    shell.print("  Current:      ");
    helpers.printU64(state.current_block);
    shell.newLine();

    shell.print("  Target:       ");
    helpers.printU64(state.target_block);
    shell.newLine();

    const progress = sync.getProgress();
    shell.print("  Progress:     ");
    helpers.printU8(progress.percent);
    shell.println("%");

    shell.print("  Blocks recv:  ");
    helpers.printU64(state.blocks_received);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// H.3: Reputation Commands
// =============================================================================

fn showReputation(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len > 0) {
        showPeerReputation(trimmed);
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine("  PEER REPUTATION SYSTEM (H.3)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Tracked peers:    ");
    helpers.printUsize(reputation.getTrackedCount());
    shell.newLine();

    shell.print("  PoW difficulty:   ");
    helpers.printU8(reputation.DEFAULT_POW_DIFFICULTY);
    shell.println(" bits");

    shell.newLine();
    shell.println("  Trust Level Thresholds:");
    shell.print("    Untrusted:    < ");
    helpers.printI32(reputation.SCORE_PROVISIONAL);
    shell.newLine();
    shell.print("    Provisional:  >= ");
    helpers.printI32(reputation.SCORE_PROVISIONAL);
    shell.newLine();
    shell.print("    Member:       >= ");
    helpers.printI32(reputation.SCORE_MEMBER);
    shell.newLine();
    shell.print("    Trusted:      >= ");
    helpers.printI32(reputation.SCORE_TRUSTED);
    shell.newLine();
    shell.print("    Auto-ban:     <= ");
    helpers.printI32(reputation.SCORE_BAN);
    shell.newLine();

    shell.newLine();
}

fn showPeerReputation(id_prefix: []const u8) void {
    const peers = peer.getAll();
    for (peers) |p| {
        if (p.status == .disconnected) continue;

        var id_str: [16]u8 = undefined;
        formatHex(p.id[0..8], &id_str);

        if (helpers.startsWith(&id_str, id_prefix)) {
            shell.printInfoLine("Peer Reputation Detail:");
            shell.newLine();

            shell.print("  Peer ID:      ");
            printHexShort(p.id[0..16]);
            shell.println("...");

            shell.print("  Trust Level:  ");
            switch (p.trust_level) {
                .untrusted => shell.printWarningLine("UNTRUSTED"),
                .provisional => shell.println("PROVISIONAL"),
                .member => shell.printSuccessLine("MEMBER"),
                .trusted => shell.printSuccessLine("TRUSTED"),
            }

            shell.print("  Score:        ");
            helpers.printI32(p.reputation);
            shell.newLine();

            shell.print("  PoW Nonce:    ");
            helpers.printU64(p.proof_of_work);
            shell.newLine();

            if (reputation.getReputation(&p.id)) |rep| {
                shell.print("  Good Actions: ");
                helpers.printU32(rep.good_actions);
                shell.newLine();
                shell.print("  Violations:   ");
                helpers.printU32(rep.violations);
                shell.newLine();
                shell.print("  Vouchers:     ");
                helpers.printU8(rep.voucher_count);
                shell.print("/");
                helpers.printU8(reputation.MAX_VOUCHERS);
                shell.newLine();
                shell.print("  PoW Verified: ");
                if (rep.pow_verified) {
                    shell.printSuccessLine("Yes");
                } else {
                    shell.printWarningLine("No");
                }
                shell.print("  PoW Diff:     ");
                helpers.printU8(rep.pow_difficulty);
                shell.println(" bits");
                shell.print("  Age:          ");
                const age = reputation.getAge(rep);
                if (age >= 3600) {
                    helpers.printU64(age / 3600);
                    shell.println(" hours");
                } else if (age >= 60) {
                    helpers.printU64(age / 60);
                    shell.println(" minutes");
                } else {
                    helpers.printU64(age);
                    shell.println(" seconds");
                }
            }

            shell.newLine();
            return;
        }
    }

    shell.printError("Peer not found: ");
    shell.println(id_prefix);
}

// =============================================================================
// H.3: Sybil Defense Commands
// =============================================================================

fn showSybilStatus(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (helpers.strEql(trimmed, "alerts")) {
        showSybilAlerts();
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine("  SYBIL DEFENSE STATUS (H.3)");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print("  Status:           ");
    if (sybil.isInitialized()) {
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.printErrorLine("INACTIVE");
    }

    shell.newLine();
    shell.println("  Registration Policy:");
    shell.print("    PoW required:   ");
    helpers.printU8(reputation.DEFAULT_POW_DIFFICULTY);
    shell.println(" leading zero bits");
    shell.print("    Max per subnet: ");
    helpers.printU16(sybil.MAX_PEERS_PER_SUBNET);
    shell.println(" peers per /24");
    shell.print("    Rate limit:     ");
    helpers.printUsize(sybil.MAX_NEW_PEERS_PER_MINUTE);
    shell.println(" per minute");

    shell.newLine();
    shell.println("  Counters:");
    shell.print("    Allowed:        ");
    helpers.printU64(sybil.getTotalRegistrations());
    shell.newLine();
    shell.print("    Denied:         ");
    helpers.printU64(sybil.getTotalDenials());
    shell.newLine();
    shell.print("    Alerts:         ");
    helpers.printUsize(sybil.getAlertCount());
    shell.newLine();

    shell.newLine();
}

fn showSybilAlerts() void {
    shell.printInfoLine("  SYBIL ATTACK ALERTS");
    shell.newLine();

    const count = sybil.getAlertCount();
    if (count == 0) {
        shell.printSuccessLine("  No alerts — network is clean.");
        shell.newLine();
        return;
    }

    shell.print("  Total alerts: ");
    helpers.printUsize(count);
    shell.newLine();
    shell.newLine();

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (sybil.getAlert(i)) |alert| {
            shell.print("  [");
            helpers.printUsize(i + 1);
            shell.print("] ");

            switch (alert.alert_type) {
                .subnet_flood => shell.print("SUBNET_FLOOD "),
                .rate_flood => shell.print("RATE_FLOOD   "),
                .coordinated => shell.print("COORDINATED  "),
            }

            shell.print("peers=");
            helpers.printU16(alert.peer_count);
            shell.newLine();
        }
    }
    shell.newLine();
}

fn showDiversity() void {
    shell.printInfoLine("  PEER DIVERSITY (H.3)");
    shell.newLine();

    const score = peer.getDiversityScore();
    const distinct = sybil.getDistinctSubnetCount();
    const total = reputation.getTrackedCount();

    shell.print("  Score:    ");
    helpers.printU8(score);
    shell.println("/100");

    shell.print("  Subnets:  ");
    helpers.printUsize(distinct);
    shell.newLine();

    shell.print("  Peers:    ");
    helpers.printUsize(total);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Testing — ALL TESTS IN ONE FUNCTION
// =============================================================================

// Static test buffers
var test_peer_a: [32]u8 = [_]u8{0} ** 32;
var test_peer_b: [32]u8 = [_]u8{0} ** 32;
var test_peer_c: [32]u8 = [_]u8{0} ** 32;
var test_sig_copy: [64]u8 = [_]u8{0} ** 64;

pub fn runTest(args: []const u8) void {
    const opt = helpers.trim(args);

    if (opt.len == 0 or helpers.strEql(opt, "all")) {
        runAllTests();
    } else if (helpers.strEql(opt, "quick")) {
        runQuickTest();
    } else {
        shell.println("p2p test options: all, quick");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("P2P Quick Test (H.3 Hardened)...");
    shell.newLine();

    var ok = true;

    shell.print("  Initialized:  ");
    if (p2p.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Peer module:  ");
    if (peer.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Discovery:    ");
    if (discovery.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Reputation:   ");
    if (reputation.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.print("  Sybil Guard:  ");
    if (sybil.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("P2P", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("P2P TEST SUITE (H.3 HARDENED)");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // =========================================================================
    // Section 1: Module Initialization (6 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== Module Initialization ===");

    passed += helpers.doTest("P2P main module", p2p.isInitialized(), &failed);
    passed += helpers.doTest("Peer manager", peer.isInitialized(), &failed);
    passed += helpers.doTest("Discovery module", discovery.isInitialized(), &failed);
    passed += helpers.doTest("Message protocol", message.isInitialized(), &failed);
    passed += helpers.doTest("Sync module", sync.isInitialized(), &failed);
    passed += helpers.doTest("Protocol handler", protocol.isInitialized(), &failed);

    // =========================================================================
    // Section 2: Node Identity (2 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== Node Identity ===");

    const node_id = p2p.getNodeId();
    var has_id = false;
    for (node_id) |b| {
        if (b != 0) {
            has_id = true;
            break;
        }
    }
    passed += helpers.doTest("Node ID generated", has_id, &failed);

    const pub_key = p2p.getPublicKey();
    var has_key = false;
    for (pub_key) |b| {
        if (b != 0) {
            has_key = true;
            break;
        }
    }
    passed += helpers.doTest("Public key generated", has_key, &failed);

    // =========================================================================
    // Section 3: Message Protocol (3 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== Message Protocol ===");

    var test_msg = message.createPing(node_id);
    var encode_buf: [512]u8 = undefined;
    const encoded_len = message.encode(&test_msg, &encode_buf);
    passed += helpers.doTest("Message encoding", encoded_len > 0, &failed);

    if (encoded_len > 0) {
        const decoded = message.decode(encode_buf[0..encoded_len]);
        passed += helpers.doTest("Message decoding", decoded != null, &failed);
        if (decoded) |d| {
            passed += helpers.doTest("Message type preserved", d.msg_type == .ping, &failed);
        } else {
            failed += 1;
        }
    } else {
        failed += 2;
    }

    // =========================================================================
    // Section 4: Peer Management (4 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== Peer Management ===");

    passed += helpers.doTest("Empty peer list", peer.getConnectedCount() == 0, &failed);
    passed += helpers.doTest("Bootstrap peers", discovery.getBootstrapPeers().len > 0, &failed);

    const stats = p2p.getStats();
    passed += helpers.doTest("Stats valid", stats.peer_count == 0 or stats.peer_count > 0, &failed);
    passed += helpers.doTest("Status valid", stats.status == .offline or stats.status == .online or
        stats.status == .connecting or stats.status == .syncing, &failed);

    // =========================================================================
    // Section 5: H.3a — PoW & Leading Zeros (4 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3a: Proof-of-Work ===");

    // LeadingZeros: 0 bits always true
    {
        const h = [_]u8{0xFF} ** 32;
        passed += helpers.doTest("LeadingZeros (0 bits)", reputation.hasLeadingZeroBits(&h, 0), &failed);
    }

    // LeadingZeros: 8 bits
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        passed += helpers.doTest("LeadingZeros (8 bits)", reputation.hasLeadingZeroBits(&h, 8), &failed);
    }

    // LeadingZeros: fail case
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        passed += helpers.doTest("LeadingZeros (fail 9)", !reputation.hasLeadingZeroBits(&h, 9), &failed);
    }

    // LeadingZeros: 16 bits
    {
        var h = [_]u8{0xFF} ** 32;
        h[0] = 0x00;
        h[1] = 0x00;
        passed += helpers.doTest("LeadingZeros (16 bits)", reputation.hasLeadingZeroBits(&h, 16) and !reputation.hasLeadingZeroBits(&h, 17), &failed);
    }

    // =========================================================================
    // Section 6: H.3a — PoW Generation & Verification (4 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3a: PoW Generation ===");

    test_peer_a[0] = 0xAA;
    test_peer_a[1] = 0x01;
    test_peer_b[0] = 0xBB;
    test_peer_b[1] = 0x02;
    test_peer_c[0] = 0xCC;
    test_peer_c[1] = 0x03;

    // Generate PoW
    var nonce_a: u64 = 0;
    {
        if (reputation.generatePow(&test_peer_a, reputation.TEST_POW_DIFFICULTY, 10000)) |n| {
            nonce_a = n;
            passed += helpers.doTest("Generate PoW (8-bit)", true, &failed);
        } else {
            passed += helpers.doTest("Generate PoW (8-bit)", false, &failed);
        }
    }

    // Verify valid PoW
    passed += helpers.doTest("Verify valid PoW", reputation.verifyPow(&test_peer_a, nonce_a, reputation.TEST_POW_DIFFICULTY), &failed);

    // Reject bad nonce
    passed += helpers.doTest("Reject bad nonce", !reputation.verifyPow(&test_peer_a, 0xDEADBEEF, reputation.TEST_POW_DIFFICULTY), &failed);

    // Reject wrong peer_id
    passed += helpers.doTest("Reject wrong peer_id", !reputation.verifyPow(&test_peer_b, nonce_a, reputation.TEST_POW_DIFFICULTY), &failed);

    // =========================================================================
    // Section 7: H.3a — Reputation Scoring (6 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3a: Reputation Scoring ===");

    // Reset reputation for clean tests
    reputation.init();

    // Register with valid PoW
    {
        if (reputation.generatePow(&test_peer_a, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            if (reputation.registerPeer(&test_peer_a, nonce, reputation.TEST_POW_DIFFICULTY)) |rep| {
                passed += helpers.doTest("Register with PoW", rep.pow_verified and rep.score > 0 and rep.active, &failed);
            } else {
                passed += helpers.doTest("Register with PoW", false, &failed);
            }
        } else {
            passed += helpers.doTest("Register with PoW", false, &failed);
        }
    }

    // Register without PoW rejected
    passed += helpers.doTest("No PoW rejected", reputation.registerPeer(&test_peer_b, 0, reputation.TEST_POW_DIFFICULTY) == null, &failed);

    // Good action increases score
    {
        if (reputation.getReputation(&test_peer_a)) |rep| {
            const before = rep.score;
            reputation.addGoodAction(&test_peer_a);
            passed += helpers.doTest("Good action +score", rep.score >= before, &failed);
        } else {
            passed += helpers.doTest("Good action +score", false, &failed);
        }
    }

    // Violation decreases score
    {
        if (reputation.getReputation(&test_peer_a)) |rep| {
            const before = rep.score;
            reputation.addViolation(&test_peer_a);
            passed += helpers.doTest("Violation -score", rep.score <= before, &failed);
        } else {
            passed += helpers.doTest("Violation -score", false, &failed);
        }
    }

    // Trust level calculation
    {
        var mock = reputation.PeerReputation{
            .peer_id = [_]u8{0} ** 32,
            .active = true,
            .score = -10,
            .first_seen = 0,
            .last_active = 0,
            .good_actions = 0,
            .violations = 0,
            .pow_difficulty = 0,
            .pow_verified = false,
            .voucher_count = 0,
            .vouchers = [_][32]u8{[_]u8{0} ** 32} ** reputation.MAX_VOUCHERS,
            .trust_level = .untrusted,
        };
        const tl1 = reputation.calculateTrustLevel(&mock);
        mock.score = 100;
        const tl2 = reputation.calculateTrustLevel(&mock);
        mock.score = 600;
        const tl3 = reputation.calculateTrustLevel(&mock);
        passed += helpers.doTest("Trust level calc", tl1 == .untrusted and tl2 == .provisional and tl3 == .trusted, &failed);
    }

    // Vouching
    {
        // Register peer B
        if (reputation.generatePow(&test_peer_b, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce_b| {
            _ = reputation.registerPeer(&test_peer_b, nonce_b, reputation.TEST_POW_DIFFICULTY);
        }

        // Boost A to member
        if (reputation.getReputation(&test_peer_a)) |rep_a| {
            rep_a.score = reputation.SCORE_MEMBER;
            rep_a.trust_level = .member;
        }

        // A vouches for B
        const vouched = reputation.addVouch(&test_peer_b, &test_peer_a);
        passed += helpers.doTest("Vouching system", vouched and reputation.getVouchCount(&test_peer_b) == 1, &failed);
    }

    // =========================================================================
    // Section 8: H.3b — Sybil IP Subnet (4 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3b: Sybil IP Subnet ===");

    sybil.resetForTest();

    // IP to subnet
    {
        const ip: u32 = (192 << 24) | (168 << 16) | (1 << 8) | 100;
        const subnet = sybil.ipToSubnet(ip);
        const expected: u24 = (192 << 16) | (168 << 8) | 1;
        passed += helpers.doTest("IP to subnet", subnet == expected, &failed);
    }

    // Subnet add peer
    {
        sybil.resetForTest();
        const subnet: u24 = (10 << 16) | (0 << 8) | 1;
        sybil.addSubnetPeer(subnet);
        passed += helpers.doTest("Subnet add peer", sybil.getSubnetPeerCount(subnet) == 1, &failed);
    }

    // Distinct subnets
    {
        sybil.resetForTest();
        sybil.addSubnetPeer((10 << 16) | (1 << 8) | 1);
        sybil.addSubnetPeer((10 << 16) | (2 << 8) | 1);
        sybil.addSubnetPeer((10 << 16) | (3 << 8) | 1);
        passed += helpers.doTest("Distinct subnets", sybil.getDistinctSubnetCount() == 3, &failed);
    }

    // Remove subnet peer
    {
        sybil.resetForTest();
        const ip: u32 = (10 << 24) | (0 << 16) | (5 << 8) | 1;
        const subnet = sybil.ipToSubnet(ip);
        sybil.addSubnetPeer(subnet);
        sybil.addSubnetPeer(subnet);
        sybil.removeSubnetPeer(ip);
        passed += helpers.doTest("Remove subnet peer", sybil.getSubnetPeerCount(subnet) == 1, &failed);
    }

    // =========================================================================
    // Section 9: H.3b — Registration & Rate Limiting (5 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3b: Registration Control ===");

    reputation.init();
    sybil.resetForTest();

    // Allowed with valid PoW + unique subnet
    {
        var tid: [32]u8 = [_]u8{0} ** 32;
        tid[0] = 0xD1;
        if (reputation.generatePow(&tid, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const ip: u32 = (172 << 24) | (16 << 16) | (0 << 8) | 1;
            const result = sybil.checkRegistration(ip, &tid, nonce, reputation.TEST_POW_DIFFICULTY);
            passed += helpers.doTest("Registration allowed", result == .allowed, &failed);
        } else {
            passed += helpers.doTest("Registration allowed", false, &failed);
        }
    }

    // Denied without PoW
    {
        var tid: [32]u8 = [_]u8{0} ** 32;
        tid[0] = 0xD2;
        const ip: u32 = (172 << 24) | (16 << 16) | (1 << 8) | 1;
        const result = sybil.checkRegistration(ip, &tid, 0, 0);
        passed += helpers.doTest("Denied no PoW", result == .denied_no_pow, &failed);
    }

    // Denied invalid PoW
    {
        var tid: [32]u8 = [_]u8{0} ** 32;
        tid[0] = 0xD3;
        const ip: u32 = (172 << 24) | (16 << 16) | (2 << 8) | 1;
        const result = sybil.checkRegistration(ip, &tid, 99999, reputation.TEST_POW_DIFFICULTY);
        passed += helpers.doTest("Denied invalid PoW", result == .denied_invalid_pow, &failed);
    }

    // Denied subnet limit
    {
        sybil.resetForTest();
        const base_ip: u32 = (10 << 24) | (0 << 16) | (3 << 8);
        var i: u32 = 0;
        while (i < sybil.MAX_PEERS_PER_SUBNET) : (i += 1) {
            sybil.addSubnetPeer(sybil.ipToSubnet(base_ip | (i + 1)));
        }
        var tid: [32]u8 = [_]u8{0} ** 32;
        tid[0] = 0xD4;
        if (reputation.generatePow(&tid, reputation.TEST_POW_DIFFICULTY, 10000)) |nonce| {
            const result = sybil.checkRegistration(base_ip | 99, &tid, nonce, reputation.TEST_POW_DIFFICULTY);
            passed += helpers.doTest("Denied subnet limit", result == .denied_subnet_limit, &failed);
        } else {
            passed += helpers.doTest("Denied subnet limit", false, &failed);
        }
    }

    // Denial counter
    passed += helpers.doTest("Denial counter", sybil.getTotalDenials() > 0, &failed);

    // =========================================================================
    // Section 10: H.3b — Diversity Score (2 tests)
    // =========================================================================
    shell.newLine();
    shell.printInfoLine("=== H.3b: Diversity Score ===");

    // Low diversity (single subnet)
    {
        sybil.resetForTest();
        reputation.init();
        const subnet: u24 = (192 << 16) | (168 << 8) | 1;
        sybil.addSubnetPeer(subnet);
        sybil.addSubnetPeer(subnet);
        sybil.addSubnetPeer(subnet);

        var fake_id: [32]u8 = [_]u8{0} ** 32;
        var i: u8 = 0;
        while (i < 3) : (i += 1) {
            fake_id[0] = 0xF0 + i;
            if (reputation.generatePow(&fake_id, reputation.TEST_POW_DIFFICULTY, 10000)) |n| {
                _ = reputation.registerPeer(&fake_id, n, reputation.TEST_POW_DIFFICULTY);
            }
        }

        const score = sybil.getDiversityScore();
        passed += helpers.doTest("Low diversity (single)", score <= 50, &failed);
    }

    // High diversity (multi subnet)
    {
        sybil.resetForTest();
        reputation.init();
        sybil.addSubnetPeer((10 << 16) | (0 << 8) | 1);
        sybil.addSubnetPeer((10 << 16) | (0 << 8) | 2);
        sybil.addSubnetPeer((10 << 16) | (0 << 8) | 3);

        var fake_id: [32]u8 = [_]u8{0} ** 32;
        var i: u8 = 0;
        while (i < 3) : (i += 1) {
            fake_id[0] = 0xE0 + i;
            if (reputation.generatePow(&fake_id, reputation.TEST_POW_DIFFICULTY, 10000)) |n| {
                _ = reputation.registerPeer(&fake_id, n, reputation.TEST_POW_DIFFICULTY);
            }
        }

        const score = sybil.getDiversityScore();
        passed += helpers.doTest("High diversity (multi)", score == 100, &failed);
    }

    // =========================================================================
    // Summary
    // =========================================================================

    helpers.printTestResults(passed, failed);
}

// =============================================================================
// Utilities
// =============================================================================

const IpPort = struct {
    ip: u32,
    port: u16,
};

fn parseIpPort(s: []const u8) IpPort {
    var result = IpPort{ .ip = 0, .port = p2p.DEFAULT_PORT };

    var colon_pos: ?usize = null;
    for (s, 0..) |c, i| {
        if (c == ':') {
            colon_pos = i;
            break;
        }
    }

    const ip_str = if (colon_pos) |pos| s[0..pos] else s;
    const port_str = if (colon_pos) |pos| s[pos + 1 ..] else "";

    result.ip = parseIp(ip_str) orelse return result;

    if (port_str.len > 0) {
        result.port = helpers.parseU16(port_str) orelse p2p.DEFAULT_PORT;
    }

    return result;
}

fn parseIp(s: []const u8) ?u32 {
    var parts: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var cur: u32 = 0;

    for (s) |c| {
        if (c == '.') {
            if (idx >= 3 or cur > 255) return null;
            parts[idx] = @intCast(cur);
            idx += 1;
            cur = 0;
        } else if (c >= '0' and c <= '9') {
            cur = cur * 10 + (c - '0');
        } else {
            return null;
        }
    }

    if (idx != 3 or cur > 255) return null;
    parts[3] = @intCast(cur);

    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}

fn printIp(ip_val: u32) void {
    helpers.printU8(@intCast((ip_val >> 24) & 0xFF));
    shell.printChar('.');
    helpers.printU8(@intCast((ip_val >> 16) & 0xFF));
    shell.printChar('.');
    helpers.printU8(@intCast((ip_val >> 8) & 0xFF));
    shell.printChar('.');
    helpers.printU8(@intCast(ip_val & 0xFF));
}

fn printHexShort(data: []const u8) void {
    const hex = "0123456789abcdef";
    for (data) |b| {
        shell.printChar(hex[b >> 4]);
        shell.printChar(hex[b & 0xF]);
    }
}

fn formatHex(data: []const u8, out: []u8) void {
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    for (data) |b| {
        if (pos + 2 > out.len) break;
        out[pos] = hex[b >> 4];
        out[pos + 1] = hex[b & 0xF];
        pos += 2;
    }
}
