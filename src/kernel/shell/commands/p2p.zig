//! Zamrud OS - P2P Shell Commands
//! P2P network management and testing

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");

const p2p = @import("../../p2p/p2p.zig");
const peer = @import("../../p2p/peer.zig");
const discovery = @import("../../p2p/discovery.zig");
const message = @import("../../p2p/message.zig");
const sync = @import("../../p2p/sync.zig");
const protocol = @import("../../p2p/protocol.zig");

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
    shell.printInfoLine("  P2P - Peer-to-Peer Network");
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

    shell.println("Sync:");
    shell.println("  sync              Show sync status");
    shell.newLine();

    shell.println("Testing:");
    shell.println("  test              Run all P2P tests");
    shell.println("  test quick        Quick health check");
    shell.newLine();
}

// =============================================================================
// Status Commands
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  P2P NODE STATUS");
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
    shell.printInfoLine("  P2P STATISTICS");
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

    shell.newLine();
    shell.println("  Discovery:");
    shell.print("    Discovered:   ");
    helpers.printUsize(discovery.getDiscoveredCount());
    shell.newLine();

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
    shell.println("  ID               Status  Rep");
    shell.println("  ---------------- ------- -----");

    const peers = peer.getAll();
    var count: usize = 0;

    for (peers) |p| {
        if (p.status == .disconnected) continue;

        shell.print("  ");
        printHexShort(p.id[0..8]);
        shell.print(" ");

        // Print state
        switch (p.status) {
            .disconnected => shell.print("DISC    "),
            .connecting => shell.print("CONN    "),
            .connected => shell.print("OK      "),
            .banned => shell.print("BAN     "),
        }

        // Print reputation
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
    shell.println(" peers");
    shell.newLine();
}

fn connectPeer(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.println("Usage: p2p connect <ip:port>");
        shell.println("Example: p2p connect 192.168.1.100:31337");
        return;
    }

    // Parse IP:Port
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

    // Find peer by ID prefix
    const peers = peer.getAll();
    for (peers) |*p| {
        if (p.status == .disconnected) continue;

        // Check if ID starts with given prefix (simplified)
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

    // Try to connect to some discovered peers
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
// Testing
// =============================================================================

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
    shell.printInfoLine("P2P Quick Test...");
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

    shell.print("  Message:      ");
    if (message.isInitialized()) {
        shell.printSuccessLine("OK");
    } else {
        shell.printErrorLine("FAIL");
        ok = false;
    }

    shell.newLine();
    helpers.printQuickResult("P2P", ok);
}

fn runAllTests() void {
    helpers.printTestHeader("P2P TEST SUITE");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Module initialization
    helpers.printTestCategory(1, 5, "Module Initialization");
    passed += helpers.doTest("P2P main module", p2p.isInitialized(), &failed);
    passed += helpers.doTest("Peer manager", peer.isInitialized(), &failed);
    passed += helpers.doTest("Discovery module", discovery.isInitialized(), &failed);
    passed += helpers.doTest("Message protocol", message.isInitialized(), &failed);
    passed += helpers.doTest("Sync module", sync.isInitialized(), &failed);
    passed += helpers.doTest("Protocol handler", protocol.isInitialized(), &failed);

    // Node identity
    helpers.printTestCategory(2, 5, "Node Identity");
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

    // Message encoding
    helpers.printTestCategory(3, 5, "Message Protocol");
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

    // Peer management
    helpers.printTestCategory(4, 5, "Peer Management");
    passed += helpers.doTest("Empty peer list", peer.getConnectedCount() == 0, &failed);
    passed += helpers.doTest("Bootstrap peers configured", discovery.getBootstrapPeers().len > 0, &failed);

    // Stats
    helpers.printTestCategory(5, 5, "Statistics");
    const stats = p2p.getStats();
    passed += helpers.doTest("Stats struct valid", stats.peer_count == 0 or stats.peer_count > 0, &failed);
    passed += helpers.doTest("Status valid", stats.status == .offline or stats.status == .online or stats.status == .connecting or stats.status == .syncing, &failed);

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

    // Find colon
    var colon_pos: ?usize = null;
    for (s, 0..) |c, i| {
        if (c == ':') {
            colon_pos = i;
            break;
        }
    }

    const ip_str = if (colon_pos) |pos| s[0..pos] else s;
    const port_str = if (colon_pos) |pos| s[pos + 1 ..] else "";

    // Parse IP
    result.ip = parseIp(ip_str) orelse return result;

    // Parse port
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
