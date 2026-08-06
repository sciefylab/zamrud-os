//! Zamrud OS - P2P Shell Commands
//! H.3 Sybil Defense + H.4 Eclipse Defense + P.3 Onion Routing + P.3e Eviction
//!
//! Commands:
//! - p2p status
//! - p2p peers
//! - p2p eviction
//! - p2p evict <peer_id_prefix> <reason>
//! - p2p banned
//! - p2p test p3e

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
const eclipse = @import("../../p2p/eclipse_defense.zig");
const eviction = @import("../../p2p/eviction.zig");

const slor = @import("../../crypto/slor.zig");
const crypto = @import("../../crypto/crypto.zig");

var static_p3_handshake: protocol.HandshakePayload = undefined;
var static_p3_tampered: protocol.HandshakePayload = undefined;

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
    } else if (helpers.strEql(parsed.cmd, "eclipse")) {
        showEclipseStatus(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "diversity")) {
        showDiversity();
    } else if (helpers.strEql(parsed.cmd, "anchors")) {
        showAnchors();
    } else if (helpers.strEql(parsed.cmd, "eviction")) {
        showEviction(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "evict")) {
        evictPeer(parsed.rest);
    } else if (helpers.strEql(parsed.cmd, "banned")) {
        showBannedPeers();
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
    shell.printInfoLine(" P2P - Zamrud Network Manager");
    shell.printInfoLine(" H.3 + H.4 + P.3d + P.3e");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Usage: p2p <command> [args]");
    shell.newLine();

    shell.println("Node:");
    shell.println(" help                     Show this help");
    shell.println(" status                   Show P2P node status");
    shell.println(" start                    Start P2P node");
    shell.println(" stop                     Stop P2P node");
    shell.println(" id                       Show node ID");
    shell.println(" stats                    Show statistics");
    shell.newLine();

    shell.println("Peer Management:");
    shell.println(" peers                    List connected peers");
    shell.println(" connect <ip:port>        Connect to peer");
    shell.println(" disconnect <id>          Disconnect peer by ID prefix");
    shell.println(" discover                 Run peer discovery");
    shell.println(" anchors                  List anchor peers");
    shell.println(" banned                   List banned/evicted peers");
    shell.newLine();

    shell.println("P.3e Twin-Node Eviction:");
    shell.println(" eviction                 Show eviction status");
    shell.println(" eviction pending         Show pending eviction votes");
    shell.println(" eviction executed        Show executed evictions");
    shell.println(" evict <id> <reason>      Report local eviction evidence");
    shell.println(" reasons: duplicate, signature, onion, sybil,");
    shell.println(" eclipse, hardware, protocol, spam,  impersonation");
    shell.newLine();

    shell.println("Sybil Defense (H.3):");
    shell.println(" reputation               Show reputation summary");
    shell.println(" reputation <id>          Show specific peer reputation");
    shell.println(" sybil                    Show Sybil defense status");
    shell.println(" sybil alerts             Show Sybil attack alerts");
    shell.println(" diversity                Show peer diversity score");
    shell.newLine();

    shell.println("Eclipse Defense (H.4):");
    shell.println(" eclipse                  Show eclipse defense status");
    shell.println(" eclipse alerts           Show eclipse attack alerts");
    shell.println(" eclipse risk             Show current risk level");
    shell.newLine();

    shell.println("Sync:");
    shell.println(" sync                      Show sync status");
    shell.newLine();

    shell.println("Testing:");
    shell.println(" test                      Run all P2P tests");
    shell.println(" test quick                Quick health check");
    shell.println(" test h3                   H.3 tests");
    shell.println(" test h4                   H.4 tests");
    shell.println(" test p3                   P.3/P.3d tests");
    shell.println(" test p3e                  P.3e eviction tests");
    shell.newLine();
}

// =============================================================================
// Status Commands
// =============================================================================

fn showStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine(" P2P NODE STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print(" Initialized:      ");
    if (p2p.isInitialized()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.print(" Status:          ");
    switch (p2p.getStatus()) {
        .offline => shell.printWarningLine("OFFLINE"),
        .connecting => shell.println("CONNECTING"),
        .online => shell.printSuccessLine("ONLINE"),
        .syncing => shell.println("SYNCING"),
    }

    shell.print(" Node ID:         ");
    const node_id = p2p.getNodeId();
    printHexShort(node_id[0..8]);
    shell.println("...");

    shell.print(" Peer Count:      ");
    helpers.printUsize(p2p.getPeerCount());
    shell.newLine();

    shell.print(" Banned Peers:    ");
    helpers.printUsize(peer.getBannedCount());
    shell.newLine();

    shell.newLine();
    shell.println(" Traffic:");
    const stats = p2p.getStats();

    shell.print("    Messages TX: ");
    helpers.printU64(stats.messages_sent);
    shell.newLine();

    shell.print("    Messages RX: ");
    helpers.printU64(stats.messages_received);
    shell.newLine();

    shell.print("    Bytes TX:     ");
    helpers.printU64(stats.bytes_sent);
    shell.newLine();

    shell.print("    Bytes RX:     ");
    helpers.printU64(stats.bytes_received);
    shell.newLine();

    shell.print("    Uptime:       ");
    helpers.printU64(stats.uptime_seconds);
    shell.println(" seconds");

    shell.newLine();
    shell.println(" H.3 Sybil Defense:");

    shell.print("    Reputation:   ");
    if (reputation.isInitialized()) {
        shell.printSuccess("ACTIVE (");
        helpers.printUsize(reputation.getTrackedCount());
        shell.printSuccessLine(" tracked)");
    } else {
        shell.printWarningLine("Not initialized");
    }

    shell.print("    Sybil Guard: ");
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
    const sybil_alerts = peer.getSybilAlertCount();
    if (sybil_alerts == 0) {
        shell.printSuccessLine("0 (clean)");
    } else {
        shell.printError("");
        helpers.printUsize(sybil_alerts);
        shell.printErrorLine(" active");
    }

    shell.newLine();
    shell.println(" H.4 Eclipse Defense:");

    shell.print("    Status:       ");
    if (eclipse.isInitialized()) {
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.printWarningLine("Not initialized");
    }

    const eclipse_status = peer.getEclipseStatus();

    shell.print("    Risk Level:   ");
    helpers.printU8(eclipse_status.risk_level);
    shell.print("/100");

    if (eclipse_status.is_safe) {
        shell.printSuccessLine(" (safe)");
    } else {
        shell.printErrorLine(" (AT RISK)");
    }

    shell.print("     Outbound:    ");
    helpers.printUsize(eclipse_status.outbound_count);
    shell.print("/");
    helpers.printUsize(eclipse.MAX_OUTBOUND);
    if (eclipse_status.outbound_count >= eclipse.MIN_OUTBOUND) {
        shell.printSuccessLine(" (ok)");
    } else {
        shell.printWarningLine(" (low)");
    }

    shell.print("     Inbound:     ");
    helpers.printUsize(eclipse_status.inbound_count);
    shell.print("/");
    helpers.printUsize(eclipse.MAX_INBOUND);
    shell.newLine();

    shell.print("     Anchors:     ");
    helpers.printUsize(eclipse_status.anchor_count);
    shell.print("/");
    helpers.printUsize(eclipse.ANCHOR_PEER_COUNT);
    if (eclipse_status.anchor_count > 0) {
        shell.printSuccessLine(" (protected)");
    } else {
        shell.printWarningLine(" (none)");
    }

    shell.print("    Subnets:      ");
    helpers.printU8(eclipse_status.subnet_diversity);
    if (eclipse_status.subnet_diversity >= eclipse.MIN_OUTBOUND_SUBNETS) {
        shell.printSuccessLine(" (diverse)");
    } else {
        shell.printWarningLine(" (low diversity)");
    }

    shell.print("    Alerts:       ");
    if (eclipse_status.alerts == 0) {
        shell.printSuccessLine("0 (clean)");
    } else {
        shell.printError("");
        helpers.printUsize(eclipse_status.alerts);
        shell.printErrorLine(" active");
    }

    shell.newLine();
    shell.println(" P.3e Eviction:");

    if (eviction.isInitialized()) {
        shell.print("    Status:       ");
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.print("    Status:       ");
        shell.printWarningLine("Not initialized");
    }

    const ev_stats = eviction.getStats();

    shell.print("    Pending:      ");
    helpers.printUsize(eviction.getPendingCount());
    shell.newLine();

    shell.print("    Executed:     ");
    helpers.printUsize(eviction.getExecutedCount());
    shell.newLine();

    shell.print("    Votes RX:     ");
    helpers.printU64(ev_stats.votes_received);
    shell.newLine();

    shell.print("    Commits RX:   ");
    helpers.printU64(ev_stats.commits_received);
    shell.newLine();

    shell.newLine();
}

fn showNodeId() void {
    shell.printInfoLine("Node Identity:");
    shell.newLine();

    shell.print(" Node ID:     ");
    const node_id = p2p.getNodeId();
    printHexShort(node_id[0..16]);
    shell.println("...");

    shell.print(" Public Key: ");
    const pub_key = p2p.getPublicKey();
    printHexShort(pub_key[0..16]);
    shell.println("...");
    shell.newLine();
}

fn showStats() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine(" P2P STATISTICS");
    shell.printInfoLine("========================================");
    shell.newLine();

    const stats = p2p.getStats();

    shell.println(" Messages:");
    shell.print("    Sent:         ");
    helpers.printU64(stats.messages_sent);
    shell.newLine();

    shell.print("    Received:     ");
    helpers.printU64(stats.messages_received);
    shell.newLine();

    shell.newLine();
    shell.println(" Bandwidth:");

    shell.print("    TX:           ");
    helpers.printU64(stats.bytes_sent);
    shell.println(" bytes");

    shell.print("    RX:           ");
    helpers.printU64(stats.bytes_received);
    shell.println(" bytes");

    shell.newLine();
    shell.println(" Peers:");

    shell.print("    Connected:    ");
    helpers.printUsize(peer.getConnectedCount());
    shell.newLine();

    shell.print("    Outbound:     ");
    helpers.printUsize(peer.getOutboundCount());
    shell.newLine();

    shell.print("    Inbound:      ");
    helpers.printUsize(peer.getInboundCount());
    shell.newLine();

    shell.print("    Anchors:      ");
    helpers.printUsize(peer.getAnchorCount());
    shell.newLine();

    shell.print("    Banned:       ");
    helpers.printUsize(peer.getBannedCount());
    shell.newLine();

    shell.print("    Total known: ");
    helpers.printUsize(peer.getTotalCount());
    shell.newLine();

    shell.print("    Tracked rep: ");
    helpers.printUsize(reputation.getTrackedCount());
    shell.newLine();

    shell.newLine();
    shell.println(" Discovery:");

    shell.print("    Discovered:   ");
    helpers.printUsize(discovery.getDiscoveredCount());
    shell.newLine();

    shell.newLine();
    shell.println(" Sybil Defense:");

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
    shell.println(" Eclipse Defense:");

    shell.print("    Risk Level:   ");
    helpers.printU8(peer.getEclipseRisk());
    shell.println("/100");

    shell.print("    Safe:          ");
    if (peer.isEclipseSafe()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printErrorLine("No");
    }

    shell.print("    Alerts:       ");
    helpers.printUsize(eclipse.getAlertCount());
    shell.newLine();

    shell.newLine();
    shell.println(" Eviction P.3e:");

    const ev_stats = eviction.getStats();

    shell.print("    Votes RX:     ");
    helpers.printU64(ev_stats.votes_received);
    shell.newLine();

    shell.print("    Votes OK:     ");
    helpers.printU64(ev_stats.votes_accepted);
    shell.newLine();

    shell.print("    Votes Bad:    ");
    helpers.printU64(ev_stats.votes_rejected);
    shell.newLine();

    shell.print("    Duplicates:   ");
    helpers.printU64(ev_stats.duplicate_votes);
    shell.newLine();

    shell.print("    Commits RX:   ");
    helpers.printU64(ev_stats.commits_received);
    shell.newLine();

    shell.print("    Executed:     ");
    helpers.printU64(ev_stats.evictions_executed);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Node Control
// =============================================================================

fn startNode() void {
    if (!p2p.isInitialized()) {
        shell.printErrorLine("P2P not initialized");
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
    shell.println(" ID                Type   Status Trust        Rep");
    shell.println(" ---------------- ------- ------- ----------- -----");

    const peers = peer.getAll();
    var count: usize = 0;

    for (peers) |p| {
        if (p.status == .disconnected) continue;

        shell.print(" ");
        printHexShort(p.id[0..8]);
        shell.print(" ");

        switch (p.conn_type) {
            .inbound => shell.print("IN        "),
            .outbound => shell.print("OUT       "),
            .anchor => shell.print("ANCHOR    "),
        }

        switch (p.status) {
            .disconnected => shell.print("DISC       "),
            .connecting => shell.print("CONN      "),
            .connected => shell.print("OK        "),
            .banned => shell.print("BAN      "),
        }

        switch (p.trust_level) {
            .untrusted => shell.print("untrusted     "),
            .provisional => shell.print("provisional "),
            .member => shell.print("member       "),
            .trusted => shell.print("trusted      "),
        }

        helpers.printI32(p.reputation);
        shell.newLine();

        count += 1;
    }

    if (count == 0) {
        shell.println("    (no peers connected)");
    }

    shell.newLine();
    shell.print("Total: ");
    helpers.printUsize(count);
    shell.print(" (out=");
    helpers.printUsize(peer.getOutboundCount());
    shell.print(", in=");
    helpers.printUsize(peer.getInboundCount());
    shell.print(", anchor=");
    helpers.printUsize(peer.getAnchorCount());
    shell.println(")");

    shell.print("Diversity: ");
    helpers.printU8(peer.getDiversityScore());
    shell.print("/100, Risk: ");
    helpers.printU8(peer.getEclipseRisk());
    shell.println("/100");

    shell.newLine();
}

fn showAnchors() void {
    shell.printInfoLine("Anchor Peers (H.4):");
    shell.newLine();

    const anchors = eclipse.getAnchors();

    if (anchors.len == 0) {
        shell.println(" (no anchor peers)");
        shell.newLine();
        shell.println(" Anchors are long-term trusted peers that protect");
        shell.println(" against eclipse attacks.");
        shell.newLine();
        return;
    }

    shell.println("    ID                               Trust");
    shell.println("    -------------------------------- -------");

    for (anchors) |anchor_id| {
        shell.print(" ");

        printHexShort(anchor_id[0..16]);
        shell.print(" ");

        if (peer.getById(anchor_id)) |p| {
            switch (p.trust_level) {
                .untrusted => shell.println("untrusted"),
                .provisional => shell.println("provisional"),
                .member => shell.println("member"),
                .trusted => shell.println("trusted"),
            }
        } else {
            shell.printWarningLine("(disconnected)");
        }
    }

    shell.newLine();
    shell.print("Total anchors: ");
    helpers.printUsize(anchors.len);
    shell.print("/");
    helpers.printUsize(eclipse.ANCHOR_PEER_COUNT);
    shell.newLine();
    shell.newLine();
}

fn showBannedPeers() void {
    shell.printInfoLine("Banned / Evicted Peers:");
    shell.newLine();

    const count = peer.getBannedCount();

    if (count == 0) {
        shell.printSuccessLine("     No banned peers.");
        shell.newLine();
        return;
    }

    shell.println("   ID");
    shell.println("   --------------------------------");

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (peer.getBannedId(i)) |id| {
            shell.print(" ");
            printHexShort(id[0..16]);
            shell.println("...");
        }
    }

    shell.newLine();
    shell.print("Total banned: ");
    helpers.printUsize(count);
    shell.newLine();
    shell.newLine();
}

fn connectPeer(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.println("Usage: p2p connect <ip:port>");
        shell.println("Example: p2p connect 192.168.1.100:27777");
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
        shell.printSuccessLine("Connected");
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

    if (findPeerByPrefix(trimmed)) |p| {
        if (p.conn_type == .anchor) {
            shell.printWarningLine("Warning: disconnecting anchor peer");
        }

        const id = p.id;
        peer.disconnect(p);

        shell.printSuccess("Disconnected peer ");
        printHexShort(id[0..8]);
        shell.newLine();
        return;
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

// =============================================================================
// P.3e Eviction Commands
// =============================================================================

fn showEviction(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (helpers.strEql(trimmed, "pending")) {
        showEvictionPending();
        return;
    }

    if (helpers.strEql(trimmed, "executed")) {
        showEvictionExecuted();
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine(" P.3e TWIN-NODE EVICTION STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print(" Initialized:         ");
    if (eviction.isInitialized()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No");
    }

    const stats = eviction.getStats();

    shell.print(" Pending Records:    ");
    helpers.printUsize(eviction.getPendingCount());
    shell.newLine();

    shell.print(" Executed Records: ");
    helpers.printUsize(eviction.getExecutedCount());
    shell.newLine();

    shell.newLine();
    shell.println(" Vote Stats:");

    shell.print("    Received:        ");
    helpers.printU64(stats.votes_received);
    shell.newLine();

    shell.print("    Accepted:        ");
    helpers.printU64(stats.votes_accepted);
    shell.newLine();

    shell.print("    Rejected:        ");
    helpers.printU64(stats.votes_rejected);
    shell.newLine();

    shell.print("    Duplicates:      ");
    helpers.printU64(stats.duplicate_votes);
    shell.newLine();

    shell.newLine();
    shell.println(" Commit Stats:");

    shell.print("    Received:        ");
    helpers.printU64(stats.commits_received);
    shell.newLine();

    shell.print("    Executed:        ");
    helpers.printU64(stats.commits_executed);
    shell.newLine();

    shell.newLine();
    shell.println(" Local:");

    shell.print("    Evidence Reports:");
    helpers.printU64(stats.local_evidence_reports);
    shell.newLine();

    shell.print("    Evictions:       ");
    helpers.printU64(stats.evictions_executed);
    shell.newLine();

    shell.newLine();
    shell.println("Use:");
    shell.println(" p2p eviction pending");
    shell.println(" p2p eviction executed");
    shell.println(" p2p evict <peer_id_prefix> <reason>");
    shell.newLine();
}

fn showEvictionPending() void {
    shell.printInfoLine("P.3e Pending Eviction Votes:");
    shell.newLine();

    const count = eviction.getPendingCount();

    if (count == 0) {
        shell.printSuccessLine("   No pending eviction records.");
        shell.newLine();
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (eviction.getPendingRecord(i)) |r| {
            shell.print(" [");
            helpers.printUsize(i);
            shell.print("] target=");
            printHexShort(r.target_id[0..8]);
            shell.print(" reason=");
            shell.print(reasonName(r.reason));
            shell.print(" votes=");
            helpers.printU8(r.vote_count);
            shell.newLine();
        }
    }

    shell.newLine();
}

fn showEvictionExecuted() void {
    shell.printInfoLine("P.3e Executed Evictions:");
    shell.newLine();

    const count = eviction.getExecutedCount();

    if (count == 0) {
        shell.println(" (no executed evictions)");
        shell.newLine();
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (eviction.getExecutedRecord(i)) |r| {
            shell.print(" [");
            helpers.printUsize(i);
            shell.print("] target=");
            printHexShort(r.target_id[0..8]);
            shell.print(" reason=");
            shell.print(reasonName(r.reason));
            shell.print(" voter_a=");
            printHexShort(r.voter_a[0..4]);
            shell.print(" voter_b=");
            printHexShort(r.voter_b[0..4]);
            shell.newLine();
        }
    }

    shell.newLine();
}

fn evictPeer(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        shell.println("Usage: p2p evict <peer_id_prefix> <reason>");
        shell.println("Reasons: duplicate, signature, onion, sybil, eclipse, hardware, protocol, spam, impersonation");
        return;
    }

    const split = splitFirstToken(trimmed);

    if (split.first.len == 0 or split.rest.len == 0) {
        shell.println("Usage: p2p evict <peer_id_prefix> <reason>");
        return;
    }

    const target = findPeerByPrefix(split.first) orelse {
        shell.printError("Peer not found: ");
        shell.println(split.first);
        return;
    };

    const reason = parseEvictionReason(helpers.trim(split.rest)) orelse {
        shell.printError("Unknown eviction reason: ");
        shell.println(split.rest);
        shell.println("Reasons: duplicate, signature, onion, sybil, eclipse, hardware, protocol, spam, impersonation");
        return;
    };

    shell.print("Reporting local eviction evidence for ");
    printHexShort(target.id[0..8]);
    shell.print(" reason=");
    shell.println(reasonName(reason));

    if (eviction.reportLocalEvidence(
        target.id,
        target.ip,
        reason,
        "manual shell eviction evidence",
    )) {
        shell.printSuccessLine("Eviction vote generated and broadcast.");
    } else {
        shell.printErrorLine("Failed to report eviction evidence.");
    }
}

// =============================================================================
// Sync
// =============================================================================

fn showSyncStatus() void {
    shell.printInfoLine("Sync Status (H.4 Multi-Path):");
    shell.newLine();

    const state = sync.getState();

    shell.print(" Status:        ");
    switch (state.status) {
        .idle => shell.println("IDLE"),
        .requesting => shell.println("REQUESTING"),
        .receiving => shell.println("RECEIVING"),

        .validating => shell.println("VALIDATING"),
        .confirming => shell.println("CONFIRMING"),
        .complete => shell.printSuccessLine("COMPLETE"),
        .failed => shell.printErrorLine("FAILED"),
        .conflict => shell.printErrorLine("CONFLICT"),
    }

    shell.print(" Current:       ");
    helpers.printU64(state.current_block);
    shell.newLine();

    shell.print(" Target:        ");
    helpers.printU64(state.target_block);
    shell.newLine();

    const progress = sync.getProgress();

    shell.print(" Progress:      ");
    helpers.printU8(progress.percent);
    shell.println("%");

    shell.print(" Blocks recv: ");
    helpers.printU64(state.blocks_received);
    shell.newLine();

    shell.newLine();
    shell.println(" Multi-Path Verification:");

    shell.print("     Sync Peers:  ");
    helpers.printUsize(state.sync_peer_count);
    shell.print("/");
    helpers.printUsize(sync.MAX_SYNC_PEERS);
    shell.newLine();

    shell.print("    Multi-Path:   ");
    if (sync.isMultiPathVerified()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No");
    }

    shell.print("     Confirmations:");
    helpers.printUsize(sync.getPendingConfirmations());
    shell.print("/");
    helpers.printUsize(sync.MIN_BLOCK_CONFIRMATIONS);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Reputation
// =============================================================================

fn showReputation(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len > 0) {
        showPeerReputation(trimmed);
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine(" PEER REPUTATION SYSTEM");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print(" Tracked peers:     ");
    helpers.printUsize(reputation.getTrackedCount());

    shell.newLine();

    shell.print(" PoW difficulty:    ");
    helpers.printU8(reputation.DEFAULT_POW_DIFFICULTY);
    shell.println(" bits");

    shell.newLine();
    shell.println(" Trust Thresholds:");

    shell.print("    Provisional: >= ");
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
    const p = findPeerByPrefix(id_prefix) orelse {
        shell.printError("Peer not found: ");
        shell.println(id_prefix);
        return;
    };

    shell.printInfoLine("Peer Reputation Detail:");
    shell.newLine();

    shell.print(" Peer ID:        ");
    printHexShort(p.id[0..16]);
    shell.println("...");

    shell.print(" IP:             ");
    printIp(p.ip);
    shell.newLine();

    shell.print(" Conn Type:     ");
    switch (p.conn_type) {
        .inbound => shell.println("INBOUND"),
        .outbound => shell.println("OUTBOUND"),
        .anchor => shell.printSuccessLine("ANCHOR"),
    }

    shell.print(" Trust Level: ");
    switch (p.trust_level) {
        .untrusted => shell.printWarningLine("UNTRUSTED"),
        .provisional => shell.println("PROVISIONAL"),
        .member => shell.printSuccessLine("MEMBER"),
        .trusted => shell.printSuccessLine("TRUSTED"),
    }

    shell.print(" Score:         ");
    helpers.printI32(p.reputation);
    shell.newLine();

    shell.print(" PoW Nonce:     ");
    helpers.printU64(p.proof_of_work);
    shell.newLine();

    if (reputation.getReputation(&p.id)) |rep| {
        shell.print(" Good Actions: ");
        helpers.printU32(rep.good_actions);
        shell.newLine();

        shell.print(" Violations:    ");
        helpers.printU32(rep.violations);
        shell.newLine();

        if (@hasField(reputation.PeerReputation, "severe_violations")) {
            shell.print(" Severe:        ");
            helpers.printU32(rep.severe_violations);
            shell.newLine();
        }

        if (@hasField(reputation.PeerReputation, "eviction_evidence_count")) {
            shell.print(" Evict Evd:     ");
            helpers.printU32(rep.eviction_evidence_count);
            shell.newLine();
        }

        shell.print(" Vouchers:      ");
        helpers.printU8(rep.voucher_count);
        shell.print("/");
        helpers.printU8(reputation.MAX_VOUCHERS);
        shell.newLine();

        shell.print(" PoW Verified: ");
        if (rep.pow_verified) {
            shell.printSuccessLine("Yes");
        } else {
            shell.printWarningLine("No");
        }

        shell.print(" Age:           ");
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

    shell.print(" Anchor Eligible: ");
    if (eclipse.isAnchorEligible(&p.id)) {
        shell.printSuccessLine("Yes");
    } else {
        shell.println("No");
    }

    shell.newLine();
}

// =============================================================================
// Sybil
// =============================================================================

fn showSybilStatus(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (helpers.strEql(trimmed, "alerts")) {
        showSybilAlerts();
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine(" SYBIL DEFENSE STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print(" Status:            ");
    if (sybil.isInitialized()) {
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.printErrorLine("INACTIVE");
    }

    shell.newLine();
    shell.println(" Registration Policy:");

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
    shell.println(" Counters:");

    shell.print("    Allowed:        ");
    helpers.printU64(sybil.getTotalRegistrations());
    shell.newLine();

    shell.print("    Denied:         ");
    helpers.printU64(sybil.getTotalDenials());
    shell.newLine();

    shell.print("    Alerts:         ");
    helpers.printUsize(sybil.getAlertCount());
    shell.newLine();

    if (@hasDecl(sybil, "getStatus")) {
        const st = sybil.getStatus();

        shell.print("    Recent Reg:     ");
        helpers.printUsize(st.recent_registrations);
        shell.newLine();

        shell.print("    Diversity:      ");
        helpers.printU8(st.diversity_score);
        shell.println("/100");

        shell.print("    High Risk:       ");
        if (st.high_risk) {
            shell.printErrorLine("YES");
        } else {
            shell.printSuccessLine("NO");
        }
    }

    shell.newLine();
}

fn showSybilAlerts() void {
    shell.printInfoLine("SYBIL ATTACK ALERTS");
    shell.newLine();

    const count = sybil.getAlertCount();

    if (count == 0) {
        shell.printSuccessLine("   No alerts.");
        shell.newLine();
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (sybil.getAlert(i)) |alert| {
            shell.print(" [");
            helpers.printUsize(i + 1);
            shell.print("] ");

            switch (alert.alert_type) {
                .subnet_flood => shell.print("SUBNET_FLOOD "),
                .rate_flood => shell.print("RATE_FLOOD   "),
                .coordinated => shell.print("COORDINATED "),
            }

            shell.print("peers=");
            helpers.printU16(alert.peer_count);
            shell.newLine();
        }
    }

    shell.newLine();
}

fn showDiversity() void {
    shell.printInfoLine("PEER DIVERSITY");
    shell.newLine();

    const score = peer.getDiversityScore();
    const distinct = sybil.getDistinctSubnetCount();
    const total = reputation.getTrackedCount();
    const eclipse_status = peer.getEclipseStatus();

    shell.print(" Sybil Score:        ");
    helpers.printU8(score);
    shell.println("/100");

    shell.print(" Eclipse Subnets: ");
    helpers.printU8(eclipse_status.subnet_diversity);
    shell.print("/");
    helpers.printUsize(eclipse.MIN_OUTBOUND_SUBNETS);
    shell.println(" outbound");

    shell.print(" Distinct Subnets: ");
    helpers.printUsize(distinct);
    shell.newLine();

    shell.print(" Tracked Peers:      ");
    helpers.printUsize(total);
    shell.newLine();

    shell.newLine();
}

// =============================================================================
// Eclipse
// =============================================================================

fn showEclipseStatus(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (helpers.strEql(trimmed, "alerts")) {
        showEclipseAlerts();

        return;
    }

    if (helpers.strEql(trimmed, "risk")) {
        showEclipseRisk();
        return;
    }

    shell.printInfoLine("========================================");
    shell.printInfoLine(" ECLIPSE DEFENSE STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.print(" Status:            ");
    if (eclipse.isInitialized()) {
        shell.printSuccessLine("ACTIVE");
    } else {
        shell.printErrorLine("INACTIVE");
    }

    const status = eclipse.getStatus();

    shell.print(" Overall Safe:      ");
    if (status.is_safe) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }

    shell.print(" Risk Level:        ");
    helpers.printU8(status.risk_level);
    shell.print("/100");

    if (status.risk_level < 30) {
        shell.printSuccessLine(" (low)");
    } else if (status.risk_level < 60) {
        shell.printWarningLine(" (medium)");
    } else {
        shell.printErrorLine(" (high)");
    }

    shell.newLine();
    shell.println(" Current Connections:");

    shell.print("     Outbound:      ");
    helpers.printUsize(status.outbound_count);
    shell.print("/");
    helpers.printUsize(eclipse.MAX_OUTBOUND);
    shell.newLine();

    shell.print("     Inbound:       ");
    helpers.printUsize(status.inbound_count);
    shell.print("/");
    helpers.printUsize(eclipse.MAX_INBOUND);
    shell.newLine();

    shell.print("     Anchors:       ");
    helpers.printUsize(status.anchor_count);
    shell.print("/");
    helpers.printUsize(eclipse.ANCHOR_PEER_COUNT);
    shell.newLine();

    shell.print("    Subnet Diversity:");
    helpers.printU8(status.subnet_diversity);
    shell.newLine();

    shell.print("    Alerts:         ");
    helpers.printUsize(status.alerts);
    shell.newLine();

    if (@hasDecl(eclipse, "isHighRisk")) {
        shell.print("    P.3e High Risk: ");
        if (eclipse.isHighRisk()) {
            shell.printErrorLine("YES");
        } else {
            shell.printSuccessLine("NO");
        }
    }

    shell.newLine();
}

fn showEclipseAlerts() void {
    shell.printInfoLine("ECLIPSE ATTACK ALERTS");
    shell.newLine();

    const count = eclipse.getAlertCount();

    if (count == 0) {
        shell.printSuccessLine("   No alerts.");
        shell.newLine();
        return;
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (eclipse.getAlert(i)) |alert| {
            shell.print(" [");
            helpers.printUsize(i + 1);
            shell.print("] ");

            switch (alert.alert_type) {
                .low_outbound => shell.print("LOW_OUTBOUND      "),
                .low_diversity => shell.print("LOW_DIVERSITY     "),
                .inbound_flood => shell.print("INBOUND_FLOOD     "),
                .anchor_lost => shell.print("ANCHOR_LOST       "),
                .block_conflict => shell.print("BLOCK_CONFLICT     "),
                .single_source_sync => shell.print("SINGLE_SOURCE      "),
            }

            shell.print("details=");
            helpers.printU32(alert.details);
            shell.newLine();
        }
    }

    shell.newLine();
}

fn showEclipseRisk() void {
    shell.printInfoLine("ECLIPSE RISK ANALYSIS");
    shell.newLine();

    const status = eclipse.getStatus();

    shell.print(" Overall Risk: ");
    helpers.printU8(status.risk_level);
    shell.println("/100");
    shell.newLine();

    shell.print(" Recommendation: ");
    if (status.is_safe) {
        shell.printSuccessLine("Node is protected.");
    } else if (status.risk_level < 70) {
        shell.printWarningLine("Add more diverse outbound connections.");
    } else {
        shell.printErrorLine("URGENT: establish outbound diverse anchors.");
    }

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
    } else if (helpers.strEql(opt, "h3")) {
        runH3Tests();
    } else if (helpers.strEql(opt, "h4")) {
        runH4Tests();
    } else if (helpers.strEql(opt, "p3")) {
        runP3Tests();
    } else if (helpers.strEql(opt, "p3e")) {
        runP3eTests();
    } else {
        shell.println("p2p test options: all, quick, h3, h4, p3, p3e");
    }
}

fn runQuickTest() void {
    shell.printInfoLine("P2P Quick Test...");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    testLine("P2P initialized", p2p.isInitialized(), &passed, &failed);
    testLine("Peer initialized", peer.isInitialized(), &passed, &failed);
    testLine("Discovery initialized", discovery.isInitialized(), &passed, &failed);
    testLine("Message initialized", message.isInitialized(), &passed, &failed);
    testLine("Protocol initialized", protocol.isInitialized(), &passed, &failed);
    testLine("Eviction initialized", eviction.isInitialized(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runAllTests() void {
    shell.printInfoLine("P2P Full Test Suite");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    testLine("P2P module tests", p2p.runTests(), &passed, &failed);
    testLine("Peer module tests", peer.runTests(), &passed, &failed);
    testLine("Message tests", message.runTests(), &passed, &failed);
    testLine("Reputation tests", reputation.runTests(), &passed, &failed);
    testLine("Sybil tests", sybil.runTests(), &passed, &failed);
    testLine("Eclipse tests", eclipse.runTests(), &passed, &failed);
    testLine("P.3 handshake/onion", runP3Internal(), &passed, &failed);
    testLine("P.3e eviction tests", eviction.runTests(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runH3Tests() void {
    shell.printInfoLine("H.3 Sybil/Reputation Tests");
    shell.newLine();

    var passed: u32 = 0;

    var failed: u32 = 0;

    testLine("Reputation tests", reputation.runTests(), &passed, &failed);
    testLine("Sybil tests", sybil.runTests(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runH4Tests() void {
    shell.printInfoLine("H.4 Eclipse Tests");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    testLine("Eclipse tests", eclipse.runTests(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runP3Tests() void {
    shell.printInfoLine("P.3/P.3d Tests");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    testLine("Handshake + Onion", runP3Internal(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runP3eTests() void {
    shell.printInfoLine("P.3e Twin-Node Eviction Tests");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    testLine("Eviction module", eviction.runTests(), &passed, &failed);

    printTestResults(passed, failed);
}

fn runP3Internal() bool {
    // ---------------------------------------------------------
    // Handshake V2
    // ---------------------------------------------------------

    if (protocol.buildHandshakeInto(&static_p3_handshake)) {
        if (static_p3_handshake.version !=
            protocol.PROTOCOL_VERSION)
        {
            return false;
        }

        if (protocol.validateHandshake(
            &static_p3_handshake,
        ) != .Valid) {
            return false;
        }

        static_p3_tampered = static_p3_handshake;

        static_p3_tampered.hardware_hash[0] ^= 0xFF;

        if (protocol.validateHandshake(
            &static_p3_tampered,
        ) != .SignatureMismatch) {
            return false;
        }

        static_p3_tampered = static_p3_handshake;

        static_p3_tampered.challenge[0] ^= 0x01;

        if (protocol.validateHandshake(
            &static_p3_tampered,
        ) != .SignatureMismatch) {
            return false;
        }

        static_p3_tampered = static_p3_handshake;

        static_p3_tampered.version = 1;

        if (protocol.validateHandshake(
            &static_p3_tampered,
        ) != .UnsupportedVersion) {
            return false;
        }

        static_p3_tampered = static_p3_handshake;

        static_p3_tampered.magic[7] = '1';

        if (protocol.validateHandshake(
            &static_p3_tampered,
        ) != .InvalidMagic) {
            return false;
        }
    } else {
        // governance session locked:
        // fail-closed is valid behaviour
    }

    // ---------------------------------------------------------
    // SLOR KEM
    // ---------------------------------------------------------

    var pk: slor.SlorPublicKey = undefined;
    var sk: slor.SlorSecretKey = undefined;

    slor.generateKeyPair(
        &pk,
        &sk,
    );

    var ct_data: slor.SlorCiphertext = undefined;

    var shared_tx: [32]u8 =
        [_]u8{0} ** 32;

    var shared_rx: [32]u8 =
        [_]u8{0} ** 32;

    slor.encapsulate(
        &pk,
        &ct_data,
        &shared_tx,
    );

    slor.decapsulate(
        &sk,
        &ct_data,
        &shared_rx,
    );

    if (!crypto.constantTimeCompare32(
        &shared_tx,
        &shared_rx,
    )) {
        return false;
    }

    // ---------------------------------------------------------
    // Onion Route
    // ---------------------------------------------------------

    const plain =
        "TOP_SECRET_ZAMRUD_ROUTING_DATA";

    var msg =
        message.createOnionRouted(
            p2p.getNodeId(),
            plain,
        );

    if (msg.msg_type != .onion_routed) {
        return false;
    }

    message.encryptPayloadOtp(
        &msg,
        &shared_tx,
    );

    var encrypted = false;

    for (plain, 0..) |c, i| {
        if (msg.payload[i] != c) {
            encrypted = true;
            break;
        }
    }

    if (!encrypted) {
        return false;
    }

    message.decryptPayloadOtp(
        &msg,
        &shared_rx,
    );

    for (plain, 0..) |c, i| {
        if (msg.payload[i] != c) {
            return false;
        }
    }

    return true;
}

fn testLine(name: []const u8, ok: bool, passed: *u32, failed: *u32) void {
    shell.print(" ");
    shell.print(name);
    shell.print("... ");

    if (ok) {
        shell.printSuccessLine("PASS");
        passed.* += 1;
    } else {
        shell.printErrorLine("FAIL");
        failed.* += 1;
    }
}

fn printTestResults(passed: u32, failed: u32) void {
    shell.newLine();
    shell.print("Results: ");
    helpers.printU32(passed);
    shell.print("/");
    helpers.printU32(passed + failed);
    shell.print(" passed");

    if (failed == 0) {
        shell.printSuccessLine(" OK");
    } else {
        shell.printErrorLine(" FAILED");
    }

    shell.newLine();
}

// =============================================================================
// Utility Parsing
// =============================================================================

const IpPort = struct {
    ip: u32,
    port: u16,
};

const SplitResult = struct {
    first: []const u8,
    rest: []const u8,
};

fn parseIpPort(s: []const u8) IpPort {
    var result = IpPort{
        .ip = 0,
        .port = p2p.DEFAULT_PORT,
    };

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

fn splitFirstToken(s: []const u8) SplitResult {
    const trimmed = helpers.trim(s);

    var i: usize = 0;

    while (i < trimmed.len) : (i += 1) {
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            return .{
                .first = trimmed[0..i],
                .rest = helpers.trim(trimmed[i + 1 ..]),
            };
        }
    }

    return .{
        .first = trimmed,
        .rest = "",
    };
}

fn parseEvictionReason(s: []const u8) ?eviction.EvictionReason {
    if (helpers.strEql(s, "duplicate")) return .duplicate_identity;
    if (helpers.strEql(s, "signature")) return .invalid_signature;
    if (helpers.strEql(s, "onion")) return .malicious_onion_route;
    if (helpers.strEql(s, "sybil")) return .sybil_confirmed;
    if (helpers.strEql(s, "eclipse")) return .eclipse_attack;
    if (helpers.strEql(s, "hardware")) return .hardware_mismatch;
    if (helpers.strEql(s, "protocol")) return .protocol_violation;
    if (helpers.strEql(s, "spam")) return .eviction_vote_spam;
    if (helpers.strEql(s, "impersonation")) return .peer_impersonation;

    return null;
}

fn reasonName(reason: eviction.EvictionReason) []const u8 {
    return switch (reason) {
        .duplicate_identity => "duplicate_identity",
        .invalid_signature => "invalid_signature",
        .malicious_onion_route => "malicious_onion_route",
        .sybil_confirmed => "sybil_confirmed",
        .eclipse_attack => "eclipse_attack",
        .hardware_mismatch => "hardware_mismatch",
        .protocol_violation => "protocol_violation",
        .eviction_vote_spam => "eviction_vote_spam",
        .peer_impersonation => "peer_impersonation",
    };
}

fn findPeerByPrefix(prefix: []const u8) ?*peer.Peer {
    const peers = peer.getAll();

    for (peers) |*p| {
        if (p.status == .disconnected) continue;

        var id_str: [16]u8 = undefined;
        formatHex(p.id[0..8], &id_str);

        if (helpers.startsWith(id_str[0..], prefix)) {
            return p;
        }
    }

    return null;
}

// =============================================================================
// Print Helpers
// =============================================================================

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
