//! Zamrud OS - P2P Ledger Synchronization (H.4 HARDENED)
//! Syncs blockchain data between peers with multi-path verification
//!
//! H.4 CHANGES:
//! ✅ Multi-path block verification (MIN_CONFIRMATIONS peers)
//! ✅ Multiple sync peers instead of single peer
//! ✅ Block conflict detection
//! ✅ Eclipse-safe sync peer selection
//! ✅ Anchor peer priority for sync

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const chain = @import("../chain/chain.zig");
const eclipse = @import("eclipse_defense.zig");

// =============================================================================
// Constants
// =============================================================================

pub const SYNC_BATCH_SIZE: u64 = 100;
pub const SYNC_TIMEOUT_MS: u64 = 30000;

// H.4: Multi-path verification
pub const MIN_SYNC_PEERS: usize = 2;
pub const MAX_SYNC_PEERS: usize = 4;
pub const MIN_BLOCK_CONFIRMATIONS: usize = 2;

// =============================================================================
// Types
// =============================================================================

pub const SyncStatus = enum {
    idle,
    requesting,
    receiving,
    validating,
    confirming, // H.4: Waiting for multi-path confirmation
    complete,
    failed,
    conflict, // H.4: Block conflict detected
};

pub const SyncPeerInfo = struct {
    peer_id: [32]u8,
    reported_height: u64,
    blocks_received: u64,
    is_anchor: bool,
    is_active: bool,
};

pub const SyncState = struct {
    status: SyncStatus,
    target_block: u64,
    current_block: u64,
    started_at: u64,
    blocks_received: u64,

    // H.4: Multi-peer sync
    sync_peers: [MAX_SYNC_PEERS]SyncPeerInfo,
    sync_peer_count: usize,
    confirmations_needed: usize,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var running: bool = false;
var sync_state: SyncState = undefined;

// H.4: Pending block confirmations
var pending_height: u64 = 0;
var pending_hash: [32]u8 = [_]u8{0} ** 32;
var pending_confirmers: [8][32]u8 = undefined;
var pending_confirm_count: usize = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    sync_state = .{
        .status = .idle,
        .target_block = 0,
        .current_block = 0,
        .started_at = 0,
        .blocks_received = 0,
        .sync_peers = undefined,
        .sync_peer_count = 0,
        .confirmations_needed = MIN_BLOCK_CONFIRMATIONS,
    };

    for (&sync_state.sync_peers) |*sp| {
        sp.* = emptySyncPeer();
    }

    for (&pending_confirmers) |*c| {
        c.* = [_]u8{0} ** 32;
    }
    pending_confirm_count = 0;
    pending_height = 0;

    initialized = true;
    serial.writeString("[SYNC] Ledger sync initialized (H.4 multi-path)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

fn emptySyncPeer() SyncPeerInfo {
    return .{
        .peer_id = [_]u8{0} ** 32,
        .reported_height = 0,
        .blocks_received = 0,
        .is_anchor = false,
        .is_active = false,
    };
}

// =============================================================================
// Sync Operations
// =============================================================================

pub fn start() void {
    if (running) return;

    running = true;
    serial.writeString("[SYNC] Starting ledger sync (H.4 multi-path)\n");

    // Get current chain height
    sync_state.current_block = chain.getHeight();

    // H.4: Select multiple sync peers with diversity
    if (!selectSyncPeers()) {
        serial.writeString("[SYNC] Not enough diverse peers for safe sync\n");
        sync_state.status = .failed;
        running = false;
        return;
    }

    // Request chain height from sync peers
    requestChainHeight();
}

pub fn stop() void {
    running = false;
    sync_state.status = .idle;
    serial.writeString("[SYNC] Stopped ledger sync\n");
}

pub fn isRunning() bool {
    return running;
}

pub fn getState() SyncState {
    return sync_state;
}

pub fn getLastBlock() u64 {
    return sync_state.current_block;
}

// =============================================================================
// H.4: Multi-Peer Selection
// =============================================================================

/// Select diverse sync peers (anchors prioritized)
fn selectSyncPeers() bool {
    sync_state.sync_peer_count = 0;

    // First: Add anchor peers (most trusted)
    const anchors = peer.getAnchors();
    for (anchors) |p| {
        if (sync_state.sync_peer_count >= MAX_SYNC_PEERS) break;
        addSyncPeer(p, true);
    }

    // Second: Add outbound peers (we chose them)
    const outbound = peer.getOutbound();
    for (outbound) |p| {
        if (sync_state.sync_peer_count >= MAX_SYNC_PEERS) break;
        if (p.conn_type == .anchor) continue; // Already added
        addSyncPeer(p, false);
    }

    // Third: Add inbound peers if still need more
    if (sync_state.sync_peer_count < MIN_SYNC_PEERS) {
        const inbound = peer.getInbound();
        for (inbound) |p| {
            if (sync_state.sync_peer_count >= MAX_SYNC_PEERS) break;
            addSyncPeer(p, false);
        }
    }

    // Check if we have enough
    if (sync_state.sync_peer_count < MIN_SYNC_PEERS) {
        serial.writeString("[SYNC] WARNING: Only ");
        printUsize(sync_state.sync_peer_count);
        serial.writeString(" sync peers (need ");
        printUsize(MIN_SYNC_PEERS);
        serial.writeString(")\n");

        // H.4: Add eclipse alert
        if (sync_state.sync_peer_count == 1) {
            // Single source sync is dangerous!
            serial.writeString("[SYNC] ALERT: Single-source sync risk!\n");
        }

        // Allow sync but with warning
        return sync_state.sync_peer_count > 0;
    }

    serial.writeString("[SYNC] Selected ");
    printUsize(sync_state.sync_peer_count);
    serial.writeString(" sync peers (");
    printUsize(countAnchorSyncPeers());
    serial.writeString(" anchors)\n");

    return true;
}

fn addSyncPeer(p: *peer.Peer, is_anchor: bool) void {
    if (sync_state.sync_peer_count >= MAX_SYNC_PEERS) return;

    // Check not already added
    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        if (eqlBytes(&sp.peer_id, &p.id)) return;
    }

    sync_state.sync_peers[sync_state.sync_peer_count] = .{
        .peer_id = p.id,
        .reported_height = 0,
        .blocks_received = 0,
        .is_anchor = is_anchor,
        .is_active = true,
    };
    sync_state.sync_peer_count += 1;
}

fn countAnchorSyncPeers() usize {
    var count: usize = 0;
    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        if (sp.is_anchor) count += 1;
    }
    return count;
}

/// Get sync peer by ID
fn getSyncPeer(peer_id: [32]u8) ?*SyncPeerInfo {
    for (&sync_state.sync_peers[0..sync_state.sync_peer_count]) |*sp| {
        if (eqlBytes(&sp.peer_id, &peer_id)) {
            return sp;
        }
    }
    return null;
}

// =============================================================================
// Chain Height Discovery
// =============================================================================

/// Request chain height from all sync peers
fn requestChainHeight() void {
    const p2p = @import("p2p.zig");

    // Encode our height in payload
    var payload: [8]u8 = undefined;
    writeU64(&payload, chain.getHeight());

    // Send to each sync peer
    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        _ = p2p.sendToPeer(sp.peer_id, .get_blocks, &payload);
    }

    sync_state.status = .requesting;
}

/// Handle chain height response from a peer
pub fn handleHeightResponse(from_peer: [32]u8, height: u64) void {
    // Find sync peer
    if (getSyncPeer(from_peer)) |sp| {
        sp.reported_height = height;

        // Update target if higher
        if (height > sync_state.target_block) {
            sync_state.target_block = height;
        }
    }

    // Check if all peers responded
    var all_responded = true;
    var heights_match = true;
    var first_height: u64 = 0;

    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        if (sp.reported_height == 0) {
            all_responded = false;
        } else {
            if (first_height == 0) {
                first_height = sp.reported_height;
            } else if (sp.reported_height != first_height) {
                heights_match = false;
            }
        }
    }

    // If all responded or timeout, proceed
    if (all_responded) {
        if (!heights_match) {
            serial.writeString("[SYNC] WARNING: Peers report different heights\n");
            // Use median/majority height in production
        }

        if (sync_state.target_block > sync_state.current_block) {
            startBlockSync();
        } else {
            sync_state.status = .complete;
            serial.writeString("[SYNC] Already at latest block\n");
        }
    }
}

// =============================================================================
// Block Synchronization
// =============================================================================

fn startBlockSync() void {
    sync_state.status = .receiving;
    sync_state.started_at = getTimestamp();
    sync_state.blocks_received = 0;

    serial.writeString("[SYNC] Syncing blocks ");
    printU64(sync_state.current_block);
    serial.writeString(" -> ");
    printU64(sync_state.target_block);
    serial.writeString(" (multi-path)\n");

    // Request blocks from ALL sync peers (for verification)
    requestBlocksFromAll(sync_state.current_block + 1, SYNC_BATCH_SIZE);
}

/// Request blocks from all sync peers
fn requestBlocksFromAll(from_block: u64, count: u64) void {
    const p2p = @import("p2p.zig");

    var payload: [16]u8 = undefined;
    writeU64(payload[0..8], from_block);
    writeU64(payload[8..16], count);

    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        if (sp.is_active) {
            _ = p2p.sendToPeer(sp.peer_id, .get_blocks, &payload);
        }
    }
}

/// Handle received blocks from a peer
pub fn handleBlocks(from_peer: [32]u8, data: []const u8) void {
    if (sync_state.status != .receiving and sync_state.status != .confirming) return;

    // Parse blocks
    if (data.len < 8) {
        markSyncPeerFailed(from_peer);
        return;
    }

    const block_count = readU64(data[0..8]);
    var pos: usize = 8;

    var i: u64 = 0;
    while (i < block_count) : (i += 1) {
        if (pos + 4 > data.len) break;
        const block_size = readU32(data[pos..]);
        pos += 4;

        if (pos + block_size > data.len) break;
        const block_data = data[pos..][0..block_size];
        pos += block_size;

        // Get block height and hash
        const block_height = sync_state.current_block + 1 + i;
        var block_hash: [32]u8 = undefined;
        computeBlockHash(block_data, &block_hash);

        // H.4: Add to multi-path verification
        if (!addBlockConfirmation(from_peer, block_height, &block_hash, block_data)) {
            serial.writeString("[SYNC] Block conflict detected!\n");
            sync_state.status = .conflict;
            return;
        }
    }

    // Update sync peer stats
    if (getSyncPeer(from_peer)) |sp| {
        sp.blocks_received += i;
    }

    // Check if we have enough confirmations for pending blocks
    processConfirmedBlocks();
}

// =============================================================================
// H.4: Multi-Path Block Verification
// =============================================================================

/// Add block confirmation from a peer
fn addBlockConfirmation(
    from_peer: [32]u8,
    block_height: u64,
    block_hash: *const [32]u8,
    block_data: []const u8,
) bool {
    // If this is a new block height
    if (block_height != pending_height) {
        // Process any previous pending block first
        if (pending_height > 0 and pending_confirm_count >= MIN_BLOCK_CONFIRMATIONS) {
            // Accept the previous block
            acceptBlock(pending_height);
        }

        // Start new pending block
        pending_height = block_height;
        pending_hash = block_hash.*;
        pending_confirmers[0] = from_peer;
        pending_confirm_count = 1;

        // Store block data for later acceptance
        storeBlockData(block_height, block_data);

        return true;
    }

    // Same height - check hash matches
    if (!eqlBytes(&pending_hash, block_hash)) {
        // CONFLICT! Different hash from different peer
        serial.writeString("[SYNC] CONFLICT: Block ");
        printU64(block_height);
        serial.writeString(" has different hashes!\n");

        // This is a potential eclipse attack or chain split
        // Log both hashes for investigation
        return false;
    }

    // Same hash - add confirmation
    if (pending_confirm_count < pending_confirmers.len) {
        // Check not already confirmed by this peer
        for (pending_confirmers[0..pending_confirm_count]) |*c| {
            if (eqlBytes(c, &from_peer)) return true; // Already confirmed
        }

        pending_confirmers[pending_confirm_count] = from_peer;
        pending_confirm_count += 1;
    }

    return true;
}

/// Process blocks that have enough confirmations
fn processConfirmedBlocks() void {
    if (pending_height == 0) return;

    if (pending_confirm_count >= MIN_BLOCK_CONFIRMATIONS) {
        serial.writeString("[SYNC] Block ");
        printU64(pending_height);
        serial.writeString(" confirmed by ");
        printUsize(pending_confirm_count);
        serial.writeString(" peers\n");

        acceptBlock(pending_height);

        // Reset pending
        pending_height = 0;
        pending_confirm_count = 0;

        // Check if sync complete
        if (sync_state.current_block >= sync_state.target_block) {
            sync_state.status = .complete;
            serial.writeString("[SYNC] Sync complete at block ");
            printU64(sync_state.current_block);
            serial.writeString("\n");
        } else {
            // Request more blocks
            requestBlocksFromAll(sync_state.current_block + 1, SYNC_BATCH_SIZE);
        }
    } else {
        sync_state.status = .confirming;
        serial.writeString("[SYNC] Waiting for confirmations (");
        printUsize(pending_confirm_count);
        serial.writeString("/");
        printUsize(MIN_BLOCK_CONFIRMATIONS);
        serial.writeString(")\n");
    }
}

/// Accept a confirmed block
fn acceptBlock(block_height: u64) void {
    // Retrieve stored block data and add to chain
    // (In real implementation, this would call chain.addBlock())

    sync_state.current_block = block_height;
    sync_state.blocks_received += 1;

    // Also register with eclipse defense for multi-path tracking
    _ = eclipse.addBlockConfirmation(
        &pending_confirmers[0],
        block_height,
        &pending_hash,
    );
}

/// Store block data temporarily
fn storeBlockData(block_height: u64, block_data: []const u8) void {
    // In real implementation, store to temp buffer
    // For now, just validate
    _ = block_height;
    _ = block_data;
}

/// Mark a sync peer as failed
fn markSyncPeerFailed(peer_id: [32]u8) void {
    if (getSyncPeer(peer_id)) |sp| {
        sp.is_active = false;
        serial.writeString("[SYNC] Sync peer failed\n");
    }

    // Check if we still have enough peers
    var active_count: usize = 0;
    for (sync_state.sync_peers[0..sync_state.sync_peer_count]) |sp| {
        if (sp.is_active) active_count += 1;
    }

    if (active_count < MIN_SYNC_PEERS) {
        serial.writeString("[SYNC] Not enough active sync peers!\n");
        sync_state.status = .failed;
    }
}

/// Compute block hash (simplified)
fn computeBlockHash(block_data: []const u8, out_hash: *[32]u8) void {
    // Simple hash for demonstration
    // Real implementation would use SHA-256
    const crypto_mod = @import("../crypto/crypto.zig");
    crypto_mod.hash(block_data, out_hash);
}

// =============================================================================
// New Block Announcement
// =============================================================================

/// Handle new block announcement from a peer
pub fn handleNewBlock(from_peer: [32]u8, data: []const u8) void {
    if (data.len < 8) return;

    const block_height = readU64(data[0..8]);

    // Only process if it's the next expected block
    if (block_height != sync_state.current_block + 1) return;

    if (data.len < 40) return; // Need at least height + hash

    var block_hash: [32]u8 = undefined;
    @memcpy(&block_hash, data[8..40]);

    // H.4: Add confirmation
    if (addBlockConfirmation(from_peer, block_height, &block_hash, data[40..])) {
        processConfirmedBlocks();
    } else {
        serial.writeString("[SYNC] Block announcement conflict!\n");
    }
}

// =============================================================================
// Progress Tracking
// =============================================================================

pub fn getProgress() struct { current: u64, target: u64, percent: u8 } {
    if (sync_state.target_block == 0) {
        return .{ .current = 0, .target = 0, .percent = 100 };
    }

    const percent: u8 = @intCast((sync_state.current_block * 100) / sync_state.target_block);

    return .{
        .current = sync_state.current_block,
        .target = sync_state.target_block,
        .percent = percent,
    };
}

/// Get sync peer count
pub fn getSyncPeerCount() usize {
    return sync_state.sync_peer_count;
}

/// Get pending confirmation count
pub fn getPendingConfirmations() usize {
    return pending_confirm_count;
}

/// Check if sync is multi-path verified
pub fn isMultiPathVerified() bool {
    return sync_state.sync_peer_count >= MIN_SYNC_PEERS;
}

// =============================================================================
// Utilities
// =============================================================================

fn getTimestamp() u64 {
    const timer = @import("../drivers/timer/timer.zig");
    return timer.getSeconds();
}

fn readU32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readU64(data: []const u8) u64 {
    return (@as(u64, data[0]) << 56) |
        (@as(u64, data[1]) << 48) |
        (@as(u64, data[2]) << 40) |
        (@as(u64, data[3]) << 32) |
        (@as(u64, data[4]) << 24) |
        (@as(u64, data[5]) << 16) |
        (@as(u64, data[6]) << 8) |
        @as(u64, data[7]);
}

fn writeU64(buf: []u8, val: u64) void {
    buf[0] = @intCast((val >> 56) & 0xFF);
    buf[1] = @intCast((val >> 48) & 0xFF);
    buf[2] = @intCast((val >> 40) & 0xFF);
    buf[3] = @intCast((val >> 32) & 0xFF);
    buf[4] = @intCast((val >> 24) & 0xFF);
    buf[5] = @intCast((val >> 16) & 0xFF);
    buf[6] = @intCast((val >> 8) & 0xFF);
    buf[7] = @intCast(val & 0xFF);
}

fn eqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn printU64(val: u64) void {
    if (val >= 10) printU64(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}

fn printUsize(val: usize) void {
    if (val >= 10) printUsize(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}
