//! Zamrud OS - P2P Ledger Synchronization
//! Syncs blockchain data between peers

const serial = @import("../drivers/serial/serial.zig");
const peer = @import("peer.zig");
const message = @import("message.zig");
const chain = @import("../chain/chain.zig");

// =============================================================================
// Constants
// =============================================================================

pub const SYNC_BATCH_SIZE: u64 = 100;
pub const SYNC_TIMEOUT_MS: u64 = 30000;

// =============================================================================
// Types
// =============================================================================

pub const SyncStatus = enum {
    idle,
    requesting,
    receiving,
    validating,
    complete,
    failed,
};

pub const SyncState = struct {
    status: SyncStatus,
    target_block: u64,
    current_block: u64,
    sync_peer: ?[32]u8,
    started_at: u64,
    blocks_received: u64,
};

// =============================================================================
// State
// =============================================================================

var initialized: bool = false;
var running: bool = false;
var sync_state: SyncState = .{
    .status = .idle,
    .target_block = 0,
    .current_block = 0,
    .sync_peer = null,
    .started_at = 0,
    .blocks_received = 0,
};

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    sync_state = .{
        .status = .idle,
        .target_block = 0,
        .current_block = 0,
        .sync_peer = null,
        .started_at = 0,
        .blocks_received = 0,
    };
    initialized = true;
    serial.writeString("[SYNC] Ledger sync initialized\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Sync Operations
// =============================================================================

pub fn start() void {
    if (running) return;

    running = true;
    serial.writeString("[SYNC] Starting ledger sync\n");

    // Get current chain height
    sync_state.current_block = chain.getHeight();

    // Request chain height from peers
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

/// Request chain height from all peers
fn requestChainHeight() void {
    const p2p = @import("p2p.zig");

    // Encode our height in payload
    var payload: [8]u8 = undefined;
    writeU64(&payload, chain.getHeight());

    p2p.broadcast(.get_blocks, &payload);
    sync_state.status = .requesting;
}

/// Handle chain height response
pub fn handleHeightResponse(from_peer: [32]u8, height: u64) void {
    if (height > sync_state.target_block) {
        sync_state.target_block = height;
        sync_state.sync_peer = from_peer;
    }

    // Check if we need to sync
    if (sync_state.target_block > sync_state.current_block) {
        startBlockSync();
    } else {
        sync_state.status = .complete;
        serial.writeString("[SYNC] Already at latest block\n");
    }
}

fn startBlockSync() void {
    sync_state.status = .receiving;
    sync_state.started_at = getTimestamp();
    sync_state.blocks_received = 0;

    serial.writeString("[SYNC] Syncing blocks ");
    printU64(sync_state.current_block);
    serial.writeString(" -> ");
    printU64(sync_state.target_block);
    serial.writeString("\n");

    // Request blocks from sync peer
    requestBlocks(sync_state.current_block + 1, SYNC_BATCH_SIZE);
}

fn requestBlocks(from_block: u64, count: u64) void {
    if (sync_state.sync_peer == null) return;

    const p2p = @import("p2p.zig");

    // Encode request
    var payload: [16]u8 = undefined;
    writeU64(payload[0..8], from_block);
    writeU64(payload[8..16], count);

    _ = p2p.sendToPeer(sync_state.sync_peer.?, .get_blocks, &payload);
}

/// Handle received blocks
pub fn handleBlocks(data: []const u8) void {
    if (sync_state.status != .receiving) return;

    sync_state.status = .validating;

    // Parse and validate blocks
    var pos: usize = 0;

    // Read block count
    if (data.len < 8) {
        sync_state.status = .failed;
        return;
    }

    const block_count = readU64(data[0..8]);
    pos = 8;

    var i: u64 = 0;
    while (i < block_count) : (i += 1) {
        // Read block size
        if (pos + 4 > data.len) break;
        const block_size = readU32(data[pos..]);
        pos += 4;

        if (pos + block_size > data.len) break;

        // Parse block
        const block_data = data[pos..][0..block_size];
        pos += block_size;

        // Validate and add block
        if (validateAndAddBlock(block_data)) {
            sync_state.blocks_received += 1;
            sync_state.current_block += 1;
        } else {
            serial.writeString("[SYNC] Invalid block received\n");
            sync_state.status = .failed;
            return;
        }
    }

    // Check if sync complete
    if (sync_state.current_block >= sync_state.target_block) {
        sync_state.status = .complete;
        serial.writeString("[SYNC] Sync complete at block ");
        printU64(sync_state.current_block);
        serial.writeString("\n");
    } else {
        // Request more blocks
        sync_state.status = .receiving;
        requestBlocks(sync_state.current_block + 1, SYNC_BATCH_SIZE);
    }
}

fn validateAndAddBlock(block_data: []const u8) bool {
    // Simplified validation - in real implementation:
    // 1. Parse block structure
    // 2. Verify block hash
    // 3. Verify previous block hash
    // 4. Verify all transactions
    // 5. Add to chain

    _ = block_data;

    // For now, just simulate success
    return true;
}

/// Handle new block announcement
pub fn handleNewBlock(from_peer: [32]u8, data: []const u8) void {
    _ = from_peer;

    if (data.len < 8) return;

    const block_height = readU64(data[0..8]);

    // Check if this is the next expected block
    if (block_height == sync_state.current_block + 1) {
        if (validateAndAddBlock(data[8..])) {
            sync_state.current_block = block_height;
            serial.writeString("[SYNC] New block: ");
            printU64(block_height);
            serial.writeString("\n");
        }
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

fn printU64(val: u64) void {
    if (val >= 10) printU64(val / 10);
    serial.writeChar('0' + @as(u8, @intCast(val % 10)));
}
