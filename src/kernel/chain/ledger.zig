//! Zamrud OS - Lightweight Ledger
//! Minimal storage for integrity blockchain with persistence
//! Updated: GOV.1a Lightweight Runtime Governance Audit API
//! Updated: GOV.1b Bounded Persistent Audit Ring Buffer
//!
//! Design:
//! - Keep CHAIN.DAT small.
//! - Do not auto-save every audit event.
//! - Do not grow chain without bound.
//! - If audit block capacity is full, fold audit event into tip hash.
//! - Persist a small bounded audit detail ring buffer.
//!
//! GOV.1b audit persistence:
//! - Fixed ring buffer.
//! - MAX_AUDIT_RECORDS = 8.
//! - Each audit record = 40 bytes.
//! - Total persistent chain file remains below ~1 KB.
//! - Old CHAIN.DAT v1 format remains readable.

const serial = @import("../drivers/serial/serial.zig");
const block_mod = @import("block.zig");
const entry_mod = @import("entry.zig");
const fat32 = @import("../fs/fat32.zig");
const hash_mod = @import("../crypto/hash.zig");

pub const Block = block_mod.Block;
pub const Entry = entry_mod.Entry;

// =============================================================================
// Constants
// =============================================================================

pub const MAX_BLOCKS: usize = 16;

// GOV.1b bounded persistent audit detail.
// Keep this small for OS-lightweight behavior.
pub const MAX_AUDIT_RECORDS: usize = 8;
pub const AUDIT_RECORD_SIZE: usize = 40;

// Persistence format
const CHAIN_MAGIC = [4]u8{ 'Z', 'M', 'R', 'D' };
const CHAIN_VERSION_V1: u32 = 1;
const CHAIN_VERSION_V2: u32 = 2;
const CHAIN_VERSION: u32 = CHAIN_VERSION_V2;
const CHAIN_FILENAME = "CHAIN.DAT";

// V1 header:
// magic(4) + version(4) + block_count(4) + height(4) = 16
const HEADER_V1_SIZE: usize = 16;

// V2 header:
// magic(4) + version(4) + block_count(4) + height(4)
// + audit_count(4) + audit_write_index(4) + audit_total(4) = 28
const HEADER_V2_SIZE: usize = 28;

// Hashes: genesis(32) + tip(32) = 64
const HASH_STATE_SIZE: usize = 64;

// Block hashes: 32 * MAX_BLOCKS = 512
const BLOCK_HASH_SIZE: usize = 32 * MAX_BLOCKS;

// Audit ring: AUDIT_RECORD_SIZE * MAX_AUDIT_RECORDS = 320
const AUDIT_RING_SIZE: usize = AUDIT_RECORD_SIZE * MAX_AUDIT_RECORDS;

// Total max v2:
// 28 + 64 + 512 + 320 = 924 bytes
const MAX_CHAIN_FILE_SIZE: usize = HEADER_V2_SIZE + HASH_STATE_SIZE + BLOCK_HASH_SIZE + AUDIT_RING_SIZE;

// Audit fold material:
// tip_hash(32) + entry_type(1) + target_hash(32) + data(32) + timestamp(4)
// = 101 bytes. Keep 128 for safety.
const AUDIT_FOLD_BUFFER_SIZE: usize = 128;

// =============================================================================
// Ledger State
// =============================================================================

pub const LedgerState = struct {
    height: u32,
    tip_hash: [32]u8,
    genesis_hash: [32]u8,
    block_count: u32,
    initialized: bool,
};

pub const AuditRecord = struct {
    active: bool = false,

    entry_type: entry_mod.EntryType = .system_update,
    action: u8 = 0,

    // Compact persistent detail.
    // Keep prefixes only to keep CHAIN.DAT small.
    target_prefix: [8]u8 = [_]u8{0} ** 8,
    data_prefix: [8]u8 = [_]u8{0} ** 8,

    timestamp: u32 = 0,

    // Tip prefix after applying this audit.
    tip_prefix: [8]u8 = [_]u8{0} ** 8,

    // Auxiliary field:
    // - firewall_audit: IP
    // - eviction_audit: target_ip
    // - authority_audit: level/status encoded if needed
    aux: u32 = 0,
};

// =============================================================================
// Global State
// =============================================================================

var ledger: LedgerState = undefined;
var ledger_inited: bool = false;
pub var block_hashes: [MAX_BLOCKS][32]u8 = undefined;

var static_ledger_entry: entry_mod.Entry = undefined;
var static_auth_key: [32]u8 = [_]u8{0} ** 32;

// GOV.1a runtime audit state.
// This uses the existing ledger/block path; it does NOT create a new ledger.
var static_audit_entry: entry_mod.Entry = undefined;
var static_audit_auth_key: [32]u8 = [_]u8{0} ** 32;
var audit_fold_buffer: [AUDIT_FOLD_BUFFER_SIZE]u8 = [_]u8{0} ** AUDIT_FOLD_BUFFER_SIZE;
var audit_fold_hash: [32]u8 = [_]u8{0} ** 32;

// GOV.1b bounded persistent audit detail ring.
var audit_records: [MAX_AUDIT_RECORDS]AuditRecord = undefined;
var audit_record_count: u32 = 0;
var audit_write_index: u32 = 0;
var audit_total: u32 = 0;

// Persistence state
var auto_save_enabled: bool = true;

// Important lightweight security policy:
// Audit auto-save is OFF by default.
//
// Normal chain blocks can auto-save.
// Governance audit events are committed into runtime block hashes / tip hash,
// but do not spam disk writes unless explicitly enabled.
var audit_auto_save_enabled: bool = false;

var last_save_height: u32 = 0;

// =============================================================================
// Core Helpers
// =============================================================================

fn resetAuditRing() void {
    for (&audit_records) |*r| {
        r.* = AuditRecord{};
    }

    audit_record_count = 0;
    audit_write_index = 0;
    audit_total = 0;
}

fn resetLedger() void {
    ledger.height = 0;
    ledger.block_count = 0;
    ledger.initialized = false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = 0;
        ledger.genesis_hash[i] = 0;
    }

    i = 0;
    while (i < MAX_BLOCKS) : (i += 1) {
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            block_hashes[i][j] = 0;
        }
    }

    resetAuditRing();
}

pub fn init(authority_pubkey: *const [32]u8) bool {
    resetLedger();

    const genesis = Block.createGenesis(authority_pubkey);
    const genesis_hash = genesis.getHash();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        block_hashes[0][i] = genesis_hash[i];
        ledger.tip_hash[i] = genesis_hash[i];
        ledger.genesis_hash[i] = genesis_hash[i];
    }

    ledger.height = 0;
    ledger.block_count = 1;
    ledger.initialized = true;
    ledger_inited = true;

    serial.writeString("[LEDGER] Initialized\n");
    return true;
}

fn addBlockInternal(blk: *const Block, do_save: bool) bool {
    if (!ledger.initialized) return false;
    if (ledger.block_count >= MAX_BLOCKS) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (blk.header.prev_hash[i] != ledger.tip_hash[i]) {
            return false;
        }
    }

    if (blk.header.height != ledger.height + 1) {
        return false;
    }

    const blk_hash = blk.getHash();

    i = 0;
    while (i < 32) : (i += 1) {
        block_hashes[ledger.block_count][i] = blk_hash[i];
        ledger.tip_hash[i] = blk_hash[i];
    }

    ledger.height = blk.header.height;
    ledger.block_count += 1;

    if (do_save) {
        _ = saveToDisk();
    }

    return true;
}

pub fn addBlock(blk: *const Block) bool {
    return addBlockInternal(blk, auto_save_enabled);
}

pub fn getHeight() u32 {
    return ledger.height;
}

pub fn getBlockCount() u32 {
    return ledger.block_count;
}

pub fn isInitialized() bool {
    return ledger.initialized;
}

pub fn getTipHash() *const [32]u8 {
    return &ledger.tip_hash;
}

pub fn getGenesisHash() *const [32]u8 {
    return &ledger.genesis_hash;
}

pub fn createBlockTemplate(authority_pubkey: *const [32]u8) *Block {
    const blk = Block.initStatic();

    blk.header.height = ledger.height + 1;
    blk.header.timestamp = 1700000000 + (ledger.block_count * 10);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        blk.header.prev_hash[i] = ledger.tip_hash[i];
        blk.header.authority[i] = authority_pubkey[i];
    }

    return blk;
}

// =============================================================================
// GOV.1b: Bounded Persistent Audit Ring
// =============================================================================

fn auditEntryAux(ent: *const Entry) u32 {
    switch (ent.entry_type) {
        .firewall_audit => {
            return (@as(u32, ent.target_hash[0]) << 24) |
                (@as(u32, ent.target_hash[1]) << 16) |
                (@as(u32, ent.target_hash[2]) << 8) |
                @as(u32, ent.target_hash[3]);
        },
        .eviction_audit => {
            return (@as(u32, ent.data[2]) << 24) |
                (@as(u32, ent.data[3]) << 16) |
                (@as(u32, ent.data[4]) << 8) |
                @as(u32, ent.data[5]);
        },
        .authority_audit => {
            return (@as(u32, ent.data[1]) << 8) | @as(u32, ent.data[2]);
        },
        else => return 0,
    }
}

fn recordAuditDetail(ent: *const Entry) void {
    const write_index_usize: usize = @intCast(audit_write_index);
    const idx: usize = write_index_usize % MAX_AUDIT_RECORDS;

    audit_records[idx].active = true;
    audit_records[idx].entry_type = ent.entry_type;
    audit_records[idx].action = ent.data[0];
    audit_records[idx].timestamp = ent.timestamp;
    audit_records[idx].aux = auditEntryAux(ent);

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        audit_records[idx].target_prefix[i] = ent.target_hash[i];
        audit_records[idx].data_prefix[i] = ent.data[i];
        audit_records[idx].tip_prefix[i] = ledger.tip_hash[i];
    }

    const next_index: usize = (idx + 1) % MAX_AUDIT_RECORDS;
    audit_write_index = @intCast(next_index);

    if (audit_record_count < MAX_AUDIT_RECORDS) {
        audit_record_count += 1;
    }

    audit_total += 1;
}

pub fn getAuditCapacity() u32 {
    return MAX_AUDIT_RECORDS;
}

pub fn getAuditRecordCount() u32 {
    return audit_record_count;
}

pub fn getAuditTotal() u32 {
    return audit_total;
}

pub fn getAuditWriteIndex() u32 {
    return audit_write_index;
}

pub fn isAuditDetailPersistent() bool {
    return true;
}

/// Return audit record in logical order: oldest -> newest.
pub fn getAuditRecord(index: usize) ?*const AuditRecord {
    if (index >= audit_record_count) return null;

    var physical: usize = index;

    if (audit_record_count == MAX_AUDIT_RECORDS) {
        physical = (@as(usize, @intCast(audit_write_index)) + index) % MAX_AUDIT_RECORDS;
    }

    return &audit_records[physical];
}

pub fn clearAuditRingForTest() void {
    resetAuditRing();
}

// =============================================================================
// GOV.1a: Lightweight Runtime Governance Audit API
// =============================================================================

fn initAuditAuthorityKey() void {
    static_audit_auth_key = [_]u8{0} ** 32;
    static_audit_auth_key[0] = 'G';
    static_audit_auth_key[1] = 'O';
    static_audit_auth_key[2] = 'V';
}

fn getAuditTimestamp() u32 {
    return 1700000000 + (ledger.block_count * 10);
}

fn ensureAuditLedger() bool {
    if (ledger.initialized) return true;

    initAuditAuthorityKey();
    return init(&static_audit_auth_key);
}

/// Fold an audit event into the current tip hash without growing block_count.
///
/// This keeps the OS lightweight:
/// - no unbounded chain growth
/// - no large CHAIN.DAT
/// - audit is still hash-committed
///
/// This path is used when MAX_BLOCKS is reached.
fn foldAuditIntoTip(ent: *const Entry) bool {
    if (!ledger.initialized) return false;
    if (ledger.block_count == 0) return false;

    var pos: usize = 0;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        audit_fold_buffer[pos] = ledger.tip_hash[i];
        pos += 1;
    }

    audit_fold_buffer[pos] = @intFromEnum(ent.entry_type);
    pos += 1;

    i = 0;
    while (i < 32) : (i += 1) {
        audit_fold_buffer[pos] = ent.target_hash[i];
        pos += 1;
    }

    i = 0;
    while (i < 32) : (i += 1) {
        audit_fold_buffer[pos] = ent.data[i];
        pos += 1;
    }

    audit_fold_buffer[pos] = @intCast(ent.timestamp & 0xFF);
    audit_fold_buffer[pos + 1] = @intCast((ent.timestamp >> 8) & 0xFF);
    audit_fold_buffer[pos + 2] = @intCast((ent.timestamp >> 16) & 0xFF);
    audit_fold_buffer[pos + 3] = @intCast((ent.timestamp >> 24) & 0xFF);
    pos += 4;

    hash_mod.sha256Into(audit_fold_buffer[0..pos], &audit_fold_hash);

    i = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = audit_fold_hash[i];
        block_hashes[ledger.block_count - 1][i] = audit_fold_hash[i];
    }

    if (audit_auto_save_enabled) {
        _ = saveToDisk();
    }

    return true;
}

/// Append a prebuilt audit entry into the existing ledger.
///
/// Important:
/// - This is not a new audit database.
/// - This creates a normal block containing an audit entry when capacity allows.
/// - If MAX_BLOCKS is full, the audit is folded into tip_hash instead.
/// - Audit auto-save is disabled by default to avoid disk spam.
/// - GOV.1b stores small persistent audit detail in a bounded ring buffer.
pub fn appendAuditEntry(ent: *const Entry) bool {
    if (!ensureAuditLedger()) {
        serial.writeString("[LEDGER] GOV audit skipped: ledger not initialized\n");
        return false;
    }

    var ok = false;

    if (ledger.block_count >= MAX_BLOCKS) {
        serial.writeString("[LEDGER] GOV audit folded into tip hash\n");
        ok = foldAuditIntoTip(ent);
    } else {
        initAuditAuthorityKey();

        const blk = createBlockTemplate(&static_audit_auth_key);

        static_audit_entry.entry_type = ent.entry_type;
        static_audit_entry.timestamp = ent.timestamp;

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            static_audit_entry.target_hash[i] = ent.target_hash[i];
            static_audit_entry.data[i] = ent.data[i];
        }

        if (!blk.addEntry(&static_audit_entry)) {
            serial.writeString("[LEDGER] GOV audit add entry failed\n");
            return false;
        }

        ok = addBlockInternal(blk, audit_auto_save_enabled);
    }

    if (ok) {
        recordAuditDetail(ent);
    }

    return ok;
}

pub fn appendAuthorityAudit(
    authority_id: *const [32]u8,
    action: u8,
    level: u8,
    status: u8,
) bool {
    var ent: Entry = undefined;

    Entry.authorityAuditInto(
        &ent,
        authority_id,
        action,
        level,
        status,
        getAuditTimestamp(),
    );

    return appendAuditEntry(&ent);
}

pub fn appendEvictionAudit(
    target_id: *const [32]u8,
    target_ip: u32,
    reason: u8,
    evidence_hash: *const [32]u8,
) bool {
    var ent: Entry = undefined;

    Entry.evictionAuditInto(
        &ent,
        target_id,
        target_ip,
        reason,
        evidence_hash,
        getAuditTimestamp(),
    );

    return appendAuditEntry(&ent);
}

pub fn appendFirewallAudit(
    ip: u32,
    action: u8,
    reason_code: u8,
) bool {
    var ent: Entry = undefined;

    Entry.firewallAuditInto(
        &ent,
        ip,
        action,
        reason_code,
        getAuditTimestamp(),
    );

    return appendAuditEntry(&ent);
}

// =============================================================================
// Persistence: Save to Disk
// =============================================================================

/// Serialize ledger state to /disk/CHAIN.DAT.
pub fn saveToDisk() bool {
    if (!ledger.initialized) {
        serial.writeString("[LEDGER] Cannot save - not initialized\n");
        return false;
    }

    if (!fat32.isMounted()) {
        serial.writeString("[LEDGER] Cannot save - disk not mounted\n");
        return false;
    }

    var buf: [MAX_CHAIN_FILE_SIZE]u8 = [_]u8{0} ** MAX_CHAIN_FILE_SIZE;
    const size = serialize(&buf);

    if (size == 0) {
        serial.writeString("[LEDGER] Serialize failed\n");
        return false;
    }

    if (fat32.findInRoot(CHAIN_FILENAME) != null) {
        _ = fat32.deleteFile(CHAIN_FILENAME);
    }

    if (fat32.createFile(CHAIN_FILENAME, buf[0..size])) {
        last_save_height = ledger.height;

        serial.writeString("[LEDGER] Saved to disk (height=");
        printU32(ledger.height);
        serial.writeString(", blocks=");
        printU32(ledger.block_count);
        serial.writeString(", audit=");
        printU32(audit_record_count);
        serial.writeString("/");
        printU32(MAX_AUDIT_RECORDS);
        serial.writeString(")\n");

        return true;
    } else {
        serial.writeString("[LEDGER] Save to disk FAILED\n");
        return false;
    }
}

/// Serialize ledger to byte buffer.
///
/// V2 lightweight format:
/// - chain metadata
/// - genesis/tip hashes
/// - block hashes
/// - bounded compact audit ring
fn serialize(buf: []u8) usize {
    if (buf.len < MAX_CHAIN_FILE_SIZE) return 0;

    var pos: usize = 0;

    buf[pos] = CHAIN_MAGIC[0];
    buf[pos + 1] = CHAIN_MAGIC[1];
    buf[pos + 2] = CHAIN_MAGIC[2];
    buf[pos + 3] = CHAIN_MAGIC[3];
    pos += 4;

    writeU32LE(buf, pos, CHAIN_VERSION);
    pos += 4;

    writeU32LE(buf, pos, ledger.block_count);
    pos += 4;

    writeU32LE(buf, pos, ledger.height);
    pos += 4;

    writeU32LE(buf, pos, audit_record_count);
    pos += 4;

    writeU32LE(buf, pos, audit_write_index);
    pos += 4;

    writeU32LE(buf, pos, audit_total);
    pos += 4;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[pos + i] = ledger.genesis_hash[i];
    }
    pos += 32;

    i = 0;
    while (i < 32) : (i += 1) {
        buf[pos + i] = ledger.tip_hash[i];
    }
    pos += 32;

    var b: usize = 0;
    while (b < ledger.block_count and b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            buf[pos + i] = block_hashes[b][i];
        }
        pos += 32;
    }

    while (b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            buf[pos + i] = 0;
        }
        pos += 32;
    }

    var r: usize = 0;
    while (r < MAX_AUDIT_RECORDS) : (r += 1) {
        const rec = &audit_records[r];

        buf[pos] = if (rec.active) 1 else 0;
        pos += 1;

        buf[pos] = @intFromEnum(rec.entry_type);
        pos += 1;

        buf[pos] = rec.action;
        pos += 1;

        buf[pos] = 0; // reserved
        pos += 1;

        i = 0;
        while (i < 8) : (i += 1) {
            buf[pos + i] = rec.target_prefix[i];
        }
        pos += 8;

        i = 0;
        while (i < 8) : (i += 1) {
            buf[pos + i] = rec.data_prefix[i];
        }
        pos += 8;

        writeU32LE(buf, pos, rec.timestamp);
        pos += 4;

        i = 0;
        while (i < 8) : (i += 1) {
            buf[pos + i] = rec.tip_prefix[i];
        }
        pos += 8;

        writeU32LE(buf, pos, rec.aux);
        pos += 4;

        // Padding to AUDIT_RECORD_SIZE.
        i = 0;
        while (i < 4) : (i += 1) {
            buf[pos + i] = 0;
        }
        pos += 4;
    }

    return pos;
}

// =============================================================================
// Persistence: Load from Disk
// =============================================================================

pub fn loadFromDisk() bool {
    if (!fat32.isMounted()) {
        serial.writeString("[LEDGER] Cannot load - disk not mounted\n");
        return false;
    }

    const file_info = fat32.findInRoot(CHAIN_FILENAME) orelse {
        serial.writeString("[LEDGER] No saved chain found\n");
        return false;
    };

    if (file_info.size < HEADER_V1_SIZE + HASH_STATE_SIZE) {
        serial.writeString("[LEDGER] Chain file too small\n");
        return false;
    }

    var buf: [MAX_CHAIN_FILE_SIZE]u8 = [_]u8{0} ** MAX_CHAIN_FILE_SIZE;
    const read_size: usize = @min(@as(usize, file_info.size), MAX_CHAIN_FILE_SIZE);
    const bytes = fat32.readFile(file_info.cluster, buf[0..read_size]);

    if (bytes < HEADER_V1_SIZE + HASH_STATE_SIZE) {
        serial.writeString("[LEDGER] Chain file read error\n");
        return false;
    }

    return deserialize(buf[0..bytes]);
}

fn deserialize(buf: []const u8) bool {
    if (buf.len < HEADER_V1_SIZE + HASH_STATE_SIZE) return false;

    if (buf[0] != CHAIN_MAGIC[0] or
        buf[1] != CHAIN_MAGIC[1] or
        buf[2] != CHAIN_MAGIC[2] or
        buf[3] != CHAIN_MAGIC[3])
    {
        serial.writeString("[LEDGER] Invalid chain file magic\n");
        return false;
    }

    const version = readU32LE(buf, 4);

    if (version == CHAIN_VERSION_V1) {
        return deserializeV1(buf);
    }

    if (version == CHAIN_VERSION_V2) {
        return deserializeV2(buf);
    }

    serial.writeString("[LEDGER] Unsupported chain version: ");
    printU32(version);
    serial.writeString("\n");
    return false;
}

fn deserializeV1(buf: []const u8) bool {
    var pos: usize = 8;

    const saved_block_count = readU32LE(buf, pos);
    if (saved_block_count == 0 or saved_block_count > MAX_BLOCKS) {
        serial.writeString("[LEDGER] Invalid block count\n");
        return false;
    }
    pos += 4;

    const saved_height = readU32LE(buf, pos);
    pos += 4;

    const needed = HEADER_V1_SIZE + HASH_STATE_SIZE + (saved_block_count * 32);
    if (buf.len < needed) {
        serial.writeString("[LEDGER] Chain file truncated\n");
        return false;
    }

    resetLedger();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        ledger.genesis_hash[i] = buf[pos + i];
    }
    pos += 32;

    i = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = buf[pos + i];
    }
    pos += 32;

    var b: usize = 0;
    while (b < saved_block_count and b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            block_hashes[b][i] = buf[pos + i];
        }
        pos += 32;
    }

    if (!validateTipMatches(saved_block_count)) {
        serial.writeString("[LEDGER] Chain integrity check FAILED\n");
        resetLedger();
        return false;
    }

    ledger.block_count = saved_block_count;
    ledger.height = saved_height;
    ledger.initialized = true;
    ledger_inited = true;
    last_save_height = saved_height;

    resetAuditRing();

    serial.writeString("[LEDGER] Loaded V1 chain (height=");
    printU32(saved_height);
    serial.writeString(", blocks=");
    printU32(saved_block_count);
    serial.writeString(", audit=0)\n");

    return true;
}

fn deserializeV2(buf: []const u8) bool {
    if (buf.len < HEADER_V2_SIZE + HASH_STATE_SIZE) return false;

    var pos: usize = 8;

    const saved_block_count = readU32LE(buf, pos);
    if (saved_block_count == 0 or saved_block_count > MAX_BLOCKS) {
        serial.writeString("[LEDGER] Invalid block count\n");
        return false;
    }
    pos += 4;

    const saved_height = readU32LE(buf, pos);
    pos += 4;

    const saved_audit_count = readU32LE(buf, pos);
    pos += 4;

    const saved_audit_write_index = readU32LE(buf, pos);
    pos += 4;

    const saved_audit_total = readU32LE(buf, pos);
    pos += 4;

    if (saved_audit_count > MAX_AUDIT_RECORDS) {
        serial.writeString("[LEDGER] Invalid audit count\n");
        return false;
    }

    if (saved_audit_write_index >= MAX_AUDIT_RECORDS) {
        serial.writeString("[LEDGER] Invalid audit write index\n");
        return false;
    }

    const needed = HEADER_V2_SIZE + HASH_STATE_SIZE + BLOCK_HASH_SIZE + AUDIT_RING_SIZE;
    if (buf.len < needed) {
        serial.writeString("[LEDGER] Chain file truncated\n");
        return false;
    }

    resetLedger();

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        ledger.genesis_hash[i] = buf[pos + i];
    }
    pos += 32;

    i = 0;
    while (i < 32) : (i += 1) {
        ledger.tip_hash[i] = buf[pos + i];
    }
    pos += 32;

    var b: usize = 0;
    while (b < MAX_BLOCKS) : (b += 1) {
        i = 0;
        while (i < 32) : (i += 1) {
            block_hashes[b][i] = buf[pos + i];
        }
        pos += 32;
    }

    if (!validateTipMatches(saved_block_count)) {
        serial.writeString("[LEDGER] Chain integrity check FAILED\n");
        resetLedger();
        return false;
    }

    var r: usize = 0;
    while (r < MAX_AUDIT_RECORDS) : (r += 1) {
        var rec = AuditRecord{};

        rec.active = buf[pos] != 0;
        pos += 1;

        const etype_raw = buf[pos];
        pos += 1;

        rec.entry_type = switch (etype_raw) {
            @intFromEnum(entry_mod.EntryType.authority_audit) => .authority_audit,
            @intFromEnum(entry_mod.EntryType.eviction_audit) => .eviction_audit,
            @intFromEnum(entry_mod.EntryType.firewall_audit) => .firewall_audit,
            @intFromEnum(entry_mod.EntryType.file_register) => .file_register,
            @intFromEnum(entry_mod.EntryType.system_update) => .system_update,
            else => .incident,
        };

        rec.action = buf[pos];
        pos += 1;

        pos += 1; // reserved

        i = 0;
        while (i < 8) : (i += 1) {
            rec.target_prefix[i] = buf[pos + i];
        }
        pos += 8;

        i = 0;
        while (i < 8) : (i += 1) {
            rec.data_prefix[i] = buf[pos + i];
        }
        pos += 8;

        rec.timestamp = readU32LE(buf, pos);
        pos += 4;

        i = 0;
        while (i < 8) : (i += 1) {
            rec.tip_prefix[i] = buf[pos + i];
        }
        pos += 8;

        rec.aux = readU32LE(buf, pos);
        pos += 4;

        pos += 4; // padding

        audit_records[r] = rec;
    }

    ledger.block_count = saved_block_count;
    ledger.height = saved_height;
    ledger.initialized = true;
    ledger_inited = true;

    audit_record_count = saved_audit_count;
    audit_write_index = saved_audit_write_index;
    audit_total = saved_audit_total;

    last_save_height = saved_height;

    serial.writeString("[LEDGER] Loaded V2 chain (height=");
    printU32(saved_height);
    serial.writeString(", blocks=");
    printU32(saved_block_count);
    serial.writeString(", audit=");
    printU32(audit_record_count);
    serial.writeString("/");
    printU32(MAX_AUDIT_RECORDS);
    serial.writeString(")\n");

    return true;
}

fn validateTipMatches(saved_block_count: u32) bool {
    if (saved_block_count == 0 or saved_block_count > MAX_BLOCKS) return false;

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (ledger.tip_hash[i] != block_hashes[saved_block_count - 1][i]) {
            return false;
        }
    }

    return true;
}

// =============================================================================
// Persistence Configuration
// =============================================================================

pub fn setAutoSave(enabled: bool) void {
    auto_save_enabled = enabled;
}

pub fn isAutoSaveEnabled() bool {
    return auto_save_enabled;
}

pub fn setAuditAutoSave(enabled: bool) void {
    audit_auto_save_enabled = enabled;
}

pub fn isAuditAutoSaveEnabled() bool {
    return audit_auto_save_enabled;
}

pub fn getLastSaveHeight() u32 {
    return last_save_height;
}

pub fn hasSavedChain() bool {
    if (!fat32.isMounted()) return false;
    return fat32.findInRoot(CHAIN_FILENAME) != null;
}

// =============================================================================
// Utility
// =============================================================================

fn writeU32LE(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value & 0xFF);
    buf[offset + 1] = @intCast((value >> 8) & 0xFF);
    buf[offset + 2] = @intCast((value >> 16) & 0xFF);
    buf[offset + 3] = @intCast((value >> 24) & 0xFF);
}

fn readU32LE(buf: []const u8, offset: usize) u32 {
    return @as(u32, buf[offset]) |
        (@as(u32, buf[offset + 1]) << 8) |
        (@as(u32, buf[offset + 2]) << 16) |
        (@as(u32, buf[offset + 3]) << 24);
}

// =============================================================================
// Test
// =============================================================================

pub fn test_ledger() bool {
    serial.writeString("[LEDGER] Testing...\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    serial.writeString("  Test 1: Initialize\n");

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        static_auth_key[i] = 0;
    }
    static_auth_key[0] = 0x01;

    const prev_auto_save = auto_save_enabled;
    const prev_audit_auto_save = audit_auto_save_enabled;

    auto_save_enabled = false;
    audit_auto_save_enabled = false;

    if (init(&static_auth_key) and ledger.initialized) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 2: Genesis height\n");
    if (getHeight() == 0 and getBlockCount() == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 3: Add block\n");

    const blk = createBlockTemplate(&static_auth_key);

    static_ledger_entry.entry_type = .file_register;
    static_ledger_entry.timestamp = 0;

    var j: usize = 0;
    while (j < 32) : (j += 1) {
        static_ledger_entry.target_hash[j] = 0;
        static_ledger_entry.data[j] = 0;
    }

    _ = blk.addEntry(&static_ledger_entry);

    if (addBlock(blk) and getHeight() == 1) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  Test 4: Authority audit\n");
    {
        var audit_id: [32]u8 = [_]u8{0} ** 32;
        audit_id[0] = 0xA7;

        const before = getHeight();

        const ok = appendAuthorityAudit(
            &audit_id,
            entry_mod.AUDIT_AUTH_REGISTER,
            3,
            1,
        );

        if (ok and getHeight() == before + 1 and getAuditRecordCount() > 0) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  Test 5: Eviction audit\n");
    {
        var target_id: [32]u8 = [_]u8{0} ** 32;
        var evidence: [32]u8 = [_]u8{0} ** 32;

        target_id[0] = 0xE7;
        evidence[0] = 0xEE;

        const before = getHeight();

        const ok = appendEvictionAudit(
            &target_id,
            0xC0A80101,
            7,
            &evidence,
        );

        if (ok and getHeight() == before + 1 and getAuditRecordCount() > 1) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  Test 6: Firewall audit\n");
    {
        const before = getHeight();

        const ok = appendFirewallAudit(
            0xC0A8FA77,
            entry_mod.AUDIT_FIREWALL_KILLSWITCH,
            1,
        );

        if (ok and getHeight() == before + 1 and getAuditRecordCount() > 2) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  Test 7: Audit fold when full\n");
    {
        while (ledger.block_count < MAX_BLOCKS) {
            var e: entry_mod.Entry = undefined;
            entry_mod.Entry.initInto(&e);
            e.entry_type = .system_update;

            const b = createBlockTemplate(&static_auth_key);
            _ = b.addEntry(&e);
            _ = addBlock(b);
        }

        var old_tip: [32]u8 = [_]u8{0} ** 32;
        i = 0;
        while (i < 32) : (i += 1) {
            old_tip[i] = ledger.tip_hash[i];
        }

        var audit_id: [32]u8 = [_]u8{0} ** 32;
        audit_id[0] = 0xFA;

        const old_height = getHeight();
        const old_blocks = getBlockCount();
        const old_audit_count = getAuditRecordCount();

        const ok = appendAuthorityAudit(
            &audit_id,
            entry_mod.AUDIT_AUTH_REVOKE,
            3,
            2,
        );

        var tip_changed = false;
        i = 0;
        while (i < 32) : (i += 1) {
            if (old_tip[i] != ledger.tip_hash[i]) {
                tip_changed = true;
                break;
            }
        }

        if (ok and
            tip_changed and
            getHeight() == old_height and
            getBlockCount() == old_blocks and
            getAuditRecordCount() >= old_audit_count)
        {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    serial.writeString("  Test 8: Audit ring bounded\n");
    {
        var n: usize = 0;
        while (n < 20) : (n += 1) {
            var audit_id: [32]u8 = [_]u8{0} ** 32;
            audit_id[0] = @intCast(n & 0xFF);

            _ = appendAuthorityAudit(
                &audit_id,
                entry_mod.AUDIT_AUTH_REGISTER,
                3,
                1,
            );
        }

        if (getAuditRecordCount() == MAX_AUDIT_RECORDS and getAuditTotal() >= 20) {
            serial.writeString("    OK\n");
            passed += 1;
        } else {
            serial.writeString("    FAIL\n");
            failed += 1;
        }
    }

    auto_save_enabled = prev_auto_save;
    audit_auto_save_enabled = prev_audit_auto_save;

    serial.writeString("  LEDGER: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = [_]u8{0} ** 10;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
