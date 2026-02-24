//! Zamrud OS - Boot Measurement (H.5 Enhanced)
//! Measures system components for integrity verification
//! H.5: PCR chain, per-section measurement, event log

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");
const ct = @import("../crypto/constant_time.zig");

// =============================================================================
// PCR (Platform Configuration Register) — TPM-like measurement chain
// =============================================================================

pub const NUM_PCRS: usize = 8;

pub const PCR_TEXT: usize = 0; // Kernel .text (code)
pub const PCR_RODATA: usize = 1; // Kernel .rodata (read-only data)
pub const PCR_DATA: usize = 2; // Kernel .data (initialized data snapshot)
pub const PCR_CONFIG: usize = 3; // Boot config / policy
pub const PCR_MODULES: usize = 4; // Loaded modules
pub const PCR_KERNEL: usize = 5; // Full kernel image
pub const PCR_AGGREGATE: usize = 6; // Chain aggregate (all stages)
pub const PCR_RUNTIME: usize = 7; // Runtime measurements

var pcr_values: [NUM_PCRS][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** NUM_PCRS;
var pcr_extended: [NUM_PCRS]bool = [_]bool{false} ** NUM_PCRS;
var pcr_extend_count: [NUM_PCRS]u16 = [_]u16{0} ** NUM_PCRS;

// Extend buffer (PCR_old || measurement)
var pcr_extend_buf: [64]u8 = [_]u8{0} ** 64;

// =============================================================================
// Event Log — records every PCR extend operation
// =============================================================================

pub const MAX_EVENTS: usize = 32;

pub const EventEntry = struct {
    pcr_index: u8,
    description: [24]u8,
    desc_len: u8,
    measurement: [32]u8,
    sequence: u16,
    valid: bool,

    pub fn getDesc(self: *const EventEntry) []const u8 {
        return self.description[0..self.desc_len];
    }
};

var events: [MAX_EVENTS]EventEntry = undefined;
var event_count: usize = 0;
var event_sequence: u16 = 0;

// =============================================================================
// Boot Chain State
// =============================================================================

pub const CHAIN_STAGES_TOTAL: u8 = 6;

var chain_complete: bool = false;
var chain_sealed: bool = false;
var chain_stages_done: u8 = 0;

pub const ChainStatus = struct {
    complete: bool,
    sealed: bool,
    stages_done: u8,
    stages_total: u8,
    pcrs_extended: u8,
    event_count: u16,
};

// =============================================================================
// Boot-time Reference Hashes (for runtime re-verification)
// =============================================================================

var boot_text_hash: [32]u8 = [_]u8{0} ** 32;
var boot_rodata_hash: [32]u8 = [_]u8{0} ** 32;
var boot_hashes_stored: bool = false;

// =============================================================================
// Kernel Boundaries (set by linker)
// =============================================================================

extern const __kernel_start: u8;
extern const __kernel_end: u8;

// Section boundaries (set by linker)
extern const __text_start: u8;
extern const __text_end: u8;
extern const __rodata_start: u8;
extern const __rodata_end: u8;
extern const __data_start: u8;
extern const __data_end: u8;
extern const __bss_start: u8;
extern const __bss_end: u8;

// =============================================================================
// Module Measurement (existing)
// =============================================================================

pub const ModuleHash = struct {
    name: [32]u8,
    name_len: u8,
    hash_val: [32]u8,
    size: usize,
    valid: bool,
};

var module_hashes: [16]ModuleHash = undefined;
var module_count: usize = 0;

// Temporary hash buffer for chain operations
var chain_tmp_hash: [32]u8 = [_]u8{0} ** 32;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    // Init modules
    module_count = 0;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        module_hashes[i].valid = false;
        module_hashes[i].name_len = 0;
        module_hashes[i].size = 0;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            module_hashes[i].name[j] = 0;
            module_hashes[i].hash_val[j] = 0;
        }
    }

    // Init PCRs
    initPcr();

    // Init boot hashes
    boot_hashes_stored = false;
    ct.secureZero32(&boot_text_hash);
    ct.secureZero32(&boot_rodata_hash);
}

/// Initialize / reset all PCR registers and event log
pub fn initPcr() void {
    var i: usize = 0;
    while (i < NUM_PCRS) : (i += 1) {
        ct.secureZero32(&pcr_values[i]);
        pcr_extended[i] = false;
        pcr_extend_count[i] = 0;
    }

    // Init event log
    event_count = 0;
    event_sequence = 0;
    i = 0;
    while (i < MAX_EVENTS) : (i += 1) {
        events[i].valid = false;
        events[i].pcr_index = 0;
        events[i].desc_len = 0;
        events[i].sequence = 0;
        var j: usize = 0;
        while (j < 24) : (j += 1) {
            events[i].description[j] = 0;
        }
        j = 0;
        while (j < 32) : (j += 1) {
            events[i].measurement[j] = 0;
        }
    }

    // Reset chain state
    chain_complete = false;
    chain_sealed = false;
    chain_stages_done = 0;
}

// =============================================================================
// PCR Operations
// =============================================================================

/// Extend PCR: PCR_new = SHA256(PCR_old || measurement)
pub fn extendPcr(index: usize, measurement: *const [32]u8, desc: []const u8) bool {
    if (index >= NUM_PCRS) return false;
    if (chain_sealed) return false;

    // Build extend buffer: PCR_old || measurement
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        pcr_extend_buf[i] = pcr_values[index][i];
    }
    i = 0;
    while (i < 32) : (i += 1) {
        pcr_extend_buf[32 + i] = measurement[i];
    }

    // PCR_new = SHA256(PCR_old || measurement)
    hash.sha256Into(&pcr_extend_buf, &pcr_values[index]);

    pcr_extended[index] = true;
    pcr_extend_count[index] += 1;

    // Log event
    logEvent(@intCast(index), measurement, desc);

    return true;
}

/// Get PCR value by index (returns null for invalid index)
pub fn getPcr(index: usize) ?*const [32]u8 {
    if (index >= NUM_PCRS) return null;
    return &pcr_values[index];
}

/// Check if a PCR has been extended
pub fn isPcrExtended(index: usize) bool {
    if (index >= NUM_PCRS) return false;
    return pcr_extended[index];
}

/// Get number of times a PCR was extended
pub fn getPcrExtendCount(index: usize) u16 {
    if (index >= NUM_PCRS) return 0;
    return pcr_extend_count[index];
}

/// Count how many PCRs have been extended
pub fn getExtendedPcrCount() u8 {
    var count: u8 = 0;
    var i: usize = 0;
    while (i < NUM_PCRS) : (i += 1) {
        if (pcr_extended[i]) count += 1;
    }
    return count;
}

/// Compute PCR extend without modifying state (for testing)
pub fn computeExtend(current: *const [32]u8, measurement: *const [32]u8, out: *[32]u8) void {
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[i] = current[i];
    }
    i = 0;
    while (i < 32) : (i += 1) {
        buf[32 + i] = measurement[i];
    }
    hash.sha256Into(&buf, out);
}

/// Get PCR name for display
pub fn getPcrName(index: usize) []const u8 {
    return switch (index) {
        PCR_TEXT => ".text",
        PCR_RODATA => ".rodata",
        PCR_DATA => ".data",
        PCR_CONFIG => "config",
        PCR_MODULES => "modules",
        PCR_KERNEL => "kernel",
        PCR_AGGREGATE => "aggregate",
        PCR_RUNTIME => "runtime",
        else => "unknown",
    };
}

// =============================================================================
// Event Log
// =============================================================================

fn logEvent(pcr_index: u8, measurement: *const [32]u8, desc: []const u8) void {
    if (event_count >= MAX_EVENTS) return;

    var e = &events[event_count];
    e.pcr_index = pcr_index;
    e.sequence = event_sequence;
    e.valid = true;

    // Copy description
    const dlen = if (desc.len > 24) 24 else desc.len;
    var i: usize = 0;
    while (i < dlen) : (i += 1) {
        e.description[i] = desc[i];
    }
    e.desc_len = @intCast(dlen);

    // Copy measurement hash
    i = 0;
    while (i < 32) : (i += 1) {
        e.measurement[i] = measurement[i];
    }

    event_count += 1;
    event_sequence += 1;
}

/// Get event by index
pub fn getEvent(index: usize) ?*const EventEntry {
    if (index >= event_count) return null;
    if (!events[index].valid) return null;
    return &events[index];
}

/// Get total event count
pub fn getEventCount() usize {
    return event_count;
}

// =============================================================================
// Kernel Measurement (existing, unchanged)
// =============================================================================

/// Measure full kernel image and produce hash
pub fn measureKernel(out: *[32]u8) bool {
    const start = @intFromPtr(&__kernel_start);
    const end = @intFromPtr(&__kernel_end);

    if (end <= start) {
        serial.writeString("[MEASURE] Invalid kernel boundaries\n");
        return false;
    }

    const size = end - start;
    if (size < 0x1000 or size > 0x10000000) {
        serial.writeString("[MEASURE] Kernel size out of range\n");
        return false;
    }

    const kernel_ptr: [*]const u8 = @ptrFromInt(start);
    hash.sha256Into(kernel_ptr[0..size], out);
    return true;
}

/// Get kernel size
pub fn getKernelSize() usize {
    const start = @intFromPtr(&__kernel_start);
    const end = @intFromPtr(&__kernel_end);
    if (end <= start) return 0;
    return end - start;
}

/// Get kernel start address
pub fn getKernelStart() usize {
    return @intFromPtr(&__kernel_start);
}

/// Get kernel end address
pub fn getKernelEnd() usize {
    return @intFromPtr(&__kernel_end);
}

// =============================================================================
// Per-Section Measurement (H.5 NEW)
// =============================================================================

/// Measure .text section (executable code — should be immutable)
pub fn measureTextSection(out: *[32]u8) bool {
    const start = @intFromPtr(&__text_start);
    const end = @intFromPtr(&__text_end);

    if (end <= start) return false;
    const size = end - start;
    if (size < 0x100 or size > 0x10000000) return false;

    const ptr: [*]const u8 = @ptrFromInt(start);
    hash.sha256Into(ptr[0..size], out);
    return true;
}

/// Measure .rodata section (read-only data — should be immutable)
pub fn measureRodataSection(out: *[32]u8) bool {
    const start = @intFromPtr(&__rodata_start);
    const end = @intFromPtr(&__rodata_end);

    if (end <= start) return false;
    const size = end - start;
    if (size < 0x10 or size > 0x10000000) return false;

    const ptr: [*]const u8 = @ptrFromInt(start);
    hash.sha256Into(ptr[0..size], out);
    return true;
}

/// Measure .data section (initialized data — snapshot at measurement time)
pub fn measureDataSection(out: *[32]u8) bool {
    const start = @intFromPtr(&__data_start);
    const end = @intFromPtr(&__data_end);

    if (end <= start) return false;
    const size = end - start;
    if (size > 0x10000000) return false;

    const ptr: [*]const u8 = @ptrFromInt(start);
    hash.sha256Into(ptr[0..size], out);
    return true;
}

/// Validate .bss section boundaries are sane
pub fn validateBssSection() bool {
    const start = @intFromPtr(&__bss_start);
    const end = @intFromPtr(&__bss_end);

    if (end < start) return false;

    // BSS should be in high memory (kernel space)
    if (start < 0xFFFFFFFF80000000) return false;

    // Size reasonable
    const size = end - start;
    if (size > 0x10000000) return false; // Max 256MB

    return true;
}

/// Get section size by name
pub fn getSectionSize(comptime section: []const u8) usize {
    if (comptime strEqualComptime(section, ".text")) {
        const s = @intFromPtr(&__text_start);
        const e = @intFromPtr(&__text_end);
        return if (e > s) e - s else 0;
    } else if (comptime strEqualComptime(section, ".rodata")) {
        const s = @intFromPtr(&__rodata_start);
        const e = @intFromPtr(&__rodata_end);
        return if (e > s) e - s else 0;
    } else if (comptime strEqualComptime(section, ".data")) {
        const s = @intFromPtr(&__data_start);
        const e = @intFromPtr(&__data_end);
        return if (e > s) e - s else 0;
    } else if (comptime strEqualComptime(section, ".bss")) {
        const s = @intFromPtr(&__bss_start);
        const e = @intFromPtr(&__bss_end);
        return if (e > s) e - s else 0;
    } else {
        return 0;
    }
}

fn strEqualComptime(comptime a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

// =============================================================================
// Boot-time Reference Hash Access
// =============================================================================

pub fn getBootTextHash() *const [32]u8 {
    return &boot_text_hash;
}

pub fn getBootRodataHash() *const [32]u8 {
    return &boot_rodata_hash;
}

pub fn hasBootHashes() bool {
    return boot_hashes_stored;
}

// =============================================================================
// Memory Layout Validation (existing, unchanged)
// =============================================================================

pub fn validateMemoryLayout() bool {
    const start = @intFromPtr(&__kernel_start);
    const end = @intFromPtr(&__kernel_end);

    if (end <= start) return false;
    if (start < 0xFFFFFFFF80000000) return false;

    const size = end - start;
    if (size < 0x1000) return false;
    if (size > 0x10000000) return false;

    return true;
}

/// Validate boot parameters
pub fn validateBootParams() bool {
    return true;
}

// =============================================================================
// Boot Measurement Chain (H.5 — orchestrates full measurement)
// =============================================================================

/// Run the complete boot measurement chain
/// Measures all sections, extends PCRs, builds aggregate
pub fn runBootChain() bool {
    serial.writeString("[MEASURE] Running boot measurement chain...\n");

    if (chain_sealed) {
        serial.writeString("[MEASURE] Chain is sealed, cannot re-run\n");
        return false;
    }

    initPcr();

    // Stage 1: .text
    serial.writeString("[MEASURE] Stage 1/6: .text section\n");
    if (measureTextSection(&chain_tmp_hash)) {
        _ = extendPcr(PCR_TEXT, &chain_tmp_hash, "kernel .text");
        _ = extendPcr(PCR_AGGREGATE, &chain_tmp_hash, "agg: .text");

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            boot_text_hash[i] = chain_tmp_hash[i];
        }
        chain_stages_done += 1;
    } else {
        serial.writeString("[MEASURE] WARNING: .text measurement failed\n");
    }

    // Stage 2: .rodata
    serial.writeString("[MEASURE] Stage 2/6: .rodata section\n");
    if (measureRodataSection(&chain_tmp_hash)) {
        _ = extendPcr(PCR_RODATA, &chain_tmp_hash, "kernel .rodata");
        _ = extendPcr(PCR_AGGREGATE, &chain_tmp_hash, "agg: .rodata");

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            boot_rodata_hash[i] = chain_tmp_hash[i];
        }
        chain_stages_done += 1;
    } else {
        serial.writeString("[MEASURE] WARNING: .rodata measurement failed\n");
    }

    boot_hashes_stored = true;

    // Stage 3: .data
    serial.writeString("[MEASURE] Stage 3/6: .data section\n");
    if (measureDataSection(&chain_tmp_hash)) {
        _ = extendPcr(PCR_DATA, &chain_tmp_hash, "kernel .data");
        _ = extendPcr(PCR_AGGREGATE, &chain_tmp_hash, "agg: .data");
        chain_stages_done += 1;
    } else {
        serial.writeString("[MEASURE] WARNING: .data measurement failed\n");
    }

    // Stage 4: boot config
    serial.writeString("[MEASURE] Stage 4/6: boot config\n");
    {
        const config_marker = [_]u8{ 'Z', 'A', 'M', 'R', 'U', 'D', '_', 'B', 'O', 'O', 'T', '_', 'C', 'O', 'N', 'F' };
        hash.sha256Into(&config_marker, &chain_tmp_hash);
        _ = extendPcr(PCR_CONFIG, &chain_tmp_hash, "boot config");
        _ = extendPcr(PCR_AGGREGATE, &chain_tmp_hash, "agg: config");
        chain_stages_done += 1;
    }

    // Stage 5: modules
    serial.writeString("[MEASURE] Stage 5/6: modules\n");
    {
        var i: usize = 0;
        while (i < module_count) : (i += 1) {
            if (module_hashes[i].valid) {
                _ = extendPcr(PCR_MODULES, &module_hashes[i].hash_val, "module");
                _ = extendPcr(PCR_AGGREGATE, &module_hashes[i].hash_val, "agg: module");
            }
        }
        if (module_count == 0) {
            const no_mod = [_]u8{0} ** 32;
            _ = extendPcr(PCR_MODULES, &no_mod, "no modules");
            _ = extendPcr(PCR_AGGREGATE, &no_mod, "agg: no mod");
        }
        chain_stages_done += 1;
    }

    // Stage 6: full kernel
    serial.writeString("[MEASURE] Stage 6/6: full kernel\n");
    if (measureKernel(&chain_tmp_hash)) {
        _ = extendPcr(PCR_KERNEL, &chain_tmp_hash, "full kernel");
        _ = extendPcr(PCR_AGGREGATE, &chain_tmp_hash, "agg: kernel");
        chain_stages_done += 1;
    } else {
        serial.writeString("[MEASURE] WARNING: kernel measurement failed\n");
    }

    chain_complete = (chain_stages_done >= CHAIN_STAGES_TOTAL);

    serial.writeString("[MEASURE] Chain complete: ");
    printDecSerial(chain_stages_done);
    serial.writeString("/");
    printDecSerial(CHAIN_STAGES_TOTAL);
    serial.writeString(" stages, ");
    printDecSerial(getExtendedPcrCount());
    serial.writeString(" PCRs, ");
    printDecSerial(@intCast(event_count));
    serial.writeString(" events\n");

    ct.secureZero32(&chain_tmp_hash);

    return chain_complete;
}
/// Check if boot chain measurement is complete
pub fn isChainComplete() bool {
    return chain_complete;
}

/// Seal the chain — no more PCR extends allowed
pub fn sealChain() void {
    chain_sealed = true;
    serial.writeString("[MEASURE] Chain SEALED - no further extends\n");
}

/// Check if chain is sealed
pub fn isChainSealed() bool {
    return chain_sealed;
}

/// Get chain status
pub fn getChainStatus() ChainStatus {
    return ChainStatus{
        .complete = chain_complete,
        .sealed = chain_sealed,
        .stages_done = chain_stages_done,
        .stages_total = CHAIN_STAGES_TOTAL,
        .pcrs_extended = getExtendedPcrCount(),
        .event_count = @intCast(event_count),
    };
}

// =============================================================================
// Module Measurement (existing)
// =============================================================================

pub fn measureModule(name: []const u8, data: []const u8) bool {
    if (module_count >= 16) return false;

    var m = &module_hashes[module_count];

    var i: usize = 0;
    while (i < name.len and i < 32) : (i += 1) {
        m.name[i] = name[i];
    }
    m.name_len = @intCast(i);

    hash.sha256Into(data, &m.hash_val);
    m.size = data.len;
    m.valid = true;

    module_count += 1;
    return true;
}

pub fn getModuleHash(name: []const u8) ?*const [32]u8 {
    var i: usize = 0;
    while (i < module_count) : (i += 1) {
        if (!module_hashes[i].valid) continue;
        const m_name = module_hashes[i].name[0..module_hashes[i].name_len];
        if (strEqual(m_name, name)) {
            return &module_hashes[i].hash_val;
        }
    }
    return null;
}

pub fn getModuleCount() usize {
    return module_count;
}

// =============================================================================
// Helpers
// =============================================================================

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn printDecSerial(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
