//! Zamrud OS - Boot Measurement
//! Measures system components for integrity verification

const serial = @import("../drivers/serial/serial.zig");
const hash = @import("../crypto/hash.zig");

// =============================================================================
// Kernel Measurement
// =============================================================================

// Kernel boundaries (set by linker)
extern const __kernel_start: u8;
extern const __kernel_end: u8;

/// Measure kernel image and produce hash
pub fn measureKernel(out: *[32]u8) bool {
    const start = @intFromPtr(&__kernel_start);
    const end = @intFromPtr(&__kernel_end);

    if (end <= start) {
        serial.writeString("[MEASURE] Invalid kernel boundaries\n");
        return false;
    }

    const size = end - start;

    // Sanity check - kernel should be reasonable size
    if (size < 0x1000 or size > 0x10000000) { // 4KB to 256MB
        serial.writeString("[MEASURE] Kernel size out of range\n");
        return false;
    }

    // Hash kernel memory
    const kernel_ptr: [*]const u8 = @ptrFromInt(start);
    const kernel_slice = kernel_ptr[0..size];

    hash.sha256Into(kernel_slice, out);

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
// Memory Layout Validation
// =============================================================================

/// Validate memory layout is sane
pub fn validateMemoryLayout() bool {
    const start = @intFromPtr(&__kernel_start);
    const end = @intFromPtr(&__kernel_end);

    // Check 1: End > Start
    if (end <= start) {
        serial.writeString("[MEASURE] Memory: end <= start\n");
        return false;
    }

    // Check 2: Kernel in expected range (high memory for 64-bit)
    // Limine loads kernel at 0xFFFFFFFF80000000+ typically
    if (start < 0xFFFFFFFF80000000) {
        serial.writeString("[MEASURE] Memory: kernel not in high memory\n");
        return false;
    }

    // Check 3: Size reasonable
    const size = end - start;
    if (size < 0x1000) { // At least 4KB
        serial.writeString("[MEASURE] Memory: kernel too small\n");
        return false;
    }

    if (size > 0x10000000) { // Max 256MB
        serial.writeString("[MEASURE] Memory: kernel too large\n");
        return false;
    }

    return true;
}

// =============================================================================
// Boot Parameters Validation
// =============================================================================

/// Validate boot parameters
pub fn validateBootParams() bool {
    // In a full implementation, we would check:
    // - Command line parameters
    // - Boot flags
    // - Module list
    // - ACPI tables

    // For now, basic validation
    return true;
}

// =============================================================================
// Module Measurement
// =============================================================================

pub const ModuleHash = struct {
    name: [32]u8,
    name_len: u8,
    hash: [32]u8,
    size: usize,
    valid: bool,
};

var module_hashes: [16]ModuleHash = undefined;
var module_count: usize = 0;

pub fn init() void {
    module_count = 0;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        module_hashes[i].valid = false;
        module_hashes[i].name_len = 0;
        module_hashes[i].size = 0;

        var j: usize = 0;
        while (j < 32) : (j += 1) {
            module_hashes[i].name[j] = 0;
            module_hashes[i].hash[j] = 0;
        }
    }
}

/// Measure a module and store its hash
pub fn measureModule(name: []const u8, data: []const u8) bool {
    if (module_count >= 16) return false;

    var m = &module_hashes[module_count];

    // Copy name
    var i: usize = 0;
    while (i < name.len and i < 32) : (i += 1) {
        m.name[i] = name[i];
    }
    m.name_len = @intCast(i);

    // Hash data
    hash.sha256Into(data, &m.hash);
    m.size = data.len;
    m.valid = true;

    module_count += 1;
    return true;
}

/// Get module hash by name
pub fn getModuleHash(name: []const u8) ?*const [32]u8 {
    var i: usize = 0;
    while (i < module_count) : (i += 1) {
        if (!module_hashes[i].valid) continue;

        const m_name = module_hashes[i].name[0..module_hashes[i].name_len];
        if (strEqual(m_name, name)) {
            return &module_hashes[i].hash;
        }
    }
    return null;
}

/// Get module count
pub fn getModuleCount() usize {
    return module_count;
}

fn strEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}
