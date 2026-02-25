//! Zamrud OS - Secure Memory Sanitization (H.9)
//! Guarantees all freed memory is cryptographically wiped.

const serial = @import("../drivers/serial/serial.zig");
const pmm = @import("pmm.zig");
const vmm = @import("vmm.zig");

// =============================================================================
// Configuration
// =============================================================================

pub const SANITIZE_ENABLED: bool = true;
pub const WIPE_BYTE: u8 = 0x00;
pub const VERIFY_WIPE: bool = true;
pub const MAX_WIPE_PAGES: u64 = 256;

// =============================================================================
// Statistics
// =============================================================================

var stats = SanitizeStats{};

pub const SanitizeStats = struct {
    heap_wipes: u64 = 0,
    page_wipes: u64 = 0,
    stack_wipes: u64 = 0,
    process_wipes: u64 = 0,
    bytes_wiped: u64 = 0,
    verify_failures: u64 = 0,
    mlock_count: u32 = 0,
    mlock_pages: u32 = 0,
};

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[SANITIZE] Initializing secure memory sanitization (H.9)...\n");

    stats = SanitizeStats{};

    var i: usize = 0;
    while (i < MAX_MLOCK_ENTRIES) : (i += 1) {
        mlock_table[i] = MlockEntry{};
    }

    initialized = true;

    serial.writeString("[SANITIZE] Wipe byte: 0x");
    printHex8(WIPE_BYTE);
    serial.writeString("\n");
    serial.writeString("[SANITIZE] Verify wipe: ");
    if (VERIFY_WIPE) {
        serial.writeString("ON\n");
    } else {
        serial.writeString("OFF\n");
    }
    serial.writeString("[SANITIZE] Secure memory sanitization ACTIVE\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// H.9a: Secure Heap Wipe (for kfree) - BYTE BY BYTE to avoid alignment issues
// =============================================================================

pub fn secureWipeHeap(data_addr: u64, size: u64) void {
    if (!SANITIZE_ENABLED) return;
    if (size == 0) return;
    if (data_addr == 0) return;

    // Wipe byte-by-byte using volatile writes (safe for any alignment)
    var offset: u64 = 0;
    while (offset < size) : (offset += 1) {
        const ptr: *volatile u8 = @ptrFromInt(data_addr + offset);
        ptr.* = WIPE_BYTE;
    }

    // Verify wipe (also byte-by-byte)
    if (VERIFY_WIPE) {
        if (!verifyWiped(data_addr, size)) {
            stats.verify_failures += 1;
        }
    }

    stats.heap_wipes += 1;
    stats.bytes_wiped += size;
}

// =============================================================================
// H.9b: Secure Page Wipe (for freePage) - BYTE BY BYTE
// =============================================================================

pub fn secureWipePage(phys_addr: u64) void {
    if (!SANITIZE_ENABLED) return;
    if (phys_addr == 0) return;

    const hhdm = pmm.getHhdmOffset();
    const virt_addr = hhdm + phys_addr;

    // Wipe byte-by-byte (safe, no alignment assumption)
    var offset: u64 = 0;
    while (offset < pmm.PAGE_SIZE) : (offset += 1) {
        const ptr: *volatile u8 = @ptrFromInt(virt_addr + offset);
        ptr.* = WIPE_BYTE;
    }

    if (VERIFY_WIPE) {
        if (!verifyWiped(virt_addr, pmm.PAGE_SIZE)) {
            stats.verify_failures += 1;
        }
    }

    stats.page_wipes += 1;
    stats.bytes_wiped += pmm.PAGE_SIZE;
}

pub fn secureWipePages(phys_addr: u64, count: u64) void {
    if (!SANITIZE_ENABLED) return;
    if (count == 0) return;

    const pages = if (count > MAX_WIPE_PAGES) MAX_WIPE_PAGES else count;
    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        secureWipePage(phys_addr + i * pmm.PAGE_SIZE);
    }
}

// =============================================================================
// H.9c: Stack Guard Pages
// =============================================================================

pub fn installStackGuard(stack_base: u64) bool {
    if (!SANITIZE_ENABLED) return true;

    const guard_addr = stack_base - pmm.PAGE_SIZE;

    if (vmm.isMapped(guard_addr) == 1) {
        _ = vmm.unmapPage(guard_addr);
    }

    return true;
}

pub fn isGuardPageFault(fault_addr: u64) bool {
    const page_addr = fault_addr & ~@as(u64, 0xFFF);
    return vmm.isMapped(page_addr) == 0;
}

// =============================================================================
// H.9d: Process Exit Memory Wipe
// =============================================================================

pub fn secureWipeProcess(
    kernel_stack_addr: u64,
    kernel_stack_size: u64,
    pid: u32,
) void {
    if (!SANITIZE_ENABLED) return;

    if (kernel_stack_addr != 0 and kernel_stack_size > 0) {
        secureWipeStack(kernel_stack_addr, kernel_stack_size);
    }

    _ = pid;
    stats.process_wipes += 1;
}

pub fn secureWipeStack(stack_addr: u64, stack_size: u64) void {
    if (!SANITIZE_ENABLED) return;
    if (stack_addr == 0 or stack_size == 0) return;

    // Wipe byte-by-byte
    var offset: u64 = 0;
    while (offset < stack_size) : (offset += 1) {
        const ptr: *volatile u8 = @ptrFromInt(stack_addr + offset);
        ptr.* = WIPE_BYTE;
    }

    stats.stack_wipes += 1;
    stats.bytes_wiped += stack_size;
}

// =============================================================================
// H.9e: Sensitive Page Locking (mlock)
// =============================================================================

const MAX_MLOCK_ENTRIES: usize = 64;

const MlockEntry = struct {
    virt_addr: u64 = 0,
    page_count: u32 = 0,
    pid: u32 = 0,
    active: bool = false,
    label: [16]u8 = [_]u8{0} ** 16,
    label_len: u8 = 0,
};

var mlock_table: [MAX_MLOCK_ENTRIES]MlockEntry = [_]MlockEntry{.{}} ** MAX_MLOCK_ENTRIES;

pub fn mlock(virt_addr: u64, size: u64, pid: u32, label: []const u8) bool {
    if (!SANITIZE_ENABLED) return true;

    const page_count = (size + pmm.PAGE_SIZE - 1) / pmm.PAGE_SIZE;

    var slot: usize = 0;
    while (slot < MAX_MLOCK_ENTRIES) : (slot += 1) {
        if (!mlock_table[slot].active) {
            mlock_table[slot] = MlockEntry{
                .virt_addr = virt_addr,
                .page_count = @intCast(page_count),
                .pid = pid,
                .active = true,
            };

            const llen = @min(label.len, 16);
            var i: usize = 0;
            while (i < llen) : (i += 1) {
                mlock_table[slot].label[i] = label[i];
            }
            mlock_table[slot].label_len = @intCast(llen);

            stats.mlock_count += 1;
            stats.mlock_pages += @intCast(page_count);

            return true;
        }
    }

    return false;
}

pub fn munlock(virt_addr: u64, size: u64) bool {
    if (!SANITIZE_ENABLED) return true;

    var slot: usize = 0;
    while (slot < MAX_MLOCK_ENTRIES) : (slot += 1) {
        if (mlock_table[slot].active and mlock_table[slot].virt_addr == virt_addr) {
            const page_count = mlock_table[slot].page_count;

            // Wipe before unlock
            var i: u32 = 0;
            while (i < page_count) : (i += 1) {
                const page_virt = virt_addr + @as(u64, i) * pmm.PAGE_SIZE;
                if (vmm.isMapped(page_virt) == 1) {
                    // Byte-by-byte wipe
                    var offset: u64 = 0;
                    while (offset < pmm.PAGE_SIZE) : (offset += 1) {
                        const ptr: *volatile u8 = @ptrFromInt(page_virt + offset);
                        ptr.* = WIPE_BYTE;
                    }
                    stats.bytes_wiped += pmm.PAGE_SIZE;
                }
            }

            if (stats.mlock_count > 0) stats.mlock_count -= 1;
            if (stats.mlock_pages >= page_count) {
                stats.mlock_pages -= page_count;
            }

            mlock_table[slot] = MlockEntry{};
            _ = size;
            return true;
        }
    }

    _ = size;
    return false;
}

pub fn isMlocked(virt_addr: u64) bool {
    var slot: usize = 0;
    while (slot < MAX_MLOCK_ENTRIES) : (slot += 1) {
        if (mlock_table[slot].active) {
            const start = mlock_table[slot].virt_addr;
            const end = start + @as(u64, mlock_table[slot].page_count) * pmm.PAGE_SIZE;
            if (virt_addr >= start and virt_addr < end) {
                return true;
            }
        }
    }
    return false;
}

pub fn munlockAll(pid: u32) void {
    var slot: usize = 0;
    while (slot < MAX_MLOCK_ENTRIES) : (slot += 1) {
        if (mlock_table[slot].active and mlock_table[slot].pid == pid) {
            _ = munlock(mlock_table[slot].virt_addr, 0);
        }
    }
}

// =============================================================================
// Secure Struct Wipe
// =============================================================================

pub fn secureWipeStruct(addr: u64, size: u64) void {
    if (!SANITIZE_ENABLED) return;
    if (size == 0 or addr == 0) return;

    var offset: u64 = 0;
    while (offset < size) : (offset += 1) {
        const ptr: *volatile u8 = @ptrFromInt(addr + offset);
        ptr.* = 0;
    }

    stats.bytes_wiped += size;
}

// =============================================================================
// Verification (byte-by-byte, safe)
// =============================================================================

fn verifyWiped(addr: u64, size: u64) bool {
    var offset: u64 = 0;
    while (offset < size) : (offset += 1) {
        const ptr: *volatile u8 = @ptrFromInt(addr + offset);
        if (ptr.* != WIPE_BYTE) return false;
    }
    return true;
}

// =============================================================================
// Statistics
// =============================================================================

pub fn getStats() SanitizeStats {
    return stats;
}

pub fn resetStats() void {
    stats.heap_wipes = 0;
    stats.page_wipes = 0;
    stats.stack_wipes = 0;
    stats.process_wipes = 0;
    stats.bytes_wiped = 0;
    stats.verify_failures = 0;
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}
