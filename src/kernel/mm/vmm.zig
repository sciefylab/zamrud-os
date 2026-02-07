//! Zamrud OS - Virtual Memory Manager (VMM)
//! Implements x86-64 4-level paging

const serial = @import("../drivers/serial/serial.zig");
const limine = @import("../core/limine.zig");
const pmm = @import("pmm.zig");

// Page constants
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u6 = 12;

// Page table entry flags
pub const PageFlags = struct {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
};

// Standard flag combinations
pub const KERNEL_FLAGS: u64 = PageFlags.PRESENT | PageFlags.WRITABLE;
pub const USER_FLAGS: u64 = PageFlags.PRESENT | PageFlags.WRITABLE | PageFlags.USER;

// Page table indices from virtual address
inline fn pml4_index(virt: u64) u9 {
    return @truncate((virt >> 39) & 0x1FF);
}

inline fn pdpt_index(virt: u64) u9 {
    return @truncate((virt >> 30) & 0x1FF);
}

inline fn pd_index(virt: u64) u9 {
    return @truncate((virt >> 21) & 0x1FF);
}

inline fn pt_index(virt: u64) u9 {
    return @truncate((virt >> 12) & 0x1FF);
}

inline fn page_offset(virt: u64) u12 {
    return @truncate(virt & 0xFFF);
}

// Current PML4 (CR3)
var kernel_pml4_phys: u64 = 0;
var hhdm_offset: u64 = 0;

// ============================================================================
// Safe Memory Access (avoid SSE)
// ============================================================================

fn safeRead(addr: u64) u64 {
    var result: u64 = undefined;
    asm volatile ("mov (%[addr]), %[result]"
        : [result] "=r" (result),
        : [addr] "r" (addr),
    );
    return result;
}

fn safeWrite(addr: u64, value: u64) void {
    asm volatile ("mov %[value], (%[addr])"
        :
        : [addr] "r" (addr),
          [value] "r" (value),
    );
}

// ============================================================================
// Page Table Operations
// ============================================================================

/// Read page table entry using HHDM
fn readEntry(table_phys: u64, index: u64) u64 {
    const entry_addr = hhdm_offset + table_phys + index * 8;
    return safeRead(entry_addr);
}

/// Write page table entry using HHDM
fn writeEntry(table_phys: u64, index: u64, value: u64) void {
    const entry_addr = hhdm_offset + table_phys + index * 8;
    safeWrite(entry_addr, value);
}

/// Get or create next level page table
/// IMPORTANT: Propagate USER flag to all levels!
fn getOrCreateTable(table_phys: u64, index: u64, flags: u64) ?u64 {
    var entry = readEntry(table_phys, index);

    if ((entry & PageFlags.PRESENT) == 0) {
        // Allocate new page table
        const new_table = pmm.allocPage() orelse return null;

        // Clear the new table
        var i: u64 = 0;
        while (i < 512) : (i += 1) {
            writeEntry(new_table, i, 0);
        }

        // Set entry with flags (including USER if requested)
        entry = new_table | flags | PageFlags.PRESENT | PageFlags.WRITABLE;
        writeEntry(table_phys, index, entry);
    } else {
        // Entry exists - make sure USER flag is set if needed
        if ((flags & PageFlags.USER) != 0 and (entry & PageFlags.USER) == 0) {
            entry = entry | PageFlags.USER;
            writeEntry(table_phys, index, entry);
        }
    }

    return entry & ~@as(u64, 0xFFF); // Clear flags, return physical address
}

// ============================================================================
// VMM Public Functions
// ============================================================================

/// Initialize VMM
pub fn init() void {
    serial.writeString("[VMM] Initializing Virtual Memory Manager...\n");

    // Get HHDM offset from PMM
    hhdm_offset = pmm.getHhdmOffset();
    serial.writeString("[VMM] HHDM offset: ");
    printHex64(hhdm_offset);
    serial.writeString("\n");

    // Get current PML4 from CR3
    kernel_pml4_phys = asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
    kernel_pml4_phys &= ~@as(u64, 0xFFF); // Clear flags

    serial.writeString("[VMM] Kernel PML4: ");
    printHex64(kernel_pml4_phys);
    serial.writeString("\n");

    serial.writeString("[VMM] Virtual Memory Manager initialized!\n");
}

/// Map a physical page to virtual address
pub fn mapPage(virt: u64, phys: u64, flags: u64) bool {
    // Check alignment
    if (virt % PAGE_SIZE != 0 or phys % PAGE_SIZE != 0) {
        serial.writeString("[VMM] ERROR: Unaligned mapping!\n");
        return false;
    }

    // Get PML4 - pass flags so USER bit propagates
    const pml4_idx = pml4_index(virt);
    const pdpt_phys = getOrCreateTable(kernel_pml4_phys, pml4_idx, flags) orelse {
        serial.writeString("[VMM] ERROR: Failed to get PDPT!\n");
        return false;
    };

    // Get PDPT
    const pdpt_idx = pdpt_index(virt);
    const pd_phys = getOrCreateTable(pdpt_phys, pdpt_idx, flags) orelse {
        serial.writeString("[VMM] ERROR: Failed to get PD!\n");
        return false;
    };

    // Get PD
    const pd_idx = pd_index(virt);
    const pt_phys = getOrCreateTable(pd_phys, pd_idx, flags) orelse {
        serial.writeString("[VMM] ERROR: Failed to get PT!\n");
        return false;
    };

    // Set PT entry
    const pt_idx = pt_index(virt);
    const entry = phys | flags | PageFlags.PRESENT;
    writeEntry(pt_phys, pt_idx, entry);

    // Flush TLB for this address
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt),
    );

    return true;
}

/// Unmap a virtual page
pub fn unmapPage(virt: u64) bool {
    // Check alignment
    if (virt % PAGE_SIZE != 0) {
        serial.writeString("[VMM] ERROR: Unaligned unmap!\n");
        return false;
    }

    // Walk page tables
    const pml4_idx = pml4_index(virt);
    var entry = readEntry(kernel_pml4_phys, pml4_idx);
    if ((entry & PageFlags.PRESENT) == 0) return false;

    const pdpt_phys = entry & ~@as(u64, 0xFFF);
    const pdpt_idx = pdpt_index(virt);
    entry = readEntry(pdpt_phys, pdpt_idx);
    if ((entry & PageFlags.PRESENT) == 0) return false;

    const pd_phys = entry & ~@as(u64, 0xFFF);
    const pd_idx = pd_index(virt);
    entry = readEntry(pd_phys, pd_idx);
    if ((entry & PageFlags.PRESENT) == 0) return false;

    const pt_phys = entry & ~@as(u64, 0xFFF);
    const pt_idx = pt_index(virt);

    // Clear PT entry
    writeEntry(pt_phys, pt_idx, 0);

    // Flush TLB
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt),
    );

    return true;
}

/// Check if virtual address is mapped
pub fn isMapped(virt: u64) u64 {
    const pml4_idx = pml4_index(virt);
    var entry = readEntry(kernel_pml4_phys, pml4_idx);
    if ((entry & PageFlags.PRESENT) == 0) return 0;

    const pdpt_phys = entry & ~@as(u64, 0xFFF);
    const pdpt_idx = pdpt_index(virt);
    entry = readEntry(pdpt_phys, pdpt_idx);
    if ((entry & PageFlags.PRESENT) == 0) return 0;

    if ((entry & PageFlags.HUGE_PAGE) != 0) return 1;

    const pd_phys = entry & ~@as(u64, 0xFFF);
    const pd_idx = pd_index(virt);
    entry = readEntry(pd_phys, pd_idx);
    if ((entry & PageFlags.PRESENT) == 0) return 0;

    if ((entry & PageFlags.HUGE_PAGE) != 0) return 1;

    const pt_phys = entry & ~@as(u64, 0xFFF);
    const pt_idx = pt_index(virt);
    entry = readEntry(pt_phys, pt_idx);
    if ((entry & PageFlags.PRESENT) == 0) return 0;

    return 1;
}

/// Get physical address for virtual address
pub fn getPhysicalAddress(virt: u64) u64 {
    const NOT_MAPPED: u64 = 0xFFFFFFFFFFFFFFFF;

    const pml4_idx = pml4_index(virt);
    var entry = readEntry(kernel_pml4_phys, pml4_idx);
    if ((entry & PageFlags.PRESENT) == 0) return NOT_MAPPED;

    const pdpt_phys = entry & ~@as(u64, 0xFFF);
    const pdpt_idx = pdpt_index(virt);
    entry = readEntry(pdpt_phys, pdpt_idx);
    if ((entry & PageFlags.PRESENT) == 0) return NOT_MAPPED;

    if ((entry & PageFlags.HUGE_PAGE) != 0) {
        const phys_base = entry & ~@as(u64, 0x3FFFFFFF);
        return phys_base | (virt & 0x3FFFFFFF);
    }

    const pd_phys = entry & ~@as(u64, 0xFFF);
    const pd_idx = pd_index(virt);
    entry = readEntry(pd_phys, pd_idx);
    if ((entry & PageFlags.PRESENT) == 0) return NOT_MAPPED;

    if ((entry & PageFlags.HUGE_PAGE) != 0) {
        const phys_base = entry & ~@as(u64, 0x1FFFFF);
        return phys_base | (virt & 0x1FFFFF);
    }

    const pt_phys = entry & ~@as(u64, 0xFFF);
    const pt_idx = pt_index(virt);
    entry = readEntry(pt_phys, pt_idx);
    if ((entry & PageFlags.PRESENT) == 0) return NOT_MAPPED;

    const phys_page = entry & ~@as(u64, 0xFFF);
    return phys_page | page_offset(virt);
}

/// Map multiple contiguous pages
pub fn mapPages(virt_start: u64, phys_start: u64, count: u64, flags: u64) bool {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const virt = virt_start + i * PAGE_SIZE;
        const phys = phys_start + i * PAGE_SIZE;
        if (!mapPage(virt, phys, flags)) {
            var j: u64 = 0;
            while (j < i) : (j += 1) {
                _ = unmapPage(virt_start + j * PAGE_SIZE);
            }
            return false;
        }
    }
    return true;
}

/// Unmap multiple contiguous pages
pub fn unmapPages(virt_start: u64, count: u64) void {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        _ = unmapPage(virt_start + i * PAGE_SIZE);
    }
}

// ============================================================================
// Debug Functions
// ============================================================================

/// Debug: Print page table walk untuk virtual address
pub fn debugPageWalk(virt: u64) void {
    serial.writeString("[VMM] Page walk for 0x");
    printHex64(virt);
    serial.writeString("\n");

    const pml4_idx = pml4_index(virt);
    serial.writeString("  PML4[0x");
    printHex9(pml4_idx);
    serial.writeString("] = 0x");

    var entry = readEntry(kernel_pml4_phys, pml4_idx);
    printHex64(entry);
    printFlags(entry);

    if ((entry & PageFlags.PRESENT) == 0) {
        serial.writeString(" NOT PRESENT!\n");
        return;
    }
    serial.writeString("\n");

    const pdpt_phys = entry & ~@as(u64, 0xFFF);
    const pdpt_idx = pdpt_index(virt);
    serial.writeString("  PDPT[0x");
    printHex9(pdpt_idx);
    serial.writeString("] = 0x");

    entry = readEntry(pdpt_phys, pdpt_idx);
    printHex64(entry);
    printFlags(entry);

    if ((entry & PageFlags.PRESENT) == 0) {
        serial.writeString(" NOT PRESENT!\n");
        return;
    }
    if ((entry & PageFlags.HUGE_PAGE) != 0) {
        serial.writeString(" (1GB HUGE)\n");
        return;
    }
    serial.writeString("\n");

    const pd_phys = entry & ~@as(u64, 0xFFF);
    const pd_idx = pd_index(virt);
    serial.writeString("  PD[0x");
    printHex9(pd_idx);
    serial.writeString("] = 0x");

    entry = readEntry(pd_phys, pd_idx);
    printHex64(entry);
    printFlags(entry);

    if ((entry & PageFlags.PRESENT) == 0) {
        serial.writeString(" NOT PRESENT!\n");
        return;
    }
    if ((entry & PageFlags.HUGE_PAGE) != 0) {
        serial.writeString(" (2MB HUGE)\n");
        return;
    }
    serial.writeString("\n");

    const pt_phys = entry & ~@as(u64, 0xFFF);
    const pt_idx = pt_index(virt);
    serial.writeString("  PT[0x");
    printHex9(pt_idx);
    serial.writeString("] = 0x");

    entry = readEntry(pt_phys, pt_idx);
    printHex64(entry);
    printFlags(entry);
    serial.writeString("\n");
}

fn printFlags(entry: u64) void {
    serial.writeString(" [");
    if ((entry & PageFlags.PRESENT) != 0) serial.writeChar('P') else serial.writeChar('-');
    if ((entry & PageFlags.WRITABLE) != 0) serial.writeChar('W') else serial.writeChar('-');
    if ((entry & PageFlags.USER) != 0) serial.writeChar('U') else serial.writeChar('-');
    serial.writeString("]");
}

/// Print 9-bit value as 3 hex digits
fn printHex9(val: u9) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 8) & 0x1]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nibble: u8 = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printHex16(value: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 12) & 0xF]);
    serial.writeChar(hex[(value >> 8) & 0xF]);
    serial.writeChar(hex[(value >> 4) & 0xF]);
    serial.writeChar(hex[value & 0xF]);
}

// ============================================================================
// VMM Tests
// ============================================================================

pub fn test_vmm() void {
    serial.writeString("\n========================================\n");
    serial.writeString("  VMM Tests\n");
    serial.writeString("========================================\n");

    serial.writeString("\n[TEST 1] Map virtual to physical:\n");

    const test_virt: u64 = 0xDEADBEEF000;
    const test_phys = pmm.allocPage() orelse {
        serial.writeString("  Failed to allocate test page!\n");
        return;
    };

    serial.writeString("  Physical page: ");
    printHex64(test_phys);
    serial.writeString("\n");

    serial.writeString("  Mapping to virt: ");
    printHex64(test_virt);
    serial.writeString("\n");

    if (mapPage(test_virt, test_phys, KERNEL_FLAGS)) {
        serial.writeString("  Mapping successful [OK]\n");
    } else {
        serial.writeString("  Mapping failed [FAIL]\n");
        pmm.freePage(test_phys);
        return;
    }

    serial.writeString("\n[TEST 2] Verify mapping:\n");
    if (isMapped(test_virt) == 1) {
        serial.writeString("  Page is mapped [OK]\n");
    } else {
        serial.writeString("  Page not mapped [FAIL]\n");
    }

    const resolved = getPhysicalAddress(test_virt);
    serial.writeString("  Resolved physical: ");
    printHex64(resolved);
    if (resolved == test_phys) {
        serial.writeString(" [OK]\n");
    } else {
        serial.writeString(" [FAIL]\n");
    }

    serial.writeString("\n[TEST 3] Write/Read through mapping:\n");
    const test_ptr: *volatile u64 = @ptrFromInt(test_virt);
    const test_value: u64 = 0xCAFEBABEDEADBEEF;
    test_ptr.* = test_value;

    const read_value = test_ptr.*;
    serial.writeString("  Wrote: ");
    printHex64(test_value);
    serial.writeString("\n");
    serial.writeString("  Read:  ");
    printHex64(read_value);
    if (read_value == test_value) {
        serial.writeString(" [OK]\n");
    } else {
        serial.writeString(" [FAIL]\n");
    }

    serial.writeString("\n[TEST 4] Unmap page:\n");
    if (unmapPage(test_virt)) {
        serial.writeString("  Unmapped successfully [OK]\n");
    } else {
        serial.writeString("  Unmap failed [FAIL]\n");
    }

    serial.writeString("  Verifying unmap...\n");
    if (isMapped(test_virt) == 0) {
        serial.writeString("  Verified unmapped [OK]\n");
    } else {
        serial.writeString("  Still mapped [FAIL]\n");
    }

    serial.writeString("  Freeing physical page...\n");
    pmm.freePage(test_phys);
    serial.writeString("  Physical page freed [OK]\n");

    serial.writeString("\n========================================\n");
    serial.writeString("  VMM Tests Complete!\n");
    serial.writeString("========================================\n\n");
}
