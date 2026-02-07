//! Zamrud OS - Physical Memory Manager (PMM)
//! Uses bitmap allocation for 4KB pages

const serial = @import("../drivers/serial/serial.zig");
const limine = @import("../core/limine.zig");

// Page size: 4 KB
pub const PAGE_SIZE: u64 = 4096;

// Bitmap for tracking free/used pages
// 1 bit per page: 0 = free, 1 = used
// Max 4GB RAM = 1M pages = 128KB bitmap
const MAX_PAGES: u64 = 1024 * 1024; // 4GB / 4KB
const BITMAP_SIZE: u64 = MAX_PAGES / 8; // 128 KB

var bitmap: [BITMAP_SIZE]u8 = undefined;
var total_pages: u64 = 0;
var used_pages: u64 = 0;
var hhdm_offset: u64 = 0;
var highest_page: u64 = 0;

// ============================================================================
// Safe Memory Read (avoid SSE)
// ============================================================================

fn readU8(addr: u64) u8 {
    var result: u8 = undefined;
    asm volatile ("movb (%[addr]), %[result]"
        : [result] "=r" (result),
        : [addr] "r" (addr),
    );
    return result;
}

fn readU64(addr: u64) u64 {
    var result: u64 = 0;
    var offset: u64 = 0;
    while (offset < 8) : (offset += 1) {
        const byte = readU8(addr + offset);
        result |= @as(u64, byte) << @intCast(offset * 8);
    }
    return result;
}

// ============================================================================
// Bitmap Operations
// ============================================================================

fn setBit(page: u64) void {
    if (page >= MAX_PAGES) return;
    const byte_idx = page / 8;
    const bit_idx: u3 = @truncate(page % 8);
    bitmap[byte_idx] |= (@as(u8, 1) << bit_idx);
}

fn clearBit(page: u64) void {
    if (page >= MAX_PAGES) return;
    const byte_idx = page / 8;
    const bit_idx: u3 = @truncate(page % 8);
    bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
}

fn testBit(page: u64) bool {
    if (page >= MAX_PAGES) return true; // Out of range = used
    const byte_idx = page / 8;
    const bit_idx: u3 = @truncate(page % 8);
    return (bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

// ============================================================================
// PMM Functions
// ============================================================================

/// Initialize PMM from Limine memory map
pub fn init(
    memmap_request: *limine.MemoryMapRequest,
    hhdm_request: *limine.HhdmRequest,
) void {
    serial.writeString("[PMM] Initializing Physical Memory Manager...\n");

    // Get HHDM offset
    if (hhdm_request.response) |hhdm| {
        hhdm_offset = hhdm.offset;
        serial.writeString("[PMM] HHDM offset: ");
        printHex64(hhdm_offset);
        serial.writeString("\n");
    } else {
        serial.writeString("[PMM] ERROR: No HHDM response!\n");
        return;
    }

    // Mark all pages as used initially
    for (&bitmap) |*b| {
        b.* = 0xFF;
    }

    // Get memory map
    const response = memmap_request.response orelse {
        serial.writeString("[PMM] ERROR: No memory map!\n");
        return;
    };

    const response_addr = @intFromPtr(response);
    const entry_count = readU64(response_addr + 8);
    const entries_addr = readU64(response_addr + 16);

    // Find highest usable address and mark free regions
    var highest_addr: u64 = 0;
    var total_usable: u64 = 0;

    serial.writeString("[PMM] Processing memory map...\n");

    // Process each entry
    var i: u64 = 0;
    while (i < entry_count) : (i += 1) {
        const entry_addr = readU64(entries_addr + i * 8);
        const base = readU64(entry_addr);
        const length = readU64(entry_addr + 8);
        const kind = readU64(entry_addr + 16);

        // Track highest address
        const end_addr = base + length;
        if (end_addr > highest_addr) {
            highest_addr = end_addr;
        }

        // Only mark USABLE regions as free
        if (kind == 0) { // USABLE
            serial.writeString("  Free region: ");
            printHex64(base);
            serial.writeString(" - ");
            printHex64(end_addr - 1);
            serial.writeString(" (");
            printHex32(length / (1024 * 1024));
            serial.writeString(" MB)\n");

            markRegionFree(base, length);
            total_usable += length;
        }
    }

    // Reserve special regions
    serial.writeString("[PMM] Reserving special regions...\n");

    // Reserve first 1MB (BIOS, IVT, etc)
    markRegionUsed(0, 0x100000);
    serial.writeString("  Reserved: 0x00000000 - 0x000FFFFF (BIOS/IVT)\n");

    // Reserve kernel and modules (approximation)
    markRegionUsed(0x0FDC0000, 0x00069000);
    serial.writeString("  Reserved: 0x0FDC0000 - 0x0FE28FFF (Kernel)\n");

    // Calculate total pages based on highest address
    highest_page = (highest_addr + PAGE_SIZE - 1) / PAGE_SIZE;
    if (highest_page > MAX_PAGES) {
        highest_page = MAX_PAGES;
    }
    total_pages = highest_page;

    // Count free and used pages
    var free_count: u64 = 0;
    var p: u64 = 0;
    while (p < total_pages) : (p += 1) {
        if (!testBit(p)) {
            free_count += 1;
        }
    }
    used_pages = total_pages - free_count;

    // Print summary
    serial.writeString("\n[PMM] Memory Summary:\n");
    serial.writeString("  Total memory: ");
    printHex64(highest_addr);
    serial.writeString(" (");
    printDecimal(highest_addr / (1024 * 1024));
    serial.writeString(" MB)\n");

    serial.writeString("  Total pages: ");
    printHex32(total_pages);
    serial.writeString(" (");
    printDecimal(total_pages);
    serial.writeString(" pages)\n");

    serial.writeString("  Free pages: ");
    printHex32(free_count);
    serial.writeString(" (");
    printDecimal((free_count * PAGE_SIZE) / (1024 * 1024));
    serial.writeString(" MB)\n");

    serial.writeString("  Used pages: ");
    printHex32(used_pages);
    serial.writeString(" (");
    printDecimal((used_pages * PAGE_SIZE) / (1024 * 1024));
    serial.writeString(" MB)\n");

    serial.writeString("  Bitmap size: ");
    printHex32(total_pages / 8);
    serial.writeString(" bytes\n");

    serial.writeString("[PMM] Physical Memory Manager initialized!\n");
}

/// Mark a memory region as free
fn markRegionFree(base: u64, length: u64) void {
    // Align to page boundaries
    const start_page = (base + PAGE_SIZE - 1) / PAGE_SIZE; // Round up
    const end_page = (base + length) / PAGE_SIZE; // Round down

    var page = start_page;
    while (page < end_page and page < MAX_PAGES) : (page += 1) {
        clearBit(page);
    }
}

/// Mark a memory region as used
fn markRegionUsed(base: u64, length: u64) void {
    const start_page = base / PAGE_SIZE;
    const end_page = (base + length + PAGE_SIZE - 1) / PAGE_SIZE;

    var page = start_page;
    while (page < end_page and page < MAX_PAGES) : (page += 1) {
        setBit(page);
    }
}

/// Allocate a single physical page
/// Returns physical address or null if no memory available
pub fn allocPage() ?u64 {
    // Search for a free page
    var page: u64 = 256; // Start after first 1MB (page 256)
    while (page < total_pages) : (page += 1) {
        if (!testBit(page)) {
            setBit(page);
            used_pages += 1;

            const phys_addr = page * PAGE_SIZE;

            // Zero the page
            zeroPage(phys_addr);

            return phys_addr;
        }
    }

    serial.writeString("[PMM] WARNING: Out of memory!\n");
    return null;
}

/// Allocate multiple contiguous pages
pub fn allocPages(count: u64) ?u64 {
    if (count == 0) return null;

    var page: u64 = 256; // Start after first 1MB
    while (page + count <= total_pages) : (page += 1) {
        // Check if all pages are free
        var all_free = true;
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            if (testBit(page + i)) {
                all_free = false;
                break;
            }
        }

        if (all_free) {
            // Mark all pages as used
            i = 0;
            while (i < count) : (i += 1) {
                setBit(page + i);
                used_pages += 1;
            }

            const phys_addr = page * PAGE_SIZE;

            // Zero all pages
            i = 0;
            while (i < count) : (i += 1) {
                zeroPage(phys_addr + i * PAGE_SIZE);
            }

            return phys_addr;
        }
    }

    serial.writeString("[PMM] WARNING: Cannot allocate ");
    printDecimal(count);
    serial.writeString(" contiguous pages!\n");
    return null;
}

/// Free a physical page
pub fn freePage(phys_addr: u64) void {
    if (phys_addr % PAGE_SIZE != 0) {
        serial.writeString("[PMM] ERROR: Unaligned free at ");
        printHex64(phys_addr);
        serial.writeString("\n");
        return;
    }

    const page = phys_addr / PAGE_SIZE;
    if (page >= total_pages) {
        serial.writeString("[PMM] ERROR: Address out of range: ");
        printHex64(phys_addr);
        serial.writeString("\n");
        return;
    }

    if (!testBit(page)) {
        serial.writeString("[PMM] WARNING: Double free at ");
        printHex64(phys_addr);
        serial.writeString("\n");
        return;
    }

    clearBit(page);
    if (used_pages > 0) {
        used_pages -= 1;
    }
}

/// Free multiple contiguous pages
pub fn freePages(phys_addr: u64, count: u64) void {
    if (phys_addr % PAGE_SIZE != 0) {
        serial.writeString("[PMM] ERROR: Unaligned free at ");
        printHex64(phys_addr);
        serial.writeString("\n");
        return;
    }

    const start_page = phys_addr / PAGE_SIZE;
    if (start_page + count > total_pages) {
        serial.writeString("[PMM] ERROR: Range out of bounds\n");
        return;
    }

    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const page = start_page + i;
        if (!testBit(page)) {
            serial.writeString("[PMM] WARNING: Double free in range\n");
        } else {
            clearBit(page);
            if (used_pages > 0) {
                used_pages -= 1;
            }
        }
    }
}

/// Zero a page using HHDM
fn zeroPage(phys_addr: u64) void {
    const virt_addr = hhdm_offset + phys_addr;
    var offset: u64 = 0;
    while (offset < PAGE_SIZE) : (offset += 8) {
        const ptr: *volatile u64 = @ptrFromInt(virt_addr + offset);
        ptr.* = 0;
    }
}

/// Get number of free pages
pub fn getFreePages() u64 {
    if (total_pages > used_pages) {
        return total_pages - used_pages;
    }
    return 0;
}

/// Get number of used pages
pub fn getUsedPages() u64 {
    return used_pages;
}

/// Get total pages
pub fn getTotalPages() u64 {
    return total_pages;
}

/// Get HHDM offset for virtual memory operations
pub fn getHhdmOffset() u64 {
    return hhdm_offset;
}

/// Get memory statistics
pub fn getStats() struct {
    total_memory: u64,
    free_memory: u64,
    used_memory: u64,
    total_pages: u64,
    free_pages: u64,
    used_pages: u64,
} {
    const free = getFreePages();
    return .{
        .total_memory = total_pages * PAGE_SIZE,
        .free_memory = free * PAGE_SIZE,
        .used_memory = used_pages * PAGE_SIZE,
        .total_pages = total_pages,
        .free_pages = free,
        .used_pages = used_pages,
    };
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    serial.writeString("0x");
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nibble: u8 = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printHex32(value: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 28;
    while (true) : (i -= 4) {
        const nibble: u8 = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

fn printHex16(value: u64) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[@truncate((value >> 12) & 0xF)]);
    serial.writeChar(hex[@truncate((value >> 8) & 0xF)]);
    serial.writeChar(hex[@truncate((value >> 4) & 0xF)]);
    serial.writeChar(hex[@truncate(value & 0xF)]);
}

// Simple decimal print without division that triggers SSE
fn printDecimal(value: u64) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }

    // For small numbers, use simple method
    if (value < 1000) {
        if (value >= 100) {
            const hundreds = value / 100;
            serial.writeChar(@truncate(hundreds + '0'));
            const remainder = value % 100;
            const tens = remainder / 10;
            serial.writeChar(@truncate(tens + '0'));
            const ones = remainder % 10;
            serial.writeChar(@truncate(ones + '0'));
        } else if (value >= 10) {
            const tens = value / 10;
            serial.writeChar(@truncate(tens + '0'));
            const ones = value % 10;
            serial.writeChar(@truncate(ones + '0'));
        } else {
            serial.writeChar(@truncate(value + '0'));
        }
    } else {
        // For larger numbers, just print hex
        printHex32(value);
    }
}

// ============================================================================
// Test Function
// ============================================================================

pub fn test_pmm() void {
    serial.writeString("\n========================================\n");
    serial.writeString("  PMM Tests\n");
    serial.writeString("========================================\n");

    // Get initial stats
    const initial_free = getFreePages();

    // Test 1: Single page allocation
    serial.writeString("\n[TEST 1] Single page allocation:\n");

    const page1 = allocPage();
    const page2 = allocPage();
    const page3 = allocPage();

    if (page1) |p1| {
        serial.writeString("  Page 1: ");
        printHex64(p1);
        serial.writeString(" [OK]\n"); // Ganti ✓ dengan [OK]
    }

    if (page2) |p2| {
        serial.writeString("  Page 2: ");
        printHex64(p2);
        serial.writeString(" [OK]\n");
    }

    if (page3) |p3| {
        serial.writeString("  Page 3: ");
        printHex64(p3);
        serial.writeString(" [OK]\n");
    }

    serial.writeString("  Free pages: ");
    printHex16(getFreePages());
    serial.writeString(" (was ");
    printHex16(initial_free);
    serial.writeString(")\n");

    // Test 2: Page free and reuse
    serial.writeString("\n[TEST 2] Page free and reuse:\n");
    if (page2) |p2| {
        serial.writeString("  Freeing page 2 (");
        printHex64(p2);
        serial.writeString(")...\n");
        freePage(p2);
    }

    serial.writeString("  Free pages after free: ");
    printHex16(getFreePages());
    serial.writeString("\n");

    serial.writeString("  Allocating new page...\n");
    const page4 = allocPage();
    if (page4) |p4| {
        serial.writeString("  Page 4: ");
        printHex64(p4);
        if (page2) |p2| {
            if (p4 == p2) {
                serial.writeString(" (Reused page 2) [OK]"); // Ganti ✓
            }
        }
        serial.writeString("\n");
    }

    // Test 3: Contiguous allocation
    serial.writeString("\n[TEST 3] Contiguous page allocation:\n");
    const cont_pages = allocPages(4);
    if (cont_pages) |cp| {
        serial.writeString("  4 contiguous pages: ");
        printHex64(cp);
        serial.writeString(" - ");
        printHex64(cp + 4 * PAGE_SIZE - 1);
        serial.writeString(" [OK]\n"); // Ganti ✓

        serial.writeString("  Freeing contiguous block...\n");
        freePages(cp, 4);
        serial.writeString("  Freed [OK]\n"); // Ganti ✓
    }

    // Final stats
    serial.writeString("\n[SUMMARY]\n");
    serial.writeString("  Final free pages: ");
    printHex16(getFreePages());
    serial.writeString("\n");
    serial.writeString("  Memory leaked: ");
    if (getFreePages() == initial_free - 3) { // We allocated 3 pages in test 1
        serial.writeString("None [PASS]\n"); // Ganti ✓
    } else {
        serial.writeString("Some pages not freed [FAIL]\n");
    }

    serial.writeString("\n========================================\n");
    serial.writeString("  PMM Tests Complete!\n");
    serial.writeString("========================================\n\n");
}

// check point 8 scheduller
