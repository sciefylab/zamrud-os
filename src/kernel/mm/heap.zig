//! Zamrud OS - Kernel Heap Allocator
//! Simple free-list based allocator with security hardening

const serial = @import("../drivers/serial/serial.zig");
const pmm = @import("pmm.zig");
const vmm = @import("vmm.zig");

// Heap configuration
const HEAP_START: u64 = 0xFFFF_C000_0000_0000;
const HEAP_INITIAL_SIZE: u64 = 16 * pmm.PAGE_SIZE; // 64 KB
const HEAP_MAX_SIZE: u64 = 256 * pmm.PAGE_SIZE; // 1 MB
const MAX_PAGES_PER_EXPAND: u64 = 256;

const BLOCK_MAGIC: u32 = 0xDEADBEEF;
const BLOCK_CANARY: u32 = 0xCAFEBABE;
const MIN_BLOCK_SIZE: u64 = 32;
const ALIGNMENT: u64 = 16;

// Block flags
const BLOCK_FLAG_USED: u32 = 0;
const BLOCK_FLAG_FREE: u32 = 1;

// Security features
const ENABLE_ZERO_ON_FREE: bool = true;
const ENABLE_CANARY: bool = true;
const ENABLE_INTEGRITY_CHECK: bool = true;
const ENABLE_DEBUG: bool = false; // Disable debug for normal operation

// Block header - use packed struct with manual alignment
// Total size: 40 bytes, aligned to 8 bytes
const BlockHeader = struct {
    magic: u32, // 0-3
    flags: u32, // 4-7
    size: u64, // 8-15
    next_addr: u64, // 16-23 (store as u64 to avoid alignment issues)
    prev_addr: u64, // 24-31 (store as u64 to avoid alignment issues)

    pub fn getNext(self: *BlockHeader) ?*BlockHeader {
        if (self.next_addr == 0) return null;
        return @ptrFromInt(self.next_addr);
    }

    pub fn setNext(self: *BlockHeader, next: ?*BlockHeader) void {
        self.next_addr = if (next) |n| @intFromPtr(n) else 0;
    }

    pub fn getPrev(self: *BlockHeader) ?*BlockHeader {
        if (self.prev_addr == 0) return null;
        return @ptrFromInt(self.prev_addr);
    }

    pub fn setPrev(self: *BlockHeader, prev: ?*BlockHeader) void {
        self.prev_addr = if (prev) |p| @intFromPtr(p) else 0;
    }
};

const HEADER_SIZE: u64 = @sizeOf(BlockHeader);
const CANARY_SIZE: u64 = if (ENABLE_CANARY) @sizeOf(u32) else 0;

// Heap state
var heap_start: u64 = 0;
var heap_end: u64 = 0;
var heap_size: u64 = 0;
var free_list_addr: u64 = 0; // Store as u64 to avoid alignment issues
var total_allocated: u64 = 0;
var total_freed: u64 = 0;
var allocation_count: u64 = 0;
var initialized: bool = false;

// Helper to get/set free list
fn getFreeList() ?*BlockHeader {
    if (free_list_addr == 0) return null;
    return @ptrFromInt(free_list_addr);
}

fn setFreeList(block: ?*BlockHeader) void {
    free_list_addr = if (block) |b| @intFromPtr(b) else 0;
}

// ============================================================================
// Heap Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[HEAP] Initializing kernel heap...\n");

    heap_start = HEAP_START;
    heap_end = HEAP_START;
    heap_size = 0;
    free_list_addr = 0;
    total_allocated = 0;
    total_freed = 0;
    allocation_count = 0;

    serial.writeString("[HEAP] Allocating initial heap (");
    printHex32(HEAP_INITIAL_SIZE / 1024);
    serial.writeString(" KB)...\n");

    if (!expandHeap(HEAP_INITIAL_SIZE)) {
        serial.writeString("[HEAP] ERROR: Failed to allocate initial heap!\n");
        return;
    }

    initialized = true;

    serial.writeString("[HEAP] Heap start: ");
    printHex64(heap_start);
    serial.writeString("\n");

    serial.writeString("[HEAP] Heap end: ");
    printHex64(heap_end);
    serial.writeString("\n");

    serial.writeString("[HEAP] Heap size: ");
    printHex32(heap_size);
    serial.writeString(" bytes\n");

    serial.writeString("[HEAP] Header size: ");
    printHex32(HEADER_SIZE);
    serial.writeString(" bytes\n");

    if (ENABLE_CANARY) {
        serial.writeString("[HEAP] Canary protection: ENABLED\n");
    }
    if (ENABLE_ZERO_ON_FREE) {
        serial.writeString("[HEAP] Zero on free: ENABLED\n");
    }

    serial.writeString("[HEAP] Kernel heap initialized!\n");
}

/// Expand heap by allocating more pages
fn expandHeap(min_size: u64) bool {
    if (ENABLE_DEBUG) {
        serial.writeString("[HEAP] expandHeap called, min_size: ");
        printHex64(min_size);
        serial.writeString("\n");
    }

    var pages_needed = (min_size + pmm.PAGE_SIZE - 1) / pmm.PAGE_SIZE;
    if (pages_needed == 0) pages_needed = 1;

    if (ENABLE_DEBUG) {
        serial.writeString("[HEAP] Pages needed: ");
        printHex32(pages_needed);
        serial.writeString("\n");
    }

    if (pages_needed > MAX_PAGES_PER_EXPAND) {
        serial.writeString("[HEAP] ERROR: Allocation too large!\n");
        return false;
    }

    if (heap_size + pages_needed * pmm.PAGE_SIZE > HEAP_MAX_SIZE) {
        serial.writeString("[HEAP] ERROR: Heap max size exceeded!\n");
        return false;
    }

    const expansion_start = heap_end;

    if (ENABLE_DEBUG) {
        serial.writeString("[HEAP] Expansion start: ");
        printHex64(expansion_start);
        serial.writeString("\n");
    }

    // Allocate and map pages
    var i: u64 = 0;
    while (i < pages_needed) : (i += 1) {
        const virt_addr = expansion_start + i * pmm.PAGE_SIZE;

        if (ENABLE_DEBUG) {
            serial.writeString("[HEAP] Allocating page ");
            printHex32(i);
            serial.writeString(" at virt: ");
            printHex64(virt_addr);
            serial.writeString("\n");
        }

        const phys_page = pmm.allocPage() orelse {
            serial.writeString("[HEAP] ERROR: Out of physical memory!\n");
            rollbackPages(expansion_start, i);
            return false;
        };

        if (ENABLE_DEBUG) {
            serial.writeString("[HEAP] Got phys page: ");
            printHex64(phys_page);
            serial.writeString("\n");
        }

        if (!vmm.mapPage(virt_addr, phys_page, vmm.KERNEL_FLAGS)) {
            serial.writeString("[HEAP] ERROR: Failed to map heap page!\n");
            pmm.freePage(phys_page);
            rollbackPages(expansion_start, i);
            return false;
        }

        if (ENABLE_DEBUG) {
            serial.writeString("[HEAP] Page mapped successfully\n");
        }
    }

    // Calculate new block size
    const new_block_size = pages_needed * pmm.PAGE_SIZE - HEADER_SIZE - CANARY_SIZE;

    if (ENABLE_DEBUG) {
        serial.writeString("[HEAP] Creating free block at: ");
        printHex64(expansion_start);
        serial.writeString(" size: ");
        printHex64(new_block_size);
        serial.writeString("\n");
    }

    // Initialize block header using direct memory writes
    const block_ptr: [*]u8 = @ptrFromInt(expansion_start);

    // Write magic (bytes 0-3)
    const magic_ptr: *align(1) u32 = @ptrCast(block_ptr);
    magic_ptr.* = BLOCK_MAGIC;

    // Write flags (bytes 4-7)
    const flags_ptr: *align(1) u32 = @ptrCast(block_ptr + 4);
    flags_ptr.* = BLOCK_FLAG_FREE;

    // Write size (bytes 8-15)
    const size_ptr: *align(1) u64 = @ptrCast(block_ptr + 8);
    size_ptr.* = new_block_size;

    // Write next_addr (bytes 16-23)
    const next_ptr: *align(1) u64 = @ptrCast(block_ptr + 16);
    next_ptr.* = free_list_addr;

    // Write prev_addr (bytes 24-31)
    const prev_ptr: *align(1) u64 = @ptrCast(block_ptr + 24);
    prev_ptr.* = 0;

    // Update old free list head's prev pointer
    if (getFreeList()) |fl| {
        const fl_ptr: [*]u8 = @ptrCast(fl);
        const fl_prev_ptr: *align(1) u64 = @ptrCast(fl_ptr + 24);
        fl_prev_ptr.* = expansion_start;
    }

    // Set new free list head
    free_list_addr = expansion_start;

    // Update heap state
    heap_end = expansion_start + pages_needed * pmm.PAGE_SIZE;
    heap_size += pages_needed * pmm.PAGE_SIZE;

    if (ENABLE_DEBUG) {
        serial.writeString("[HEAP] Expansion complete. New heap_end: ");
        printHex64(heap_end);
        serial.writeString("\n");
    }

    return true;
}

/// Rollback mapped pages on failure
fn rollbackPages(start: u64, count: u64) void {
    if (count == 0) return;

    serial.writeString("[HEAP] Rolling back ");
    printHex32(count);
    serial.writeString(" pages...\n");

    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const virt = start + i * pmm.PAGE_SIZE;
        const phys = vmm.getPhysicalAddress(virt);
        if (phys != 0) {
            _ = vmm.unmapPage(virt);
            pmm.freePage(phys);
        }
    }
}

// ============================================================================
// Helper functions for unaligned memory access
// ============================================================================

fn readU32(addr: u64) u32 {
    const ptr: *align(1) u32 = @ptrFromInt(addr);
    return ptr.*;
}

fn writeU32(addr: u64, value: u32) void {
    const ptr: *align(1) u32 = @ptrFromInt(addr);
    ptr.* = value;
}

fn readU64(addr: u64) u64 {
    const ptr: *align(1) u64 = @ptrFromInt(addr);
    return ptr.*;
}

fn writeU64(addr: u64, value: u64) void {
    const ptr: *align(1) u64 = @ptrFromInt(addr);
    ptr.* = value;
}

// Block field offsets
const OFF_MAGIC: u64 = 0;
const OFF_FLAGS: u64 = 4;
const OFF_SIZE: u64 = 8;
const OFF_NEXT: u64 = 16;
const OFF_PREV: u64 = 24;

fn blockGetMagic(block_addr: u64) u32 {
    return readU32(block_addr + OFF_MAGIC);
}

fn blockSetMagic(block_addr: u64, value: u32) void {
    writeU32(block_addr + OFF_MAGIC, value);
}

fn blockGetFlags(block_addr: u64) u32 {
    return readU32(block_addr + OFF_FLAGS);
}

fn blockSetFlags(block_addr: u64, value: u32) void {
    writeU32(block_addr + OFF_FLAGS, value);
}

fn blockGetSize(block_addr: u64) u64 {
    return readU64(block_addr + OFF_SIZE);
}

fn blockSetSize(block_addr: u64, value: u64) void {
    writeU64(block_addr + OFF_SIZE, value);
}

fn blockGetNext(block_addr: u64) u64 {
    return readU64(block_addr + OFF_NEXT);
}

fn blockSetNext(block_addr: u64, value: u64) void {
    writeU64(block_addr + OFF_NEXT, value);
}

fn blockGetPrev(block_addr: u64) u64 {
    return readU64(block_addr + OFF_PREV);
}

fn blockSetPrev(block_addr: u64, value: u64) void {
    writeU64(block_addr + OFF_PREV, value);
}

// ============================================================================
// Memory Allocation
// ============================================================================

pub fn kmalloc(size: u64) ?[*]u8 {
    if (!initialized) {
        serial.writeString("[HEAP] ERROR: Heap not initialized!\n");
        return null;
    }

    if (size == 0) return null;

    if (size > HEAP_MAX_SIZE - ALIGNMENT - HEADER_SIZE - CANARY_SIZE) {
        serial.writeString("[HEAP] ERROR: Allocation size too large!\n");
        return null;
    }

    // Align size
    var aligned_size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    if (aligned_size < MIN_BLOCK_SIZE) {
        aligned_size = MIN_BLOCK_SIZE;
    }

    const total_size = aligned_size + CANARY_SIZE;

    // Find free block
    var current_addr = free_list_addr;
    while (current_addr != 0) {
        const flags = blockGetFlags(current_addr);
        const block_size = blockGetSize(current_addr);

        if (flags == BLOCK_FLAG_FREE and block_size >= total_size) {
            return allocateFromBlock(current_addr, total_size);
        }
        current_addr = blockGetNext(current_addr);
    }

    // Expand heap and retry
    if (expandHeap(total_size + HEADER_SIZE)) {
        current_addr = free_list_addr;
        while (current_addr != 0) {
            const flags = blockGetFlags(current_addr);
            const block_size = blockGetSize(current_addr);

            if (flags == BLOCK_FLAG_FREE and block_size >= total_size) {
                return allocateFromBlock(current_addr, total_size);
            }
            current_addr = blockGetNext(current_addr);
        }
    }

    serial.writeString("[HEAP] ERROR: Out of heap memory!\n");
    return null;
}

fn allocateFromBlock(block_addr: u64, size: u64) ?[*]u8 {
    const magic = blockGetMagic(block_addr);
    if (magic != BLOCK_MAGIC) {
        serial.writeString("[HEAP] ERROR: Invalid block magic!\n");
        return null;
    }

    const flags = blockGetFlags(block_addr);
    if (flags != BLOCK_FLAG_FREE) {
        serial.writeString("[HEAP] ERROR: Block is not free!\n");
        return null;
    }

    const block_size = blockGetSize(block_addr);
    const remaining = block_size - size;

    if (remaining >= HEADER_SIZE + MIN_BLOCK_SIZE + CANARY_SIZE) {
        // Split block
        const new_block_addr = block_addr + HEADER_SIZE + size;

        blockSetMagic(new_block_addr, BLOCK_MAGIC);
        blockSetFlags(new_block_addr, BLOCK_FLAG_FREE);
        blockSetSize(new_block_addr, remaining - HEADER_SIZE);
        blockSetNext(new_block_addr, blockGetNext(block_addr));
        blockSetPrev(new_block_addr, blockGetPrev(block_addr));

        // Update neighbors
        const next_addr = blockGetNext(new_block_addr);
        if (next_addr != 0) {
            blockSetPrev(next_addr, new_block_addr);
        }

        const prev_addr = blockGetPrev(new_block_addr);
        if (prev_addr != 0) {
            blockSetNext(prev_addr, new_block_addr);
        } else {
            free_list_addr = new_block_addr;
        }

        blockSetSize(block_addr, size);
    } else {
        // Use whole block - remove from free list
        const next_addr = blockGetNext(block_addr);
        const prev_addr = blockGetPrev(block_addr);

        if (next_addr != 0) {
            blockSetPrev(next_addr, prev_addr);
        }
        if (prev_addr != 0) {
            blockSetNext(prev_addr, next_addr);
        } else {
            free_list_addr = next_addr;
        }
    }

    blockSetFlags(block_addr, BLOCK_FLAG_USED);
    blockSetNext(block_addr, 0);
    blockSetPrev(block_addr, 0);

    // Write canary
    if (ENABLE_CANARY) {
        const canary_addr = block_addr + HEADER_SIZE + blockGetSize(block_addr) - CANARY_SIZE;
        writeU32(canary_addr, BLOCK_CANARY);
    }

    total_allocated += blockGetSize(block_addr);
    allocation_count += 1;

    const data_addr = block_addr + HEADER_SIZE;
    return @ptrFromInt(data_addr);
}

pub fn kfree(ptr: ?[*]u8) void {
    if (ptr == null) return;
    if (!initialized) return;

    const data_addr = @intFromPtr(ptr.?);

    if (data_addr < heap_start + HEADER_SIZE or data_addr >= heap_end) {
        serial.writeString("[HEAP] ERROR: Invalid free address!\n");
        return;
    }

    const block_addr = data_addr - HEADER_SIZE;

    const magic = blockGetMagic(block_addr);
    if (magic != BLOCK_MAGIC) {
        serial.writeString("[HEAP] ERROR: Corrupted block header!\n");
        return;
    }

    const flags = blockGetFlags(block_addr);
    if (flags == BLOCK_FLAG_FREE) {
        serial.writeString("[HEAP] WARNING: Double free detected!\n");
        return;
    }

    const block_size = blockGetSize(block_addr);

    // Check canary
    if (ENABLE_CANARY) {
        const canary_addr = block_addr + HEADER_SIZE + block_size - CANARY_SIZE;
        if (canary_addr + CANARY_SIZE <= heap_end) {
            const canary = readU32(canary_addr);
            if (canary != BLOCK_CANARY) {
                serial.writeString("[HEAP] ERROR: Buffer overflow detected!\n");
                return;
            }
        }
    }

    // Zero memory
    if (ENABLE_ZERO_ON_FREE) {
        const zero_size = block_size - CANARY_SIZE;
        var i: u64 = 0;
        while (i < zero_size) : (i += 1) {
            const byte_ptr: *u8 = @ptrFromInt(data_addr + i);
            byte_ptr.* = 0;
        }
    }

    blockSetFlags(block_addr, BLOCK_FLAG_FREE);

    total_freed += block_size;
    if (allocation_count > 0) {
        allocation_count -= 1;
    }

    // Add to free list
    blockSetNext(block_addr, free_list_addr);
    blockSetPrev(block_addr, 0);

    if (free_list_addr != 0) {
        blockSetPrev(free_list_addr, block_addr);
    }
    free_list_addr = block_addr;

    coalesceBlocks();
}

fn coalesceBlocks() void {
    var current_addr = free_list_addr;

    while (current_addr != 0) {
        const flags = blockGetFlags(current_addr);
        if (flags != BLOCK_FLAG_FREE) {
            current_addr = blockGetNext(current_addr);
            continue;
        }

        if (current_addr < heap_start or current_addr >= heap_end) {
            current_addr = blockGetNext(current_addr);
            continue;
        }

        const block_size = blockGetSize(current_addr);
        const next_block_addr = current_addr + HEADER_SIZE + block_size;

        if (next_block_addr + HEADER_SIZE > heap_end) {
            current_addr = blockGetNext(current_addr);
            continue;
        }

        const next_magic = blockGetMagic(next_block_addr);
        const next_flags = blockGetFlags(next_block_addr);

        if (next_magic == BLOCK_MAGIC and next_flags == BLOCK_FLAG_FREE) {
            // Merge blocks
            const next_size = blockGetSize(next_block_addr);
            blockSetSize(current_addr, block_size + HEADER_SIZE + next_size);

            // Remove next_block from free list
            const next_next = blockGetNext(next_block_addr);
            const next_prev = blockGetPrev(next_block_addr);

            if (next_prev != 0) {
                blockSetNext(next_prev, next_next);
            }
            if (next_next != 0) {
                blockSetPrev(next_next, next_prev);
            }
            if (free_list_addr == next_block_addr) {
                free_list_addr = next_next;
            }

            blockSetMagic(next_block_addr, 0);
            continue;
        }

        current_addr = blockGetNext(current_addr);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

pub fn checkIntegrity() bool {
    if (!ENABLE_INTEGRITY_CHECK) return true;
    if (!initialized) return false;

    var current_addr = free_list_addr;
    var count: u64 = 0;
    var issues: u64 = 0;

    while (current_addr != 0) {
        count += 1;
        if (count > 10000) {
            serial.writeString("[HEAP] ERROR: Circular list!\n");
            return false;
        }

        if (blockGetMagic(current_addr) != BLOCK_MAGIC) issues += 1;
        if (current_addr < heap_start or current_addr >= heap_end) issues += 1;
        if (blockGetFlags(current_addr) != BLOCK_FLAG_FREE) issues += 1;

        const size = blockGetSize(current_addr);
        if (size == 0 or size > heap_size) issues += 1;

        current_addr = blockGetNext(current_addr);
    }

    return issues == 0;
}

pub fn getStats() struct {
    heap_size: u64,
    total_allocated: u64,
    total_freed: u64,
    allocation_count: u64,
    free_blocks: u64,
    largest_free: u64,
} {
    var free_count: u64 = 0;
    var largest: u64 = 0;

    var current_addr = free_list_addr;
    while (current_addr != 0) {
        if (blockGetFlags(current_addr) == BLOCK_FLAG_FREE) {
            free_count += 1;
            const size = blockGetSize(current_addr);
            if (size > largest) largest = size;
        }
        current_addr = blockGetNext(current_addr);
    }

    return .{
        .heap_size = heap_size,
        .total_allocated = total_allocated,
        .total_freed = total_freed,
        .allocation_count = allocation_count,
        .free_blocks = free_count,
        .largest_free = largest,
    };
}

pub fn isInitialized() bool {
    return initialized;
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

// ============================================================================
// Tests
// ============================================================================

pub fn test_heap() void {
    serial.writeString("\n========================================\n");
    serial.writeString("  Heap Allocator Tests\n");
    serial.writeString("========================================\n");

    if (!initialized) {
        serial.writeString("[TEST] Heap not initialized!\n");
        return;
    }

    // Test 1: Simple allocation
    serial.writeString("\n[TEST 1] Simple allocation:\n");
    const ptr1 = kmalloc(64);
    if (ptr1) |p| {
        serial.writeString("  64 bytes at: ");
        printHex64(@intFromPtr(p));
        serial.writeString(" [OK]\n");
        p[0] = 0xAB;
        p[63] = 0xCD;
        if (p[0] == 0xAB and p[63] == 0xCD) {
            serial.writeString("  Write/Read: [OK]\n");
        }
    } else {
        serial.writeString("  FAILED\n");
    }

    // Test 2: Multiple allocations
    serial.writeString("\n[TEST 2] Multiple allocations:\n");
    const ptr2 = kmalloc(128);
    const ptr3 = kmalloc(256);
    const ptr4 = kmalloc(512);

    if (ptr2) |p| {
        serial.writeString("  128 bytes at: ");
        printHex64(@intFromPtr(p));
        serial.writeString(" [OK]\n");
    }
    if (ptr3) |p| {
        serial.writeString("  256 bytes at: ");
        printHex64(@intFromPtr(p));
        serial.writeString(" [OK]\n");
    }
    if (ptr4) |p| {
        serial.writeString("  512 bytes at: ");
        printHex64(@intFromPtr(p));
        serial.writeString(" [OK]\n");
    }

    // Test 3: Free and reuse
    serial.writeString("\n[TEST 3] Free and reuse:\n");
    kfree(ptr2);
    const ptr5 = kmalloc(100);
    if (ptr5) |p| {
        serial.writeString("  100 bytes at: ");
        printHex64(@intFromPtr(p));
        serial.writeString(" [OK]\n");
    }

    // Test 4: Free all
    serial.writeString("\n[TEST 4] Free all:\n");
    kfree(ptr1);
    kfree(ptr3);
    kfree(ptr4);
    kfree(ptr5);
    serial.writeString("  All freed [OK]\n");

    // Stats
    serial.writeString("\n[STATS]:\n");
    const stats = getStats();
    serial.writeString("  Heap size: ");
    printHex32(stats.heap_size);
    serial.writeString("\n  Allocated: ");
    printHex32(stats.total_allocated);
    serial.writeString("\n  Freed: ");
    printHex32(stats.total_freed);
    serial.writeString("\n  Free blocks: ");
    printHex32(stats.free_blocks);
    serial.writeString("\n");

    serial.writeString("\n========================================\n");
    serial.writeString("  Tests Complete!\n");
    serial.writeString("========================================\n\n");
}

// check point 8 scheduller
