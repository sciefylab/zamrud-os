//! Zamrud OS - User Memory Manager
//! Allocates memory in user-accessible address space

const serial = @import("../drivers/serial/serial.zig");
const pmm = @import("pmm.zig");
const vmm = @import("vmm.zig");

// =============================================================================
// User Space Address Layout
// =============================================================================

// Gunakan alamat tinggi yang kemungkinan besar tidak di-map oleh bootloader
// 0x100000000 = 4GB, well beyond typical bootloader identity mapping

/// User code starts at 4GB
pub const USER_CODE_BASE: u64 = 0x0000000100000000; // 4GB

/// User heap starts at 4GB + 256MB
pub const USER_HEAP_BASE: u64 = 0x0000000110000000; // 4GB + 256MB

/// User stack top (grows down from 8GB)
pub const USER_STACK_TOP: u64 = 0x0000000200000000; // 8GB

/// Maximum user address
pub const USER_MAX_ADDR: u64 = 0x00007FFFFFFFFFFF;

// =============================================================================
// State
// =============================================================================

var user_code_next: u64 = USER_CODE_BASE;
var user_heap_next: u64 = USER_HEAP_BASE;
var user_stack_next: u64 = USER_STACK_TOP;

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[USER_MEM] Initializing user memory manager...\n");

    user_code_next = USER_CODE_BASE;
    user_heap_next = USER_HEAP_BASE;
    user_stack_next = USER_STACK_TOP;

    initialized = true;

    serial.writeString("[USER_MEM] User code base:  0x");
    printHex64(USER_CODE_BASE);
    serial.writeString("\n");

    serial.writeString("[USER_MEM] User stack top:  0x");
    printHex64(USER_STACK_TOP);
    serial.writeString("\n");

    serial.writeString("[USER_MEM] User memory manager ready!\n");
}

// =============================================================================
// User Memory Allocation
// =============================================================================

pub fn allocUserCode(size: u64) ?u64 {
    const page_size = vmm.PAGE_SIZE;
    const pages = (size + page_size - 1) / page_size;
    const virt_start = user_code_next;

    serial.writeString("[USER_MEM] Allocating ");
    printSmallNum(pages);
    serial.writeString(" pages at 0x");
    printHex64(virt_start);
    serial.writeString("\n");

    // First check if this address range is already mapped
    serial.writeString("[USER_MEM] Checking for existing mappings...\n");
    if (vmm.isMapped(virt_start) == 1) {
        serial.writeString("[USER_MEM] WARNING: Address already mapped! Checking type...\n");
        vmm.debugPageWalk(virt_start);
        // We need to find a different address or handle this
    }

    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const phys = pmm.allocPage() orelse {
            serial.writeString("[USER_MEM] ERROR: PMM allocation failed!\n");
            unmapUserPages(virt_start, i);
            return null;
        };

        const virt = virt_start + i * page_size;

        serial.writeString("[USER_MEM] Mapping 0x");
        printHex64(virt);
        serial.writeString(" -> 0x");
        printHex64(phys);
        serial.writeString("\n");

        if (!vmm.mapPage(virt, phys, vmm.USER_FLAGS)) {
            serial.writeString("[USER_MEM] ERROR: VMM mapping failed!\n");
            pmm.freePage(phys);
            unmapUserPages(virt_start, i);
            return null;
        }

        // Zero via HHDM (kernel accessible)
        zeroPageViaHhdm(phys);
    }

    // Verify mapping
    serial.writeString("[USER_MEM] Verifying mapping:\n");
    vmm.debugPageWalk(virt_start);

    user_code_next += pages * page_size;

    serial.writeString("[USER_MEM] User code allocated OK\n");
    return virt_start;
}

pub fn allocUserStack(size: u64) ?u64 {
    const page_size = vmm.PAGE_SIZE;
    const pages = (size + page_size - 1) / page_size;
    const stack_bottom = user_stack_next - (pages * page_size);

    serial.writeString("[USER_MEM] Allocating user stack (");
    printSmallNum(pages);
    serial.writeString(" pages) at 0x");
    printHex64(stack_bottom);
    serial.writeString("\n");

    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        const phys = pmm.allocPage() orelse {
            serial.writeString("[USER_MEM] ERROR: PMM allocation failed for stack!\n");
            unmapUserPages(stack_bottom, i);
            return null;
        };

        const virt = stack_bottom + i * page_size;

        if (!vmm.mapPage(virt, phys, vmm.USER_FLAGS)) {
            serial.writeString("[USER_MEM] ERROR: VMM mapping failed for stack!\n");
            pmm.freePage(phys);
            unmapUserPages(stack_bottom, i);
            return null;
        }

        // Zero via HHDM
        zeroPageViaHhdm(phys);
    }

    const stack_top = user_stack_next;
    user_stack_next = stack_bottom;

    serial.writeString("[USER_MEM] User stack top = 0x");
    printHex64(stack_top);
    serial.writeString("\n");

    return stack_top;
}

fn unmapUserPages(virt_start: u64, count: u64) void {
    const page_size = vmm.PAGE_SIZE;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const virt = virt_start + i * page_size;
        const phys = vmm.getPhysicalAddress(virt);
        if (phys != 0xFFFFFFFFFFFFFFFF) {
            _ = vmm.unmapPage(virt);
            pmm.freePage(phys);
        }
    }
}

/// Zero a page via HHDM (kernel accessible), not user space address
fn zeroPageViaHhdm(phys: u64) void {
    const hhdm = pmm.getHhdmOffset();
    const virt = hhdm + phys;
    var i: u64 = 0;
    while (i < vmm.PAGE_SIZE) : (i += 8) {
        const ptr: *volatile u64 = @ptrFromInt(virt + i);
        ptr.* = 0;
    }
}

pub fn copyToUser(user_dest: u64, kernel_src: [*]const u8, len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const dest: *volatile u8 = @ptrFromInt(user_dest + i);
        dest.* = kernel_src[i];
    }
}

pub fn isUserAddress(addr: u64) bool {
    return addr <= USER_MAX_ADDR;
}

// =============================================================================
// Debug Helpers
// =============================================================================

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var shift: u6 = 60;
    while (true) {
        const nibble: u4 = @truncate((val >> shift) & 0xF);
        serial.writeChar(hex[nibble]);
        if (shift == 0) break;
        shift -= 4;
    }
}

fn printSmallNum(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    if (val < 10) {
        serial.writeChar(@as(u8, @intCast(val)) + '0');
    } else if (val < 100) {
        serial.writeChar(@as(u8, @intCast(val / 10)) + '0');
        serial.writeChar(@as(u8, @intCast(val % 10)) + '0');
    } else {
        serial.writeString("many");
    }
}
