//! Zamrud OS - Task State Segment (TSS)
//! Required untuk x86_64 untuk menyimpan kernel stack pointer

const serial = @import("../../drivers/serial/serial.zig");
const gdt = @import("gdt.zig");

/// TSS Structure untuk x86_64
/// Total size: 104 bytes
pub const TSS = extern struct {
    reserved0: u32 = 0,

    /// Stack pointers untuk privilege levels
    rsp0: u64 = 0, // Kernel stack (Ring 0)
    rsp1: u64 = 0, // Ring 1 (tidak dipakai)
    rsp2: u64 = 0, // Ring 2 (tidak dipakai)

    reserved1: u64 = 0,

    /// Interrupt Stack Table (IST)
    /// Untuk handling interrupts dengan stack terpisah
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,

    reserved2: u64 = 0,
    reserved3: u16 = 0,

    /// I/O Map Base Address
    iopb: u16 = 0,
};

/// TSS instance global
pub var tss: TSS = .{};

/// Kernel stack untuk interrupt handling
var kernel_stack: [16384]u8 align(16) = undefined; // 16KB stack

/// Interrupt stack (untuk double fault, NMI, etc)
var interrupt_stack: [8192]u8 align(16) = undefined; // 8KB stack

/// Initialize TSS
pub fn init() void {
    serial.writeString("[TSS] Initializing Task State Segment...\n");

    // Set kernel stack pointer (top of stack)
    const kernel_stack_top = @intFromPtr(&kernel_stack) + kernel_stack.len;
    tss.rsp0 = kernel_stack_top;

    serial.writeString("[TSS] Kernel stack (RSP0): 0x");
    printHex64(kernel_stack_top);
    serial.writeString("\n");

    // Set interrupt stack (IST1) untuk double fault handler
    const ist_stack_top = @intFromPtr(&interrupt_stack) + interrupt_stack.len;
    tss.ist1 = ist_stack_top;

    serial.writeString("[TSS] Interrupt stack (IST1): 0x");
    printHex64(ist_stack_top);
    serial.writeString("\n");

    // Set IOPB offset (no I/O permission bitmap)
    tss.iopb = @sizeOf(TSS);

    serial.writeString("[TSS] TSS initialized!\n");
}

/// Load TSS ke CPU
pub fn load() void {
    serial.writeString("[TSS] Loading TSS...\n");

    // Load TSS selector (index 5 di GDT, offset 0x28)
    const tss_selector: u16 = 0x28;

    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (tss_selector),
    );

    serial.writeString("[TSS] TSS loaded with selector 0x");
    printHex16(tss_selector);
    serial.writeString("\n");
}

/// Get TSS address
pub fn getAddress() u64 {
    return @intFromPtr(&tss);
}

/// Get TSS size
pub fn getSize() u32 {
    return @sizeOf(TSS);
}

/// Set kernel stack untuk current process
pub fn setKernelStack(stack_top: u64) void {
    tss.rsp0 = stack_top;
}

// ============================================================================
// Helper Functions
// ============================================================================

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    var i: u5 = 12;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

// check point 8 scheduller
