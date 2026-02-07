//! Zamrud OS - Global Descriptor Table (GDT)
//! Fixed layout untuk SYSCALL/SYSRET compatibility

const serial = @import("../../drivers/serial/serial.zig");

// ============================================================================
// Segment Descriptor (8 bytes)
// ============================================================================

const SegmentDescriptor = packed struct(u64) {
    limit_lo: u16 = 0,
    base_address_lo: u16 = 0,
    base_address_hi: u8 = 0,
    access: Access,
    limit_hi: u4 = 0,
    reserved_1: u1 = 0,
    long_mode: bool = true,
    reserved_2: u1 = 0,
    use_chunks: bool = false,
    base_address_ext: u8 = 0,

    const Access = packed struct(u8) {
        accessed: bool = true,
        read_write: bool = true,
        grow_down_or_conforming: bool = false,
        is_code: bool,
        not_system: bool = true,
        ring: u2,
        present: bool = true,
    };
};

// ============================================================================
// TSS Descriptor (16 bytes - special untuk 64-bit mode)
// ============================================================================

const TSSDescriptor = packed struct(u128) {
    limit_lo: u16,
    base_lo: u16,
    base_mid: u8,
    access: TSSAccess,
    limit_hi_flags: u8,
    base_hi: u8,
    base_upper: u32,
    reserved: u32 = 0,

    const TSSAccess = packed struct(u8) {
        segment_type: u4 = 0x9, // 64-bit TSS (Available)
        zero: u1 = 0,
        dpl: u2 = 0,
        present: bool = true,
    };
};

// ============================================================================
// TSS Structure (104 bytes)
// ============================================================================

pub const TSS = extern struct {
    reserved0: u32 = 0,
    rsp0: u64 = 0,
    rsp1: u64 = 0,
    rsp2: u64 = 0,
    reserved1: u64 = 0,
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    reserved2: u64 = 0,
    reserved3: u16 = 0,
    iopb: u16 = 104,
};

// ============================================================================
// Segment Definitions
// ============================================================================

const null_segment = SegmentDescriptor{
    .access = .{
        .accessed = false,
        .read_write = false,
        .grow_down_or_conforming = false,
        .is_code = false,
        .not_system = false,
        .ring = 0,
        .present = false,
    },
};

const kernel_code = SegmentDescriptor{
    .access = .{ .is_code = true, .ring = 0 },
};

const kernel_data = SegmentDescriptor{
    .access = .{ .is_code = false, .ring = 0 },
};

// PENTING: User Data SEBELUM User Code untuk SYSRET!
const user_data = SegmentDescriptor{
    .access = .{ .is_code = false, .ring = 3 },
};

const user_code = SegmentDescriptor{
    .access = .{ .is_code = true, .ring = 3 },
};

// ============================================================================
// GDT Table - FIXED LAYOUT untuk SYSCALL/SYSRET
// ============================================================================

// GDT Layout (FIXED untuk SYSRET compatibility):
// 0x00: Null
// 0x08: Kernel Code (CS = 0x08)
// 0x10: Kernel Data (DS = 0x10)
// 0x18: User Data   (DS = 0x1B dengan RPL=3)  <- SYSRET SS = base + 8
// 0x20: User Code   (CS = 0x23 dengan RPL=3)  <- SYSRET CS = base + 16
// 0x28: TSS Low
// 0x30: TSS High
//
// STAR MSR configuration:
//   bits[47:32] = 0x08 (kernel CS base)
//   bits[63:48] = 0x10 (user base, SYSRET adds +8 for SS, +16 for CS)

const GDTTable = extern struct {
    null_desc: SegmentDescriptor,
    kernel_code: SegmentDescriptor,
    kernel_data: SegmentDescriptor,
    user_data: SegmentDescriptor, // 0x18 - SEBELUM user_code!
    user_code: SegmentDescriptor, // 0x20 - SESUDAH user_data!
    tss_low: u64,
    tss_high: u64,
};

var gdt_table: GDTTable = .{
    .null_desc = null_segment,
    .kernel_code = kernel_code,
    .kernel_data = kernel_data,
    .user_data = user_data, // 0x18
    .user_code = user_code, // 0x20
    .tss_low = 0,
    .tss_high = 0,
};

// ============================================================================
// Selectors - FIXED VALUES
// ============================================================================

pub const kernel_cs: u16 = 0x08;
pub const kernel_ds: u16 = 0x10;
pub const user_ds: u16 = 0x18 | 3; // 0x1B - Data SEBELUM Code
pub const user_cs: u16 = 0x20 | 3; // 0x23 - Code SESUDAH Data
pub const tss_selector: u16 = 0x28;

// Untuk STAR MSR
pub const STAR_KERNEL_BASE: u64 = 0x08;
pub const STAR_USER_BASE: u64 = 0x10; // SYSRET: SS=0x18|3, CS=0x20|3

// ============================================================================
// TSS Instance & Stacks
// ============================================================================

pub var tss: TSS = .{};

var kernel_stack: [16384]u8 align(16) = undefined;
var interrupt_stack: [8192]u8 align(16) = undefined;

// Syscall-specific kernel stack
var syscall_stack: [16384]u8 align(16) = undefined;
pub var syscall_stack_top: u64 = 0;

// ============================================================================
// GDTR
// ============================================================================

const Gdtr = packed struct {
    limit: u16,
    base: u64,
};

var gdtr: Gdtr = undefined;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("  GDT: Loading descriptor table...\n");

    setupTSS();

    gdtr = .{
        .limit = @sizeOf(GDTTable) - 1,
        .base = @intFromPtr(&gdt_table),
    };

    lgdt(&gdtr);
    reloadSegments();

    // Setup syscall stack
    syscall_stack_top = @intFromPtr(&syscall_stack) + syscall_stack.len;

    // Verify
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const ds = asm volatile ("mov %%ds, %[result]"
        : [result] "=r" (-> u16),
    );

    serial.writeString("  GDT: CS=0x");
    printHex16(cs);
    serial.writeString(" DS=0x");
    printHex16(ds);
    serial.writeString("\n");

    serial.writeString("  GDT: User CS=0x");
    printHex16(user_cs);
    serial.writeString(" User DS=0x");
    printHex16(user_ds);
    serial.writeString(" (SYSRET compatible)\n");
}

fn setupTSS() void {
    serial.writeString("  GDT: Setting up TSS...\n");

    const kernel_stack_top = @intFromPtr(&kernel_stack) + kernel_stack.len;
    tss.rsp0 = kernel_stack_top;

    const ist_stack_top = @intFromPtr(&interrupt_stack) + interrupt_stack.len;
    tss.ist1 = ist_stack_top;

    tss.iopb = @sizeOf(TSS);

    const tss_addr = @intFromPtr(&tss);
    const tss_limit: u32 = @sizeOf(TSS) - 1;

    const tss_desc = TSSDescriptor{
        .limit_lo = @truncate(tss_limit & 0xFFFF),
        .base_lo = @truncate(tss_addr & 0xFFFF),
        .base_mid = @truncate((tss_addr >> 16) & 0xFF),
        .access = .{},
        .limit_hi_flags = @truncate(((tss_limit >> 16) & 0xF)),
        .base_hi = @truncate((tss_addr >> 24) & 0xFF),
        .base_upper = @truncate(tss_addr >> 32),
    };

    const tss_bytes: *const [16]u8 = @ptrCast(&tss_desc);
    const gdt_tss_ptr: *[16]u8 = @ptrCast(&gdt_table.tss_low);
    for (0..16) |i| {
        gdt_tss_ptr[i] = tss_bytes[i];
    }

    serial.writeString("  GDT: TSS at 0x");
    printHex64(tss_addr);
    serial.writeString("\n");
}

pub fn loadTSS() void {
    serial.writeString("  GDT: Loading TSS register...\n");
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (tss_selector),
    );
    serial.writeString("  GDT: TSS loaded\n");
}

fn lgdt(ptr: *const Gdtr) void {
    asm volatile ("lgdt (%[p])"
        :
        : [p] "r" (ptr),
        : .{ .memory = true });
}

pub fn reloadSegments() void {
    asm volatile (
        \\push $0x08
        \\lea 1f(%%rip), %%rax
        \\push %%rax
        \\lretq
        \\1:
        ::: .{ .rax = true, .memory = true });

    asm volatile (
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        \\mov %%ax, %%ss
        ::: .{ .ax = true, .memory = true });
}

pub fn setKernelStack(stack_top: u64) void {
    tss.rsp0 = stack_top;
}

pub fn getKernelStack() u64 {
    return tss.rsp0;
}

// =============================================================================
// Additional Getters
// =============================================================================

/// Get syscall kernel stack top (untuk user.zig)
pub fn getSyscallStackTop() u64 {
    // Use the same stack as TSS RSP0 for now
    return tss.rsp0;
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 12) & 0xF]);
    serial.writeChar(hex[(val >> 8) & 0xF]);
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}
