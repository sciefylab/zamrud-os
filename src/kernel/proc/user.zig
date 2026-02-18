//! Zamrud OS - User Mode Support (SC1 Final)
//! Ring 3 execution with SYSCALL/SYSRET interface
//! Production fix: conditional debug logging

const serial = @import("../drivers/serial/serial.zig");
const gdt = @import("../arch/x86_64/gdt.zig");
const heap = @import("../mm/heap.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");
const user_mem = @import("../mm/user_mem.zig");
const syscall_handler = @import("../syscall/table.zig");

// =============================================================================
// Debug Configuration
// =============================================================================

/// Set to true for verbose syscall logging (kills performance at 115200 baud)
const SYSCALL_DEBUG = false;

// =============================================================================
// MSR Constants
// =============================================================================

const MSR_EFER: u32 = 0xC0000080;
const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_SFMASK: u32 = 0xC0000084;

const EFER_SCE: u64 = 1 << 0;
const SFMASK_IF: u64 = 1 << 9;
const SFMASK_TF: u64 = 1 << 8;
const SFMASK_DF: u64 = 1 << 10;

// =============================================================================
// Size Constants
// =============================================================================

pub const USER_STACK_SIZE: u64 = 16 * 1024;
pub const USER_CODE_SIZE: u64 = 4 * 1024;
pub const KERNEL_STACK_SIZE: u64 = 16 * 1024;

// =============================================================================
// User Context
// =============================================================================

pub const UserContext = struct {
    user_rip: u64 = 0,
    user_rflags: u64 = 0,
    user_rsp: u64 = 0,
    kernel_stack_base: u64 = 0,
    kernel_stack_top: u64 = 0,
    user_stack_base: u64 = 0,
    user_stack_top: u64 = 0,
    user_code_base: u64 = 0,
    in_kernel: bool = false,
};

var current_context: UserContext = .{};
var context_valid: bool = false;
var syscall_kernel_stack: [KERNEL_STACK_SIZE]u8 align(16) = undefined;
pub var syscall_kernel_stack_top: u64 = 0;
var initialized: bool = false;

export var temp_user_rsp: u64 = 0;
export var temp_kernel_rsp: u64 = 0;

// =============================================================================
// MSR Functions
// =============================================================================

fn rdmsr(msr: u32) u64 {
    var lo: u32 = 0;
    var hi: u32 = 0;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn wrmsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
    );
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var shift: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> shift) & 0xF)]);
        if (shift == 0) break;
        shift -= 4;
    }
}

fn printNum(val: usize) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v = val;
    var started = false;

    if (v >= 1000) {
        var d: u8 = 0;
        while (v >= 1000) : (d += 1) v -= 1000;
        serial.writeChar('0' + d);
        started = true;
    }
    if (v >= 100 or started) {
        var d: u8 = 0;
        while (v >= 100) : (d += 1) v -= 100;
        serial.writeChar('0' + d);
        started = true;
    }
    if (v >= 10 or started) {
        var d: u8 = 0;
        while (v >= 10) : (d += 1) v -= 10;
        serial.writeChar('0' + d);
    }
    serial.writeChar('0' + @as(u8, @intCast(v)));
}

fn printNumU64(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v = val;
    var started = false;

    const divisors = [_]u64{
        10000000000000000000,
        1000000000000000000,
        100000000000000000,
        10000000000000000,
        1000000000000000,
        100000000000000,
        10000000000000,
        1000000000000,
        100000000000,
        10000000000,
        1000000000,
        100000000,
        10000000,
        1000000,
        100000,
        10000,
        1000,
        100,
        10,
        1,
    };

    for (divisors) |div| {
        var d: u8 = 0;
        while (v >= div) : (d += 1) v -= div;
        if (d > 0 or started) {
            serial.writeChar('0' + d);
            started = true;
        }
    }
}

fn printI64(val: i64) void {
    if (val < 0) {
        serial.writeChar('-');
        if (val == -9223372036854775808) {
            serial.writeString("9223372036854775808");
        } else {
            printNumU64(@as(u64, @intCast(-val)));
        }
    } else {
        printNumU64(@as(u64, @intCast(val)));
    }
}

fn printSyscallName(num: u64) void {
    if (num == 0) {
        serial.writeString("SYS_READ");
    } else if (num == 1) {
        serial.writeString("SYS_WRITE");
    } else if (num == 20) {
        serial.writeString("SYS_GETPID");
    } else if (num == 60) {
        serial.writeString("SYS_EXIT");
    } else {
        serial.writeString("SYS_");
        printNumU64(num);
    }
}

// =============================================================================
// Syscall Handler (called from assembly)
// =============================================================================

export fn syscallHandler(
    num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) i64 {
    if (SYSCALL_DEBUG) {
        serial.writeString("[SYSCALL] ");
        printSyscallName(num);
        serial.writeString("(");
        printNumU64(num);
        serial.writeString(")");

        if (num == 1) {
            serial.writeString(" fd=");
            printNumU64(arg1);
            serial.writeString(" len=");
            printNumU64(arg3);
        } else if (num == 60) {
            serial.writeString(" code=");
            printNumU64(arg1);
        }
        serial.writeString("\n");
    }

    const result = syscall_handler.dispatch(num, arg1, arg2, arg3, arg4, arg5, 0);

    if (SYSCALL_DEBUG) {
        serial.writeString("[SYSCALL] -> ");
        printI64(result);
        serial.writeString("\n");
    }

    return result;
}

// =============================================================================
// Syscall Entry Stub
// =============================================================================

export fn syscallEntryStub() callconv(.naked) void {
    asm volatile (
        \\mov %%rsp, temp_user_rsp(%%rip)
        \\mov temp_kernel_rsp(%%rip), %%rsp
        \\push %%rcx
        \\push %%r11
        \\push %%rbx
        \\push %%rbp
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        \\mov %%r8, %%r15
        \\mov %%r10, %%r8
        \\mov %%r15, %%r9
        \\mov %%rdx, %%rcx
        \\mov %%rsi, %%rdx
        \\mov %%rdi, %%rsi
        \\mov %%rax, %%rdi
        \\call syscallHandler
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%rbp
        \\pop %%rbx
        \\pop %%r11
        \\pop %%rcx
        \\mov temp_user_rsp(%%rip), %%rsp
        \\sysretq
    );
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[USER] Initializing SYSCALL interface...\n");

    user_mem.init();
    syscall_kernel_stack_top = @intFromPtr(&syscall_kernel_stack) + KERNEL_STACK_SIZE;
    temp_kernel_rsp = syscall_kernel_stack_top;

    const efer = rdmsr(MSR_EFER);
    wrmsr(MSR_EFER, efer | EFER_SCE);
    serial.writeString("[USER] EFER.SCE enabled\n");

    const star: u64 = (@as(u64, gdt.STAR_USER_BASE) << 48) | (@as(u64, gdt.STAR_KERNEL_BASE) << 32);
    wrmsr(MSR_STAR, star);
    serial.writeString("[USER] STAR configured\n");

    const entry_addr = @intFromPtr(&syscallEntryStub);
    wrmsr(MSR_LSTAR, entry_addr);
    serial.writeString("[USER] LSTAR = 0x");
    printHex64(entry_addr);
    serial.writeString("\n");

    wrmsr(MSR_SFMASK, SFMASK_IF | SFMASK_TF | SFMASK_DF);
    serial.writeString("[USER] SFMASK configured\n");

    initialized = true;
    serial.writeString("[USER] SYSCALL interface ready!\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Context Management
// =============================================================================

pub fn createUserContext() ?*UserContext {
    const user_stack_top = user_mem.allocUserStack(USER_STACK_SIZE) orelse return null;
    const user_code_base = user_mem.allocUserCode(USER_CODE_SIZE) orelse return null;

    current_context = .{
        .user_rip = user_code_base,
        .user_rflags = 0x202,
        .user_rsp = user_stack_top - 8,
        .kernel_stack_base = @intFromPtr(&syscall_kernel_stack),
        .kernel_stack_top = syscall_kernel_stack_top,
        .user_stack_base = user_stack_top - USER_STACK_SIZE,
        .user_stack_top = user_stack_top,
        .user_code_base = user_code_base,
        .in_kernel = false,
    };

    context_valid = true;
    return &current_context;
}

pub fn destroyUserContext() void {
    context_valid = false;
    current_context = .{};
}

pub fn getCurrentContext() ?*UserContext {
    if (context_valid) return &current_context;
    return null;
}

pub fn getSyscallStackTop() u64 {
    return syscall_kernel_stack_top;
}

// =============================================================================
// Jump to User Mode
// =============================================================================

pub fn jumpToUserMode(entry_point: u64) noreturn {
    if (!user_mem.isUserAddress(entry_point) or !context_valid) {
        serial.writeString("[USER] FATAL: Invalid entry point or context!\n");
        while (true) asm volatile ("hlt");
    }

    const user_rsp = current_context.user_rsp;
    const user_cs: u64 = gdt.user_cs;
    const user_ds: u64 = gdt.user_ds;
    const user_rflags: u64 = 0x202;

    asm volatile (
        \\mov %[ds], %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        :
        : [ds] "r" (@as(u16, @truncate(user_ds))),
        : .{ .ax = true });

    asm volatile (
        \\push %[ss]
        \\push %[rsp]
        \\push %[rflags]
        \\push %[cs]
        \\push %[rip]
        \\iretq
        :
        : [ss] "r" (user_ds),
          [rsp] "r" (user_rsp),
          [rflags] "r" (user_rflags),
          [cs] "r" (user_cs),
          [rip] "r" (entry_point),
    );

    unreachable;
}

fn jumpToUserModeIOPL3(entry_point: u64) noreturn {
    const user_rsp = current_context.user_rsp;
    const user_cs: u64 = gdt.user_cs;
    const user_ds: u64 = gdt.user_ds;
    const user_rflags: u64 = 0x7202;

    asm volatile (
        \\mov %[ds], %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        :
        : [ds] "r" (@as(u16, @truncate(user_ds))),
        : .{ .ax = true });

    asm volatile (
        \\push %[ss]
        \\push %[rsp]
        \\push %[rflags]
        \\push %[cs]
        \\push %[rip]
        \\iretq
        :
        : [ss] "r" (user_ds),
          [rsp] "r" (user_rsp),
          [rflags] "r" (user_rflags),
          [cs] "r" (user_cs),
          [rip] "r" (entry_point),
    );

    unreachable;
}

// =============================================================================
// Test: Complete Syscall Test
// =============================================================================

pub fn testSyscallFromUser() bool {
    serial.writeString("\n");
    serial.writeString("========================================\n");
    serial.writeString("  COMPLETE SYSCALL TEST FROM RING 3\n");
    serial.writeString("========================================\n\n");

    serial.writeString("[USER] This test will execute:\n");
    serial.writeString("  1. SYS_GETPID  - Get process ID\n");
    serial.writeString("  2. SYS_WRITE   - Print message to console\n");
    serial.writeString("  3. SYS_EXIT    - Terminate with code 0\n\n");

    if (!initialized) {
        serial.writeString("[USER] ERROR: Not initialized!\n");
        return false;
    }

    serial.writeString("[DEBUG] Creating context...\n");

    const ctx = createUserContext() orelse {
        serial.writeString("[USER] ERROR: Context creation failed!\n");
        return false;
    };

    serial.writeString("[USER] Code base: 0x");
    printHex64(ctx.user_code_base);
    serial.writeString("\n");

    const code_base = ctx.user_code_base;
    const code_ptr: [*]volatile u8 = @ptrFromInt(code_base);

    const msg1 = ">>> Hello from Ring 3! <<<\n";
    const msg2 = ">>> Syscall complete! <<<\n";
    const msg1_offset: usize = 256;
    const msg2_offset: usize = 300;

    for (msg1, 0..) |c, j| {
        code_ptr[msg1_offset + j] = c;
    }
    const msg1_addr: u64 = code_base + msg1_offset;

    for (msg2, 0..) |c, j| {
        code_ptr[msg2_offset + j] = c;
    }
    const msg2_addr: u64 = code_base + msg2_offset;

    serial.writeString("[DEBUG] Generating user code...\n");

    var i: usize = 0;

    // SYS_GETPID (20 in numbers.zig)
    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC0;
    i += 1;
    code_ptr[i] = 20;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x0F;
    i += 1;
    code_ptr[i] = 0x05;
    i += 1;

    // SYS_WRITE msg1
    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC0;
    i += 1;
    code_ptr[i] = 1;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 1;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xBE;
    i += 1;
    code_ptr[i] = @truncate(msg1_addr);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 8);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 16);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 24);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 32);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 40);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 48);
    i += 1;
    code_ptr[i] = @truncate(msg1_addr >> 56);
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC2;
    i += 1;
    code_ptr[i] = @intCast(msg1.len);
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x0F;
    i += 1;
    code_ptr[i] = 0x05;
    i += 1;

    // SYS_WRITE msg2
    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC0;
    i += 1;
    code_ptr[i] = 1;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 1;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xBE;
    i += 1;
    code_ptr[i] = @truncate(msg2_addr);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 8);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 16);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 24);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 32);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 40);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 48);
    i += 1;
    code_ptr[i] = @truncate(msg2_addr >> 56);
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC2;
    i += 1;
    code_ptr[i] = @intCast(msg2.len);
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x0F;
    i += 1;
    code_ptr[i] = 0x05;
    i += 1;

    // SYS_EXIT (60)
    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC0;
    i += 1;
    code_ptr[i] = 60;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x48;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0xC7;
    i += 1;
    code_ptr[i] = 0;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;
    code_ptr[i] = 0x00;
    i += 1;

    code_ptr[i] = 0x0F;
    i += 1;
    code_ptr[i] = 0x05;
    i += 1;

    // Fallback: jmp $
    code_ptr[i] = 0xEB;
    i += 1;
    code_ptr[i] = 0xFE;
    i += 1;

    serial.writeString("[USER] Code size: ");
    printNum(i);
    serial.writeString(" bytes\n\n");

    serial.writeString("========================================\n");
    serial.writeString(">>> JUMPING TO RING 3 <<<\n");
    serial.writeString("========================================\n\n");

    jumpToUserMode(code_base);

    return true;
}

// =============================================================================
// Test: Direct I/O (IOPL=3)
// =============================================================================

pub fn testUserMode() bool {
    serial.writeString("\n[USER] Testing Ring 3 execution (direct I/O)...\n");

    if (!initialized) {
        serial.writeString("[USER] ERROR: Not initialized!\n");
        return false;
    }

    const ctx = createUserContext() orelse {
        serial.writeString("[USER] ERROR: Context creation failed!\n");
        return false;
    };

    current_context.user_rflags = 0x7202;

    const code_ptr: [*]volatile u8 = @ptrFromInt(ctx.user_code_base);
    var i: usize = 0;

    code_ptr[i] = 0x66;
    i += 1;
    code_ptr[i] = 0xBA;
    i += 1;
    code_ptr[i] = 0xF8;
    i += 1;
    code_ptr[i] = 0x03;
    i += 1;

    const msg = "USER3!\n";
    for (msg) |c| {
        code_ptr[i] = 0xB0;
        i += 1;
        code_ptr[i] = c;
        i += 1;
        code_ptr[i] = 0xEE;
        i += 1;
    }

    code_ptr[i] = 0xEB;
    i += 1;
    code_ptr[i] = 0xFE;
    i += 1;

    serial.writeString("[USER] Jumping to Ring 3...\n");
    jumpToUserModeIOPL3(ctx.user_code_base);

    return true;
}
