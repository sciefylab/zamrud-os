//! Zamrud OS - Interrupt Descriptor Table (IDT)
//! Updated for Preemptive Scheduling + Syscall Support

const cpu = @import("../../core/cpu.zig");
const gdt = @import("gdt.zig");
const serial = @import("../../drivers/serial/serial.zig");
const pic = @import("pic.zig");
const keyboard = @import("../../drivers/input/keyboard.zig");
const timer = @import("../../drivers/timer/timer.zig");
const scheduler = @import("../../proc/scheduler.zig");
const syscall_handler = @import("../../syscall/table.zig");

const IDTEntry = packed struct {
    isr_low: u16,
    kernel_cs: u16,
    ist: u8 = 0,
    flags: Flags,
    isr_mid: u16,
    isr_high: u32,
    reserved: u32 = 0,

    const Flags = packed struct(u8) {
        kind: Kind,
        reserved: u1 = 0,
        ring: u2,
        present: bool = true,
    };

    const Kind = enum(u4) {
        trap = 0xF,
        interrupt = 0xE,
    };
};

const Idtr = packed struct {
    limit: u16,
    base: u64,
};

var idt: [256]IDTEntry = undefined;
var idtr: Idtr = undefined;

// =============================================================================
// Exception Handlers
// =============================================================================

export fn handleDivideError() void {
    serial.writeString("\n[#DE:DIVIDE_ERROR]\n");
    cpu.cli();
    cpu.halt();
}

export fn handleDebug() void {
    serial.writeString("[#DB:DEBUG]");
}

export fn handleNMI() void {
    serial.writeString("[NMI]");
}

export fn handleBreakpoint() void {
    serial.writeString("[#BP:BREAKPOINT]");
}

export fn handleOverflow() void {
    serial.writeString("[#OF:OVERFLOW]");
}

export fn handleBoundRange() void {
    serial.writeString("[#BR:BOUND_RANGE]");
}

export fn handleInvalidOpcode() void {
    serial.writeString("\n[#UD:INVALID_OPCODE]\n");
    cpu.cli();
    cpu.halt();
}

export fn handleDeviceNotAvailable() void {
    serial.writeString("[#NM:DEVICE_NOT_AVAILABLE]");
}

export fn handleDoubleFault() void {
    serial.writeString("\n[#DF:DOUBLE_FAULT]\n");
    cpu.cli();
    cpu.halt();
}

export fn handleInvalidTSS() void {
    serial.writeString("[#TS:INVALID_TSS]");
}

export fn handleSegmentNotPresent() void {
    serial.writeString("[#NP:SEGMENT_NOT_PRESENT]");
}

export fn handleStackSegment() void {
    serial.writeString("[#SS:STACK_SEGMENT]");
}

export fn handleGPF() void {
    serial.writeString("\n[#GP:GENERAL_PROTECTION]\n");

    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    serial.writeString("  CS=0x");
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(cs >> 12) & 0xF]);
    serial.writeChar(hex[(cs >> 8) & 0xF]);
    serial.writeChar(hex[(cs >> 4) & 0xF]);
    serial.writeChar(hex[cs & 0xF]);
    serial.writeString("\n");

    cpu.cli();
    cpu.halt();
}

export fn handlePageFault() void {
    const cr2 = asm volatile ("mov %%cr2, %[result]"
        : [result] "=r" (-> u64),
    );
    serial.writeString("\n[#PF:PAGE_FAULT @ 0x");
    printHex64(cr2);
    serial.writeString("]\n");
    cpu.cli();
    cpu.halt();
}

export fn handlex87FP() void {
    serial.writeString("[#MF:x87_FP]");
}

export fn handleAlignmentCheck() void {
    serial.writeString("[#AC:ALIGNMENT_CHECK]");
}

export fn handleMachineCheck() void {
    serial.writeString("[#MC:MACHINE_CHECK]");
}

export fn handleSIMDFP() void {
    serial.writeString("[#XM:SIMD_FP]");
}

export fn handleGenericException() void {
    serial.writeString("[EXCEPTION]");
}

fn printHex64(value: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nibble: u8 = @truncate((value >> i) & 0xF);
        serial.writeChar(hex[nibble]);
        if (i == 0) break;
    }
}

// =============================================================================
// IRQ Handlers
// =============================================================================

export fn handleKeyboard() void {
    keyboard.handleInterrupt();
    pic.sendEoi(1);
}

export fn handleTimer() void {
    timer.handleInterrupt();
    scheduler.checkPreempt();
    pic.sendEoi(0);
}

export fn handleDefault() void {
    pic.sendEoi(0);
}

// =============================================================================
// Syscall Handler
// =============================================================================

const SyscallFrame = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
};

export fn handleSyscall(frame: *SyscallFrame) void {
    // rax = syscall number
    // rdi = arg1, rsi = arg2, rdx = arg3
    // r10 = arg4, r8 = arg5, r9 = arg6

    const result = syscall_handler.dispatch(
        frame.rax,
        frame.rdi,
        frame.rsi,
        frame.rdx,
        frame.r10,
        frame.r8,
        frame.r9,
    );

    frame.rax = @bitCast(result);
}

// =============================================================================
// ISR Stubs - No Error Code
// =============================================================================

fn makeIsrNoError(comptime handler_name: []const u8) fn () callconv(.naked) void {
    return struct {
        fn isr() callconv(.naked) void {
            asm volatile ("push %%rax\n" ++
                    "push %%rcx\n" ++
                    "push %%rdx\n" ++
                    "push %%rbx\n" ++
                    "push %%rsi\n" ++
                    "push %%rdi\n" ++
                    "push %%rbp\n" ++
                    "push %%r8\n" ++
                    "push %%r9\n" ++
                    "push %%r10\n" ++
                    "push %%r11\n" ++
                    "push %%r12\n" ++
                    "push %%r13\n" ++
                    "push %%r14\n" ++
                    "push %%r15\n" ++
                    "sub $8, %%rsp\n" ++
                    "call " ++ handler_name ++ "\n" ++
                    "add $8, %%rsp\n" ++
                    "pop %%r15\n" ++
                    "pop %%r14\n" ++
                    "pop %%r13\n" ++
                    "pop %%r12\n" ++
                    "pop %%r11\n" ++
                    "pop %%r10\n" ++
                    "pop %%r9\n" ++
                    "pop %%r8\n" ++
                    "pop %%rbp\n" ++
                    "pop %%rdi\n" ++
                    "pop %%rsi\n" ++
                    "pop %%rbx\n" ++
                    "pop %%rdx\n" ++
                    "pop %%rcx\n" ++
                    "pop %%rax\n" ++
                    "iretq\n");
        }
    }.isr;
}

// =============================================================================
// ISR Stubs - With Error Code
// =============================================================================

fn makeIsrWithError(comptime handler_name: []const u8) fn () callconv(.naked) void {
    return struct {
        fn isr() callconv(.naked) void {
            asm volatile ("push %%rax\n" ++
                    "push %%rcx\n" ++
                    "push %%rdx\n" ++
                    "push %%rbx\n" ++
                    "push %%rsi\n" ++
                    "push %%rdi\n" ++
                    "push %%rbp\n" ++
                    "push %%r8\n" ++
                    "push %%r9\n" ++
                    "push %%r10\n" ++
                    "push %%r11\n" ++
                    "push %%r12\n" ++
                    "push %%r13\n" ++
                    "push %%r14\n" ++
                    "push %%r15\n" ++
                    "sub $8, %%rsp\n" ++
                    "call " ++ handler_name ++ "\n" ++
                    "add $8, %%rsp\n" ++
                    "pop %%r15\n" ++
                    "pop %%r14\n" ++
                    "pop %%r13\n" ++
                    "pop %%r12\n" ++
                    "pop %%r11\n" ++
                    "pop %%r10\n" ++
                    "pop %%r9\n" ++
                    "pop %%r8\n" ++
                    "pop %%rbp\n" ++
                    "pop %%rdi\n" ++
                    "pop %%rsi\n" ++
                    "pop %%rbx\n" ++
                    "pop %%rdx\n" ++
                    "pop %%rcx\n" ++
                    "pop %%rax\n" ++
                    "add $8, %%rsp\n" ++
                    "iretq\n");
        }
    }.isr;
}

// =============================================================================
// Exception ISR Stubs
// =============================================================================

const isr_divide_error = makeIsrNoError("handleDivideError");
const isr_debug = makeIsrNoError("handleDebug");
const isr_nmi = makeIsrNoError("handleNMI");
const isr_breakpoint = makeIsrNoError("handleBreakpoint");
const isr_overflow = makeIsrNoError("handleOverflow");
const isr_bound_range = makeIsrNoError("handleBoundRange");
const isr_invalid_opcode = makeIsrNoError("handleInvalidOpcode");
const isr_device_not_available = makeIsrNoError("handleDeviceNotAvailable");
const isr_double_fault = makeIsrWithError("handleDoubleFault");
const isr_invalid_tss = makeIsrWithError("handleInvalidTSS");
const isr_segment_not_present = makeIsrWithError("handleSegmentNotPresent");
const isr_stack_segment = makeIsrWithError("handleStackSegment");
const isr_gpf = makeIsrWithError("handleGPF");
const isr_page_fault = makeIsrWithError("handlePageFault");
const isr_x87_fp = makeIsrNoError("handlex87FP");
const isr_alignment_check = makeIsrWithError("handleAlignmentCheck");
const isr_machine_check = makeIsrNoError("handleMachineCheck");
const isr_simd_fp = makeIsrNoError("handleSIMDFP");
const isr_generic = makeIsrNoError("handleGenericException");

// =============================================================================
// IRQ ISR Stubs
// =============================================================================

fn isr_keyboard() callconv(.naked) void {
    asm volatile ("push %%rax\n" ++
            "push %%rcx\n" ++
            "push %%rdx\n" ++
            "push %%rbx\n" ++
            "push %%rsi\n" ++
            "push %%rdi\n" ++
            "push %%rbp\n" ++
            "push %%r8\n" ++
            "push %%r9\n" ++
            "push %%r10\n" ++
            "push %%r11\n" ++
            "push %%r12\n" ++
            "push %%r13\n" ++
            "push %%r14\n" ++
            "push %%r15\n" ++
            "sub $8, %%rsp\n" ++
            "call handleKeyboard\n" ++
            "add $8, %%rsp\n" ++
            "pop %%r15\n" ++
            "pop %%r14\n" ++
            "pop %%r13\n" ++
            "pop %%r12\n" ++
            "pop %%r11\n" ++
            "pop %%r10\n" ++
            "pop %%r9\n" ++
            "pop %%r8\n" ++
            "pop %%rbp\n" ++
            "pop %%rdi\n" ++
            "pop %%rsi\n" ++
            "pop %%rbx\n" ++
            "pop %%rdx\n" ++
            "pop %%rcx\n" ++
            "pop %%rax\n" ++
            "iretq");
}

fn isr_timer() callconv(.naked) void {
    asm volatile ("push %%rax\n" ++
            "push %%rcx\n" ++
            "push %%rdx\n" ++
            "push %%rbx\n" ++
            "push %%rsi\n" ++
            "push %%rdi\n" ++
            "push %%rbp\n" ++
            "push %%r8\n" ++
            "push %%r9\n" ++
            "push %%r10\n" ++
            "push %%r11\n" ++
            "push %%r12\n" ++
            "push %%r13\n" ++
            "push %%r14\n" ++
            "push %%r15\n" ++
            "sub $8, %%rsp\n" ++
            "call handleTimer\n" ++
            "add $8, %%rsp\n" ++
            "pop %%r15\n" ++
            "pop %%r14\n" ++
            "pop %%r13\n" ++
            "pop %%r12\n" ++
            "pop %%r11\n" ++
            "pop %%r10\n" ++
            "pop %%r9\n" ++
            "pop %%r8\n" ++
            "pop %%rbp\n" ++
            "pop %%rdi\n" ++
            "pop %%rsi\n" ++
            "pop %%rbx\n" ++
            "pop %%rdx\n" ++
            "pop %%rcx\n" ++
            "pop %%rax\n" ++
            "iretq");
}

fn isr_default() callconv(.naked) void {
    asm volatile ("push %%rax\n" ++
            "push %%rcx\n" ++
            "push %%rdx\n" ++
            "push %%rbx\n" ++
            "push %%rsi\n" ++
            "push %%rdi\n" ++
            "push %%rbp\n" ++
            "push %%r8\n" ++
            "push %%r9\n" ++
            "push %%r10\n" ++
            "push %%r11\n" ++
            "push %%r12\n" ++
            "push %%r13\n" ++
            "push %%r14\n" ++
            "push %%r15\n" ++
            "sub $8, %%rsp\n" ++
            "call handleDefault\n" ++
            "add $8, %%rsp\n" ++
            "pop %%r15\n" ++
            "pop %%r14\n" ++
            "pop %%r13\n" ++
            "pop %%r12\n" ++
            "pop %%r11\n" ++
            "pop %%r10\n" ++
            "pop %%r9\n" ++
            "pop %%r8\n" ++
            "pop %%rbp\n" ++
            "pop %%rdi\n" ++
            "pop %%rsi\n" ++
            "pop %%rbx\n" ++
            "pop %%rdx\n" ++
            "pop %%rcx\n" ++
            "pop %%rax\n" ++
            "iretq");
}

// =============================================================================
// Syscall ISR Stub (INT 0x80)
// =============================================================================

fn isr_syscall() callconv(.naked) void {
    asm volatile (
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rsi
        \\push %%rdi
        \\push %%rbp
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15
        //
        \\mov %%rsp, %%rdi
        \\call handleSyscall
        //
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rbp
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        //
        \\iretq
    );
}

// =============================================================================
// Set IDT Descriptor
// =============================================================================

fn setDescriptor(vector: u8, handler: *const fn () callconv(.naked) void) void {
    const addr = @intFromPtr(handler);
    idt[vector] = .{
        .isr_low = @truncate(addr & 0xFFFF),
        .isr_mid = @truncate((addr >> 16) & 0xFFFF),
        .isr_high = @truncate(addr >> 32),
        .kernel_cs = gdt.kernel_cs,
        .flags = .{
            .ring = 0,
            .kind = .interrupt,
        },
    };
}

fn setDescriptorUser(vector: u8, handler: *const fn () callconv(.naked) void) void {
    const addr = @intFromPtr(handler);
    idt[vector] = .{
        .isr_low = @truncate(addr & 0xFFFF),
        .isr_mid = @truncate((addr >> 16) & 0xFFFF),
        .isr_high = @truncate(addr >> 32),
        .kernel_cs = gdt.kernel_cs,
        .flags = .{
            .ring = 3,
            .kind = .interrupt,
        },
    };
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("  IDT: Setting up...\n");

    for (0..256) |i| {
        idt[i] = .{
            .isr_low = 0,
            .kernel_cs = 0,
            .flags = .{ .kind = .interrupt, .ring = 0, .present = false },
            .isr_mid = 0,
            .isr_high = 0,
        };
    }

    setDescriptor(0, &isr_divide_error);
    setDescriptor(1, &isr_debug);
    setDescriptor(2, &isr_nmi);
    setDescriptor(3, &isr_breakpoint);
    setDescriptor(4, &isr_overflow);
    setDescriptor(5, &isr_bound_range);
    setDescriptor(6, &isr_invalid_opcode);
    setDescriptor(7, &isr_device_not_available);
    setDescriptor(8, &isr_double_fault);
    setDescriptor(10, &isr_invalid_tss);
    setDescriptor(11, &isr_segment_not_present);
    setDescriptor(12, &isr_stack_segment);
    setDescriptor(13, &isr_gpf);
    setDescriptor(14, &isr_page_fault);
    setDescriptor(16, &isr_x87_fp);
    setDescriptor(17, &isr_alignment_check);
    setDescriptor(18, &isr_machine_check);
    setDescriptor(19, &isr_simd_fp);

    for (20..32) |i| {
        setDescriptor(@intCast(i), &isr_generic);
    }

    pic.remap(32, 40);

    setDescriptor(32, &isr_timer);
    setDescriptor(33, &isr_keyboard);

    for (34..48) |i| {
        setDescriptor(@intCast(i), &isr_default);
    }

    setDescriptorUser(0x80, &isr_syscall);
    serial.writeString("  IDT: Syscall handler at INT 0x80\n");

    idtr = .{
        .limit = @sizeOf(@TypeOf(idt)) - 1,
        .base = @intFromPtr(&idt[0]),
    };

    asm volatile ("lidt (%[idtr])"
        :
        : [idtr] "r" (&idtr),
    );

    serial.writeString("  IDT: Loaded\n");
}

pub fn enableInterrupts() void {
    serial.writeString("  IDT: Enabling interrupts...\n");
    cpu.sti();
}

pub fn disableInterrupts() void {
    cpu.cli();
}
