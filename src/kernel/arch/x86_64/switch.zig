//! Zamrud OS - Context Switch

const serial = @import("../../drivers/serial/serial.zig");

pub fn setupProcessStack(stack_top: u64, entry: u64, arg: u64) u64 {
    var sp = stack_top;
    sp = sp & ~@as(u64, 0xF);

    sp -= 8;
    writeStack(sp, entry); // return address

    sp -= 8;
    writeStack(sp, 0); // rbp

    sp -= 8;
    writeStack(sp, 0); // rbx

    sp -= 8;
    writeStack(sp, arg); // r12 = argument

    sp -= 8;
    writeStack(sp, 0); // r13

    sp -= 8;
    writeStack(sp, 0); // r14

    sp -= 8;
    writeStack(sp, 0); // r15

    return sp;
}

inline fn writeStack(addr: u64, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(addr);
    ptr.* = value;
}

export fn _contextSwitchNaked() callconv(.naked) void {
    asm volatile (
        \\pushq %%rbp
        \\pushq %%rbx
        \\pushq %%r12
        \\pushq %%r13
        \\pushq %%r14
        \\pushq %%r15
        \\movq %%rsp, (%%rdi)
        \\movq %%rsi, %%rsp
        \\popq %%r15
        \\popq %%r14
        \\popq %%r13
        \\popq %%r12
        \\popq %%rbx
        \\popq %%rbp
        \\retq
    );
}

pub fn contextSwitch(old_rsp_ptr: *u64, new_rsp: u64) void {
    asm volatile (
        \\call _contextSwitchNaked
        :
        : [ptr] "{rdi}" (old_rsp_ptr),
          [rsp] "{rsi}" (new_rsp),
        : .{ .memory = true, .cc = true, .rcx = true, .rdx = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true });
}

export fn _jumpToFirstNaked() callconv(.naked) noreturn {
    asm volatile (
        \\movq %%rdi, %%rsp
        \\popq %%r15
        \\popq %%r14
        \\popq %%r13
        \\popq %%r12
        \\popq %%rbx
        \\popq %%rbp
        \\sti
        \\retq
    );
}

pub fn jumpToFirst(rsp: u64, arg: u64) noreturn {
    _ = arg;
    asm volatile (
        \\jmp _jumpToFirstNaked
        :
        : [rsp] "{rdi}" (rsp),
    );
    unreachable;
}
