//! Zamrud OS - CPU Instructions
//! Low-level CPU operations, port I/O, and control registers

const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Context Structure for Interrupt Handling
// =============================================================================

/// Context harus match dengan urutan push di ISR wrapper
pub const Context = extern struct {
    // Registers pushed by our wrapper
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

    // Pushed by CPU or our wrapper
    int_num: u64,
    error_code: u64,

    // Pushed by CPU
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// =============================================================================
// CPUID
// =============================================================================

pub const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

/// Execute CPUID instruction
pub fn cpuid(leaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [_eax] "={eax}" (eax),
          [_ebx] "={ebx}" (ebx),
          [_ecx] "={ecx}" (ecx),
          [_edx] "={edx}" (edx),
        : [in_eax] "{eax}" (leaf),
    );

    return .{
        .eax = eax,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

/// Execute CPUID with subleaf
pub fn cpuidEx(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [_eax] "={eax}" (eax),
          [_ebx] "={ebx}" (ebx),
          [_ecx] "={ecx}" (ecx),
          [_edx] "={edx}" (edx),
        : [in_eax] "{eax}" (leaf),
          [in_ecx] "{ecx}" (subleaf),
    );

    return .{
        .eax = eax,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

// =============================================================================
// SSE/FPU Initialization
// =============================================================================

/// Enable SSE instructions (required for Zig's auto-vectorization)
pub fn enableSSE() void {
    // CR0: Clear EM (bit 2), Set MP (bit 1)
    var cr0 = readCR0();
    cr0 &= ~@as(usize, 1 << 2); // Clear EM
    cr0 |= (1 << 1); // Set MP
    writeCR0(cr0);

    // CR4: Set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
    var cr4 = readCR4();
    cr4 |= (1 << 9); // OSFXSR
    cr4 |= (1 << 10); // OSXMMEXCPT
    writeCR4(cr4);
}

/// Check if SSE is available
pub fn hasSSE() bool {
    const result = cpuid(1);
    return (result.edx & (1 << 25)) != 0;
}

/// Check if SSE2 is available
pub fn hasSSE2() bool {
    const result = cpuid(1);
    return (result.edx & (1 << 26)) != 0;
}

// =============================================================================
// Port I/O - 8-bit
// =============================================================================

/// Write 8-bit value to I/O port
pub inline fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{al}" (value),
    );
}

/// Read 8-bit value from I/O port
pub inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

// =============================================================================
// Port I/O - 16-bit
// =============================================================================

/// Write 16-bit value to I/O port
pub inline fn outw(port: u16, value: u16) void {
    asm volatile ("outw %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{ax}" (value),
    );
}

/// Read 16-bit value from I/O port
pub inline fn inw(port: u16) u16 {
    return asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "{dx}" (port),
    );
}

// =============================================================================
// Port I/O - 32-bit
// =============================================================================

/// Write 32-bit value to I/O port
pub inline fn outl(port: u16, value: u32) void {
    asm volatile ("outl %[value], %[port]"
        :
        : [port] "{dx}" (port),
          [value] "{eax}" (value),
    );
}

/// Read 32-bit value from I/O port
pub inline fn inl(port: u16) u32 {
    return asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "{dx}" (port),
    );
}

// =============================================================================
// Interrupt Control
// =============================================================================

/// Disable interrupts
pub inline fn cli() void {
    asm volatile ("cli");
}

/// Enable interrupts
pub inline fn sti() void {
    asm volatile ("sti");
}

/// Halt CPU until next interrupt
pub inline fn hlt() void {
    asm volatile ("hlt");
}

/// Halt CPU forever (infinite loop)
pub fn halt() noreturn {
    cli();
    while (true) {
        asm volatile ("hlt");
    }
}

/// Short I/O delay (approximately 1-4 microseconds)
pub inline fn ioWait() void {
    outb(0x80, 0);
}

// =============================================================================
// Control Registers
// =============================================================================

/// Read CR0 register
pub inline fn readCR0() usize {
    return asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Write CR0 register
pub inline fn writeCR0(value: usize) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (value),
    );
}

/// Read CR2 register (page fault address)
pub inline fn readCR2() usize {
    return asm volatile ("mov %%cr2, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Read CR3 register (page directory base)
pub inline fn readCR3() usize {
    return asm volatile ("mov %%cr3, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Write CR3 register (flushes TLB)
pub inline fn writeCR3(value: usize) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (value),
    );
}

/// Read CR4 register
pub inline fn readCR4() usize {
    return asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Write CR4 register
pub inline fn writeCR4(value: usize) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (value),
    );
}

// =============================================================================
// MSR (Model Specific Registers)
// =============================================================================

/// Read MSR
pub inline fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return @as(u64, low) | (@as(u64, high) << 32);
}

/// Write MSR
pub inline fn wrmsr(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

// =============================================================================
// Misc CPU Operations
// =============================================================================

/// Invalidate TLB entry for address
pub inline fn invlpg(addr: usize) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
        : .{ .memory = true }
    );
}

/// Read timestamp counter
pub inline fn rdtsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return @as(u64, low) | (@as(u64, high) << 32);
}

/// Pause hint for spin-wait loops
pub inline fn pause() void {
    asm volatile ("pause");
}

/// Memory barrier
pub inline fn mfence() void {
    asm volatile ("mfence" ::: .{ .memory = true });
}

/// Load fence
pub inline fn lfence() void {
    asm volatile ("lfence" ::: .{ .memory = true });
}

/// Store fence
pub inline fn sfence() void {
    asm volatile ("sfence" ::: .{ .memory = true });
}

// =============================================================================
// Stack Operations
// =============================================================================

/// Get current stack pointer
pub inline fn getStackPointer() usize {
    return asm volatile ("mov %%rsp, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Get current base pointer
pub inline fn getBasePointer() usize {
    return asm volatile ("mov %%rbp, %[ret]"
        : [ret] "=r" (-> usize),
    );
}

/// Get current instruction pointer (via call)
pub inline fn getInstructionPointer() usize {
    return @returnAddress();
}

// =============================================================================
// Flags
// =============================================================================

/// Read RFLAGS register
pub inline fn readFlags() u64 {
    return asm volatile (
        \\pushfq
        \\pop %[ret]
        : [ret] "=r" (-> u64),
    );
}

/// Check if interrupts are enabled
pub inline fn interruptsEnabled() bool {
    const flags = readFlags();
    return (flags & (1 << 9)) != 0; // IF flag is bit 9
}
