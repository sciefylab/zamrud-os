//! Zamrud OS - Boot Syscall Dispatcher (H.5 Enhanced)

const serial = @import("../drivers/serial/serial.zig");
const boot_verify = @import("../boot/verify.zig");
const policy = @import("../boot/policy.zig");
const measure = @import("../boot/measure.zig");
const numbers = @import("numbers.zig");

// H.5 local syscall numbers
const SYS_BOOT_GET_PCR: u64 = 0xB005;
const SYS_BOOT_REMEASURE: u64 = 0xB006;
const SYS_BOOT_EVENT_COUNT: u64 = 0xB007;
const SYS_BOOT_CHAIN_STATUS: u64 = 0xB008;

// =============================================================================
// Dispatcher — 2 args only (matches table.zig)
// =============================================================================

pub fn dispatch(num: u64, a1: u64) i64 {
    return switch (num) {
        numbers.SYS_BOOT_STATUS => sysBootStatus(),
        numbers.SYS_BOOT_VERIFY => sysBootVerify(),
        numbers.SYS_BOOT_GET_HASH => sysBootGetHash(a1),
        numbers.SYS_BOOT_GET_POLICY => sysBootGetPolicy(),
        numbers.SYS_BOOT_SET_POLICY => sysBootSetPolicy(a1),
        SYS_BOOT_GET_PCR => sysBootGetPcrStatus(a1),
        SYS_BOOT_REMEASURE => sysBootRemeasure(),
        SYS_BOOT_EVENT_COUNT => sysBootEventCount(),
        SYS_BOOT_CHAIN_STATUS => sysBootChainStatus(),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Existing Syscalls
// =============================================================================

fn sysBootStatus() i64 {
    return if (boot_verify.isVerified()) 1 else 0;
}

fn sysBootVerify() i64 {
    const result = boot_verify.verify();
    if (result.success) {
        return @intCast(result.checks_passed);
    }
    return numbers.EBOOT_TAMPERED;
}

fn sysBootGetHash(out_buf: u64) i64 {
    if (out_buf == 0) return numbers.EFAULT;

    const h = boot_verify.getKernelHash();
    const buf: [*]u8 = @ptrFromInt(out_buf);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[i] = h[i];
    }

    return 32;
}

fn sysBootGetPolicy() i64 {
    return switch (policy.getLevel()) {
        .permissive => 0,
        .standard => 1,
        .strict => 2,
        .paranoid => 3,
    };
}

fn sysBootSetPolicy(level: u64) i64 {
    switch (level) {
        0 => policy.setLevel(.permissive),
        1 => policy.setLevel(.standard),
        2 => policy.setLevel(.strict),
        3 => policy.setLevel(.paranoid),
        else => return numbers.EINVAL,
    }
    return numbers.SUCCESS;
}

// =============================================================================
// H.5 New Syscalls
// =============================================================================

/// Get PCR extended status: a1 = PCR index, returns 1 if extended, 0 if not
fn sysBootGetPcrStatus(pcr_index: u64) i64 {
    if (pcr_index >= measure.NUM_PCRS) return numbers.EINVAL;
    return if (measure.isPcrExtended(@intCast(pcr_index))) 1 else 0;
}

/// Runtime re-measurement: returns 1 if intact, 0 if tampered
fn sysBootRemeasure() i64 {
    const status = boot_verify.runtimeVerify();
    if (!status.checked) return numbers.EINVAL;
    if (status.text_ok and status.rodata_ok) return 1;
    return 0;
}

/// Get boot event count
fn sysBootEventCount() i64 {
    return @intCast(measure.getEventCount());
}

/// Get chain status: stages_done in high 8 bits, flags in low 8 bits
fn sysBootChainStatus() i64 {
    const status = measure.getChainStatus();
    var result: u64 = 0;
    result |= @as(u64, status.stages_done) << 8;
    if (status.complete) result |= 0x01;
    if (status.sealed) result |= 0x02;
    return @intCast(result);
}
