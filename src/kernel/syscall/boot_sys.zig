//! Zamrud OS - Boot Syscall Dispatcher
//! SC1: Fixed types (i64/u64), added dispatch(), matches numbers.zig

const serial = @import("../drivers/serial/serial.zig");
const boot_verify = @import("../boot/verify.zig");
const policy = @import("../boot/policy.zig");
const numbers = @import("numbers.zig");

// =============================================================================
// Dispatcher — called from table.zig
// =============================================================================

pub fn dispatch(num: u64, a1: u64) i64 {
    return switch (num) {
        numbers.SYS_BOOT_STATUS => sysBootStatus(),
        numbers.SYS_BOOT_VERIFY => sysBootVerify(),
        numbers.SYS_BOOT_GET_HASH => sysBootGetHash(a1),
        numbers.SYS_BOOT_GET_POLICY => sysBootGetPolicy(),
        numbers.SYS_BOOT_SET_POLICY => sysBootSetPolicy(a1),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Boot Verification
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
