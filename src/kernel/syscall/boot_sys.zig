//! Zamrud OS - Boot Syscalls
//! System call handlers for boot verification

const serial = @import("../drivers/serial/serial.zig");
const boot_verify = @import("../boot/verify.zig");
const policy = @import("../boot/policy.zig");
const numbers = @import("numbers.zig");

// =============================================================================
// Boot Verification
// =============================================================================

/// SYS_BOOT_STATUS: Get boot verification status
/// Returns: 1 if verified, 0 if not
pub fn sysBootStatus() isize {
    return if (boot_verify.isVerified()) 1 else 0;
}

/// SYS_BOOT_VERIFY: Re-run boot verification
/// Returns: Number of checks passed, negative on error
pub fn sysBootVerify() isize {
    const result = boot_verify.verify();
    if (result.success) {
        return @intCast(result.checks_passed);
    } else {
        return numbers.EBOOT_TAMPERED;
    }
}

/// SYS_BOOT_GET_HASH: Get kernel hash
/// Args: rdi = out_buf (32 bytes)
/// Returns: 32 on success
pub fn sysBootGetHash(out_buf: usize) isize {
    if (out_buf == 0) return numbers.EFAULT;

    const hash = boot_verify.getKernelHash();
    const buf: [*]u8 = @ptrFromInt(out_buf);

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        buf[i] = hash[i];
    }

    return 32;
}

/// SYS_BOOT_GET_POLICY: Get current security policy level
/// Returns: 0=permissive, 1=standard, 2=strict, 3=paranoid
pub fn sysBootGetPolicy() isize {
    return switch (policy.getLevel()) {
        .permissive => 0,
        .standard => 1,
        .strict => 2,
        .paranoid => 3,
    };
}

/// SYS_BOOT_SET_POLICY: Set security policy level (requires privilege)
/// Args: rdi = level (0-3)
/// Returns: 0 on success
pub fn sysBootSetPolicy(level: usize) isize {
    // In production, check caller privileges here
    switch (level) {
        0 => policy.setLevel(.permissive),
        1 => policy.setLevel(.standard),
        2 => policy.setLevel(.strict),
        3 => policy.setLevel(.paranoid),
        else => return numbers.EINVAL,
    }
    return numbers.ESUCCESS;
}
