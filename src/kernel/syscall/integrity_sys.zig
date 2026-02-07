//! Zamrud OS - Integrity Syscalls
//! System call handlers for integrity verification

const serial = @import("../drivers/serial/serial.zig");
const integrity = @import("../integrity/integrity.zig");
const registry = integrity.registry;
const quarantine = integrity.quarantine;
const monitor = integrity.monitor;
const numbers = @import("numbers.zig");

// =============================================================================
// File Integrity
// =============================================================================

/// SYS_INTEGRITY_REGISTER: Register file hash
/// Args: rdi = path_ptr, rsi = path_len, rdx = hash_ptr (32 bytes)
/// Returns: 0 on success
pub fn sysIntegrityRegister(path_ptr: usize, path_len: usize, hash_ptr: usize) isize {
    if (path_ptr == 0 or hash_ptr == 0) return numbers.EFAULT;
    if (path_len == 0 or path_len > 256) return numbers.EINVAL;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..path_len];
    const hash: *const [32]u8 = @ptrFromInt(hash_ptr);

    if (registry.registerFile(path, hash)) {
        return numbers.ESUCCESS;
    } else {
        return numbers.ENOMEM;
    }
}

/// SYS_INTEGRITY_VERIFY: Verify file integrity
/// Args: rdi = path_ptr, rsi = path_len, rdx = hash_ptr (32 bytes)
/// Returns: 1 if valid, 0 if invalid, negative on error
pub fn sysIntegrityVerify(path_ptr: usize, path_len: usize, hash_ptr: usize) isize {
    if (path_ptr == 0 or hash_ptr == 0) return numbers.EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..path_len];
    const hash: *const [32]u8 = @ptrFromInt(hash_ptr);

    const result = registry.verifyFile(path, hash);

    return switch (result) {
        .valid => 1,
        .invalid => 0,
        .not_registered => numbers.EINTEG_NOTFOUND,
        .error_reading => numbers.EIO,
    };
}

/// SYS_INTEGRITY_UNREGISTER: Remove file from registry
/// Args: rdi = path_ptr, rsi = path_len
/// Returns: 0 on success
pub fn sysIntegrityUnregister(path_ptr: usize, path_len: usize) isize {
    if (path_ptr == 0) return numbers.EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..path_len];

    if (registry.unregisterFile(path)) {
        return numbers.ESUCCESS;
    } else {
        return numbers.EINTEG_NOTFOUND;
    }
}

/// SYS_INTEGRITY_GET_HASH: Get registered hash for file
/// Args: rdi = path_ptr, rsi = path_len, rdx = out_hash (32 bytes)
/// Returns: 32 on success, negative on error
pub fn sysIntegrityGetHash(path_ptr: usize, path_len: usize, out_hash: usize) isize {
    if (path_ptr == 0 or out_hash == 0) return numbers.EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..path_len];

    if (registry.getFileHash(path)) |hash| {
        const buf: [*]u8 = @ptrFromInt(out_hash);
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            buf[i] = hash[i];
        }
        return 32;
    } else {
        return numbers.EINTEG_NOTFOUND;
    }
}

/// SYS_INTEGRITY_STATUS: Get integrity subsystem status
/// Returns: 1 if initialized, 0 otherwise
pub fn sysIntegrityStatus() isize {
    return if (integrity.isInitialized()) 1 else 0;
}

// =============================================================================
// Quarantine
// =============================================================================

/// SYS_QUARANTINE_CHECK: Check if file is quarantined
/// Args: rdi = path_ptr, rsi = path_len
/// Returns: 1 if quarantined, 0 if not, negative on error
pub fn sysQuarantineCheck(path_ptr: usize, path_len: usize) isize {
    if (path_ptr == 0) return numbers.EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..path_len];

    return if (quarantine.isQuarantined(path)) 1 else 0;
}

// =============================================================================
// Monitor
// =============================================================================

/// SYS_MONITOR_STATUS: Get monitor status
/// Returns: 1 if running, 0 if stopped
pub fn sysMonitorStatus() isize {
    return if (monitor.isRunning()) 1 else 0;
}
