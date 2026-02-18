//! Zamrud OS - Integrity Syscall Dispatcher
//! Wraps integrity subsystem calls with unified dispatch function.
//! SC1: Fixed types (i64), added dispatch(), matches numbers.zig

const serial = @import("../drivers/serial/serial.zig");
const integrity = @import("../integrity/integrity.zig");
const numbers = @import("numbers.zig");

// =============================================================================
// Dispatcher — called from table.zig
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        numbers.SYS_INTEGRITY_REGISTER => sysIntegrityRegister(a1, a2, a3),
        numbers.SYS_INTEGRITY_VERIFY => numbers.ENOSYS, // TODO
        numbers.SYS_INTEGRITY_UNREGISTER => numbers.ENOSYS, // TODO
        numbers.SYS_INTEGRITY_GET_HASH => numbers.ENOSYS, // TODO
        numbers.SYS_INTEGRITY_STATUS => sysIntegrityStatus(),
        numbers.SYS_QUARANTINE_ADD => numbers.ENOSYS, // TODO
        numbers.SYS_QUARANTINE_REMOVE => numbers.ENOSYS, // TODO
        numbers.SYS_QUARANTINE_LIST => numbers.ENOSYS, // TODO
        numbers.SYS_QUARANTINE_CHECK => sysQuarantineCheck(a1, a2),
        numbers.SYS_MONITOR_START => numbers.ENOSYS, // TODO
        numbers.SYS_MONITOR_STOP => numbers.ENOSYS, // TODO
        numbers.SYS_MONITOR_STATUS => sysMonitorEnabled(),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Pointer Validation
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

// =============================================================================
// File Integrity
// =============================================================================

fn sysIntegrityRegister(path_ptr: u64, path_len: u64, hash_ptr: u64) i64 {
    if (!validatePtr(path_ptr, path_len)) return numbers.EFAULT;
    if (!validatePtr(hash_ptr, 32)) return numbers.EFAULT;
    if (path_len == 0 or path_len > 256) return numbers.EINVAL;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..@intCast(path_len)];
    const hash_val: *const [32]u8 = @ptrFromInt(hash_ptr);

    // registry.registerFile may take 2 or 4 args depending on version
    // Try the 4-arg version first (name, hash, file_type, version)
    if (integrity.registry.registerFile(path, hash_val, .user_app, 1)) {
        return numbers.SUCCESS;
    }
    return numbers.ENOMEM;
}

fn sysIntegrityStatus() i64 {
    return if (integrity.isInitialized()) 1 else 0;
}

// =============================================================================
// Quarantine
// =============================================================================

fn sysQuarantineCheck(path_ptr: u64, path_len: u64) i64 {
    if (!validatePtr(path_ptr, path_len)) return numbers.EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..@intCast(path_len)];

    return if (integrity.quarantine.isQuarantined(path)) 1 else 0;
}

// =============================================================================
// Monitor
// =============================================================================

fn sysMonitorEnabled() i64 {
    return if (integrity.monitor.isEnabled()) 1 else 0;
}
