//! Zamrud OS - System Call Dispatcher

const serial = @import("../drivers/serial/serial.zig");
const vfs = @import("../fs/vfs.zig");
const process = @import("../proc/process.zig");
const timer = @import("../drivers/timer/timer.zig");

// Subsystem imports
const identity = @import("../identity/identity.zig");
const integrity = @import("../integrity/integrity.zig");
const boot_verify = @import("../boot/verify.zig");
const policy = @import("../boot/policy.zig");
const crypto = @import("../crypto/crypto.zig");
const hash = @import("../crypto/hash.zig");

// =============================================================================
// Syscall Statistics
// =============================================================================

var syscall_count: u64 = 0;
var last_syscall: u64 = 0;
var initialized: bool = false;

// =============================================================================
// Error Codes (Linux compatible + Zamrud extensions)
// =============================================================================

pub const SUCCESS: i64 = 0;
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ERANGE: i64 = -34;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;

// Identity specific errors
pub const EIDENT_NOTFOUND: i64 = -100;
pub const EIDENT_EXISTS: i64 = -101;
pub const EIDENT_LOCKED: i64 = -102;
pub const EIDENT_BADPIN: i64 = -103;
pub const EIDENT_FULL: i64 = -104;
pub const EIDENT_INVALID: i64 = -105;

// Integrity specific errors
pub const EINTEG_MISMATCH: i64 = -110;
pub const EINTEG_NOTFOUND: i64 = -111;
pub const EINTEG_QUARANTINE: i64 = -112;

// Boot specific errors
pub const EBOOT_UNVERIFIED: i64 = -120;
pub const EBOOT_TAMPERED: i64 = -121;

// =============================================================================
// Syscall Numbers
// =============================================================================

// Core syscalls (Linux x86_64 compatible: 0-49)
const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_NANOSLEEP: u64 = 35;
const SYS_GETPID: u64 = 39;
const SYS_EXIT: u64 = 60;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_UNLINK: u64 = 87;
const SYS_GETUID: u64 = 102;
const SYS_GETGID: u64 = 104;
const SYS_GETPPID: u64 = 110;

// Identity syscalls (100-119)
const SYS_IDENTITY_CREATE: u64 = 100;
const SYS_IDENTITY_DELETE: u64 = 101;
const SYS_IDENTITY_LIST: u64 = 102;
const SYS_IDENTITY_GET: u64 = 103;
const SYS_IDENTITY_GET_CURRENT: u64 = 104;
const SYS_IDENTITY_SET_CURRENT: u64 = 105;
const SYS_IDENTITY_UNLOCK: u64 = 106;
const SYS_IDENTITY_LOCK: u64 = 107;
const SYS_IDENTITY_IS_UNLOCKED: u64 = 108;
const SYS_IDENTITY_GET_ADDRESS: u64 = 111;
const SYS_IDENTITY_GET_PUBKEY: u64 = 112;
const SYS_PRIVACY_GET_MODE: u64 = 115;
const SYS_PRIVACY_SET_MODE: u64 = 116;
const SYS_NAME_AVAILABLE: u64 = 119;

// Integrity syscalls (120-139)
const SYS_INTEGRITY_REGISTER: u64 = 120;
const SYS_INTEGRITY_STATUS: u64 = 124;
const SYS_QUARANTINE_CHECK: u64 = 133;
const SYS_MONITOR_ENABLED: u64 = 137;

// Boot/Security syscalls (140-159)
const SYS_BOOT_STATUS: u64 = 140;
const SYS_BOOT_VERIFY: u64 = 141;
const SYS_BOOT_GET_HASH: u64 = 142;
const SYS_BOOT_GET_POLICY: u64 = 143;
const SYS_BOOT_SET_POLICY: u64 = 144;

// Crypto syscalls (160-179)
const SYS_CRYPTO_HASH: u64 = 160;
const SYS_CRYPTO_RANDOM: u64 = 162;

// Zamrud-specific syscalls (400+)
const SYS_DEBUG_PRINT: u64 = 400;
const SYS_GET_TICKS: u64 = 401;
const SYS_GET_UPTIME: u64 = 402;

// =============================================================================
// Pointer Validation
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;

    const result = @addWithOverflow(ptr, len);
    if (result[1] != 0) return false;

    return true;
}

fn strLen(ptr: u64, max_len: usize) ?usize {
    if (ptr == 0) return null;

    const str: [*]const u8 = @ptrFromInt(ptr);
    var len: usize = 0;
    while (len < max_len) : (len += 1) {
        if (str[len] == 0) return len;
    }
    return null;
}

// =============================================================================
// Main Dispatcher
// =============================================================================

pub fn dispatch(
    syscall_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) i64 {
    _ = arg5;

    syscall_count += 1;
    last_syscall = syscall_num;

    // Core syscalls (0-99)
    if (syscall_num < 100) {
        return dispatchCore(syscall_num, arg1, arg2, arg3, arg4);
    }

    // Identity syscalls (100-119)
    if (syscall_num < 120) {
        return dispatchIdentity(syscall_num, arg1, arg2, arg3, arg4);
    }

    // Integrity syscalls (120-139)
    if (syscall_num < 140) {
        return dispatchIntegrity(syscall_num, arg1, arg2, arg3);
    }

    // Boot syscalls (140-159)
    if (syscall_num < 160) {
        return dispatchBoot(syscall_num, arg1);
    }

    // Crypto syscalls (160-179)
    if (syscall_num < 180) {
        return dispatchCrypto(syscall_num, arg1, arg2, arg3);
    }

    // Zamrud-specific syscalls (400+)
    if (syscall_num >= 400) {
        return dispatchZamrud(syscall_num, arg1, arg2, arg3);
    }

    return ENOSYS;
}

// =============================================================================
// Core Syscall Dispatcher
// =============================================================================

fn dispatchCore(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    _ = a4;

    return switch (num) {
        SYS_READ => sysRead(a1, a2, a3),
        SYS_WRITE => sysWrite(a1, a2, a3),
        SYS_GETPID => @intCast(process.getCurrentPid()),
        SYS_GETPPID => 0,
        SYS_GETUID => 0,
        SYS_GETGID => 0,
        SYS_GETCWD => sysGetcwd(a1, a2),
        SYS_CHDIR => sysChdir(a1),
        SYS_MKDIR => sysMkdir(a1, a2),
        SYS_RMDIR => sysRmdir(a1),
        SYS_UNLINK => sysUnlink(a1),
        SYS_NANOSLEEP => sysNanosleep(a1),
        SYS_EXIT => sysExit(a1),
        else => ENOSYS,
    };
}

// =============================================================================
// Identity Syscall Dispatcher
// =============================================================================

fn dispatchIdentity(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    return switch (num) {
        SYS_IDENTITY_CREATE => sysIdentityCreate(a1, a2, a3, a4),
        SYS_IDENTITY_DELETE => sysIdentityDelete(a1, a2),
        SYS_IDENTITY_LIST => sysIdentityList(),
        SYS_IDENTITY_GET => sysIdentityGet(a1, a2, a3),
        SYS_IDENTITY_GET_CURRENT => sysIdentityGetCurrent(a1, a2),
        SYS_IDENTITY_SET_CURRENT => sysIdentitySetCurrent(a1, a2),
        SYS_IDENTITY_UNLOCK => sysIdentityUnlock(a1, a2, a3, a4),
        SYS_IDENTITY_LOCK => sysIdentityLock(),
        SYS_IDENTITY_IS_UNLOCKED => sysIdentityIsUnlocked(),
        SYS_IDENTITY_GET_ADDRESS => sysIdentityGetAddress(a1, a2, a3, a4),
        SYS_IDENTITY_GET_PUBKEY => sysIdentityGetPubkey(a1, a2, a3),
        SYS_PRIVACY_GET_MODE => sysPrivacyGetMode(),
        SYS_PRIVACY_SET_MODE => sysPrivacySetMode(a1),
        SYS_NAME_AVAILABLE => sysNameAvailable(a1, a2),
        else => ENOSYS,
    };
}

// =============================================================================
// Integrity Syscall Dispatcher
// =============================================================================

fn dispatchIntegrity(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        SYS_INTEGRITY_STATUS => sysIntegrityStatus(),
        SYS_QUARANTINE_CHECK => sysQuarantineCheck(a1, a2),
        SYS_MONITOR_ENABLED => sysMonitorEnabled(),
        SYS_INTEGRITY_REGISTER => sysIntegrityRegister(a1, a2, a3),
        else => ENOSYS,
    };
}

// =============================================================================
// Boot Syscall Dispatcher
// =============================================================================

fn dispatchBoot(num: u64, a1: u64) i64 {
    return switch (num) {
        SYS_BOOT_STATUS => sysBootStatus(),
        SYS_BOOT_VERIFY => sysBootVerify(),
        SYS_BOOT_GET_HASH => sysBootGetHash(a1),
        SYS_BOOT_GET_POLICY => sysBootGetPolicy(),
        SYS_BOOT_SET_POLICY => sysBootSetPolicy(a1),
        else => ENOSYS,
    };
}

// =============================================================================
// Crypto Syscall Dispatcher
// =============================================================================

fn dispatchCrypto(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        SYS_CRYPTO_HASH => sysCryptoHash(a1, a2, a3),
        SYS_CRYPTO_RANDOM => sysCryptoRandom(a1, a2),
        else => ENOSYS,
    };
}

// =============================================================================
// Zamrud-specific Syscall Dispatcher
// =============================================================================

fn dispatchZamrud(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    _ = a3;

    return switch (num) {
        SYS_DEBUG_PRINT => sysDebugPrint(a1, a2),
        SYS_GET_TICKS => @intCast(timer.getTicks()),
        SYS_GET_UPTIME => @intCast(timer.getSeconds()),
        else => ENOSYS,
    };
}

// =============================================================================
// Core Syscall Implementations
// =============================================================================

fn sysRead(fd: u64, buf: u64, count: u64) i64 {
    if (!validatePtr(buf, count)) return EFAULT;
    if (count == 0) return 0;
    if (fd == 0) return 0; // stdin EOF
    return EBADF;
}

fn sysWrite(fd: u64, buf: u64, count: u64) i64 {
    if (!validatePtr(buf, count)) return EFAULT;
    if (count == 0) return 0;

    if (fd == 1 or fd == 2) {
        const ptr: [*]const u8 = @ptrFromInt(buf);
        const len = @min(count, 4096);

        var i: usize = 0;
        while (i < len) : (i += 1) {
            serial.writeChar(ptr[i]);
        }
        return @intCast(len);
    }

    return EBADF;
}

fn sysGetcwd(buf: u64, size: u64) i64 {
    if (!validatePtr(buf, size)) return EFAULT;
    if (size == 0) return EINVAL;

    const ptr: [*]u8 = @ptrFromInt(buf);
    const cwd = vfs.getcwd();

    if (cwd.len >= size) return ERANGE;

    for (cwd, 0..) |c, i| {
        ptr[i] = c;
    }
    ptr[cwd.len] = 0;

    return @intCast(buf);
}

fn sysChdir(path: u64) i64 {
    const len = strLen(path, 256) orelse return EFAULT;
    if (len == 0) return EINVAL;

    const ptr: [*]const u8 = @ptrFromInt(path);
    if (vfs.chdir(ptr[0..len])) {
        return SUCCESS;
    }
    return ENOENT;
}

fn sysMkdir(path: u64, mode: u64) i64 {
    _ = mode;

    const len = strLen(path, 256) orelse return EFAULT;
    if (len == 0) return EINVAL;

    const ptr: [*]const u8 = @ptrFromInt(path);
    if (vfs.createDir(ptr[0..len]) != null) {
        return SUCCESS;
    }
    return EACCES;
}

fn sysRmdir(path: u64) i64 {
    const len = strLen(path, 256) orelse return EFAULT;
    if (len == 0) return EINVAL;

    const ptr: [*]const u8 = @ptrFromInt(path);
    if (vfs.removeDir(ptr[0..len])) {
        return SUCCESS;
    }
    return ENOENT;
}

fn sysUnlink(path: u64) i64 {
    const len = strLen(path, 256) orelse return EFAULT;
    if (len == 0) return EINVAL;

    const ptr: [*]const u8 = @ptrFromInt(path);
    if (vfs.removeFile(ptr[0..len])) {
        return SUCCESS;
    }
    return ENOENT;
}

fn sysDebugPrint(buf: u64, len: u64) i64 {
    if (!validatePtr(buf, len)) return EFAULT;
    if (len == 0) return 0;

    const ptr: [*]const u8 = @ptrFromInt(buf);
    const safe_len = @min(len, 4096);

    serial.writeString("[USER] ");
    var i: usize = 0;
    while (i < safe_len) : (i += 1) {
        serial.writeChar(ptr[i]);
    }
    serial.writeString("\n");

    return @intCast(safe_len);
}

fn sysNanosleep(req: u64) i64 {
    if (!validatePtr(req, 16)) return EFAULT;

    const timespec: *const extern struct { sec: i64, nsec: i64 } = @ptrFromInt(req);
    const ms = timespec.sec * 1000 + @divTrunc(timespec.nsec, 1_000_000);
    timer.sleep(@intCast(@max(0, ms)));

    return SUCCESS;
}

fn sysExit(code: u64) i64 {
    _ = code;

    const pid = process.getCurrentPid();
    if (pid != 0) {
        _ = process.terminate(pid);
    }

    while (true) {
        asm volatile ("hlt");
    }
}

// =============================================================================
// Identity Syscall Implementations
// =============================================================================

fn sysIdentityCreate(name_ptr: u64, name_len: u64, pin_ptr: u64, pin_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (!validatePtr(pin_ptr, pin_len)) return EFAULT;
    if (name_len == 0 or name_len > 32) return EINVAL;
    if (pin_len < 4 or pin_len > 64) return EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..@intCast(pin_len)];

    if (identity.keyring.createIdentity(name, pin)) |_| {
        return SUCCESS;
    }
    return EIDENT_FULL;
}

fn sysIdentityDelete(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (name_len == 0 or name_len > 32) return EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.deleteIdentity(name)) {
        return SUCCESS;
    }
    return EIDENT_NOTFOUND;
}

fn sysIdentityList() i64 {
    return @intCast(identity.keyring.getIdentityCount());
}

fn sysIdentityGet(index: u64, out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(out_buf, buf_len)) return EFAULT;
    if (buf_len < 64) return EINVAL;

    if (identity.keyring.getIdentityByIndex(@intCast(index))) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }
        return @intCast(i);
    }
    return EIDENT_NOTFOUND;
}

fn sysIdentityGetCurrent(out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(out_buf, buf_len)) return EFAULT;

    if (identity.keyring.getCurrentIdentity()) |id| {
        const buf: [*]u8 = @ptrFromInt(out_buf);
        const name = id.getName();

        var i: usize = 0;
        while (i < name.len and i < buf_len) : (i += 1) {
            buf[i] = name[i];
        }
        return @intCast(i);
    }
    return EIDENT_NOTFOUND;
}

fn sysIdentitySetCurrent(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (name_len == 0 or name_len > 32) return EINVAL;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.setCurrentIdentity(name)) {
        return SUCCESS;
    }
    return EIDENT_NOTFOUND;
}

// auth.unlock takes (name, credential) - not (identity, pin)
fn sysIdentityUnlock(name_ptr: u64, name_len: u64, pin_ptr: u64, pin_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (!validatePtr(pin_ptr, pin_len)) return EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];
    const pin: []const u8 = @as([*]const u8, @ptrFromInt(pin_ptr))[0..@intCast(pin_len)];

    if (identity.auth.unlock(name, pin)) {
        return SUCCESS;
    }
    return EIDENT_BADPIN;
}

// auth.lock takes no arguments
fn sysIdentityLock() i64 {
    identity.auth.lock();
    return SUCCESS;
}

// auth.isUnlocked takes no arguments
fn sysIdentityIsUnlocked() i64 {
    return if (identity.auth.isUnlocked()) 1 else 0;
}

fn sysIdentityGetAddress(name_ptr: u64, name_len: u64, out_buf: u64, buf_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (!validatePtr(out_buf, buf_len)) return EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.findIdentity(name)) |id| {
        const addr = id.getAddress();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < addr.len and i < buf_len) : (i += 1) {
            buf[i] = addr[i];
        }
        return @intCast(i);
    }
    return EIDENT_NOTFOUND;
}

fn sysIdentityGetPubkey(name_ptr: u64, name_len: u64, out_buf: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;
    if (!validatePtr(out_buf, 32)) return EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    if (identity.keyring.findIdentity(name)) |id| {
        const pubkey = id.getPublicKey();
        const buf: [*]u8 = @ptrFromInt(out_buf);

        var i: usize = 0;
        while (i < 32) : (i += 1) {
            buf[i] = pubkey[i];
        }
        return 32;
    }
    return EIDENT_NOTFOUND;
}

// privacy.PrivacyMode uses .public not .public_mode
fn sysPrivacyGetMode() i64 {
    return switch (identity.privacy.getMode()) {
        .stealth => 0,
        .pseudonymous => 1,
        .public => 2,
    };
}

fn sysPrivacySetMode(mode: u64) i64 {
    switch (mode) {
        0 => identity.privacy.setMode(.stealth),
        1 => identity.privacy.setMode(.pseudonymous),
        2 => identity.privacy.setMode(.public),
        else => return EINVAL,
    }
    return SUCCESS;
}

fn sysNameAvailable(name_ptr: u64, name_len: u64) i64 {
    if (!validatePtr(name_ptr, name_len)) return EFAULT;

    const name: []const u8 = @as([*]const u8, @ptrFromInt(name_ptr))[0..@intCast(name_len)];

    return if (identity.names.isAvailable(name)) 1 else 0;
}

// =============================================================================
// Integrity Syscall Implementations
// =============================================================================

fn sysIntegrityStatus() i64 {
    return if (integrity.isInitialized()) 1 else 0;
}

fn sysQuarantineCheck(path_ptr: u64, path_len: u64) i64 {
    if (!validatePtr(path_ptr, path_len)) return EFAULT;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..@intCast(path_len)];

    return if (integrity.quarantine.isQuarantined(path)) 1 else 0;
}

// monitor.isEnabled() instead of isRunning()
fn sysMonitorEnabled() i64 {
    return if (integrity.monitor.isEnabled()) 1 else 0;
}

// registry.registerFile needs 4 args: name, hash, file_type, version
fn sysIntegrityRegister(path_ptr: u64, path_len: u64, hash_ptr: u64) i64 {
    if (!validatePtr(path_ptr, path_len)) return EFAULT;
    if (!validatePtr(hash_ptr, 32)) return EFAULT;
    if (path_len == 0 or path_len > 32) return EINVAL;

    const path: []const u8 = @as([*]const u8, @ptrFromInt(path_ptr))[0..@intCast(path_len)];
    const hash_val: *const [32]u8 = @ptrFromInt(hash_ptr);

    if (integrity.registry.registerFile(path, hash_val, .user_app, 1)) {
        return SUCCESS;
    }
    return ENOMEM;
}

// =============================================================================
// Boot Syscall Implementations
// =============================================================================

fn sysBootStatus() i64 {
    return if (boot_verify.isVerified()) 1 else 0;
}

fn sysBootVerify() i64 {
    const result = boot_verify.verify();
    if (result.success) {
        return @intCast(result.checks_passed);
    }
    return EBOOT_TAMPERED;
}

fn sysBootGetHash(out_buf: u64) i64 {
    if (!validatePtr(out_buf, 32)) return EFAULT;

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
        else => return EINVAL,
    }
    return SUCCESS;
}

// =============================================================================
// Crypto Syscall Implementations
// =============================================================================

fn sysCryptoHash(data_ptr: u64, data_len: u64, out_hash: u64) i64 {
    if (!validatePtr(data_ptr, data_len)) return EFAULT;
    if (!validatePtr(out_hash, 32)) return EFAULT;
    if (data_len > 0x100000) return EINVAL; // Max 1MB

    const data: []const u8 = @as([*]const u8, @ptrFromInt(data_ptr))[0..@intCast(data_len)];
    const out: *[32]u8 = @ptrFromInt(out_hash);

    hash.sha256Into(data, out);
    return 32;
}

fn sysCryptoRandom(out_buf: u64, count: u64) i64 {
    if (!validatePtr(out_buf, count)) return EFAULT;
    if (count == 0 or count > 256) return EINVAL;

    const buf: [*]u8 = @ptrFromInt(out_buf);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        var byte: [1]u8 = undefined;
        crypto.random.getBytes(&byte);
        buf[i] = byte[0];
    }
    return @intCast(count);
}

// =============================================================================
// Statistics & Init
// =============================================================================

pub fn getSyscallCount() u64 {
    return syscall_count;
}

pub fn getLastSyscall() u64 {
    return last_syscall;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn init() void {
    serial.writeString("[SYSCALL] Initializing...\n");
    syscall_count = 0;
    last_syscall = 0;
    initialized = true;
    serial.writeString("[SYSCALL] Ready\n");
}

// =============================================================================
// Test
// =============================================================================

pub fn test_syscalls() bool {
    serial.writeString("\n=== Syscall Test ===\n");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: Boot status
    serial.writeString("  Test 1: SYS_BOOT_STATUS\n");
    const boot_status = dispatch(SYS_BOOT_STATUS, 0, 0, 0, 0, 0);
    if (boot_status >= 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 2: Identity list
    serial.writeString("  Test 2: SYS_IDENTITY_LIST\n");
    const id_count = dispatch(SYS_IDENTITY_LIST, 0, 0, 0, 0, 0);
    if (id_count >= 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 3: Integrity status
    serial.writeString("  Test 3: SYS_INTEGRITY_STATUS\n");
    const integ_status = dispatch(SYS_INTEGRITY_STATUS, 0, 0, 0, 0, 0);
    if (integ_status >= 0) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 4: Privacy mode
    serial.writeString("  Test 4: SYS_PRIVACY_GET_MODE\n");
    const priv_mode = dispatch(SYS_PRIVACY_GET_MODE, 0, 0, 0, 0, 0);
    if (priv_mode >= 0 and priv_mode <= 2) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 5: Crypto random
    serial.writeString("  Test 5: SYS_CRYPTO_RANDOM\n");
    var rand_buf: [16]u8 = undefined;
    const rand_result = dispatch(SYS_CRYPTO_RANDOM, @intFromPtr(&rand_buf), 16, 0, 0, 0);
    if (rand_result == 16) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 6: Unknown syscall
    serial.writeString("  Test 6: Unknown syscall\n");
    const unknown = dispatch(9999, 0, 0, 0, 0, 0);
    if (unknown == ENOSYS) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 7: Boot policy
    serial.writeString("  Test 7: SYS_BOOT_GET_POLICY\n");
    const pol = dispatch(SYS_BOOT_GET_POLICY, 0, 0, 0, 0, 0);
    if (pol >= 0 and pol <= 3) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    // Test 8: Crypto hash
    serial.writeString("  Test 8: SYS_CRYPTO_HASH\n");
    const test_data = "test";
    var hash_out: [32]u8 = undefined;
    const hash_result = dispatch(
        SYS_CRYPTO_HASH,
        @intFromPtr(test_data.ptr),
        test_data.len,
        @intFromPtr(&hash_out),
        0,
        0,
    );
    if (hash_result == 32) {
        serial.writeString("    OK\n");
        passed += 1;
    } else {
        serial.writeString("    FAIL\n");
        failed += 1;
    }

    serial.writeString("  SYSCALL: ");
    printU32(passed);
    serial.writeString("/");
    printU32(passed + failed);
    serial.writeString(" passed\n");

    return failed == 0;
}

fn printU32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = [_]u8{0} ** 10;
    var i: usize = 0;
    var v = val;

    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v = v / 10;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
