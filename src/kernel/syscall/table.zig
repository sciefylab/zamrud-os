//! Zamrud OS - Syscall Dispatch Table (SC1-SC7: Unified)

const handlers = @import("handlers.zig");
const numbers = @import("numbers.zig");
const capability = @import("../security/capability.zig");
const process = @import("../proc/process.zig");
const timer = @import("../drivers/timer/timer.zig");
const serial = @import("../drivers/serial/serial.zig");

// Subsystem dispatchers
const identity_sys = @import("identity_sys.zig");
const integrity_sys = @import("integrity_sys.zig");
const boot_sys = @import("boot_sys.zig");
const crypto_sys = @import("crypto_sys.zig");
const proc_sys = @import("proc_sys.zig");
const ipc_sys = @import("ipc_sys.zig");
const shm_sys = @import("shm_sys.zig");
const user_sys = @import("user_sys.zig");
const net_sys = @import("net_sys.zig");
const enc_sys = @import("enc_sys.zig");

// =============================================================================
// Statistics
// =============================================================================

var syscall_count: u64 = 0;
var last_syscall: u64 = 0;
var initialized: bool = false;

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
    serial.writeString("[SYSCALL] Initializing unified dispatch...\n");
    syscall_count = 0;
    last_syscall = 0;
    initialized = true;
    serial.writeString("[SYSCALL] Ready (unified)\n");
}

// =============================================================================
// Main Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, _: u64, _: u64) i64 {
    syscall_count += 1;
    last_syscall = num;

    // === Capability Check ===
    if (capability.isInitialized()) {
        const pid = process.getCurrentPid();

        if (num == numbers.SYS_WRITE) {
            if (!capability.checkWrite(pid, a1)) {
                capability.recordViolationPublic(pid, capability.CAP_FS_WRITE, num, timer.getTicks());
                if (capability.shouldKill(pid)) {
                    serial.writeString("[CAP] AUTO-KILL PID=");
                    printDec32(pid);
                    serial.writeString("\n");
                    _ = process.terminate(pid);
                    return numbers.EPERM;
                }
                return numbers.EPERM;
            }
        } else {
            const required = capability.syscallRequiredCap(num);
            if (required != capability.CAP_NONE) {
                if (!capability.checkAndEnforce(pid, required, num, timer.getTicks())) {
                    if (capability.shouldKill(pid)) {
                        serial.writeString("[CAP] AUTO-KILL PID=");
                        printDec32(pid);
                        serial.writeString("\n");
                        _ = process.terminate(pid);
                        return numbers.EPERM;
                    }
                    return numbers.EPERM;
                }
            }
        }
    }

    // === Route by range ===

    if (numbers.isCoreSyscall(num)) return dispatchCore(num, a1, a2, a3, a4);
    if (numbers.isIdentitySyscall(num)) return identity_sys.dispatch(num, a1, a2, a3, a4);
    if (numbers.isIntegritySyscall(num)) return integrity_sys.dispatch(num, a1, a2, a3);
    if (numbers.isBootSyscall(num)) return boot_sys.dispatch(num, a1);
    if (numbers.isCryptoSyscall(num)) return crypto_sys.dispatch(num, a1, a2, a3);
    if (numbers.isChainSyscall(num)) return numbers.ENOSYS;
    if (numbers.isIpcSyscall(num)) return ipc_sys.dispatch(num, a1, a2, a3, a4);
    if (numbers.isShmSyscall(num)) return shm_sys.dispatch(num, a1, a2, a3, a4);
    if (numbers.isUserSyscall(num)) return user_sys.dispatch(num, a1, a2, a3, a4);
    if (numbers.isProcExtSyscall(num)) return proc_sys.dispatch(num, a1, a2, a3);
    if (numbers.isCapSyscall(num)) return dispatchCap(num, a1, a2);
    if (numbers.isNetSyscall(num)) return net_sys.dispatch(num, a1, a2, a3, a4);

    // Encrypted FS (260-269) + ELF/Loader (270-279) — SC7
    if (numbers.isEncFsSyscall(num)) return enc_sys.dispatch(num, a1, a2, a3, a4);
    if (numbers.isLoaderSyscall(num)) return enc_sys.dispatch(num, a1, a2, a3, a4);

    if (numbers.isFsExtSyscall(num)) return dispatchFsExt(num, a1, a2, a3);
    if (numbers.isGraphicsSyscall(num)) return dispatchGraphics(num, a1, a2);
    if (numbers.isInputSyscall(num)) return dispatchInput(num, a1, a2);
    if (numbers.isDebugSyscall(num)) return dispatchDebug(num, a1, a2);

    return numbers.ENOSYS;
}

// =============================================================================
// Core Dispatcher (0-99)
// =============================================================================

fn dispatchCore(num: u64, a1: u64, a2: u64, a3: u64, a4: u64) i64 {
    _ = a4;
    return switch (num) {
        numbers.SYS_READ => handlers.sysRead(a1, a2, a3),
        numbers.SYS_WRITE => handlers.sysWrite(a1, a2, a3),
        numbers.SYS_OPEN => handlers.sysOpen(a1, a2, a3),
        numbers.SYS_CLOSE => handlers.sysClose(a1),
        numbers.SYS_STAT => handlers.sysStat(a1, a2),
        numbers.SYS_LSEEK => handlers.sysSeek(a1, a2, a3),
        numbers.SYS_GETPID => handlers.sysGetpid(),
        numbers.SYS_GETUID => handlers.sysGetuid(),
        numbers.SYS_GETGID => handlers.sysGetgid(),
        numbers.SYS_GETEUID => handlers.sysGeteuid(),
        numbers.SYS_GETEGID => handlers.sysGetegid(),
        numbers.SYS_GETPPID => handlers.sysGetppid(),
        numbers.SYS_GETCWD => handlers.sysGetcwd(a1, a2),
        numbers.SYS_CHDIR => handlers.sysChdir(a1),
        numbers.SYS_MKDIR => handlers.sysMkdir(a1, a2),
        numbers.SYS_RMDIR => handlers.sysRmdir(a1),
        numbers.SYS_UNLINK => handlers.sysUnlink(a1),
        numbers.SYS_NANOSLEEP => handlers.sysNanosleep(a1, a2),
        numbers.SYS_SCHED_YIELD => handlers.sysSchedYield(),
        numbers.SYS_EXIT => {
            handlers.sysExit(a1);
        },
        else => numbers.ENOSYS,
    };
}

fn dispatchCap(num: u64, a1: u64, a2: u64) i64 {
    const pid = process.getCurrentPid();
    return switch (num) {
        numbers.SYS_CAP_GET => blk: {
            const target = if (a1 == 0) pid else @as(u32, @intCast(a1 & 0xFFFFFFFF));
            break :blk @intCast(capability.getCaps(target));
        },
        numbers.SYS_CAP_CHECK => blk: {
            const target = if (a1 == 0) pid else @as(u32, @intCast(a1 & 0xFFFFFFFF));
            const cap: u32 = @intCast(a2 & 0xFFFFFFFF);
            break :blk if (capability.check(target, cap)) 1 else 0;
        },
        numbers.SYS_CAP_DROP => blk: {
            const cap: u32 = @intCast(a1 & 0xFFFFFFFF);
            break :blk if (capability.revokeCap(pid, cap)) numbers.SUCCESS else numbers.EPERM;
        },
        else => numbers.ENOSYS,
    };
}

fn dispatchFsExt(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        numbers.SYS_FSTAT_PATH => handlers.sysStat(a1, a2),
        numbers.SYS_READDIR => handlers.sysReaddir(a1, a2, a3),
        numbers.SYS_RENAME => handlers.sysRename(a1, a2),
        numbers.SYS_TRUNCATE => handlers.sysTruncate(a1, a2),
        numbers.SYS_SEEK => handlers.sysSeek(a1, a2, a3),
        else => numbers.ENOSYS,
    };
}

fn dispatchGraphics(num: u64, a1: u64, a2: u64) i64 {
    return switch (num) {
        numbers.SYS_FB_GET_INFO => handlers.sysFbGetInfo(a1),
        numbers.SYS_FB_MAP => handlers.sysFbMap(),
        numbers.SYS_FB_UNMAP => handlers.sysFbUnmap(a1),
        numbers.SYS_FB_FLUSH => handlers.sysFbFlush(a1),
        numbers.SYS_CURSOR_SET_POS => handlers.sysCursorSetPos(a1, a2),
        numbers.SYS_CURSOR_SET_VISIBLE => handlers.sysCursorSetVisible(a1),
        numbers.SYS_CURSOR_SET_TYPE => handlers.sysCursorSetType(a1),
        numbers.SYS_SCREEN_GET_ORIENTATION => handlers.sysScreenGetOrientation(),
        else => numbers.ENOSYS,
    };
}

fn dispatchInput(num: u64, a1: u64, a2: u64) i64 {
    return switch (num) {
        numbers.SYS_INPUT_POLL => handlers.sysInputPoll(a1),
        numbers.SYS_INPUT_WAIT => handlers.sysInputWait(a1, a2),
        numbers.SYS_INPUT_GET_TOUCH_CAPS => handlers.sysInputGetTouchCaps(a1),
        else => numbers.ENOSYS,
    };
}

fn dispatchDebug(num: u64, a1: u64, a2: u64) i64 {
    return switch (num) {
        numbers.SYS_DEBUG_PRINT => handlers.sysDebugPrint(a1, a2),
        numbers.SYS_GET_TICKS => handlers.sysGetTicks(),
        numbers.SYS_GET_UPTIME => handlers.sysGetUptime(),
        numbers.SYS_SYSCALL_COUNT => @intCast(syscall_count),
        else => numbers.ENOSYS,
    };
}

fn printDec32(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var v: u32 = val;
    var started = false;
    const divs = [_]u32{ 1000000000, 100000000, 10000000, 1000000, 100000, 10000, 1000, 100, 10, 1 };
    for (divs) |d| {
        var digit: u8 = 0;
        while (v >= d) : (digit += 1) v -= d;
        if (digit > 0 or started) {
            serial.writeChar('0' + digit);
            started = true;
        }
    }
}
