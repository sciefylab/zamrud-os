//! Zamrud OS - Syscall Dispatch Table

const handlers = @import("handlers.zig");
const numbers = @import("numbers.zig");

/// Dispatch syscall by number
pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) i64 {
    // Mark unused args - akan dipakai nanti untuk syscall yang butuh lebih banyak args
    _ = a4;
    _ = a5;
    _ = a6;

    return switch (num) {
        // === Standard Syscalls ===
        numbers.SYS_READ => handlers.sysRead(a1, a2, a3),
        numbers.SYS_WRITE => handlers.sysWrite(a1, a2, a3),
        numbers.SYS_OPEN => handlers.sysOpen(a1, a2, a3),
        numbers.SYS_CLOSE => handlers.sysClose(a1),
        numbers.SYS_EXIT => {
            handlers.sysExit(a1);
        },
        numbers.SYS_GETPID => handlers.sysGetpid(),
        numbers.SYS_GETPPID => handlers.sysGetppid(),
        numbers.SYS_GETUID => handlers.sysGetuid(),
        numbers.SYS_GETGID => handlers.sysGetgid(),
        numbers.SYS_GETCWD => handlers.sysGetcwd(a1, a2),
        numbers.SYS_CHDIR => handlers.sysChdir(a1),
        numbers.SYS_MKDIR => handlers.sysMkdir(a1, a2),
        numbers.SYS_RMDIR => handlers.sysRmdir(a1),
        numbers.SYS_UNLINK => handlers.sysUnlink(a1),
        numbers.SYS_SCHED_YIELD => handlers.sysSchedYield(),
        numbers.SYS_NANOSLEEP => handlers.sysNanosleep(a1, a2),

        // === Zamrud Debug ===
        numbers.SYS_DEBUG_PRINT => handlers.sysDebugPrint(a1, a2),
        numbers.SYS_GET_TICKS => handlers.sysGetTicks(),
        numbers.SYS_GET_UPTIME => handlers.sysGetUptime(),

        // === Graphics ===
        numbers.SYS_FB_GET_INFO => handlers.sysFbGetInfo(a1),
        numbers.SYS_FB_MAP => handlers.sysFbMap(),
        numbers.SYS_FB_UNMAP => handlers.sysFbUnmap(a1),
        numbers.SYS_FB_FLUSH => handlers.sysFbFlush(a1),
        numbers.SYS_CURSOR_SET_POS => handlers.sysCursorSetPos(a1, a2),
        numbers.SYS_CURSOR_SET_VISIBLE => handlers.sysCursorSetVisible(a1),
        numbers.SYS_CURSOR_SET_TYPE => handlers.sysCursorSetType(a1),
        numbers.SYS_SCREEN_GET_ORIENTATION => handlers.sysScreenGetOrientation(),

        // === Input ===
        numbers.SYS_INPUT_POLL => handlers.sysInputPoll(a1),
        numbers.SYS_INPUT_WAIT => handlers.sysInputWait(a1, a2),
        numbers.SYS_INPUT_GET_TOUCH_CAPS => handlers.sysInputGetTouchCaps(a1),

        // === Unknown ===
        else => handlers.ENOSYS,
    };
}
