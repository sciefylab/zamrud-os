//! Zamrud OS - Syscall Dispatch Table (E3.1: with Capability Enforcement)

const handlers = @import("handlers.zig");
const numbers = @import("numbers.zig");
const capability = @import("../security/capability.zig");
const process = @import("../proc/process.zig");
const timer = @import("../drivers/timer/timer.zig");
const serial = @import("../drivers/serial/serial.zig");

/// Dispatch syscall by number - with capability enforcement
pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) i64 {
    _ = a4;
    _ = a5;
    _ = a6;

    // === E3.1: Capability Check ===
    // Fast path: only check if capability system is initialized
    if (capability.isInitialized()) {
        const pid = process.getCurrentPid();

        // Special handling for SYS_WRITE: stdout/stderr always allowed
        if (num == numbers.SYS_WRITE) {
            if (!capability.checkWrite(pid, a1)) {
                // fd > 2 and no FS_WRITE cap
                const ts = if (@import("std").meta.hasFn(timer, "getTicks"))
                    timer.getTicks()
                else
                    0;
                _ = ts;
                capability.recordViolationPublic(pid, capability.CAP_FS_WRITE, num, timer.getTicks());
                if (capability.shouldKill(pid)) {
                    serial.writeString("[CAP] AUTO-KILL PID=");
                    printDec32(pid);
                    serial.writeString(" (violation threshold)\n");
                    _ = process.terminate(pid);
                    // Return error; process is dead but syscall returns gracefully
                    return handlers.EPERM;
                }
                return handlers.EPERM;
            }
        } else {
            // General capability check
            const required = capability.syscallRequiredCap(num);
            if (required != capability.CAP_NONE) {
                if (!capability.checkAndEnforce(pid, required, num, timer.getTicks())) {
                    // Violation recorded. Check kill threshold.
                    if (capability.shouldKill(pid)) {
                        serial.writeString("[CAP] AUTO-KILL PID=");
                        printDec32(pid);
                        serial.writeString(" (violation threshold)\n");
                        _ = process.terminate(pid);
                        return handlers.EPERM;
                    }
                    return handlers.EPERM;
                }
            }
        }
    }

    // === Normal Dispatch ===
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

// =============================================================================
// Helper
// =============================================================================

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
