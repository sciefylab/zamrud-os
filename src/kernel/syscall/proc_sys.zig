//! Zamrud OS - Process Extended Syscalls (SC2)
//! SYS_SPAWN, SYS_PROC_KILL, SYS_PROC_WAITPID,
//! SYS_PROC_YIELD, SYS_GETPRIORITY, SYS_SETPRIORITY

const numbers = @import("numbers.zig");
const process = @import("../proc/process.zig");
const scheduler = @import("../proc/scheduler.zig");
const serial = @import("../drivers/serial/serial.zig");

// =============================================================================
// Dispatcher
// =============================================================================

pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64) i64 {
    return switch (num) {
        numbers.SYS_SPAWN => sysSpawn(a1, a2, a3),
        numbers.SYS_PROC_KILL => sysProcKill(a1),
        numbers.SYS_PROC_WAITPID => sysProcWaitpid(a1, a2, a3),
        numbers.SYS_PROC_YIELD => sysProcYield(),
        numbers.SYS_GETPRIORITY => sysGetPriority(a1),
        numbers.SYS_SETPRIORITY => sysSetPriority(a1, a2),
        else => numbers.ENOSYS,
    };
}

// =============================================================================
// Pointer Validation (shared)
// =============================================================================

fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

fn readCString(ptr: u64, max_len: usize) ?[]const u8 {
    if (ptr == 0) return null;
    const p: [*]const u8 = @ptrFromInt(ptr);
    var len: usize = 0;
    while (len < max_len) : (len += 1) {
        if (p[len] == 0) return p[0..len];
    }
    return null;
}

// =============================================================================
// SYS_SPAWN (230) — Create a new process
//   a1 = name_ptr  (C string, 0 = "unnamed")
//   a2 = entry_ptr (function address)
//   a3 = arg       (argument passed to entry)
//   Returns: PID (>0) on success, negative error
// =============================================================================

fn sysSpawn(name_ptr: u64, entry_ptr: u64, arg: u64) i64 {
    if (entry_ptr == 0) return numbers.EINVAL;

    const name: []const u8 = if (name_ptr != 0)
        readCString(name_ptr, 32) orelse "spawned"
    else
        "spawned";

    const pid = process.createWithEntry(name, entry_ptr, arg) orelse {
        return numbers.ENOMEM;
    };

    return @intCast(pid);
}

// =============================================================================
// SYS_PROC_KILL (231) — Terminate a process
//   a1 = pid
//   Returns: 0 on success, negative error
// =============================================================================

fn sysProcKill(pid_raw: u64) i64 {
    if (pid_raw == 0) return numbers.EINVAL; // cannot kill idle

    const pid: u32 = @intCast(@min(pid_raw, 0xFFFFFFFF));

    // Verify process exists
    if (process.getSlotByPid(pid) == null) return numbers.ESRCH;

    // Cannot kill self via this syscall (use SYS_EXIT instead)
    if (pid == process.getCurrentPid()) {
        // Use scheduler's exit path for safe self-termination
        if (scheduler.isRunning()) {
            scheduler.exitCurrentProcess();
            // Should not return, but just in case:
            return numbers.SUCCESS;
        }
    }

    if (process.terminate(pid)) return numbers.SUCCESS;
    return numbers.EPERM;
}

// =============================================================================
// SYS_PROC_WAITPID (232) — Wait for child process
//   a1 = pid       (process to wait for, 0 = any child)
//   a2 = status_ptr (where to write exit status, 0 = don't care)
//   a3 = options   (0 = return immediately if not yet exited)
//   Returns: PID if exited, -EAGAIN if still running, -ESRCH if not found
//
//   NOTE: Non-blocking for now. Full blocking wait requires wait queues (future).
// =============================================================================

fn sysProcWaitpid(pid_raw: u64, status_ptr: u64, options: u64) i64 {
    _ = options;

    const pid: u32 = @intCast(@min(pid_raw, 0xFFFFFFFF));

    if (pid == 0) {
        // Wait for any child — scan for terminated processes
        var i: usize = 1;
        while (i < process.MAX_SLOTS_USED) : (i += 1) {
            if (process.process_used[i] and
                process.process_table[i].state == .Terminated)
            {
                const found_pid = process.process_table[i].pid;
                writeExitStatus(status_ptr, 0);
                // Clean up the terminated process
                _ = process.terminate(found_pid);
                return @intCast(found_pid);
            }
        }
        return numbers.EAGAIN; // no child has exited yet
    }

    // Wait for specific PID
    if (process.getSlotByPid(pid)) |slot| {
        if (process.process_table[slot].state == .Terminated) {
            writeExitStatus(status_ptr, 0);
            _ = process.terminate(pid);
            return @intCast(pid);
        }
        // Still running
        return numbers.EAGAIN;
    }

    // PID not found — already exited and cleaned up, or never existed
    return numbers.ESRCH;
}

fn writeExitStatus(status_ptr: u64, code: u32) void {
    if (status_ptr != 0 and validatePtr(status_ptr, 4)) {
        const status: *u32 = @ptrFromInt(status_ptr);
        status.* = code;
    }
}

// =============================================================================
// SYS_PROC_YIELD (233) — Yield CPU to another process
//   Returns: 0 always
// =============================================================================

fn sysProcYield() i64 {
    scheduler.yield();
    return numbers.SUCCESS;
}

// =============================================================================
// SYS_GETPRIORITY (234)
// =============================================================================

fn sysGetPriority(pid_raw: u64) i64 {
    const pid: u32 = if (pid_raw == 0)
        process.getCurrentPid()
    else
        @intCast(@min(pid_raw, 0xFFFFFFFF));

    // PID 0 (idle) — return its priority directly, don't error
    if (pid == 0) return @intCast(process.process_table[0].priority);

    const slot = process.getSlotByPid(pid) orelse return numbers.ESRCH;
    return @intCast(process.process_table[slot].priority);
}

// =============================================================================
// SYS_SETPRIORITY (235)
// =============================================================================

fn sysSetPriority(pid_raw: u64, priority_raw: u64) i64 {
    const pid: u32 = if (pid_raw == 0)
        process.getCurrentPid()
    else
        @intCast(@min(pid_raw, 0xFFFFFFFF));

    const priority: u8 = @intCast(@min(priority_raw, 255));

    // Allow setting priority on PID 0 if it's "self" (shell context)
    if (pid == 0) {
        if (process.process_used[0]) {
            process.process_table[0].priority = priority;
            return numbers.SUCCESS;
        }
        return numbers.ESRCH;
    }

    const slot = process.getSlotByPid(pid) orelse return numbers.ESRCH;

    if (process.process_table[slot].state == .Terminated) return numbers.ESRCH;

    process.process_table[slot].priority = priority;
    return numbers.SUCCESS;
}
