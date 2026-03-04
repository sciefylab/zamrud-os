//! Zamrud OS - Spinlock Primitives
//! B2.9d: Atomic synchronization for SMP
//!
//! Provides:
//! - Spinlock (basic mutual exclusion)
//! - TicketLock (fair ordering)
//! - IRQ-safe variants (save/restore interrupt state)

const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");

// ============================================================================
// Basic Spinlock (Test-and-Set with backoff)
// ============================================================================

pub const SpinLock = struct {
    locked: u32 = 0,

    const Self = @This();

    /// Acquire the lock (busy-wait)
    pub fn acquire(self: *Self) void {
        while (true) {
            // Try to atomically set locked from 0 to 1
            if (@atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) == 0) {
                return; // Got the lock
            }

            // Spin with pause hint (reduces bus contention)
            while (@atomicLoad(u32, &self.locked, .monotonic) != 0) {
                cpu.pause();
            }
        }
    }

    /// Try to acquire without blocking
    pub fn tryAcquire(self: *Self) bool {
        return @atomicRmw(u32, &self.locked, .Xchg, 1, .acquire) == 0;
    }

    /// Release the lock
    pub fn release(self: *Self) void {
        @atomicStore(u32, &self.locked, 0, .release);
    }

    /// Check if locked (for debugging)
    pub fn isLocked(self: *const Self) bool {
        return @atomicLoad(u32, &self.locked, .monotonic) != 0;
    }
};

// ============================================================================
// IRQ-Safe Spinlock (disables interrupts while held)
// ============================================================================

pub const IrqSpinLock = struct {
    lock: SpinLock = .{},
    saved_flags: u64 = 0,

    const Self = @This();

    /// Acquire lock and disable interrupts
    pub fn acquire(self: *Self) void {
        const flags = cpu.readFlags();
        cpu.cli();
        self.lock.acquire();
        self.saved_flags = flags;
    }

    /// Release lock and restore interrupt state
    pub fn release(self: *Self) void {
        const flags = self.saved_flags;
        self.lock.release();
        if ((flags & (1 << 9)) != 0) {
            cpu.sti(); // Restore IF flag
        }
    }

    /// Try to acquire without blocking
    pub fn tryAcquire(self: *Self) bool {
        const flags = cpu.readFlags();
        cpu.cli();
        if (self.lock.tryAcquire()) {
            self.saved_flags = flags;
            return true;
        }
        if ((flags & (1 << 9)) != 0) {
            cpu.sti();
        }
        return false;
    }

    pub fn isLocked(self: *const Self) bool {
        return self.lock.isLocked();
    }
};

// ============================================================================
// Ticket Lock (FIFO fairness)
// ============================================================================

pub const TicketLock = struct {
    next_ticket: u32 = 0,
    now_serving: u32 = 0,

    const Self = @This();

    /// Acquire with FIFO ordering
    pub fn acquire(self: *Self) void {
        const my_ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .monotonic);

        while (@atomicLoad(u32, &self.now_serving, .acquire) != my_ticket) {
            cpu.pause();
        }
    }

    /// Release (advance serving counter)
    pub fn release(self: *Self) void {
        _ = @atomicRmw(u32, &self.now_serving, .Add, 1, .release);
    }

    pub fn isLocked(self: *const Self) bool {
        return @atomicLoad(u32, &self.next_ticket, .monotonic) !=
            @atomicLoad(u32, &self.now_serving, .monotonic);
    }
};

// ============================================================================
// Atomic Operations Helper
// ============================================================================

pub const Atomic = struct {
    /// Atomic increment, returns old value
    pub fn fetchAdd(ptr: *u32, val: u32) u32 {
        return @atomicRmw(u32, ptr, .Add, val, .seq_cst);
    }

    /// Atomic decrement, returns old value
    pub fn fetchSub(ptr: *u32, val: u32) u32 {
        return @atomicRmw(u32, ptr, .Sub, val, .seq_cst);
    }

    /// Atomic compare-and-swap
    pub fn cmpxchg(ptr: *u32, expected: u32, desired: u32) ?u32 {
        return @cmpxchgStrong(u32, ptr, expected, desired, .seq_cst, .seq_cst);
    }

    /// Atomic load
    pub fn load(ptr: *const u32) u32 {
        return @atomicLoad(u32, ptr, .seq_cst);
    }

    /// Atomic store
    pub fn store(ptr: *u32, val: u32) void {
        @atomicStore(u32, ptr, val, .seq_cst);
    }

    // 64-bit variants

    pub fn fetchAdd64(ptr: *u64, val: u64) u64 {
        return @atomicRmw(u64, ptr, .Add, val, .seq_cst);
    }

    pub fn load64(ptr: *const u64) u64 {
        return @atomicLoad(u64, ptr, .seq_cst);
    }

    pub fn store64(ptr: *u64, val: u64) void {
        @atomicStore(u64, ptr, val, .seq_cst);
    }

    // Bool variant
    pub fn loadBool(ptr: *const bool) bool {
        return @atomicLoad(bool, ptr, .seq_cst);
    }

    pub fn storeBool(ptr: *bool, val: bool) void {
        @atomicStore(bool, ptr, val, .seq_cst);
    }
};

// ============================================================================
// Once (run initialization exactly once across CPUs)
// ============================================================================

pub const Once = struct {
    state: u32 = 0, // 0=not started, 1=in progress, 2=done

    const Self = @This();
    const NOT_STARTED: u32 = 0;
    const IN_PROGRESS: u32 = 1;
    const DONE: u32 = 2;

    /// Run function exactly once. All callers block until complete.
    pub fn callOnce(self: *Self, func: *const fn () void) void {
        if (@atomicLoad(u32, &self.state, .acquire) == DONE) return;

        if (@cmpxchgStrong(u32, &self.state, NOT_STARTED, IN_PROGRESS, .seq_cst, .seq_cst) == null) {
            // We won the race - run the function
            func();
            @atomicStore(u32, &self.state, DONE, .release);
        } else {
            // Someone else is running it - wait
            while (@atomicLoad(u32, &self.state, .acquire) != DONE) {
                cpu.pause();
            }
        }
    }

    pub fn isDone(self: *const Self) bool {
        return @atomicLoad(u32, &self.state, .acquire) == DONE;
    }
};
