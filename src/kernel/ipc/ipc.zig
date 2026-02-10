//! Zamrud OS - F1+F2: IPC Main Module
//! Unified IPC subsystem entry point

const serial = @import("../drivers/serial/serial.zig");

pub const message = @import("message.zig");
pub const pipe = @import("pipe.zig");
pub const signal = @import("signal.zig");
pub const shared_mem = @import("shared_mem.zig");

var initialized: bool = false;

pub fn init() void {
    serial.writeString("[IPC] Initializing IPC subsystem...\n");

    message.init();
    pipe.init();
    signal.init();
    shared_mem.init();

    initialized = true;
    serial.writeString("[IPC] IPC subsystem ready\n");
}

pub fn isInitialized() bool {
    return initialized;
}

/// Cleanup all IPC resources for a process (call on exit)
pub fn cleanupProcess(pid: u16) void {
    message.destroyMailbox(pid);
    pipe.closeAllForPid(pid);
    signal.unregisterProcess(pid);
    shared_mem.detachAll(pid);
}

/// Print all IPC subsystem status
pub fn printStatus() void {
    serial.writeString("\n========== IPC STATUS ==========\n");
    message.printStatus();
    pipe.printStatus();
    signal.printStatus();
    shared_mem.printStatus();
    serial.writeString("================================\n\n");
}
