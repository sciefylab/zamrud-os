//! Zamrud OS - Process Commands
//! ps, spawn, kill, sched

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const process = @import("../../proc/process.zig");
const scheduler = @import("../../proc/scheduler.zig");
const test_procs = @import("../../proc/test_procs.zig");

pub fn cmdPs(_: []const u8) void {
    shell.printInfoLine("Process List:");
    shell.println("  PID   STATE       PRIORITY");
    shell.println("  ----  ----------  --------");

    var count: u32 = 0;
    var i: usize = 0;

    while (i < 8) : (i += 1) {
        if (process.process_used[i]) {
            const pid_val: u32 = process.process_table[i].pid;
            const state: u8 = @intFromEnum(process.process_table[i].state);
            const priority: u8 = process.process_table[i].priority;

            shell.print("  ");
            helpers.printU32(pid_val);
            shell.print("     ");

            switch (state) {
                0 => shell.print("Created   "),
                1 => shell.print("Ready     "),
                2 => shell.print("Running   "),
                3 => shell.print("Blocked   "),
                4 => shell.print("Terminated"),
                else => shell.print("???       "),
            }

            shell.print("  ");
            helpers.printU8(priority);
            shell.newLine();

            count += 1;
        }
    }

    shell.println("  ----  ----------  --------");
    shell.print("  Total: ");
    helpers.printU32(count);
    shell.println(" processes");
}

pub fn cmdSpawn(_: []const u8) void {
    shell.printInfoLine("Spawning test process...");

    const id = process.getCount() + 1;
    const pid_result = process.createWithEntry(
        "counter",
        @intFromPtr(&test_procs.counterProcess),
        id,
    );

    if (pid_result) |p| {
        shell.printSuccess("Created process PID: ");
        helpers.printU32(p);
        shell.newLine();
    } else {
        shell.printErrorLine("Failed to create process!");
    }
}

pub fn cmdKill(args: []const u8) void {
    const trimmed = helpers.trim(args);
    if (trimmed.len == 0) {
        shell.printErrorLine("kill: usage: kill <pid>");
        return;
    }

    const pid_val = helpers.parseU32(trimmed) orelse {
        shell.printErrorLine("kill: invalid PID");
        return;
    };

    if (pid_val == 0) {
        shell.printErrorLine("Cannot kill idle process (PID 0)!");
        return;
    }

    if (process.terminate(pid_val)) {
        shell.printSuccessLine("Process terminated");
    } else {
        shell.printErrorLine("Process not found!");
    }
}

pub fn cmdSched(_: []const u8) void {
    shell.printInfoLine("Scheduler Status:");

    shell.print("  Enabled: ");
    if (scheduler.isEnabled()) {
        shell.printSuccessLine("YES");
    } else {
        shell.printErrorLine("NO");
    }

    shell.print("  Ticks: ");
    helpers.printU64(scheduler.getTicks());
    shell.newLine();

    shell.print("  Switches: ");
    helpers.printU64(scheduler.getSwitchCount());
    shell.newLine();

    shell.print("  Processes: ");
    helpers.printU32(process.getCount());
    shell.newLine();
}

pub fn cmdSchedEnable(_: []const u8) void {
    scheduler.enable();
    shell.printSuccessLine("Scheduler enabled");
}

pub fn cmdSchedDisable(_: []const u8) void {
    scheduler.disable();
    shell.printWarningLine("Scheduler disabled");
}
