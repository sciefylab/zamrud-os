//! Zamrud OS - Power Commands
//! System power management: reboot, shutdown, exit

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const serial = @import("../../drivers/serial/serial.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const timer = @import("../../drivers/timer/timer.zig");
const cpu = @import("../../core/cpu.zig");

// =============================================================================
// Command Entry Points
// =============================================================================

/// Reboot the system
pub fn reboot() void {
    shell.printWarningLine("========================================");
    shell.printWarningLine("  SYSTEM REBOOT");
    shell.printWarningLine("========================================");
    shell.newLine();

    shell.println("  Preparing for reboot...");
    shell.newLine();

    // Give user time to see message
    shell.println("  Syncing filesystems...");
    timer.sleep(500);

    shell.println("  Stopping services...");
    timer.sleep(500);

    shell.println("  Rebooting in 1 second...");
    timer.sleep(1000);

    serial.writeString("\n[REBOOT] System rebooting...\n");

    // Method 1: Triple fault via invalid IDT
    cpu.cli();

    // Load null IDT to cause triple fault
    asm volatile (
        \\lidt (%%rax)
        :
        : [null_idt] "{rax}" (@as(u64, 0)),
    );

    // Trigger interrupt with null IDT
    asm volatile ("int $0");

    // Method 2: Keyboard controller reset (fallback)
    // Port 0x64 command 0xFE triggers CPU reset
    asm volatile (
        \\mov $0xFE, %%al
        \\out %%al, $0x64
    );

    // If we're still here, halt
    cpu.halt();
}

/// Shutdown/halt the system
pub fn shutdown() void {
    shell.printWarningLine("========================================");
    shell.printWarningLine("  SYSTEM SHUTDOWN");
    shell.printWarningLine("========================================");
    shell.newLine();

    shell.println("  Preparing for shutdown...");
    shell.newLine();

    // Give user time to see message
    shell.println("  Syncing filesystems...");
    timer.sleep(500);

    shell.println("  Stopping services...");
    timer.sleep(500);

    shell.println("  Halting system...");
    timer.sleep(500);

    serial.writeString("\n[SHUTDOWN] System halted.\n");

    // Clear screen and show final message
    if (terminal.isInitialized()) {
        terminal.setColors(terminal.Colors.WHITE, terminal.Colors.BLACK);
        terminal.clear();

        // Center the message
        const msg1 = "Zamrud OS";
        const msg2 = "System halted.";
        const msg3 = "It is now safe to turn off your computer.";

        const height = terminal.getHeight();
        const width = terminal.getWidth();

        // Cast lengths to u32 for setCursor
        const msg1_len: u32 = @intCast(msg1.len);
        const msg2_len: u32 = @intCast(msg2.len);
        const msg3_len: u32 = @intCast(msg3.len);

        terminal.setCursor((width - msg1_len) / 2, height / 2 - 2);
        terminal.setFgColor(terminal.Colors.INFO);
        terminal.println(msg1);

        terminal.setCursor((width - msg2_len) / 2, height / 2);
        terminal.setFgColor(terminal.Colors.SUCCESS);
        terminal.println(msg2);

        terminal.setCursor((width - msg3_len) / 2, height / 2 + 2);
        terminal.setFgColor(terminal.Colors.FG_DEFAULT);
        terminal.println(msg3);
    }

    // Disable interrupts and halt
    cpu.cli();

    // Try ACPI shutdown if available (simplified)
    // Real implementation would use ACPI tables

    // Halt the CPU
    while (true) {
        cpu.halt();
    }
}

/// Exit the shell (returns to caller or halts)
pub fn exit() void {
    shell.printInfoLine("Exiting shell...");
    serial.writeString("[EXIT] Shell exit requested\n");

    // Signal shell to stop
    shell.stop();
}

/// Power management help
pub fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  POWER MANAGEMENT");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  reboot    Restart the system");
    shell.println("  shutdown  Power off / halt the system");
    shell.println("  halt      Same as shutdown");
    shell.println("  exit      Exit the shell");
    shell.newLine();

    shell.println("Notes:");
    shell.println("  - Reboot performs a CPU reset");
    shell.println("  - Shutdown halts the CPU");
    shell.println("  - On VM, shutdown may just halt");
    shell.println("  - Exit returns control to kernel");
    shell.newLine();
}

/// Handle power-related subcommands (for extensibility)
pub fn execute(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        showHelp();
    } else if (helpers.strEql(trimmed, "status")) {
        showPowerStatus();
    } else if (helpers.strEql(trimmed, "sleep")) {
        // Future: implement sleep mode
        shell.printWarningLine("Sleep mode not yet implemented");
    } else {
        shell.printError("power: unknown subcommand '");
        shell.print(trimmed);
        shell.println("'");
    }
}

fn showPowerStatus() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  POWER STATUS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("  Power Source:   Unknown (no ACPI)");
    shell.println("  Battery:        N/A");
    shell.println("  CPU State:      Running");
    shell.println("  Thermal:        Unknown");
    shell.newLine();

    shell.print("  Uptime:         ");
    helpers.printUsize(timer.getSeconds());
    shell.println(" seconds");

    shell.print("  Timer Ticks:    ");
    helpers.printUsize(@intCast(timer.getTicks() & 0xFFFFFFFF));
    shell.newLine();

    shell.newLine();
}
