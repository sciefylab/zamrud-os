//! Zamrud OS - Power Commands
//! System power management: reboot, shutdown, exit
//! Now with ACPI support!

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const serial = @import("../../drivers/serial/serial.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const timer = @import("../../drivers/timer/timer.zig");
const cpu = @import("../../core/cpu.zig");
const acpi = @import("../../drivers/acpi/acpi.zig");

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

    // Show which method will be used
    if (acpi.isACPIEnabled()) {
        shell.println("  Using ACPI reset register...");
    } else {
        shell.println("  Using keyboard controller reset...");
    }
    timer.sleep(500);

    shell.println("  Rebooting in 1 second...");
    timer.sleep(1000);

    serial.writeString("\n[REBOOT] System rebooting...\n");

    // Disable interrupts
    cpu.cli();

    // Use ACPI reboot
    acpi.reboot();

    // Should not reach here
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

    // Show which method will be used
    if (acpi.isACPIEnabled()) {
        shell.println("  Using ACPI S5 sleep state...");
    } else {
        shell.println("  Using QEMU shutdown port...");
    }
    timer.sleep(500);

    shell.println("  Halting system...");
    timer.sleep(500);

    serial.writeString("\n[SHUTDOWN] System halted.\n");

    // Clear screen and show final message
    if (terminal.isInitialized()) {
        terminal.setColors(terminal.Colors.WHITE, terminal.Colors.BLACK);
        terminal.clear();

        const msg1 = "Zamrud OS";
        const msg2 = "System halted.";
        const msg3 = "It is now safe to turn off your computer.";

        const height = terminal.getHeight();
        const width = terminal.getWidth();

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

    // Disable interrupts
    cpu.cli();

    // Use ACPI shutdown
    acpi.shutdown();

    // Should not reach here, but halt anyway
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

    shell.println("ACPI Status:");
    if (acpi.isACPIEnabled()) {
        shell.printSuccessLine("  ACPI: Enabled");
        shell.print("  Revision: ");
        if (acpi.getRevision() == 0) {
            shell.println("1.0");
        } else {
            shell.println("2.0+");
        }
        shell.print("  Tables found: ");
        helpers.printUsize(acpi.getTablesFound());
        shell.newLine();
    } else {
        shell.printWarningLine("  ACPI: Not available (using fallback)");
    }
    shell.newLine();

    shell.println("Notes:");
    shell.println("  - Shutdown uses ACPI S5 state (if available)");
    shell.println("  - Reboot uses ACPI reset register (if available)");
    shell.println("  - Falls back to keyboard controller / QEMU ports");
    shell.newLine();
}

/// Handle power-related subcommands
pub fn execute(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "help")) {
        showHelp();
    } else if (helpers.strEql(trimmed, "status")) {
        showPowerStatus();
    } else if (helpers.strEql(trimmed, "acpi")) {
        showACPIInfo();
    } else if (helpers.strEql(trimmed, "sleep")) {
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

    if (acpi.isACPIEnabled()) {
        shell.println("  Power Source:   ACPI");
    } else {
        shell.println("  Power Source:   Unknown (no ACPI)");
    }
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

fn showACPIInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  ACPI INFORMATION");
    shell.printInfoLine("========================================");
    shell.newLine();

    if (!acpi.isInitialized()) {
        shell.printWarningLine("  ACPI not initialized");
        return;
    }

    shell.print("  Initialized:    ");
    if (acpi.isACPIEnabled()) {
        shell.printSuccessLine("Yes");
    } else {
        shell.printWarningLine("No (fallback mode)");
    }

    shell.print("  ACPI Revision:  ");
    if (acpi.getRevision() == 0) {
        shell.println("1.0");
    } else {
        shell.println("2.0+");
    }

    shell.print("  Tables Found:   ");
    helpers.printUsize(acpi.getTablesFound());
    shell.newLine();

    shell.print("  PM1a_CNT:       0x");
    helpers.printHex32(acpi.getPM1aControlBlock());
    shell.newLine();

    shell.print("  SLP_TYPa:       ");
    helpers.printUsize(acpi.getSleepTypeA());
    shell.newLine();

    shell.newLine();
    shell.println("  Shutdown: Uses ACPI S5 state");
    shell.println("  Reboot:   Uses ACPI reset register");
    shell.newLine();
}
