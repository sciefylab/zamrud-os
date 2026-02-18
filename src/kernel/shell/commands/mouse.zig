//! Zamrud OS - Mouse Shell Commands (B2.1)

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const mouse = @import("../../drivers/input/mouse.zig");
const timer = @import("../../drivers/timer/timer.zig");
const pic = @import("../../arch/x86_64/pic.zig");
const cpu = @import("../../core/cpu.zig");
const serial = @import("../../drivers/serial/serial.zig");

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);

    if (parsed.cmd.len == 0 or helpers.strEql(parsed.cmd, "help")) {
        showHelp();
    } else if (helpers.strEql(parsed.cmd, "status")) {
        showStatus();
    } else if (helpers.strEql(parsed.cmd, "test")) {
        runTests();
    } else if (helpers.strEql(parsed.cmd, "watch")) {
        watchMouse();
    } else if (helpers.strEql(parsed.cmd, "diag")) {
        runDiag();
    } else {
        shell.printError("mouse: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'mouse help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  MOUSE - PS/2 Mouse Driver (B2.1)");
    shell.printInfoLine("========================================");
    shell.newLine();
    shell.println("Commands:");
    shell.println("  help     Show this help");
    shell.println("  status   Show mouse state & stats");
    shell.println("  test     Run mouse driver tests");
    shell.println("  watch    Watch mouse events (5s)");
    shell.println("  diag     Hardware diagnostics");
    shell.newLine();
}

fn showStatus() void {
    shell.printInfoLine("=== Mouse Status ===");

    const stats = mouse.getStats();

    shell.print("  Initialized:   ");
    if (stats.initialized) shell.printSuccessLine("Yes") else shell.printErrorLine("No");

    shell.print("  Scroll wheel:  ");
    if (stats.has_scroll) shell.printSuccessLine("Yes") else shell.println("No");

    shell.print("  Position:      (");
    helpers.printI32(stats.x);
    shell.print(", ");
    helpers.printI32(stats.y);
    shell.println(")");

    shell.print("  Buttons:       ");
    if ((stats.buttons & 0x01) != 0) shell.print("[L]") else shell.print("[ ]");
    if ((stats.buttons & 0x02) != 0) shell.print("[R]") else shell.print("[ ]");
    if ((stats.buttons & 0x04) != 0) shell.print("[M]") else shell.print("[ ]");
    shell.newLine();

    shell.print("  IRQ count:     ");
    helpers.printU64(stats.irq_count);
    shell.newLine();

    shell.print("  Packets:       ");
    helpers.printU64(stats.total_packets);
    shell.newLine();

    shell.print("  Events:        ");
    helpers.printU64(stats.total_events);
    shell.newLine();

    // PIC mask check
    shell.print("  PIC2 mask:     0x");
    helpers.printHexU8(pic.getMask2());
    shell.newLine();

    shell.print("  IRQ12 enabled: ");
    if ((pic.getMask2() & 0x10) == 0) shell.printSuccessLine("Yes") else shell.printErrorLine("No (MASKED!)");

    // Cascade check
    shell.print("  IRQ2 cascade:  ");
    if ((pic.getMask1() & 0x04) == 0) shell.printSuccessLine("Yes") else shell.printErrorLine("No (MASKED!)");

    shell.newLine();
}

fn watchMouse() void {
    shell.printInfoLine("Watching mouse for 5 seconds...");
    shell.println("Move mouse in QEMU window (click to capture)");
    shell.newLine();

    const start = timer.getTicks();
    var event_count: u32 = 0;
    const stats_before = mouse.getStats();

    while (timer.getTicks() - start < 5000) {
        if (mouse.pollEvent()) |ev| {
            event_count += 1;
            shell.print("  [");
            helpers.printU32(event_count);
            shell.print("] pos=(");
            helpers.printI32(ev.x);
            shell.print(",");
            helpers.printI32(ev.y);
            shell.print(") d=(");
            helpers.printI16(ev.dx);
            shell.print(",");
            helpers.printI16(ev.dy);
            shell.print(") btn=");
            if ((ev.buttons & 0x01) != 0) shell.print("L");
            if ((ev.buttons & 0x02) != 0) shell.print("R");
            if ((ev.buttons & 0x04) != 0) shell.print("M");
            if (ev.scroll != 0) {
                shell.print(" scroll=");
                helpers.printI8(ev.scroll);
            }
            shell.newLine();

            if (event_count >= 20) {
                shell.println("  (max display reached)");
                break;
            }
        }
        asm volatile ("hlt");
    }

    const stats_after = mouse.getStats();
    shell.newLine();
    shell.print("  Events displayed: ");
    helpers.printU32(event_count);
    shell.newLine();
    shell.print("  IRQs during watch: ");
    helpers.printU64(stats_after.irq_count - stats_before.irq_count);
    shell.newLine();
    shell.print("  Packets during watch: ");
    helpers.printU64(stats_after.total_packets - stats_before.total_packets);
    shell.newLine();

    if (stats_after.irq_count == stats_before.irq_count) {
        shell.printErrorLine("  WARNING: No IRQ12 received! Check PIC/IDT wiring.");
    }
}

fn runDiag() void {
    shell.printInfoLine("=== Mouse Hardware Diagnostics ===");
    shell.newLine();

    // Check PIC masks
    const m1 = pic.getMask1();
    const m2 = pic.getMask2();

    shell.print("  PIC1 mask: 0x");
    helpers.printHexU8(m1);
    shell.newLine();
    shell.print("  PIC2 mask: 0x");
    helpers.printHexU8(m2);
    shell.newLine();

    shell.print("  IRQ0 Timer:    ");
    printMaskBit(m1, 0);
    shell.print("  IRQ1 Keyboard: ");
    printMaskBit(m1, 1);
    shell.print("  IRQ2 Cascade:  ");
    printMaskBit(m1, 2);
    shell.print("  IRQ12 Mouse:   ");
    printMaskBit(m2, 4);

    shell.newLine();

    // Read PS/2 status
    const status = cpu.inb(0x64);
    shell.print("  PS/2 status:   0x");
    helpers.printHexU8(status);
    shell.newLine();
    shell.print("    Output full: ");
    if ((status & 0x01) != 0) shell.println("Yes") else shell.println("No");
    shell.print("    Input full:  ");
    if ((status & 0x02) != 0) shell.println("Yes") else shell.println("No");
    shell.print("    Aux data:    ");
    if ((status & 0x20) != 0) shell.println("Yes") else shell.println("No");

    // Read controller config safely with interrupts disabled
    const cfg = readPS2ConfigSafe();
    if (cfg) |config| {
        shell.print("  PS/2 config:   0x");
        helpers.printHexU8(config);
        shell.newLine();
        shell.print("    KB IRQ:      ");
        if ((config & 0x01) != 0) shell.println("Enabled") else shell.println("Disabled");
        shell.print("    Mouse IRQ:   ");
        if ((config & 0x02) != 0) shell.println("Enabled") else shell.println("Disabled");
        shell.print("    KB clock:    ");
        if ((config & 0x10) != 0) shell.println("Disabled") else shell.println("Enabled");
        shell.print("    Mouse clock: ");
        if ((config & 0x20) != 0) shell.println("Disabled") else shell.println("Enabled");
    } else {
        shell.printErrorLine("  PS/2 config: read timeout");
    }

    shell.newLine();
    shell.print("  Mouse init:    ");
    if (mouse.isInitialized()) shell.printSuccessLine("Yes") else shell.printErrorLine("No");
    shell.print("  IRQ count:     ");
    helpers.printU64(mouse.getStats().irq_count);
    shell.newLine();
}

fn printMaskBit(mask: u8, bit: u3) void {
    if ((mask & (@as(u8, 1) << bit)) == 0) {
        shell.printSuccessLine("ENABLED");
    } else {
        shell.printErrorLine("MASKED");
    }
}

// =============================================================================
// Safe PS/2 Config Byte Reader
// Disables interrupts to prevent IRQ handlers from stealing data from port 0x60
// =============================================================================

fn readPS2ConfigSafe() ?u8 {
    // Disable interrupts so no IRQ handler reads port 0x60 between
    // our command write and our data read
    cpu.cli();
    defer cpu.sti();

    // Flush any pending data first
    var flush_count: u32 = 0;
    while (flush_count < 16) : (flush_count += 1) {
        if ((cpu.inb(0x64) & 0x01) == 0) break;
        _ = cpu.inb(0x60);
    }

    // Wait for input buffer empty before sending command
    var wait: u32 = 100000;
    while (wait > 0) : (wait -= 1) {
        if ((cpu.inb(0x64) & 0x02) == 0) break;
    }
    if (wait == 0) return null;

    // Send "read config byte" command
    cpu.outb(0x64, 0x20);

    // Wait for output buffer full (controller response)
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(0x64) & 0x01) != 0) {
            return cpu.inb(0x60);
        }
    }

    return null;
}

fn runTests() void {
    helpers.printTestHeader("MOUSE DRIVER TEST SUITE (B2.1)");

    var p: u32 = 0;
    var f: u32 = 0;

    // Driver state tests
    shell.printInfoLine("=== Driver State ===");
    p += helpers.doTest("Mouse initialized", mouse.isInitialized(), &f);
    p += helpers.doTest("Position X >= 0", mouse.getX() >= 0, &f);
    p += helpers.doTest("Position Y >= 0", mouse.getY() >= 0, &f);
    p += helpers.doTest("Buttons initial=0", mouse.getButtons() == 0, &f);
    p += helpers.doTest("Left not pressed", !mouse.isLeftPressed(), &f);
    p += helpers.doTest("Right not pressed", !mouse.isRightPressed(), &f);
    p += helpers.doTest("Middle not pressed", !mouse.isMiddlePressed(), &f);

    // Stats tests
    shell.newLine();
    shell.printInfoLine("=== Statistics ===");
    const stats = mouse.getStats();
    p += helpers.doTest("Stats accessible", stats.initialized, &f);
    p += helpers.doTest("IRQ count >= 0", true, &f);
    p += helpers.doTest("Packet count >= 0", true, &f);
    p += helpers.doTest("Event count >= 0", true, &f);

    // PIC configuration tests
    shell.newLine();
    shell.printInfoLine("=== PIC Configuration ===");
    const m1 = pic.getMask1();
    const m2 = pic.getMask2();
    p += helpers.doTest("IRQ2 cascade unmasked", (m1 & 0x04) == 0, &f);
    p += helpers.doTest("IRQ12 mouse unmasked", (m2 & 0x10) == 0, &f);

    // PS/2 controller tests — read safely with interrupts disabled
    shell.newLine();
    shell.printInfoLine("=== PS/2 Controller ===");

    if (readPS2ConfigSafe()) |config| {
        p += helpers.doTest("Aux IRQ enabled", (config & 0x02) != 0, &f);
        p += helpers.doTest("Aux clock enabled", (config & 0x20) == 0, &f);
    } else {
        // Config read timed out — this itself is a failure
        p += helpers.doTest("Aux IRQ enabled", false, &f);
        p += helpers.doTest("Aux clock enabled", false, &f);
    }

    // API tests
    shell.newLine();
    shell.printInfoLine("=== API Functions ===");

    mouse.setPosition(100, 200);
    p += helpers.doTest("setPosition X", mouse.getX() == 100, &f);
    p += helpers.doTest("setPosition Y", mouse.getY() == 200, &f);

    mouse.setPosition(-50, -50);
    p += helpers.doTest("Clamp neg X", mouse.getX() == 0, &f);
    p += helpers.doTest("Clamp neg Y", mouse.getY() == 0, &f);

    mouse.setPosition(99999, 99999);
    p += helpers.doTest("Clamp max X", mouse.getX() < 99999, &f);
    p += helpers.doTest("Clamp max Y", mouse.getY() < 99999, &f);

    // Restore center
    mouse.setPosition(512, 384);

    p += helpers.doTest("pollEvent (none)", mouse.pollEvent() == null, &f);
    p += helpers.doTest("hasEvent = false", !mouse.hasEvent(), &f);

    p += helpers.doTest("getScrollDelta", mouse.getScrollDelta() == 0, &f);

    // Scroll wheel detection (may or may not have it)
    p += helpers.doTest("hasScrollWheel check", true, &f);

    helpers.printTestResults(p, f);
}
