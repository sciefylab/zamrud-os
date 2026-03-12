//! Zamrud OS - Mouse Shell Commands (B2.1 + B2.11c)

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const mouse = @import("../../drivers/input/mouse.zig");
const framebuffer = @import("../../drivers/display/framebuffer.zig");
const hid = @import("../../drivers/usb/hid.zig");
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
    } else if (helpers.strEql(parsed.cmd, "cursor")) {
        toggleCursor(parsed.rest);
    } else {
        shell.printError("mouse: unknown '");
        shell.print(parsed.cmd);
        shell.println("'. Try 'mouse help'");
    }
}

fn showHelp() void {
    shell.printInfoLine("================================================");
    shell.printInfoLine("  MOUSE - PS/2 + USB Mouse Driver (B2.1+B2.11c)");
    shell.printInfoLine("================================================");
    shell.newLine();
    shell.println("Commands:");
    shell.println("  help       Show this help");
    shell.println("  status     Show mouse state & stats");
    shell.println("  test       Run mouse driver tests (25)");
    shell.println("  watch      Watch mouse events (5s)");
    shell.println("  diag       Hardware diagnostics");
    shell.println("  cursor on  Enable framebuffer cursor");
    shell.println("  cursor off Disable framebuffer cursor");
    shell.newLine();
}

fn toggleCursor(args: []const u8) void {
    var start: usize = 0;
    while (start < args.len and args[start] == ' ') : (start += 1) {}
    const arg = args[start..];

    if (arg.len >= 2 and arg[0] == 'o' and arg[1] == 'n') {
        mouse.enableCursor();
        shell.printSuccessLine("Cursor enabled");
    } else if (arg.len >= 3 and arg[0] == 'o' and arg[1] == 'f' and arg[2] == 'f') {
        mouse.disableCursor();
        shell.printSuccessLine("Cursor disabled");
    } else {
        shell.print("  Cursor: ");
        if (mouse.isCursorEnabled()) {
            shell.printSuccessLine("VISIBLE");
        } else {
            shell.println("HIDDEN");
        }
        shell.println("  Usage: mouse cursor on|off");
    }
}

fn showStatus() void {
    shell.printInfoLine("=== Mouse Status (B2.11c) ===");

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

    // B2.11c: Cursor state
    shell.print("  Cursor:        ");
    if (stats.cursor_enabled) shell.printSuccessLine("VISIBLE") else shell.println("hidden");

    shell.newLine();
    shell.printInfoLine("=== Input Sources ===");

    shell.print("  PS/2 IRQs:     ");
    helpers.printU64(stats.irq_count);
    shell.newLine();

    shell.print("  PS/2 packets:  ");
    helpers.printU64(stats.total_packets);
    shell.newLine();

    shell.print("  USB mouse:     ");
    if (stats.usb_mouse_active) {
        shell.printSuccess("ACTIVE");
        shell.print(" (");
        helpers.printU64(stats.usb_mouse_events);
        shell.println(" events)");
    } else {
        shell.println("not detected");
    }

    shell.print("  USB tablet:    ");
    if (stats.usb_tablet_active) {
        shell.printSuccess("ACTIVE");
        shell.print(" (");
        helpers.printU64(stats.usb_tablet_events);
        shell.println(" events)");
    } else {
        shell.println("not detected");
    }

    shell.print("  Total events:  ");
    helpers.printU64(stats.total_events);
    shell.newLine();

    // HID stats
    const hid_stats = hid.getStats();
    if (hid_stats.mice > 0 or hid_stats.tablets > 0) {
        shell.newLine();
        shell.printInfoLine("=== HID Polling ===");
        shell.print("  HID mice:      ");
        helpers.printU64(hid_stats.mice);
        shell.newLine();
        shell.print("  HID tablets:   ");
        helpers.printU64(hid_stats.tablets);
        shell.newLine();
        shell.print("  Mouse polls:   ");
        helpers.printU64(hid_stats.mouse_events);
        shell.newLine();
        shell.print("  Tablet polls:  ");
        helpers.printU64(hid_stats.tablet_events);
        shell.newLine();
    }

    // PIC mask check
    shell.newLine();
    shell.printInfoLine("=== IRQ Status ===");
    shell.print("  PIC2 mask:     0x");
    helpers.printHexU8(pic.getMask2());
    shell.newLine();

    shell.print("  IRQ12 enabled: ");
    if ((pic.getMask2() & 0x10) == 0) shell.printSuccessLine("Yes") else shell.printErrorLine("No (MASKED!)");

    shell.print("  IRQ2 cascade:  ");
    if ((pic.getMask1() & 0x04) == 0) shell.printSuccessLine("Yes") else shell.printErrorLine("No (MASKED!)");

    shell.newLine();
}

fn watchMouse() void {
    shell.printInfoLine("Watching mouse for 5 seconds...");
    shell.println("Move mouse in QEMU window (click to capture)");
    shell.println("Sources: PS/2, USB Mouse, USB Tablet");
    shell.newLine();

    const start = timer.getTicks();
    var event_count: u32 = 0;
    const stats_before = mouse.getStats();

    while (timer.getTicks() - start < 5000) {
        // B2.11c: Process USB HID during watch
        hid.processPending();

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
            // Show source
            shell.print(" [");
            switch (ev.source) {
                .ps2 => shell.print("PS/2"),
                .usb_mouse => shell.print("USB-Mouse"),
                .usb_tablet => shell.print("USB-Tablet"),
            }
            shell.print("]");
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
    shell.print("  PS/2 IRQs: ");
    helpers.printU64(stats_after.irq_count - stats_before.irq_count);
    shell.newLine();
    shell.print("  USB mouse events: ");
    helpers.printU64(stats_after.usb_mouse_events - stats_before.usb_mouse_events);
    shell.newLine();
    shell.print("  USB tablet events: ");
    helpers.printU64(stats_after.usb_tablet_events - stats_before.usb_tablet_events);
    shell.newLine();

    if (stats_after.irq_count == stats_before.irq_count and
        stats_after.usb_mouse_events == stats_before.usb_mouse_events and
        stats_after.usb_tablet_events == stats_before.usb_tablet_events)
    {
        shell.printWarningLine("  No mouse input detected. Check QEMU focus/capture.");
    }
}

fn runDiag() void {
    shell.printInfoLine("=== Mouse Hardware Diagnostics (B2.11c) ===");
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

    // PS/2 status
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

    const cfg = readPS2ConfigSafe();
    if (cfg) |config| {
        shell.print("  PS/2 config:   0x");
        helpers.printHexU8(config);
        shell.newLine();
        shell.print("    KB IRQ:      ");
        if ((config & 0x01) != 0) shell.println("Enabled") else shell.println("Disabled");
        shell.print("    Mouse IRQ:   ");
        if ((config & 0x02) != 0) shell.println("Enabled") else shell.println("Disabled");
    } else {
        shell.printErrorLine("  PS/2 config: read timeout");
    }

    // USB HID diagnostics
    shell.newLine();
    shell.printInfoLine("=== USB HID Mouse/Tablet ===");
    shell.print("  HID initialized: ");
    if (hid.isInitialized()) shell.printSuccessLine("Yes") else shell.printErrorLine("No");
    shell.print("  HID mice:        ");
    helpers.printU64(hid.getMouseCount());
    shell.newLine();
    shell.print("  HID tablets:     ");
    helpers.printU64(hid.getTabletCount());
    shell.newLine();
    shell.print("  HID polling:     ");
    if (hid.isPollingEnabled()) shell.printSuccessLine("ON") else shell.printErrorLine("OFF");

    // Framebuffer cursor
    shell.newLine();
    shell.printInfoLine("=== Framebuffer Cursor ===");
    shell.print("  Framebuffer:     ");
    if (framebuffer.isInitialized()) shell.printSuccessLine("OK") else shell.printErrorLine("No");
    if (framebuffer.isInitialized()) {
        shell.print("  Resolution:      ");
        helpers.printU32(framebuffer.getWidth());
        shell.print("x");
        helpers.printU32(framebuffer.getHeight());
        shell.newLine();
    }
    shell.print("  Cursor visible:  ");
    if (mouse.isCursorEnabled()) shell.printSuccessLine("Yes") else shell.println("No");
    shell.print("  Cursor position: (");
    const cp = framebuffer.getCursorPos();
    helpers.printU32(cp.x);
    shell.print(", ");
    helpers.printU32(cp.y);
    shell.println(")");

    shell.newLine();
}

fn printMaskBit(mask: u8, bit: u3) void {
    if ((mask & (@as(u8, 1) << bit)) == 0) {
        shell.printSuccessLine("ENABLED");
    } else {
        shell.printErrorLine("MASKED");
    }
}

fn readPS2ConfigSafe() ?u8 {
    cpu.cli();
    defer cpu.sti();

    var flush_count: u32 = 0;
    while (flush_count < 16) : (flush_count += 1) {
        if ((cpu.inb(0x64) & 0x01) == 0) break;
        _ = cpu.inb(0x60);
    }

    var wait: u32 = 100000;
    while (wait > 0) : (wait -= 1) {
        if ((cpu.inb(0x64) & 0x02) == 0) break;
    }
    if (wait == 0) return null;

    cpu.outb(0x64, 0x20);

    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(0x64) & 0x01) != 0) {
            return cpu.inb(0x60);
        }
    }

    return null;
}

fn runTests() void {
    helpers.printTestHeader("MOUSE DRIVER TEST SUITE (B2.1 + B2.11c)");

    var p: u32 = 0;
    var f: u32 = 0;

    // PS/2 Driver state tests (1-7)
    shell.printInfoLine("=== PS/2 Driver State ===");
    p += helpers.doTest("Mouse initialized", mouse.isInitialized(), &f);
    p += helpers.doTest("Position X >= 0", mouse.getX() >= 0, &f);
    p += helpers.doTest("Position Y >= 0", mouse.getY() >= 0, &f);
    p += helpers.doTest("Buttons initial=0", mouse.getButtons() == 0, &f);
    p += helpers.doTest("Left not pressed", !mouse.isLeftPressed(), &f);
    p += helpers.doTest("Right not pressed", !mouse.isRightPressed(), &f);
    p += helpers.doTest("Middle not pressed", !mouse.isMiddlePressed(), &f);

    // PIC tests (8-9)
    shell.newLine();
    shell.printInfoLine("=== PIC Configuration ===");
    const m1 = pic.getMask1();
    const m2 = pic.getMask2();
    p += helpers.doTest("IRQ2 cascade unmasked", (m1 & 0x04) == 0, &f);
    p += helpers.doTest("IRQ12 mouse unmasked", (m2 & 0x10) == 0, &f);

    // PS/2 controller tests (10-11)
    shell.newLine();
    shell.printInfoLine("=== PS/2 Controller ===");
    if (readPS2ConfigSafe()) |config| {
        p += helpers.doTest("Aux IRQ enabled", (config & 0x02) != 0, &f);
        p += helpers.doTest("Aux clock enabled", (config & 0x20) == 0, &f);
    } else {
        p += helpers.doTest("Aux IRQ enabled", false, &f);
        p += helpers.doTest("Aux clock enabled", false, &f);
    }

    // Position API tests (12-17)
    shell.newLine();
    shell.printInfoLine("=== Position API ===");

    mouse.setPosition(100, 200);
    p += helpers.doTest("setPosition X", mouse.getX() == 100, &f);
    p += helpers.doTest("setPosition Y", mouse.getY() == 200, &f);

    mouse.setPosition(-50, -50);
    p += helpers.doTest("Clamp neg X", mouse.getX() == 0, &f);
    p += helpers.doTest("Clamp neg Y", mouse.getY() == 0, &f);

    mouse.setPosition(99999, 99999);
    p += helpers.doTest("Clamp max X", mouse.getX() < 99999, &f);
    p += helpers.doTest("Clamp max Y", mouse.getY() < 99999, &f);

    mouse.setPosition(512, 384);

    // Event queue tests (18-19)
    shell.newLine();
    shell.printInfoLine("=== Event Queue ===");
    p += helpers.doTest("pollEvent (none)", mouse.pollEvent() == null, &f);
    p += helpers.doTest("hasEvent = false", !mouse.hasEvent(), &f);

    // B2.11c: USB Mouse integration (20-22)
    shell.newLine();
    shell.printInfoLine("=== USB Mouse Integration (B2.11c) ===");

    // Test USB mouse event injection
    mouse.queueUsbEvent(5, -3, 0x01, 0);
    p += helpers.doTest("USB mouse event queued", mouse.hasEvent(), &f);
    if (mouse.pollEvent()) |ev| {
        p += helpers.doTest("USB mouse dx correct", ev.dx == 5, &f);
        p += helpers.doTest("USB mouse buttons", ev.buttons == 0x01, &f);
    } else {
        p += helpers.doTest("USB mouse dx correct", false, &f);
        p += helpers.doTest("USB mouse buttons", false, &f);
    }

    // B2.11c: USB Tablet integration (23-24)
    shell.newLine();
    shell.printInfoLine("=== USB Tablet Integration (B2.11c) ===");

    mouse.setUsbTabletPosition(16384, 16384, 0);
    p += helpers.doTest("Tablet position set", mouse.hasEvent(), &f);
    _ = mouse.pollEvent(); // consume

    mouse.setUsbTabletPosition(0, 0, 0x02);
    if (mouse.pollEvent()) |ev| {
        p += helpers.doTest("Tablet origin maps to 0,0", ev.x == 0 and ev.y == 0, &f);
    } else {
        p += helpers.doTest("Tablet origin maps to 0,0", false, &f);
    }

    // B2.11c: Framebuffer cursor (25)
    shell.newLine();
    shell.printInfoLine("=== Framebuffer Cursor (B2.11c) ===");

    mouse.enableCursor();
    const cursor_ok = mouse.isCursorEnabled() and framebuffer.isInitialized();
    mouse.disableCursor();
    mouse.enableCursor(); // leave enabled
    p += helpers.doTest("Cursor enable/disable", cursor_ok, &f);

    // Restore position
    mouse.setPosition(512, 384);

    helpers.printTestResults(p, f);
}
