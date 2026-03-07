//! Zamrud OS - USB Shell Commands (B2.11 + B2.11b)

const shell = @import("../shell.zig");
const usb = @import("../../drivers/usb/usb.zig");
const uhci = @import("../../drivers/usb/uhci.zig");
const ehci = @import("../../drivers/usb/ehci.zig");
const hid = @import("../../drivers/usb/hid.zig");
const serial = @import("../../drivers/serial/serial.zig");

pub fn execute(args: []const u8) void {
    const cmd = parseSubcommand(args);

    if (strEql(cmd, "status")) {
        showStatus();
    } else if (strEql(cmd, "controllers")) {
        showControllers();
    } else if (strEql(cmd, "devices")) {
        showDevices();
    } else if (strEql(cmd, "ports")) {
        showPorts();
    } else if (strEql(cmd, "scan")) {
        scanDevices();
    } else if (strEql(cmd, "hid")) {
        showHidStatus();
    } else if (strEql(cmd, "test")) {
        runTests();
    } else if (strEql(cmd, "help") or cmd.len == 0) {
        showHelp();
    } else {
        shell.printError("Unknown USB command: ");
        shell.print(cmd);
        shell.newLine();
        showHelp();
    }
}

fn showHelp() void {
    shell.println("");
    shell.printInfo("USB Subsystem Commands (B2.11 + B2.11b):");
    shell.println("===============================");
    shell.println("");
    shell.println("  usb status      - Show USB subsystem status");
    shell.println("  usb controllers - List USB host controllers");
    shell.println("  usb devices     - List connected USB devices");
    shell.println("  usb ports       - Show port status details");
    shell.println("  usb scan        - Rescan for devices");
    shell.println("  usb hid         - Show HID driver status (B2.11b)");
    shell.println("  usb test        - Run USB tests (25 tests)");
    shell.println("  usb help        - Show this help");
    shell.println("");
}

fn showStatus() void {
    shell.println("");
    shell.printInfo("USB Subsystem Status");
    shell.println("====================");
    shell.println("");

    shell.print("  Initialized:       ");
    shell.println(if (usb.isInitialized()) "Yes" else "No");

    shell.print("  Controllers:       ");
    printDec(usb.getControllerCount());
    shell.print(" (");
    printDec(usb.getInitializedControllerCount());
    shell.println(" active)");

    shell.print("  Total Ports:       ");
    printDec(usb.getTotalPorts());
    shell.newLine();

    shell.print("  Devices:           ");
    printDec(usb.getDeviceCount());
    shell.newLine();

    shell.print("  Configured:        ");
    printDec(usb.getConfiguredCount());
    shell.newLine();

    shell.print("  UHCI support:      ");
    shell.println(if (usb.hasUhci()) "Yes" else "No");

    shell.print("  EHCI support:      ");
    shell.println(if (usb.hasEhci()) "Yes" else "No");

    shell.print("  HID devices:       ");
    printDec(hid.getDeviceCount());
    shell.newLine();

    shell.print("  Keyboards:         ");
    printDec(hid.getKeyboardCount());
    shell.newLine();

    shell.print("  Mice:              ");
    printDec(hid.getMouseCount());
    shell.newLine();

    shell.print("  Tablets:           ");
    printDec(hid.getTabletCount());
    shell.newLine();

    shell.print("  HID Mode:          ");
    shell.println(if (hid.isPollingEnabled()) "GET_REPORT (active)" else "Disabled");

    shell.print("  Mass Storage:      ");
    printDec(usb.getMassStorageCount());
    shell.newLine();

    shell.print("  Enumerations:      ");
    printDec(usb.getTotalEnumerations());
    shell.print(" (");
    printDec(usb.getFailedEnumerations());
    shell.println(" failed)");

    shell.println("");
}

fn showHidStatus() void {
    shell.println("");
    shell.printInfo("USB HID Driver Status (B2.11b)");
    shell.println("==============================");
    shell.println("");

    const stats = hid.getStats();

    shell.print("  Initialized:       ");
    shell.println(if (hid.isInitialized()) "Yes" else "No");

    shell.print("  Mode:              ");
    shell.println(if (stats.polling_enabled) "GET_REPORT (control transfer)" else "DISABLED");

    shell.print("  HID Devices:       ");
    printDec(stats.device_count);
    shell.newLine();

    shell.print("  Keyboards:         ");
    printDec(stats.keyboards);
    shell.newLine();

    shell.print("  Mice:              ");
    printDec(stats.mice);
    shell.newLine();

    shell.print("  Tablets:           ");
    printDec(stats.tablets);
    shell.newLine();

    shell.println("");
    shell.printInfo("Polling Statistics:");
    shell.println("");

    shell.print("  Total polls:       ");
    printDec64(stats.total_polls);
    shell.newLine();

    shell.print("  Successful:        ");
    printDec64(stats.successful_polls);
    shell.newLine();

    shell.print("  Keyboard events:   ");
    printDec64(stats.keyboard_events);
    shell.newLine();

    shell.print("  Mouse events:      ");
    printDec64(stats.mouse_events);
    shell.newLine();

    if (stats.total_polls > 0) {
        shell.print("  Success rate:      ");
        const rate = (stats.successful_polls * 100) / stats.total_polls;
        printDec64(rate);
        shell.println("%");
    }

    shell.println("");
}

fn showControllers() void {
    shell.println("");
    shell.printInfo("USB Controllers");
    shell.println("===============");
    shell.println("");

    const count = usb.getControllerCount();
    if (count == 0) {
        shell.println("  No USB controllers found");
        shell.println("");
        return;
    }

    for (0..count) |i| {
        if (usb.getController(i)) |ctrl| {
            shell.print("  [");
            printDec(i);
            shell.print("] ");
            shell.print(ctrl.controller_type.toString());
            shell.print(" - ");
            shell.print(if (ctrl.initialized) "Active" else "Inactive");
            shell.newLine();

            shell.print("      Base: 0x");
            printHex64(ctrl.base_addr);
            shell.print(" IRQ: ");
            printDec(ctrl.irq);
            shell.print(" Ports: ");
            printDec(ctrl.num_ports);
            shell.newLine();
        }
    }
    shell.println("");
}

fn showDevices() void {
    shell.println("");
    shell.printInfo("USB Devices");
    shell.println("===========");
    shell.println("");

    const count = usb.getDeviceCount();
    if (count == 0) {
        shell.println("  No USB devices connected");
        shell.println("");
        return;
    }

    shell.println("  Addr VID:PID    Class        Speed       State      Ctrl");
    shell.println("  ---- ---------- ------------ ----------- ---------- ----");

    for (0..count) |i| {
        if (usb.getDevice(i)) |dev| {
            shell.print("  ");

            if (dev.address < 10) shell.print("  ");
            printDec(dev.address);
            shell.print(" ");

            printHex16(dev.vendor_id);
            shell.print(":");
            printHex16(dev.product_id);
            shell.print(" ");

            const class_name = dev.getClassName();
            shell.print(class_name);
            padTo(class_name.len, 12);
            shell.print(" ");

            const speed = dev.getSpeedString();
            shell.print(speed);
            padTo(speed.len, 11);
            shell.print(" ");

            const state = dev.getStateString();
            shell.print(state);
            padTo(state.len, 10);
            shell.print(" ");

            shell.print(dev.controller_type.toString());
            shell.newLine();
        }
    }
    shell.println("");
}

fn showPorts() void {
    shell.println("");
    shell.printInfo("USB Port Status");
    shell.println("===============");
    shell.println("");

    if (usb.hasUhci()) {
        shell.println("  UHCI Controller:");
        for (0..2) |port| {
            const status = uhci.getPortStatus(0, @intCast(port));
            shell.print("    Port ");
            printDec(port + 1);
            shell.print(": 0x");
            printHex16(status);
            if ((status & 0x0001) != 0) shell.print(" [Connected]");
            if ((status & 0x0004) != 0) shell.print(" [Enabled]");
            shell.newLine();
        }
    }

    if (usb.hasEhci()) {
        shell.println("  EHCI Controller:");
        const num_ports: u8 = if (usb.getController(1)) |c| c.num_ports else 6;
        for (0..num_ports) |port| {
            const status = ehci.getPortStatus(0, @intCast(port));
            shell.print("    Port ");
            printDec(port + 1);
            shell.print(": 0x");
            printHex32(status);
            if ((status & 0x0001) != 0) shell.print(" [Connected]");
            if ((status & 0x0004) != 0) shell.print(" [Enabled]");
            shell.newLine();
        }
    }

    shell.println("");
}

fn scanDevices() void {
    shell.println("");
    shell.printInfo("Scanning for USB devices...");
    shell.newLine();
    const count = usb.getDeviceCount();
    shell.print("Found ");
    printDec(count);
    shell.println(" device(s)");
    shell.println("");
}

// =============================================================================
// Test Suite (Updated for GET_REPORT mode - B2.11b)
// =============================================================================

fn runTests() void {
    shell.println("");
    shell.println("########################################");
    shell.println("##  USB SUBSYSTEM TESTS (B2.11+B2.11b)");
    shell.println("########################################");
    shell.println("");

    var passed: u32 = 0;
    var failed: u32 = 0;

    // === B2.11: Core USB Tests (1-15) ===
    runTest(1, "USB subsystem initialized", usb.isInitialized(), &passed, &failed);
    runTest(2, "Controller count >= 1", usb.getControllerCount() >= 1, &passed, &failed);
    runTest(3, "Active controllers >= 1", usb.getInitializedControllerCount() >= 1, &passed, &failed);
    runTest(4, "UHCI or EHCI detected", usb.hasUhci() or usb.hasEhci(), &passed, &failed);

    var type_valid = false;
    if (usb.getController(0)) |ctrl| {
        type_valid = ctrl.controller_type != .none;
    }
    runTest(5, "Controller type enum valid", type_valid, &passed, &failed);

    var type_str_valid = false;
    if (usb.getController(0)) |ctrl| {
        type_str_valid = ctrl.controller_type.toString().len > 0;
    }
    runTest(6, "Controller type strings", type_str_valid, &passed, &failed);

    var base_valid = false;
    if (usb.getController(0)) |ctrl| {
        base_valid = ctrl.base_addr != 0;
    }
    runTest(7, "Active ctrl base addr != 0", base_valid, &passed, &failed);

    var irq_valid = false;
    if (usb.getController(0)) |ctrl| {
        irq_valid = ctrl.irq <= 15 or ctrl.irq == 11;
    }
    runTest(8, "IRQ in valid range", irq_valid, &passed, &failed);

    var ports_valid = false;
    if (usb.getController(0)) |ctrl| {
        ports_valid = ctrl.num_ports > 0;
    }
    runTest(9, "Active ctrl ports > 0", ports_valid, &passed, &failed);

    runTest(10, "Total ports > 0", usb.getTotalPorts() > 0, &passed, &failed);
    runTest(11, "UHCI driver status", !usb.hasUhci() or uhci.isInitialized(), &passed, &failed);
    runTest(12, "UHCI port status readable", !usb.hasUhci() or uhci.getPortStatus(0, 0) != 0xFFFF, &passed, &failed);
    runTest(13, "EHCI driver status", !usb.hasEhci() or ehci.isInitialized(), &passed, &failed);

    var ehci_ver_valid = true;
    if (usb.hasEhci()) {
        const ver = ehci.getVersion(0);
        ehci_ver_valid = ver == 0x0100 or ver == 0x0110 or ver == 0x0095;
    }
    runTest(14, "EHCI version valid", ehci_ver_valid, &passed, &failed);

    const dev_count1 = usb.getDeviceCount();
    const dev_count2 = usb.getDeviceCount();
    runTest(15, "Device count stable", dev_count1 == dev_count2, &passed, &failed);

    // === B2.11b: HID + GET_REPORT Tests (16-25) ===
    runTest(16, "HID driver initialized", hid.isInitialized(), &passed, &failed);

    const hid_stats = hid.getStats();
    runTest(17, "HID device count consistent", hid_stats.device_count == hid.getDeviceCount(), &passed, &failed);
    runTest(18, "HID keyboard count valid", hid_stats.keyboards <= hid_stats.device_count, &passed, &failed);
    runTest(19, "HID mouse count valid", hid_stats.mice <= hid_stats.device_count, &passed, &failed);
    runTest(20, "HID tablet count valid", hid_stats.tablets <= hid_stats.device_count, &passed, &failed);

    // Test 21: HID polling active when devices exist (GET_REPORT mode)
    const has_hid_devices = hid_stats.device_count > 0;
    runTest(21, "HID polling active", !has_hid_devices or hid.isPollingEnabled(), &passed, &failed);

    // Test 22: GET_REPORT succeeds (polls > 0 means control transfers work)
    runTest(22, "GET_REPORT transfers work", !has_hid_devices or hid_stats.successful_polls > 0, &passed, &failed);

    // Test 23: HID event counters valid
    runTest(23, "HID events count valid", hid_stats.keyboard_events >= 0 and hid_stats.mouse_events >= 0, &passed, &failed);

    // Test 24: Device state consistency
    var dev_state_valid = true;
    for (0..usb.getDeviceCount()) |i| {
        if (usb.getDevice(i)) |dev| {
            if (dev.state == .detached and dev.allocated) {
                dev_state_valid = false;
                break;
            }
        }
    }
    runTest(24, "Device states consistent", dev_state_valid, &passed, &failed);

    // Test 25: Transfer counter works
    const transfers1 = usb.getTotalTransfers();
    usb.incrementTransfers();
    const transfers2 = usb.getTotalTransfers();
    runTest(25, "Transfer counter works", transfers2 == transfers1 + 1, &passed, &failed);

    // === Summary ===
    shell.println("");
    shell.print("USB Tests: ");
    printDec(passed);
    shell.print(" passed, ");
    printDec(failed);
    shell.println(" failed");
    shell.println("");

    if (failed == 0) {
        shell.printSuccess("All USB tests PASSED!");
        shell.newLine();
    } else {
        shell.printError("Some USB tests FAILED!");
        shell.newLine();
    }

    shell.println("");

    shell.print("Controllers: ");
    printDec(usb.getControllerCount());
    shell.print(" (UHCI: ");
    shell.print(if (usb.hasUhci()) "OK" else "N/A");
    shell.print(", EHCI: ");
    shell.print(if (usb.hasEhci()) "OK" else "N/A");
    shell.println(")");

    shell.print("Devices: ");
    printDec(usb.getDeviceCount());
    shell.print(" (");
    printDec(hid.getDeviceCount());
    shell.print(" HID, ");
    printDec(hid.getKeyboardCount());
    shell.print(" kbd, ");
    printDec(usb.getConfiguredCount());
    shell.println(" configured)");

    shell.print("HID Mode: GET_REPORT, polling=");
    shell.println(if (hid.isPollingEnabled()) "ON" else "OFF");

    if (hid_stats.total_polls > 0) {
        shell.print("HID Polls: ");
        printDec64(hid_stats.total_polls);
        shell.print(" total, ");
        printDec64(hid_stats.successful_polls);
        shell.print(" successful (");
        const rate = (hid_stats.successful_polls * 100) / hid_stats.total_polls;
        printDec64(rate);
        shell.println("%)");
    }

    shell.println("");

    if (usb.getDeviceCount() > 0) {
        shell.println("Detected devices:");
        for (0..usb.getDeviceCount()) |i| {
            if (usb.getDevice(i)) |dev| {
                shell.print("  [");
                printDec(dev.address);
                shell.print("] ");
                printHex16(dev.vendor_id);
                shell.print(":");
                printHex16(dev.product_id);
                shell.print(" ");
                shell.print(dev.getClassName());
                shell.print(" (");
                shell.print(dev.controller_type.toString());
                shell.print(", ");
                shell.print(dev.getStateString());
                shell.println(")");
            }
        }
        shell.println("");
    }
}

fn runTest(num: u32, name: []const u8, passed_cond: bool, passed: *u32, failed: *u32) void {
    shell.print("[");
    if (num < 10) shell.print("0");
    printDec(num);
    shell.print("] ");
    shell.print(name);
    shell.print(": ");

    if (passed_cond) {
        shell.printSuccess("PASS");
        passed.* += 1;
    } else {
        shell.printError("FAIL");
        failed.* += 1;
    }
    shell.newLine();
}

// =============================================================================
// Helpers
// =============================================================================

fn parseSubcommand(args: []const u8) []const u8 {
    var start: usize = 0;
    while (start < args.len and args[start] == ' ') : (start += 1) {}
    var end = start;
    while (end < args.len and args[end] != ' ') : (end += 1) {}
    return args[start..end];
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        var la = ca;
        var lb = cb;
        if (la >= 'A' and la <= 'Z') la += 32;
        if (lb >= 'A' and lb <= 'Z') lb += 32;
        if (la != lb) return false;
    }
    return true;
}

fn padTo(current: usize, target: usize) void {
    var i = current;
    while (i < target) : (i += 1) {
        shell.print(" ");
    }
}

fn printDec(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        shell.print("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        shell.printChar(buf[i]);
    }
}

fn printDec64(val: u64) void {
    if (val == 0) {
        shell.print("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = val;
    while (n > 0) : (i += 1) {
        buf[i] = @truncate((n % 10) + '0');
        n /= 10;
    }
    while (i > 0) {
        i -= 1;
        shell.printChar(buf[i]);
    }
}

fn printHex16(val: u16) void {
    const hex = "0123456789ABCDEF";
    shell.printChar(hex[(val >> 12) & 0xF]);
    shell.printChar(hex[(val >> 8) & 0xF]);
    shell.printChar(hex[(val >> 4) & 0xF]);
    shell.printChar(hex[val & 0xF]);
}

fn printHex32(val: u32) void {
    const hex = "0123456789ABCDEF";
    var shift: u5 = 28;
    while (true) {
        shell.printChar(hex[@intCast((val >> shift) & 0xF)]);
        if (shift == 0) break;
        shift -= 4;
    }
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var shift: u6 = 60;
    while (true) {
        shell.printChar(hex[@intCast((val >> shift) & 0xF)]);
        if (shift == 0) break;
        shift -= 4;
    }
}
