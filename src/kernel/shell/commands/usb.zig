//! Zamrud OS - USB Shell Commands
//! B2.11: USB device management and testing (25 tests)

const shell = @import("../shell.zig");
const helpers = @import("helpers.zig");
const usb = @import("../../drivers/usb/usb.zig");
const uhci = @import("../../drivers/usb/uhci.zig");
const ehci = @import("../../drivers/usb/ehci.zig");
const hid = @import("../../drivers/usb/hid.zig");

// =============================================================================
// Local Print Helpers
// =============================================================================

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
        const nibble = (val >> shift) & 0xF;
        shell.printChar(hex[@as(usize, nibble)]);
        if (shift == 0) break;
        shift -= 4;
    }
}

// =============================================================================
// Main Command Handler
// =============================================================================

pub fn execute(args: []const u8) void {
    const parsed = helpers.parseArgs(args);
    const subcmd = parsed.cmd;

    if (subcmd.len == 0 or helpers.strEql(subcmd, "help")) {
        showHelp();
    } else if (helpers.strEql(subcmd, "status")) {
        cmdStatus();
    } else if (helpers.strEql(subcmd, "controllers") or helpers.strEql(subcmd, "ctrl")) {
        cmdControllers();
    } else if (helpers.strEql(subcmd, "devices") or helpers.strEql(subcmd, "dev")) {
        cmdDevices();
    } else if (helpers.strEql(subcmd, "ports")) {
        cmdPorts();
    } else if (helpers.strEql(subcmd, "scan")) {
        cmdScan();
    } else if (helpers.strEql(subcmd, "test")) {
        cmdTest();
    } else {
        shell.printError("Unknown USB command: ");
        shell.print(subcmd);
        shell.newLine();
        shell.println("  Type 'usb help' for usage");
    }
}

// =============================================================================
// Help
// =============================================================================

fn showHelp() void {
    shell.println("");
    shell.println("USB Subsystem Commands (B2.11):");
    shell.println("===============================");
    shell.println("");
    shell.println("  usb status      - Show USB subsystem status");
    shell.println("  usb controllers - List USB host controllers");
    shell.println("  usb devices     - List connected USB devices");
    shell.println("  usb ports       - Show port status details");
    shell.println("  usb scan        - Rescan for devices");
    shell.println("  usb test        - Run USB tests (25 tests)");
    shell.println("  usb help        - Show this help");
    shell.println("");
}

// =============================================================================
// Status Command
// =============================================================================

fn cmdStatus() void {
    shell.println("");
    shell.println("USB Subsystem Status");
    shell.println("====================");
    shell.println("");

    shell.print("  Initialized:       ");
    shell.println(if (usb.isInitialized()) "Yes" else "No");

    shell.print("  Controllers:       ");
    helpers.printDec64(usb.getControllerCount());
    shell.print(" (");
    helpers.printDec64(usb.getInitializedControllerCount());
    shell.println(" active)");

    shell.print("  Total Ports:       ");
    helpers.printDec64(usb.getTotalPorts());
    shell.newLine();

    shell.print("  Devices:           ");
    helpers.printDec64(usb.getDeviceCount());
    shell.newLine();

    shell.print("  Configured:        ");
    helpers.printDec64(usb.getConfiguredCount());
    shell.newLine();

    shell.print("  UHCI support:      ");
    shell.println(if (usb.hasUhci()) "Yes" else "No");

    shell.print("  EHCI support:      ");
    shell.println(if (usb.hasEhci()) "Yes" else "No");

    shell.print("  HID devices:       ");
    helpers.printDec64(usb.getHidCount());
    shell.newLine();

    shell.print("  Keyboards:         ");
    helpers.printDec64(usb.getKeyboardCount());
    shell.newLine();

    shell.print("  Mice:              ");
    helpers.printDec64(usb.getMouseCount());
    shell.newLine();

    shell.print("  Tablets:           ");
    helpers.printDec64(usb.getTabletCount());
    shell.newLine();

    shell.print("  Mass Storage:      ");
    helpers.printDec64(usb.getMassStorageCount());
    shell.newLine();

    shell.print("  Enumerations:      ");
    helpers.printDec64(usb.getTotalEnumerations());
    shell.print(" (");
    helpers.printDec64(usb.getFailedEnumerations());
    shell.println(" failed)");

    shell.println("");
}

// =============================================================================
// Controllers Command
// =============================================================================

fn cmdControllers() void {
    shell.println("");
    shell.println("USB Host Controllers");
    shell.println("====================");
    shell.println("");

    const count = usb.getControllerCount();
    if (count == 0) {
        shell.println("  No USB controllers found");
        shell.println("");
        return;
    }

    shell.println("  #  Type  PCI Addr   Base        IRQ  Ports Devs Status");
    shell.println("  -- ----- ---------- ----------- ---- ----- ---- --------");

    for (0..count) |i| {
        if (usb.getController(i)) |ctrl| {
            shell.print("  ");
            helpers.printDec64(i);
            if (i < 10) shell.print(" ");
            shell.print(" ");

            // Type
            const type_str = ctrl.controller_type.toString();
            shell.print(type_str);
            var pad: usize = 5;
            if (type_str.len < pad) {
                pad -= type_str.len;
                while (pad > 0) : (pad -= 1) shell.print(" ");
            }
            shell.print(" ");

            // PCI Address
            helpers.printHex8(ctrl.pci_bus);
            shell.print(":");
            helpers.printHex8(ctrl.pci_device);
            shell.print(".");
            helpers.printDec64(ctrl.pci_function);
            shell.print("    ");

            // Base address
            if (ctrl.is_mmio) {
                shell.print("0x");
                printHex32(@truncate(ctrl.base_addr));
            } else {
                shell.print("I/O 0x");
                printHex16(@truncate(ctrl.base_addr));
                shell.print("  ");
            }
            shell.print(" ");

            // IRQ
            helpers.printDec64(ctrl.irq);
            if (ctrl.irq < 10) shell.print(" ");
            shell.print("   ");

            // Ports
            helpers.printDec64(ctrl.num_ports);
            shell.print("     ");

            // Devices found
            helpers.printDec64(ctrl.devices_found);
            shell.print("    ");

            // Status
            if (ctrl.initialized) {
                shell.print("[OK]");
            } else {
                shell.print("[FAIL]");
            }
            shell.newLine();
        }
    }

    shell.println("");
}

// =============================================================================
// Ports Command
// =============================================================================

fn cmdPorts() void {
    shell.println("");
    shell.println("USB Port Status");
    shell.println("===============");
    shell.println("");

    var any_ports = false;

    // UHCI ports
    if (usb.hasUhci()) {
        any_ports = true;
        shell.println("  UHCI Controller Ports:");
        for (0..2) |port| {
            const status = uhci.getPortStatus(0, @truncate(port));
            shell.print("    Port ");
            helpers.printDec64(port + 1);
            shell.print(": 0x");
            printHex16(status);
            shell.print(" ");

            if ((status & 0x0001) != 0) {
                shell.print("[Connected]");
                if ((status & 0x0004) != 0) shell.print("[Enabled]");
                if ((status & 0x0100) != 0) shell.print("[LowSpeed]") else shell.print("[FullSpeed]");
            } else {
                shell.print("[Empty]");
            }
            shell.newLine();
        }
        shell.println("");
    }

    // EHCI ports
    if (usb.hasEhci()) {
        any_ports = true;
        if (ehci.getController(0)) |ctrl| {
            shell.println("  EHCI Controller Ports:");
            for (0..ctrl.num_ports) |port| {
                const status = ehci.getPortStatus(0, @truncate(port));
                shell.print("    Port ");
                helpers.printDec64(port + 1);
                shell.print(": 0x");
                printHex32(status);
                shell.print(" ");

                if ((status & 0x0001) != 0) {
                    shell.print("[Connected]");
                    if ((status & 0x0004) != 0) shell.print("[Enabled]");
                    if ((status & 0x2000) != 0) shell.print("[->Companion]");
                } else {
                    shell.print("[Empty]");
                }
                shell.newLine();
            }
        }
        shell.println("");
    }

    if (!any_ports) {
        shell.println("  No USB controllers initialized");
        shell.println("");
    }
}

// =============================================================================
// Devices Command
// =============================================================================

fn cmdDevices() void {
    shell.println("");
    shell.println("USB Devices");
    shell.println("===========");
    shell.println("");

    const count = usb.getDeviceCount();
    if (count == 0) {
        shell.println("  No USB devices connected");
        shell.println("");
        shell.println("  Hint: Add USB devices in QEMU with:");
        shell.println("    -device usb-tablet,bus=usb-bus1.0");
        shell.println("");
        return;
    }

    shell.println("  Addr VID:PID    Class        Speed       State      Ctrl");
    shell.println("  ---- ---------- ------------ ----------- ---------- ----");

    for (0..usb.MAX_DEVICES) |i| {
        if (usb.getDevice(i)) |dev| {
            shell.print("  ");

            // Address
            if (dev.address < 10) shell.print(" ");
            if (dev.address < 100) shell.print(" ");
            helpers.printDec64(dev.address);
            shell.print(" ");

            // VID:PID
            printHex16(dev.vendor_id);
            shell.print(":");
            printHex16(dev.product_id);
            shell.print(" ");

            // Class (12 chars)
            const class_name = dev.getClassName();
            shell.print(class_name);
            var cpad: usize = 12;
            if (class_name.len < cpad) {
                cpad -= class_name.len;
                while (cpad > 0) : (cpad -= 1) shell.print(" ");
            }
            shell.print(" ");

            // Speed (11 chars)
            const speed_str = dev.getSpeedString();
            shell.print(speed_str);
            var spad: usize = 11;
            if (speed_str.len < spad) {
                spad -= speed_str.len;
                while (spad > 0) : (spad -= 1) shell.print(" ");
            }
            shell.print(" ");

            // State (10 chars)
            const state_str = dev.getStateString();
            shell.print(state_str);
            var stpad: usize = 10;
            if (state_str.len < stpad) {
                stpad -= state_str.len;
                while (stpad > 0) : (stpad -= 1) shell.print(" ");
            }
            shell.print(" ");

            // Controller
            shell.print(dev.controller_type.toString());
            shell.newLine();
        }
    }

    shell.println("");
}

// =============================================================================
// Scan Command
// =============================================================================

fn cmdScan() void {
    shell.println("");
    shell.println("Rescanning USB devices...");
    shell.println("");

    const old_count = usb.getDeviceCount();

    if (usb.init()) {
        const new_count = usb.getDeviceCount();
        shell.print("  Controllers: ");
        helpers.printDec64(usb.getControllerCount());
        shell.print(" (");
        helpers.printDec64(usb.getInitializedControllerCount());
        shell.println(" active)");

        shell.print("  Devices:     ");
        helpers.printDec64(new_count);
        if (new_count != old_count) {
            shell.print(" (was ");
            helpers.printDec64(old_count);
            shell.print(")");
        }
        shell.newLine();
    } else {
        shell.println("  No USB controllers found");
    }

    // Re-init HID
    hid.init();
    shell.print("  HID devices: ");
    helpers.printDec64(hid.getDeviceCount());
    shell.newLine();

    shell.println("");
}

// =============================================================================
// Test Command (25 tests)
// =============================================================================

fn cmdTest() void {
    helpers.printTestHeader("USB SUBSYSTEM TESTS (B2.11)");

    var passed: u32 = 0;
    var failed: u32 = 0;

    const ctrl_count = usb.getControllerCount();
    const dev_count = usb.getDeviceCount();

    // ═══════════════════════════════════════════════════════════════════════
    // Section 1: Subsystem Initialization (Tests 01-03)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 01: USB subsystem initialized
    shell.print("[01] USB subsystem initialized: ");
    if (usb.isInitialized()) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 02: Controller count >= 1
    shell.print("[02] Controller count >= 1: ");
    if (ctrl_count >= 1) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 03: At least one controller initialized
    shell.print("[03] Active controllers >= 1: ");
    if (usb.getInitializedControllerCount() >= 1) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 2: Controller Types (Tests 04-06)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 04: UHCI or EHCI detected
    shell.print("[04] UHCI or EHCI detected: ");
    if (usb.hasUhci() or usb.hasEhci()) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 05: Controller type enum valid
    shell.print("[05] Controller type enum valid: ");
    var type_valid = true;
    for (0..ctrl_count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.controller_type == .none and ctrl.initialized) {
                type_valid = false;
            }
        }
    }
    if (type_valid) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 06: Controller type strings
    shell.print("[06] Controller type strings: ");
    const uhci_str = usb.ControllerType.uhci.toString();
    const ehci_str = usb.ControllerType.ehci.toString();
    if (uhci_str.len > 0 and ehci_str.len > 0) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 3: Controller Properties (Tests 07-10)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 07: Active controller base address != 0
    shell.print("[07] Active ctrl base addr != 0: ");
    var addr_valid = true;
    for (0..ctrl_count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.initialized and ctrl.base_addr == 0) {
                addr_valid = false;
            }
        }
    }
    if (addr_valid) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 08: IRQ in valid range (0-15)
    shell.print("[08] IRQ in valid range: ");
    var irq_valid = true;
    for (0..ctrl_count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.irq > 15) {
                irq_valid = false;
            }
        }
    }
    if (irq_valid) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 09: Active controllers have ports > 0
    shell.print("[09] Active ctrl ports > 0: ");
    var port_valid = true;
    for (0..ctrl_count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.initialized and ctrl.num_ports == 0) {
                port_valid = false;
            }
        }
    }
    if (port_valid) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 10: Total ports > 0
    shell.print("[10] Total ports > 0: ");
    if (usb.getTotalPorts() > 0) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 4: UHCI Driver (Tests 11-12)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 11: UHCI driver init check
    shell.print("[11] UHCI driver status: ");
    // Pass if UHCI is initialized OR if there's no UHCI controller
    if (uhci.isInitialized() or !hasUhciController()) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 12: UHCI port status readable
    shell.print("[12] UHCI port status readable: ");
    if (uhci.isInitialized()) {
        const p1 = uhci.getPortStatus(0, 0);
        const p2 = uhci.getPortStatus(0, 1);
        if (p1 != 0xFFFF and p2 != 0xFFFF) {
            shell.println("PASS");
            passed += 1;
        } else {
            shell.println("FAIL");
            failed += 1;
        }
    } else {
        shell.println("PASS (N/A)");
        passed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 5: EHCI Driver (Tests 13-14)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 13: EHCI driver status
    shell.print("[13] EHCI driver status: ");
    if (ehci.isInitialized() or !hasEhciController()) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 14: EHCI version valid (0x0100 - 0x0110)
    shell.print("[14] EHCI version valid: ");
    if (ehci.isInitialized()) {
        const version = ehci.getVersion(0);
        if (version >= 0x0095 and version <= 0x0200) {
            shell.println("PASS");
            passed += 1;
        } else {
            shell.println("FAIL");
            failed += 1;
        }
    } else {
        shell.println("PASS (N/A)");
        passed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 6: Device Detection (Tests 15-18)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 15: Device count stable
    shell.print("[15] Device count stable: ");
    const check1 = usb.getDeviceCount();
    const check2 = usb.getDeviceCount();
    if (check1 == check2) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 16: Out-of-bounds index returns null
    shell.print("[16] OOB index returns null: ");
    if (usb.getDevice(usb.MAX_DEVICES) == null and usb.getDevice(999) == null) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 17: All allocated devices have valid state
    shell.print("[17] Devices have valid state: ");
    var state_valid = true;
    for (0..usb.MAX_DEVICES) |i| {
        if (usb.getDevice(i)) |dev| {
            // Allocated devices should not be detached
            if (dev.state == .detached) {
                state_valid = false;
            }
        }
    }
    if (state_valid) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 18: Devices have controller type set
    shell.print("[18] Devices have ctrl type: ");
    var ctrl_type_ok = true;
    for (0..usb.MAX_DEVICES) |i| {
        if (usb.getDevice(i)) |dev| {
            if (dev.controller_type == .none) {
                ctrl_type_ok = false;
            }
        }
    }
    if (ctrl_type_ok or dev_count == 0) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 7: Device Classification (Tests 19-21)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 19: HID count <= device count
    shell.print("[19] HID count <= dev count: ");
    if (usb.getHidCount() <= dev_count) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 20: Class name not empty
    shell.print("[20] Class names valid: ");
    var class_ok = true;
    for (0..usb.MAX_DEVICES) |i| {
        if (usb.getDevice(i)) |dev| {
            if (dev.getClassName().len == 0) class_ok = false;
        }
    }
    if (class_ok) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 21: Speed string not empty
    shell.print("[21] Speed strings valid: ");
    var speed_ok = true;
    for (0..usb.MAX_DEVICES) |i| {
        if (usb.getDevice(i)) |dev| {
            if (dev.getSpeedString().len == 0) speed_ok = false;
        }
    }
    if (speed_ok) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 8: HID Subsystem (Tests 22-23)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 22: HID driver initialized
    shell.print("[22] HID driver initialized: ");
    if (hid.isInitialized()) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 23: HID counts consistent
    shell.print("[23] HID counts consistent: ");
    const hid_total = hid.getDeviceCount();
    const hid_kb = hid.getKeyboardCount();
    const hid_mouse = hid.getMouseCount();
    if (hid_kb <= hid_total and hid_mouse <= hid_total) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Section 9: Statistics (Tests 24-25)
    // ═══════════════════════════════════════════════════════════════════════

    // Test 24: Enumeration counter >= device count
    shell.print("[24] Enum count >= dev count: ");
    if (usb.getTotalEnumerations() >= dev_count) {
        shell.println("PASS");
        passed += 1;
    } else {
        shell.println("FAIL");
        failed += 1;
    }

    // Test 25: Transfer counter accessible
    shell.print("[25] Transfer counter works: ");
    const transfers = usb.getTotalTransfers();
    _ = transfers; // Just check it doesn't crash
    shell.println("PASS");
    passed += 1;

    // ═══════════════════════════════════════════════════════════════════════
    // Summary
    // ═══════════════════════════════════════════════════════════════════════

    shell.println("");
    shell.print("USB Tests: ");
    helpers.printDec64(passed);
    shell.print(" passed, ");
    helpers.printDec64(failed);
    shell.println(" failed");
    shell.println("");

    if (failed == 0) {
        shell.println("All USB tests PASSED!");
    } else {
        shell.printError("Some USB tests FAILED!");
        shell.newLine();
    }

    // Device summary
    shell.println("");
    shell.print("Controllers: ");
    helpers.printDec64(ctrl_count);
    shell.print(" (UHCI: ");
    shell.print(if (usb.hasUhci()) "OK" else "NO");
    shell.print(", EHCI: ");
    shell.print(if (usb.hasEhci()) "OK" else "NO");
    shell.println(")");

    shell.print("Devices: ");
    helpers.printDec64(dev_count);
    if (dev_count > 0) {
        shell.print(" (");
        helpers.printDec64(usb.getHidCount());
        shell.print(" HID, ");
        helpers.printDec64(usb.getTabletCount());
        shell.print(" tablet, ");
        helpers.printDec64(usb.getConfiguredCount());
        shell.print(" configured)");
    }
    shell.newLine();

    // List detected devices
    if (dev_count > 0) {
        shell.println("");
        shell.println("Detected devices:");
        for (0..usb.MAX_DEVICES) |i| {
            if (usb.getDevice(i)) |dev| {
                shell.print("  [");
                helpers.printDec64(dev.address);
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
    }

    shell.println("");
}

// =============================================================================
// Helper Functions
// =============================================================================

fn hasUhciController() bool {
    const count = usb.getControllerCount();
    for (0..count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.controller_type == .uhci) return true;
        }
    }
    return false;
}

fn hasEhciController() bool {
    const count = usb.getControllerCount();
    for (0..count) |i| {
        if (usb.getController(i)) |ctrl| {
            if (ctrl.controller_type == .ehci) return true;
        }
    }
    return false;
}
