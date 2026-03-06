//! Zamrud OS - USB HID (Human Interface Device) Driver
//! B2.11: USB keyboard and mouse support
//!
//! HID Class:
//!   - Subclass 0x01 = Boot Interface (keyboard/mouse with fixed report format)
//!   - Protocol 0x01 = Keyboard
//!   - Protocol 0x02 = Mouse
//!
//! Boot Protocol Report Formats:
//!   Keyboard: 8 bytes [modifier, reserved, key1-6]
//!   Mouse: 3-4 bytes [buttons, x, y, (wheel)]

const serial = @import("../../drivers/serial/serial.zig");
const usb = @import("usb.zig");
const timer = @import("../timer/timer.zig");

// =============================================================================
// HID Constants
// =============================================================================

// HID Class Requests
const HID_REQ_GET_REPORT: u8 = 0x01;
const HID_REQ_GET_IDLE: u8 = 0x02;
const HID_REQ_GET_PROTOCOL: u8 = 0x03;
const HID_REQ_SET_REPORT: u8 = 0x09;
const HID_REQ_SET_IDLE: u8 = 0x0A;
const HID_REQ_SET_PROTOCOL: u8 = 0x0B;

// HID Report Types
const HID_REPORT_INPUT: u8 = 0x01;
const HID_REPORT_OUTPUT: u8 = 0x02;
const HID_REPORT_FEATURE: u8 = 0x03;

// HID Protocols
const HID_PROTOCOL_BOOT: u8 = 0x00;
const HID_PROTOCOL_REPORT: u8 = 0x01;

// Boot Keyboard Modifier Keys (byte 0)
const MOD_LEFT_CTRL: u8 = 1 << 0;
const MOD_LEFT_SHIFT: u8 = 1 << 1;
const MOD_LEFT_ALT: u8 = 1 << 2;
const MOD_LEFT_GUI: u8 = 1 << 3;
const MOD_RIGHT_CTRL: u8 = 1 << 4;
const MOD_RIGHT_SHIFT: u8 = 1 << 5;
const MOD_RIGHT_ALT: u8 = 1 << 6;
const MOD_RIGHT_GUI: u8 = 1 << 7;

// Boot Mouse Buttons (byte 0)
const MOUSE_BTN_LEFT: u8 = 1 << 0;
const MOUSE_BTN_RIGHT: u8 = 1 << 1;
const MOUSE_BTN_MIDDLE: u8 = 1 << 2;

// =============================================================================
// HID Device State
// =============================================================================

const MAX_HID_DEVICES: usize = 8;

const HidDeviceType = enum {
    none,
    keyboard,
    mouse,
    other,
};

const HidDevice = struct {
    usb_device: ?*usb.UsbDevice = null,
    device_type: HidDeviceType = .none,
    interface_num: u8 = 0,
    interrupt_ep: u8 = 0,
    interrupt_interval: u8 = 0,
    max_packet_size: u16 = 0,

    // Keyboard state
    last_keys: [6]u8 = [_]u8{0} ** 6,
    last_modifiers: u8 = 0,

    // Mouse state
    last_buttons: u8 = 0,

    allocated: bool = false,
    active: bool = false,
};

var hid_devices: [MAX_HID_DEVICES]HidDevice = [_]HidDevice{.{}} ** MAX_HID_DEVICES;
var hid_device_count: usize = 0;
var initialized: bool = false;

// USB HID keycode to ASCII/scancode translation
const HID_TO_ASCII = [_]u8{
    0, 0, 0, 0, 'a', 'b', 'c', 'd', // 0x00-0x07
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', // 0x08-0x0F
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', // 0x10-0x17
    'u', 'v', 'w', 'x', 'y', 'z', '1', '2', // 0x18-0x1F
    '3', '4', '5', '6', '7', '8', '9', '0', // 0x20-0x27
    '\n', 0x1B, 0x08, '\t', ' ', '-', '=', '[', // 0x28-0x2F
    ']', '\\', 0, ';', '\'', '`', ',', '.', // 0x30-0x37
    '/', 0, 0, 0, 0, 0, 0, 0, // 0x38-0x3F (F1-F6)
    0, 0, 0, 0, 0, 0, 0, 0, // 0x40-0x47 (F7-F12, etc)
    0, 0, 0, 0, 0, 0, 0, 0, // 0x48-0x4F (arrows, etc)
    0, 0, 0, 0, '/', '*', '-', '+', // 0x50-0x57 (keypad)
    '\n', '1', '2', '3', '4', '5', '6', '7', // 0x58-0x5F (keypad)
    '8', '9', '0', '.', // 0x60-0x63 (keypad)
};

const HID_TO_ASCII_SHIFT = [_]u8{
    0, 0, 0, 0, 'A', 'B', 'C', 'D', // 0x00-0x07
    'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', // 0x08-0x0F
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', // 0x10-0x17
    'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@', // 0x18-0x1F
    '#', '$', '%', '^', '&', '*', '(', ')', // 0x20-0x27
    '\n', 0x1B, 0x08, '\t', ' ', '_', '+', '{', // 0x28-0x2F
    '}', '|', 0, ':', '"', '~', '<', '>', // 0x30-0x37
    '?', 0, 0, 0, 0, 0, 0, 0, // 0x38-0x3F
    0, 0, 0, 0, 0, 0, 0, 0, // 0x40-0x47
    0, 0, 0, 0, 0, 0, 0, 0, // 0x48-0x4F
    0, 0, 0, 0, '/', '*', '-', '+', // 0x50-0x57
    '\n', '1', '2', '3', '4', '5', '6', '7', // 0x58-0x5F
    '8', '9', '0', '.', // 0x60-0x63
};

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[USB-HID] Initializing HID driver...\n");

    // Reset state
    for (&hid_devices) |*dev| {
        dev.* = HidDevice{};
    }
    hid_device_count = 0;

    // Scan for HID devices
    scanForHidDevices();

    initialized = true;

    serial.writeString("[USB-HID] HID driver initialized (");
    printU8(@intCast(hid_device_count));
    serial.writeString(" devices)\n");
}

fn scanForHidDevices() void {
    const dev_count = usb.getDeviceCount();

    for (0..dev_count) |i| {
        if (usb.getDevice(i)) |dev| {
            if (dev.isHid()) {
                registerHidDevice(dev);
            }
        }
    }
}

fn registerHidDevice(usb_dev: *const usb.UsbDevice) void {
    if (hid_device_count >= MAX_HID_DEVICES) return;

    // Find HID interface
    for (usb_dev.interfaces[0..usb_dev.num_interfaces]) |iface| {
        if (!iface.active) continue;
        if (iface.class != usb.USB_CLASS_HID) continue;

        const hid = &hid_devices[hid_device_count];
        hid.usb_device = @constCast(usb_dev);
        hid.interface_num = iface.number;
        hid.allocated = true;

        // Determine device type
        if (iface.subclass == usb.USB_HID_SUBCLASS_BOOT) {
            switch (iface.protocol) {
                usb.USB_HID_PROTOCOL_KEYBOARD => {
                    hid.device_type = .keyboard;
                    serial.writeString("[USB-HID] Boot keyboard detected\n");
                },
                usb.USB_HID_PROTOCOL_MOUSE => {
                    hid.device_type = .mouse;
                    serial.writeString("[USB-HID] Boot mouse detected\n");
                },
                else => {
                    hid.device_type = .other;
                },
            }
        } else {
            hid.device_type = .other;
        }

        // Find interrupt IN endpoint
        for (iface.endpoints[0..iface.num_endpoints]) |ep| {
            if (!ep.active) continue;
            if ((ep.attributes & 0x03) == usb.USB_EP_TYPE_INTERRUPT) {
                if ((ep.address & usb.USB_EP_DIR_IN) != 0) {
                    hid.interrupt_ep = ep.address;
                    hid.interrupt_interval = ep.interval;
                    hid.max_packet_size = ep.max_packet_size;
                    break;
                }
            }
        }

        hid.active = true;
        hid_device_count += 1;
        break;
    }
}

// =============================================================================
// HID Report Processing
// =============================================================================

/// Process boot keyboard report (8 bytes)
pub fn processKeyboardReport(hid: *HidDevice, report: []const u8) void {
    if (report.len < 8) return;

    const modifiers = report[0];
    // report[1] is reserved
    const keys = report[2..8];

    // Check for modifier changes
    processModifierChange(hid.last_modifiers, modifiers);

    // Process key releases (keys in last_keys but not in current)
    for (hid.last_keys) |last_key| {
        if (last_key == 0) continue;
        var found = false;
        for (keys) |key| {
            if (key == last_key) {
                found = true;
                break;
            }
        }
        if (!found) {
            processKeyRelease(last_key, modifiers);
        }
    }

    // Process key presses (keys in current but not in last_keys)
    for (keys) |key| {
        if (key == 0) continue;
        var found = false;
        for (hid.last_keys) |last_key| {
            if (last_key == key) {
                found = true;
                break;
            }
        }
        if (!found) {
            processKeyPress(key, modifiers);
        }
    }

    // Save state
    hid.last_modifiers = modifiers;
    @memcpy(&hid.last_keys, keys);
}

fn processModifierChange(old: u8, new: u8) void {
    // Detect modifier key changes for PS/2 keyboard emulation
    _ = old;
    _ = new;
    // This would update shift_pressed, ctrl_pressed, etc.
}

fn processKeyPress(keycode: u8, modifiers: u8) void {
    if (keycode >= HID_TO_ASCII.len) return;

    const shift = (modifiers & (MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT)) != 0;
    const ascii = if (shift) HID_TO_ASCII_SHIFT[keycode] else HID_TO_ASCII[keycode];

    if (ascii != 0) {
        // Buffer the key for the shell
        serial.writeString("[USB-HID] Key: ");
        if (ascii >= 0x20 and ascii < 0x7F) {
            serial.writeChar(ascii);
        } else {
            serial.writeString("0x");
            printHex8(ascii);
        }
        serial.writeString("\n");

        // TODO: Push to keyboard buffer
        // keyboard.bufferKey(ascii);
    }
}

fn processKeyRelease(keycode: u8, modifiers: u8) void {
    _ = modifiers;
    _ = keycode;
    // Key release handling if needed
}

/// Process boot mouse report (3-4 bytes)
pub fn processMouseReport(hid: *HidDevice, report: []const u8) void {
    if (report.len < 3) return;

    const buttons = report[0];
    const dx: i8 = @bitCast(report[1]);
    const dy: i8 = @bitCast(report[2]);
    var dz: i8 = 0;
    if (report.len >= 4) {
        dz = @bitCast(report[3]);
    }

    // Detect button changes
    const btn_changed = buttons ^ hid.last_buttons;

    if (btn_changed != 0) {
        if ((btn_changed & MOUSE_BTN_LEFT) != 0) {
            serial.writeString("[USB-HID] Left button ");
            serial.writeString(if ((buttons & MOUSE_BTN_LEFT) != 0) "pressed\n" else "released\n");
        }
        if ((btn_changed & MOUSE_BTN_RIGHT) != 0) {
            serial.writeString("[USB-HID] Right button ");
            serial.writeString(if ((buttons & MOUSE_BTN_RIGHT) != 0) "pressed\n" else "released\n");
        }
        if ((btn_changed & MOUSE_BTN_MIDDLE) != 0) {
            serial.writeString("[USB-HID] Middle button ");
            serial.writeString(if ((buttons & MOUSE_BTN_MIDDLE) != 0) "pressed\n" else "released\n");
        }
    }

    // Process movement
    if (dx != 0 or dy != 0) {
        // TODO: Update mouse position via mouse.zig
        // mouse.updatePosition(dx, dy);
        serial.writeString("[USB-HID] Mouse move: ");
        printI8(dx);
        serial.writeString(", ");
        printI8(dy);
        serial.writeString("\n");
    }

    // Process scroll
    if (dz != 0) {
        // TODO: Update scroll via mouse.zig
        serial.writeString("[USB-HID] Scroll: ");
        printI8(dz);
        serial.writeString("\n");
    }

    hid.last_buttons = buttons;
}

// =============================================================================
// Polling
// =============================================================================

/// Poll all HID devices for new reports
pub fn poll() void {
    if (!initialized) return;

    for (&hid_devices) |*hid| {
        if (!hid.active) continue;
        if (hid.usb_device == null) continue;

        // TODO: Issue interrupt IN transfer and process report
        // This requires the USB controller to perform the transfer
    }
}

// =============================================================================
// Query Functions
// =============================================================================

pub fn isInitialized() bool {
    return initialized;
}

pub fn getDeviceCount() usize {
    return hid_device_count;
}

pub fn getKeyboardCount() usize {
    var count: usize = 0;
    for (hid_devices[0..hid_device_count]) |hid| {
        if (hid.device_type == .keyboard) count += 1;
    }
    return count;
}

pub fn getMouseCount() usize {
    var count: usize = 0;
    for (hid_devices[0..hid_device_count]) |hid| {
        if (hid.device_type == .mouse) count += 1;
    }
    return count;
}

// =============================================================================
// Print Helpers
// =============================================================================

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}

fn printI8(val: i8) void {
    if (val < 0) {
        serial.writeChar('-');
        printU8(@intCast(-val));
    } else {
        printU8(@intCast(val));
    }
}

fn printHex8(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}
