//! Zamrud OS - USB HID Driver (B2.11b + B2.11c)
//! Uses GET_REPORT control transfers for reliable QEMU compatibility
//! B2.11c: Mouse/tablet reports + dedup protection for QEMU addr=0

const serial = @import("../../drivers/serial/serial.zig");
const usb = @import("usb.zig");
const ehci = @import("ehci.zig");
const keyboard = @import("../input/keyboard.zig");
const mouse = @import("../input/mouse.zig");
const spinlock = @import("../../arch/x86_64/spinlock.zig");

const MAX_HID_DEVICES: usize = 8;
const POLL_INTERVAL_TICKS: u32 = 2; // 20ms at 100Hz
const MAX_REPORT_SIZE: usize = 16;

// HID Request codes
const HID_GET_REPORT: u8 = 0x01;
const HID_SET_IDLE: u8 = 0x0A;
const HID_SET_PROTOCOL: u8 = 0x0B;
const HID_REPORT_TYPE_INPUT: u16 = 0x0100;

const MOD_LEFT_CTRL: u8 = 1 << 0;
const MOD_LEFT_SHIFT: u8 = 1 << 1;
const MOD_LEFT_ALT: u8 = 1 << 2;
const MOD_LEFT_GUI: u8 = 1 << 3;
const MOD_RIGHT_CTRL: u8 = 1 << 4;
const MOD_RIGHT_SHIFT: u8 = 1 << 5;
const MOD_RIGHT_ALT: u8 = 1 << 6;
const MOD_RIGHT_GUI: u8 = 1 << 7;

const HidDeviceType = enum(u8) {
    none = 0,
    keyboard = 1,
    mouse = 2,
    tablet = 3,
    other = 4,
};

const HidDevice = struct {
    usb_device: ?*usb.UsbDevice = null,
    device_type: HidDeviceType = .none,
    interface_num: u8 = 0,
    report_size: u8 = 8,
    controller_index: u8 = 0,
    last_report: [MAX_REPORT_SIZE]u8 = [_]u8{0} ** MAX_REPORT_SIZE,
    active: bool = false,
    poll_count: u64 = 0,
    success_count: u64 = 0,
    error_count: u64 = 0,
};

var hid_devices: [MAX_HID_DEVICES]HidDevice = [_]HidDevice{.{}} ** MAX_HID_DEVICES;
var hid_device_count: usize = 0;
var initialized: bool = false;
var polling_enabled: bool = false;
var poll_pending: bool = false;
var poll_tick_counter: u32 = 0;
var hid_lock: spinlock.SpinLock = .{};

var stats_total_polls: u64 = 0;
var stats_successful_polls: u64 = 0;
var stats_keyboard_events: u64 = 0;
var stats_mouse_events: u64 = 0;
var stats_tablet_events: u64 = 0;
var stats_duplicates_skipped: u64 = 0;

// Keycode tables
const HID_TO_ASCII = [_]u8{
    0,   0,    0,   0,   'a',  'b', 'c', 'd', 'e',  'f',  'g',  'h',  'i', 'j', 'k', 'l',
    'm', 'n',  'o', 'p', 'q',  'r', 's', 't', 'u',  'v',  'w',  'x',  'y', 'z', '1', '2',
    '3', '4',  '5', '6', '7',  '8', '9', '0', '\n', 0x1B, 0x08, '\t', ' ', '-', '=', '[',
    ']', '\\', 0,   ';', '\'', '`', ',', '.', '/',  0,    0,    0,    0,   0,   0,   0,
};

const HID_TO_ASCII_SHIFT = [_]u8{
    0,   0,   0,   0,   'A', 'B', 'C', 'D', 'E',  'F',  'G',  'H',  'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',  'V',  'W',  'X',  'Y', 'Z', '!', '@',
    '#', '$', '%', '^', '&', '*', '(', ')', '\n', 0x1B, 0x08, '\t', ' ', '_', '+', '{',
    '}', '|', 0,   ':', '"', '~', '<', '>', '?',  0,    0,    0,    0,   0,   0,   0,
};

fn hidToSpecialKey(keycode: u8) ?u8 {
    return switch (keycode) {
        0x4F => keyboard.KEY_RIGHT,
        0x50 => keyboard.KEY_LEFT,
        0x51 => keyboard.KEY_DOWN,
        0x52 => keyboard.KEY_UP,
        0x49 => keyboard.KEY_INSERT,
        0x4A => keyboard.KEY_HOME,
        0x4B => keyboard.KEY_PGUP,
        0x4C => keyboard.KEY_DELETE,
        0x4D => keyboard.KEY_END,
        0x4E => keyboard.KEY_PGDN,
        0x3A => keyboard.KEY_F1,
        0x3B => keyboard.KEY_F2,
        0x3C => keyboard.KEY_F3,
        0x3D => keyboard.KEY_F4,
        0x3E => keyboard.KEY_F5,
        0x3F => keyboard.KEY_F6,
        0x40 => keyboard.KEY_F7,
        0x41 => keyboard.KEY_F8,
        0x42 => keyboard.KEY_F9,
        0x43 => keyboard.KEY_F10,
        0x44 => keyboard.KEY_F11,
        0x45 => keyboard.KEY_F12,
        else => null,
    };
}

pub fn init() void {
    serial.writeString("[USB-HID] Initializing HID driver (B2.11c)...\n");

    hid_lock.acquire();
    defer hid_lock.release();

    for (&hid_devices) |*dev| {
        dev.* = HidDevice{};
    }
    hid_device_count = 0;
    stats_total_polls = 0;
    stats_successful_polls = 0;
    stats_keyboard_events = 0;
    stats_mouse_events = 0;
    stats_tablet_events = 0;
    stats_duplicates_skipped = 0;
    poll_pending = false;
    poll_tick_counter = 0;

    scanForHidDevices();

    initialized = true;
    polling_enabled = hid_device_count > 0;

    serial.writeString("[USB-HID] HID driver initialized (");
    printU8(@intCast(hid_device_count));
    serial.writeString(" devices: ");
    printU8(@intCast(getKeyboardCount()));
    serial.writeString(" kbd, ");
    printU8(@intCast(getMouseCount()));
    serial.writeString(" mouse, ");
    printU8(@intCast(getTabletCount()));
    serial.writeString(" tablet, GET_REPORT mode)\n");

    if (stats_duplicates_skipped > 0) {
        serial.writeString("[USB-HID] Skipped ");
        printU8(@intCast(stats_duplicates_skipped));
        serial.writeString(" duplicate(s) (QEMU addr=0 dedup)\n");
    }
}

fn scanForHidDevices() void {
    const dev_count = usb.getDeviceCount();
    for (0..dev_count) |i| {
        if (usb.getDeviceMut(i)) |dev| {
            registerDevice(dev);
        }
    }
}

/// QEMU addr=0 dedup: check if we already have this device type on this controller
fn hasDuplicateOnController(ctrl_index: u8, dtype: HidDeviceType) bool {
    for (hid_devices[0..hid_device_count]) |hid| {
        if (hid.active and hid.controller_index == ctrl_index and hid.device_type == dtype) {
            return true;
        }
    }
    return false;
}

fn registerDevice(usb_dev: *usb.UsbDevice) void {
    if (hid_device_count >= MAX_HID_DEVICES) return;

    var hid = &hid_devices[hid_device_count];
    hid.usb_device = usb_dev;
    hid.controller_index = usb_dev.controller_index;

    for (usb_dev.interfaces[0..usb_dev.num_interfaces]) |iface| {
        if (!iface.active) continue;
        if (iface.class != usb.USB_CLASS_HID) continue;

        hid.interface_num = iface.number;

        if (iface.subclass == usb.USB_HID_SUBCLASS_BOOT) {
            switch (iface.protocol) {
                usb.USB_HID_PROTOCOL_KEYBOARD => {
                    // QEMU addr=0 dedup: skip if already have keyboard on this controller
                    if (hasDuplicateOnController(usb_dev.controller_index, .keyboard)) {
                        serial.writeString("[USB-HID] SKIP duplicate keyboard (addr=0 dedup, ctrl=");
                        printU8(usb_dev.controller_index);
                        serial.writeString(")\n");
                        stats_duplicates_skipped += 1;
                        return;
                    }
                    hid.device_type = .keyboard;
                    hid.report_size = 8;
                    hid.active = true;
                    hid_device_count += 1;
                    serial.writeString("[USB-HID] Boot keyboard registered (ctrl=");
                    printU8(usb_dev.controller_index);
                    serial.writeString(")\n");
                    return;
                },
                usb.USB_HID_PROTOCOL_MOUSE => {
                    // QEMU addr=0 dedup: skip if already have mouse on this controller
                    if (hasDuplicateOnController(usb_dev.controller_index, .mouse)) {
                        serial.writeString("[USB-HID] SKIP duplicate mouse (addr=0 dedup, ctrl=");
                        printU8(usb_dev.controller_index);
                        serial.writeString(")\n");
                        stats_duplicates_skipped += 1;
                        return;
                    }
                    hid.device_type = .mouse;
                    hid.report_size = 4;
                    hid.active = true;
                    hid_device_count += 1;
                    serial.writeString("[USB-HID] Boot mouse registered (ctrl=");
                    printU8(usb_dev.controller_index);
                    serial.writeString(")\n");
                    return;
                },
                else => {},
            }
        }

        // Generic HID — also dedup
        if (hasDuplicateOnController(usb_dev.controller_index, .other)) {
            stats_duplicates_skipped += 1;
            return;
        }
        hid.device_type = .other;
        hid.report_size = 8;
        hid.active = true;
        hid_device_count += 1;
        serial.writeString("[USB-HID] Generic HID registered\n");
        return;
    }

    // QEMU tablet fallback: VID:PID 0627:0001
    if (usb_dev.vendor_id == 0x0627 and usb_dev.product_id == 0x0001) {
        // Check dedup — QEMU tablet at addr=0 looks same as keyboard
        if (hasDuplicateOnController(usb_dev.controller_index, .tablet)) {
            stats_duplicates_skipped += 1;
            return;
        }
        // Also skip if we already have a keyboard on this controller
        // (QEMU addr=0: tablet and keyboard return same data)
        if (hasDuplicateOnController(usb_dev.controller_index, .keyboard)) {
            serial.writeString("[USB-HID] SKIP tablet (keyboard already on ctrl=");
            printU8(usb_dev.controller_index);
            serial.writeString(", addr=0 conflict)\n");
            stats_duplicates_skipped += 1;
            return;
        }
        hid.device_type = .tablet;
        hid.report_size = 6;
        hid.active = true;
        hid_device_count += 1;
        serial.writeString("[USB-HID] QEMU Tablet registered (ctrl=");
        printU8(usb_dev.controller_index);
        serial.writeString(")\n");
    }
}

/// Called from APIC timer
pub fn timerTick() void {
    if (!initialized or !polling_enabled) return;

    poll_tick_counter += 1;
    if (poll_tick_counter >= POLL_INTERVAL_TICKS) {
        poll_tick_counter = 0;
        @atomicStore(bool, &poll_pending, true, .release);
    }
}

/// Called from shell idle loop - does actual polling via GET_REPORT
pub fn processPending() void {
    if (!@atomicLoad(bool, &poll_pending, .acquire)) return;
    @atomicStore(bool, &poll_pending, false, .release);

    if (!polling_enabled) return;
    if (!hid_lock.tryAcquire()) return;
    defer hid_lock.release();

    for (&hid_devices) |*hid| {
        if (!hid.active) continue;
        const dev = hid.usb_device orelse continue;

        var report: [MAX_REPORT_SIZE]u8 = [_]u8{0} ** MAX_REPORT_SIZE;
        stats_total_polls += 1;
        hid.poll_count += 1;

        // Use GET_REPORT control transfer (works reliably on QEMU)
        const setup = usb.SetupPacket{
            .bmRequestType = 0xA1, // Device-to-host, Class, Interface
            .bRequest = HID_GET_REPORT,
            .wValue = HID_REPORT_TYPE_INPUT, // Input report, ID=0
            .wIndex = hid.interface_num,
            .wLength = hid.report_size,
        };

        if (!ehci.controlTransfer(dev, &setup, report[0..hid.report_size], true)) {
            hid.error_count += 1;
            continue;
        }

        stats_successful_polls += 1;
        hid.success_count += 1;

        // Check if report changed
        var changed = false;
        for (0..hid.report_size) |j| {
            if (report[j] != hid.last_report[j]) {
                changed = true;
                break;
            }
        }

        if (!changed) continue;

        // Process based on device type
        switch (hid.device_type) {
            .keyboard => processKeyboardReport(hid, report[0..8]),
            .mouse => processMouseReport(hid, report[0..hid.report_size]),
            .tablet => processTabletReport(hid, report[0..hid.report_size]),
            else => {},
        }

        @memcpy(hid.last_report[0..hid.report_size], report[0..hid.report_size]);
    }
}

fn processKeyboardReport(hid: *HidDevice, report: []const u8) void {
    if (report.len < 8) return;

    const modifiers = report[0];
    const keys = report[2..8];
    const last_keys = hid.last_report[2..8];

    const shift = (modifiers & (MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT)) != 0;
    const ctrl = (modifiers & (MOD_LEFT_CTRL | MOD_RIGHT_CTRL)) != 0;
    const alt = (modifiers & (MOD_LEFT_ALT | MOD_RIGHT_ALT)) != 0;
    keyboard.setUsbModifiers(shift, ctrl, alt);

    for (keys) |key| {
        if (key == 0) continue;

        var is_new = true;
        for (last_keys) |last| {
            if (last == key) {
                is_new = false;
                break;
            }
        }

        if (is_new) {
            handleKeyPress(key, modifiers);
            stats_keyboard_events += 1;
        }
    }
}

fn handleKeyPress(keycode: u8, modifiers: u8) void {
    const shift = (modifiers & (MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT)) != 0;
    const ctrl = (modifiers & (MOD_LEFT_CTRL | MOD_RIGHT_CTRL)) != 0;

    if (hidToSpecialKey(keycode)) |special| {
        keyboard.bufferUsbKey(special);
        return;
    }

    if (keycode < HID_TO_ASCII.len) {
        var ascii = if (shift) HID_TO_ASCII_SHIFT[keycode] else HID_TO_ASCII[keycode];

        if (ascii != 0) {
            if (ctrl and ascii >= 'a' and ascii <= 'z') {
                ascii = ascii - 'a' + 1;
            } else if (ctrl and ascii >= 'A' and ascii <= 'Z') {
                ascii = ascii - 'A' + 1;
            }
            keyboard.bufferUsbKey(ascii);
        }
    }
}

fn processMouseReport(hid: *HidDevice, report: []const u8) void {
    if (report.len < 3) return;

    const btns = report[0] & 0x07;
    const dx: i8 = @bitCast(report[1]);
    const dy: i8 = @bitCast(report[2]);
    var scroll: i8 = 0;
    if (report.len >= 4) {
        scroll = @bitCast(report[3]);
    }

    const last_buttons = hid.last_report[0] & 0x07;

    if (dx != 0 or dy != 0 or btns != last_buttons or scroll != 0) {
        mouse.queueUsbEvent(@intCast(dx), @intCast(-dy), btns, scroll);
        stats_mouse_events += 1;
    }
}

fn processTabletReport(hid: *HidDevice, report: []const u8) void {
    if (report.len < 6) return;

    const btns = report[0] & 0x07;
    const abs_x: u16 = @as(u16, report[1]) | (@as(u16, report[2]) << 8);
    const abs_y: u16 = @as(u16, report[3]) | (@as(u16, report[4]) << 8);

    const last_buttons = hid.last_report[0] & 0x07;
    const last_x: u16 = @as(u16, hid.last_report[1]) | (@as(u16, hid.last_report[2]) << 8);
    const last_y: u16 = @as(u16, hid.last_report[3]) | (@as(u16, hid.last_report[4]) << 8);

    if (abs_x != last_x or abs_y != last_y or btns != last_buttons) {
        mouse.setUsbTabletPosition(abs_x, abs_y, btns);
        stats_tablet_events += 1;
        stats_mouse_events += 1;
    }
}

// Public API
pub fn isInitialized() bool {
    return initialized;
}

pub fn isPollingEnabled() bool {
    return polling_enabled;
}

pub fn setPollingEnabled(enabled: bool) void {
    polling_enabled = enabled;
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

pub fn getTabletCount() usize {
    var count: usize = 0;
    for (hid_devices[0..hid_device_count]) |hid| {
        if (hid.device_type == .tablet) count += 1;
    }
    return count;
}

pub fn getDuplicatesSkipped() u64 {
    return stats_duplicates_skipped;
}

pub fn getDeviceType(index: usize) ?HidDeviceType {
    if (index >= hid_device_count) return null;
    return hid_devices[index].device_type;
}

pub fn getDeviceStats(index: usize) ?struct { polls: u64, successes: u64, errors: u64 } {
    if (index >= hid_device_count) return null;
    const d = &hid_devices[index];
    return .{ .polls = d.poll_count, .successes = d.success_count, .errors = d.error_count };
}

pub const HidStats = struct {
    device_count: usize,
    keyboards: usize,
    mice: usize,
    tablets: usize,
    total_polls: u64,
    successful_polls: u64,
    keyboard_events: u64,
    mouse_events: u64,
    tablet_events: u64,
    duplicates_skipped: u64,
    polling_enabled: bool,
};

pub fn getStats() HidStats {
    return .{
        .device_count = hid_device_count,
        .keyboards = getKeyboardCount(),
        .mice = getMouseCount(),
        .tablets = getTabletCount(),
        .total_polls = stats_total_polls,
        .successful_polls = stats_successful_polls,
        .keyboard_events = stats_keyboard_events,
        .mouse_events = stats_mouse_events,
        .tablet_events = stats_tablet_events,
        .duplicates_skipped = stats_duplicates_skipped,
        .polling_enabled = polling_enabled,
    };
}

pub fn enablePolling() void {
    if (hid_device_count > 0) {
        polling_enabled = true;
    }
}

pub fn disablePolling() void {
    polling_enabled = false;
    poll_pending = false;
}

pub fn printStatus() void {
    serial.writeString("\n[USB-HID] Status (B2.11c):\n");
    serial.writeString("  Devices: ");
    printU8(@intCast(hid_device_count));
    serial.writeString(" (");
    printU8(@intCast(getKeyboardCount()));
    serial.writeString(" kbd, ");
    printU8(@intCast(getMouseCount()));
    serial.writeString(" mouse, ");
    printU8(@intCast(getTabletCount()));
    serial.writeString(" tablet)\n");
    serial.writeString("  Mode: GET_REPORT (control transfers)\n");
    serial.writeString("  Polling: ");
    serial.writeString(if (polling_enabled) "ENABLED\n" else "DISABLED\n");
    if (stats_duplicates_skipped > 0) {
        serial.writeString("  Dedup: ");
        printU8(@intCast(stats_duplicates_skipped));
        serial.writeString(" skipped (QEMU addr=0)\n");
    }
}

fn printU8(val: u8) void {
    if (val >= 100) serial.writeChar('0' + val / 100);
    if (val >= 10) serial.writeChar('0' + (val / 10) % 10);
    serial.writeChar('0' + val % 10);
}
