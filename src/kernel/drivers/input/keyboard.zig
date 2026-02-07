//! Zamrud OS - Keyboard Driver (Clean)
//! PS/2 Keyboard Driver - Only handles hardware and key buffering

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

// Keyboard state
var shift_pressed: bool = false;
var ctrl_pressed: bool = false;
var alt_pressed: bool = false;
var caps_lock: bool = false;

// Key buffer for shell to read
const KEY_BUFFER_SIZE: usize = 64;
var key_buffer: [KEY_BUFFER_SIZE]u8 = undefined;
var buffer_head: usize = 0;
var buffer_tail: usize = 0;

// Special scancodes
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_CTRL: u8 = 0x1D;
const SC_ALT: u8 = 0x38;
const SC_CAPS: u8 = 0x3A;
const SC_BACKSPACE: u8 = 0x0E;
const SC_ENTER: u8 = 0x1C;
const SC_ESCAPE: u8 = 0x01;
const SC_TAB: u8 = 0x0F;
const SC_UP: u8 = 0x48;
const SC_DOWN: u8 = 0x50;
const SC_LEFT: u8 = 0x4B;
const SC_RIGHT: u8 = 0x4D;
const SC_F1: u8 = 0x3B;
const SC_F2: u8 = 0x3C;
const SC_F3: u8 = 0x3D;
const SC_F4: u8 = 0x3E;

// Scancode tables
const SCANCODE_NORMAL = [_]u8{
    0, 0x1B, '1', '2', '3', '4', '5', '6', // 0x00-0x07
    '7', '8', '9', '0', '-', '=', 0x08, '\t', // 0x08-0x0F
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', // 0x10-0x17
    'o', 'p', '[', ']', '\n', 0, 'a', 's', // 0x18-0x1F
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', // 0x20-0x27
    '\'', '`', 0, '\\', 'z', 'x', 'c', 'v', // 0x28-0x2F
    'b', 'n', 'm', ',', '.', '/', 0, '*', // 0x30-0x37
    0, ' ', 0, 0, 0, 0, 0, 0, // 0x38-0x3F
};

const SCANCODE_SHIFT = [_]u8{
    0, 0x1B, '!', '@', '#', '$', '%', '^', // 0x00-0x07
    '&', '*', '(', ')', '_', '+', 0x08, '\t', // 0x08-0x0F
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', // 0x10-0x17
    'O', 'P', '{', '}', '\n', 0, 'A', 'S', // 0x18-0x1F
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', // 0x20-0x27
    '"', '~', 0, '|', 'Z', 'X', 'C', 'V', // 0x28-0x2F
    'B', 'N', 'M', '<', '>', '?', 0, '*', // 0x30-0x37
    0, ' ', 0, 0, 0, 0, 0, 0, // 0x38-0x3F
};

// Special key codes (values > 0x80 for shell to detect)
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_F1: u8 = 0x84;
pub const KEY_F2: u8 = 0x85;
pub const KEY_F3: u8 = 0x86;
pub const KEY_F4: u8 = 0x87;
pub const KEY_ESCAPE: u8 = 0x1B;
pub const KEY_BACKSPACE: u8 = 0x08;
pub const KEY_TAB: u8 = '\t';
pub const KEY_ENTER: u8 = '\n';

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("  KB: Starting init sequence...\n");

    // 1. Disable devices during configuration
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAD);
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA7);

    // 2. Flush output buffer
    flushBuffer();

    // 3. Get configuration byte
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20);
    waitRead();
    var config = cpu.inb(DATA_PORT);
    serial.writeString("  KB: Current config: 0x");
    printHex(config);
    serial.writeString("\n");

    // 4. Modify configuration
    config |= 0x01;
    config &= ~@as(u8, 0x02);
    config &= ~@as(u8, 0x40);

    // 5. Write configuration back
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x60);
    waitWrite();
    cpu.outb(DATA_PORT, config);
    serial.writeString("  KB: New config: 0x");
    printHex(config);
    serial.writeString("\n");

    // 6. Controller self-test
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAA);
    waitRead();
    const ctrl_test = cpu.inb(DATA_PORT);
    if (ctrl_test == 0x55) {
        serial.writeString("  KB: Controller self-test passed\n");
    } else {
        serial.writeString("  KB: Controller self-test failed: 0x");
        printHex(ctrl_test);
        serial.writeString("\n");
    }

    // 7. Check if keyboard exists
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAB);
    waitRead();
    const kb_test = cpu.inb(DATA_PORT);
    if (kb_test == 0x00) {
        serial.writeString("  KB: Keyboard port test passed\n");
    } else {
        serial.writeString("  KB: Keyboard port test result: 0x");
        printHex(kb_test);
        serial.writeString("\n");
    }

    // 8. Enable keyboard port
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAE);
    serial.writeString("  KB: Keyboard port enabled\n");

    // 9. Reset keyboard device
    serial.writeString("  KB: Resetting keyboard device...\n");
    waitWrite();
    cpu.outb(DATA_PORT, 0xFF);

    if (waitReadTimeout()) {
        const resp = cpu.inb(DATA_PORT);
        if (resp == 0xFA) {
            serial.writeString("  KB: Reset ACK received\n");
            if (waitReadTimeout()) {
                const result = cpu.inb(DATA_PORT);
                if (result == 0xAA) {
                    serial.writeString("  KB: Keyboard self-test passed\n");
                } else {
                    serial.writeString("  KB: Keyboard self-test: 0x");
                    printHex(result);
                    serial.writeString("\n");
                }
            }
        } else {
            serial.writeString("  KB: Reset response: 0x");
            printHex(resp);
            serial.writeString("\n");
        }
    }

    // 10. Set scancode set 1
    waitWrite();
    cpu.outb(DATA_PORT, 0xF0);
    if (waitReadTimeout()) {
        _ = cpu.inb(DATA_PORT);
    }

    waitWrite();
    cpu.outb(DATA_PORT, 0x01);
    if (waitReadTimeout()) {
        _ = cpu.inb(DATA_PORT);
    }
    serial.writeString("  KB: Using scancode set 1\n");

    // 11. Enable scanning
    waitWrite();
    cpu.outb(DATA_PORT, 0xF4);
    if (waitReadTimeout()) {
        const ack = cpu.inb(DATA_PORT);
        if (ack == 0xFA) {
            serial.writeString("  KB: Scanning enabled\n");
        }
    }

    // 12. Clear LEDs
    waitWrite();
    cpu.outb(DATA_PORT, 0xED);
    if (waitReadTimeout()) {
        _ = cpu.inb(DATA_PORT);
    }
    waitWrite();
    cpu.outb(DATA_PORT, 0x00);
    if (waitReadTimeout()) {
        _ = cpu.inb(DATA_PORT);
    }

    // 13. Final flush
    flushBuffer();

    // 14. Clear key buffer
    buffer_head = 0;
    buffer_tail = 0;

    // 15. Check final status
    const final_status = cpu.inb(STATUS_PORT);
    serial.writeString("  KB: Final status: 0x");
    printHex(final_status);
    serial.writeString("\n");

    serial.writeString("  KB: Init complete\n");
}

// ============================================================================
// Wait Functions
// ============================================================================

fn waitWrite() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x02) == 0) {
            return;
        }
    }
}

fn waitRead() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) != 0) {
            return;
        }
    }
}

fn waitReadTimeout() bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) != 0) {
            return true;
        }
    }
    return false;
}

fn flushBuffer() void {
    while ((cpu.inb(STATUS_PORT) & 0x01) != 0) {
        _ = cpu.inb(DATA_PORT);
    }
}

// ============================================================================
// Key Buffer Management
// ============================================================================

fn bufferKey(key: u8) void {
    const next = (buffer_head + 1) % KEY_BUFFER_SIZE;
    if (next != buffer_tail) {
        key_buffer[buffer_head] = key;
        buffer_head = next;
    }
}

/// Get next key from buffer (called by shell)
pub fn getKey() ?u8 {
    if (buffer_head == buffer_tail) {
        return null;
    }
    const key = key_buffer[buffer_tail];
    buffer_tail = (buffer_tail + 1) % KEY_BUFFER_SIZE;
    return key;
}

/// Check if key is available
pub fn hasKey() bool {
    return buffer_head != buffer_tail;
}

/// Get modifier state
pub fn isShiftPressed() bool {
    return shift_pressed;
}

pub fn isCtrlPressed() bool {
    return ctrl_pressed;
}

pub fn isAltPressed() bool {
    return alt_pressed;
}

pub fn isCapsLock() bool {
    return caps_lock;
}

// ============================================================================
// Interrupt Handler
// ============================================================================

pub fn handleInterrupt() void {
    const scancode = cpu.inb(DATA_PORT);

    // Handle key release
    if ((scancode & 0x80) != 0) {
        const released = scancode & 0x7F;
        if (released == SC_LSHIFT or released == SC_RSHIFT) {
            shift_pressed = false;
        } else if (released == SC_CTRL) {
            ctrl_pressed = false;
        } else if (released == SC_ALT) {
            alt_pressed = false;
        }
        return;
    }

    // Handle modifier key press
    if (scancode == SC_LSHIFT or scancode == SC_RSHIFT) {
        shift_pressed = true;
        return;
    }
    if (scancode == SC_CTRL) {
        ctrl_pressed = true;
        return;
    }
    if (scancode == SC_ALT) {
        alt_pressed = true;
        return;
    }
    if (scancode == SC_CAPS) {
        caps_lock = !caps_lock;
        return;
    }

    // Handle special keys - send special codes
    if (scancode == SC_UP) {
        bufferKey(KEY_UP);
        return;
    }
    if (scancode == SC_DOWN) {
        bufferKey(KEY_DOWN);
        return;
    }
    if (scancode == SC_LEFT) {
        bufferKey(KEY_LEFT);
        return;
    }
    if (scancode == SC_RIGHT) {
        bufferKey(KEY_RIGHT);
        return;
    }
    if (scancode == SC_F1) {
        bufferKey(KEY_F1);
        return;
    }
    if (scancode == SC_F2) {
        bufferKey(KEY_F2);
        return;
    }
    if (scancode == SC_F3) {
        bufferKey(KEY_F3);
        return;
    }
    if (scancode == SC_F4) {
        bufferKey(KEY_F4);
        return;
    }

    // Convert scancode to ASCII
    var ascii: u8 = 0;
    if (scancode < SCANCODE_NORMAL.len) {
        if (shift_pressed) {
            ascii = SCANCODE_SHIFT[scancode];
        } else {
            ascii = SCANCODE_NORMAL[scancode];
        }

        // Apply caps lock
        if (caps_lock) {
            if (ascii >= 'a' and ascii <= 'z') {
                ascii -= 32;
            } else if (ascii >= 'A' and ascii <= 'Z') {
                ascii += 32;
            }
        }
    }

    // Buffer the key if valid
    if (ascii != 0) {
        bufferKey(ascii);
    }
}

// ============================================================================
// Debug
// ============================================================================

fn printHex(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0x0F]);
    serial.writeChar(hex[value & 0x0F]);
}
