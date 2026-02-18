//! Zamrud OS - Keyboard Driver (T3 Enhanced)
//! PS/2 Keyboard Driver with full extended key support
//! Supports: arrows, Home/End, PgUp/PgDn, Delete, Ctrl+letter, Shift+arrows

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");
const terminal = @import("../display/terminal.zig");

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

// Keyboard state
var shift_pressed: bool = false;
var ctrl_pressed: bool = false;
var alt_pressed: bool = false;
var caps_lock: bool = false;
var e0_prefix: bool = false; // T3: Extended scancode prefix
var boot_grace_count: u32 = 0; // Count early IRQs to discard phantoms
var boot_grace_active: bool = true; // Ignore phantom keys from mouse init

// Key buffer for shell to read
const KEY_BUFFER_SIZE: usize = 64;
var key_buffer: [KEY_BUFFER_SIZE]u8 = undefined;
var buffer_head: usize = 0;
var buffer_tail: usize = 0;

// Special scancodes (Set 1)
const SC_LSHIFT: u8 = 0x2A;
const SC_RSHIFT: u8 = 0x36;
const SC_CTRL: u8 = 0x1D;
const SC_ALT: u8 = 0x38;
const SC_CAPS: u8 = 0x3A;
const SC_BACKSPACE: u8 = 0x0E;
const SC_ENTER: u8 = 0x1C;
const SC_ESCAPE: u8 = 0x01;
const SC_TAB: u8 = 0x0F;
const SC_SPACE: u8 = 0x39;

// Non-E0 arrow scancodes (numpad without numlock)
const SC_UP: u8 = 0x48;
const SC_DOWN: u8 = 0x50;
const SC_LEFT: u8 = 0x4B;
const SC_RIGHT: u8 = 0x4D;

// Function keys
const SC_F1: u8 = 0x3B;
const SC_F2: u8 = 0x3C;
const SC_F3: u8 = 0x3D;
const SC_F4: u8 = 0x3E;
const SC_F5: u8 = 0x3F;
const SC_F6: u8 = 0x40;
const SC_F7: u8 = 0x41;
const SC_F8: u8 = 0x42;
const SC_F9: u8 = 0x43;
const SC_F10: u8 = 0x44;
const SC_F11: u8 = 0x57;
const SC_F12: u8 = 0x58;

// E0 prefix scancodes
const SC_E0_UP: u8 = 0x48;
const SC_E0_DOWN: u8 = 0x50;
const SC_E0_LEFT: u8 = 0x4B;
const SC_E0_RIGHT: u8 = 0x4D;
const SC_E0_HOME: u8 = 0x47;
const SC_E0_END: u8 = 0x4F;
const SC_E0_PGUP: u8 = 0x49;
const SC_E0_PGDN: u8 = 0x51;
const SC_E0_INSERT: u8 = 0x52;
const SC_E0_DELETE: u8 = 0x53;
const SC_E0_RCTRL: u8 = 0x1D;

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

// =============================================================================
// T3: Extended Key Codes (values > 0x80 for shell to detect)
// =============================================================================

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

// T3: New extended keys
pub const KEY_HOME: u8 = 0x88;
pub const KEY_END: u8 = 0x89;
pub const KEY_PGUP: u8 = 0x8A;
pub const KEY_PGDN: u8 = 0x8B;
pub const KEY_DELETE: u8 = 0x8C;
pub const KEY_INSERT: u8 = 0x8D;
pub const KEY_F5: u8 = 0x8E;
pub const KEY_F6: u8 = 0x8F;
pub const KEY_F7: u8 = 0x90;
pub const KEY_F8: u8 = 0x91;
pub const KEY_F9: u8 = 0x92;
pub const KEY_F10: u8 = 0x93;
pub const KEY_F11: u8 = 0x94;
pub const KEY_F12: u8 = 0x95;

// T3: Ctrl+key codes (0xC0 range)
pub const KEY_CTRL_A: u8 = 0x01;
pub const KEY_CTRL_B: u8 = 0x02;
pub const KEY_CTRL_C: u8 = 0x03;
pub const KEY_CTRL_D: u8 = 0x04;
pub const KEY_CTRL_E: u8 = 0x05;
pub const KEY_CTRL_F: u8 = 0x06;
pub const KEY_CTRL_K: u8 = 0x0B;
pub const KEY_CTRL_L: u8 = 0x0C;
pub const KEY_CTRL_N: u8 = 0x0E;
pub const KEY_CTRL_P: u8 = 0x10;
pub const KEY_CTRL_R: u8 = 0x12;
pub const KEY_CTRL_U: u8 = 0x15;
pub const KEY_CTRL_W: u8 = 0x17;

// T3: Shift+special combos
pub const KEY_SHIFT_UP: u8 = 0xA0;
pub const KEY_SHIFT_DOWN: u8 = 0xA1;
pub const KEY_SHIFT_PGUP: u8 = 0xA2;
pub const KEY_SHIFT_PGDN: u8 = 0xA3;
pub const KEY_SHIFT_HOME: u8 = 0xA4;
pub const KEY_SHIFT_END: u8 = 0xA5;

// T3: Ctrl+arrow combos
pub const KEY_CTRL_LEFT: u8 = 0xB0;
pub const KEY_CTRL_RIGHT: u8 = 0xB1;

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString(" KB: Starting init sequence...\n");

    // 1. Disable devices during configuration
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAD);
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA7);

    // 2. Flush output buffer
    flushBuffer();

    // 3. Controller self-test (MUST be before config write!)
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAA);
    waitRead();
    const ctrl_test = cpu.inb(DATA_PORT);
    if (ctrl_test == 0x55) {
        serial.writeString(" KB: Controller self-test passed\n");
    } else {
        serial.writeString(" KB: Controller self-test failed: 0x");
        printHex(ctrl_test);
        serial.writeString("\n");
    }

    // 4. Get configuration byte (AFTER self-test reset)
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20);
    waitRead();
    var config = cpu.inb(DATA_PORT);
    serial.writeString(" KB: Current config: 0x");
    printHex(config);
    serial.writeString("\n");

    // 5. Modify configuration — preserve mouse settings
    config |= 0x01; // Enable keyboard IRQ (bit 0)
    config |= 0x02; // Enable aux/mouse IRQ (bit 1) — B2.1
    config &= ~@as(u8, 0x20); // Bit 5: Clear = enable aux clock
    config &= ~@as(u8, 0x10); // Bit 4: Clear = enable keyboard clock
    config &= ~@as(u8, 0x40); // Disable translation (bit 6)

    // 6. Write configuration back
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x60);
    waitWrite();
    cpu.outb(DATA_PORT, config);
    serial.writeString(" KB: New config: 0x");
    printHex(config);
    serial.writeString("\n");

    // 7. Check if keyboard exists
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAB);
    waitRead();
    const kb_test = cpu.inb(DATA_PORT);
    if (kb_test == 0x00) {
        serial.writeString(" KB: Keyboard port test passed\n");
    } else {
        serial.writeString(" KB: Keyboard port test result: 0x");
        printHex(kb_test);
        serial.writeString("\n");
    }

    // 8. Enable keyboard port
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAE);
    serial.writeString(" KB: Keyboard port enabled\n");

    // 8b. Re-enable aux port (self-test 0xAA may have disabled it)
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA8);
    serial.writeString(" KB: Aux port re-enabled\n");

    // 9. Reset keyboard device
    serial.writeString(" KB: Resetting keyboard device...\n");
    waitWrite();
    cpu.outb(DATA_PORT, 0xFF);

    if (waitReadTimeout()) {
        const resp = cpu.inb(DATA_PORT);
        if (resp == 0xFA) {
            serial.writeString(" KB: Reset ACK received\n");
            if (waitReadTimeout()) {
                const result = cpu.inb(DATA_PORT);
                if (result == 0xAA) {
                    serial.writeString(" KB: Keyboard self-test passed\n");
                } else {
                    serial.writeString(" KB: Keyboard self-test: 0x");
                    printHex(result);
                    serial.writeString("\n");
                }
            }
        } else {
            serial.writeString(" KB: Reset response: 0x");
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
    serial.writeString(" KB: Using scancode set 1\n");

    // 11. Enable scanning
    waitWrite();
    cpu.outb(DATA_PORT, 0xF4);
    if (waitReadTimeout()) {
        const ack = cpu.inb(DATA_PORT);
        if (ack == 0xFA) {
            serial.writeString(" KB: Scanning enabled\n");
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

    // 13. Re-write controller config to ensure mouse bits survive
    //     (keyboard reset and self-test can clear aux bits)
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20); // Read current config
    waitRead();
    var final_config = cpu.inb(DATA_PORT);

    final_config |= 0x01; // Bit 0: keyboard IRQ
    final_config |= 0x02; // Bit 1: aux/mouse IRQ
    final_config &= ~@as(u8, 0x20); // Bit 5: enable aux clock
    final_config &= ~@as(u8, 0x10); // Bit 4: enable keyboard clock

    waitWrite();
    cpu.outb(COMMAND_PORT, 0x60);
    waitWrite();
    cpu.outb(DATA_PORT, final_config);

    serial.writeString(" KB: Final config: 0x");
    printHex(final_config);
    serial.writeString("\n");

    // 14. Final flush — clear any pending data from all init operations
    flushBuffer();

    // 15. Clear key buffer and reset state
    buffer_head = 0;
    buffer_tail = 0;
    e0_prefix = false;

    // 16. Enable boot grace period
    // After interrupts are enabled (sti), mouse init response bytes
    // (0xFA, 0xAA, 0x00 etc.) may still arrive and trigger IRQ1.
    // We discard the first few scancodes that arrive before any
    // real human keypress could possibly occur.
    boot_grace_count = 0;
    boot_grace_active = true;

    // 17. Check final status
    const final_status = cpu.inb(STATUS_PORT);
    serial.writeString(" KB: Final status: 0x");
    printHex(final_status);
    serial.writeString("\n");

    serial.writeString(" KB: Init complete (T3 enhanced)\n");
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
    var count: u32 = 0;
    while (count < 64) : (count += 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) == 0) break;
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
// T3: Enhanced Interrupt Handler with E0 prefix support
// ============================================================================

pub fn handleInterrupt() void {
    // CRITICAL: Check status register BEFORE reading data port
    // Bit 5 (0x20) of status indicates data is from aux (mouse) device
    // If set, this is mouse data — do NOT process as keyboard
    const status = cpu.inb(STATUS_PORT);

    if ((status & 0x01) == 0) {
        // No data available at all — spurious IRQ
        return;
    }

    if ((status & 0x20) != 0) {
        // Data is from aux (mouse) port — read and discard
        // This prevents mouse bytes from being interpreted as keypresses
        _ = cpu.inb(DATA_PORT);
        return;
    }

    const scancode = cpu.inb(DATA_PORT);

    // Boot grace period: discard phantom scancodes that arrive shortly
    // after interrupts are enabled. During boot, mouse init sends many
    // PS/2 commands whose response bytes can be misrouted to keyboard IRQ.
    // These phantom bytes produce garbage characters like "22".
    // We discard first few non-release scancodes until a real keypress
    // (which will have a matching key release) is detected.
    if (boot_grace_active) {
        boot_grace_count += 1;

        // Discard up to 8 phantom scancodes during grace period.
        // Real human keypresses cannot arrive this fast after boot.
        if (boot_grace_count <= 8) {
            // Still allow modifier key releases through (they're harmless)
            // but discard anything that would produce a character
            if ((scancode & 0x80) == 0) {
                // Key press (not release) — likely phantom, discard
                return;
            }
            // Key release — let it through (just clears modifier state)
        } else {
            // Grace period over — all subsequent scancodes are real
            boot_grace_active = false;
        }
    }

    // Handle E0 prefix — next scancode is an extended key
    if (scancode == 0xE0) {
        e0_prefix = true;
        return;
    }

    // Handle E0-prefixed scancodes
    if (e0_prefix) {
        e0_prefix = false;
        handleE0Scancode(scancode);
        return;
    }

    // Handle key release (bit 7 set)
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

    // Handle arrow keys (non-E0, numpad arrows)
    if (scancode == SC_UP) {
        if (shift_pressed) {
            bufferKey(KEY_SHIFT_UP);
        } else {
            bufferKey(KEY_UP);
        }
        return;
    }
    if (scancode == SC_DOWN) {
        if (shift_pressed) {
            bufferKey(KEY_SHIFT_DOWN);
        } else {
            bufferKey(KEY_DOWN);
        }
        return;
    }
    if (scancode == SC_LEFT) {
        if (ctrl_pressed) {
            bufferKey(KEY_CTRL_LEFT);
        } else {
            bufferKey(KEY_LEFT);
        }
        return;
    }
    if (scancode == SC_RIGHT) {
        if (ctrl_pressed) {
            bufferKey(KEY_CTRL_RIGHT);
        } else {
            bufferKey(KEY_RIGHT);
        }
        return;
    }

    // Function keys
    switch (scancode) {
        SC_F1 => {
            bufferKey(KEY_F1);
            return;
        },
        SC_F2 => {
            bufferKey(KEY_F2);
            return;
        },
        SC_F3 => {
            bufferKey(KEY_F3);
            return;
        },
        SC_F4 => {
            bufferKey(KEY_F4);
            return;
        },
        SC_F5 => {
            bufferKey(KEY_F5);
            return;
        },
        SC_F6 => {
            bufferKey(KEY_F6);
            return;
        },
        SC_F7 => {
            bufferKey(KEY_F7);
            return;
        },
        SC_F8 => {
            bufferKey(KEY_F8);
            return;
        },
        SC_F9 => {
            bufferKey(KEY_F9);
            return;
        },
        SC_F10 => {
            bufferKey(KEY_F10);
            return;
        },
        SC_F11 => {
            bufferKey(KEY_F11);
            return;
        },
        SC_F12 => {
            bufferKey(KEY_F12);
            return;
        },
        else => {},
    }

    // Convert scancode to ASCII
    var ascii: u8 = 0;
    if (scancode < SCANCODE_NORMAL.len) {
        if (shift_pressed) {
            ascii = SCANCODE_SHIFT[scancode];
        } else {
            ascii = SCANCODE_NORMAL[scancode];
        }

        // Apply caps lock to letters only
        if (caps_lock) {
            if (ascii >= 'a' and ascii <= 'z') {
                ascii -= 32;
            } else if (ascii >= 'A' and ascii <= 'Z') {
                ascii += 32;
            }
        }
    }

    // T3: Handle Ctrl+letter combinations
    if (ctrl_pressed and ascii != 0) {
        if (ascii >= 'a' and ascii <= 'z') {
            // Ctrl+A = 0x01, Ctrl+B = 0x02, ..., Ctrl+Z = 0x1A
            bufferKey(ascii - 'a' + 1);
            return;
        } else if (ascii >= 'A' and ascii <= 'Z') {
            bufferKey(ascii - 'A' + 1);
            return;
        }
    }

    // Buffer the key if valid
    if (ascii != 0) {
        bufferKey(ascii);
    }
}

// ============================================================================
// T3: E0 Extended Scancode Handler
// ============================================================================

fn handleE0Scancode(scancode: u8) void {
    // E0 key release
    if ((scancode & 0x80) != 0) {
        const released = scancode & 0x7F;
        if (released == SC_E0_RCTRL) {
            ctrl_pressed = false;
        }
        return;
    }

    // E0 modifier press
    if (scancode == SC_E0_RCTRL) {
        ctrl_pressed = true;
        return;
    }

    // E0 arrow keys
    switch (scancode) {
        SC_E0_UP => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_UP);
            } else {
                bufferKey(KEY_UP);
            }
        },
        SC_E0_DOWN => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_DOWN);
            } else {
                bufferKey(KEY_DOWN);
            }
        },
        SC_E0_LEFT => {
            if (ctrl_pressed) {
                bufferKey(KEY_CTRL_LEFT);
            } else {
                bufferKey(KEY_LEFT);
            }
        },
        SC_E0_RIGHT => {
            if (ctrl_pressed) {
                bufferKey(KEY_CTRL_RIGHT);
            } else {
                bufferKey(KEY_RIGHT);
            }
        },
        SC_E0_HOME => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_HOME);
            } else {
                bufferKey(KEY_HOME);
            }
        },
        SC_E0_END => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_END);
            } else {
                bufferKey(KEY_END);
            }
        },
        SC_E0_PGUP => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_PGUP);
            } else {
                bufferKey(KEY_PGUP);
            }
        },
        SC_E0_PGDN => {
            if (shift_pressed) {
                bufferKey(KEY_SHIFT_PGDN);
            } else {
                bufferKey(KEY_PGDN);
            }
        },
        SC_E0_DELETE => {
            bufferKey(KEY_DELETE);
        },
        SC_E0_INSERT => {
            bufferKey(KEY_INSERT);
        },
        else => {},
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
