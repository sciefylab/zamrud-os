//! Zamrud OS - PS/2 Mouse Driver (B2.1)
//! Supports: 3-button mouse, scroll wheel (IntelliMouse), absolute position tracking
//! IRQ12 via slave PIC, integrates with input_api.zig

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");
const timer = @import("../timer/timer.zig");

// =============================================================================
// PS/2 Controller Ports
// =============================================================================

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

// =============================================================================
// Mouse State
// =============================================================================

var mouse_x: i32 = 0;
var mouse_y: i32 = 0;
var screen_width: i32 = 1024;
var screen_height: i32 = 768;

var buttons: u8 = 0; // bit0=left, bit1=right, bit2=middle
var scroll_delta: i8 = 0;

var initialized: bool = false;
var has_scroll_wheel: bool = false;

// Packet assembly state
var packet: [4]u8 = [_]u8{0} ** 4;
var packet_index: u8 = 0;
var packet_size: u8 = 3; // 3 for standard, 4 for IntelliMouse

// Event queue
const EVENT_QUEUE_SIZE: usize = 32;

const MouseEvent = struct {
    x: i32 = 0,
    y: i32 = 0,
    dx: i16 = 0,
    dy: i16 = 0,
    buttons: u8 = 0,
    scroll: i8 = 0,
    timestamp: u64 = 0,
};

var event_queue: [EVENT_QUEUE_SIZE]MouseEvent = [_]MouseEvent{.{}} ** EVENT_QUEUE_SIZE;
var queue_head: usize = 0;
var queue_tail: usize = 0;

// Statistics
var total_packets: u64 = 0;
var total_events: u64 = 0;
var irq_count: u64 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString(" MOUSE: Starting PS/2 mouse init...\n");

    // Disable interrupts during init to prevent partial state
    cpu.cli();

    // 1. Disable both PS/2 ports during setup
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAD); // Disable keyboard port
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA7); // Disable mouse port

    // Flush any pending data
    flushBuffer();

    // 2. Read controller config, enable aux interrupt, enable aux clock
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20); // Read config byte
    waitRead();
    var config = cpu.inb(DATA_PORT);

    serial.writeString(" MOUSE: Initial PS/2 config: 0x");
    printHex(config);
    serial.writeString("\n");

    config |= 0x02; // Bit 1: Enable aux interrupt (IRQ12)
    config |= 0x01; // Bit 0: Keep keyboard interrupt (IRQ1)
    config &= ~@as(u8, 0x20); // Bit 5: Clear = enable aux clock
    config &= ~@as(u8, 0x10); // Bit 4: Clear = enable keyboard clock

    waitWrite();
    cpu.outb(COMMAND_PORT, 0x60); // Write config byte
    waitWrite();
    cpu.outb(DATA_PORT, config);

    // Small delay to let controller process
    ioDelay();

    // 3. Re-enable both ports
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xAE); // Enable keyboard port
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA8); // Enable mouse (aux) port

    // Small delay
    ioDelay();

    // 4. Test aux port
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xA9); // Test aux port
    waitRead();
    const test_result = cpu.inb(DATA_PORT);
    if (test_result == 0x00) {
        serial.writeString(" MOUSE: Aux port test passed\n");
    } else {
        serial.writeString(" MOUSE: Aux port test result: 0x");
        printHex(test_result);
        serial.writeString("\n");
    }

    // 5. Reset mouse
    mouseWrite(0xFF); // Reset
    if (mouseReadTimeout()) |resp| {
        if (resp == 0xFA) { // ACK
            serial.writeString(" MOUSE: Reset ACK\n");
            // Wait for self-test result (0xAA) and device ID (0x00)
            if (mouseReadTimeout()) |st| {
                if (st == 0xAA) {
                    serial.writeString(" MOUSE: Self-test passed\n");
                }
            }
            _ = mouseReadTimeout(); // Device ID (0x00)
        }
    }

    // 6. Set defaults
    mouseWrite(0xF6); // Set defaults
    _ = mouseReadTimeout(); // ACK

    // 7. Try to enable scroll wheel (IntelliMouse protocol)
    // Magic sequence: set sample rate 200, 100, 80, then read device ID
    setSampleRate(200);
    setSampleRate(100);
    setSampleRate(80);

    // Read device ID
    mouseWrite(0xF2); // Get device ID
    if (mouseReadTimeout()) |ack| {
        if (ack == 0xFA) {
            if (mouseReadTimeout()) |dev_id| {
                if (dev_id == 0x03) {
                    has_scroll_wheel = true;
                    packet_size = 4;
                    serial.writeString(" MOUSE: IntelliMouse detected (scroll wheel)\n");
                } else if (dev_id == 0x00) {
                    serial.writeString(" MOUSE: Standard PS/2 mouse (no scroll)\n");
                } else {
                    serial.writeString(" MOUSE: Device ID: 0x");
                    printHex(dev_id);
                    serial.writeString("\n");
                }
            }
        }
    }

    // 8. Set sample rate to 100 samples/sec
    setSampleRate(100);

    // 9. Set resolution (8 counts/mm)
    mouseWrite(0xE8); // Set resolution
    _ = mouseReadTimeout();
    mouseWrite(0x03); // 8 counts/mm
    _ = mouseReadTimeout();

    // 10. Enable data reporting
    mouseWrite(0xF4); // Enable
    if (mouseReadTimeout()) |ack| {
        if (ack == 0xFA) {
            serial.writeString(" MOUSE: Data reporting enabled\n");
        }
    }

    // 11. Re-read and force-set controller config AFTER mouse reset
    //     (mouse reset 0xFF can clear aux interrupt bit)
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20); // Read config
    waitRead();
    var final_config = cpu.inb(DATA_PORT);

    serial.writeString(" MOUSE: Post-reset config: 0x");
    printHex(final_config);
    serial.writeString("\n");

    final_config |= 0x02; // Bit 1: Enable aux interrupt (IRQ12)
    final_config |= 0x01; // Bit 0: Keep keyboard interrupt (IRQ1)
    final_config &= ~@as(u8, 0x20); // Bit 5: Clear = enable aux clock
    final_config &= ~@as(u8, 0x10); // Bit 4: Clear = enable keyboard clock

    waitWrite();
    cpu.outb(COMMAND_PORT, 0x60); // Write config
    waitWrite();
    cpu.outb(DATA_PORT, final_config);

    // Delay to let controller apply
    ioDelay();

    // 12. Verify config was actually written
    waitWrite();
    cpu.outb(COMMAND_PORT, 0x20);
    waitRead();
    const verify_config = cpu.inb(DATA_PORT);

    serial.writeString(" MOUSE: Verified config: 0x");
    printHex(verify_config);
    serial.writeString(" [aux_irq=");
    if ((verify_config & 0x02) != 0) serial.writeString("ON") else serial.writeString("OFF");
    serial.writeString(", aux_clk=");
    if ((verify_config & 0x20) == 0) serial.writeString("ON") else serial.writeString("OFF");
    serial.writeString("]\n");

    // 13. Unmask IRQ12 on slave PIC
    const mask2 = cpu.inb(0xA1);
    cpu.outb(0xA1, mask2 & ~@as(u8, 0x10)); // Clear bit 4 (IRQ12 = slave IRQ4)

    // Also ensure IRQ2 (cascade) is unmasked on master PIC
    const mask1 = cpu.inb(0x21);
    cpu.outb(0x21, mask1 & ~@as(u8, 0x04)); // Clear bit 2 (cascade)

    // 14. Flush any leftover data from init sequence
    flushBuffer();

    // 15. Reset packet/queue state
    packet_index = 0;
    queue_head = 0;
    queue_tail = 0;
    mouse_x = @divTrunc(screen_width, 2);
    mouse_y = @divTrunc(screen_height, 2);

    initialized = true;

    // Re-enable interrupts
    cpu.sti();

    serial.writeString(" MOUSE: Init complete (");
    if (has_scroll_wheel) {
        serial.writeString("4-byte IntelliMouse");
    } else {
        serial.writeString("3-byte standard");
    }
    serial.writeString(")\n");
}

// =============================================================================
// IRQ12 Interrupt Handler (called from idt.zig)
// =============================================================================

pub fn handleInterrupt() void {
    irq_count += 1;

    // Check if data is available
    const status = cpu.inb(STATUS_PORT);
    if ((status & 0x01) == 0) return; // No data available

    // Bit 5 should be set for aux (mouse) data
    // Some emulators don't set this properly, so we read regardless
    // but log if it's not aux data
    const data = cpu.inb(DATA_PORT);

    // If bit 5 is NOT set, this might be keyboard data leaking — skip
    if ((status & 0x20) == 0) {
        return;
    }

    // Validate first byte of packet
    if (packet_index == 0) {
        // Byte 0 must have bit 3 set (always 1 in PS/2 protocol)
        if ((data & 0x08) == 0) {
            // Out of sync — skip this byte
            return;
        }
        // Check for overflow bits
        if ((data & 0xC0) != 0) {
            // X or Y overflow — discard packet
            return;
        }
    }

    packet[packet_index] = data;
    packet_index += 1;

    if (packet_index >= packet_size) {
        packet_index = 0;
        processPacket();
    }
}

// =============================================================================
// Packet Processing
// =============================================================================

fn processPacket() void {
    total_packets += 1;

    const byte0 = packet[0];

    // Extract buttons
    const new_buttons: u8 = byte0 & 0x07; // bits 0-2: left, right, middle

    // Extract deltas with sign extension
    var dx: i16 = @intCast(packet[1]);
    var dy: i16 = @intCast(packet[2]);

    // Apply sign from byte 0
    if ((byte0 & 0x10) != 0) {
        dx = dx - 256; // X sign bit
    }
    if ((byte0 & 0x20) != 0) {
        dy = dy - 256; // Y sign bit
    }

    // Extract scroll wheel (4th byte, signed)
    var scroll: i8 = 0;
    if (has_scroll_wheel and packet_size == 4) {
        const raw_scroll: i8 = @bitCast(packet[3] & 0x0F);
        // Sign extend 4-bit value
        if ((packet[3] & 0x08) != 0) {
            scroll = raw_scroll | @as(i8, -16); // extend sign from bit 3
        } else {
            scroll = raw_scroll;
        }
    }

    // Update absolute position (Y is inverted in PS/2)
    mouse_x += dx;
    mouse_y -= dy; // PS/2 Y is inverted (positive = up)

    // Clamp to screen bounds
    if (mouse_x < 0) mouse_x = 0;
    if (mouse_y < 0) mouse_y = 0;
    if (mouse_x >= screen_width) mouse_x = screen_width - 1;
    if (mouse_y >= screen_height) mouse_y = screen_height - 1;

    // Only queue event if something changed
    if (dx != 0 or dy != 0 or new_buttons != buttons or scroll != 0) {
        buttons = new_buttons;
        scroll_delta = scroll;

        queueEvent(.{
            .x = mouse_x,
            .y = mouse_y,
            .dx = dx,
            .dy = @intCast(-dy), // Convert to screen coordinates
            .buttons = new_buttons,
            .scroll = scroll,
            .timestamp = timer.getTicks(),
        });
    }
}

// =============================================================================
// Event Queue
// =============================================================================

fn queueEvent(event: MouseEvent) void {
    const next = (queue_head + 1) % EVENT_QUEUE_SIZE;
    if (next != queue_tail) {
        event_queue[queue_head] = event;
        queue_head = next;
        total_events += 1;
    }
    // else: queue full, drop event
}

/// Poll for mouse event. Returns null if no events pending.
pub fn pollEvent() ?MouseEvent {
    if (queue_head == queue_tail) return null;

    const event = event_queue[queue_tail];
    queue_tail = (queue_tail + 1) % EVENT_QUEUE_SIZE;
    return event;
}

/// Check if events are available
pub fn hasEvent() bool {
    return queue_head != queue_tail;
}

// =============================================================================
// Public Accessors
// =============================================================================

pub fn getX() i32 {
    return mouse_x;
}

pub fn getY() i32 {
    return mouse_y;
}

pub fn getButtons() u8 {
    return buttons;
}

pub fn isLeftPressed() bool {
    return (buttons & 0x01) != 0;
}

pub fn isRightPressed() bool {
    return (buttons & 0x02) != 0;
}

pub fn isMiddlePressed() bool {
    return (buttons & 0x04) != 0;
}

pub fn getScrollDelta() i8 {
    return scroll_delta;
}

pub fn hasScrollWheel() bool {
    return has_scroll_wheel;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn setScreenSize(w: u32, h: u32) void {
    screen_width = @intCast(w);
    screen_height = @intCast(h);
    // Clamp current position
    if (mouse_x >= screen_width) mouse_x = screen_width - 1;
    if (mouse_y >= screen_height) mouse_y = screen_height - 1;
}

pub fn setPosition(x: i32, y: i32) void {
    mouse_x = @max(0, @min(x, screen_width - 1));
    mouse_y = @max(0, @min(y, screen_height - 1));
}

// =============================================================================
// Statistics
// =============================================================================

pub const MouseStats = struct {
    total_packets: u64,
    total_events: u64,
    irq_count: u64,
    x: i32,
    y: i32,
    buttons: u8,
    has_scroll: bool,
    initialized: bool,
};

pub fn getStats() MouseStats {
    return .{
        .total_packets = total_packets,
        .total_events = total_events,
        .irq_count = irq_count,
        .x = mouse_x,
        .y = mouse_y,
        .buttons = buttons,
        .has_scroll = has_scroll_wheel,
        .initialized = initialized,
    };
}

// =============================================================================
// PS/2 Aux Communication Helpers
// =============================================================================

fn mouseWrite(data: u8) void {
    waitWrite();
    cpu.outb(COMMAND_PORT, 0xD4); // Tell controller next byte goes to aux
    waitWrite();
    cpu.outb(DATA_PORT, data);
}

fn mouseReadTimeout() ?u8 {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) != 0) {
            return cpu.inb(DATA_PORT);
        }
    }
    return null;
}

fn setSampleRate(rate: u8) void {
    mouseWrite(0xF3); // Set sample rate
    _ = mouseReadTimeout(); // ACK
    mouseWrite(rate);
    _ = mouseReadTimeout(); // ACK
}

fn waitWrite() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x02) == 0) return;
    }
}

fn waitRead() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) != 0) return;
    }
}

fn flushBuffer() void {
    var count: u32 = 0;
    while (count < 64) : (count += 1) {
        if ((cpu.inb(STATUS_PORT) & 0x01) == 0) break;
        _ = cpu.inb(DATA_PORT);
        ioDelay();
    }
}

fn ioDelay() void {
    var i: u32 = 0;
    while (i < 10000) : (i += 1) {
        asm volatile ("pause");
    }
}

// =============================================================================
// Debug
// =============================================================================

fn printHex(value: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(value >> 4) & 0x0F]);
    serial.writeChar(hex[value & 0x0F]);
}
