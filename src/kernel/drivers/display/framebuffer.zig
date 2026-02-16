//! Zamrud OS - Framebuffer Driver
//! Low-level framebuffer access — text rendering moved to terminal.zig

const limine = @import("../../core/limine.zig");
const serial = @import("../serial/serial.zig");

// ============================================================================
// State
// ============================================================================

var fb_addr: ?[*]u8 = null;
var fb_width: u32 = 0;
var fb_height: u32 = 0;
var fb_pitch: u32 = 0;
var fb_bpp: u16 = 0;
var initialized: bool = false;

// ============================================================================
// Initialization
// ============================================================================

pub fn init(request: *limine.FramebufferRequest) void {
    serial.writeString("[FB] Initializing framebuffer...\n");

    if (request.response) |response| {
        serial.writeString("[FB] Found 0x");
        printHex(@as(u8, @intCast(response.framebuffer_count)));
        serial.writeString(" framebuffer(s)\n");

        if (response.framebuffer_count > 0) {
            const fb = response.framebuffers_ptr[0];

            fb_addr = fb.address;
            fb_width = @intCast(fb.width);
            fb_height = @intCast(fb.height);
            fb_pitch = @intCast(fb.pitch);
            fb_bpp = fb.bpp;

            serial.writeString("[FB] Address: 0x");
            printHex64(@intFromPtr(fb_addr));
            serial.writeString("\n");

            serial.writeString("[FB] Resolution: ");
            printDec(fb_width);
            serial.writeString("x");
            printDec(fb_height);
            serial.writeString(" @ ");
            printDec(@as(u32, fb_bpp));
            serial.writeString(" bpp\n");

            serial.writeString("[FB] Pitch: ");
            printDec(fb_pitch);
            serial.writeString(" bytes\n");

            initialized = true;
            serial.writeString("[FB] Framebuffer ready!\n");
        }
    } else {
        serial.writeString("[FB] No framebuffer response from bootloader\n");
    }
}

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Getters for Terminal
// ============================================================================

pub fn getAddress() [*]u32 {
    if (fb_addr) |addr| {
        return @ptrCast(@alignCast(addr));
    }
    unreachable;
}

pub fn getWidth() u32 {
    return fb_width;
}

pub fn getHeight() u32 {
    return fb_height;
}

pub fn getPitch() u32 {
    return fb_pitch;
}

pub fn getBpp() u16 {
    return fb_bpp;
}

// ============================================================================
// Low-level Drawing (used by terminal.zig and others)
// ============================================================================

pub fn putPixel(x: u32, y: u32, color: u32) void {
    if (!initialized) return;
    if (x >= fb_width or y >= fb_height) return;

    if (fb_addr) |addr| {
        const offset = y * fb_pitch + x * (fb_bpp / 8);
        const pixel: *u32 = @ptrCast(@alignCast(addr + offset));
        pixel.* = color;
    }
}

pub fn fillRect(x: u32, y: u32, width: u32, height: u32, color: u32) void {
    if (!initialized) return;

    var py = y;
    while (py < y + height and py < fb_height) : (py += 1) {
        var px = x;
        while (px < x + width and px < fb_width) : (px += 1) {
            putPixel(px, py, color);
        }
    }
}

pub fn clear(color: u32) void {
    if (!initialized) return;

    if (fb_addr) |addr| {
        const pixels_per_row = fb_pitch / (fb_bpp / 8);
        var y: u32 = 0;
        while (y < fb_height) : (y += 1) {
            var x: u32 = 0;
            while (x < fb_width) : (x += 1) {
                const offset = y * pixels_per_row + x;
                const pixel: *u32 = @ptrCast(@alignCast(addr + offset * 4));
                pixel.* = color;
            }
        }
    }
}

// ============================================================================
// Debug/Test
// ============================================================================

pub fn test_framebuffer() void {
    if (!initialized) {
        serial.writeString("[FB] Not initialized!\n");
        return;
    }

    serial.writeString("[FB] Running test...\n");

    const bar_width = fb_width / 8;
    const colors_test = [_]u32{
        0x00FF0000, 0x0000FF00, 0x000000FF, 0x00FFFF00,
        0x0000FFFF, 0x00FF00FF, 0x00FFFFFF, 0x00808080,
    };

    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        fillRect(i * bar_width, 0, bar_width, 50, colors_test[i]);
    }

    serial.writeString("[FB] Test complete\n");
}

// ============================================================================
// Helper Functions
// ============================================================================

fn printHex(val: u8) void {
    const hex = "0123456789ABCDEF";
    serial.writeChar(hex[(val >> 4) & 0xF]);
    serial.writeChar(hex[val & 0xF]);
}

fn printHex64(val: u64) void {
    const hex = "0123456789ABCDEF";
    var i: u6 = 60;
    while (true) {
        serial.writeChar(hex[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

fn printDec(val: u32) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }

    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
