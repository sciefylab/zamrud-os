//! Zamrud OS - Framebuffer Driver
//! Low-level framebuffer access for graphics output

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

// Colors (32-bit ARGB)
pub const Colors = struct {
    pub const BLACK: u32 = 0x00000000;
    pub const WHITE: u32 = 0x00FFFFFF;
    pub const RED: u32 = 0x00FF0000;
    pub const GREEN: u32 = 0x0000FF00;
    pub const BLUE: u32 = 0x000000FF;
    pub const CYAN: u32 = 0x0000FFFF;
    pub const MAGENTA: u32 = 0x00FF00FF;
    pub const YELLOW: u32 = 0x00FFFF00;
    pub const DARK_BLUE: u32 = 0x00000080;
    pub const DARK_GREEN: u32 = 0x00008000;
    pub const DARK_RED: u32 = 0x00800000;
    pub const DARK_CYAN: u32 = 0x00008080;
    pub const DARK_MAGENTA: u32 = 0x00800080;
    pub const DARK_YELLOW: u32 = 0x00808000;
    pub const LIGHT_GRAY: u32 = 0x00C0C0C0;
    pub const DARK_GRAY: u32 = 0x00808080;
};

// Simple 8x8 font for basic text (legacy support)
const FONT_WIDTH: u32 = 8;
const FONT_HEIGHT: u32 = 8;

// Current text position and colors (legacy)
var cursor_x: u32 = 0;
var cursor_y: u32 = 0;
var fg_color: u32 = Colors.WHITE;
var bg_color: u32 = Colors.BLACK;

// Basic 8x8 font data
const font_8x8 = [_][8]u8{
    // 32: Space
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    // 33: !
    .{ 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00 },
    // 34: "
    .{ 0x6C, 0x6C, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00 },
    // 35: #
    .{ 0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00 },
    // 36: $
    .{ 0x18, 0x7E, 0xC0, 0x7C, 0x06, 0xFC, 0x18, 0x00 },
    // 37: %
    .{ 0x00, 0xC6, 0xCC, 0x18, 0x30, 0x66, 0xC6, 0x00 },
    // 38: &
    .{ 0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00 },
    // 39: '
    .{ 0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00 },
    // 40: (
    .{ 0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00 },
    // 41: )
    .{ 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00 },
    // 42: *
    .{ 0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00 },
    // 43: +
    .{ 0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00 },
    // 44: ,
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30 },
    // 45: -
    .{ 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00 },
    // 46: .
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00 },
    // 47: /
    .{ 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00 },
    // 48: 0
    .{ 0x7C, 0xCE, 0xDE, 0xF6, 0xE6, 0xC6, 0x7C, 0x00 },
    // 49: 1
    .{ 0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00 },
    // 50: 2
    .{ 0x7C, 0xC6, 0x06, 0x1C, 0x70, 0xC6, 0xFE, 0x00 },
    // 51: 3
    .{ 0x7C, 0xC6, 0x06, 0x3C, 0x06, 0xC6, 0x7C, 0x00 },
    // 52: 4
    .{ 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x1E, 0x00 },
    // 53: 5
    .{ 0xFE, 0xC0, 0xFC, 0x06, 0x06, 0xC6, 0x7C, 0x00 },
    // 54: 6
    .{ 0x38, 0x60, 0xC0, 0xFC, 0xC6, 0xC6, 0x7C, 0x00 },
    // 55: 7
    .{ 0xFE, 0xC6, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00 },
    // 56: 8
    .{ 0x7C, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0x7C, 0x00 },
    // 57: 9
    .{ 0x7C, 0xC6, 0xC6, 0x7E, 0x06, 0x0C, 0x78, 0x00 },
    // 58: :
    .{ 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00 },
    // 59: ;
    .{ 0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30 },
    // 60: <
    .{ 0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00 },
    // 61: =
    .{ 0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00 },
    // 62: >
    .{ 0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00 },
    // 63: ?
    .{ 0x7C, 0xC6, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x00 },
    // 64: @
    .{ 0x7C, 0xC6, 0xDE, 0xDE, 0xDC, 0xC0, 0x7C, 0x00 },
    // 65: A
    .{ 0x38, 0x6C, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00 },
    // 66: B
    .{ 0xFC, 0x66, 0x66, 0x7C, 0x66, 0x66, 0xFC, 0x00 },
    // 67: C
    .{ 0x3C, 0x66, 0xC0, 0xC0, 0xC0, 0x66, 0x3C, 0x00 },
    // 68: D
    .{ 0xF8, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0xF8, 0x00 },
    // 69: E
    .{ 0xFE, 0x62, 0x68, 0x78, 0x68, 0x62, 0xFE, 0x00 },
    // 70: F
    .{ 0xFE, 0x62, 0x68, 0x78, 0x68, 0x60, 0xF0, 0x00 },
    // 71: G
    .{ 0x3C, 0x66, 0xC0, 0xC0, 0xCE, 0x66, 0x3E, 0x00 },
    // 72: H
    .{ 0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00 },
    // 73: I
    .{ 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    // 74: J
    .{ 0x1E, 0x0C, 0x0C, 0x0C, 0xCC, 0xCC, 0x78, 0x00 },
    // 75: K
    .{ 0xE6, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0xE6, 0x00 },
    // 76: L
    .{ 0xF0, 0x60, 0x60, 0x60, 0x62, 0x66, 0xFE, 0x00 },
    // 77: M
    .{ 0xC6, 0xEE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0x00 },
    // 78: N
    .{ 0xC6, 0xE6, 0xF6, 0xDE, 0xCE, 0xC6, 0xC6, 0x00 },
    // 79: O
    .{ 0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 },
    // 80: P
    .{ 0xFC, 0x66, 0x66, 0x7C, 0x60, 0x60, 0xF0, 0x00 },
    // 81: Q
    .{ 0x7C, 0xC6, 0xC6, 0xC6, 0xD6, 0x7C, 0x0E, 0x00 },
    // 82: R
    .{ 0xFC, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0xE6, 0x00 },
    // 83: S
    .{ 0x7C, 0xC6, 0x60, 0x38, 0x0C, 0xC6, 0x7C, 0x00 },
    // 84: T
    .{ 0x7E, 0x5A, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    // 85: U
    .{ 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 },
    // 86: V
    .{ 0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00 },
    // 87: W
    .{ 0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00 },
    // 88: X
    .{ 0xC6, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0xC6, 0x00 },
    // 89: Y
    .{ 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x3C, 0x00 },
    // 90: Z
    .{ 0xFE, 0xC6, 0x8C, 0x18, 0x32, 0x66, 0xFE, 0x00 },
    // 91: [
    .{ 0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00 },
    // 92: backslash
    .{ 0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00 },
    // 93: ]
    .{ 0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00 },
    // 94: ^
    .{ 0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00 },
    // 95: _
    .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF },
    // 96: `
    .{ 0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 },
    // 97: a
    .{ 0x00, 0x00, 0x78, 0x0C, 0x7C, 0xCC, 0x76, 0x00 },
    // 98: b
    .{ 0xE0, 0x60, 0x7C, 0x66, 0x66, 0x66, 0xDC, 0x00 },
    // 99: c
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC6, 0x7C, 0x00 },
    // 100: d
    .{ 0x1C, 0x0C, 0x7C, 0xCC, 0xCC, 0xCC, 0x76, 0x00 },
    // 101: e
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0x7C, 0x00 },
    // 102: f
    .{ 0x1C, 0x36, 0x30, 0x78, 0x30, 0x30, 0x78, 0x00 },
    // 103: g
    .{ 0x00, 0x00, 0x76, 0xCC, 0xCC, 0x7C, 0x0C, 0x78 },
    // 104: h
    .{ 0xE0, 0x60, 0x6C, 0x76, 0x66, 0x66, 0xE6, 0x00 },
    // 105: i
    .{ 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    // 106: j
    .{ 0x06, 0x00, 0x0E, 0x06, 0x06, 0x66, 0x66, 0x3C },
    // 107: k
    .{ 0xE0, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0xE6, 0x00 },
    // 108: l
    .{ 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    // 109: m
    .{ 0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xD6, 0xD6, 0x00 },
    // 110: n
    .{ 0x00, 0x00, 0xDC, 0x66, 0x66, 0x66, 0x66, 0x00 },
    // 111: o
    .{ 0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0x00 },
    // 112: p
    .{ 0x00, 0x00, 0xDC, 0x66, 0x66, 0x7C, 0x60, 0xF0 },
    // 113: q
    .{ 0x00, 0x00, 0x76, 0xCC, 0xCC, 0x7C, 0x0C, 0x1E },
    // 114: r
    .{ 0x00, 0x00, 0xDC, 0x76, 0x60, 0x60, 0xF0, 0x00 },
    // 115: s
    .{ 0x00, 0x00, 0x7C, 0xC0, 0x7C, 0x06, 0xFC, 0x00 },
    // 116: t
    .{ 0x30, 0x30, 0x7C, 0x30, 0x30, 0x36, 0x1C, 0x00 },
    // 117: u
    .{ 0x00, 0x00, 0xCC, 0xCC, 0xCC, 0xCC, 0x76, 0x00 },
    // 118: v
    .{ 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x00 },
    // 119: w
    .{ 0x00, 0x00, 0xC6, 0xD6, 0xD6, 0xFE, 0x6C, 0x00 },
    // 120: x
    .{ 0x00, 0x00, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0x00 },
    // 121: y
    .{ 0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x7C },
    // 122: z
    .{ 0x00, 0x00, 0xFE, 0x8C, 0x18, 0x32, 0xFE, 0x00 },
    // 123: {
    .{ 0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00 },
    // 124: |
    .{ 0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00 },
    // 125: }
    .{ 0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00 },
    // 126: ~
    .{ 0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

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
            // FIX: Use framebuffers_ptr instead of framebuffers
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
// Low-level Drawing
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

    cursor_x = 0;
    cursor_y = 0;
}

// ============================================================================
// Legacy Text Output (8x8 font)
// ============================================================================

fn drawChar8x8(x: u32, y: u32, char: u8, fg: u32, bg: u32) void {
    if (char < 32 or char > 126) return;

    const glyph = font_8x8[char - 32];

    var row: u32 = 0;
    while (row < FONT_HEIGHT) : (row += 1) {
        var col: u32 = 0;
        while (col < FONT_WIDTH) : (col += 1) {
            const pixel_set = (glyph[row] >> @intCast(7 - col)) & 1;
            const color = if (pixel_set == 1) fg else bg;
            putPixel(x + col, y + row, color);
        }
    }
}

pub fn printChar(c: u8) void {
    if (!initialized) return;

    const max_cols = fb_width / FONT_WIDTH;
    const max_rows = fb_height / FONT_HEIGHT;

    switch (c) {
        '\n' => {
            cursor_x = 0;
            cursor_y += 1;
            if (cursor_y >= max_rows) {
                scrollLegacy();
                cursor_y = max_rows - 1;
            }
        },
        '\r' => {
            cursor_x = 0;
        },
        '\t' => {
            cursor_x = (cursor_x + 4) & ~@as(u32, 3);
            if (cursor_x >= max_cols) {
                cursor_x = 0;
                cursor_y += 1;
                if (cursor_y >= max_rows) {
                    scrollLegacy();
                    cursor_y = max_rows - 1;
                }
            }
        },
        else => {
            if (c >= 32 and c < 127) {
                drawChar8x8(
                    cursor_x * FONT_WIDTH,
                    cursor_y * FONT_HEIGHT,
                    c,
                    fg_color,
                    bg_color,
                );
                cursor_x += 1;
                if (cursor_x >= max_cols) {
                    cursor_x = 0;
                    cursor_y += 1;
                    if (cursor_y >= max_rows) {
                        scrollLegacy();
                        cursor_y = max_rows - 1;
                    }
                }
            }
        },
    }
}

pub fn print(s: []const u8) void {
    for (s) |c| {
        printChar(c);
    }
}

pub fn println(s: []const u8) void {
    print(s);
    printChar('\n');
}

fn scrollLegacy() void {
    if (!initialized) return;
    if (fb_addr == null) return;

    const addr = fb_addr.?;
    const bytes_per_pixel = fb_bpp / 8;
    const row_size = fb_pitch;
    const scroll_height = FONT_HEIGHT;

    var y: u32 = 0;
    while (y < fb_height - scroll_height) : (y += 1) {
        const dest_offset = y * row_size;
        const src_offset = (y + scroll_height) * row_size;

        var x: u32 = 0;
        while (x < fb_width * bytes_per_pixel) : (x += 1) {
            addr[dest_offset + x] = addr[src_offset + x];
        }
    }

    fillRect(0, fb_height - scroll_height, fb_width, scroll_height, bg_color);
}

// ============================================================================
// Color and Cursor Control (Legacy)
// ============================================================================

pub fn setColors(fg: u32, bg: u32) void {
    fg_color = fg;
    bg_color = bg;
}

pub fn setCursor(x: u32, y: u32) void {
    const max_cols = if (fb_width > 0) fb_width / FONT_WIDTH else 1;
    const max_rows = if (fb_height > 0) fb_height / FONT_HEIGHT else 1;

    cursor_x = if (x < max_cols) x else max_cols - 1;
    cursor_y = if (y < max_rows) y else max_rows - 1;
}

pub fn getCursor() struct { x: u32, y: u32 } {
    return .{ .x = cursor_x, .y = cursor_y };
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
        Colors.RED,
        Colors.GREEN,
        Colors.BLUE,
        Colors.YELLOW,
        Colors.CYAN,
        Colors.MAGENTA,
        Colors.WHITE,
        Colors.DARK_GRAY,
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
