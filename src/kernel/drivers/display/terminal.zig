//! Zamrud OS - Terminal Emulator
//! Full-featured terminal with scrolling, colors, and blinking block cursor

const serial = @import("../serial/serial.zig");
const font = @import("font.zig");

// =============================================================================
// Configuration
// =============================================================================

const CHAR_WIDTH = font.FONT_WIDTH;
const CHAR_HEIGHT = font.FONT_HEIGHT;
const TAB_WIDTH = 4;

const SCROLLBACK_LINES = 1000;
const MAX_COLS = 200;

// Cursor blink: 50 ticks * 10ms = 500ms
const CURSOR_BLINK_TICKS: u32 = 50;

// =============================================================================
// Colors (32-bit ARGB)
// =============================================================================

pub const ColorValue = u32;

pub const Colors = struct {
    pub const BLACK: ColorValue = 0xFF000000;
    pub const WHITE: ColorValue = 0xFFFFFFFF;
    pub const RED: ColorValue = 0xFFFF0000;
    pub const GREEN: ColorValue = 0xFF00FF00;
    pub const BLUE: ColorValue = 0xFF0000FF;
    pub const CYAN: ColorValue = 0xFF00FFFF;
    pub const MAGENTA: ColorValue = 0xFFFF00FF;
    pub const YELLOW: ColorValue = 0xFFFFFF00;
    pub const ORANGE: ColorValue = 0xFFFFA500;
    pub const PINK: ColorValue = 0xFFFFB6C1;
    pub const GRAY: ColorValue = 0xFF808080;
    pub const LIGHT_GRAY: ColorValue = 0xFFC0C0C0;
    pub const DARK_GRAY: ColorValue = 0xFF404040;

    pub const BG_DEFAULT: ColorValue = 0xFF1E1E2E;
    pub const FG_DEFAULT: ColorValue = 0xFFCDD6F4;
    pub const PROMPT: ColorValue = 0xFF89B4FA;
    pub const ERROR: ColorValue = 0xFFF38BA8;
    pub const SUCCESS: ColorValue = 0xFFA6E3A1;
    pub const WARNING: ColorValue = 0xFFF9E2AF;
    pub const INFO: ColorValue = 0xFF89DCEB;
    pub const DIR_COLOR: ColorValue = 0xFF89B4FA;
    pub const FILE_COLOR: ColorValue = 0xFFCDD6F4;
    pub const EXE_COLOR: ColorValue = 0xFFA6E3A1;
    pub const CURSOR_COLOR: ColorValue = 0xFFCDD6F4;
};

pub const Color = struct {
    pub const Black = Colors.BLACK;
    pub const White = Colors.WHITE;
    pub const Red = Colors.ERROR;
    pub const Green = Colors.SUCCESS;
    pub const Blue = Colors.BLUE;
    pub const Cyan = Colors.INFO;
    pub const Magenta = Colors.MAGENTA;
    pub const Yellow = Colors.WARNING;
    pub const LightGray = Colors.LIGHT_GRAY;
    pub const DarkGray = Colors.DARK_GRAY;
};

// =============================================================================
// Character Cell
// =============================================================================

const Cell = struct {
    char: u8,
    fg: ColorValue,
    bg: ColorValue,
};

// =============================================================================
// State
// =============================================================================

var framebuffer: ?[*]u32 = null;
var fb_width: u32 = 0;
var fb_height: u32 = 0;
var fb_pitch: u32 = 0;

var cols: u32 = 0;
var rows: u32 = 0;

var cursor_x: u32 = 0;
var cursor_y: u32 = 0;

var fg_color: ColorValue = Colors.FG_DEFAULT;
var bg_color: ColorValue = Colors.BG_DEFAULT;

var scroll_top: u32 = 0;
var scroll_bottom: u32 = 0;

var buffer: [SCROLLBACK_LINES][MAX_COLS]Cell = undefined;
var buffer_head: u32 = 0;
var buffer_tail: u32 = 0;
var view_offset: u32 = 0;

var cursor_visible: bool = true;
var cursor_blink_state: bool = true;
var cursor_blink_counter: u32 = 0;
var cursor_drawn: bool = false;

var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init(fb: [*]u32, width: u32, height: u32, pitch: u32) void {
    framebuffer = fb;
    fb_width = width;
    fb_height = height;
    fb_pitch = pitch / 4;

    cols = width / CHAR_WIDTH;
    rows = height / CHAR_HEIGHT;

    if (cols > MAX_COLS) cols = MAX_COLS;

    scroll_top = 0;
    scroll_bottom = rows - 1;

    cursor_x = 0;
    cursor_y = 0;

    view_offset = 0;
    buffer_head = 0;
    buffer_tail = 0;

    cursor_visible = true;
    cursor_blink_state = true;
    cursor_blink_counter = 0;
    cursor_drawn = false;

    clearBuffer();
    clear();

    initialized = true;

    serial.writeString("[TERM] Initialized ");
    printDecSerial(cols);
    serial.writeString("x");
    printDecSerial(rows);
    serial.writeString("\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Timer Tick - Called from timer interrupt for cursor blink
// =============================================================================

pub fn tick() void {
    if (!initialized) return;
    if (!cursor_visible) return;

    cursor_blink_counter += 1;

    if (cursor_blink_counter >= CURSOR_BLINK_TICKS) {
        cursor_blink_counter = 0;
        cursor_blink_state = !cursor_blink_state;

        if (cursor_blink_state) {
            drawBlockCursor();
        } else {
            eraseBlockCursor();
        }
    }
}

// =============================================================================
// Buffer Management
// =============================================================================

fn clearBuffer() void {
    var y: u32 = 0;
    while (y < SCROLLBACK_LINES) : (y += 1) {
        var x: u32 = 0;
        while (x < MAX_COLS) : (x += 1) {
            buffer[y][x] = .{
                .char = ' ',
                .fg = Colors.FG_DEFAULT,
                .bg = Colors.BG_DEFAULT,
            };
        }
    }
}

fn getBufferLine(visible_line: u32) u32 {
    const total_lines = if (buffer_tail >= buffer_head)
        buffer_tail - buffer_head
    else
        SCROLLBACK_LINES - buffer_head + buffer_tail;

    if (total_lines <= rows) {
        return (buffer_head + visible_line) % SCROLLBACK_LINES;
    }

    const scroll_pos = total_lines - rows - view_offset;
    return (buffer_head + scroll_pos + visible_line) % SCROLLBACK_LINES;
}

fn addLine() void {
    buffer_tail = (buffer_tail + 1) % SCROLLBACK_LINES;
    if (buffer_tail == buffer_head) {
        buffer_head = (buffer_head + 1) % SCROLLBACK_LINES;
    }

    var x: u32 = 0;
    while (x < cols) : (x += 1) {
        buffer[buffer_tail][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
        };
    }
}

// =============================================================================
// Drawing
// =============================================================================

fn putPixel(x: u32, y: u32, color: ColorValue) void {
    if (framebuffer) |fb| {
        if (x < fb_width and y < fb_height) {
            fb[y * fb_pitch + x] = color;
        }
    }
}

fn drawChar(x: u32, y: u32, c: u8, fg: ColorValue, bg: ColorValue) void {
    const char_data = font.getChar(c);
    const px = x * CHAR_WIDTH;
    const py = y * CHAR_HEIGHT;

    var row: u32 = 0;
    while (row < CHAR_HEIGHT) : (row += 1) {
        const byte = if (row < char_data.len) char_data[row] else 0;
        var col: u32 = 0;
        while (col < CHAR_WIDTH) : (col += 1) {
            const bit = (byte >> @intCast(7 - col)) & 1;
            const color = if (bit == 1) fg else bg;
            putPixel(px + col, py + row, color);
        }
    }
}

/// Draw block cursor (inverted colors)
fn drawBlockCursor() void {
    if (!cursor_visible) return;
    if (cursor_drawn) return;

    const line = getBufferLine(cursor_y);
    const cell = if (cursor_x < cols) buffer[line][cursor_x] else Cell{
        .char = ' ',
        .fg = fg_color,
        .bg = bg_color,
    };

    // Draw with inverted colors (swap fg and bg)
    drawChar(cursor_x, cursor_y, cell.char, cell.bg, Colors.CURSOR_COLOR);
    cursor_drawn = true;
}

/// Erase block cursor (restore original character)
fn eraseBlockCursor() void {
    if (!cursor_drawn) return;

    const line = getBufferLine(cursor_y);
    const cell = if (cursor_x < cols) buffer[line][cursor_x] else Cell{
        .char = ' ',
        .fg = fg_color,
        .bg = bg_color,
    };

    // Restore original colors
    drawChar(cursor_x, cursor_y, cell.char, cell.fg, cell.bg);
    cursor_drawn = false;
}

pub fn refreshScreen() void {
    if (!initialized) return;

    var y: u32 = 0;
    while (y < rows) : (y += 1) {
        const line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            const cell = buffer[line][x];
            drawChar(x, y, cell.char, cell.fg, cell.bg);
        }
    }

    cursor_drawn = false;
    if (cursor_blink_state and cursor_visible) {
        drawBlockCursor();
    }
}

// =============================================================================
// Scrolling
// =============================================================================

fn scrollUpInternal() void {
    addLine();

    var y: u32 = scroll_top;
    while (y < scroll_bottom) : (y += 1) {
        const src_line = getBufferLine(y + 1);
        const dst_line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[dst_line][x] = buffer[src_line][x];
        }
    }

    const bottom_line = getBufferLine(scroll_bottom);
    var x: u32 = 0;
    while (x < cols) : (x += 1) {
        buffer[bottom_line][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
        };
    }

    refreshScreen();
}

pub fn scrollView(lines: i32) void {
    const total_lines = if (buffer_tail >= buffer_head)
        buffer_tail - buffer_head
    else
        SCROLLBACK_LINES - buffer_head + buffer_tail;

    if (total_lines <= rows) return;

    const max_offset = total_lines - rows;

    if (lines < 0) {
        const abs_lines: u32 = @intCast(-lines);
        if (view_offset + abs_lines <= max_offset) {
            view_offset += abs_lines;
        } else {
            view_offset = max_offset;
        }
    } else {
        const abs_lines: u32 = @intCast(lines);
        if (view_offset >= abs_lines) {
            view_offset -= abs_lines;
        } else {
            view_offset = 0;
        }
    }

    refreshScreen();
}

/// Scroll view up by specified lines (for user scrolling - shows older content)
pub fn scrollUp(lines: u32) void {
    scrollView(-@as(i32, @intCast(lines)));
}

/// Scroll view down by specified lines (for user scrolling - shows newer content)
pub fn scrollDown(lines: u32) void {
    scrollView(@as(i32, @intCast(lines)));
}

pub fn scrollToBottom() void {
    view_offset = 0;
    refreshScreen();
}

// =============================================================================
// Character Output
// =============================================================================

pub fn putChar(c: u8) void {
    if (!initialized) return;

    // Erase cursor before modifying screen
    eraseBlockCursor();

    switch (c) {
        '\n' => {
            cursor_x = 0;
            if (cursor_y >= scroll_bottom) {
                scrollUpInternal();
            } else {
                cursor_y += 1;
            }
        },
        '\r' => {
            cursor_x = 0;
        },
        '\t' => {
            const spaces = TAB_WIDTH - (cursor_x % TAB_WIDTH);
            var i: u32 = 0;
            while (i < spaces) : (i += 1) {
                putChar(' ');
            }
        },
        0x08 => { // Backspace
            if (cursor_x > 0) {
                cursor_x -= 1;
                const line = getBufferLine(cursor_y);
                buffer[line][cursor_x] = .{
                    .char = ' ',
                    .fg = fg_color,
                    .bg = bg_color,
                };
                drawChar(cursor_x, cursor_y, ' ', fg_color, bg_color);
            }
        },
        0x7F => { // Delete
            putChar(0x08);
        },
        else => {
            if (c >= 0x20 and c < 0x7F) {
                const line = getBufferLine(cursor_y);
                buffer[line][cursor_x] = .{
                    .char = c,
                    .fg = fg_color,
                    .bg = bg_color,
                };
                drawChar(cursor_x, cursor_y, c, fg_color, bg_color);

                cursor_x += 1;
                if (cursor_x >= cols) {
                    cursor_x = 0;
                    if (cursor_y >= scroll_bottom) {
                        scrollUpInternal();
                    } else {
                        cursor_y += 1;
                    }
                }
            }
        },
    }

    // Reset blink state and show cursor immediately after typing
    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

pub fn writeChar(c: u8) void {
    putChar(c);
}

pub fn print(s: []const u8) void {
    for (s) |c| {
        putChar(c);
    }
}

pub fn println(s: []const u8) void {
    print(s);
    putChar('\n');
}

// =============================================================================
// Colors
// =============================================================================

pub fn setFgColor(color: ColorValue) void {
    fg_color = color;
}

pub fn setBgColor(color: ColorValue) void {
    bg_color = color;
}

pub fn setColors(fg: ColorValue, bg: ColorValue) void {
    fg_color = fg;
    bg_color = bg;
}

pub fn resetColors() void {
    fg_color = Colors.FG_DEFAULT;
    bg_color = Colors.BG_DEFAULT;
}

pub fn getFgColor() ColorValue {
    return fg_color;
}

pub fn getBgColor() ColorValue {
    return bg_color;
}

pub fn setForeground(color: ColorValue) void {
    setFgColor(color);
}

pub fn setBackground(color: ColorValue) void {
    setBgColor(color);
}

// =============================================================================
// Screen Operations
// =============================================================================

pub fn clear() void {
    if (!initialized) return;

    eraseBlockCursor();

    if (framebuffer) |fb| {
        var y: u32 = 0;
        while (y < fb_height) : (y += 1) {
            var x: u32 = 0;
            while (x < fb_width) : (x += 1) {
                fb[y * fb_pitch + x] = bg_color;
            }
        }
    }

    var y: u32 = 0;
    while (y < rows) : (y += 1) {
        const line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[line][x] = .{
                .char = ' ',
                .fg = fg_color,
                .bg = bg_color,
            };
        }
    }

    cursor_x = 0;
    cursor_y = 0;
    view_offset = 0;

    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

pub fn clearScreen() void {
    clear();
}

pub fn clearLine() void {
    if (!initialized) return;

    eraseBlockCursor();

    const line = getBufferLine(cursor_y);
    var x: u32 = 0;
    while (x < cols) : (x += 1) {
        buffer[line][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
        };
        drawChar(x, cursor_y, ' ', fg_color, bg_color);
    }

    cursor_x = 0;
    drawBlockCursor();
}

pub fn clearToEndOfLine() void {
    if (!initialized) return;

    eraseBlockCursor();

    const line = getBufferLine(cursor_y);
    var x = cursor_x;
    while (x < cols) : (x += 1) {
        buffer[line][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
        };
        drawChar(x, cursor_y, ' ', fg_color, bg_color);
    }

    drawBlockCursor();
}

// =============================================================================
// Cursor Control
// =============================================================================

pub fn setCursor(x: u32, y: u32) void {
    eraseBlockCursor();
    cursor_x = if (x < cols) x else cols - 1;
    cursor_y = if (y < rows) y else rows - 1;
    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

pub fn getCursor() struct { x: u32, y: u32 } {
    return .{ .x = cursor_x, .y = cursor_y };
}

/// Get current cursor column position
pub fn getCursorCol() u32 {
    return cursor_x;
}

/// Get current cursor row position
pub fn getCursorRow() u32 {
    return cursor_y;
}

pub fn moveCursor(dx: i32, dy: i32) void {
    eraseBlockCursor();

    if (dx < 0) {
        const abs_dx: u32 = @intCast(-dx);
        if (cursor_x >= abs_dx) {
            cursor_x -= abs_dx;
        } else {
            cursor_x = 0;
        }
    } else {
        cursor_x += @intCast(dx);
        if (cursor_x >= cols) cursor_x = cols - 1;
    }

    if (dy < 0) {
        const abs_dy: u32 = @intCast(-dy);
        if (cursor_y >= abs_dy) {
            cursor_y -= abs_dy;
        } else {
            cursor_y = 0;
        }
    } else {
        cursor_y += @intCast(dy);
        if (cursor_y >= rows) cursor_y = rows - 1;
    }

    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

pub fn showCursor() void {
    cursor_visible = true;
    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

pub fn hideCursor() void {
    eraseBlockCursor();
    cursor_visible = false;
}

// =============================================================================
// Info
// =============================================================================

pub fn getWidth() u32 {
    return fb_width;
}

pub fn getHeight() u32 {
    return fb_height;
}

pub fn getCols() u32 {
    return cols;
}

pub fn getRows() u32 {
    return rows;
}

// =============================================================================
// Print Helpers (Public API)
// =============================================================================

pub fn printDec(val: anytype) void {
    const T = @TypeOf(val);
    var v: u64 = 0;

    switch (@typeInfo(T)) {
        .int => |info| {
            if (info.signedness == .signed) {
                if (val < 0) {
                    putChar('-');
                    v = @intCast(-@as(i64, val));
                } else {
                    v = @intCast(val);
                }
            } else {
                v = @intCast(val);
            }
        },
        .comptime_int => {
            if (val < 0) {
                putChar('-');
                v = @intCast(-val);
            } else {
                v = @intCast(val);
            }
        },
        else => {
            print("<ERR>");
            return;
        },
    }

    printNumber(v);
}

pub fn printNumber(val: u64) void {
    if (val == 0) {
        putChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;

    while (v > 0) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        putChar(buf[i]);
    }
}

pub fn printHex(val: u64) void {
    const hex = "0123456789ABCDEF";
    print("0x");

    var started = false;
    var shift: u6 = 60;

    while (true) {
        const nibble: u8 = @intCast((val >> shift) & 0xF);
        if (nibble != 0 or started or shift == 0) {
            putChar(hex[nibble]);
            started = true;
        }
        if (shift == 0) break;
        shift -= 4;
    }
}

// =============================================================================
// Debug (Private)
// =============================================================================

fn printDecSerial(val: u32) void {
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
