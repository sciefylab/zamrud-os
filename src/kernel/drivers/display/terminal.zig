//! Zamrud OS - Terminal Emulator
//! Full-featured terminal with scrolling, colors, and blinking block cursor
//! T1.0: Enhanced with Unicode glyph support and text styles
//! T2.1: ANSI Escape Sequence Parser (CSI colors, SGR, cursor, erase)
//! T2.2: Screen Management (resize, word wrap, tab stops)

const serial = @import("../serial/serial.zig");
const font = @import("font.zig");

// =============================================================================
// Configuration
// =============================================================================

const CHAR_WIDTH = font.FONT_WIDTH;
const CHAR_HEIGHT = font.FONT_HEIGHT;

const SCROLLBACK_LINES = 1000;
const MAX_COLS = 200;
const MAX_TAB_STOPS = 200; // T2.2

// Cursor blink: 50 ticks * 10ms = 500ms
const CURSOR_BLINK_TICKS: u32 = 50;

// T2.2: Default tab width (standard = 8)
const DEFAULT_TAB_WIDTH: u32 = 8;

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

    pub const BG_DEFAULT: ColorValue = 0xFF050F05;
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
// T2.1: ANSI Standard Color Table (SGR 30-37, 40-47, 90-97, 100-107)
// =============================================================================

/// Standard 8 colors (SGR 30-37 foreground, 40-47 background)
const ansi_standard_colors = [8]ColorValue{
    0xFF000000, // 0: Black
    0xFFCD3131, // 1: Red
    0xFF0DBC79, // 2: Green
    0xFFE5E510, // 3: Yellow
    0xFF2472C8, // 4: Blue
    0xFFBC3FBC, // 5: Magenta
    0xFF11A8CD, // 6: Cyan
    0xFFE5E5E5, // 7: White
};

/// Bright/High-intensity colors (SGR 90-97 foreground, 100-107 background)
const ansi_bright_colors = [8]ColorValue{
    0xFF666666, // 0: Bright Black (Dark Gray)
    0xFFF14C4C, // 1: Bright Red
    0xFF23D18B, // 2: Bright Green
    0xFFF5F543, // 3: Bright Yellow
    0xFF3B8EEA, // 4: Bright Blue
    0xFFD670D6, // 5: Bright Magenta
    0xFF29B8DB, // 6: Bright Cyan
    0xFFFFFFFF, // 7: Bright White
};

/// 256-color palette (first 16 = standard+bright, 16-231 = color cube, 232-255 = grays)
fn ansi256ToRgb(n: u8) ColorValue {
    if (n < 8) return ansi_standard_colors[n];
    if (n < 16) return ansi_bright_colors[n - 8];

    if (n >= 232) {
        // Grayscale: 232-255 → 24 shades from dark to light
        const shade: u32 = @as(u32, n - 232) * 255 / 23;
        return 0xFF000000 | (shade << 16) | (shade << 8) | shade;
    }

    // 6x6x6 color cube: indices 16-231
    const idx: u32 = @as(u32, n) - 16;
    const b_idx: u32 = idx % 6;
    const g_idx: u32 = (idx / 6) % 6;
    const r_idx: u32 = idx / 36;

    const r: u32 = if (r_idx == 0) 0 else 55 + r_idx * 40;
    const g: u32 = if (g_idx == 0) 0 else 55 + g_idx * 40;
    const b: u32 = if (b_idx == 0) 0 else 55 + b_idx * 40;

    return 0xFF000000 | (r << 16) | (g << 8) | b;
}

// =============================================================================
// T2.1: ANSI Escape Sequence State Machine
// =============================================================================

const AnsiState = enum {
    normal, // Normal character output
    escape, // Got ESC (0x1B), waiting for next
    csi, // Got ESC[, collecting CSI params
    osc, // Got ESC], Operating System Command (ignore)
    escape_hash, // Got ESC# (ignore)
};

const MAX_CSI_PARAMS = 16;
const MAX_CSI_INTERMEDIATE = 4;

var ansi_state: AnsiState = .normal;
var csi_params: [MAX_CSI_PARAMS]u16 = [_]u16{0} ** MAX_CSI_PARAMS;
var csi_param_count: u32 = 0;
var csi_current_param: u16 = 0;
var csi_has_digit: bool = false;
var csi_intermediate: [MAX_CSI_INTERMEDIATE]u8 = [_]u8{0} ** MAX_CSI_INTERMEDIATE;
var csi_intermediate_count: u32 = 0;

// T2.1: Saved cursor state (SCP/RCP)
var saved_cursor_x: u32 = 0;
var saved_cursor_y: u32 = 0;
var saved_fg_color: ColorValue = Colors.FG_DEFAULT;
var saved_bg_color: ColorValue = Colors.BG_DEFAULT;
var saved_bold: bool = false;
var saved_underline: bool = false;

// =============================================================================
// T1.0: Enhanced Character Cell — supports styles
// =============================================================================

const Cell = struct {
    char: u8,
    fg: ColorValue,
    bg: ColorValue,
    bold: bool = false,
    underline: bool = false,
    wrapped: bool = false, // T2.2: soft-wrap marker
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

// T1.0: Current text style
var current_bold: bool = false;
var current_underline: bool = false;

// T2.1: Inverse video mode (SGR 7)
var current_inverse: bool = false;

// T2.2: Tab stops array
var tab_stops: [MAX_TAB_STOPS]bool = undefined;

// T2.2: Auto-wrap mode (can be toggled by DECAWM)
var auto_wrap: bool = true;

// T2.2: Resize callback (optional, for notifying shell)
var resize_callback: ?*const fn (u32, u32) void = null;

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

    current_bold = false;
    current_underline = false;
    current_inverse = false;
    auto_wrap = true;

    // T2.1: Reset ANSI state
    ansi_state = .normal;
    csi_param_count = 0;
    csi_current_param = 0;
    csi_has_digit = false;
    csi_intermediate_count = 0;

    // T2.2: Initialize tab stops (every 8 columns)
    initTabStops();

    clearBuffer();
    clear();

    initialized = true;

    serial.writeString("[TERM] Initialized ");
    printDecSerial(cols);
    serial.writeString("x");
    printDecSerial(rows);
    serial.writeString(" (T2.2 screen mgmt + T2.1 ANSI + T1.0 font: ");
    printDecSerial(font.getGlyphCount());
    serial.writeString(" glyphs)\n");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// T2.2: Tab Stop Management
// =============================================================================

/// Initialize tab stops at every DEFAULT_TAB_WIDTH columns
fn initTabStops() void {
    var i: u32 = 0;
    while (i < MAX_TAB_STOPS) : (i += 1) {
        tab_stops[i] = (i > 0 and i % DEFAULT_TAB_WIDTH == 0);
    }
}

/// Set a tab stop at the current cursor column
fn setTabStopAtCursor() void {
    if (cursor_x < MAX_TAB_STOPS) {
        tab_stops[cursor_x] = true;
    }
}

/// Clear tab stop at current column
fn clearTabStopAtCursor() void {
    if (cursor_x < MAX_TAB_STOPS) {
        tab_stops[cursor_x] = false;
    }
}

/// Clear all tab stops
fn clearAllTabStops() void {
    var i: u32 = 0;
    while (i < MAX_TAB_STOPS) : (i += 1) {
        tab_stops[i] = false;
    }
}

/// Find next tab stop from current position
fn nextTabStop() u32 {
    var pos = cursor_x + 1;
    while (pos < cols) : (pos += 1) {
        if (pos < MAX_TAB_STOPS and tab_stops[pos]) {
            return pos;
        }
    }
    // No tab stop found — go to last column
    return cols - 1;
}

/// Find previous tab stop from current position
fn prevTabStop() u32 {
    if (cursor_x == 0) return 0;
    var pos = cursor_x - 1;
    while (pos > 0) : (pos -= 1) {
        if (pos < MAX_TAB_STOPS and tab_stops[pos]) {
            return pos;
        }
    }
    return 0;
}

/// Get current tab width setting
pub fn getTabWidth() u32 {
    return DEFAULT_TAB_WIDTH;
}

// =============================================================================
// T2.2: Terminal Resize
// =============================================================================

/// Resize terminal to new framebuffer dimensions
/// Called when framebuffer changes or for testing
pub fn resize(new_width: u32, new_height: u32) void {
    if (!initialized) return;

    eraseBlockCursor();

    // Save old dimensions
    const old_cols = cols;
    const old_rows = rows;

    // Calculate new dimensions
    cols = new_width / CHAR_WIDTH;
    rows = new_height / CHAR_HEIGHT;
    if (cols > MAX_COLS) cols = MAX_COLS;
    if (cols == 0) cols = 1;
    if (rows == 0) rows = 1;

    fb_width = new_width;
    fb_height = new_height;

    // Update scroll region
    scroll_top = 0;
    scroll_bottom = rows - 1;

    // Clamp cursor to new bounds
    if (cursor_x >= cols) cursor_x = cols - 1;
    if (cursor_y >= rows) cursor_y = rows - 1;

    // Reset view
    view_offset = 0;

    // Re-initialize tab stops for new width
    initTabStops();

    // Redraw
    refreshScreen();

    // Notify callback if registered
    if (resize_callback) |cb| {
        cb(cols, rows);
    }

    serial.writeString("[TERM] Resized ");
    printDecSerial(old_cols);
    serial.writeString("x");
    printDecSerial(old_rows);
    serial.writeString(" -> ");
    printDecSerial(cols);
    serial.writeString("x");
    printDecSerial(rows);
    serial.writeString("\n");
}

/// Resize with new framebuffer pointer
pub fn resizeWithBuffer(fb: [*]u32, new_width: u32, new_height: u32, pitch: u32) void {
    framebuffer = fb;
    fb_pitch = pitch / 4;
    resize(new_width, new_height);
}

/// Register a resize callback (e.g., for shell to update $COLUMNS/$LINES)
pub fn setResizeCallback(cb: *const fn (u32, u32) void) void {
    resize_callback = cb;
}

/// Get current terminal dimensions as struct
pub fn getSize() struct { cols: u32, rows: u32, width: u32, height: u32 } {
    return .{
        .cols = cols,
        .rows = rows,
        .width = fb_width,
        .height = fb_height,
    };
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
// T1.0: Text Style Control
// =============================================================================

pub fn setBold(bold: bool) void {
    current_bold = bold;
}

pub fn setUnderline(underline: bool) void {
    current_underline = underline;
}

pub fn resetStyle() void {
    current_bold = false;
    current_underline = false;
    current_inverse = false;
}

pub fn resetAll() void {
    resetColors();
    resetStyle();
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
                .bold = false,
                .underline = false,
                .wrapped = false,
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
            .bold = false,
            .underline = false,
            .wrapped = false,
        };
    }
}

// =============================================================================
// T1.0: Enhanced Drawing with Style Support
// =============================================================================

fn putPixel(x: u32, y: u32, color: ColorValue) void {
    if (framebuffer) |fb| {
        if (x < fb_width and y < fb_height) {
            fb[y * fb_pitch + x] = color;
        }
    }
}

/// Draw character with full style support (bold, underline)
fn drawCharStyled(x: u32, y: u32, c: u8, fg_arg: ColorValue, bg_arg: ColorValue, bold: bool, underline: bool) void {
    const px = x * CHAR_WIDTH;
    const py = y * CHAR_HEIGHT;

    // Get glyph data
    const char_data = font.getGlyph(@as(u21, c));

    // Get bold version if needed
    var bold_data: [16]u8 = undefined;
    if (bold) {
        bold_data = font.getGlyphBold(@as(u21, c));
    }

    var row: u32 = 0;
    while (row < CHAR_HEIGHT) : (row += 1) {
        var byte: u8 = undefined;
        if (bold) {
            byte = bold_data[row];
        } else {
            byte = if (row < char_data.len) char_data[row] else 0;
        }

        // Add underline at row 13
        if (underline and row == 13) {
            byte = 0xFF;
        }

        var col: u32 = 0;
        while (col < CHAR_WIDTH) : (col += 1) {
            const bit = (byte >> @intCast(7 - col)) & 1;
            const color = if (bit == 1) fg_arg else bg_arg;
            putPixel(px + col, py + row, color);
        }
    }
}

/// Legacy drawChar
fn drawChar(x: u32, y: u32, c: u8, fg_arg: ColorValue, bg_arg: ColorValue) void {
    drawCharStyled(x, y, c, fg_arg, bg_arg, false, false);
}

/// Draw a Unicode codepoint at cell position
pub fn drawCodepoint(x: u32, y: u32, codepoint: u21, fg_arg: ColorValue, bg_arg: ColorValue) void {
    const glyph_data = font.getGlyph(codepoint);
    const px = x * CHAR_WIDTH;
    const py = y * CHAR_HEIGHT;

    var row: u32 = 0;
    while (row < CHAR_HEIGHT) : (row += 1) {
        const byte = if (row < glyph_data.len) glyph_data[row] else 0;
        var col: u32 = 0;
        while (col < CHAR_WIDTH) : (col += 1) {
            const bit = (byte >> @intCast(7 - col)) & 1;
            const color = if (bit == 1) fg_arg else bg_arg;
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
        .bold = false,
        .underline = false,
        .wrapped = false,
    };

    drawCharStyled(cursor_x, cursor_y, cell.char, cell.bg, Colors.CURSOR_COLOR, cell.bold, false);
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
        .bold = false,
        .underline = false,
        .wrapped = false,
    };

    drawCharStyled(cursor_x, cursor_y, cell.char, cell.fg, cell.bg, cell.bold, cell.underline);
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
            drawCharStyled(x, y, cell.char, cell.fg, cell.bg, cell.bold, cell.underline);
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
    // Shift lines up within visible area
    var y: u32 = scroll_top;
    while (y < scroll_bottom) : (y += 1) {
        const src_line = getBufferLine(y + 1);
        const dst_line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[dst_line][x] = buffer[src_line][x];
        }
    }

    // Clear bottom line
    const bottom_line = getBufferLine(scroll_bottom);
    var x: u32 = 0;
    while (x < cols) : (x += 1) {
        buffer[bottom_line][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
            .bold = false,
            .underline = false,
            .wrapped = false,
        };
    }

    refreshScreen();
}
/// T2.2: Scroll down (reverse scroll) within scroll region
fn scrollDownInternal() void {
    var y: u32 = scroll_bottom;
    while (y > scroll_top) : (y -= 1) {
        const src_line = getBufferLine(y - 1);
        const dst_line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[dst_line][x] = buffer[src_line][x];
        }
    }

    // Clear top line of scroll region
    const top_line = getBufferLine(scroll_top);
    var x: u32 = 0;
    while (x < cols) : (x += 1) {
        buffer[top_line][x] = .{
            .char = ' ',
            .fg = fg_color,
            .bg = bg_color,
            .bold = false,
            .underline = false,
            .wrapped = false,
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

pub fn scrollUp(lines: u32) void {
    scrollView(-@as(i32, @intCast(lines)));
}

pub fn scrollDown(lines: u32) void {
    scrollView(@as(i32, @intCast(lines)));
}

pub fn scrollToBottom() void {
    view_offset = 0;
    refreshScreen();
}

// =============================================================================
// T2.1: ANSI Escape Sequence Processing — Main Entry Point
// =============================================================================

/// Main character output — routes through ANSI state machine
pub fn putChar(c: u8) void {
    if (!initialized) return;

    switch (ansi_state) {
        .normal => putCharNormal(c),
        .escape => handleEscapeChar(c),
        .csi => handleCsiChar(c),
        .osc => handleOscChar(c),
        .escape_hash => {
            // ESC # <char> — ignore (e.g., DECDHL)
            ansi_state = .normal;
        },
    }
}

/// Normal mode — check for ESC or output character directly
fn putCharNormal(c: u8) void {
    if (c == 0x1B) {
        // ESC — start escape sequence
        ansi_state = .escape;
        return;
    }

    // Regular character output
    putCharDirect(c);
}

/// After receiving ESC, determine the sequence type
fn handleEscapeChar(c: u8) void {
    switch (c) {
        '[' => {
            // CSI — Control Sequence Introducer
            ansi_state = .csi;
            csiReset();
        },
        ']' => {
            // OSC — Operating System Command (ignore until ST)
            ansi_state = .osc;
        },
        '#' => {
            ansi_state = .escape_hash;
        },
        '7' => {
            // ESC 7 — Save cursor (DECSC)
            saveCursorState();
            ansi_state = .normal;
        },
        '8' => {
            // ESC 8 — Restore cursor (DECRC)
            restoreCursorState();
            ansi_state = .normal;
        },
        'c' => {
            // ESC c — Full reset (RIS)
            resetAll();
            initTabStops(); // T2.2: reset tab stops too
            clear();
            ansi_state = .normal;
        },
        'D' => {
            // ESC D — Index (move cursor down, scroll if needed)
            if (cursor_y >= scroll_bottom) {
                scrollUpInternal();
            } else {
                cursor_y += 1;
            }
            ansi_state = .normal;
        },
        'E' => {
            // ESC E — Next line
            cursor_x = 0;
            if (cursor_y >= scroll_bottom) {
                scrollUpInternal();
            } else {
                cursor_y += 1;
            }
            ansi_state = .normal;
        },
        'H' => {
            // ESC H — Set tab stop at current column (HTS)
            setTabStopAtCursor();
            ansi_state = .normal;
        },
        'M' => {
            // ESC M — Reverse index (scroll down if at top)
            if (cursor_y <= scroll_top) {
                scrollDownInternal(); // T2.2: proper reverse scroll
            } else {
                cursor_y -= 1;
            }
            ansi_state = .normal;
        },
        else => {
            // Unknown escape — silently discard
            ansi_state = .normal;
        },
    }
}

/// Reset CSI parameter collection
fn csiReset() void {
    csi_param_count = 0;
    csi_current_param = 0;
    csi_has_digit = false;
    csi_intermediate_count = 0;
    var i: u32 = 0;
    while (i < MAX_CSI_PARAMS) : (i += 1) {
        csi_params[i] = 0;
    }
    i = 0;
    while (i < MAX_CSI_INTERMEDIATE) : (i += 1) {
        csi_intermediate[i] = 0;
    }
}

/// Collect CSI parameters and dispatch on final byte
fn handleCsiChar(c: u8) void {
    // Parameter bytes: digits and semicolons
    if (c >= '0' and c <= '9') {
        csi_current_param = csi_current_param * 10 + @as(u16, c - '0');
        csi_has_digit = true;
        return;
    }

    if (c == ';') {
        // Push current param
        if (csi_param_count < MAX_CSI_PARAMS) {
            csi_params[csi_param_count] = if (csi_has_digit) csi_current_param else 0;
            csi_param_count += 1;
        }
        csi_current_param = 0;
        csi_has_digit = false;
        return;
    }

    // Intermediate bytes (0x20-0x2F): !, ", #, $, %, etc.
    if (c >= 0x20 and c <= 0x2F) {
        if (csi_intermediate_count < MAX_CSI_INTERMEDIATE) {
            csi_intermediate[csi_intermediate_count] = c;
            csi_intermediate_count += 1;
        }
        return;
    }

    // Final byte (0x40-0x7E) — dispatch command
    if (c >= 0x40 and c <= 0x7E) {
        // Push last param if there were digits
        if (csi_has_digit or csi_param_count > 0) {
            if (csi_param_count < MAX_CSI_PARAMS) {
                csi_params[csi_param_count] = if (csi_has_digit) csi_current_param else 0;
                csi_param_count += 1;
            }
        }

        executeCsiCommand(c);
        ansi_state = .normal;
        return;
    }

    // Invalid byte — abort sequence
    ansi_state = .normal;
}

/// OSC sequences — ignore until BEL (0x07) or ST (ESC \)
fn handleOscChar(c: u8) void {
    if (c == 0x07) {
        // BEL terminates OSC
        ansi_state = .normal;
    } else if (c == 0x1B) {
        // Might be start of ST (ESC \), but we'll just reset
        ansi_state = .normal;
    }
    // Otherwise keep consuming
}

// =============================================================================
// T2.1: CSI Command Dispatch (T2.2: added tab stop commands)
// =============================================================================

fn executeCsiCommand(final: u8) void {
    eraseBlockCursor();

    switch (final) {
        // --- Cursor Movement ---
        'A' => csiCursorUp(),
        'B' => csiCursorDown(),
        'C' => csiCursorForward(),
        'D' => csiCursorBack(),
        'E' => csiCursorNextLine(),
        'F' => csiCursorPrevLine(),
        'G' => csiCursorHorizontalAbsolute(),
        'H', 'f' => csiCursorPosition(),
        'd' => csiCursorVerticalAbsolute(),

        // --- Tab ---
        'I' => csiCursorForwardTab(), // T2.2: CHT
        'Z' => csiCursorBackwardTab(), // T2.2: CBT

        // --- Erase ---
        'J' => csiEraseInDisplay(),
        'K' => csiEraseInLine(),

        // --- SGR (Select Graphic Rendition) ---
        'm' => csiSgr(),

        // --- Scroll ---
        'S' => csiScrollUp(),
        'T' => csiScrollDown(),

        // --- Cursor save/restore ---
        's' => saveCursorState(),
        'u' => restoreCursorState(),

        // --- Device status / cursor position report ---
        'n' => {
            // CSI 6 n — Report cursor position (we can't send back, ignore)
        },

        // --- Set scroll region ---
        'r' => csiSetScrollRegion(),

        // --- Tab stop control --- T2.2
        'g' => csiTabClear(),

        // --- Show/Hide cursor ---
        'l', 'h' => {
            // CSI ? 25 l/h — hide/show cursor (DECTCEM)
            // CSI ? 7 l/h — auto-wrap mode (DECAWM) — T2.2
            if (csi_intermediate_count > 0 and csi_intermediate[0] == '?') {
                if (csi_param_count > 0) {
                    if (csi_params[0] == 25) {
                        if (final == 'l') {
                            hideCursor();
                        } else {
                            showCursor();
                        }
                    } else if (csi_params[0] == 7) {
                        // T2.2: DECAWM — auto-wrap mode
                        auto_wrap = (final == 'h');
                    }
                }
            }
        },

        else => {
            // Unknown CSI command — ignore
        },
    }

    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

// =============================================================================
// T2.1: Cursor Movement Commands
// =============================================================================

/// CSI Ps A — Cursor Up (CUU)
fn csiCursorUp() void {
    const n = getParam(0, 1);
    if (cursor_y >= n) {
        cursor_y -= n;
    } else {
        cursor_y = 0;
    }
}

/// CSI Ps B — Cursor Down (CUD)
fn csiCursorDown() void {
    const n = getParam(0, 1);
    cursor_y += n;
    if (cursor_y >= rows) cursor_y = rows - 1;
}

/// CSI Ps C — Cursor Forward (CUF)
fn csiCursorForward() void {
    const n = getParam(0, 1);
    cursor_x += n;
    if (cursor_x >= cols) cursor_x = cols - 1;
}

/// CSI Ps D — Cursor Back (CUB)
fn csiCursorBack() void {
    const n = getParam(0, 1);
    if (cursor_x >= n) {
        cursor_x -= n;
    } else {
        cursor_x = 0;
    }
}

/// CSI Ps E — Cursor Next Line (CNL)
fn csiCursorNextLine() void {
    const n = getParam(0, 1);
    cursor_x = 0;
    cursor_y += n;
    if (cursor_y >= rows) cursor_y = rows - 1;
}

/// CSI Ps F — Cursor Previous Line (CPL)
fn csiCursorPrevLine() void {
    const n = getParam(0, 1);
    cursor_x = 0;
    if (cursor_y >= n) {
        cursor_y -= n;
    } else {
        cursor_y = 0;
    }
}

/// CSI Ps G — Cursor Horizontal Absolute (CHA)
fn csiCursorHorizontalAbsolute() void {
    const n = getParam(0, 1);
    cursor_x = if (n > 0) n - 1 else 0; // 1-based
    if (cursor_x >= cols) cursor_x = cols - 1;
}

/// CSI Ps d — Cursor Vertical Absolute (VPA)
fn csiCursorVerticalAbsolute() void {
    const n = getParam(0, 1);
    cursor_y = if (n > 0) n - 1 else 0; // 1-based
    if (cursor_y >= rows) cursor_y = rows - 1;
}

/// CSI Ps ; Ps H — Cursor Position (CUP)
fn csiCursorPosition() void {
    const row = getParam(0, 1);
    const col = getParam(1, 1);
    cursor_y = if (row > 0) row - 1 else 0; // 1-based
    cursor_x = if (col > 0) col - 1 else 0; // 1-based
    if (cursor_y >= rows) cursor_y = rows - 1;
    if (cursor_x >= cols) cursor_x = cols - 1;
}

// =============================================================================
// T2.2: Tab Movement Commands
// =============================================================================

/// CSI Ps I — Cursor Forward Tabulation (CHT)
fn csiCursorForwardTab() void {
    const n = getParam(0, 1);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        cursor_x = nextTabStop();
    }
}

/// CSI Ps Z — Cursor Backward Tabulation (CBT)
fn csiCursorBackwardTab() void {
    const n = getParam(0, 1);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        cursor_x = prevTabStop();
    }
}

/// CSI Ps g — Tab Clear (TBC)
fn csiTabClear() void {
    const mode = getParam(0, 0);
    switch (mode) {
        0 => clearTabStopAtCursor(), // Clear at current position
        3 => clearAllTabStops(), // Clear all tab stops
        else => {},
    }
}

// =============================================================================
// T2.1: Erase Commands
// =============================================================================

/// CSI Ps J — Erase in Display (ED)
fn csiEraseInDisplay() void {
    const mode = getParam(0, 0);

    switch (mode) {
        0 => {
            // Erase from cursor to end of screen
            eraseFromCursorToEnd();
        },
        1 => {
            // Erase from start to cursor
            eraseFromStartToCursor();
        },
        2, 3 => {
            // Erase entire screen
            eraseEntireScreen();
        },
        else => {},
    }
}

/// CSI Ps K — Erase in Line (EL)
fn csiEraseInLine() void {
    const mode = getParam(0, 0);
    const line = getBufferLine(cursor_y);

    switch (mode) {
        0 => {
            // Erase from cursor to end of line
            var x = cursor_x;
            while (x < cols) : (x += 1) {
                buffer[line][x] = makeBlankCell();
                drawChar(x, cursor_y, ' ', fg_color, bg_color);
            }
        },
        1 => {
            // Erase from start of line to cursor
            var x: u32 = 0;
            while (x <= cursor_x and x < cols) : (x += 1) {
                buffer[line][x] = makeBlankCell();
                drawChar(x, cursor_y, ' ', fg_color, bg_color);
            }
        },
        2 => {
            // Erase entire line
            var x: u32 = 0;
            while (x < cols) : (x += 1) {
                buffer[line][x] = makeBlankCell();
                drawChar(x, cursor_y, ' ', fg_color, bg_color);
            }
        },
        else => {},
    }
}

fn eraseFromCursorToEnd() void {
    // Erase rest of current line
    const cur_line = getBufferLine(cursor_y);
    var x = cursor_x;
    while (x < cols) : (x += 1) {
        buffer[cur_line][x] = makeBlankCell();
        drawChar(x, cursor_y, ' ', fg_color, bg_color);
    }

    // Erase lines below
    var y = cursor_y + 1;
    while (y < rows) : (y += 1) {
        const line = getBufferLine(y);
        x = 0;
        while (x < cols) : (x += 1) {
            buffer[line][x] = makeBlankCell();
            drawChar(x, y, ' ', fg_color, bg_color);
        }
    }
}

fn eraseFromStartToCursor() void {
    // Erase lines above
    var y: u32 = 0;
    while (y < cursor_y) : (y += 1) {
        const line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[line][x] = makeBlankCell();
            drawChar(x, y, ' ', fg_color, bg_color);
        }
    }

    // Erase current line up to cursor
    const cur_line = getBufferLine(cursor_y);
    var x: u32 = 0;
    while (x <= cursor_x and x < cols) : (x += 1) {
        buffer[cur_line][x] = makeBlankCell();
        drawChar(x, cursor_y, ' ', fg_color, bg_color);
    }
}

fn eraseEntireScreen() void {
    var y: u32 = 0;
    while (y < rows) : (y += 1) {
        const line = getBufferLine(y);
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            buffer[line][x] = makeBlankCell();
            drawChar(x, y, ' ', fg_color, bg_color);
        }
    }
    cursor_x = 0;
    cursor_y = 0;
}

fn makeBlankCell() Cell {
    return .{
        .char = ' ',
        .fg = fg_color,
        .bg = bg_color,
        .bold = false,
        .underline = false,
        .wrapped = false,
    };
}

// =============================================================================
// T2.1: SGR (Select Graphic Rendition) — CSI Ps m
// =============================================================================

fn csiSgr() void {
    // No params = reset
    if (csi_param_count == 0) {
        sgrReset();
        return;
    }

    var i: u32 = 0;
    while (i < csi_param_count) : (i += 1) {
        const p = csi_params[i];

        switch (p) {
            // --- Reset ---
            0 => sgrReset(),

            // --- Attributes ---
            1 => current_bold = true,
            2 => {}, // Dim — ignore (or could halve brightness)
            3 => {}, // Italic — ignore (no italic font)
            4 => current_underline = true,
            5, 6 => {}, // Blink — ignore
            7 => current_inverse = true,
            8 => {}, // Hidden — ignore
            9 => {}, // Strikethrough — ignore for now

            // --- Attribute off ---
            21 => current_bold = false, // Bold off (or double underline)
            22 => current_bold = false, // Normal intensity
            23 => {}, // Not italic
            24 => current_underline = false,
            25 => {}, // Not blinking
            27 => current_inverse = false,
            28 => {}, // Not hidden
            29 => {}, // Not strikethrough

            // --- Standard foreground colors (30-37) ---
            30...37 => {
                fg_color = ansi_standard_colors[p - 30];
            },

            // --- Extended foreground (38) ---
            38 => {
                i = parseSgrExtendedColor(i, true);
            },

            // --- Default foreground (39) ---
            39 => {
                fg_color = Colors.FG_DEFAULT;
            },

            // --- Standard background colors (40-47) ---
            40...47 => {
                bg_color = ansi_standard_colors[p - 40];
            },

            // --- Extended background (48) ---
            48 => {
                i = parseSgrExtendedColor(i, false);
            },

            // --- Default background (49) ---
            49 => {
                bg_color = Colors.BG_DEFAULT;
            },

            // --- Bright foreground colors (90-97) ---
            90...97 => {
                fg_color = ansi_bright_colors[p - 90];
            },

            // --- Bright background colors (100-107) ---
            100...107 => {
                bg_color = ansi_bright_colors[p - 100];
            },

            else => {}, // Unknown SGR — ignore
        }
    }
}

/// Parse ESC[38;5;Nm (256-color) or ESC[38;2;R;G;Bm (truecolor)
/// Returns updated index
fn parseSgrExtendedColor(start_idx: u32, is_fg: bool) u32 {
    const i = start_idx;

    // Need at least one more param (the sub-command)
    if (i + 1 >= csi_param_count) return i;

    const sub = csi_params[i + 1];

    if (sub == 5) {
        // 256-color mode: ESC[38;5;Nm
        if (i + 2 < csi_param_count) {
            const color_idx: u8 = @intCast(csi_params[i + 2] & 0xFF);
            const color = ansi256ToRgb(color_idx);
            if (is_fg) {
                fg_color = color;
            } else {
                bg_color = color;
            }
            return i + 2; // Skip sub-command and color index
        }
    } else if (sub == 2) {
        // Truecolor mode: ESC[38;2;R;G;Bm
        if (i + 4 < csi_param_count) {
            const r: u32 = @as(u32, csi_params[i + 2]) & 0xFF;
            const g: u32 = @as(u32, csi_params[i + 3]) & 0xFF;
            const b: u32 = @as(u32, csi_params[i + 4]) & 0xFF;
            const color: ColorValue = 0xFF000000 | (r << 16) | (g << 8) | b;
            if (is_fg) {
                fg_color = color;
            } else {
                bg_color = color;
            }
            return i + 4; // Skip sub-command and R, G, B
        }
    }

    return i + 1; // At minimum skip the sub-command
}

fn sgrReset() void {
    fg_color = Colors.FG_DEFAULT;
    bg_color = Colors.BG_DEFAULT;
    current_bold = false;
    current_underline = false;
    current_inverse = false;
}

// =============================================================================
// T2.1: Scroll Commands (T2.2: reverse scroll implemented)
// =============================================================================

/// CSI Ps S — Scroll Up
fn csiScrollUp() void {
    const n = getParam(0, 1);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        scrollUpInternal();
    }
}

/// CSI Ps T — Scroll Down (T2.2: now implemented)
fn csiScrollDown() void {
    const n = getParam(0, 1);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        scrollDownInternal();
    }
}

/// CSI Pt ; Pb r — Set Scrolling Region (DECSTBM)
fn csiSetScrollRegion() void {
    const top = getParam(0, 1);
    const bottom = getParam(1, @as(u16, @intCast(rows)));

    scroll_top = if (top > 0) top - 1 else 0;
    scroll_bottom = if (bottom > 0) bottom - 1 else rows - 1;

    if (scroll_top >= rows) scroll_top = 0;
    if (scroll_bottom >= rows) scroll_bottom = rows - 1;
    if (scroll_top >= scroll_bottom) {
        scroll_top = 0;
        scroll_bottom = rows - 1;
    }

    // Move cursor to home
    cursor_x = 0;
    cursor_y = scroll_top;
}

// =============================================================================
// T2.1: Cursor Save/Restore
// =============================================================================

fn saveCursorState() void {
    saved_cursor_x = cursor_x;
    saved_cursor_y = cursor_y;
    saved_fg_color = fg_color;
    saved_bg_color = bg_color;
    saved_bold = current_bold;
    saved_underline = current_underline;
}

fn restoreCursorState() void {
    eraseBlockCursor();
    cursor_x = saved_cursor_x;
    cursor_y = saved_cursor_y;
    fg_color = saved_fg_color;
    bg_color = saved_bg_color;
    current_bold = saved_bold;
    current_underline = saved_underline;
    if (cursor_x >= cols) cursor_x = cols - 1;
    if (cursor_y >= rows) cursor_y = rows - 1;
    cursor_blink_state = true;
    cursor_blink_counter = 0;
    drawBlockCursor();
}

// =============================================================================
// T2.1: Helper — Get CSI parameter with default
// =============================================================================

fn getParam(idx: u32, default: u32) u32 {
    if (idx < csi_param_count) {
        const val = csi_params[idx];
        return if (val == 0) default else @as(u32, val);
    }
    return default;
}

// =============================================================================
// Character Output (T2.2: proper tab stops + word wrap)
// =============================================================================

fn putCharDirect(c: u8) void {
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
            // T2.2: Use tab stop array instead of fixed width
            const target = nextTabStop();
            // Fill with spaces up to the tab stop
            while (cursor_x < target and cursor_x < cols) {
                const line = getBufferLine(cursor_y);
                buffer[line][cursor_x] = .{
                    .char = ' ',
                    .fg = fg_color,
                    .bg = bg_color,
                    .bold = false,
                    .underline = false,
                    .wrapped = false,
                };
                drawChar(cursor_x, cursor_y, ' ', fg_color, bg_color);
                cursor_x += 1;
            }
            // Handle wrap if tab pushed past end
            if (cursor_x >= cols and auto_wrap) {
                cursor_x = 0;
                if (cursor_y >= scroll_bottom) {
                    scrollUpInternal();
                } else {
                    cursor_y += 1;
                }
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
                    .bold = false,
                    .underline = false,
                    .wrapped = false,
                };
                drawChar(cursor_x, cursor_y, ' ', fg_color, bg_color);
            }
        },
        0x7F => { // Delete
            putCharDirect(0x08);
        },
        0x07 => { // BEL — beep (ignore, no speaker)
        },
        else => {
            if (c >= 0x20 and c < 0x7F) {
                // Determine effective colors (handle inverse)
                var eff_fg = fg_color;
                var eff_bg = bg_color;
                if (current_inverse) {
                    eff_fg = bg_color;
                    eff_bg = fg_color;
                }

                const line = getBufferLine(cursor_y);
                buffer[line][cursor_x] = .{
                    .char = c,
                    .fg = eff_fg,
                    .bg = eff_bg,
                    .bold = current_bold,
                    .underline = current_underline,
                    .wrapped = false,
                };
                drawCharStyled(cursor_x, cursor_y, c, eff_fg, eff_bg, current_bold, current_underline);

                cursor_x += 1;
                if (cursor_x >= cols) {
                    if (auto_wrap) {
                        // T2.2: Mark this line as soft-wrapped
                        buffer[line][cols - 1].wrapped = true;

                        cursor_x = 0;
                        if (cursor_y >= scroll_bottom) {
                            scrollUpInternal();
                        } else {
                            cursor_y += 1;
                        }
                    } else {
                        // No auto-wrap: cursor stays at last column
                        cursor_x = cols - 1;
                    }
                }
            }
        },
    }

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
// T2.1: ANSI String Output Helpers
// =============================================================================

/// Write a raw ANSI escape sequence string
pub fn writeAnsi(s: []const u8) void {
    for (s) |c| {
        putChar(c);
    }
}

/// Write CSI sequence: ESC [ <params> <final>
pub fn writeCsi(params_str: []const u8, final_char: u8) void {
    putChar(0x1B);
    putChar('[');
    for (params_str) |c| {
        putChar(c);
    }
    putChar(final_char);
}

// =============================================================================
// T1.0: Styled Print Functions
// =============================================================================

/// Print text with bold style
pub fn printBold(s: []const u8) void {
    const was_bold = current_bold;
    current_bold = true;
    print(s);
    current_bold = was_bold;
}

/// Print text with underline style
pub fn printUnderline(s: []const u8) void {
    const was_underline = current_underline;
    current_underline = true;
    print(s);
    current_underline = was_underline;
}

/// Print text with specific color (restores previous after)
pub fn printColored(s: []const u8, color: ColorValue) void {
    const prev_fg = fg_color;
    fg_color = color;
    print(s);
    fg_color = prev_fg;
}

/// Print text with bold and color
pub fn printBoldColored(s: []const u8, color: ColorValue) void {
    const prev_fg = fg_color;
    const was_bold = current_bold;
    fg_color = color;
    current_bold = true;
    print(s);
    fg_color = prev_fg;
    current_bold = was_bold;
}

// =============================================================================
// T1.0: Unicode Box Drawing Support
// =============================================================================

/// Draw a horizontal line using box drawing chars
pub fn drawHLine(x: u32, y: u32, width: u32) void {
    if (!initialized) return;
    var i: u32 = 0;
    while (i < width) : (i += 1) {
        drawCodepoint(x + i, y, 0x2500, fg_color, bg_color);
    }
}

/// Draw a vertical line using box drawing chars
pub fn drawVLine(x: u32, y: u32, height: u32) void {
    if (!initialized) return;
    var i: u32 = 0;
    while (i < height) : (i += 1) {
        drawCodepoint(x, y + i, 0x2502, fg_color, bg_color);
    }
}

/// Draw a box with corners using box drawing chars
pub fn drawBox(x: u32, y: u32, width: u32, height: u32) void {
    if (!initialized) return;
    if (width < 2 or height < 2) return;

    // Corners
    drawCodepoint(x, y, 0x250C, fg_color, bg_color);
    drawCodepoint(x + width - 1, y, 0x2510, fg_color, bg_color);
    drawCodepoint(x, y + height - 1, 0x2514, fg_color, bg_color);
    drawCodepoint(x + width - 1, y + height - 1, 0x2518, fg_color, bg_color);

    // Top and bottom edges
    var i: u32 = 1;
    while (i < width - 1) : (i += 1) {
        drawCodepoint(x + i, y, 0x2500, fg_color, bg_color);
        drawCodepoint(x + i, y + height - 1, 0x2500, fg_color, bg_color);
    }

    // Left and right edges
    i = 1;
    while (i < height - 1) : (i += 1) {
        drawCodepoint(x, y + i, 0x2502, fg_color, bg_color);
        drawCodepoint(x + width - 1, y + i, 0x2502, fg_color, bg_color);
    }
}

/// Draw a double-line box
pub fn drawDoubleBox(x: u32, y: u32, width: u32, height: u32) void {
    if (!initialized) return;
    if (width < 2 or height < 2) return;

    drawCodepoint(x, y, 0x2554, fg_color, bg_color);
    drawCodepoint(x + width - 1, y, 0x2557, fg_color, bg_color);
    drawCodepoint(x, y + height - 1, 0x255A, fg_color, bg_color);
    drawCodepoint(x + width - 1, y + height - 1, 0x255D, fg_color, bg_color);

    var i: u32 = 1;
    while (i < width - 1) : (i += 1) {
        drawCodepoint(x + i, y, 0x2550, fg_color, bg_color);
        drawCodepoint(x + i, y + height - 1, 0x2550, fg_color, bg_color);
    }

    i = 1;
    while (i < height - 1) : (i += 1) {
        drawCodepoint(x, y + i, 0x2551, fg_color, bg_color);
        drawCodepoint(x + width - 1, y + i, 0x2551, fg_color, bg_color);
    }
}

/// Draw a rounded box
pub fn drawRoundedBox(x: u32, y: u32, width: u32, height: u32) void {
    if (!initialized) return;
    if (width < 2 or height < 2) return;

    drawCodepoint(x, y, 0x256D, fg_color, bg_color);
    drawCodepoint(x + width - 1, y, 0x256E, fg_color, bg_color);
    drawCodepoint(x, y + height - 1, 0x2570, fg_color, bg_color);
    drawCodepoint(x + width - 1, y + height - 1, 0x256F, fg_color, bg_color);

    var i: u32 = 1;
    while (i < width - 1) : (i += 1) {
        drawCodepoint(x + i, y, 0x2500, fg_color, bg_color);
        drawCodepoint(x + i, y + height - 1, 0x2500, fg_color, bg_color);
    }

    i = 1;
    while (i < height - 1) : (i += 1) {
        drawCodepoint(x, y + i, 0x2502, fg_color, bg_color);
        drawCodepoint(x + width - 1, y + i, 0x2502, fg_color, bg_color);
    }
}

/// Draw a progress bar using block elements
pub fn drawProgressBar(x: u32, y: u32, width: u32, progress: u32, max: u32) void {
    if (!initialized) return;
    if (width < 2 or max == 0) return;

    const inner_width = width - 2;
    const filled = (progress * inner_width) / max;

    drawCodepoint(x, y, 0x2502, fg_color, bg_color);

    var i: u32 = 0;
    while (i < inner_width) : (i += 1) {
        if (i < filled) {
            drawCodepoint(x + 1 + i, y, 0x2588, Colors.SUCCESS, bg_color);
        } else if (i == filled and progress < max) {
            drawCodepoint(x + 1 + i, y, 0x2592, Colors.GRAY, bg_color);
        } else {
            drawCodepoint(x + 1 + i, y, 0x2591, Colors.DARK_GRAY, bg_color);
        }
    }

    drawCodepoint(x + width - 1, y, 0x2502, fg_color, bg_color);
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
                .bold = false,
                .underline = false,
                .wrapped = false,
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
            .bold = false,
            .underline = false,
            .wrapped = false,
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
            .bold = false,
            .underline = false,
            .wrapped = false,
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

pub fn getCursorCol() u32 {
    return cursor_x;
}

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
// T2.2: Printable character helper
// =============================================================================

pub fn printChar(c: u8) void {
    putChar(c);
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
