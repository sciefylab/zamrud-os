//! Zamrud OS - Shell UI Components
//! Professional terminal interface elements

const terminal = @import("../drivers/display/terminal.zig");
const serial = @import("../drivers/serial/serial.zig");
const timer = @import("../drivers/timer/timer.zig");
const heap = @import("../mm/heap.zig");
const identity = @import("../identity/identity.zig");
const boot_verify = @import("../boot/verify.zig");

// =============================================================================
// Theme Colors
// =============================================================================

pub const Theme = struct {
    // Status bar
    status_bg: u32,
    status_fg: u32,
    status_accent: u32,

    // Prompt
    prompt_user: u32,
    prompt_path: u32,
    prompt_symbol: u32,
    prompt_error: u32,

    // Content
    text_normal: u32,
    text_dim: u32,
    text_bright: u32,
    text_success: u32,
    text_warning: u32,
    text_error: u32,
    text_info: u32,

    // Special
    border: u32,
    highlight: u32,
};

pub const themes = struct {
    pub const dark = Theme{
        .status_bg = 0x1A1A2E,
        .status_fg = 0xE0E0E0,
        .status_accent = 0x00D9FF,

        .prompt_user = 0x00D9FF,
        .prompt_path = 0x7FFF00,
        .prompt_symbol = 0xFFFFFF,
        .prompt_error = 0xFF4444,

        .text_normal = 0xE0E0E0,
        .text_dim = 0x808080,
        .text_bright = 0xFFFFFF,
        .text_success = 0x00FF7F,
        .text_warning = 0xFFD700,
        .text_error = 0xFF4444,
        .text_info = 0x00BFFF,

        .border = 0x404040,
        .highlight = 0x0066CC,
    };

    pub const light = Theme{
        .status_bg = 0x2196F3,
        .status_fg = 0xFFFFFF,
        .status_accent = 0xFFEB3B,

        .prompt_user = 0x1565C0,
        .prompt_path = 0x2E7D32,
        .prompt_symbol = 0x212121,
        .prompt_error = 0xC62828,

        .text_normal = 0x212121,
        .text_dim = 0x757575,
        .text_bright = 0x000000,
        .text_success = 0x2E7D32,
        .text_warning = 0xF57C00,
        .text_error = 0xC62828,
        .text_info = 0x1565C0,

        .border = 0xBDBDBD,
        .highlight = 0xBBDEFB,
    };

    pub const matrix = Theme{
        .status_bg = 0x001100,
        .status_fg = 0x00FF00,
        .status_accent = 0x00FF00,

        .prompt_user = 0x00FF00,
        .prompt_path = 0x00CC00,
        .prompt_symbol = 0x00FF00,
        .prompt_error = 0xFF0000,

        .text_normal = 0x00DD00,
        .text_dim = 0x006600,
        .text_bright = 0x00FF00,
        .text_success = 0x00FF00,
        .text_warning = 0xCCCC00,
        .text_error = 0xFF0000,
        .text_info = 0x00FFFF,

        .border = 0x003300,
        .highlight = 0x004400,
    };

    pub const dracula = Theme{
        .status_bg = 0x282A36,
        .status_fg = 0xF8F8F2,
        .status_accent = 0xBD93F9,

        .prompt_user = 0xBD93F9,
        .prompt_path = 0x50FA7B,
        .prompt_symbol = 0xF8F8F2,
        .prompt_error = 0xFF5555,

        .text_normal = 0xF8F8F2,
        .text_dim = 0x6272A4,
        .text_bright = 0xFFFFFF,
        .text_success = 0x50FA7B,
        .text_warning = 0xFFB86C,
        .text_error = 0xFF5555,
        .text_info = 0x8BE9FD,

        .border = 0x44475A,
        .highlight = 0x6272A4,
    };
};

// =============================================================================
// State
// =============================================================================

var current_theme: *const Theme = &themes.dark;
var status_bar_enabled: bool = true;
var last_command_success: bool = true;
var last_command_name: [32]u8 = [_]u8{0} ** 32;
var last_command_len: usize = 0;

var screen_width: u32 = 128;
var screen_height: u32 = 48;
var content_start_row: u32 = 2;
var initialized: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    if (terminal.isInitialized()) {
        screen_width = terminal.getCols();
        screen_height = terminal.getRows();
        content_start_row = 2;
    }
    initialized = true;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn setTheme(theme: *const Theme) void {
    current_theme = theme;
    if (terminal.isInitialized()) {
        refresh();
    }
}

pub fn getTheme() *const Theme {
    return current_theme;
}

pub fn getContentStartRow() u32 {
    return content_start_row;
}

// =============================================================================
// Status Bar
// =============================================================================

pub fn drawStatusBar() void {
    if (!terminal.isInitialized() or !status_bar_enabled) return;

    const saved_col = terminal.getCursorCol();
    const saved_row = terminal.getCursorRow();

    // Draw background
    terminal.setCursor(0, 0);
    terminal.setBgColor(current_theme.status_bg);
    terminal.setFgColor(current_theme.status_fg);

    // Clear line with spaces
    var i: u32 = 0;
    while (i < screen_width) : (i += 1) {
        terminal.writeChar(' ');
    }

    // Left side: Logo
    terminal.setCursor(1, 0);
    terminal.setFgColor(current_theme.status_accent);
    terminal.writeChar('*'); // Use '*' instead of 0x04
    terminal.writeChar(' ');
    terminal.setFgColor(current_theme.status_fg);
    writeStr("Zamrud");

    // Separator
    writeStr(" | ");

    // Identity
    if (identity.isInitialized()) {
        const current = identity.getCurrentIdentity();
        if (current != null) {
            if (current.?.unlocked) {
                terminal.setFgColor(current_theme.text_success);
                writeStr("[*] ");
            } else {
                terminal.setFgColor(current_theme.text_warning);
                writeStr("[ ] ");
            }
            terminal.setFgColor(current_theme.status_fg);
            const name = current.?.getName();
            if (name.len > 0) {
                writeStr(name);
            } else {
                writeStr("anon");
            }
        } else {
            terminal.setFgColor(current_theme.text_dim);
            writeStr("guest");
        }
    } else {
        terminal.setFgColor(current_theme.text_dim);
        writeStr("--");
    }

    // Right side
    if (screen_width > 60) {
        terminal.setCursor(screen_width - 40, 0);
        terminal.setFgColor(current_theme.status_fg);

        // Boot status
        if (boot_verify.isVerified()) {
            terminal.setFgColor(current_theme.text_success);
            writeStr("OK ");
        } else {
            terminal.setFgColor(current_theme.text_error);
            writeStr("!! ");
        }

        terminal.setFgColor(current_theme.status_fg);
        writeStr("| ");

        // Memory
        const stats = heap.getStats();
        const used_kb = stats.total_allocated / 1024;
        writeStr("Mem:");
        writeNumber(used_kb);
        writeStr("K | ");

        // Uptime
        const uptime = timer.getSeconds();
        const hours = uptime / 3600;
        const minutes = (uptime % 3600) / 60;
        const secs = uptime % 60;

        if (hours > 0) {
            writeNumber(hours);
            writeStr(":");
        }
        if (minutes < 10 and hours > 0) writeStr("0");
        writeNumber(minutes);
        writeStr(":");
        if (secs < 10) writeStr("0");
        writeNumber(secs);
    }

    // Restore
    terminal.setBgColor(0x000000);
    terminal.setFgColor(current_theme.text_normal);
    terminal.setCursor(saved_col, saved_row);
}

// =============================================================================
// Separator Line
// =============================================================================

pub fn drawSeparator() void {
    if (!terminal.isInitialized()) return;

    const saved_col = terminal.getCursorCol();
    const saved_row = terminal.getCursorRow();

    terminal.setCursor(0, 1);
    terminal.setFgColor(current_theme.border);

    var i: u32 = 0;
    while (i < screen_width) : (i += 1) {
        terminal.writeChar('-');
    }

    terminal.setFgColor(current_theme.text_normal);
    terminal.setCursor(saved_col, saved_row);
}

// =============================================================================
// Prompt
// =============================================================================

pub fn drawPrompt(cwd: []const u8) void {
    if (!terminal.isInitialized()) return;

    // Username
    terminal.setFgColor(current_theme.prompt_user);
    if (identity.isInitialized()) {
        const current = identity.getCurrentIdentity();
        if (current != null) {
            const name = current.?.getName();
            if (name.len > 0) {
                writeStr(name);
            } else {
                writeStr("anon");
            }
        } else {
            writeStr("guest");
        }
    } else {
        writeStr("zamrud");
    }

    // Separator
    terminal.setFgColor(current_theme.text_dim);
    writeStr(":");

    // Path
    terminal.setFgColor(current_theme.prompt_path);
    writeStr(cwd);

    // Symbol
    if (last_command_success) {
        terminal.setFgColor(current_theme.prompt_symbol);
    } else {
        terminal.setFgColor(current_theme.prompt_error);
    }
    writeStr(" > ");

    terminal.setFgColor(current_theme.text_normal);
}

// =============================================================================
// Messages
// =============================================================================

pub fn showSuccess(msg: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(current_theme.text_success);
        writeStr("[OK] ");
        terminal.setFgColor(current_theme.text_normal);
        writeStr(msg);
        terminal.writeChar('\n');
    }
    serial.writeString("[OK] ");
    serial.writeString(msg);
    serial.writeString("\n");
}

pub fn showError(msg: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(current_theme.text_error);
        writeStr("[ERR] ");
        terminal.setFgColor(current_theme.text_normal);
        writeStr(msg);
        terminal.writeChar('\n');
    }
    serial.writeString("[ERR] ");
    serial.writeString(msg);
    serial.writeString("\n");
}

pub fn showWarning(msg: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(current_theme.text_warning);
        writeStr("[WARN] ");
        terminal.setFgColor(current_theme.text_normal);
        writeStr(msg);
        terminal.writeChar('\n');
    }
    serial.writeString("[WARN] ");
    serial.writeString(msg);
    serial.writeString("\n");
}

pub fn showInfo(msg: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(current_theme.text_info);
        writeStr("[INFO] ");
        terminal.setFgColor(current_theme.text_normal);
        writeStr(msg);
        terminal.writeChar('\n');
    }
    serial.writeString("[INFO] ");
    serial.writeString(msg);
    serial.writeString("\n");
}

// =============================================================================
// Box Drawing
// =============================================================================

pub fn drawBox(x: u32, y: u32, width: u32, height: u32, title: ?[]const u8) void {
    if (!terminal.isInitialized()) return;
    if (width < 4 or height < 3) return;

    terminal.setFgColor(current_theme.border);

    // Top
    terminal.setCursor(x, y);
    terminal.writeChar('+');
    if (title) |t| {
        terminal.writeChar('-');
        terminal.setFgColor(current_theme.text_bright);
        writeStr(t);
        terminal.setFgColor(current_theme.border);
        terminal.writeChar('-');
        var i: u32 = @intCast(t.len + 3);
        while (i < width - 1) : (i += 1) {
            terminal.writeChar('-');
        }
    } else {
        var i: u32 = 1;
        while (i < width - 1) : (i += 1) {
            terminal.writeChar('-');
        }
    }
    terminal.writeChar('+');

    // Sides
    var row: u32 = 1;
    while (row < height - 1) : (row += 1) {
        terminal.setCursor(x, y + row);
        terminal.writeChar('|');
        terminal.setCursor(x + width - 1, y + row);
        terminal.writeChar('|');
    }

    // Bottom
    terminal.setCursor(x, y + height - 1);
    terminal.writeChar('+');
    var i: u32 = 1;
    while (i < width - 1) : (i += 1) {
        terminal.writeChar('-');
    }
    terminal.writeChar('+');

    terminal.setFgColor(current_theme.text_normal);
}

// =============================================================================
// Progress Bar
// =============================================================================

pub fn drawProgress(x: u32, y: u32, width: u32, percent: u8) void {
    if (!terminal.isInitialized()) return;

    terminal.setCursor(x, y);
    terminal.setFgColor(current_theme.border);
    terminal.writeChar('[');

    const bar_width: u32 = if (width > 7) width - 7 else 10;
    const filled: u32 = (@as(u32, percent) * bar_width) / 100;

    terminal.setFgColor(current_theme.text_success);
    var i: u32 = 0;
    while (i < filled) : (i += 1) {
        terminal.writeChar('#');
    }

    terminal.setFgColor(current_theme.text_dim);
    while (i < bar_width) : (i += 1) {
        terminal.writeChar('-');
    }

    terminal.setFgColor(current_theme.border);
    terminal.writeChar(']');

    terminal.setFgColor(current_theme.text_normal);
    terminal.writeChar(' ');
    writeNumber(percent);
    terminal.writeChar('%');
}

// =============================================================================
// Refresh
// =============================================================================

pub fn refresh() void {
    drawStatusBar();
    drawSeparator();
}

pub fn setLastCommand(name: []const u8, success: bool) void {
    last_command_success = success;
    last_command_len = 0;

    var i: usize = 0;
    while (i < name.len and i < 32) : (i += 1) {
        last_command_name[i] = name[i];
        last_command_len += 1;
    }
}

pub fn getLastCommandSuccess() bool {
    return last_command_success;
}

// =============================================================================
// Helpers
// =============================================================================

fn writeStr(s: []const u8) void {
    for (s) |c| {
        terminal.writeChar(c);
    }
}

fn writeNumber(val: anytype) void {
    const v: u64 = @intCast(val);
    if (v == 0) {
        terminal.writeChar('0');
        return;
    }

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var n = v;

    while (n > 0) : (i += 1) {
        buf[i] = @intCast((n % 10) + '0');
        n /= 10;
    }

    while (i > 0) {
        i -= 1;
        terminal.writeChar(buf[i]);
    }
}
