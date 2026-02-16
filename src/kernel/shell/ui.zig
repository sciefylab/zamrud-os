//! Zamrud OS - Shell UI Components
//! Professional terminal interface with Zamrud Emerald Forest theme
//! T3: Fixed cursor positioning — all text-based rendering

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
    // =========================================================================
    // DEFAULT: Zamrud Emerald Forest
    // =========================================================================
    pub const zamrud = Theme{
        .status_bg = 0xFF081808,
        .status_fg = 0xFFA8D5A0,
        .status_accent = 0xFF50FA7B,

        .prompt_user = 0xFF50FA7B,
        .prompt_path = 0xFF2ECC71,
        .prompt_symbol = 0xFFD4AF37,
        .prompt_error = 0xFFE74C3C,

        .text_normal = 0xFFD0E8D0,
        .text_dim = 0xFF4A6B4A,
        .text_bright = 0xFFEAFFEA,
        .text_success = 0xFF27AE60,
        .text_warning = 0xFFF39C12,
        .text_error = 0xFFE74C3C,
        .text_info = 0xFF5DADE2,

        .border = 0xFF1B5E20,
        .highlight = 0xFF2E7D32,
    };

    pub const dark = Theme{
        .status_bg = 0xFF1A1A2E,
        .status_fg = 0xFFE0E0E0,
        .status_accent = 0xFF00D9FF,

        .prompt_user = 0xFF00D9FF,
        .prompt_path = 0xFF7FFF00,
        .prompt_symbol = 0xFFFFFFFF,
        .prompt_error = 0xFFFF4444,

        .text_normal = 0xFFE0E0E0,
        .text_dim = 0xFF808080,
        .text_bright = 0xFFFFFFFF,
        .text_success = 0xFF00FF7F,
        .text_warning = 0xFFFFD700,
        .text_error = 0xFFFF4444,
        .text_info = 0xFF00BFFF,

        .border = 0xFF404040,
        .highlight = 0xFF0066CC,
    };

    pub const light = Theme{
        .status_bg = 0xFF2196F3,
        .status_fg = 0xFFFFFFFF,
        .status_accent = 0xFFFFEB3B,

        .prompt_user = 0xFF1565C0,
        .prompt_path = 0xFF2E7D32,
        .prompt_symbol = 0xFF212121,
        .prompt_error = 0xFFC62828,

        .text_normal = 0xFF212121,
        .text_dim = 0xFF757575,
        .text_bright = 0xFF000000,
        .text_success = 0xFF2E7D32,
        .text_warning = 0xFFF57C00,
        .text_error = 0xFFC62828,
        .text_info = 0xFF1565C0,

        .border = 0xFFBDBDBD,
        .highlight = 0xFFBBDEFB,
    };

    pub const matrix = Theme{
        .status_bg = 0xFF001100,
        .status_fg = 0xFF00FF00,
        .status_accent = 0xFF00FF00,

        .prompt_user = 0xFF00FF00,
        .prompt_path = 0xFF00CC00,
        .prompt_symbol = 0xFF00FF00,
        .prompt_error = 0xFFFF0000,

        .text_normal = 0xFF00DD00,
        .text_dim = 0xFF006600,
        .text_bright = 0xFF00FF00,
        .text_success = 0xFF00FF00,
        .text_warning = 0xFFCCCC00,
        .text_error = 0xFFFF0000,
        .text_info = 0xFF00FFFF,

        .border = 0xFF003300,
        .highlight = 0xFF004400,
    };

    pub const dracula = Theme{
        .status_bg = 0xFF282A36,
        .status_fg = 0xFFF8F8F2,
        .status_accent = 0xFFBD93F9,

        .prompt_user = 0xFFBD93F9,
        .prompt_path = 0xFF50FA7B,
        .prompt_symbol = 0xFFF8F8F2,
        .prompt_error = 0xFFFF5555,

        .text_normal = 0xFFF8F8F2,
        .text_dim = 0xFF6272A4,
        .text_bright = 0xFFFFFFFF,
        .text_success = 0xFF50FA7B,
        .text_warning = 0xFFFFB86C,
        .text_error = 0xFFFF5555,
        .text_info = 0xFF8BE9FD,

        .border = 0xFF44475A,
        .highlight = 0xFF6272A4,
    };

    pub const zamrud_deep = Theme{
        .status_bg = 0xFF041208,
        .status_fg = 0xFF7CB87C,
        .status_accent = 0xFF00FF88,

        .prompt_user = 0xFF00FF88,
        .prompt_path = 0xFF1ABC9C,
        .prompt_symbol = 0xFFC8A832,
        .prompt_error = 0xFFFF4444,

        .text_normal = 0xFFB8D8B8,
        .text_dim = 0xFF355E35,
        .text_bright = 0xFFD4FFD4,
        .text_success = 0xFF00E676,
        .text_warning = 0xFFFFAB40,
        .text_error = 0xFFFF5252,
        .text_info = 0xFF40C4FF,

        .border = 0xFF0D3B1E,
        .highlight = 0xFF1B5E20,
    };
};

// =============================================================================
// Background constant — single source of truth
// =============================================================================

pub const BG_FOREST: u32 = 0xFF050F05;

// =============================================================================
// State
// =============================================================================

var current_theme: *const Theme = &themes.zamrud;
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

        terminal.setBgColor(BG_FOREST);
        terminal.setFgColor(current_theme.text_normal);
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

/// Get theme by name string
pub fn getThemeByName(name: []const u8) ?*const Theme {
    if (strEql(name, "zamrud")) return &themes.zamrud;
    if (strEql(name, "zamrud-deep")) return &themes.zamrud_deep;
    if (strEql(name, "dark")) return &themes.dark;
    if (strEql(name, "light")) return &themes.light;
    if (strEql(name, "matrix")) return &themes.matrix;
    if (strEql(name, "dracula")) return &themes.dracula;
    return null;
}

/// List available themes
pub fn listThemes() void {
    terminal.setFgColor(current_theme.text_bright);
    terminal.setBold(true);
    writeStr("  Available Themes:\n");
    terminal.setBold(false);
    terminal.setFgColor(current_theme.text_normal);

    const theme_list = [_]struct { name: []const u8, desc: []const u8, is_current: bool }{
        .{ .name = "zamrud", .desc = "Emerald Forest (default)", .is_current = current_theme == &themes.zamrud },
        .{ .name = "zamrud-deep", .desc = "Deep Midnight Forest", .is_current = current_theme == &themes.zamrud_deep },
        .{ .name = "dark", .desc = "Classic Dark", .is_current = current_theme == &themes.dark },
        .{ .name = "light", .desc = "Light", .is_current = current_theme == &themes.light },
        .{ .name = "matrix", .desc = "Matrix Green", .is_current = current_theme == &themes.matrix },
        .{ .name = "dracula", .desc = "Dracula", .is_current = current_theme == &themes.dracula },
    };

    for (theme_list) |t| {
        if (t.is_current) {
            terminal.setFgColor(current_theme.status_accent);
            writeStr("  > ");
        } else {
            writeStr("    ");
        }

        terminal.setFgColor(current_theme.text_info);
        writeStr(t.name);

        // Pad to align
        const pad: usize = 14;
        if (t.name.len < pad) {
            var p: usize = 0;
            while (p < pad - t.name.len) : (p += 1) {
                terminal.writeChar(' ');
            }
        }

        terminal.setFgColor(current_theme.text_dim);
        writeStr(t.desc);

        if (t.is_current) {
            terminal.setFgColor(current_theme.text_success);
            writeStr(" (active)");
        }

        terminal.writeChar('\n');
        terminal.setFgColor(current_theme.text_normal);
    }
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

    // Clear status line
    var i: u32 = 0;
    while (i < screen_width) : (i += 1) {
        terminal.writeChar(' ');
    }

    // Left side: Logo
    terminal.setCursor(1, 0);
    terminal.setFgColor(current_theme.status_accent);
    terminal.setBold(true);
    writeStr("* Zamrud");
    terminal.setBold(false);

    // Separator
    terminal.setFgColor(current_theme.border);
    writeStr(" | ");

    // Identity
    if (identity.isInitialized()) {
        const current = identity.getCurrentIdentity();
        if (current != null) {
            if (current.?.unlocked) {
                terminal.setFgColor(current_theme.text_success);
                writeStr("[+] ");
            } else {
                terminal.setFgColor(current_theme.text_warning);
                writeStr("[-] ");
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
        terminal.setFgColor(current_theme.border);
        writeStr("| ");
        if (boot_verify.isVerified()) {
            terminal.setFgColor(current_theme.text_success);
            writeStr("OK ");
        } else {
            terminal.setFgColor(current_theme.text_error);
            writeStr("!! ");
        }

        // Memory
        terminal.setFgColor(current_theme.border);
        writeStr("| ");
        terminal.setFgColor(current_theme.status_fg);

        const stats = heap.getStats();
        const used_kb = stats.total_allocated / 1024;
        writeStr("Mem:");
        writeNumber(used_kb);
        writeStr("K ");

        // Uptime
        terminal.setFgColor(current_theme.border);
        writeStr("| ");
        terminal.setFgColor(current_theme.text_info);

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
    terminal.setBgColor(BG_FOREST);
    terminal.setFgColor(current_theme.text_normal);
    terminal.setBold(false);
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
// Prompt — Text-only, cursor-safe
// =============================================================================

pub fn drawPrompt(cwd: []const u8) void {
    if (!terminal.isInitialized()) return;

    // Username (bold, emerald)
    terminal.setFgColor(current_theme.prompt_user);
    terminal.setBold(true);
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
    terminal.setBold(false);

    // @host
    terminal.setFgColor(current_theme.text_dim);
    writeStr("@");
    terminal.setFgColor(current_theme.status_accent);
    writeStr("zamrud");

    // :path
    terminal.setFgColor(current_theme.text_dim);
    writeStr(":");
    terminal.setFgColor(current_theme.prompt_path);
    terminal.setBold(true);
    writeStr(cwd);
    terminal.setBold(false);

    // Prompt symbol
    if (last_command_success) {
        terminal.setFgColor(current_theme.prompt_symbol);
    } else {
        terminal.setFgColor(current_theme.prompt_error);
    }
    writeStr(" > ");

    terminal.setFgColor(current_theme.text_normal);
}

// =============================================================================
// Messages — Text-only, cursor-safe
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
// Box Drawing — Text-based, cursor-safe
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
        var filled: u32 = @intCast(t.len + 3);
        while (filled < width - 1) : (filled += 1) {
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

/// Double-line box for emphasis
pub fn drawDoubleBox(x: u32, y: u32, width: u32, height: u32, title: ?[]const u8) void {
    if (!terminal.isInitialized()) return;
    if (width < 4 or height < 3) return;

    terminal.setFgColor(current_theme.status_accent);

    // Top
    terminal.setCursor(x, y);
    terminal.writeChar('#');
    if (title) |t| {
        terminal.writeChar('=');
        terminal.setFgColor(current_theme.text_bright);
        terminal.setBold(true);
        writeStr(t);
        terminal.setBold(false);
        terminal.setFgColor(current_theme.status_accent);
        terminal.writeChar('=');
        var filled: u32 = @intCast(t.len + 3);
        while (filled < width - 1) : (filled += 1) {
            terminal.writeChar('=');
        }
    } else {
        var i: u32 = 1;
        while (i < width - 1) : (i += 1) {
            terminal.writeChar('=');
        }
    }
    terminal.writeChar('#');

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
    terminal.writeChar('#');
    var i: u32 = 1;
    while (i < width - 1) : (i += 1) {
        terminal.writeChar('=');
    }
    terminal.writeChar('#');

    terminal.setFgColor(current_theme.text_normal);
}

// =============================================================================
// Progress Bar — Text-based
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

/// Draw prompt with custom path (used for ~ substitution)
pub fn drawPromptWithPath(display_path: []const u8) void {
    if (!terminal.isInitialized()) return;

    // Username (bold, emerald)
    terminal.setFgColor(current_theme.prompt_user);
    terminal.setBold(true);
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
    terminal.setBold(false);

    // @host
    terminal.setFgColor(current_theme.text_dim);
    writeStr("@");
    terminal.setFgColor(current_theme.status_accent);
    writeStr("zamrud");

    // :path
    terminal.setFgColor(current_theme.text_dim);
    writeStr(":");
    terminal.setFgColor(current_theme.prompt_path);
    terminal.setBold(true);
    writeStr(display_path);
    terminal.setBold(false);

    // Prompt symbol
    if (last_command_success) {
        terminal.setFgColor(current_theme.prompt_symbol);
    } else {
        terminal.setFgColor(current_theme.prompt_error);
    }
    writeStr(" > ");

    terminal.setFgColor(current_theme.text_normal);
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

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        var la = ca;
        var lb = cb;
        if (la >= 'A' and la <= 'Z') la += 32;
        if (lb >= 'A' and lb <= 'Z') lb += 32;
        if (la != lb) return false;
    }
    return true;
}
