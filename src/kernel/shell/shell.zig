//! Zamrud OS - Enhanced Professional Shell

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const vfs = @import("../fs/vfs.zig");
const timer = @import("../drivers/timer/timer.zig");
const commands = @import("commands.zig");
const ui = @import("ui.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_INPUT: usize = 256;
const MAX_HISTORY: usize = 32;
const TAB_COMPLETE_MAX: usize = 20;

// =============================================================================
// State
// =============================================================================

var input_buffer: [MAX_INPUT]u8 = [_]u8{0} ** MAX_INPUT;
var input_len: usize = 0;
var cursor_pos: usize = 0;

// History - FIX: Correct array initialization
var history: [MAX_HISTORY][MAX_INPUT]u8 = [_][MAX_INPUT]u8{[_]u8{0} ** MAX_INPUT} ** MAX_HISTORY;
var history_lens: [MAX_HISTORY]usize = [_]usize{0} ** MAX_HISTORY;
var history_count: usize = 0;
var history_index: usize = 0;
var browsing_history: bool = false;

// Tab completion
var completions: [TAB_COMPLETE_MAX][48]u8 = undefined;
var completion_lens: [TAB_COMPLETE_MAX]usize = [_]usize{0} ** TAB_COMPLETE_MAX;
var completion_count: usize = 0;
var completion_index: usize = 0;
var last_was_tab: bool = false;

var running: bool = false;
var initialized: bool = false;

// Prompt tracking
var prompt_row: u32 = 0;
var prompt_col: u32 = 0;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[SHELL] Initializing...\n");

    clearInputBuffer();
    history_count = 0;
    history_index = 0;

    ui.init();

    initialized = true;
    serial.writeString("[SHELL] Initialized\n");
}

pub fn run() void {
    running = true;

    if (terminal.isInitialized()) {
        terminal.clear();
        ui.refresh();
        terminal.setCursor(0, @intCast(ui.getContentStartRow()));
        drawWelcome();
    }

    while (running) {
        // Periodic status bar update
        ui.drawStatusBar();

        // Show prompt
        drawPrompt();

        // Read input
        readInput();

        if (input_len > 0) {
            addToHistory();

            // Track command for status
            var cmd_end: usize = 0;
            while (cmd_end < input_len and input_buffer[cmd_end] != ' ') : (cmd_end += 1) {}

            // Log to serial
            serial.writeString("[CMD] ");
            serial.writeString(input_buffer[0..input_len]);
            serial.writeString("\n");

            // Execute
            commands.execute(input_buffer[0..input_len]);

            // Update status
            ui.setLastCommand(input_buffer[0..cmd_end], true);
        }

        clearInputBuffer();
    }
}

pub fn stop() void {
    running = false;
}

// =============================================================================
// Welcome Screen
// =============================================================================

fn drawWelcome() void {
    const theme = ui.getTheme();

    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    println("  +============================================+");
    println("  |                                            |");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
    }
    print("  |");
    print("       * ZAMRUD OS v0.1.0 *                 ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    println("|");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    println("  |                                            |");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    print("  |");
    print("       Secure - Private - Decentralized     ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    println("|");

    println("  |                                            |");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    print("  |");
    print("       Type 'help' for commands             ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.border);
    }
    println("|");

    println("  |                                            |");
    println("  +============================================+");

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    newLine();
}

// =============================================================================
// Prompt
// =============================================================================

fn drawPrompt() void {
    if (terminal.isInitialized()) {
        prompt_col = terminal.getCursorCol();
        prompt_row = terminal.getCursorRow();
        ui.drawPrompt(vfs.getcwd());
    } else {
        serial.writeString(vfs.getcwd());
        serial.writeString("> ");
    }
}

// =============================================================================
// Input Handling (Simplified - ASCII only)
// =============================================================================

fn readInput() void {
    browsing_history = false;
    last_was_tab = false;

    while (true) {
        if (keyboard.hasKey()) {
            const ascii = keyboard.getKey() orelse continue;

            if (ascii == 0) continue;

            // Enter
            if (ascii == '\n' or ascii == '\r') {
                newLine();
                return;
            }

            // Backspace
            if (ascii == 8 or ascii == 127) {
                handleBackspace();
                continue;
            }

            // Tab
            if (ascii == '\t') {
                handleTabComplete();
                continue;
            }

            // Printable characters
            if (ascii >= 32 and ascii < 127) {
                insertChar(ascii);
                last_was_tab = false;
            }
        }

        asm volatile ("pause");
    }
}

fn insertChar(c: u8) void {
    if (input_len >= MAX_INPUT - 1) return;

    // Shift right if not at end
    if (cursor_pos < input_len) {
        var i = input_len;
        while (i > cursor_pos) : (i -= 1) {
            input_buffer[i] = input_buffer[i - 1];
        }
    }

    input_buffer[cursor_pos] = c;
    input_len += 1;
    cursor_pos += 1;

    redrawInput();
}

fn handleBackspace() void {
    if (cursor_pos == 0) return;

    // Shift left
    var i = cursor_pos - 1;
    while (i < input_len - 1) : (i += 1) {
        input_buffer[i] = input_buffer[i + 1];
    }
    input_buffer[input_len - 1] = 0;
    input_len -= 1;
    cursor_pos -= 1;

    redrawInput();
    last_was_tab = false;
}

fn redrawInput() void {
    if (!terminal.isInitialized()) return;

    // Go to prompt position
    terminal.setCursor(0, prompt_row);

    // Redraw prompt
    ui.drawPrompt(vfs.getcwd());

    // Draw input
    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        terminal.writeChar(input_buffer[i]);
    }

    // Clear rest of line
    i = 0;
    while (i < 10) : (i += 1) {
        terminal.writeChar(' ');
    }

    // Position cursor at end (simplified - no cursor movement)
    terminal.setCursor(0, prompt_row);
    ui.drawPrompt(vfs.getcwd());
    i = 0;
    while (i < cursor_pos) : (i += 1) {
        terminal.writeChar(input_buffer[i]);
    }
}

fn clearInputBuffer() void {
    var i: usize = 0;
    while (i < MAX_INPUT) : (i += 1) {
        input_buffer[i] = 0;
    }
    input_len = 0;
    cursor_pos = 0;
}

// =============================================================================
// Tab Completion
// =============================================================================

fn handleTabComplete() void {
    if (input_len == 0) return;

    // Find word start
    var word_start: usize = input_len;
    while (word_start > 0 and input_buffer[word_start - 1] != ' ') : (word_start -= 1) {}

    const prefix = input_buffer[word_start..input_len];
    if (prefix.len == 0) return;

    const is_first_word = (word_start == 0);

    if (!last_was_tab) {
        // First tab - find completions
        completion_count = 0;
        completion_index = 0;

        if (is_first_word) {
            findCommandCompletions(prefix);
        } else {
            findPathCompletions(prefix);
        }

        if (completion_count == 1) {
            applyCompletion(word_start, 0);
        } else if (completion_count > 1) {
            // Show all completions
            newLine();
            showCompletions();
            drawPrompt();
            redrawInput();
        }
    } else if (completion_count > 1) {
        // Cycle through completions
        completion_index = (completion_index + 1) % completion_count;
        applyCompletion(word_start, completion_index);
    }

    last_was_tab = true;
}

fn findCommandCompletions(prefix: []const u8) void {
    const cmds = [_][]const u8{
        "help",         "clear",    "info",    "uptime",   "memory",
        "history",      "echo",     "ls",      "cd",       "pwd",
        "mkdir",        "touch",    "rm",      "rmdir",    "cat",
        "write",        "lsdev",    "devtest", "ps",       "spawn",
        "kill",         "sched",    "crypto",  "chain",    "integrity",
        "identity",     "syscall",  "boot",    "whoami",   "theme",
        "reboot",       "shutdown", "exit",    "test-all", "test-fs",
        "test-syscall",
        // F3: User/Group
        "login",    "logout",  "id",       "su",
        "sudo",         "sudoend",  "user",    "usertest",
    };

    for (cmds) |cmd| {
        if (startsWith(cmd, prefix) and completion_count < TAB_COMPLETE_MAX) {
            copyToCompletion(completion_count, cmd);
            completion_count += 1;
        }
    }
}

fn findPathCompletions(prefix: []const u8) void {
    // Basic path completion from current directory
    const cwd = vfs.getcwd();
    var index: usize = 0;

    while (index < 32 and completion_count < TAB_COMPLETE_MAX) {
        const entry = vfs.readdir(cwd, index);
        if (entry == null) break;

        const name = entry.?.getName();
        if (startsWith(name, prefix)) {
            copyToCompletion(completion_count, name);
            completion_count += 1;
        }

        index += 1;
    }
}

fn copyToCompletion(idx: usize, str: []const u8) void {
    var i: usize = 0;
    while (i < str.len and i < 47) : (i += 1) {
        completions[idx][i] = str[i];
    }
    completions[idx][i] = 0;
    completion_lens[idx] = i;
}

fn applyCompletion(word_start: usize, idx: usize) void {
    if (idx >= completion_count) return;

    const comp_len = completion_lens[idx];

    // Replace word
    var i: usize = 0;
    while (i < comp_len and word_start + i < MAX_INPUT - 2) : (i += 1) {
        input_buffer[word_start + i] = completions[idx][i];
    }

    // Add space for commands
    if (word_start == 0 and word_start + i < MAX_INPUT - 1) {
        input_buffer[word_start + i] = ' ';
        i += 1;
    }

    input_len = word_start + i;
    cursor_pos = input_len;

    redrawInput();
}

fn showCompletions() void {
    const theme = ui.getTheme();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }

    var i: usize = 0;
    while (i < completion_count) : (i += 1) {
        print("  ");
        print(completions[i][0..completion_lens[i]]);

        if ((i + 1) % 5 == 0 and i + 1 < completion_count) {
            newLine();
        }
    }
    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (prefix.len > str.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        // Case insensitive
        var a = str[i];
        var b = prefix[i];
        if (a >= 'A' and a <= 'Z') a += 32;
        if (b >= 'A' and b <= 'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

// =============================================================================
// History
// =============================================================================

fn addToHistory() void {
    if (input_len == 0) return;

    // Skip duplicates
    if (history_count > 0 and history_lens[history_count - 1] == input_len) {
        var same = true;
        var i: usize = 0;
        while (i < input_len) : (i += 1) {
            if (history[history_count - 1][i] != input_buffer[i]) {
                same = false;
                break;
            }
        }
        if (same) return;
    }

    // Shift if full
    if (history_count >= MAX_HISTORY) {
        var i: usize = 0;
        while (i < MAX_HISTORY - 1) : (i += 1) {
            var j: usize = 0;
            while (j < MAX_INPUT) : (j += 1) {
                history[i][j] = history[i + 1][j];
            }
            history_lens[i] = history_lens[i + 1];
        }
        history_count = MAX_HISTORY - 1;
    }

    // Add
    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        history[history_count][i] = input_buffer[i];
    }
    history_lens[history_count] = input_len;
    history_count += 1;
    history_index = history_count;
}

pub fn getHistoryCount() usize {
    return history_count;
}

pub fn getHistoryEntry(idx: usize) ?[]const u8 {
    if (idx >= history_count) return null;
    return history[idx][0..history_lens[idx]];
}

// =============================================================================
// Output Functions
// =============================================================================

pub fn print(text: []const u8) void {
    if (terminal.isInitialized()) {
        for (text) |c| {
            terminal.writeChar(c);
        }
    }
    serial.writeString(text);
}

pub fn println(text: []const u8) void {
    print(text);
    newLine();
}

pub fn printChar(c: u8) void {
    if (terminal.isInitialized()) {
        terminal.writeChar(c);
    }
    serial.writeChar(c);
}

pub fn newLine() void {
    if (terminal.isInitialized()) {
        terminal.writeChar('\n');
    }
    serial.writeString("\n");
}

pub fn clearScreen() void {
    if (terminal.isInitialized()) {
        terminal.clear();
        ui.refresh();
        terminal.setCursor(0, @intCast(ui.getContentStartRow()));
    }
}

// Styled output
pub fn printSuccess(text: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_success);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printSuccessLine(text: []const u8) void {
    ui.showSuccess(text);
}

pub fn printError(text: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_error);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printErrorLine(text: []const u8) void {
    ui.showError(text);
}

pub fn printWarning(text: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_warning);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printWarningLine(text: []const u8) void {
    ui.showWarning(text);
}

pub fn printInfo(text: []const u8) void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_info);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printInfoLine(text: []const u8) void {
    ui.showInfo(text);
}
