//! Zamrud OS - Enhanced Professional Shell (T3 + T4.2 + T4.3 + T5.1)
//! Full readline-style line editing with login, env vars, I/O redirection

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const vfs = @import("../fs/vfs.zig");
const timer = @import("../drivers/timer/timer.zig");
const commands = @import("commands.zig");
const ui = @import("ui.zig");
const users = @import("../security/users.zig");
const identity = @import("../identity/identity.zig");
const env = @import("env.zig"); // T4.2
const redir = @import("redir.zig"); // T4.3

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

// History
var history: [MAX_HISTORY][MAX_INPUT]u8 = [_][MAX_INPUT]u8{[_]u8{0} ** MAX_INPUT} ** MAX_HISTORY;
var history_lens: [MAX_HISTORY]usize = [_]usize{0} ** MAX_HISTORY;
var history_count: usize = 0;
var history_index: usize = 0;
var browsing_history: bool = false;

// T3: Saved input when browsing history
var saved_input: [MAX_INPUT]u8 = [_]u8{0} ** MAX_INPUT;
var saved_input_len: usize = 0;

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
var prompt_len: u32 = 0;

// T5.1: Login state
var logged_in: bool = false;
var current_user: [32]u8 = [_]u8{0} ** 32;
var current_user_len: usize = 0;
var home_dir: [64]u8 = [_]u8{0} ** 64;
var home_dir_len: usize = 0;

// T4.2: Last command exit status
var last_exit_success: bool = true;

// Track if login is required
var login_required: bool = false;

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    serial.writeString("[SHELL] Initializing...\n");

    clearInputBuffer();
    history_count = 0;
    history_index = 0;
    logged_in = false;
    current_user_len = 0;
    home_dir_len = 0;
    last_exit_success = true;
    login_required = false;

    ui.init();

    // T4.2: Initialize environment variables
    env.init();

    initialized = true;
    serial.writeString("[SHELL] Initialized (T3+T4.2+T4.3+T5.1)\n");
}

pub fn run() void {
    running = true;

    if (terminal.isInitialized()) {
        terminal.clear();
        ui.refresh();
        terminal.setCursor(0, @intCast(ui.getContentStartRow()));
    }

    // Determine if login is actually needed
    login_required = hasAnyUsers();

    if (login_required) {
        // Login loop
        while (running) {
            drawWelcome();
            loginPrompt();

            if (!logged_in) continue;

            shellLoop();

            logged_in = false;
            current_user_len = 0;
            home_dir_len = 0;

            env.clearLoginVars();

            if (terminal.isInitialized()) {
                terminal.clear();
                ui.refresh();
                terminal.setCursor(0, @intCast(ui.getContentStartRow()));
            }
        }
    } else {
        drawWelcome();
        autoLoginDefault();
        shellLoop();
    }
}

pub fn stop() void {
    running = false;
}

fn hasAnyUsers() bool {
    if (users.isInitialized() and users.getUserCount() > 0) {
        return true;
    }
    if (identity.isInitialized() and identity.getIdentityCount() > 0) {
        return true;
    }
    return false;
}

/// Called by logout command
pub fn logout() void {
    if (users.isInitialized() and users.isLoggedIn()) {
        users.logout();
    }
    logged_in = false;

    if (!login_required) {
        autoLoginDefault();
        return;
    }

    vfs.setCwd("/");
}

/// T4.2: Get last command exit status
pub fn getLastExitSuccess() bool {
    return last_exit_success;
}

/// T4.2: Set last command exit status
pub fn setLastExitSuccess(success: bool) void {
    last_exit_success = success;
}

// =============================================================================
// Auto-login (no users configured)
// =============================================================================

fn autoLoginDefault() void {
    const default_name = "zamrud";

    var i: usize = 0;
    while (i < default_name.len) : (i += 1) {
        current_user[i] = default_name[i];
    }
    current_user_len = default_name.len;

    logged_in = true;

    setupHomeDir(default_name);

    const home_path = home_dir[0..home_dir_len];
    env.setLoginVars(default_name, home_path);

    const theme = ui.getTheme();
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
        printDirect("  Type 'help' for available commands");
        newLineDirect();
        terminal.setFgColor(theme.text_normal);
        newLineDirect();
    }

    serial.writeString("[SHELL] Auto-login as zamrud (no users configured)\n");
}

fn setupHomeDir(username: []const u8) void {
    home_dir[0] = '/';
    home_dir[1] = 'h';
    home_dir[2] = 'o';
    home_dir[3] = 'm';
    home_dir[4] = 'e';
    home_dir[5] = '/';
    home_dir_len = 6;

    var i: usize = 0;
    while (i < username.len and home_dir_len < 63) : (i += 1) {
        home_dir[home_dir_len] = username[i];
        home_dir_len += 1;
    }

    const home_path = home_dir[0..home_dir_len];
    _ = vfs.ensureDir(home_path);
    vfs.setCwd(home_path);
}

// =============================================================================
// T5.1: Login Prompt
// =============================================================================

fn loginPrompt() void {
    const theme = ui.getTheme();

    var attempts: u32 = 0;
    while (attempts < 3 and running) : (attempts += 1) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
        printDirect("zamrud login: ");
        clearInputBuffer();
        readLoginInput();

        if (input_len == 0) continue;

        var i: usize = 0;
        while (i < input_len and i < 31) : (i += 1) {
            current_user[i] = input_buffer[i];
        }
        current_user_len = i;
        const username = current_user[0..current_user_len];

        newLine();

        if (users.isInitialized() and users.getUserCount() > 0) {
            if (users.findUserByName(username) != null) {
                if (users.login(username, "")) {
                    loginSuccess(username);
                    return;
                }
            }
        }

        if (identity.isInitialized() and identity.getIdentityCount() > 0) {
            if (identity.getCurrentIdentity()) |id| {
                const id_name = id.getName();
                if (strEql(username, id_name)) {
                    loginSuccess(username);
                    return;
                }
            }
        }

        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_error);
        }
        println("Login incorrect");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
        newLine();
    }

    if (attempts >= 3) {
        println("Too many failed login attempts.");
        newLine();
    }
}

fn loginSuccess(username: []const u8) void {
    const theme = ui.getTheme();

    logged_in = true;
    setupHomeDir(username);

    const home_path = home_dir[0..home_dir_len];
    env.setLoginVars(username, home_path);

    if (terminal.isInitialized()) {
        newLine();
        terminal.setFgColor(theme.text_success);
        printDirect("Welcome, ");
        printDirect(username);
        println("!");
        terminal.setFgColor(theme.text_dim);
        printDirect("Home: ");
        println(home_path);
        terminal.setFgColor(theme.text_normal);
        newLine();
    }

    serial.writeString("[LOGIN] User: ");
    serial.writeString(username);
    serial.writeString(" Home: ");
    serial.writeString(home_path);
    serial.writeString("\n");
}

pub fn getHomeDir() []const u8 {
    if (home_dir_len == 0) return "/";
    return home_dir[0..home_dir_len];
}

pub fn getCurrentUser() []const u8 {
    if (current_user_len == 0) return "zamrud";
    return current_user[0..current_user_len];
}

fn readLoginInput() void {
    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;
            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                return;
            }

            if (key == keyboard.KEY_BACKSPACE or key == 127) {
                if (input_len > 0) {
                    input_len -= 1;
                    input_buffer[input_len] = 0;
                    if (terminal.isInitialized()) {
                        terminal.writeChar(0x08);
                    }
                }
                continue;
            }

            if (key == keyboard.KEY_CTRL_C) {
                clearInputBuffer();
                newLine();
                return;
            }

            if (key >= 32 and key < 127 and input_len < MAX_INPUT - 1) {
                input_buffer[input_len] = key;
                input_len += 1;
                if (terminal.isInitialized()) {
                    terminal.writeChar(key);
                }
            }
        }
        asm volatile ("pause");
    }
}

// =============================================================================
// Main Shell Loop (T4.3: redirection support)
// =============================================================================

fn shellLoop() void {
    while (running and logged_in) {
        ui.drawStatusBar();

        drawPrompt();

        readInput();

        if (input_len > 0) {
            // Check logout
            if (strEql(input_buffer[0..input_len], "logout")) {
                if (login_required) {
                    println("Logging out...");
                    logout();
                    return;
                } else {
                    println("No login session — use 'shutdown' or 'reboot'");
                    clearInputBuffer();
                    continue;
                }
            }

            addToHistory();

            // T4.2: Expand environment variables
            const raw_input = input_buffer[0..input_len];
            const expanded = env.expandVars(raw_input);

            serial.writeString("[CMD] ");
            serial.writeString(expanded);
            serial.writeString("\n");

            // T4.2: Update $PWD before command
            env.updatePwd();

            // T4.3: Check for I/O redirection first
            if (!redir.executeWithRedirection(expanded)) {
                // No redirection — execute normally
                commands.execute(expanded);
            }

            // T4.2: Update $PWD after command
            env.updatePwd();

            // Update status bar with command name
            var cmd_end: usize = 0;
            while (cmd_end < expanded.len and expanded[cmd_end] != ' ') : (cmd_end += 1) {}
            ui.setLastCommand(expanded[0..cmd_end], last_exit_success);
        }

        clearInputBuffer();
    }
}

// =============================================================================
// Welcome Screen
// =============================================================================

fn drawWelcome() void {
    const theme = ui.getTheme();

    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.status_accent);
        terminal.setBold(true);
        println("  ZAMRUD OS v0.1.0");
        terminal.setBold(false);

        terminal.setFgColor(theme.text_dim);
        println("  Secure - Private - Decentralized");

        terminal.setFgColor(theme.text_normal);
        newLine();
    }
}

// =============================================================================
// Prompt
// =============================================================================

fn drawPrompt() void {
    if (terminal.isInitialized()) {
        prompt_row = terminal.getCursorRow();
        const col_before = terminal.getCursorCol();

        var display_path_buf: [128]u8 = undefined;
        const display_path = getDisplayPath(&display_path_buf);

        ui.drawPromptWithPath(display_path);

        prompt_len = terminal.getCursorCol() - col_before;
        prompt_col = terminal.getCursorCol();
    } else {
        serial.writeString(vfs.getcwd());
        serial.writeString("> ");
    }
}

fn getDisplayPath(buf: []u8) []const u8 {
    const cwd = vfs.getcwd();

    if (home_dir_len > 0 and cwd.len >= home_dir_len) {
        var match = true;
        var i: usize = 0;
        while (i < home_dir_len) : (i += 1) {
            if (cwd[i] != home_dir[i]) {
                match = false;
                break;
            }
        }

        if (match) {
            buf[0] = '~';
            if (cwd.len == home_dir_len) {
                return buf[0..1];
            } else {
                var j: usize = 1;
                i = home_dir_len;
                while (i < cwd.len and j < buf.len - 1) : ({
                    i += 1;
                    j += 1;
                }) {
                    buf[j] = cwd[i];
                }
                return buf[0..j];
            }
        }
    }

    return cwd;
}

// =============================================================================
// T3: Full Input Handling with Line Editing
// =============================================================================

fn readInput() void {
    browsing_history = false;
    last_was_tab = false;

    while (true) {
        if (keyboard.hasKey()) {
            const key = keyboard.getKey() orelse continue;

            if (key == 0) continue;

            if (key == '\n' or key == '\r') {
                newLine();
                return;
            }

            if (key == keyboard.KEY_BACKSPACE or key == 127) {
                handleBackspace();
                last_was_tab = false;
                continue;
            }

            if (key == '\t') {
                handleTabComplete();
                continue;
            }

            if (key == keyboard.KEY_LEFT) {
                handleCursorLeft();
                last_was_tab = false;
                continue;
            }
            if (key == keyboard.KEY_RIGHT) {
                handleCursorRight();
                last_was_tab = false;
                continue;
            }
            if (key == keyboard.KEY_UP) {
                handleHistoryUp();
                last_was_tab = false;
                continue;
            }
            if (key == keyboard.KEY_DOWN) {
                handleHistoryDown();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_HOME) {
                handleHome();
                last_was_tab = false;
                continue;
            }
            if (key == keyboard.KEY_END) {
                handleEnd();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_DELETE) {
                handleDelete();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_LEFT) {
                handleWordLeft();
                last_was_tab = false;
                continue;
            }
            if (key == keyboard.KEY_CTRL_RIGHT) {
                handleWordRight();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_SHIFT_PGUP) {
                terminal.scrollUp(10);
                continue;
            }
            if (key == keyboard.KEY_SHIFT_PGDN) {
                terminal.scrollDown(10);
                continue;
            }
            if (key == keyboard.KEY_SHIFT_HOME) {
                terminal.scrollUp(1000);
                continue;
            }
            if (key == keyboard.KEY_SHIFT_END) {
                terminal.scrollToBottom();
                continue;
            }

            if (key == keyboard.KEY_CTRL_A) {
                handleHome();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_E) {
                handleEnd();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_K) {
                handleKillToEnd();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_U) {
                handleKillToStart();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_W) {
                handleKillWord();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_L) {
                clearScreen();
                drawPrompt();
                redrawInput();
                last_was_tab = false;
                continue;
            }

            if (key == keyboard.KEY_CTRL_C) {
                handleCancel();
                last_was_tab = false;
                return;
            }

            if (key == keyboard.KEY_CTRL_D) {
                if (input_len == 0) {
                    if (login_required) {
                        newLine();
                        println("logout");
                        logout();
                        return;
                    } else {
                        continue;
                    }
                }
                handleDelete();
                last_was_tab = false;
                continue;
            }

            if (key >= 32 and key < 127) {
                insertChar(key);
                last_was_tab = false;
            }
        }

        asm volatile ("pause");
    }
}

// =============================================================================
// T3: Cursor Movement
// =============================================================================

fn handleCursorLeft() void {
    if (cursor_pos > 0) {
        cursor_pos -= 1;
        updateCursorPosition();
    }
}

fn handleCursorRight() void {
    if (cursor_pos < input_len) {
        cursor_pos += 1;
        updateCursorPosition();
    }
}

fn handleHome() void {
    cursor_pos = 0;
    updateCursorPosition();
}

fn handleEnd() void {
    cursor_pos = input_len;
    updateCursorPosition();
}

fn handleWordLeft() void {
    if (cursor_pos == 0) return;
    while (cursor_pos > 0 and input_buffer[cursor_pos - 1] == ' ') {
        cursor_pos -= 1;
    }
    while (cursor_pos > 0 and input_buffer[cursor_pos - 1] != ' ') {
        cursor_pos -= 1;
    }
    updateCursorPosition();
}

fn handleWordRight() void {
    if (cursor_pos >= input_len) return;
    while (cursor_pos < input_len and input_buffer[cursor_pos] != ' ') {
        cursor_pos += 1;
    }
    while (cursor_pos < input_len and input_buffer[cursor_pos] == ' ') {
        cursor_pos += 1;
    }
    updateCursorPosition();
}

fn updateCursorPosition() void {
    if (!terminal.isInitialized()) return;
    terminal.setCursor(prompt_col + @as(u32, @intCast(cursor_pos)), prompt_row);
}

// =============================================================================
// T3: Line Editing
// =============================================================================

fn insertChar(c: u8) void {
    if (input_len >= MAX_INPUT - 1) return;
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
    var i = cursor_pos - 1;
    while (i < input_len - 1) : (i += 1) {
        input_buffer[i] = input_buffer[i + 1];
    }
    input_buffer[input_len - 1] = 0;
    input_len -= 1;
    cursor_pos -= 1;
    redrawInput();
}

fn handleDelete() void {
    if (cursor_pos >= input_len) return;
    var i = cursor_pos;
    while (i < input_len - 1) : (i += 1) {
        input_buffer[i] = input_buffer[i + 1];
    }
    input_buffer[input_len - 1] = 0;
    input_len -= 1;
    redrawInput();
}

fn handleKillToEnd() void {
    var i = cursor_pos;
    while (i < MAX_INPUT) : (i += 1) {
        input_buffer[i] = 0;
    }
    input_len = cursor_pos;
    redrawInput();
}

fn handleKillToStart() void {
    if (cursor_pos == 0) return;
    const remaining = input_len - cursor_pos;
    var i: usize = 0;
    while (i < remaining) : (i += 1) {
        input_buffer[i] = input_buffer[cursor_pos + i];
    }
    while (i < input_len) : (i += 1) {
        input_buffer[i] = 0;
    }
    input_len = remaining;
    cursor_pos = 0;
    redrawInput();
}

fn handleKillWord() void {
    if (cursor_pos == 0) return;
    var new_pos = cursor_pos;
    while (new_pos > 0 and input_buffer[new_pos - 1] == ' ') {
        new_pos -= 1;
    }
    while (new_pos > 0 and input_buffer[new_pos - 1] != ' ') {
        new_pos -= 1;
    }
    const deleted = cursor_pos - new_pos;
    if (deleted == 0) return;
    const remaining = input_len - cursor_pos;
    var i: usize = 0;
    while (i < remaining) : (i += 1) {
        input_buffer[new_pos + i] = input_buffer[cursor_pos + i];
    }
    i = new_pos + remaining;
    while (i < input_len) : (i += 1) {
        input_buffer[i] = 0;
    }
    input_len -= deleted;
    cursor_pos = new_pos;
    redrawInput();
}

fn handleCancel() void {
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_error);
        writeStr("^C");
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString("^C\n");
    newLine();
    clearInputBuffer();
}

// =============================================================================
// T3: Command History
// =============================================================================

fn handleHistoryUp() void {
    if (history_count == 0) return;
    if (!browsing_history) {
        saved_input_len = input_len;
        var i: usize = 0;
        while (i < input_len) : (i += 1) {
            saved_input[i] = input_buffer[i];
        }
        browsing_history = true;
        history_index = history_count;
    }
    if (history_index > 0) {
        history_index -= 1;
        loadHistoryEntry(history_index);
    }
}

fn handleHistoryDown() void {
    if (!browsing_history) return;
    if (history_index < history_count - 1) {
        history_index += 1;
        loadHistoryEntry(history_index);
    } else {
        history_index = history_count;
        input_len = saved_input_len;
        cursor_pos = saved_input_len;
        var i: usize = 0;
        while (i < saved_input_len) : (i += 1) {
            input_buffer[i] = saved_input[i];
        }
        while (i < MAX_INPUT) : (i += 1) {
            input_buffer[i] = 0;
        }
        browsing_history = false;
        redrawInput();
    }
}

fn loadHistoryEntry(idx: usize) void {
    if (idx >= history_count) return;
    input_len = history_lens[idx];
    cursor_pos = input_len;
    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        input_buffer[i] = history[idx][i];
    }
    while (i < MAX_INPUT) : (i += 1) {
        input_buffer[i] = 0;
    }
    redrawInput();
}

// =============================================================================
// Input Redraw
// =============================================================================

fn redrawInput() void {
    if (!terminal.isInitialized()) return;
    terminal.setCursor(0, prompt_row);
    var display_path_buf: [128]u8 = undefined;
    const display_path = getDisplayPath(&display_path_buf);
    ui.drawPromptWithPath(display_path);
    prompt_col = terminal.getCursorCol();
    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        terminal.writeChar(input_buffer[i]);
    }
    var clear_count: usize = 0;
    while (clear_count < 10) : (clear_count += 1) {
        terminal.writeChar(' ');
    }
    updateCursorPosition();
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
    var word_start: usize = input_len;
    while (word_start > 0 and input_buffer[word_start - 1] != ' ') : (word_start -= 1) {}
    const prefix = input_buffer[word_start..input_len];
    if (prefix.len == 0) return;
    const is_first_word = (word_start == 0);

    if (!last_was_tab) {
        completion_count = 0;
        completion_index = 0;
        if (is_first_word) {
            findCommandCompletions(prefix);
        } else {
            if (prefix.len > 0 and prefix[0] == '$') {
                findEnvCompletions(prefix[1..]);
            } else {
                findPathCompletions(prefix);
            }
        }
        if (completion_count == 1) {
            applyCompletion(word_start, 0);
        } else if (completion_count > 1) {
            newLine();
            showCompletions();
            drawPrompt();
            redrawInput();
        }
    } else if (completion_count > 1) {
        completion_index = (completion_index + 1) % completion_count;
        applyCompletion(word_start, completion_index);
    }
    last_was_tab = true;
}

fn findCommandCompletions(prefix: []const u8) void {
    const cmds = [_][]const u8{
        "help",     "clear",        "info",    "uptime",   "memory",
        "history",  "echo",         "ls",      "cd",       "pwd",
        "mkdir",    "touch",        "rm",      "rmdir",    "cat",
        "write",    "lsdev",        "devtest", "ps",       "spawn",
        "kill",     "sched",        "crypto",  "chain",    "integrity",
        "identity", "syscall",      "boot",    "whoami",   "theme",
        "reboot",   "shutdown",     "exit",    "logout",   "test-all",
        "test-fs",  "test-syscall", "login",   "id",       "su",
        "sudo",     "sudoend",      "user",    "usertest", "set",
        "unset",    "env",          "export",  "printenv",
    };
    for (cmds) |cmd| {
        if (startsWith(cmd, prefix) and completion_count < TAB_COMPLETE_MAX) {
            copyToCompletion(completion_count, cmd);
            completion_count += 1;
        }
    }
}

fn findEnvCompletions(prefix: []const u8) void {
    var idx: usize = 0;
    while (idx < env.getVarCount()) : (idx += 1) {
        if (env.getEntry(idx)) |entry| {
            if (startsWith(entry.key, prefix) and completion_count < TAB_COMPLETE_MAX) {
                var buf: [48]u8 = undefined;
                buf[0] = '$';
                var i: usize = 0;
                while (i < entry.key.len and i + 1 < 47) : (i += 1) {
                    buf[i + 1] = entry.key[i];
                }
                copyToCompletion(completion_count, buf[0 .. i + 1]);
                completion_count += 1;
            }
        } else break;
    }
}

fn findPathCompletions(prefix: []const u8) void {
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
    var i: usize = 0;
    while (i < comp_len and word_start + i < MAX_INPUT - 2) : (i += 1) {
        input_buffer[word_start + i] = completions[idx][i];
    }
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
        printDirect("  ");
        printDirect(completions[i][0..completion_lens[i]]);
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
// T4.3: Output Functions (capture-aware)
// =============================================================================

/// Direct print — always goes to terminal+serial (never captured)
fn printDirect(text: []const u8) void {
    if (terminal.isInitialized()) {
        for (text) |c| {
            terminal.writeChar(c);
        }
    }
    serial.writeString(text);
}

/// Direct newline — always goes to terminal+serial
fn newLineDirect() void {
    if (terminal.isInitialized()) {
        terminal.writeChar('\n');
    }
    serial.writeString("\n");
}

/// Print — goes to capture buffer when capturing, otherwise to terminal+serial
pub fn print(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr(text);
        serial.writeString(text);
        return;
    }
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

/// PrintChar — capture-aware
pub fn printChar(c: u8) void {
    if (redir.isCapturing()) {
        redir.captureChar(c);
        serial.writeChar(c);
        return;
    }
    if (terminal.isInitialized()) {
        terminal.writeChar(c);
    }
    serial.writeChar(c);
}

/// NewLine — capture-aware
pub fn newLine() void {
    if (redir.isCapturing()) {
        redir.captureChar('\n');
        serial.writeString("\n");
        return;
    }
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

pub fn printSuccess(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr(text);
        serial.writeString(text);
        return;
    }
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_success);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printSuccessLine(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr("[OK] ");
        redir.captureStr(text);
        redir.captureChar('\n');
        serial.writeString(text);
        return;
    }
    ui.showSuccess(text);
}

pub fn printError(text: []const u8) void {
    // Errors always go to terminal (not captured) — like stderr
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_error);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printErrorLine(text: []const u8) void {
    // Errors always go to terminal (stderr behavior)
    ui.showError(text);
}

pub fn printWarning(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr(text);
        serial.writeString(text);
        return;
    }
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_warning);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printWarningLine(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr("[WARN] ");
        redir.captureStr(text);
        redir.captureChar('\n');
        serial.writeString(text);
        return;
    }
    ui.showWarning(text);
}

pub fn printInfo(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr(text);
        serial.writeString(text);
        return;
    }
    if (terminal.isInitialized()) {
        terminal.setFgColor(ui.getTheme().text_info);
        for (text) |c| terminal.writeChar(c);
        terminal.setFgColor(ui.getTheme().text_normal);
    }
    serial.writeString(text);
}

pub fn printInfoLine(text: []const u8) void {
    if (redir.isCapturing()) {
        redir.captureStr("[INFO] ");
        redir.captureStr(text);
        redir.captureChar('\n');
        serial.writeString(text);
        return;
    }
    ui.showInfo(text);
}

// =============================================================================
// Helpers
// =============================================================================

fn writeStr(s: []const u8) void {
    for (s) |c| {
        terminal.writeChar(c);
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
