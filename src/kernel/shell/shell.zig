//! Zamrud OS - Enhanced Professional Shell (T3 + T4.2 + T4.3 + T5.1 + H.7)
//! Full readline-style line editing with login, env vars, I/O redirection
//! H.7 FIX: Proper login gate, identity loading, system key management
//! FIX: Keyboard buffer cleared after login to prevent ghost characters

const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const vfs = @import("../fs/vfs.zig");
const timer = @import("../drivers/timer/timer.zig");
const commands = @import("commands.zig");
const ui = @import("ui.zig");
const users = @import("../security/users.zig");
const identity = @import("../identity/identity.zig");
const env = @import("env.zig");
const redir = @import("redir.zig");

// H.7: Additional imports for login gate
const identity_store = @import("../persist/identity_store.zig");
const config_store = @import("../persist/config_store.zig");
const trust_ceremony = @import("../boot/trust_ceremony.zig");
const sys_encrypt = @import("../crypto/sys_encrypt.zig");
const auth = @import("../identity/auth.zig");
const rtc = @import("../drivers/timer/rtc.zig");

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

// H.7: Recovery mode flag
var recovery_mode: bool = false;

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
    recovery_mode = false;

    ui.init();

    // T4.2: Initialize environment variables
    env.init();

    initialized = true;
    serial.writeString("[SHELL] Initialized (T3+T4.2+T4.3+T5.1+H.7)\n");
}

// =============================================================================
// H.7: Login Requirement Detection
// =============================================================================

fn hasAnyUsers() bool {
    // Check users system
    if (users.isInitialized() and users.getUserCount() > 0) {
        return true;
    }

    // Check identity system
    if (identity.isInitialized() and identity.getIdentityCount() > 0) {
        return true;
    }

    return false;
}

/// H.7: Determine if login MUST be required
/// This is smarter than just checking "has users" - it considers disk state
fn mustRequireLogin() bool {
    // Always require login if ceremony just completed
    if (trust_ceremony.ceremonyJustCompleted()) {
        serial.writeString("[SHELL] Login required: ceremony just completed\n");
        return true;
    }

    // Always require login for returning users
    if (trust_ceremony.isReturningUser()) {
        serial.writeString("[SHELL] Login required: returning user\n");
        return true;
    }

    // Check if identity file exists on disk (even if not loaded yet)
    if (identity_store.hasIdentityFile()) {
        serial.writeString("[SHELL] Login required: identity file exists\n");
        return true;
    }

    // Check if ceremony was ever completed (config flag)
    if (trust_ceremony.isCeremonyComplete()) {
        serial.writeString("[SHELL] Login required: ceremony was completed\n");
        return true;
    }

    // Fallback: check memory
    if (hasAnyUsers()) {
        serial.writeString("[SHELL] Login required: users in memory\n");
        return true;
    }

    serial.writeString("[SHELL] No login required: first boot, no ceremony\n");
    return false;
}

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn run() void {
    running = true;

    if (terminal.isInitialized()) {
        terminal.clear();
        ui.refresh();
        terminal.setCursor(0, @intCast(ui.getContentStartRow()));
    }

    // End keyboard grace period — shell is ready for input
    keyboard.endGracePeriod();

    // H.7 FIX: Use mustRequireLogin() instead of hasAnyUsers()
    login_required = mustRequireLogin();

    if (login_required) {
        // Login loop
        while (running) {
            drawWelcome();

            // H.7: Load identities NOW (before login prompt)
            // This is when we actually deserialize the file
            if (!hasAnyUsers()) {
                if (identity_store.hasIdentityFile()) {
                    serial.writeString("[SHELL] Loading identities from disk...\n");
                    if (!identity_store.loadFromDisk()) {
                        // Load failed - show recovery options
                        showRecoveryPrompt();
                        if (recovery_mode) {
                            // Enter recovery shell
                            autoLoginRecovery();
                            shellLoop();
                            recovery_mode = false;
                            continue;
                        }
                        continue;
                    }
                    serial.writeString("[SHELL] Loaded ");
                    printNumberSerial(identity.getIdentityCount());
                    serial.writeString(" identities\n");
                }
            }

            // Check again after loading
            if (!hasAnyUsers()) {
                serial.writeString("[SHELL] No users after load - auto-login\n");
                autoLoginDefault();
                shellLoop();
                continue;
            }

            loginPrompt();

            if (!logged_in) continue;

            // H.7: Set system master key after successful login
            setSystemKeyFromCurrentIdentity();

            // H.7: Load encrypted config now that we have the key
            loadEncryptedConfigIfNeeded();

            shellLoop();

            // Logout cleanup
            logged_in = false;
            current_user_len = 0;
            home_dir_len = 0;

            env.clearLoginVars();

            // H.7: Clear system key on logout
            clearSystemKey();

            // H.7: Lock identity
            auth.lock();

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

// =============================================================================
// H.7: System Key Management
// =============================================================================

/// Set system encryption key from current identity
fn setSystemKeyFromCurrentIdentity() void {
    if (identity.getCurrentIdentity()) |id| {
        if (id.keypair.valid) {
            sys_encrypt.setMasterKeyFromIdentity(&id.keypair.public_key);
            serial.writeString("[SHELL] System key set from identity: ");
            serial.writeString(id.getName());
            serial.writeString("\n");
        }
    }
}

/// Load encrypted config after login
fn loadEncryptedConfigIfNeeded() void {
    // Only if we have the key and config wasn't loaded yet
    if (sys_encrypt.isMasterKeySet() and !config_store.wasLoadedFromDisk()) {
        if (config_store.hasSavedConfig()) {
            if (config_store.loadFromDisk()) {
                serial.writeString("[SHELL] Encrypted config loaded (");
                printNumberSerial(config_store.getEntryCount());
                serial.writeString(" entries)\n");
            } else {
                serial.writeString("[SHELL] Config load failed (may need re-save)\n");
            }
        }
    }
}

/// Clear system key on logout
fn clearSystemKey() void {
    sys_encrypt.clearMasterKey();
    serial.writeString("[SHELL] System key cleared\n");
}

// =============================================================================
// H.7: Recovery Mode
// =============================================================================

/// Show recovery options when identity load fails
fn showRecoveryPrompt() void {
    const theme = ui.getTheme();

    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_error);
        terminal.setBold(true);
    }
    println("  ════════════════════════════════════════");
    println("   IDENTITY DATA ERROR");
    println("  ════════════════════════════════════════");
    if (terminal.isInitialized()) {
        terminal.setBold(false);
    }

    newLine();

    // Show specific error
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
    }
    printDirect("  Error: ");

    const err = identity_store.getLastLoadError();
    switch (err) {
        .invalid_magic => println("Invalid file format (corrupted header)"),
        .unsupported_version => println("Unsupported file version"),
        .checksum_mismatch => println("Data integrity check failed"),
        .file_too_small => println("File is truncated or incomplete"),
        .read_error => println("Disk read error"),
        else => println("Unknown error"),
    }

    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    println("  Recovery options:");
    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    println("    [1] If you have your 24-word seed phrase:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    println("        Enter recovery shell, then run:");
    println("          ceremony reset");
    println("          ceremony start");
    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_info);
    }
    println("    [2] If you have a backup of IDENTITY.DAT:");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_dim);
    }
    println("        Restore the file and reboot");
    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
    }
    println("  ════════════════════════════════════════");
    newLine();

    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    printDirect("  Press ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_success);
    }
    printDirect("R");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    printDirect(" for recovery shell, ");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_warning);
    }
    printDirect("ESC");
    if (terminal.isInitialized()) {
        terminal.setFgColor(theme.text_normal);
    }
    println(" to retry...");

    while (true) {
        if (keyboard.getKey()) |key| {
            if (key == 'r' or key == 'R') {
                recovery_mode = true;
                return;
            }
            if (key == 0x1B) {
                recovery_mode = false;
                return;
            }
        }
        asm volatile ("pause");
    }
}

/// Auto-login for recovery mode (limited shell)
fn autoLoginRecovery() void {
    const recovery_name = "recovery";

    var i: usize = 0;
    while (i < recovery_name.len) : (i += 1) {
        current_user[i] = recovery_name[i];
    }
    current_user_len = recovery_name.len;

    logged_in = true;
    home_dir[0] = '/';
    home_dir_len = 1;
    vfs.setCwd("/");

    env.setLoginVars(recovery_name, "/");

    const theme = ui.getTheme();
    if (terminal.isInitialized()) {
        newLine();
        terminal.setFgColor(theme.text_warning);
        terminal.setBold(true);
        println("  RECOVERY SHELL");
        terminal.setBold(false);
        terminal.setFgColor(theme.text_dim);
        println("  Limited functionality - run 'ceremony' to restore");
        terminal.setFgColor(theme.text_normal);
        newLine();
    }

    serial.writeString("[SHELL] Entered recovery mode\n");
}

// =============================================================================
// Auto-login (no users configured / first boot)
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

    // FIX: Clear keyboard buffer after auto-login
    keyboard.clearBuffer();

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
// T5.1 + H.7: Login Prompt with Password Authentication
// =============================================================================

fn loginPrompt() void {
    const theme = ui.getTheme();

    var attempts: u32 = 0;
    const max_attempts: u32 = 5;

    while (attempts < max_attempts and running) : (attempts += 1) {
        // Check lockout status
        if (auth.isLockedOut()) {
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_error);
            }
            if (auth.getLockoutState() == .hard_lock) {
                println("Account locked. Use seed phrase to recover.");
                println("Run 'ceremony reset' then 'ceremony start' to reset.");
            } else {
                println("Too many failed attempts. Please wait...");
            }
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_normal);
            }
            // Wait a bit before allowing retry
            var wait: u32 = 0;
            while (wait < 10000000) : (wait += 1) {
                asm volatile ("pause");
            }
            continue;
        }

        // FIX: Clear keyboard buffer before username prompt
        keyboard.clearBuffer();

        // Username prompt
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
        printDirect("zamrud login: ");
        clearInputBuffer();
        readLoginInput();

        if (input_len == 0) continue;

        // Copy username
        var i: usize = 0;
        while (i < input_len and i < 31) : (i += 1) {
            current_user[i] = input_buffer[i];
        }
        current_user_len = i;

        // Handle @ prefix
        var username_start: usize = 0;
        if (current_user_len > 0 and current_user[0] == '@') {
            username_start = 1;
        }
        const username = current_user[username_start..current_user_len];

        newLine();

        // Check if user exists
        var user_exists = false;
        var needs_password = false;

        // Check identity system first (H.7 ceremony users)
        if (identity.isInitialized() and identity.getIdentityCount() > 0) {
            if (identity.getIdentity(username)) |id| {
                user_exists = true;
                // H.7: Check if this identity uses password
                needs_password = (id.credential_type == .password);
            }
        }

        // Fallback to legacy users system
        if (!user_exists and users.isInitialized() and users.getUserCount() > 0) {
            if (users.findUserByName(username) != null) {
                user_exists = true;
                needs_password = false;
            }
        }

        if (!user_exists) {
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_error);
            }
            println("Login incorrect");
            if (terminal.isInitialized()) {
                terminal.setFgColor(theme.text_normal);
            }
            newLine();
            continue;
        }

        // Password prompt (if needed)
        if (needs_password) {
            // FIX: Clear keyboard buffer before password prompt
            keyboard.clearBuffer();

            printDirect("Password: ");

            var password_buf: [64]u8 = [_]u8{0} ** 64;
            var password_len: usize = 0;

            // Read password (hidden input)
            while (true) {
                if (keyboard.hasKey()) {
                    const key = keyboard.getKey() orelse continue;
                    if (key == 0) continue;

                    if (key == '\n' or key == '\r') {
                        break;
                    }

                    if (key == keyboard.KEY_BACKSPACE or key == 127) {
                        if (password_len > 0) {
                            password_len -= 1;
                            password_buf[password_len] = 0;
                            if (terminal.isInitialized()) {
                                terminal.writeChar(0x08);
                                terminal.writeChar(' ');
                                terminal.writeChar(0x08);
                            }
                        }
                        continue;
                    }

                    if (key == keyboard.KEY_CTRL_C) {
                        newLine();
                        // Wipe password buffer
                        i = 0;
                        while (i < 64) : (i += 1) {
                            password_buf[i] = 0;
                        }
                        return;
                    }

                    if (key >= 32 and key < 127 and password_len < 63) {
                        password_buf[password_len] = key;
                        password_len += 1;
                        if (terminal.isInitialized()) {
                            terminal.writeChar('*');
                        }
                    }
                }
                asm volatile ("pause");
            }

            newLine();

            // Verify password using auth system
            const password = password_buf[0..password_len];

            if (auth.unlock(username, password)) {
                // Wipe password from memory
                i = 0;
                while (i < 64) : (i += 1) {
                    password_buf[i] = 0;
                }

                // FIX: Clear keyboard buffer after successful auth
                keyboard.clearBuffer();

                loginSuccess(current_user[0..current_user_len]);
                return;
            } else {
                // Wipe password from memory
                i = 0;
                while (i < 64) : (i += 1) {
                    password_buf[i] = 0;
                }

                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_error);
                }

                const remaining = max_attempts - attempts - 1;
                if (remaining > 0) {
                    printDirect("Authentication failed (");
                    printNumber(remaining);
                    println(" attempts remaining)");
                } else {
                    println("Authentication failed");
                }

                if (terminal.isInitialized()) {
                    terminal.setFgColor(theme.text_normal);
                }
                newLine();
                continue;
            }
        } else {
            // No password needed (legacy user or PIN identity)
            // For PIN identity, still need to verify
            if (identity.getIdentity(username)) |id| {
                if (id.credential_type == .pin) {
                    // FIX: Clear keyboard buffer before PIN prompt
                    keyboard.clearBuffer();

                    // Prompt for PIN
                    printDirect("PIN: ");

                    var pin_buf: [16]u8 = [_]u8{0} ** 16;
                    var pin_len: usize = 0;

                    while (true) {
                        if (keyboard.hasKey()) {
                            const key = keyboard.getKey() orelse continue;
                            if (key == 0) continue;

                            if (key == '\n' or key == '\r') break;

                            if (key == keyboard.KEY_BACKSPACE or key == 127) {
                                if (pin_len > 0) {
                                    pin_len -= 1;
                                    pin_buf[pin_len] = 0;
                                    if (terminal.isInitialized()) {
                                        terminal.writeChar(0x08);
                                        terminal.writeChar(' ');
                                        terminal.writeChar(0x08);
                                    }
                                }
                                continue;
                            }

                            if (key == keyboard.KEY_CTRL_C) {
                                newLine();
                                i = 0;
                                while (i < 16) : (i += 1) pin_buf[i] = 0;
                                return;
                            }

                            if (key >= '0' and key <= '9' and pin_len < 8) {
                                pin_buf[pin_len] = key;
                                pin_len += 1;
                                if (terminal.isInitialized()) {
                                    terminal.writeChar('*');
                                }
                            }
                        }
                        asm volatile ("pause");
                    }

                    newLine();

                    if (auth.unlock(username, pin_buf[0..pin_len])) {
                        i = 0;
                        while (i < 16) : (i += 1) pin_buf[i] = 0;

                        // FIX: Clear keyboard buffer after successful PIN auth
                        keyboard.clearBuffer();

                        loginSuccess(current_user[0..current_user_len]);
                        return;
                    } else {
                        i = 0;
                        while (i < 16) : (i += 1) pin_buf[i] = 0;

                        if (terminal.isInitialized()) {
                            terminal.setFgColor(theme.text_error);
                        }
                        println("Invalid PIN");
                        if (terminal.isInitialized()) {
                            terminal.setFgColor(theme.text_normal);
                        }
                        newLine();
                        continue;
                    }
                }
            }

            // Legacy user without authentication
            if (users.isInitialized()) {
                _ = users.login(username, "");
            }

            // FIX: Clear keyboard buffer after legacy login
            keyboard.clearBuffer();

            loginSuccess(current_user[0..current_user_len]);
            return;
        }
    }

    if (attempts >= max_attempts) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_error);
        }
        println("Too many failed login attempts.");
        println("System locked. Please wait or use seed phrase recovery.");
        if (terminal.isInitialized()) {
            terminal.setFgColor(theme.text_normal);
        }
        newLine();
    }
}

fn printNumber(val: u32) void {
    if (val == 0) {
        printDirect("0");
        return;
    }
    var buf: [10]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        if (terminal.isInitialized()) {
            terminal.writeChar(buf[i]);
        }
    }
}

fn printNumberSerial(val: usize) void {
    if (val == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}

fn loginSuccess(username: []const u8) void {
    const theme = ui.getTheme();

    logged_in = true;
    setupHomeDir(username);

    // FIX: Clear keyboard buffer to prevent ghost characters after login
    keyboard.clearBuffer();

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

        // Show current date/time
        if (rtc.isInitialized()) {
            const dt = rtc.now();
            var buf: [19]u8 = undefined;
            const len = dt.format(&buf);

            terminal.setFgColor(theme.text_dim);
            printDirect("Date: ");
            printDirect(dt.weekdayName());
            printDirect(", ");
            printDirect(buf[0..len]);
            printDirect(" ");
            printDirect(rtc.getTimezoneName());
            newLineDirect();
        }

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
                        terminal.writeChar(' ');
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

/// Called by logout command
pub fn logout() void {
    if (users.isInitialized() and users.isLoggedIn()) {
        users.logout();
    }

    // H.7: Lock identity and clear key
    auth.lock();
    clearSystemKey();

    logged_in = false;

    // FIX: Clear keyboard buffer on logout
    keyboard.clearBuffer();

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
// Main Shell Loop (T4.3: redirection support)
// =============================================================================

fn shellLoop() void {
    // FIX: Clear any leftover keys before starting shell loop
    clearInputBuffer();

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

            // Check exit (same as logout)
            if (strEql(input_buffer[0..input_len], "exit")) {
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

        // H.7: Show recovery indicator
        if (recovery_mode) {
            ui.drawPromptRecovery(display_path);
        } else {
            ui.drawPromptWithPath(display_path);
        }

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

    if (recovery_mode) {
        ui.drawPromptRecovery(display_path);
    } else {
        ui.drawPromptWithPath(display_path);
    }

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
        "unset",    "env",          "export",  "printenv", "ceremony",
        "acpi",
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

// =============================================================================
// H.7: Public State Accessors
// =============================================================================

pub fn isRecoveryMode() bool {
    return recovery_mode;
}

pub fn isLoginRequired() bool {
    return login_required;
}

pub fn isLoggedIn() bool {
    return logged_in;
}
