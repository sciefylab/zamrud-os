//! Zamrud OS - I/O Redirection (T4.3)
//! Supports: cmd > file, cmd >> file, cmd < file, cmd1 | cmd2

const shell = @import("shell.zig");
const commands = @import("commands.zig");
const vfs = @import("../fs/vfs.zig");
const pipe = @import("../ipc/pipe.zig");
const serial = @import("../drivers/serial/serial.zig");
const terminal = @import("../drivers/display/terminal.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_CAPTURE: usize = 4096;
const MAX_CMD_LEN: usize = 256;

// =============================================================================
// Redirection Types
// =============================================================================

pub const RedirType = enum {
    none, // No redirection
    stdout_overwrite, // cmd > file
    stdout_append, // cmd >> file
    stdin_file, // cmd < file
    pipe_cmd, // cmd1 | cmd2
};

pub const RedirInfo = struct {
    redir_type: RedirType,
    command: []const u8, // The command part (before redirect operator)
    target: []const u8, // Filename or second command
};

// =============================================================================
// Output Capture Buffer
// =============================================================================

var capture_buf: [MAX_CAPTURE]u8 = [_]u8{0} ** MAX_CAPTURE;
var capture_len: usize = 0;
var capturing: bool = false;

// =============================================================================
// Parse Redirection
// =============================================================================

/// Parse input for redirection operators
/// Returns RedirInfo with parsed components
/// Handles: >, >>, <, |
/// Respects single quotes (no redirect inside quotes)
pub fn parseRedirection(input: []const u8) RedirInfo {
    var i: usize = 0;
    var in_single_quote = false;

    while (i < input.len) {
        const c = input[i];

        // Track quotes
        if (c == '\'') {
            in_single_quote = !in_single_quote;
            i += 1;
            continue;
        }

        // Skip if inside quotes
        if (in_single_quote) {
            i += 1;
            continue;
        }

        // Check for pipe |
        if (c == '|') {
            const cmd = trimRight(input[0..i]);
            const target = trimLeft(input[i + 1 ..]);
            if (cmd.len > 0 and target.len > 0) {
                return .{
                    .redir_type = .pipe_cmd,
                    .command = cmd,
                    .target = target,
                };
            }
        }

        // Check for >> (must check before >)
        if (c == '>' and i + 1 < input.len and input[i + 1] == '>') {
            const cmd = trimRight(input[0..i]);
            const target = trimLeft(input[i + 2 ..]);
            if (cmd.len > 0 and target.len > 0) {
                return .{
                    .redir_type = .stdout_append,
                    .command = cmd,
                    .target = target,
                };
            }
        }

        // Check for >
        if (c == '>') {
            const cmd = trimRight(input[0..i]);
            const target = trimLeft(input[i + 1 ..]);
            if (cmd.len > 0 and target.len > 0) {
                return .{
                    .redir_type = .stdout_overwrite,
                    .command = cmd,
                    .target = target,
                };
            }
        }

        // Check for <
        if (c == '<') {
            const cmd = trimRight(input[0..i]);
            const target = trimLeft(input[i + 1 ..]);
            if (cmd.len > 0 and target.len > 0) {
                return .{
                    .redir_type = .stdin_file,
                    .command = cmd,
                    .target = target,
                };
            }
        }

        i += 1;
    }

    // No redirection found
    return .{
        .redir_type = .none,
        .command = input,
        .target = "",
    };
}

// =============================================================================
// Execute with Redirection
// =============================================================================

/// Execute a command with I/O redirection
/// Returns true if redirection was handled, false if normal execution needed
pub fn executeWithRedirection(input: []const u8) bool {
    const redir = parseRedirection(input);

    switch (redir.redir_type) {
        .none => return false, // No redirection — caller should execute normally

        .stdout_overwrite => {
            handleStdoutRedirect(redir.command, redir.target, false);
            return true;
        },

        .stdout_append => {
            handleStdoutRedirect(redir.command, redir.target, true);
            return true;
        },

        .stdin_file => {
            handleStdinRedirect(redir.command, redir.target);
            return true;
        },

        .pipe_cmd => {
            handlePipe(redir.command, redir.target);
            return true;
        },
    }
}

// =============================================================================
// stdout > file / >> file
// =============================================================================

fn handleStdoutRedirect(command: []const u8, filename: []const u8, append: bool) void {
    serial.writeString("[REDIR] ");
    serial.writeString(command);
    serial.writeString(if (append) " >> " else " > ");
    serial.writeString(filename);
    serial.writeString("\n");

    // Start capturing output
    startCapture();

    // Execute the command (output goes to capture buffer)
    commands.execute(command);

    // Stop capturing
    stopCapture();

    // Write captured output to file
    const output = getCaptured();

    if (output.len == 0) {
        // Command produced no output — create empty file or leave as-is
        if (!append) {
            if (!vfs.exists(filename)) {
                _ = vfs.createFile(filename);
            } else {
                // Truncate: open and write empty
                var flags = vfs.OpenFlags.O_WRONLY;
                flags.write = true;
                flags.truncate = true;
                const file = vfs.open(filename, flags);
                if (file != null) {
                    vfs.close(file.?);
                }
            }
        }
        shell.setLastExitSuccess(true);
        return;
    }

    // Create file if it doesn't exist
    if (!vfs.exists(filename)) {
        if (vfs.createFile(filename) == null) {
            shell.printError("redirect: cannot create '");
            shell.print(filename);
            shell.println("'");
            shell.setLastExitSuccess(false);
            return;
        }
    }

    if (append) {
        // Append mode: read existing content, then write all
        var existing_buf: [MAX_CAPTURE]u8 = [_]u8{0} ** MAX_CAPTURE;
        var existing_len: usize = 0;

        // Read existing content
        var rflags = vfs.OpenFlags.O_RDONLY;
        rflags.read = true;
        const rfile = vfs.open(filename, rflags);
        if (rfile != null) {
            const bytes = vfs.read(rfile.?, existing_buf[0..MAX_CAPTURE]);
            if (bytes > 0) {
                existing_len = @intCast(bytes);
            }
            vfs.close(rfile.?);
        }

        // Write existing + new
        var wflags = vfs.OpenFlags.O_WRONLY;
        wflags.write = true;
        wflags.truncate = true;
        const wfile = vfs.open(filename, wflags);
        if (wfile != null) {
            if (existing_len > 0) {
                _ = vfs.write(wfile.?, existing_buf[0..existing_len]);
            }
            _ = vfs.write(wfile.?, output);
            vfs.close(wfile.?);

            shell.setLastExitSuccess(true);
        } else {
            shell.printError("redirect: cannot open '");
            shell.print(filename);
            shell.println("' for writing");
            shell.setLastExitSuccess(false);
        }
    } else {
        // Overwrite mode
        var wflags = vfs.OpenFlags.O_WRONLY;
        wflags.write = true;
        wflags.truncate = true;
        const wfile = vfs.open(filename, wflags);
        if (wfile != null) {
            _ = vfs.write(wfile.?, output);
            vfs.close(wfile.?);

            shell.setLastExitSuccess(true);
        } else {
            shell.printError("redirect: cannot open '");
            shell.print(filename);
            shell.println("' for writing");
            shell.setLastExitSuccess(false);
        }
    }
}

// =============================================================================
// stdin < file
// =============================================================================

fn handleStdinRedirect(command: []const u8, filename: []const u8) void {
    serial.writeString("[REDIR] ");
    serial.writeString(command);
    serial.writeString(" < ");
    serial.writeString(filename);
    serial.writeString("\n");

    // Read file content
    var rflags = vfs.OpenFlags.O_RDONLY;
    rflags.read = true;
    const file = vfs.open(filename, rflags);
    if (file == null) {
        shell.printError("redirect: cannot open '");
        shell.print(filename);
        shell.println("': No such file");
        shell.setLastExitSuccess(false);
        return;
    }

    var file_buf: [MAX_CAPTURE]u8 = [_]u8{0} ** MAX_CAPTURE;
    const bytes = vfs.read(file.?, file_buf[0..MAX_CAPTURE]);
    vfs.close(file.?);

    if (bytes <= 0) {
        // Empty file — execute command with no additional args
        commands.execute(command);
        return;
    }

    const file_content = file_buf[0..@as(usize, @intCast(bytes))];

    // Strip trailing newline if present
    var content_len = file_content.len;
    while (content_len > 0 and (file_content[content_len - 1] == '\n' or file_content[content_len - 1] == '\r')) {
        content_len -= 1;
    }
    const clean_content = file_content[0..content_len];

    // Build new command: "command <file_content>"
    // This appends file content as arguments to the command
    var combined: [MAX_CMD_LEN * 2]u8 = [_]u8{0} ** (MAX_CMD_LEN * 2);
    var pos: usize = 0;

    // Copy command
    for (command) |c| {
        if (pos < combined.len - 1) {
            combined[pos] = c;
            pos += 1;
        }
    }

    // Add space separator
    if (pos < combined.len - 1) {
        combined[pos] = ' ';
        pos += 1;
    }

    // Copy file content as argument
    for (clean_content) |c| {
        if (pos < combined.len - 1) {
            combined[pos] = c;
            pos += 1;
        }
    }

    // Execute combined command
    commands.execute(combined[0..pos]);
}

// =============================================================================
// Pipe: cmd1 | cmd2
// =============================================================================

fn handlePipe(cmd1: []const u8, cmd2: []const u8) void {
    serial.writeString("[REDIR] ");
    serial.writeString(cmd1);
    serial.writeString(" | ");
    serial.writeString(cmd2);
    serial.writeString("\n");

    // Step 1: Capture output of cmd1
    startCapture();
    commands.execute(cmd1);
    stopCapture();

    const cmd1_output = getCaptured();

    if (cmd1_output.len == 0) {
        // No output from cmd1 — execute cmd2 with no extra input
        commands.execute(cmd2);
        return;
    }

    // Step 2: Feed cmd1 output as argument to cmd2
    // Strip trailing newline
    var output_len = cmd1_output.len;
    while (output_len > 0 and (cmd1_output[output_len - 1] == '\n' or cmd1_output[output_len - 1] == '\r')) {
        output_len -= 1;
    }
    const clean_output = cmd1_output[0..output_len];

    // Build: "cmd2 <output_of_cmd1>"
    var combined: [MAX_CMD_LEN * 2]u8 = [_]u8{0} ** (MAX_CMD_LEN * 2);
    var pos: usize = 0;

    for (cmd2) |c| {
        if (pos < combined.len - 1) {
            combined[pos] = c;
            pos += 1;
        }
    }

    if (pos < combined.len - 1) {
        combined[pos] = ' ';
        pos += 1;
    }

    for (clean_output) |c| {
        if (pos < combined.len - 1) {
            // Replace newlines with spaces for pipe
            if (c == '\n' or c == '\r') {
                combined[pos] = ' ';
            } else {
                combined[pos] = c;
            }
            pos += 1;
        }
    }

    commands.execute(combined[0..pos]);
}

// =============================================================================
// Output Capture Engine
// =============================================================================

/// Start capturing shell output to internal buffer
pub fn startCapture() void {
    capture_len = 0;
    var i: usize = 0;
    while (i < MAX_CAPTURE) : (i += 1) {
        capture_buf[i] = 0;
    }
    capturing = true;
}

/// Stop capturing
pub fn stopCapture() void {
    capturing = false;
}

/// Get captured output
pub fn getCaptured() []const u8 {
    return capture_buf[0..capture_len];
}

/// Check if currently capturing
pub fn isCapturing() bool {
    return capturing;
}

/// Write a character to capture buffer (called by shell.print when capturing)
pub fn captureChar(c: u8) void {
    if (capturing and capture_len < MAX_CAPTURE) {
        capture_buf[capture_len] = c;
        capture_len += 1;
    }
}

/// Write a string to capture buffer
pub fn captureStr(s: []const u8) void {
    for (s) |c| {
        captureChar(c);
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn trimLeft(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and (s[start] == ' ' or s[start] == '\t')) : (start += 1) {}
    return s[start..];
}

fn trimRight(s: []const u8) []const u8 {
    var end: usize = s.len;
    while (end > 0 and (s[end - 1] == ' ' or s[end - 1] == '\t')) : (end -= 1) {}
    return s[0..end];
}
