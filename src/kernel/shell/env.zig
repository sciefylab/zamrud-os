//! Zamrud OS - Environment Variables (T4.2)
//! Storage, expansion, and built-in variable support

const shell = @import("shell.zig");
const vfs = @import("../fs/vfs.zig");
const timer = @import("../drivers/timer/timer.zig");

// =============================================================================
// Constants
// =============================================================================

const MAX_VARS: usize = 64;
const MAX_KEY_LEN: usize = 32;
const MAX_VAL_LEN: usize = 128;
const MAX_EXPAND_LEN: usize = 512;

// =============================================================================
// Types
// =============================================================================

const EnvVar = struct {
    key: [MAX_KEY_LEN]u8,
    key_len: usize,
    value: [MAX_VAL_LEN]u8,
    value_len: usize,
    active: bool,
    exported: bool, // marked for export to child processes

    fn getKey(self: *const EnvVar) []const u8 {
        return self.key[0..self.key_len];
    }

    fn getValue(self: *const EnvVar) []const u8 {
        return self.value[0..self.value_len];
    }
};

// =============================================================================
// Storage
// =============================================================================

var vars: [MAX_VARS]EnvVar = initVars();
var var_count: usize = 0;
var initialized: bool = false;

fn initVars() [MAX_VARS]EnvVar {
    var v: [MAX_VARS]EnvVar = undefined;
    for (&v) |*entry| {
        entry.key = [_]u8{0} ** MAX_KEY_LEN;
        entry.key_len = 0;
        entry.value = [_]u8{0} ** MAX_VAL_LEN;
        entry.value_len = 0;
        entry.active = false;
        entry.exported = false;
    }
    return v;
}

// =============================================================================
// Initialization
// =============================================================================

pub fn init() void {
    // Reset all vars
    for (&vars) |*v| {
        v.active = false;
        v.key_len = 0;
        v.value_len = 0;
        v.exported = false;
    }
    var_count = 0;

    // Set default built-in variables
    setVar("SHELL", "/bin/zamsh") catch {};
    setVar("TERM", "zamrud-term") catch {};
    setVar("OS", "ZamrudOS") catch {};
    setVar("VERSION", "0.1.0") catch {};
    setVar("LANG", "en_US.UTF-8") catch {};
    setVar("EDITOR", "cat") catch {};
    setVar("PS1", "\\u@\\h:\\w > ") catch {};
    setVar("HISTSIZE", "32") catch {};
    setVar("COLUMNS", "128") catch {};
    setVar("LINES", "48") catch {};

    // Mark standard vars as exported
    markExported("SHELL");
    markExported("TERM");
    markExported("OS");
    markExported("PATH");
    markExported("HOME");
    markExported("USER");
    markExported("PWD");
    markExported("LANG");

    initialized = true;
}

/// Called after login — set user-specific vars
pub fn setLoginVars(username: []const u8, home_path: []const u8) void {
    setVar("USER", username) catch {};
    setVar("HOME", home_path) catch {};
    setVar("PWD", home_path) catch {};
    setVar("LOGNAME", username) catch {};
    setVar("PATH", "/bin:/usr/bin:/sbin") catch {};

    markExported("USER");
    markExported("HOME");
    markExported("PWD");
    markExported("LOGNAME");
    markExported("PATH");
}

/// Called when CWD changes
pub fn updatePwd() void {
    const cwd = vfs.getcwd();
    setVar("PWD", cwd) catch {};
}

/// Called on logout — clear user-specific vars
pub fn clearLoginVars() void {
    unsetVar("USER");
    unsetVar("HOME");
    unsetVar("PWD");
    unsetVar("LOGNAME");
}

pub fn isInitialized() bool {
    return initialized;
}

// =============================================================================
// Core Operations
// =============================================================================

pub const EnvError = error{
    TooManyVars,
    KeyTooLong,
    ValueTooLong,
    InvalidKey,
};

/// Set or update an environment variable
pub fn setVar(key: []const u8, value: []const u8) EnvError!void {
    if (key.len == 0) return EnvError.InvalidKey;
    if (key.len > MAX_KEY_LEN) return EnvError.KeyTooLong;
    if (value.len > MAX_VAL_LEN) return EnvError.ValueTooLong;

    // Validate key: must start with letter or _, contain only alnum and _
    if (!isValidKeyChar(key[0], true)) return EnvError.InvalidKey;
    for (key[1..]) |c| {
        if (!isValidKeyChar(c, false)) return EnvError.InvalidKey;
    }

    // Check if already exists — update in place
    for (&vars) |*v| {
        if (v.active and v.key_len == key.len) {
            if (keysEqual(v.key[0..v.key_len], key)) {
                // Update value
                copyInto(&v.value, &v.value_len, value);
                return;
            }
        }
    }

    // Find free slot
    for (&vars) |*v| {
        if (!v.active) {
            copyInto(&v.key, &v.key_len, key);
            copyInto(&v.value, &v.value_len, value);
            v.active = true;
            v.exported = false;
            var_count += 1;
            return;
        }
    }

    return EnvError.TooManyVars;
}

/// Get the value of an environment variable
pub fn getVar(key: []const u8) ?[]const u8 {
    // Check dynamic built-ins first (always up-to-date)
    if (keysEqual(key, "PWD")) {
        // Always return live CWD
        const cwd = vfs.getcwd();
        // Update stored value too
        for (&vars) |*v| {
            if (v.active and keysEqual(v.key[0..v.key_len], "PWD")) {
                copyInto(&v.value, &v.value_len, cwd);
                return v.value[0..v.value_len];
            }
        }
        // If PWD not in table, return CWD directly
        return cwd;
    }

    if (keysEqual(key, "?")) {
        return if (shell.getLastExitSuccess()) "0" else "1";
    }

    // Look up in table
    for (&vars) |*v| {
        if (v.active and v.key_len == key.len) {
            if (keysEqual(v.key[0..v.key_len], key)) {
                return v.value[0..v.value_len];
            }
        }
    }

    return null;
}

/// Remove an environment variable
pub fn unsetVar(key: []const u8) void {
    for (&vars) |*v| {
        if (v.active and v.key_len == key.len) {
            if (keysEqual(v.key[0..v.key_len], key)) {
                v.active = false;
                v.key_len = 0;
                v.value_len = 0;
                v.exported = false;
                if (var_count > 0) var_count -= 1;
                return;
            }
        }
    }
}

/// Mark a variable as exported
pub fn markExported(key: []const u8) void {
    for (&vars) |*v| {
        if (v.active and v.key_len == key.len) {
            if (keysEqual(v.key[0..v.key_len], key)) {
                v.exported = true;
                return;
            }
        }
    }
}

/// Get count of active variables
pub fn getVarCount() usize {
    return var_count;
}

// =============================================================================
// Variable Expansion
// =============================================================================

/// Expand $VAR, ${VAR}, and $? in input string
/// Returns expanded string in static buffer
var expand_buf: [MAX_EXPAND_LEN]u8 = [_]u8{0} ** MAX_EXPAND_LEN;
var expand_len: usize = 0;

pub fn expandVars(input: []const u8) []const u8 {
    expand_len = 0;

    var i: usize = 0;
    while (i < input.len) {
        // Check for $ (but not at end of string)
        if (input[i] == '$' and i + 1 < input.len) {
            // Check for escaped \$
            if (i > 0 and input[i - 1] == '\\') {
                // Replace \$ with literal $
                if (expand_len > 0) expand_len -= 1; // remove the backslash
                appendChar('$');
                i += 1;
                continue;
            }

            i += 1; // skip $

            // $? — last exit status
            if (input[i] == '?') {
                const val = getVar("?") orelse "0";
                appendStr(val);
                i += 1;
                continue;
            }

            // $$ — PID (always 1 for kernel shell)
            if (input[i] == '$') {
                appendStr("1");
                i += 1;
                continue;
            }

            // ${VAR} — braced variable
            if (input[i] == '{') {
                i += 1; // skip {
                const var_start = i;
                while (i < input.len and input[i] != '}') : (i += 1) {}

                if (i < input.len) {
                    // Found closing }
                    const var_name = input[var_start..i];
                    i += 1; // skip }

                    if (getVar(var_name)) |val| {
                        appendStr(val);
                    }
                    // If var not found, expand to empty string
                } else {
                    // No closing } — output literally
                    appendChar('$');
                    appendChar('{');
                    appendStr(input[var_start..]);
                }
                continue;
            }

            // $VAR — unbraced variable (alphanumeric + _)
            const var_start = i;
            while (i < input.len and isValidKeyChar(input[i], i == var_start)) : (i += 1) {}

            if (i > var_start) {
                const var_name = input[var_start..i];
                if (getVar(var_name)) |val| {
                    appendStr(val);
                }
                // If var not found, expand to empty string
            } else {
                // Lone $ or $ followed by non-var char
                appendChar('$');
            }
            continue;
        }

        // Single-quoted strings: no expansion
        if (input[i] == '\'') {
            i += 1; // skip opening quote
            while (i < input.len and input[i] != '\'') {
                appendChar(input[i]);
                i += 1;
            }
            if (i < input.len) i += 1; // skip closing quote
            continue;
        }

        // Regular character
        appendChar(input[i]);
        i += 1;
    }

    return expand_buf[0..expand_len];
}

fn appendChar(c: u8) void {
    if (expand_len < MAX_EXPAND_LEN) {
        expand_buf[expand_len] = c;
        expand_len += 1;
    }
}

fn appendStr(s: []const u8) void {
    for (s) |c| {
        appendChar(c);
    }
}

// =============================================================================
// Iteration (for env command)
// =============================================================================

pub const EnvEntry = struct {
    key: []const u8,
    value: []const u8,
    exported: bool,
};

/// Iterate all active variables. Returns null when done.
pub fn getEntry(index: usize) ?EnvEntry {
    var count: usize = 0;
    for (&vars) |*v| {
        if (v.active) {
            if (count == index) {
                return EnvEntry{
                    .key = v.key[0..v.key_len],
                    .value = v.value[0..v.value_len],
                    .exported = v.exported,
                };
            }
            count += 1;
        }
    }
    return null;
}

/// Get all entries sorted alphabetically (simple insertion sort by key)
pub fn getSortedEntries(out: []EnvEntry) usize {
    var count: usize = 0;

    // Collect all active entries
    for (&vars) |*v| {
        if (v.active and count < out.len) {
            out[count] = EnvEntry{
                .key = v.key[0..v.key_len],
                .value = v.value[0..v.value_len],
                .exported = v.exported,
            };
            count += 1;
        }
    }

    // Simple insertion sort by key
    if (count > 1) {
        var i: usize = 1;
        while (i < count) : (i += 1) {
            const temp = out[i];
            var j: usize = i;
            while (j > 0 and strLessThan(temp.key, out[j - 1].key)) {
                out[j] = out[j - 1];
                j -= 1;
            }
            out[j] = temp;
        }
    }

    return count;
}

// =============================================================================
// Helpers
// =============================================================================

fn isValidKeyChar(c: u8, is_first: bool) bool {
    if (c >= 'A' and c <= 'Z') return true;
    if (c >= 'a' and c <= 'z') return true;
    if (c == '_') return true;
    if (!is_first and c >= '0' and c <= '9') return true;
    return false;
}

fn keysEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

fn strLessThan(a: []const u8, b: []const u8) bool {
    const min_len = if (a.len < b.len) a.len else b.len;
    for (a[0..min_len], b[0..min_len]) |ca, cb| {
        if (ca < cb) return true;
        if (ca > cb) return false;
    }
    return a.len < b.len;
}

fn copyInto(dest: anytype, dest_len: *usize, src: []const u8) void {
    var i: usize = 0;
    while (i < src.len and i < dest.len) : (i += 1) {
        dest[i] = src[i];
    }
    dest_len.* = i;
    // Zero remainder
    while (i < dest.len) : (i += 1) {
        dest[i] = 0;
    }
}

// =============================================================================
// Parse "KEY=VALUE" format
// =============================================================================

pub fn parseAssignment(input: []const u8) ?struct { key: []const u8, value: []const u8 } {
    // Find '='
    for (input, 0..) |c, i| {
        if (c == '=') {
            const key = input[0..i];
            const value = if (i + 1 < input.len) input[i + 1 ..] else "";

            // Validate key
            if (key.len == 0) return null;
            if (!isValidKeyChar(key[0], true)) return null;
            for (key[1..]) |k| {
                if (!isValidKeyChar(k, false)) return null;
            }

            // Strip quotes from value if present
            const stripped = stripQuotes(value);
            return .{ .key = key, .value = stripped };
        }
    }
    return null;
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2) {
        if ((s[0] == '"' and s[s.len - 1] == '"') or
            (s[0] == '\'' and s[s.len - 1] == '\''))
        {
            return s[1 .. s.len - 1];
        }
    }
    return s;
}
