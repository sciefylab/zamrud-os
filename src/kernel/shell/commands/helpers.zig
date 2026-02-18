//! Zamrud OS - Command Helpers
//! Utility functions for shell commands
//! Updated: E3.4 Network Capability

const shell = @import("../shell.zig");
const terminal = @import("../../drivers/display/terminal.zig");
const serial = @import("../../drivers/serial/serial.zig");

// =============================================================================
// String Utilities
// =============================================================================

pub fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}

pub fn eqlStr(a: []const u8, b: []const u8) bool {
    return strEql(a, b);
}

pub fn startsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return strEql(haystack[0..needle.len], needle);
}

pub fn endsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return strEql(haystack[haystack.len - needle.len ..], needle);
}

pub fn trim(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;

    while (start < end and (s[start] == ' ' or s[start] == '\t')) : (start += 1) {}
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) : (end -= 1) {}

    return s[start..end];
}

pub fn parseArgs(input: []const u8) struct { cmd: []const u8, rest: []const u8 } {
    const trimmed = trim(input);
    if (trimmed.len == 0) {
        return .{ .cmd = "", .rest = "" };
    }

    var i: usize = 0;
    while (i < trimmed.len and trimmed[i] != ' ') : (i += 1) {}

    const cmd = trimmed[0..i];
    var rest: []const u8 = "";

    if (i < trimmed.len) {
        rest = trim(trimmed[i..]);
    }

    return .{ .cmd = cmd, .rest = rest };
}

pub fn splitFirst(s: []const u8, delim: u8) struct { first: []const u8, rest: []const u8 } {
    for (s, 0..) |c, i| {
        if (c == delim) {
            return .{
                .first = s[0..i],
                .rest = if (i + 1 < s.len) trim(s[i + 1 ..]) else "",
            };
        }
    }
    return .{ .first = s, .rest = "" };
}

pub fn splitAll(s: []const u8, delim: u8, out: [][]const u8) usize {
    var count: usize = 0;
    var start: usize = 0;
    var in_word = false;

    for (s, 0..) |c, i| {
        if (c == delim) {
            if (in_word and count < out.len) {
                out[count] = s[start..i];
                count += 1;
            }
            in_word = false;
        } else {
            if (!in_word) {
                start = i;
                in_word = true;
            }
        }
    }

    if (in_word and count < out.len) {
        out[count] = s[start..];
        count += 1;
    }

    return count;
}

pub fn strEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

// =============================================================================
// Number Parsing
// =============================================================================

pub fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;

    var result: u32 = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            const digit: u32 = c - '0';
            if (result > 429496729 or (result == 429496729 and digit > 5)) {
                return null;
            }
            result = result * 10 + digit;
        } else if (c == ' ' or c == '\t') {
            break;
        } else {
            return null;
        }
    }
    return result;
}

pub fn parseU16(s: []const u8) ?u16 {
    if (s.len == 0) return null;

    var result: u16 = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            const digit: u16 = c - '0';
            if (result > 6553 or (result == 6553 and digit > 5)) {
                return null;
            }
            result = result * 10 + digit;
        } else if (c == ' ' or c == '\t') {
            break;
        } else {
            return null;
        }
    }
    return result;
}

/// Alias for parseU16 — used by E3.4 commands
pub fn parseDec16(s: []const u8) ?u16 {
    return parseU16(s);
}

pub fn parseU64(s: []const u8) ?u64 {
    if (s.len == 0) return null;

    var result: u64 = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            const digit: u64 = c - '0';
            if (result > 1844674407370955161 or (result == 1844674407370955161 and digit > 5)) {
                return null;
            }
            result = result * 10 + digit;
        } else if (c == ' ' or c == '\t') {
            break;
        } else {
            return null;
        }
    }
    return result;
}

/// Parse hex string (without 0x prefix)
pub fn parseHex(s: []const u8) ?u32 {
    if (s.len == 0) return null;

    var result: u32 = 0;
    for (s) |c| {
        var digit: u32 = 0;
        if (c >= '0' and c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' and c <= 'f') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' and c <= 'F') {
            digit = c - 'A' + 10;
        } else if (c == ' ' or c == '\t') {
            break;
        } else {
            return null;
        }

        if (result > 0x0FFFFFFF) return null;
        result = (result << 4) | digit;
    }
    return result;
}

/// Alias for parseHex — used by E3.4
pub fn parseHex32(s: []const u8) ?u32 {
    return parseHex(s);
}

/// Parse hex with optional 0x prefix
pub fn parseHexAuto(s: []const u8) ?u32 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        return parseHex(s[2..]);
    }
    return parseHex(s);
}

// =============================================================================
// Number Printing (via Shell)
// =============================================================================

pub fn printU8(val: u8) void {
    if (val >= 100) shell.printChar('0' + val / 100);
    if (val >= 10) shell.printChar('0' + (val / 10) % 10);
    shell.printChar('0' + val % 10);
}

pub fn printU16(val: u16) void {
    if (val >= 10000) shell.printChar('0' + @as(u8, @intCast((val / 10000) % 10)));
    if (val >= 1000) shell.printChar('0' + @as(u8, @intCast((val / 1000) % 10)));
    if (val >= 100) shell.printChar('0' + @as(u8, @intCast((val / 100) % 10)));
    if (val >= 10) shell.printChar('0' + @as(u8, @intCast((val / 10) % 10)));
    shell.printChar('0' + @as(u8, @intCast(val % 10)));
}

pub fn printU32(val: u32) void {
    if (val == 0) {
        shell.printChar('0');
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
        shell.printChar(buf[i]);
    }
}

pub fn printU64(val: u64) void {
    if (val == 0) {
        shell.printChar('0');
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
        shell.printChar(buf[i]);
    }
}

pub fn printUsize(val: usize) void {
    if (val == 0) {
        shell.printChar('0');
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
        shell.printChar(buf[i]);
    }
}

pub fn printI32(val: i32) void {
    if (val < 0) {
        shell.printChar('-');
        printU32(@intCast(-val));
    } else {
        printU32(@intCast(val));
    }
}

// =============================================================================
// E3.4 Generic Print Functions
// =============================================================================

/// Generic decimal print — any integer type via shell
pub fn printDec(val: anytype) void {
    const T = @TypeOf(val);
    switch (@typeInfo(T)) {
        .int => |info| {
            if (info.signedness == .signed) {
                if (val < 0) {
                    shell.printChar('-');
                    const unsigned_type = @Type(.{ .int = .{ .signedness = .unsigned, .bits = info.bits } });
                    printU64(@intCast(@as(unsigned_type, @intCast(-val))));
                    return;
                }
            }
            printU64(@intCast(val));
        },
        .comptime_int => {
            if (val < 0) {
                shell.printChar('-');
                printU64(@intCast(-val));
            } else {
                printU64(@intCast(val));
            }
        },
        else => {
            shell.print("?");
        },
    }
}

/// Print u64 as decimal — alias for printU64
pub fn printDec64(val: u64) void {
    printU64(val);
}

/// Generic number print (for any integer type)
pub fn printNumber(n: anytype) void {
    const T = @TypeOf(n);
    const val = switch (@typeInfo(T)) {
        .int => @as(u64, @intCast(if (n < 0) -n else n)),
        .comptime_int => @as(u64, @intCast(if (n < 0) -n else n)),
        else => @compileError("printNumber requires integer type"),
    };

    if (@typeInfo(T) == .int and @typeInfo(T).int.signedness == .signed and n < 0) {
        shell.printChar('-');
    }

    if (val == 0) {
        shell.printChar('0');
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
        shell.printChar(buf[i]);
    }
}

// =============================================================================
// Number Printing (via Terminal)
// =============================================================================

pub fn printNumberTerminal(n: anytype) void {
    const val = @as(u64, @intCast(n));

    if (val == 0) {
        terminal.printChar('0');
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
        terminal.printChar(buf[i]);
    }
}

// =============================================================================
// Padded Number Printing
// =============================================================================

pub fn printU16Padded(val: u16, width: usize) void {
    var buf: [6]u8 = undefined;
    var len: usize = 0;
    var v = val;

    if (v == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (v > 0 and len < 6) {
            buf[len] = @intCast((v % 10) + '0');
            v /= 10;
            len += 1;
        }
    }

    var pad = if (width > len) width - len else 0;
    while (pad > 0) : (pad -= 1) {
        shell.printChar(' ');
    }

    while (len > 0) {
        len -= 1;
        shell.printChar(buf[len]);
    }
}

pub fn printU32Padded(val: u32, width: usize) void {
    var buf: [10]u8 = undefined;
    var len: usize = 0;
    var v = val;

    if (v == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (v > 0 and len < 10) {
            buf[len] = @intCast((v % 10) + '0');
            v /= 10;
            len += 1;
        }
    }

    var pad = if (width > len) width - len else 0;
    while (pad > 0) : (pad -= 1) {
        shell.printChar(' ');
    }

    while (len > 0) {
        len -= 1;
        shell.printChar(buf[len]);
    }
}

pub fn printU64Padded(val: u64, width: usize) void {
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var v = val;

    if (v == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (v > 0 and len < 20) {
            buf[len] = @intCast((v % 10) + '0');
            v /= 10;
            len += 1;
        }
    }

    var pad = if (width > len) width - len else 0;
    while (pad > 0) : (pad -= 1) {
        shell.printChar(' ');
    }

    while (len > 0) {
        len -= 1;
        shell.printChar(buf[len]);
    }
}

pub fn printI32Padded(val: i32, width: usize) void {
    var buf: [12]u8 = undefined;
    var len: usize = 0;
    var v: u32 = undefined;
    var neg = false;

    if (val < 0) {
        neg = true;
        v = @intCast(-val);
    } else {
        v = @intCast(val);
    }

    if (v == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (v > 0 and len < 11) {
            buf[len] = @intCast((v % 10) + '0');
            v /= 10;
            len += 1;
        }
    }

    if (neg) {
        buf[len] = '-';
        len += 1;
    }

    var pad = if (width > len) width - len else 0;
    while (pad > 0) : (pad -= 1) {
        shell.printChar(' ');
    }

    while (len > 0) {
        len -= 1;
        shell.printChar(buf[len]);
    }
}

pub fn printNumberPadded(n: anytype, width: usize) void {
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var val = @as(u64, @intCast(n));

    if (val == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (val > 0 and len < 20) : (len += 1) {
            buf[len] = @intCast((val % 10) + '0');
            val /= 10;
        }
    }

    var pad = if (width > len) width - len else 0;
    while (pad > 0) : (pad -= 1) {
        shell.printChar(' ');
    }

    while (len > 0) {
        len -= 1;
        shell.printChar(buf[len]);
    }
}

/// Generic padded decimal — used by E3.4
pub fn printDecPadded(val: anytype, width: usize) void {
    const v: u64 = @intCast(val);
    printU64Padded(v, width);
}

// =============================================================================
// Hex Printing
// =============================================================================

pub fn printHex(data: []const u8) void {
    const hex_chars = "0123456789abcdef";
    for (data) |b| {
        shell.printChar(hex_chars[b >> 4]);
        shell.printChar(hex_chars[b & 0xF]);
    }
}

pub fn printHexByte(b: u8) void {
    const hex_chars = "0123456789abcdef";
    shell.printChar(hex_chars[b >> 4]);
    shell.printChar(hex_chars[b & 0xF]);
}

pub fn printHexU32(val: u32) void {
    const hex_chars = "0123456789abcdef";
    var i: u5 = 28;
    while (true) {
        shell.printChar(hex_chars[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

pub fn printHexU64(val: u64) void {
    const hex_chars = "0123456789abcdef";
    var i: u6 = 60;
    while (true) {
        shell.printChar(hex_chars[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

/// Print u32 as 8-digit uppercase hex — used by E3.4 netreg
pub fn printHex32(val: u32) void {
    const hex_chars = "0123456789ABCDEF";
    var i: u5 = 28;
    while (true) {
        shell.printChar(hex_chars[@intCast((val >> i) & 0xF)]);
        if (i == 0) break;
        i -= 4;
    }
}

/// Alias for printHexU64 — used by zam.zig
pub fn printHex64(val: u64) void {
    printHexU64(val);
}

/// Alias for printHexByte — used by zam.zig
pub fn printHex8(val: u8) void {
    printHexByte(val);
}

pub fn printHexTerminal(data: []const u8) void {
    const hex_chars = "0123456789abcdef";
    for (data) |b| {
        terminal.printChar(hex_chars[b >> 4]);
        terminal.printChar(hex_chars[b & 0xF]);
    }
}

// =============================================================================
// Additional Integer Print Helpers (B2.1)
// =============================================================================

pub fn printI16(val: i16) void {
    printI32(@intCast(val));
}

pub fn printI8(val: i8) void {
    printI32(@intCast(val));
}

pub fn printHexU8(val: u8) void {
    const hex_chars = "0123456789ABCDEF";
    shell.printChar(hex_chars[(val >> 4) & 0x0F]);
    shell.printChar(hex_chars[val & 0x0F]);
}

// =============================================================================
// IP Address Utilities
// =============================================================================

pub fn printIp(ip: u32) void {
    printU8(@intCast((ip >> 24) & 0xFF));
    shell.printChar('.');
    printU8(@intCast((ip >> 16) & 0xFF));
    shell.printChar('.');
    printU8(@intCast((ip >> 8) & 0xFF));
    shell.printChar('.');
    printU8(@intCast(ip & 0xFF));
}

pub fn parseIp(s: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current: u16 = 0;
    var has_digit = false;

    for (s) |c| {
        if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            if (current > 255) return null;
            has_digit = true;
        } else if (c == '.') {
            if (!has_digit or octet_idx >= 3) return null;
            octets[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
            has_digit = false;
        } else if (c == ' ' or c == '\t') {
            break;
        } else {
            return null;
        }
    }

    if (!has_digit or octet_idx != 3) return null;
    octets[3] = @intCast(current);

    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

// =============================================================================
// MAC Address Utilities
// =============================================================================

pub fn printMac(mac: [6]u8) void {
    const hex_chars = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        shell.printChar(hex_chars[b >> 4]);
        shell.printChar(hex_chars[b & 0xF]);
        if (i < 5) shell.printChar(':');
    }
}

// =============================================================================
// Buffer Utilities
// =============================================================================

pub fn zeroBuffer(buf: []u8) void {
    for (buf) |*b| {
        b.* = 0;
    }
}

pub fn fillBuffer(buf: []u8, val: u8) void {
    for (buf) |*b| {
        b.* = val;
    }
}

pub fn copyBuffer(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    for (0..len) |i| {
        dest[i] = src[i];
    }
    return len;
}

// =============================================================================
// Byte Size Formatting
// =============================================================================

pub fn printBytesFormatted(bytes: u64) void {
    if (bytes < 1024) {
        printU64(bytes);
        shell.print(" B");
    } else if (bytes < 1024 * 1024) {
        printU64(bytes / 1024);
        shell.print(" KB");
    } else if (bytes < 1024 * 1024 * 1024) {
        printU64(bytes / (1024 * 1024));
        shell.print(" MB");
    } else {
        printU64(bytes / (1024 * 1024 * 1024));
        shell.print(" GB");
    }
}

// =============================================================================
// Test Helpers
// =============================================================================

pub fn printTestHeader(title: []const u8) void {
    shell.newLine();
    shell.println("########################################");
    shell.print("##  ");
    shell.print(title);
    shell.newLine();
    shell.println("########################################");
    shell.newLine();
}

pub fn printTestCategory(num: u32, total: u32, name: []const u8) void {
    shell.print("[");
    printU32(num);
    shell.print("/");
    printU32(total);
    shell.print("] ");
    shell.println(name);
}

pub fn printSubsection(name: []const u8) void {
    shell.newLine();
    shell.print("  ");
    shell.println(name);
}

pub fn doTest(name: []const u8, passed: bool, failed: *u32) u32 {
    shell.print("  ");
    shell.print(name);

    var pad: usize = 0;
    if (name.len < 26) {
        pad = 26 - name.len;
    }
    while (pad > 0) : (pad -= 1) {
        shell.printChar('.');
    }
    shell.print(" ");

    if (passed) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.SUCCESS);
        }
        shell.println("PASS");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
        return 1;
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.ERROR);
        }
        shell.println("FAIL");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
        failed.* += 1;
        return 0;
    }
}

pub fn doSkip(name: []const u8) void {
    shell.print("  ");
    shell.print(name);

    var pad: usize = 0;
    if (name.len < 26) {
        pad = 26 - name.len;
    }
    while (pad > 0) : (pad -= 1) {
        shell.printChar('.');
    }
    shell.print(" ");

    if (terminal.isInitialized()) {
        terminal.setFgColor(terminal.Colors.WARNING);
    }
    shell.println("SKIP");
    if (terminal.isInitialized()) {
        terminal.resetColors();
    }
}

pub fn printTestResults(passed: u32, failed: u32) void {
    shell.newLine();
    shell.println("========================================");
    shell.print("  Results: ");
    printU32(passed);
    shell.print(" passed, ");
    printU32(failed);
    shell.println(" failed");
    shell.println("========================================");
    shell.newLine();

    if (failed == 0) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.SUCCESS);
        }
        shell.println("All tests PASSED!");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.ERROR);
        }
        shell.println("Some tests FAILED!");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }
    shell.newLine();
}

pub fn printQuickResult(name: []const u8, ok: bool) void {
    shell.print(name);
    shell.print(": ");
    if (ok) {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.SUCCESS);
        }
        shell.println("All checks PASSED");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    } else {
        if (terminal.isInitialized()) {
            terminal.setFgColor(terminal.Colors.ERROR);
        }
        shell.println("Some checks FAILED");
        if (terminal.isInitialized()) {
            terminal.resetColors();
        }
    }
}

// =============================================================================
// CPU Utilities
// =============================================================================

pub fn getCS() u16 {
    return asm volatile ("mov %%cs, %[ret]"
        : [ret] "=r" (-> u16),
    );
}

pub fn getDS() u16 {
    return asm volatile ("mov %%ds, %[ret]"
        : [ret] "=r" (-> u16),
    );
}

pub fn readMSR(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;

    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );

    return (@as(u64, high) << 32) | low;
}

pub fn busyWait(iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause");
    }
}

// =============================================================================
// Time Utilities
// =============================================================================

pub fn printDuration(ms: u64) void {
    if (ms < 1000) {
        printU64(ms);
        shell.print(" ms");
    } else if (ms < 60000) {
        printU64(ms / 1000);
        shell.print(".");
        printU64((ms % 1000) / 100);
        shell.print(" sec");
    } else if (ms < 3600000) {
        printU64(ms / 60000);
        shell.print(" min ");
        printU64((ms % 60000) / 1000);
        shell.print(" sec");
    } else {
        printU64(ms / 3600000);
        shell.print(" hr ");
        printU64((ms % 3600000) / 60000);
        shell.print(" min");
    }
}

// =============================================================================
// Progress Indicator
// =============================================================================

pub fn printProgress(current: usize, total: usize, width: usize) void {
    if (total == 0) return;

    const percent = (current * 100) / total;
    const filled = (current * width) / total;

    shell.print("[");
    var i: usize = 0;
    while (i < width) : (i += 1) {
        if (i < filled) {
            shell.printChar('=');
        } else if (i == filled) {
            shell.printChar('>');
        } else {
            shell.printChar(' ');
        }
    }
    shell.print("] ");
    printU64(percent);
    shell.print("%");
}
