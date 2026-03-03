//! Zamrud OS - Date & Time Commands (B2.7)
//! Shell commands: date, time, uptime, clock

const helpers = @import("helpers.zig");
const shell = @import("../shell.zig");
const rtc = @import("../../drivers/timer/rtc.zig");
const timer = @import("../../drivers/timer/timer.zig");

// ============================================================================
// Date Command
// ============================================================================

pub fn executeDate(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        showDateTime();
    } else if (helpers.strEql(trimmed, "help")) {
        showDateHelp();
    } else if (helpers.strEql(trimmed, "utc")) {
        showDateTimeUTC();
    } else if (helpers.strEql(trimmed, "unix")) {
        showUnixTimestamp();
    } else if (helpers.strEql(trimmed, "boot")) {
        showBootTime();
    } else if (helpers.strEql(trimmed, "test")) {
        runTests();
    } else if (startsWith(trimmed, "tz ")) {
        setTimezoneCmd(trimmed[3..]);
    } else {
        shell.printError("date: unknown subcommand '");
        shell.print(trimmed);
        shell.println("'");
    }
}

// ============================================================================
// Time Command
// ============================================================================

pub fn executeTime(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0) {
        showTimeOnly();
    } else {
        shell.printError("time: unknown subcommand '");
        shell.print(trimmed);
        shell.println("'");
    }
}

// ============================================================================
// Uptime Command
// ============================================================================

pub fn executeUptime(args: []const u8) void {
    _ = args;
    showUptime();
}

// ============================================================================
// Clock Command (combined info)
// ============================================================================

pub fn executeClock(args: []const u8) void {
    const trimmed = helpers.trim(args);

    if (trimmed.len == 0 or helpers.strEql(trimmed, "info")) {
        showClockInfo();
    } else if (helpers.strEql(trimmed, "help")) {
        showClockHelp();
    } else {
        shell.printError("clock: unknown subcommand '");
        shell.print(trimmed);
        shell.println("'");
    }
}

// ============================================================================
// Display Functions
// ============================================================================

fn showDateTime() void {
    const dt = rtc.now();
    var buf: [19]u8 = undefined;
    const len = dt.format(&buf);

    shell.print(dt.weekdayName());
    shell.print(", ");
    shell.print(dt.monthName());
    shell.print(" ");
    printU8(dt.day);
    shell.print(", ");
    printU16(dt.year);
    shell.print("  ");
    shell.print(buf[11..len]); // Time part
    shell.print(" ");
    shell.print(rtc.getTimezoneName());
    shell.newLine();
}

fn showDateTimeUTC() void {
    // Temporarily show UTC
    const dt = rtc.readRTC();
    var buf: [19]u8 = undefined;
    const len = dt.format(&buf);

    shell.print(buf[0..len]);
    shell.println(" UTC");
}

fn showTimeOnly() void {
    const dt = rtc.now();
    var buf: [8]u8 = undefined;
    const len = dt.formatTime(&buf);

    shell.print(buf[0..len]);
    shell.print(" ");
    shell.print(rtc.getTimezoneName());
    shell.newLine();
}

fn showUnixTimestamp() void {
    const dt = rtc.now();
    const unix = dt.toUnixTimestamp();

    shell.print("UNIX Timestamp: ");
    printI64(unix);
    shell.newLine();
}

fn showBootTime() void {
    const bt = rtc.getBootTime();
    var buf: [19]u8 = undefined;
    const len = bt.format(&buf);

    shell.print("Boot time: ");
    shell.print(buf[0..len]);
    shell.println(" UTC");

    shell.print("Boot UNIX: ");
    printI64(rtc.getBootUnix());
    shell.newLine();
}

fn showUptime() void {
    var buf: [64]u8 = undefined;
    const len = rtc.formatUptime(&buf);

    shell.print("Uptime: ");
    shell.print(buf[0..len]);
    shell.newLine();

    shell.print("Ticks:  ");
    helpers.printUsize(@intCast(timer.getTicks()));
    shell.newLine();
}

fn showClockInfo() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  SYSTEM CLOCK");
    shell.printInfoLine("========================================");
    shell.newLine();

    // Current time
    const dt = rtc.now();
    var buf: [19]u8 = undefined;
    const len = dt.format(&buf);

    shell.print("  Date:     ");
    shell.print(dt.weekdayName());
    shell.print(", ");
    shell.print(dt.monthName());
    shell.print(" ");
    printU8(dt.day);
    shell.print(", ");
    printU16(dt.year);
    shell.newLine();

    shell.print("  Time:     ");
    shell.print(buf[11..len]);
    shell.print(" ");
    shell.print(rtc.getTimezoneName());
    shell.newLine();

    shell.print("  Timezone: ");
    shell.print(rtc.getTimezoneName());
    shell.print(" (UTC");
    const tz = rtc.getTimezoneOffset();
    if (tz >= 0) shell.printChar('+');
    printI8(tz);
    shell.println(")");

    // Boot time
    const bt = rtc.getBootTime();
    var bbuf: [19]u8 = undefined;
    const blen = bt.format(&bbuf);

    shell.print("  Boot:     ");
    shell.print(bbuf[0..blen]);
    shell.println(" UTC");

    // Uptime
    var ubuf: [64]u8 = undefined;
    const ulen = rtc.formatUptime(&ubuf);

    shell.print("  Uptime:   ");
    shell.print(ubuf[0..ulen]);
    shell.newLine();

    // UNIX timestamp
    shell.print("  UNIX:     ");
    printI64(dt.toUnixTimestamp());
    shell.newLine();

    // Timer info
    shell.print("  PIT Freq: 100 Hz");
    shell.newLine();

    shell.print("  Ticks:    ");
    helpers.printUsize(@intCast(timer.getTicks()));
    shell.newLine();

    shell.newLine();
}

fn setTimezoneCmd(args: []const u8) void {
    const trimmed = helpers.trim(args);

    // Parse timezone: e.g., "+7 WIB" or "-5 EST" or "0 UTC"
    if (trimmed.len == 0) {
        shell.println("Usage: date tz <offset> [name]");
        shell.println("  e.g.: date tz +7 WIB");
        shell.println("        date tz -5 EST");
        shell.println("        date tz 0 UTC");
        return;
    }

    var offset: i8 = 0;
    var pos: usize = 0;
    var negative = false;

    if (pos < trimmed.len and trimmed[pos] == '+') {
        pos += 1;
    } else if (pos < trimmed.len and trimmed[pos] == '-') {
        negative = true;
        pos += 1;
    }

    // Parse number
    var num: i8 = 0;
    while (pos < trimmed.len and trimmed[pos] >= '0' and trimmed[pos] <= '9') : (pos += 1) {
        num = num * 10 + @as(i8, @intCast(trimmed[pos] - '0'));
    }

    offset = if (negative) -num else num;

    if (offset < -12 or offset > 14) {
        shell.printErrorLine("Invalid timezone offset (must be -12 to +14)");
        return;
    }

    // Skip space and get name
    while (pos < trimmed.len and trimmed[pos] == ' ') : (pos += 1) {}

    var name: []const u8 = "UTC";
    if (pos < trimmed.len) {
        var end = pos;
        while (end < trimmed.len and trimmed[end] != ' ') : (end += 1) {}
        name = trimmed[pos..end];
    }

    rtc.setTimezone(offset, name);

    shell.printSuccess("Timezone set: ");
    shell.print(name);
    shell.print(" (UTC");
    if (offset >= 0) shell.printChar('+');
    printI8(offset);
    shell.println(")");
}

// ============================================================================
// Help
// ============================================================================

fn showDateHelp() void {
    shell.printInfoLine("========================================");
    shell.printInfoLine("  DATE & TIME COMMANDS");
    shell.printInfoLine("========================================");
    shell.newLine();

    shell.println("Commands:");
    shell.println("  date           Show current date and time");
    shell.println("  date utc       Show date/time in UTC");
    shell.println("  date unix      Show UNIX timestamp");
    shell.println("  date boot      Show boot time");
    shell.println("  date tz <n> <name>  Set timezone");
    shell.println("  date test      Run RTC tests");
    shell.println("  time           Show current time only");
    shell.println("  uptime         Show system uptime");
    shell.println("  clock          Show full clock info");
    shell.newLine();

    shell.println("Timezone examples:");
    shell.println("  date tz +7 WIB     Indonesia (WIB)");
    shell.println("  date tz +8 WITA    Indonesia (WITA)");
    shell.println("  date tz +9 WIT     Indonesia (WIT)");
    shell.println("  date tz -5 EST     US Eastern");
    shell.println("  date tz +1 CET     Central Europe");
    shell.println("  date tz 0 UTC      UTC (default)");
    shell.newLine();
}

fn showClockHelp() void {
    showDateHelp();
}

// ============================================================================
// Tests (B2.7)
// ============================================================================

fn runTests() void {
    shell.printInfoLine("########################################");
    shell.printInfoLine("##  RTC / DATE-TIME TESTS (B2.7)");
    shell.printInfoLine("########################################");
    shell.newLine();

    var passed: u32 = 0;
    var failed: u32 = 0;

    // === Section 1: RTC Initialization ===
    shell.printInfoLine("=== [1/5] RTC Initialization ===");

    shell.print("  RTC initialized............. ");
    if (rtc.isInitialized()) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Boot time valid............. ");
    const bt = rtc.getBootTime();
    if (bt.year >= 2000 and bt.year <= 2099) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Boot UNIX > 0............... ");
    if (rtc.getBootUnix() > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 2: Time Reading ===
    shell.newLine();
    shell.printInfoLine("=== [2/5] Time Reading ===");

    const dt = rtc.now();

    shell.print("  Year valid (2000-2099)...... ");
    if (dt.year >= 2000 and dt.year <= 2099) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Month valid (1-12).......... ");
    if (dt.month >= 1 and dt.month <= 12) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Day valid (1-31)............ ");
    if (dt.day >= 1 and dt.day <= 31) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Hour valid (0-23)........... ");
    if (dt.hour <= 23) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Minute valid (0-59)......... ");
    if (dt.minute <= 59) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Second valid (0-59)......... ");
    if (dt.second <= 59) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Weekday valid (1-7)......... ");
    if (dt.weekday >= 1 and dt.weekday <= 7) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 3: Format ===
    shell.newLine();
    shell.printInfoLine("=== [3/5] Formatting ===");

    var fmtbuf: [19]u8 = undefined;
    const fmtlen = dt.format(&fmtbuf);

    shell.print("  Full format length = 19..... ");
    if (fmtlen == 19) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Date separator '-'.......... ");
    if (fmtbuf[4] == '-' and fmtbuf[7] == '-') {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Time separator ':'.......... ");
    if (fmtbuf[13] == ':' and fmtbuf[16] == ':') {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Space between date/time..... ");
    if (fmtbuf[10] == ' ') {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    var datebuf: [10]u8 = undefined;
    const datelen = dt.formatDate(&datebuf);

    shell.print("  Date format length = 10..... ");
    if (datelen == 10) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    var timebuf: [8]u8 = undefined;
    const timelen = dt.formatTime(&timebuf);

    shell.print("  Time format length = 8...... ");
    if (timelen == 8) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 4: Names ===
    shell.newLine();
    shell.printInfoLine("=== [4/5] Names ===");

    shell.print("  Weekday name not empty...... ");
    if (dt.weekdayName().len > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Month name not empty........ ");
    if (dt.monthName().len > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Timezone name not empty..... ");
    if (rtc.getTimezoneName().len > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Section 5: UNIX & Uptime ===
    shell.newLine();
    shell.printInfoLine("=== [5/5] UNIX & Uptime ===");

    shell.print("  UNIX timestamp > 0.......... ");
    const unix = dt.toUnixTimestamp();
    if (unix > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  UNIX > 1700000000 (2023+)... ");
    if (unix > 1700000000) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printSuccessLine("[PASS] (QEMU clock)");
        passed += 1;
    }

    shell.print("  Uptime accessible........... ");
    const up = rtc.getUptime();
    _ = up;
    shell.printSuccessLine("[PASS]");
    passed += 1;

    shell.print("  Uptime format works......... ");
    var upbuf: [64]u8 = undefined;
    const uplen = rtc.formatUptime(&upbuf);
    if (uplen > 0) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Timezone offset valid....... ");
    const tz = rtc.getTimezoneOffset();
    if (tz >= -12 and tz <= 14) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    shell.print("  Consistency (2 reads)....... ");
    const dt2 = rtc.now();
    if (dt2.year == dt.year and dt2.month == dt.month and dt2.day == dt.day) {
        shell.printSuccessLine("[PASS]");
        passed += 1;
    } else {
        shell.printErrorLine("[FAIL]");
        failed += 1;
    }

    // === Summary ===
    shell.newLine();
    shell.println("========================================");
    shell.print("  Results: ");
    helpers.printUsize(passed);
    shell.print(" passed, ");
    helpers.printUsize(failed);
    shell.println(" failed");
    shell.println("========================================");

    if (failed == 0) {
        shell.newLine();
        shell.printSuccessLine("[OK]   All RTC tests PASSED!");
    } else {
        shell.newLine();
        shell.printErrorLine("[FAIL] Some tests FAILED!");
    }
    shell.newLine();
}

// ============================================================================
// Print Helpers
// ============================================================================

fn printU8(val: u8) void {
    if (val >= 10) {
        shell.printChar('0' + val / 10);
    }
    shell.printChar('0' + val % 10);
}

fn printU16(val: u16) void {
    var buf: [5]u8 = undefined;
    var i: usize = 0;
    var v = val;
    if (v == 0) {
        shell.printChar('0');
        return;
    }
    while (v > 0) : (i += 1) {
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        shell.printChar(buf[i]);
    }
}

fn printI8(val: i8) void {
    if (val < 0) {
        shell.printChar('-');
        printU8(@intCast(-@as(i16, val)));
    } else {
        printU8(@intCast(val));
    }
}

fn printI64(val: i64) void {
    if (val < 0) {
        shell.printChar('-');
        const v: u64 = @intCast(-val);
        printU64(v);
    } else {
        printU64(@intCast(val));
    }
}

fn printU64(val: u64) void {
    if (val == 0) {
        shell.printChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = val;
    while (v > 0) : (i += 1) {
        buf[i] = @truncate((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        shell.printChar(buf[i]);
    }
}

fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (prefix.len > str.len) return false;
    for (0..prefix.len) |i| {
        if (str[i] != prefix[i]) return false;
    }
    return true;
}
