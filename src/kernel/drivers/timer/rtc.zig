//! Zamrud OS - CMOS RTC Driver (B2.7)
//! Real-Time Clock via CMOS ports 0x70/0x71
//! Provides date, time, and boot timestamp

const cpu = @import("../../core/cpu.zig");
const serial = @import("../serial/serial.zig");
const timer = @import("timer.zig");
const limine = @import("../../core/limine.zig");

// ============================================================================
// CMOS Ports
// ============================================================================

const CMOS_ADDRESS: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// ============================================================================
// CMOS Register Addresses
// ============================================================================

const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_WEEKDAY: u8 = 0x06;
const RTC_DAY: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_CENTURY: u8 = 0x32; // May not exist on all hardware
const RTC_STATUS_A: u8 = 0x0A;
const RTC_STATUS_B: u8 = 0x0B;

// ============================================================================
// Date/Time Structure
// ============================================================================

pub const DateTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    weekday: u8, // 1=Sunday, 7=Saturday

    /// Format as "YYYY-MM-DD HH:MM:SS"
    pub fn format(self: *const DateTime, buf: []u8) usize {
        if (buf.len < 19) return 0;

        // YYYY
        buf[0] = digitChar(self.year / 1000);
        buf[1] = digitChar((self.year / 100) % 10);
        buf[2] = digitChar((self.year / 10) % 10);
        buf[3] = digitChar(self.year % 10);
        buf[4] = '-';

        // MM
        buf[5] = digitChar(self.month / 10);
        buf[6] = digitChar(self.month % 10);
        buf[7] = '-';

        // DD
        buf[8] = digitChar(self.day / 10);
        buf[9] = digitChar(self.day % 10);
        buf[10] = ' ';

        // HH
        buf[11] = digitChar(self.hour / 10);
        buf[12] = digitChar(self.hour % 10);
        buf[13] = ':';

        // MM
        buf[14] = digitChar(self.minute / 10);
        buf[15] = digitChar(self.minute % 10);
        buf[16] = ':';

        // SS
        buf[17] = digitChar(self.second / 10);
        buf[18] = digitChar(self.second % 10);

        return 19;
    }

    /// Format date only "YYYY-MM-DD"
    pub fn formatDate(self: *const DateTime, buf: []u8) usize {
        if (buf.len < 10) return 0;

        buf[0] = digitChar(self.year / 1000);
        buf[1] = digitChar((self.year / 100) % 10);
        buf[2] = digitChar((self.year / 10) % 10);
        buf[3] = digitChar(self.year % 10);
        buf[4] = '-';
        buf[5] = digitChar(self.month / 10);
        buf[6] = digitChar(self.month % 10);
        buf[7] = '-';
        buf[8] = digitChar(self.day / 10);
        buf[9] = digitChar(self.day % 10);

        return 10;
    }

    /// Format time only "HH:MM:SS"
    pub fn formatTime(self: *const DateTime, buf: []u8) usize {
        if (buf.len < 8) return 0;

        buf[0] = digitChar(self.hour / 10);
        buf[1] = digitChar(self.hour % 10);
        buf[2] = ':';
        buf[3] = digitChar(self.minute / 10);
        buf[4] = digitChar(self.minute % 10);
        buf[5] = ':';
        buf[6] = digitChar(self.second / 10);
        buf[7] = digitChar(self.second % 10);

        return 8;
    }

    /// Get weekday name
    pub fn weekdayName(self: *const DateTime) []const u8 {
        return switch (self.weekday) {
            1 => "Sunday",
            2 => "Monday",
            3 => "Tuesday",
            4 => "Wednesday",
            5 => "Thursday",
            6 => "Friday",
            7 => "Saturday",
            else => "Unknown",
        };
    }

    /// Get month name
    pub fn monthName(self: *const DateTime) []const u8 {
        return switch (self.month) {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            else => "Unknown",
        };
    }

    /// Convert to UNIX timestamp (approximate, no leap second handling)
    pub fn toUnixTimestamp(self: *const DateTime) i64 {
        var y: i64 = self.year;
        var m: i64 = self.month;

        // Adjust for months <= 2
        if (m <= 2) {
            y -= 1;
            m += 12;
        }

        const days: i64 = 365 * y + @divFloor(y, 4) - @divFloor(y, 100) + @divFloor(y, 400) + @divFloor((153 * (m - 3) + 2), 5) + self.day - 719469;

        return days * 86400 + @as(i64, self.hour) * 3600 + @as(i64, self.minute) * 60 + @as(i64, self.second);
    }
};

fn digitChar(val: anytype) u8 {
    const v: u8 = @intCast(@as(u16, @intCast(val)) % 10);
    return '0' + v;
}

// ============================================================================
// State
// ============================================================================

var initialized: bool = false;
var boot_time: DateTime = undefined;
var boot_unix: i64 = 0;
var tz_offset_hours: i8 = 0; // UTC offset in hours
var tz_name: [8]u8 = [_]u8{ 'U', 'T', 'C', 0, 0, 0, 0, 0 };
var tz_name_len: usize = 3;

// Limine boot time request
pub export var boot_time_request: limine.BootTimeRequest linksection(".limine_requests") = .{};

// ============================================================================
// CMOS Read
// ============================================================================

fn cmosRead(reg: u8) u8 {
    // Disable NMI (bit 7 = 1) and select register
    cpu.outb(CMOS_ADDRESS, 0x80 | reg);
    cpu.ioWait();
    return cpu.inb(CMOS_DATA);
}

fn cmosWrite(reg: u8, value: u8) void {
    cpu.outb(CMOS_ADDRESS, 0x80 | reg);
    cpu.ioWait();
    cpu.outb(CMOS_DATA, value);
}

/// Wait until RTC update is not in progress
fn waitForUpdate() void {
    // Wait for any ongoing update to finish
    var timeout: u32 = 0;
    while (timeout < 10000) : (timeout += 1) {
        if ((cmosRead(RTC_STATUS_A) & 0x80) == 0) return;
        cpu.ioWait();
    }
}

/// Convert BCD to binary
fn bcdToBin(bcd: u8) u8 {
    return (bcd & 0x0F) + ((bcd >> 4) * 10);
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init() void {
    serial.writeString("[RTC] Initializing CMOS RTC...\n");

    // Read current time as boot time
    boot_time = readRTC();

    // Try to get boot time from Limine
    if (boot_time_request.response) |response| {
        boot_unix = response.boot_time;
        serial.writeString("[RTC] Boot time from Limine: ");
        printDecSigned(boot_unix);
        serial.writeString(" (UNIX)\n");
    } else {
        boot_unix = boot_time.toUnixTimestamp();
        serial.writeString("[RTC] Boot time from RTC\n");
    }

    // Log boot time
    var buf: [19]u8 = undefined;
    const len = boot_time.format(&buf);
    serial.writeString("[RTC] Boot: ");
    serial.writeString(buf[0..len]);
    serial.writeString(" UTC\n");

    initialized = true;
    serial.writeString("[RTC] CMOS RTC initialized\n");
}

// ============================================================================
// Read RTC
// ============================================================================

/// Read current date/time from CMOS RTC
pub fn readRTC() DateTime {
    // Read twice and compare to avoid inconsistency during update
    var dt1: DateTime = undefined;
    var dt2: DateTime = undefined;

    var attempts: u32 = 0;
    while (attempts < 10) : (attempts += 1) {
        waitForUpdate();

        dt1.second = cmosRead(RTC_SECONDS);
        dt1.minute = cmosRead(RTC_MINUTES);
        dt1.hour = cmosRead(RTC_HOURS);
        dt1.weekday = cmosRead(RTC_WEEKDAY);
        dt1.day = cmosRead(RTC_DAY);
        dt1.month = cmosRead(RTC_MONTH);
        dt1.year = cmosRead(RTC_YEAR);

        waitForUpdate();

        dt2.second = cmosRead(RTC_SECONDS);
        dt2.minute = cmosRead(RTC_MINUTES);
        dt2.hour = cmosRead(RTC_HOURS);
        dt2.weekday = cmosRead(RTC_WEEKDAY);
        dt2.day = cmosRead(RTC_DAY);
        dt2.month = cmosRead(RTC_MONTH);
        dt2.year = cmosRead(RTC_YEAR);

        // If both reads match, data is consistent
        if (dt1.second == dt2.second and
            dt1.minute == dt2.minute and
            dt1.hour == dt2.hour and
            dt1.day == dt2.day and
            dt1.month == dt2.month and
            @as(u16, dt1.year) == @as(u16, dt2.year))
        {
            break;
        }
    }

    // Check status register B for format
    const status_b = cmosRead(RTC_STATUS_B);
    const is_bcd = (status_b & 0x04) == 0;
    const is_24h = (status_b & 0x02) != 0;

    var dt = dt1;

    // Convert BCD to binary if needed
    if (is_bcd) {
        dt.second = bcdToBin(dt.second);
        dt.minute = bcdToBin(dt.minute);
        dt.hour = bcdToBin(dt.hour & 0x7F); // Mask PM bit
        dt.weekday = bcdToBin(dt.weekday);
        dt.day = bcdToBin(dt.day);
        dt.month = bcdToBin(dt.month);
        dt.year = bcdToBin(@truncate(dt.year));
    }

    // Handle 12-hour format
    if (!is_24h) {
        const pm = (dt1.hour & 0x80) != 0;
        if (is_bcd) {
            // Already converted hour without PM bit
        } else {
            dt.hour = dt.hour & 0x7F;
        }

        if (pm and dt.hour < 12) {
            dt.hour += 12;
        } else if (!pm and dt.hour == 12) {
            dt.hour = 0;
        }
    }

    // Try to read century register
    const century_val = cmosRead(RTC_CENTURY);
    var century: u16 = 20; // Default to 2000s

    if (century_val != 0 and century_val != 0xFF) {
        if (is_bcd) {
            century = bcdToBin(century_val);
        } else {
            century = century_val;
        }
    }

    dt.year = century * 100 + dt.year;

    // Sanity checks
    if (dt.year < 2000 or dt.year > 2099) dt.year = 2025;
    if (dt.month == 0 or dt.month > 12) dt.month = 1;
    if (dt.day == 0 or dt.day > 31) dt.day = 1;
    if (dt.hour > 23) dt.hour = 0;
    if (dt.minute > 59) dt.minute = 0;
    if (dt.second > 59) dt.second = 0;
    if (dt.weekday == 0 or dt.weekday > 7) dt.weekday = 1;

    // Apply timezone offset
    if (tz_offset_hours != 0) {
        var hour_signed: i16 = @as(i16, dt.hour) + tz_offset_hours;
        if (hour_signed < 0) {
            hour_signed += 24;
            // Day rollback (simplified, doesn't handle month boundaries)
            if (dt.day > 1) dt.day -= 1;
        } else if (hour_signed >= 24) {
            hour_signed -= 24;
            dt.day += 1;
        }
        dt.hour = @intCast(@as(u16, @intCast(hour_signed)));
    }

    return dt;
}

/// Get current date/time (convenience function)
pub fn now() DateTime {
    return readRTC();
}

// ============================================================================
// Boot Time & Uptime
// ============================================================================

pub fn getBootTime() DateTime {
    return boot_time;
}

pub fn getBootUnix() i64 {
    return boot_unix;
}

/// Get uptime in seconds
pub fn getUptime() u64 {
    return timer.getSeconds();
}

/// Get uptime formatted as "Xd Xh Xm Xs"
pub fn formatUptime(buf: []u8) usize {
    const total = getUptime();
    const days = total / 86400;
    const hours = (total % 86400) / 3600;
    const minutes = (total % 3600) / 60;
    const secs = total % 60;

    var pos: usize = 0;

    if (days > 0) {
        pos += writeDecU64(buf[pos..], days);
        if (pos < buf.len) {
            buf[pos] = 'd';
            pos += 1;
        }
        if (pos < buf.len) {
            buf[pos] = ' ';
            pos += 1;
        }
    }

    pos += writeDecU64(buf[pos..], hours);
    if (pos < buf.len) {
        buf[pos] = 'h';
        pos += 1;
    }
    if (pos < buf.len) {
        buf[pos] = ' ';
        pos += 1;
    }

    pos += writeDecU64(buf[pos..], minutes);
    if (pos < buf.len) {
        buf[pos] = 'm';
        pos += 1;
    }
    if (pos < buf.len) {
        buf[pos] = ' ';
        pos += 1;
    }

    pos += writeDecU64(buf[pos..], secs);
    if (pos < buf.len) {
        buf[pos] = 's';
        pos += 1;
    }

    return pos;
}

// ============================================================================
// Timezone
// ============================================================================

pub fn setTimezone(offset_hours: i8, name: []const u8) void {
    tz_offset_hours = offset_hours;
    tz_name_len = 0;
    for (0..name.len) |i| {
        if (i >= 7) break;
        tz_name[i] = name[i];
        tz_name_len += 1;
    }
    tz_name[tz_name_len] = 0;

    serial.writeString("[RTC] Timezone set: ");
    serial.writeString(name);
    serial.writeString(" (UTC");
    if (offset_hours >= 0) serial.writeChar('+');
    printDecSigned(offset_hours);
    serial.writeString(")\n");
}

pub fn getTimezoneOffset() i8 {
    return tz_offset_hours;
}

pub fn getTimezoneName() []const u8 {
    return tz_name[0..tz_name_len];
}

// ============================================================================
// Public Getters
// ============================================================================

pub fn isInitialized() bool {
    return initialized;
}

// ============================================================================
// Helpers
// ============================================================================

fn writeDecU64(buf: []u8, value: u64) usize {
    if (value == 0) {
        if (buf.len > 0) {
            buf[0] = '0';
            return 1;
        }
        return 0;
    }

    var tmp: [20]u8 = undefined;
    var i: usize = 0;
    var v = value;
    while (v > 0) : (i += 1) {
        tmp[i] = @truncate((v % 10) + '0');
        v /= 10;
    }

    var pos: usize = 0;
    while (i > 0 and pos < buf.len) {
        i -= 1;
        buf[pos] = tmp[i];
        pos += 1;
    }
    return pos;
}

fn printDecSigned(value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int => {
            if (value < 0) {
                serial.writeChar('-');
                const abs: u64 = @intCast(-@as(i64, value));
                printDecU(abs);
            } else {
                const v: u64 = @intCast(value);
                printDecU(v);
            }
        },
        .comptime_int => {
            if (value < 0) {
                serial.writeChar('-');
                printDecU(@as(u64, @intCast(-value)));
            } else {
                printDecU(@as(u64, @intCast(value)));
            }
        },
        else => serial.writeChar('?'),
    }
}

fn printDecU(value: u64) void {
    if (value == 0) {
        serial.writeChar('0');
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 0;
    var v = value;
    while (v > 0) : (i += 1) {
        buf[i] = @truncate((v % 10) + '0');
        v /= 10;
    }
    while (i > 0) {
        i -= 1;
        serial.writeChar(buf[i]);
    }
}
