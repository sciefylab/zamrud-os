//! Zamrud OS - System Call Handlers
//! NOTE: Capability checks are now done in table.zig BEFORE handlers are called.
//! Handlers remain unchanged - they just execute. Security is enforced at dispatch level.

const serial = @import("../drivers/serial/serial.zig");
const vfs = @import("../fs/vfs.zig");
const process = @import("../proc/process.zig");
const timer = @import("../drivers/timer/timer.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const framebuffer = @import("../drivers/display/framebuffer.zig");
const config = @import("../config.zig");

const graphics_api = @import("../api/graphics.zig");
const input_api = @import("../api/input.zig");

// =============================================================================
// Error Codes
// =============================================================================

pub const ENOSYS: i64 = -38;
pub const EBADF: i64 = -9;
pub const EINVAL: i64 = -22;
pub const EFAULT: i64 = -14;
pub const ENOMEM: i64 = -12;
pub const ENOENT: i64 = -2;
pub const EACCES: i64 = -13;
pub const EPERM: i64 = -1;
pub const ENODEV: i64 = -19;
pub const EAGAIN: i64 = -11;

// =============================================================================
// Cursor State
// =============================================================================

var cursor_x: i32 = 0;
var cursor_y: i32 = 0;
var cursor_visible: bool = true;
var cursor_type: u8 = 0;

// =============================================================================
// Process Syscalls
// =============================================================================

pub fn sysExit(status: u64) noreturn {
    serial.writeString("[SYSCALL] exit(");
    printDec(status);
    serial.writeString(")\n");

    const pid = process.getCurrentPid();
    if (pid != 0) {
        _ = process.terminate(pid);
    }

    while (true) {
        asm volatile ("hlt");
    }
}

pub fn sysGetpid() i64 {
    return @intCast(process.getCurrentPid());
}

pub fn sysGetppid() i64 {
    return 0;
}

pub fn sysGetuid() i64 {
    return 0;
}

pub fn sysGetgid() i64 {
    return 0;
}

pub fn sysSchedYield() i64 {
    return 0;
}

// =============================================================================
// File Syscalls
// =============================================================================

pub fn sysWrite(fd: u64, buf_ptr: u64, count: u64) i64 {
    if (buf_ptr == 0) return EFAULT;
    if (count == 0) return 0;

    if (fd == 1 or fd == 2) {
        const buf: [*]const u8 = @ptrFromInt(buf_ptr);
        const len = @min(count, 4096);

        for (0..len) |i| {
            serial.writeChar(buf[i]);
        }

        return @intCast(len);
    }

    return EBADF;
}

pub fn sysRead(fd: u64, buf_ptr: u64, count: u64) i64 {
    if (buf_ptr == 0) return EFAULT;
    if (count == 0) return 0;
    if (fd == 0) return 0;
    return EBADF;
}

pub fn sysOpen(path_ptr: u64, flags: u64, mode: u64) i64 {
    _ = path_ptr;
    _ = flags;
    _ = mode;
    return ENOSYS;
}

pub fn sysClose(fd: u64) i64 {
    _ = fd;
    return 0;
}

// =============================================================================
// Directory Syscalls
// =============================================================================

pub fn sysGetcwd(buf_ptr: u64, size: u64) i64 {
    if (buf_ptr == 0) return EFAULT;
    if (size == 0) return EINVAL;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const cwd = vfs.getcwd();

    if (cwd.len >= size) return EINVAL;

    for (cwd, 0..) |c, i| {
        buf[i] = c;
    }
    buf[cwd.len] = 0;

    return @intCast(buf_ptr);
}

pub fn sysChdir(path_ptr: u64) i64 {
    if (path_ptr == 0) return EFAULT;

    const path: [*]const u8 = @ptrFromInt(path_ptr);
    var len: usize = 0;
    while (len < 256 and path[len] != 0) : (len += 1) {}
    if (len == 0) return EINVAL;

    if (vfs.chdir(path[0..len])) return 0;
    return ENOENT;
}

pub fn sysMkdir(path_ptr: u64, mode: u64) i64 {
    _ = mode;
    if (path_ptr == 0) return EFAULT;

    const path: [*]const u8 = @ptrFromInt(path_ptr);
    var len: usize = 0;
    while (len < 256 and path[len] != 0) : (len += 1) {}
    if (len == 0) return EINVAL;

    if (vfs.createDir(path[0..len]) != null) return 0;
    return EACCES;
}

pub fn sysRmdir(path_ptr: u64) i64 {
    if (path_ptr == 0) return EFAULT;

    const path: [*]const u8 = @ptrFromInt(path_ptr);
    var len: usize = 0;
    while (len < 256 and path[len] != 0) : (len += 1) {}
    if (len == 0) return EINVAL;

    if (vfs.removeDir(path[0..len])) return 0;
    return ENOENT;
}

pub fn sysUnlink(path_ptr: u64) i64 {
    if (path_ptr == 0) return EFAULT;

    const path: [*]const u8 = @ptrFromInt(path_ptr);
    var len: usize = 0;
    while (len < 256 and path[len] != 0) : (len += 1) {}
    if (len == 0) return EINVAL;

    if (vfs.removeFile(path[0..len])) return 0;
    return ENOENT;
}

// =============================================================================
// Time Syscalls
// =============================================================================

pub fn sysNanosleep(req_ptr: u64, rem_ptr: u64) i64 {
    _ = rem_ptr;
    if (req_ptr == 0) return EFAULT;

    const timespec: *const extern struct { sec: i64, nsec: i64 } = @ptrFromInt(req_ptr);
    const ms = timespec.sec * 1000 + @divTrunc(timespec.nsec, 1000000);
    timer.sleep(@intCast(ms));

    return 0;
}

// =============================================================================
// Zamrud Debug Syscalls
// =============================================================================

pub fn sysDebugPrint(str_ptr: u64, len: u64) i64 {
    if (str_ptr == 0) return EFAULT;

    const str: [*]const u8 = @ptrFromInt(str_ptr);
    const actual_len = @min(len, 4096);

    serial.writeString("[USER] ");
    for (0..actual_len) |i| {
        serial.writeChar(str[i]);
    }
    serial.writeString("\n");

    return @intCast(actual_len);
}

pub fn sysGetTicks() i64 {
    return @intCast(timer.getTicks());
}

pub fn sysGetUptime() i64 {
    return @intCast(timer.getSeconds());
}

// =============================================================================
// Graphics Syscalls
// =============================================================================

/// SYS_FB_GET_INFO
pub fn sysFbGetInfo(info_ptr: u64) i64 {
    if (info_ptr == 0) return EFAULT;
    if (!framebuffer.isInitialized()) return ENODEV;

    const info: *graphics_api.FramebufferInfo = @ptrFromInt(info_ptr);

    info.address = @intFromPtr(framebuffer.getAddress());
    info.width = framebuffer.getWidth();
    info.height = framebuffer.getHeight();
    info.pitch = framebuffer.getPitch();
    info.bpp = framebuffer.getBpp();
    info.format = .BGRA8888;
    info.size = @as(u64, info.pitch) * @as(u64, info.height);
    info.dpi_x = 96;
    info.dpi_y = 96;
    info.refresh_rate = 60;
    info.flags = .{};

    return 0;
}

/// SYS_FB_MAP
pub fn sysFbMap() i64 {
    if (!framebuffer.isInitialized()) return ENODEV;
    return @intCast(@intFromPtr(framebuffer.getAddress()));
}

/// SYS_FB_UNMAP
pub fn sysFbUnmap(addr: u64) i64 {
    _ = addr;
    return 0;
}

/// SYS_FB_FLUSH
pub fn sysFbFlush(rect_ptr: u64) i64 {
    if (!framebuffer.isInitialized()) return ENODEV;
    _ = rect_ptr;
    return 0;
}

/// SYS_CURSOR_SET_POS
pub fn sysCursorSetPos(x: u64, y: u64) i64 {
    if (!framebuffer.isInitialized()) return ENODEV;

    cursor_x = @intCast(@min(x, @as(u64, framebuffer.getWidth())));
    cursor_y = @intCast(@min(y, @as(u64, framebuffer.getHeight())));

    return 0;
}

/// SYS_CURSOR_SET_VISIBLE
pub fn sysCursorSetVisible(visible: u64) i64 {
    cursor_visible = visible != 0;
    return 0;
}

/// SYS_CURSOR_SET_TYPE
pub fn sysCursorSetType(ctype: u64) i64 {
    cursor_type = @truncate(ctype);
    return 0;
}

/// SYS_SCREEN_GET_ORIENTATION
pub fn sysScreenGetOrientation() i64 {
    if (!framebuffer.isInitialized()) return ENODEV;

    if (framebuffer.getWidth() > framebuffer.getHeight()) {
        return @intFromEnum(graphics_api.Orientation.Landscape);
    }
    return @intFromEnum(graphics_api.Orientation.Portrait);
}

// =============================================================================
// Input Syscalls
// =============================================================================

/// SYS_INPUT_POLL
pub fn sysInputPoll(event_ptr: u64) i64 {
    if (event_ptr == 0) return EFAULT;

    const event: *input_api.InputEvent = @ptrFromInt(event_ptr);

    if (keyboard.getKey()) |key| {
        event.timestamp = timer.getTicks();
        event.event_type = if (key.released) .KeyRelease else .KeyPress;
        event.device_id = 0;
        event.data.key = .{
            .scancode = key.scancode,
            .keycode = scancodeToKeycode(key.scancode),
            .modifiers = .{},
            .unicode = scancodeToUnicode(key.scancode, false),
        };
        return 1;
    }

    event.event_type = .None;
    return 0;
}

/// SYS_INPUT_WAIT
pub fn sysInputWait(event_ptr: u64, timeout_ms: u64) i64 {
    if (event_ptr == 0) return EFAULT;

    const start = timer.getTicks();
    const timeout_ticks = timeout_ms;

    while (true) {
        const result = sysInputPoll(event_ptr);
        if (result > 0) return result;

        if (timeout_ms > 0) {
            const elapsed = timer.getTicks() - start;
            if (elapsed >= timeout_ticks) return 0;
        }

        asm volatile ("hlt");
    }
}

/// SYS_INPUT_GET_TOUCH_CAPS
pub fn sysInputGetTouchCaps(caps_ptr: u64) i64 {
    if (caps_ptr == 0) return EFAULT;

    const caps: *input_api.TouchCapabilities = @ptrFromInt(caps_ptr);

    caps.has_touch = false;
    caps.max_touch_points = 0;
    caps.has_pressure = false;
    caps.has_radius = false;
    caps.has_stylus = false;

    return 0;
}

// =============================================================================
// Helpers
// =============================================================================

fn scancodeToKeycode(scancode: u16) input_api.KeyCode {
    return switch (scancode) {
        0x1E => .A,
        0x30 => .B,
        0x2E => .C,
        0x20 => .D,
        0x12 => .E,
        0x21 => .F,
        0x22 => .G,
        0x23 => .H,
        0x17 => .I,
        0x24 => .J,
        0x25 => .K,
        0x26 => .L,
        0x32 => .M,
        0x31 => .N,
        0x18 => .O,
        0x19 => .P,
        0x10 => .Q,
        0x13 => .R,
        0x1F => .S,
        0x14 => .T,
        0x16 => .U,
        0x2F => .V,
        0x11 => .W,
        0x2D => .X,
        0x15 => .Y,
        0x2C => .Z,
        0x1C => .Enter,
        0x01 => .Escape,
        0x0E => .Backspace,
        0x0F => .Tab,
        0x39 => .Space,
        0x48 => .Up,
        0x50 => .Down,
        0x4B => .Left,
        0x4D => .Right,
        else => .Unknown,
    };
}

fn scancodeToUnicode(scancode: u16, shift: bool) u32 {
    _ = shift;
    const c: ?u8 = switch (scancode) {
        0x1E => 'a',
        0x30 => 'b',
        0x2E => 'c',
        0x20 => 'd',
        0x12 => 'e',
        0x21 => 'f',
        0x22 => 'g',
        0x23 => 'h',
        0x17 => 'i',
        0x24 => 'j',
        0x25 => 'k',
        0x26 => 'l',
        0x32 => 'm',
        0x31 => 'n',
        0x18 => 'o',
        0x19 => 'p',
        0x10 => 'q',
        0x13 => 'r',
        0x1F => 's',
        0x14 => 't',
        0x16 => 'u',
        0x2F => 'v',
        0x11 => 'w',
        0x2D => 'x',
        0x15 => 'y',
        0x2C => 'z',
        0x39 => ' ',
        else => null,
    };
    return if (c) |char| char else 0;
}

fn printDec(val: u64) void {
    if (val == 0) {
        serial.writeChar('0');
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
        serial.writeChar(buf[i]);
    }
}
