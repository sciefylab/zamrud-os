//! Zamrud OS - System Call Handlers (SC1 Final)
//! All handlers use numbers.zig error codes.
//! Capability checks done in table.zig BEFORE handlers.
//! Production fixes: fd overflow, user address validation, safe casts.

const serial = @import("../drivers/serial/serial.zig");
const vfs = @import("../fs/vfs.zig");
const file_mod = @import("../fs/file.zig");
const process = @import("../proc/process.zig");
const timer = @import("../drivers/timer/timer.zig");
const keyboard = @import("../drivers/input/keyboard.zig");
const framebuffer = @import("../drivers/display/framebuffer.zig");
const numbers = @import("numbers.zig");
const graphics_api = @import("../api/graphics.zig");
const input_api = @import("../api/input.zig");

// =============================================================================
// Re-export error codes from numbers.zig
// =============================================================================

pub const SUCCESS = numbers.SUCCESS;
pub const EPERM = numbers.EPERM;
pub const ENOENT = numbers.ENOENT;
pub const ESRCH = numbers.ESRCH;
pub const EINTR = numbers.EINTR;
pub const EIO = numbers.EIO;
pub const EBADF = numbers.EBADF;
pub const EAGAIN = numbers.EAGAIN;
pub const ENOMEM = numbers.ENOMEM;
pub const EACCES = numbers.EACCES;
pub const EFAULT = numbers.EFAULT;
pub const EBUSY = numbers.EBUSY;
pub const EEXIST = numbers.EEXIST;
pub const ENODEV = numbers.ENODEV;
pub const EINVAL = numbers.EINVAL;
pub const EMFILE = numbers.EMFILE;
pub const ERANGE = numbers.ERANGE;
pub const ENOSYS = numbers.ENOSYS;

// =============================================================================
// Per-process File Descriptor Table
// =============================================================================

const MAX_FDS: usize = 64;
const MAX_FD_PROCS: usize = 32;

const FdEntry = struct {
    file: ?*vfs.File = null,
    in_use: bool = false,
};

const ProcessFdTable = struct {
    pid: u32 = 0,
    active: bool = false,
    fds: [MAX_FDS]FdEntry = [_]FdEntry{.{}} ** MAX_FDS,

    fn allocFd(self: *ProcessFdTable, file: *vfs.File) ?i32 {
        var i: usize = 3;
        while (i < MAX_FDS) : (i += 1) {
            if (!self.fds[i].in_use) {
                self.fds[i] = .{ .file = file, .in_use = true };
                return @intCast(i);
            }
        }
        return null;
    }

    fn getFile(self: *ProcessFdTable, fd: i32) ?*vfs.File {
        if (fd < 3 or fd >= MAX_FDS) return null;
        const idx: usize = @intCast(fd);
        if (!self.fds[idx].in_use) return null;
        return self.fds[idx].file;
    }

    fn closeFd(self: *ProcessFdTable, fd: i32) ?*vfs.File {
        if (fd < 3 or fd >= MAX_FDS) return null;
        const idx: usize = @intCast(fd);
        if (!self.fds[idx].in_use) return null;
        const file = self.fds[idx].file;
        self.fds[idx] = .{};
        return file;
    }
};

var fd_tables: [MAX_FD_PROCS]ProcessFdTable = [_]ProcessFdTable{.{}} ** MAX_FD_PROCS;

/// Get fd table for current process. Returns null if no slots available.
fn getFdTable() ?*ProcessFdTable {
    const pid = process.getCurrentPid();

    // Find existing table for this PID
    for (&fd_tables) |*t| {
        if (t.active and t.pid == pid) return t;
    }

    // Allocate new table
    for (&fd_tables) |*t| {
        if (!t.active) {
            t.* = .{};
            t.pid = pid;
            t.active = true;
            return t;
        }
    }

    // No slots available — do NOT corrupt existing tables
    return null;
}

/// Called when process terminates — close all fds
pub fn cleanupProcessFds(pid: u32) void {
    for (&fd_tables) |*t| {
        if (t.active and t.pid == pid) {
            var i: usize = 3;
            while (i < MAX_FDS) : (i += 1) {
                if (t.fds[i].in_use) {
                    if (t.fds[i].file) |f| {
                        vfs.close(f);
                    }
                    t.fds[i] = .{};
                }
            }
            t.active = false;
            return;
        }
    }
}

/// Get count of active fd tables (for diagnostics)
pub fn getActiveFdTableCount() usize {
    var count: usize = 0;
    for (&fd_tables) |*t| {
        if (t.active) count += 1;
    }
    return count;
}

// =============================================================================
// Pointer & Address Validation
// =============================================================================

/// Kernel address space starts at 0xFFFF800000000000 (higher half)
const KERNEL_BASE: u64 = 0xFFFF800000000000;

/// Minimum valid user address
const USER_MIN: u64 = 0x1000;

/// Maximum valid user address (below kernel)
const USER_MAX: u64 = 0x00007FFFFFFFFFFF;

/// Check if address is in user space (not kernel memory)
fn isUserAddress(addr: u64) bool {
    return addr >= USER_MIN and addr <= USER_MAX;
}

/// Check if entire range is in user space
fn isUserRange(addr: u64, len: u64) bool {
    if (addr == 0) return false;
    if (len == 0) return true;
    if (!isUserAddress(addr)) return false;
    const result = @addWithOverflow(addr, len);
    if (result[1] != 0) return false; // overflow
    return isUserAddress(result[0] - 1);
}

/// Validate pointer and length (kernel-space pointers also accepted for now)
/// TODO: Strict user-only validation when full MMU separation is active
fn validatePtr(ptr: u64, len: u64) bool {
    if (ptr == 0) return false;
    if (len == 0) return true;
    const result = @addWithOverflow(ptr, len);
    return result[1] == 0;
}

fn ptrToSlice(ptr: u64, len: u64) ?[]const u8 {
    if (ptr == 0) return null;
    if (len == 0) return &[_]u8{};
    const p: [*]const u8 = @ptrFromInt(ptr);
    return p[0..@intCast(len)];
}

fn readCString(ptr: u64, max_len: usize) ?[]const u8 {
    if (ptr == 0) return null;
    const p: [*]const u8 = @ptrFromInt(ptr);
    var len: usize = 0;
    while (len < max_len) : (len += 1) {
        if (p[len] == 0) return p[0..len];
    }
    return null;
}

// =============================================================================
// Cursor State (for graphics syscalls)
// =============================================================================

var cursor_x: i32 = 0;
var cursor_y: i32 = 0;
var cursor_visible: bool = true;
var cursor_type: u8 = 0;

// =============================================================================
// Core: Process Info
// =============================================================================

pub fn sysExit(status: u64) noreturn {
    const pid = process.getCurrentPid();
    cleanupProcessFds(pid);

    if (pid != 0) {
        _ = process.terminate(pid);
    }
    _ = status;

    while (true) {
        asm volatile ("hlt");
    }
}

pub fn sysGetpid() i64 {
    return @intCast(process.getCurrentPid());
}

pub fn sysGetppid() i64 {
    return 0; // TODO SC2: parent tracking
}

pub fn sysGetuid() i64 {
    return @intCast(process.getProcessUid(process.getCurrentPid()));
}

pub fn sysGetgid() i64 {
    return @intCast(process.getProcessGid(process.getCurrentPid()));
}

pub fn sysGeteuid() i64 {
    return sysGetuid();
}

pub fn sysGetegid() i64 {
    return sysGetgid();
}

pub fn sysSchedYield() i64 {
    const sched = @import("../proc/scheduler.zig");
    sched.yield();
    return SUCCESS;
}

// =============================================================================
// Core: File I/O — SC1 with fd table + VFS
// =============================================================================

/// SYS_OPEN: open file, return fd
pub fn sysOpen(path_ptr: u64, flags_raw: u64, mode: u64) i64 {
    _ = mode;

    const file_path = readCString(path_ptr, 256) orelse return EFAULT;
    if (file_path.len == 0) return EINVAL;

    var flags = vfs.OpenFlags{};

    const access = flags_raw & 0x3;
    if (access == 0) {
        flags.read = true;
    } else if (access == 1) {
        flags.write = true;
    } else {
        flags.read = true;
        flags.write = true;
    }

    if (flags_raw & 0x40 != 0) flags.create = true;
    if (flags_raw & 0x200 != 0) flags.truncate = true;
    if (flags_raw & 0x400 != 0) flags.append = true;

    const file = vfs.open(file_path, flags) orelse {
        return ENOENT;
    };

    const table = getFdTable() orelse {
        vfs.close(file);
        return ENOMEM;
    };

    const fd = table.allocFd(file) orelse {
        vfs.close(file);
        return EMFILE;
    };

    return fd;
}

/// SYS_CLOSE: close fd
pub fn sysClose(fd_raw: u64) i64 {
    const fd: i32 = @intCast(@min(fd_raw, 0x7FFFFFFF));

    if (fd < 3) return SUCCESS;

    const table = getFdTable() orelse return EBADF;
    const file = table.closeFd(fd) orelse return EBADF;
    vfs.close(file);
    return SUCCESS;
}

/// SYS_READ: read from fd (stdin or file)
pub fn sysRead(fd_raw: u64, buf_ptr: u64, count: u64) i64 {
    if (!validatePtr(buf_ptr, count)) return EFAULT;
    if (count == 0) return 0;

    const fd: i32 = @intCast(@min(fd_raw, 0x7FFFFFFF));

    // fd 0 = stdin
    if (fd == 0) return 0; // EOF — keyboard via SYS_INPUT_POLL

    // fd 1,2 = stdout/stderr — cannot read
    if (fd == 1 or fd == 2) return EBADF;

    const table = getFdTable() orelse return EBADF;
    const file = table.getFile(fd) orelse return EBADF;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const len = @min(count, 0x100000); // Max 1MB per read
    const result = vfs.read(file, buf[0..len]);

    return result;
}

/// SYS_WRITE: write to fd (stdout/stderr or file)
pub fn sysWrite(fd_raw: u64, buf_ptr: u64, count: u64) i64 {
    if (!validatePtr(buf_ptr, count)) return EFAULT;
    if (count == 0) return 0;

    const fd: i32 = @intCast(@min(fd_raw, 0x7FFFFFFF));
    const ptr: [*]const u8 = @ptrFromInt(buf_ptr);
    const len = @min(count, 4096);

    // fd 1 = stdout, fd 2 = stderr → serial
    if (fd == 1 or fd == 2) {
        var i: usize = 0;
        while (i < len) : (i += 1) {
            serial.writeChar(ptr[i]);
        }
        return @intCast(len);
    }

    // fd 0 = stdin — cannot write
    if (fd == 0) return EBADF;

    const table = getFdTable() orelse return EBADF;
    const file = table.getFile(fd) orelse return EBADF;

    const result = vfs.write(file, ptr[0..len]);
    return result;
}

// =============================================================================
// Core: Directory Operations
// =============================================================================

pub fn sysGetcwd(buf_ptr: u64, size: u64) i64 {
    if (!validatePtr(buf_ptr, size)) return EFAULT;
    if (size == 0) return EINVAL;

    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    const cwd = vfs.getcwd();

    if (cwd.len >= size) return ERANGE;

    for (cwd, 0..) |c, i| {
        buf[i] = c;
    }
    buf[cwd.len] = 0;

    return @intCast(buf_ptr);
}

pub fn sysChdir(path_ptr: u64) i64 {
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (p.len == 0) return EINVAL;
    if (vfs.chdir(p)) return SUCCESS;
    return ENOENT;
}

pub fn sysMkdir(path_ptr: u64, mode: u64) i64 {
    _ = mode;
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (p.len == 0) return EINVAL;
    if (vfs.createDir(p) != null) return SUCCESS;
    return EACCES;
}

pub fn sysRmdir(path_ptr: u64) i64 {
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (p.len == 0) return EINVAL;
    if (vfs.removeDir(p)) return SUCCESS;
    return ENOENT;
}

pub fn sysUnlink(path_ptr: u64) i64 {
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (p.len == 0) return EINVAL;
    if (vfs.removeFile(p)) return SUCCESS;
    return ENOENT;
}

// =============================================================================
// Core: Time
// =============================================================================

pub fn sysNanosleep(req_ptr: u64, rem_ptr: u64) i64 {
    _ = rem_ptr;
    if (!validatePtr(req_ptr, 16)) return EFAULT;

    const timespec: *const extern struct { sec: i64, nsec: i64 } = @ptrFromInt(req_ptr);
    const ms = timespec.sec * 1000 + @divTrunc(timespec.nsec, 1_000_000);
    timer.sleep(@intCast(@max(0, ms)));

    return SUCCESS;
}

// =============================================================================
// FS Extended
// =============================================================================

pub fn sysStat(path_ptr: u64, stat_ptr: u64) i64 {
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (!validatePtr(stat_ptr, @sizeOf(StatResult))) return EFAULT;

    const inode = vfs.resolvePath(p) orelse return ENOENT;
    const stat: *StatResult = @ptrFromInt(stat_ptr);

    stat.size = inode.size;
    stat.file_type = @intFromEnum(inode.file_type);
    stat.mode = @bitCast(inode.mode);
    stat.uid = @truncate(inode.uid);
    stat.gid = @truncate(inode.gid);

    return SUCCESS;
}

const StatResult = extern struct {
    size: u64 = 0,
    file_type: u8 = 0,
    mode: u16 = 0,
    uid: u16 = 0,
    gid: u16 = 0,
    _pad: [5]u8 = [_]u8{0} ** 5,
};

pub fn sysReaddir(path_ptr: u64, index: u64, entry_ptr: u64) i64 {
    const p = readCString(path_ptr, 256) orelse return EFAULT;
    if (!validatePtr(entry_ptr, @sizeOf(ReaddirResult))) return EFAULT;

    const entry = vfs.readdir(p, @intCast(index)) orelse return 0;
    const out: *ReaddirResult = @ptrFromInt(entry_ptr);

    // Zero-initialize output
    out.* = .{};

    const name = entry.getName();
    var i: usize = 0;
    while (i < name.len and i < 255) : (i += 1) {
        out.name[i] = name[i];
    }
    out.name[i] = 0;
    out.name_len = @intCast(i);
    out.file_type = @intFromEnum(entry.file_type);
    out.size = entry.getSize();

    return 1;
}

const ReaddirResult = extern struct {
    name: [256]u8 = [_]u8{0} ** 256,
    name_len: u16 = 0,
    file_type: u8 = 0,
    _pad: [5]u8 = [_]u8{0} ** 5,
    size: u64 = 0,
};

pub fn sysRename(old_ptr: u64, new_ptr: u64) i64 {
    _ = old_ptr;
    _ = new_ptr;
    return ENOSYS; // TODO SC8
}

pub fn sysTruncate(path_ptr: u64, length: u64) i64 {
    _ = path_ptr;
    _ = length;
    return ENOSYS; // TODO SC8
}

pub fn sysSeek(fd_raw: u64, offset: u64, whence: u64) i64 {
    const fd: i32 = @intCast(@min(fd_raw, 0x7FFFFFFF));
    if (fd < 3) return EBADF;

    const table = getFdTable() orelse return EBADF;
    const file = table.getFile(fd) orelse return EBADF;

    const w: vfs.SeekWhence = switch (whence) {
        0 => .Set,
        1 => .Cur,
        2 => .End,
        else => return EINVAL,
    };

    return vfs.seek(file, @intCast(offset), w);
}

// =============================================================================
// Debug Syscalls
// =============================================================================

pub fn sysDebugPrint(str_ptr: u64, len: u64) i64 {
    if (!validatePtr(str_ptr, len)) return EFAULT;

    const ptr: [*]const u8 = @ptrFromInt(str_ptr);
    const actual_len = @min(len, 4096);

    serial.writeString("[USER] ");
    var i: usize = 0;
    while (i < actual_len) : (i += 1) {
        serial.writeChar(ptr[i]);
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

    return SUCCESS;
}

pub fn sysFbMap() i64 {
    if (!framebuffer.isInitialized()) return ENODEV;
    // Framebuffer address is in higher-half (bit 63 set).
    // Return as bitcast to preserve full 64-bit address.
    const addr: u64 = @intFromPtr(framebuffer.getAddress());
    return @bitCast(addr);
}

pub fn sysFbUnmap(addr: u64) i64 {
    _ = addr;
    return SUCCESS;
}

pub fn sysFbFlush(rect_ptr: u64) i64 {
    _ = rect_ptr;
    if (!framebuffer.isInitialized()) return ENODEV;
    return SUCCESS;
}

pub fn sysCursorSetPos(x: u64, y: u64) i64 {
    if (!framebuffer.isInitialized()) return ENODEV;
    cursor_x = @intCast(@min(x, @as(u64, framebuffer.getWidth())));
    cursor_y = @intCast(@min(y, @as(u64, framebuffer.getHeight())));
    return SUCCESS;
}

pub fn sysCursorSetVisible(visible: u64) i64 {
    cursor_visible = visible != 0;
    return SUCCESS;
}

pub fn sysCursorSetType(ctype: u64) i64 {
    cursor_type = @truncate(ctype);
    return SUCCESS;
}

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

pub fn sysInputPoll(event_ptr: u64) i64 {
    if (event_ptr == 0) return EFAULT;

    const event: *input_api.InputEvent = @ptrFromInt(event_ptr);

    // Check keyboard first
    if (keyboard.getKey()) |scancode| {
        event.timestamp = timer.getTicks();
        const released = (scancode & 0x80) != 0;
        const actual_scancode: u16 = @intCast(scancode & 0x7F);
        event.event_type = if (released) .KeyUp else .KeyDown;
        event.device_id = 0;
        event.data.key = .{
            .scancode = actual_scancode,
            .keycode = scancodeToKeycode(actual_scancode),
            .modifiers = .{},
            .unicode = scancodeToUnicode(actual_scancode, false),
        };
        return 1;
    }

    // Check mouse
    const mouse = @import("../drivers/input/mouse.zig");
    if (mouse.pollEvent()) |me| {
        event.timestamp = me.timestamp;
        event.device_id = 1; // mouse = device 1

        // Determine event type
        const prev_buttons = event.data.mouse.buttons;
        _ = prev_buttons;

        if (me.dx != 0 or me.dy != 0) {
            event.event_type = .MouseMove;
        } else if (me.scroll != 0) {
            event.event_type = .MouseScroll;
        } else {
            // Button change
            event.event_type = .MouseButtonDown;
        }

        event.data.mouse = .{
            .x = me.x,
            .y = me.y,
            .delta_x = me.dx,
            .delta_y = me.dy,
            .button = if ((me.buttons & 0x01) != 0) .Left else if ((me.buttons & 0x02) != 0) .Right else if ((me.buttons & 0x04) != 0) .Middle else .None,
            .buttons = .{
                .left = (me.buttons & 0x01) != 0,
                .right = (me.buttons & 0x02) != 0,
                .middle = (me.buttons & 0x04) != 0,
            },
            .scroll_y = @intCast(me.scroll),
            .scroll_x = 0,
        };
        return 1;
    }

    event.event_type = .None;
    return 0;
}

pub fn sysInputWait(event_ptr: u64, timeout_ms: u64) i64 {
    if (event_ptr == 0) return EFAULT;

    const start = timer.getTicks();
    const timeout_ticks = timeout_ms;

    while (true) {
        const result = sysInputPoll(event_ptr);
        if (result > 0) return result;

        if (timeout_ms > 0) {
            if (timer.getTicks() - start >= timeout_ticks) return 0;
        }

        asm volatile ("hlt");
    }
}

pub fn sysInputGetTouchCaps(caps_ptr: u64) i64 {
    if (caps_ptr == 0) return EFAULT;

    const caps: *input_api.TouchCapabilities = @ptrFromInt(caps_ptr);
    caps.has_touch = false;
    caps.max_touch_points = 0;
    caps.has_pressure = false;
    caps.has_radius = false;
    caps.has_stylus = false;

    return SUCCESS;
}

// =============================================================================
// Scancode helpers
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
    return if (c) |ch| ch else 0;
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
